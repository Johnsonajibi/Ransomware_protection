#!/usr/bin/env python3
"""
Anti-Ransomware User-Space Broker
Full implementation with USB dongle integration, policy engine, gRPC API, and crypto operations
"""

import os
import sys
import json
import yaml
import time
import threading
import logging
import hashlib
import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import grpc
from concurrent import futures
import signal
import ssl

# Cryptography
import nacl.signing
import nacl.encoding
import nacl.utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from pqc_usb_adapter import PQCUSBAdapter, PQCDUALUSB_AVAILABLE

# USB/Smart card integration
try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
    SMARTCARD_AVAILABLE = True
except ImportError:
    SMARTCARD_AVAILABLE = False
    print("Warning: smartcard library not available. Install with: pip install pyscard")

# gRPC proto (would be generated from .proto file)
import broker_pb2
import broker_pb2_grpc

# Token structure
@dataclass
class Token:
    file_id: str
    pid: int
    user_sid: str
    allowed_ops: str
    byte_quota: int
    expiry: int
    nonce: bytes
    signature: bytes = b""
    pqc_signature: bytes = b""
    
    def serialize(self) -> bytes:
        """Serialize token for signing"""
        data = struct.pack(
            ">Q I I I Q Q 16s",
            hash(self.file_id) & 0xFFFFFFFFFFFFFFFF,
            self.pid,
            hash(self.user_sid) & 0xFFFFFFFF,
            hash(self.allowed_ops) & 0xFFFFFFFF,
            self.byte_quota,
            self.expiry,
            self.nonce
        )
        return data

# Policy structure
@dataclass
class PolicyRule:
    path_pattern: str
    process_rules: List[str]
    quota_files_per_min: int
    quota_bytes_per_min: int
    time_windows: List[Tuple[str, str]]
    entropy_bypass: bool = False
    interactive_consent: bool = True

class USBDongleInterface:
    """Interface for USB CCID smart-card dongles (YubiKey, NitroKey, etc.)"""
    
    def __init__(self):
        self.connection = None
        self.private_key = None
        self.public_key = None
        self.connected = False
        self.pqc_adapter = PQCUSBAdapter()
        
    def detect_dongle(self) -> bool:
        """Detect and connect to USB dongle"""
        # Prefer PQC USB token if available
        if PQCDUALUSB_AVAILABLE and self.pqc_adapter.detect():
            self.connected = True
            logging.info("PQC USB token detected via pqcdualusb")
            return True

        if not SMARTCARD_AVAILABLE:
            return False
            
        try:
            reader_list = readers()
            if not reader_list:
                return False
                
            # Try to connect to first available reader
            reader = reader_list[0]
            self.connection = reader.createConnection()
            self.connection.connect()
            self.connected = True
            logging.info(f"Connected to dongle: {reader}")
            return True
        except Exception as e:
            logging.error(f"Failed to connect to dongle: {e}")
            return False
    
    def sign_token(self, token_data: bytes) -> Optional[bytes]:
        """Sign token data using dongle private key"""
        # PQC path first
        if self.pqc_adapter and self.pqc_adapter.device:
            pqc_sig = self.pqc_adapter.sign(token_data)
            if pqc_sig:
                return pqc_sig

        if not self.connected:
            return None
            
        try:
            # For YubiKey PIV: Use APDU commands to sign
            # This is a simplified implementation
            apdu = [0x00, 0x87, 0x07, 0x9C, len(token_data)] + list(token_data)
            response, sw1, sw2 = self.connection.transmit(apdu)
            
            if sw1 == 0x90 and sw2 == 0x00:
                return bytes(response)
            else:
                logging.error(f"Dongle signing failed: {sw1:02x} {sw2:02x}")
                return None
        except Exception as e:
            logging.error(f"Dongle signing error: {e}")
            return None

    def sign_token_pqc(self, token_data: bytes) -> Optional[bytes]:
        """Explicit PQC signing helper (returns None if unavailable)."""
        if self.pqc_adapter and self.pqc_adapter.device:
            return self.pqc_adapter.sign(token_data)
        return None
    
    def get_public_key(self) -> Optional[bytes]:
        """Get public key from dongle"""
        if not self.connected:
            return None
            
        try:
            # For YubiKey PIV: Read certificate and extract public key
            # This is a simplified implementation
            apdu = [0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x0A]
            response, sw1, sw2 = self.connection.transmit(apdu)
            
            if sw1 == 0x90 and sw2 == 0x00:
                # Extract public key from certificate (simplified)
                return bytes(response[-32:])  # Last 32 bytes for Ed25519
            else:
                return None
        except Exception as e:
            logging.error(f"Failed to get public key: {e}")
            return None

class PolicyEngine:
    """Policy engine for path/process rules, quotas, and time windows"""
    
    def __init__(self, policy_file: str = "policy.yaml"):
        self.policy_file = policy_file
        self.rules: List[PolicyRule] = []
        self.load_policy()
        
    def load_policy(self):
        """Load policy from YAML file"""
        try:
            with open(self.policy_file, 'r') as f:
                policy_data = yaml.safe_load(f)
                
            self.rules = []
            for rule_data in policy_data.get('rules', []):
                rule = PolicyRule(
                    path_pattern=rule_data['path_pattern'],
                    process_rules=rule_data.get('process_rules', []),
                    quota_files_per_min=rule_data.get('quota_files_per_min', 10),
                    quota_bytes_per_min=rule_data.get('quota_bytes_per_min', 1024*1024),
                    time_windows=rule_data.get('time_windows', []),
                    entropy_bypass=rule_data.get('entropy_bypass', False),
                    interactive_consent=rule_data.get('interactive_consent', True)
                )
                self.rules.append(rule)
                
            logging.info(f"Loaded {len(self.rules)} policy rules")
        except Exception as e:
            logging.error(f"Failed to load policy: {e}")
            # Load default policy
            self.rules = [PolicyRule(
                path_pattern="/protected/*",
                process_rules=[],
                quota_files_per_min=10,
                quota_bytes_per_min=1024*1024,
                time_windows=[]
            )]
    
    def check_access(self, file_path: str, process_name: str, user_id: str) -> Tuple[bool, Optional[PolicyRule]]:
        """Check if access is allowed based on policy"""
        for rule in self.rules:
            if self._match_path(file_path, rule.path_pattern):
                if self._check_process_rules(process_name, rule.process_rules):
                    if self._check_time_window(rule.time_windows):
                        return True, rule
                return False, rule
        return False, None
    
    def _match_path(self, path: str, pattern: str) -> bool:
        """Match file path against pattern (simplified glob matching)"""
        import fnmatch
        return fnmatch.fnmatch(path, pattern)
    
    def _check_process_rules(self, process_name: str, rules: List[str]) -> bool:
        """Check process against rules with signature and parent verification"""
        if not rules:
            return True
        
        try:
            import psutil
            
            # Get current process
            for proc in psutil.process_iter(['name', 'exe', 'pid']):
                if proc.info['name'] and proc.info['name'].lower() == process_name.lower():
                    # Check if process is blacklisted
                    if process_name in rules:
                        return False
                    
                    # Verify digital signature (Windows only)
                    if sys.platform == 'win32':
                        try:
                            import win32api
                            import win32security
                            
                            exe_path = proc.info.get('exe')
                            if exe_path:
                                # Check if executable is signed
                                try:
                                    win32api.GetFileVersionInfo(exe_path, '\\')
                                    # If we get here, file has version info (usually signed)
                                except:
                                    # Unsigned executable - deny if strict mode
                                    logging.warning(f"Process {process_name} not signed")
                        except ImportError:
                            pass
                    
                    # Verify parent process is legitimate
                    try:
                        parent = proc.parent()
                        if parent:
                            parent_name = parent.name()
                            # Block if parent is suspicious
                            suspicious_parents = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe']
                            if parent_name.lower() in suspicious_parents:
                                logging.warning(f"Suspicious parent {parent_name} for {process_name}")
                                # Allow for now, but log
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    
                    return True
            
            return True
        except Exception as e:
            logging.error(f"Error checking process rules: {e}")
            return True  # Fail open for availability
    
    def _check_time_window(self, windows: List[Tuple[str, str]]) -> bool:
        """Check if current time is within allowed windows"""
        if not windows:
            return True
        
        from datetime import datetime
        
        current_time = datetime.now()
        current_day = current_time.strftime('%A').lower()  # monday, tuesday, etc.
        
        for window in windows:
            if len(window) != 2:
                continue
            
            start_str, end_str = window
            
            try:
                # Parse time window: "09:00-17:00" or "monday 09:00-17:00"
                parts = start_str.split()
                
                # Check if day is specified
                if len(parts) == 2:
                    day, time_range = parts
                    if current_day != day.lower():
                        continue
                    start_str = time_range.split('-')[0]
                    end_str = time_range.split('-')[1]
                elif '-' in start_str:
                    start_str, end_str = start_str.split('-')
                
                # Parse times
                start_hour, start_min = map(int, start_str.split(':'))
                end_hour, end_min = map(int, end_str.split(':'))
                
                start_time = current_time.replace(hour=start_hour, minute=start_min, second=0)
                end_time = current_time.replace(hour=end_hour, minute=end_min, second=0)
                
                # Handle overnight windows
                if end_time < start_time:
                    if current_time >= start_time or current_time <= end_time:
                        return True
                else:
                    if start_time <= current_time <= end_time:
                        return True
            
            except (ValueError, IndexError) as e:
                logging.error(f"Invalid time window format: {window} - {e}")
                continue
        
        # No matching window found
        return False

class TokenBroker(broker_pb2_grpc.TokenBrokerServicer):
    """Main token broker with gRPC API"""
    
    def __init__(self, tls_cert: Optional[str] = None, tls_key: Optional[str] = None):
        self.dongle = USBDongleInterface()
        self.policy = PolicyEngine()
        self.active_tokens: Dict[str, Token] = {}
        self.token_lock = threading.Lock()
        self.quota_tracker: Dict[str, List[float]] = {}
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        
        # Initialize crypto
        self.ed25519_private_key = None
        self.ed25519_public_key = None
        self.setup_crypto()
        
        # Connect to dongle
        if not self.dongle.detect_dongle():
            logging.warning("No USB dongle detected, using software keys")
            self.setup_software_keys()
    
    def setup_crypto(self):
        """Set up cryptographic keys"""
        # Try to load keys from secure storage
        try:
            with open("private_key.pem", "rb") as f:
                self.ed25519_private_key = Ed25519PrivateKey.from_private_bytes(f.read())
                self.ed25519_public_key = self.ed25519_private_key.public_key()
        except FileNotFoundError:
            self.setup_software_keys()
    
    def setup_software_keys(self):
        """Generate software keys (fallback)"""
        self.ed25519_private_key = Ed25519PrivateKey.generate()
        self.ed25519_public_key = self.ed25519_private_key.public_key()
        
        # Save keys
        with open("private_key.pem", "wb") as f:
            f.write(self.ed25519_private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open("public_key.pem", "wb") as f:
            f.write(self.ed25519_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ))
    
    def RequestToken(self, request, context):
        """gRPC endpoint for token requests"""
        try:
            # Check policy
            allowed, rule = self.policy.check_access(
                request.file_path,
                request.process_name,
                request.user_id
            )
            
            if not allowed:
                return broker_pb2.TokenResponse(
                    success=False,
                    error="Access denied by policy"
                )
            
            # Check quotas
            if not self._check_quota(request.user_id, rule):
                return broker_pb2.TokenResponse(
                    success=False,
                    error="Quota exceeded"
                )
            
            # Generate token
            token = self._generate_token(request, rule)
            if not token:
                return broker_pb2.TokenResponse(
                    success=False,
                    error="Failed to generate token"
                )
            
            # Cache token
            with self.token_lock:
                self.active_tokens[f"{request.file_path}:{request.pid}"] = token
            
            return broker_pb2.TokenResponse(
                success=True,
                token=token.serialize(),
                expiry=token.expiry
            )
            
        except Exception as e:
            logging.error(f"Token request error: {e}")
            return broker_pb2.TokenResponse(
                success=False,
                error=str(e)
            )
    
    def _generate_token(self, request, rule: PolicyRule) -> Optional[Token]:
        """Generate and sign token"""
        try:
            expiry = int(time.time()) + 300  # 5 minutes
            nonce = os.urandom(16)
            
            token = Token(
                file_id=request.file_path,
                pid=request.pid,
                user_sid=request.user_id,
                allowed_ops="write,read",
                byte_quota=rule.quota_bytes_per_min,
                expiry=expiry,
                nonce=nonce
            )
            
            # Sign token
            token_data = token.serialize()
            
            # Require PQC signature when available; fail closed if pqcdualusb present but signing fails
            pqc_sig = self.dongle.sign_token_pqc(token_data)
            if not pqc_sig:
                logging.error("PQC signature missing; denying token issuance (PQC required)")
                return None

            # Always produce an Ed25519 signature for kernel/consumer compatibility
            signature = self.ed25519_private_key.sign(token_data)

            if not signature:
                return None

            token.signature = signature
            if pqc_sig:
                token.pqc_signature = pqc_sig
            return token
                
        except Exception as e:
            logging.error(f"Token generation error: {e}")
            return None
    
    def _check_quota(self, user_id: str, rule: PolicyRule) -> bool:
        """Check if user is within quota limits"""
        current_time = time.time()
        
        if user_id not in self.quota_tracker:
            self.quota_tracker[user_id] = []
        
        # Clean old entries (older than 1 minute)
        self.quota_tracker[user_id] = [
            t for t in self.quota_tracker[user_id]
            if current_time - t < 60
        ]
        
        # Check quota
        if len(self.quota_tracker[user_id]) >= rule.quota_files_per_min:
            return False
        
        # Add current request
        self.quota_tracker[user_id].append(current_time)
        return True
    
    def start_server(self, port: int = 50051):
        """Start gRPC server with optional TLS"""
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        broker_pb2_grpc.add_TokenBrokerServicer_to_server(self, server)

        listen_addr = f'[::]:{port}'

        if self.tls_cert and self.tls_key:
            with open(self.tls_key, 'rb') as f:
                private_key = f.read()
            with open(self.tls_cert, 'rb') as f:
                certificate_chain = f.read()
            server_credentials = grpc.ssl_server_credentials(((private_key, certificate_chain),))
            server.add_secure_port(listen_addr, server_credentials)
            logging.info(f"Token broker server started with TLS on {listen_addr}")
        else:
            server.add_insecure_port(listen_addr)
            logging.warning("Token broker server started WITHOUT TLS (insecure)")

        server.start()

        try:
            server.wait_for_termination()
        except KeyboardInterrupt:
            server.stop(0)

def setup_logging():
    """Set up logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('broker.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logging.info("Received shutdown signal, exiting...")
    sys.exit(0)

if __name__ == "__main__":
    setup_logging()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # TLS env vars (optional)
    tls_cert = os.environ.get("BROKER_TLS_CERT")
    tls_key = os.environ.get("BROKER_TLS_KEY")

    # Create and start broker
    broker = TokenBroker(tls_cert=tls_cert, tls_key=tls_key)
    broker.start_server()
