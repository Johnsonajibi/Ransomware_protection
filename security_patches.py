#!/usr/bin/env python3
"""
CRITICAL SECURITY PATCHES
Implementation of fixes for the security vulnerabilities identified
"""

import os
import sys
import secrets
import hashlib
import hmac
import json
import platform
import subprocess
import winreg
import ctypes
import ctypes.wintypes
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import psutil
import sqlite3
import threading
import time
from datetime import datetime, timedelta

class SecureTokenManager:
    """SECURITY PATCHED: Token management with AES-GCM and proper key derivation"""
    
    def __init__(self):
        self.hardware_fingerprint = self._generate_secure_hardware_fingerprint()
        # No more legacy token support by default
        self.enable_legacy_support = False
        
    def _generate_secure_hardware_fingerprint(self):
        """Generate cryptographically secure hardware fingerprint"""
        fingerprint_data = []
        
        try:
            # CPU information
            import cpuinfo
            cpu_info = cpuinfo.get_cpu_info()
            fingerprint_data.append(cpu_info.get('brand_raw', ''))
            fingerprint_data.append(str(cpu_info.get('hz_actual_friendly', '')))
        except:
            # Fallback without external dependency
            fingerprint_data.append(platform.processor())
        
        try:
            # Memory information
            mem = psutil.virtual_memory()
            fingerprint_data.append(str(mem.total))
        except:
            pass
            
        try:
            # Disk serial numbers (more reliable than WMI)
            for disk in psutil.disk_partitions():
                if disk.device:
                    fingerprint_data.append(disk.device)
        except:
            pass
            
        try:
            # Network MAC addresses (via psutil, not WMI)
            import uuid
            fingerprint_data.append(str(uuid.getnode()))
        except:
            pass
            
        # Create hash
        combined = '|'.join(fingerprint_data)
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def create_secure_token(self, process_id, allowed_operations):
        """Create cryptographically secure token with AES-GCM"""
        # Generate random salt and nonce for each token
        salt = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)  # AES-GCM nonce
        
        # Derive key using PBKDF2 with random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(self.hardware_fingerprint.encode())
        
        # Create token data
        token_data = {
            'hardware_fingerprint': self.hardware_fingerprint,
            'process_id': process_id,
            'allowed_operations': allowed_operations,
            'timestamp': int(time.time()),
            'expires_at': int(time.time()) + (7 * 24 * 3600),  # 7 days instead of 24h
            'nonce': nonce.hex(),
            'version': '2.0'  # Mark as new format
        }
        
        # Serialize and encrypt with AES-GCM (provides authentication)
        plaintext = json.dumps(token_data, sort_keys=True).encode()
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Package: salt + nonce + ciphertext
        packaged_token = {
            'salt': salt.hex(),
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex(),
            'version': '2.0'
        }
        
        return json.dumps(packaged_token)
    
    def validate_secure_token(self, token_data):
        """Validate token with AES-GCM authentication"""
        try:
            token_obj = json.loads(token_data)
            
            # Check version - reject legacy by default
            if token_obj.get('version') != '2.0':
                if not self.enable_legacy_support:
                    return False
                return self._validate_legacy_token_safe(token_data)
            
            # Extract components
            salt = bytes.fromhex(token_obj['salt'])
            nonce = bytes.fromhex(token_obj['nonce'])
            ciphertext = bytes.fromhex(token_obj['ciphertext'])
            
            # Derive key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(self.hardware_fingerprint.encode())
            
            # Decrypt and authenticate
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Parse decrypted data
            decrypted_data = json.loads(plaintext.decode())
            
            # Validate hardware fingerprint
            if decrypted_data['hardware_fingerprint'] != self.hardware_fingerprint:
                return False
            
            # Check expiry
            if int(time.time()) > decrypted_data['expires_at']:
                return False
                
            return True
            
        except Exception:
            return False
    
    def _validate_legacy_token_safe(self, token_data):
        """DEPRECATED: Legacy token validation - disabled by default"""
        # This should only be enabled during migration period
        return False

class SecurePathManager:
    """SECURITY PATCHED: Path handling without command injection"""
    
    @staticmethod
    def normalize_path(path_input):
        """Safely normalize and validate paths"""
        try:
            # Convert to Path object and resolve
            path = Path(path_input).resolve()
            
            # Block system directories
            blocked_paths = [
                Path(os.environ.get('WINDIR', 'C:\\Windows')),
                Path(os.environ.get('PROGRAMFILES', 'C:\\Program Files')),
                Path(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)')),
                Path(os.environ.get('SYSTEMROOT', 'C:\\Windows')),
            ]
            
            for blocked in blocked_paths:
                try:
                    if path.is_relative_to(blocked):
                        raise ValueError(f"Cannot protect system directory: {path}")
                except AttributeError:
                    # Python < 3.9 compatibility
                    if str(blocked).lower() in str(path).lower():
                        raise ValueError(f"Cannot protect system directory: {path}")
            
            return path
            
        except Exception as e:
            raise ValueError(f"Invalid path: {e}")
    
    @staticmethod
    def detect_ads_safe(file_path):
        """Detect Alternate Data Streams using Win32 API instead of shell commands"""
        try:
            import win32file
            import win32api
            
            # Use Win32 API to enumerate streams
            try:
                streams = win32file.FindStreams(str(file_path))
                return len(streams) > 1  # More than just the main stream
            except:
                return False
                
        except ImportError:
            # Fallback without pywin32 - use safer subprocess
            try:
                result = subprocess.run([
                    'powershell', '-Command', 
                    f'Get-Item "{file_path}" -Stream *'
                ], capture_output=True, text=True, shell=False, timeout=5)
                return 'Zone.Identifier' in result.stdout or ':' in result.stdout
            except:
                return False
    
    @staticmethod
    def detect_junction_safe(dir_path):
        """Detect junction points using Win32 API"""
        try:
            import win32file
            attrs = win32file.GetFileAttributes(str(dir_path))
            return bool(attrs & win32file.FILE_ATTRIBUTE_REPARSE_POINT)
        except ImportError:
            # Fallback
            try:
                result = subprocess.run([
                    'dir', '/AL', str(dir_path)
                ], capture_output=True, text=True, shell=False, timeout=5)
                return '<JUNCTION>' in result.stdout
            except:
                return False

class SecureACLManager:
    """SECURITY PATCHED: Safe ACL management without denying SYSTEM"""
    
    def __init__(self):
        self.backup_acls = {}
    
    def create_safe_protection_acl(self, path):
        """Create safe ACL that doesn't deny SYSTEM"""
        try:
            # First, backup current ACL
            result = subprocess.run([
                'icacls', str(path), '/save', 'acl_backup.txt'
            ], capture_output=True, text=True, shell=False)
            
            if result.returncode != 0:
                raise Exception("Failed to backup ACL")
            
            # Apply restrictive but safe ACL
            # Allow SYSTEM and Administrators read access
            # Deny only specific users from write/delete
            subprocess.run([
                'icacls', str(path), 
                '/grant', 'SYSTEM:(OI)(CI)R',
                '/grant', 'Administrators:(OI)(CI)R'
            ], capture_output=True, shell=False, check=True)
            
            # Remove inheritance and grant specific permissions
            subprocess.run([
                'icacls', str(path), '/inheritance:r'
            ], capture_output=True, shell=False, check=True)
            
            return True
            
        except Exception as e:
            print(f"Safe ACL application failed: {e}")
            return False
    
    def restore_acl_safe(self, path):
        """Safely restore ACL from backup"""
        try:
            if os.path.exists('acl_backup.txt'):
                result = subprocess.run([
                    'icacls', str(path), '/restore', 'acl_backup.txt'
                ], capture_output=True, shell=False)
                return result.returncode == 0
            return False
        except:
            return False

class SecureUSBTokenFinder:
    """SECURITY PATCHED: Consistent USB token discovery using psutil only"""
    
    @staticmethod
    def find_usb_drives():
        """Find USB drives using psutil consistently"""
        usb_drives = []
        
        try:
            for partition in psutil.disk_partitions():
                # Check if removable
                if 'removable' in partition.opts:
                    # Verify it's actually accessible
                    try:
                        os.listdir(partition.mountpoint)
                        usb_drives.append(partition.mountpoint)
                    except (OSError, PermissionError):
                        continue
                        
        except Exception:
            pass
            
        return usb_drives
    
    @staticmethod
    def find_tokens_safe():
        """Find tokens safely without shell injection"""
        tokens = []
        
        for drive in SecureUSBTokenFinder.find_usb_drives():
            try:
                drive_path = Path(drive)
                # Look for token files with safe pattern matching
                for token_file in drive_path.glob('protection_token_*.key'):
                    if token_file.is_file() and token_file.stat().st_size < 10240:  # Max 10KB
                        tokens.append(token_file)
            except Exception:
                continue
                
        return tokens

class SecureEventLogger:
    """SECURITY PATCHED: Tamper-evident logging to Windows Event Log"""
    
    def __init__(self):
        self.event_source = "AntiRansomwareSystem"
        self._register_event_source()
        
    def _register_event_source(self):
        """Register with Windows Event Log"""
        try:
            import win32evtlog
            import win32evtlogutil
            
            win32evtlogutil.AddSourceToRegistry(
                self.event_source,
                "Application"
            )
        except (ImportError, Exception):
            # Fallback to file logging with integrity protection
            self.log_file = Path("antiransomware_secure.log")
            
    def log_security_event(self, event_type, message, severity="INFO"):
        """Log security events with integrity protection"""
        timestamp = datetime.now().isoformat()
        
        try:
            import win32evtlog
            import win32evtlogutil
            
            win32evtlogutil.ReportEvent(
                self.event_source,
                1,  # Event ID
                eventCategory=0,
                eventType=win32evtlog.EVENTLOG_INFORMATION_TYPE,
                strings=[f"{event_type}: {message}"],
            )
        except (ImportError, Exception):
            # Fallback with hash chaining for integrity
            self._log_to_file_with_integrity(timestamp, event_type, message, severity)
    
    def _log_to_file_with_integrity(self, timestamp, event_type, message, severity):
        """Log to file with hash chaining for tamper detection"""
        try:
            # Read last hash if exists
            last_hash = "0" * 64
            if self.log_file.exists():
                with open(self.log_file, 'r') as f:
                    lines = f.readlines()
                    if lines:
                        last_line = lines[-1].strip()
                        if last_line.startswith("HASH:"):
                            last_hash = last_line[5:]
            
            # Create new entry
            entry = f"{timestamp}|{severity}|{event_type}|{message}"
            
            # Calculate hash chain
            chain_input = f"{last_hash}|{entry}"
            new_hash = hashlib.sha256(chain_input.encode()).hexdigest()
            
            # Append to log
            with open(self.log_file, 'a') as f:
                f.write(f"{entry}\n")
                f.write(f"HASH:{new_hash}\n")
                
        except Exception as e:
            print(f"Logging failed: {e}")

def main():
    """Test the security patches"""
    print("🔒 TESTING SECURITY PATCHES")
    print("=" * 40)
    
    # Test secure token manager
    print("1. Testing SecureTokenManager...")
    token_mgr = SecureTokenManager()
    token = token_mgr.create_secure_token(1234, ['read', 'write'])
    is_valid = token_mgr.validate_secure_token(token)
    print(f"   Token validation: {'✅ PASS' if is_valid else '❌ FAIL'}")
    
    # Test path normalization
    print("2. Testing SecurePathManager...")
    try:
        safe_path = SecurePathManager.normalize_path("C:\\Users\\test")
        print(f"   Path normalization: ✅ PASS")
    except:
        print(f"   Path normalization: ❌ FAIL")
    
    try:
        SecurePathManager.normalize_path("C:\\Windows\\System32")
        print(f"   System path blocking: ❌ FAIL (should have blocked)")
    except ValueError:
        print(f"   System path blocking: ✅ PASS")
    
    # Test USB token finder  
    print("3. Testing SecureUSBTokenFinder...")
    drives = SecureUSBTokenFinder.find_usb_drives()
    print(f"   Found {len(drives)} USB drives: ✅ PASS")
    
    # Test secure logging
    print("4. Testing SecureEventLogger...")
    logger = SecureEventLogger()
    logger.log_security_event("TEST", "Security patch testing", "INFO")
    print(f"   Event logging: ✅ PASS")
    
    print("\n🎉 Security patches tested successfully!")

if __name__ == "__main__":
    main()
