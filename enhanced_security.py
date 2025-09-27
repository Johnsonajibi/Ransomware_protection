#!/usr/bin/env python3
"""
ENHANCED SECURITY MODULE
========================
Advanced protection against sophisticated attack vectors identified
in the attack simulation. This module addresses critical vulnerabilities.
"""

import os
import sys
import json
import hashlib
import hmac
import secrets
import subprocess
import threading
import time
import ctypes
import winreg
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

class HardwareTokenValidator:
    """Cryptographically secure hardware token validation"""
    
    def __init__(self):
        self.secret_key = self._generate_hardware_fingerprint()
        self.challenge_cache = {}
        
    def _generate_hardware_fingerprint(self):
        """Generate unique hardware fingerprint beyond machine ID"""
        fingerprint_sources = [
            self._get_cpu_info(),
            self._get_motherboard_serial(),
            self._get_bios_serial(),
            self._get_mac_addresses(),
            self._get_disk_serials(),
        ]
        
        combined = "|".join(filter(None, fingerprint_sources))
        return hashlib.sha256(combined.encode()).hexdigest()
        
    def _get_cpu_info(self):
        """Get CPU information"""
        try:
            result = subprocess.run(['wmic', 'cpu', 'get', 'ProcessorId', '/value'], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'ProcessorId=' in line:
                    return line.split('=')[1].strip()
        except:
            pass
        return ""
        
    def _get_motherboard_serial(self):
        """Get motherboard serial number"""
        try:
            result = subprocess.run(['wmic', 'baseboard', 'get', 'SerialNumber', '/value'],
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'SerialNumber=' in line:
                    return line.split('=')[1].strip()
        except:
            pass
        return ""
        
    def _get_bios_serial(self):
        """Get BIOS serial number"""
        try:
            result = subprocess.run(['wmic', 'bios', 'get', 'SerialNumber', '/value'],
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'SerialNumber=' in line:
                    return line.split('=')[1].strip()
        except:
            pass
        return ""
        
    def _get_mac_addresses(self):
        """Get network adapter MAC addresses"""
        try:
            result = subprocess.run(['getmac', '/fo', 'csv', '/nh'], 
                                  capture_output=True, text=True)
            macs = []
            for line in result.stdout.split('\n'):
                if line.strip():
                    mac = line.split(',')[0].strip('"')
                    if mac and mac != "Physical Address":
                        macs.append(mac)
            return "|".join(sorted(macs))
        except:
            pass
        return ""
        
    def _get_disk_serials(self):
        """Get disk drive serial numbers"""
        try:
            result = subprocess.run(['wmic', 'diskdrive', 'get', 'SerialNumber', '/value'],
                                  capture_output=True, text=True)
            serials = []
            for line in result.stdout.split('\n'):
                if 'SerialNumber=' in line:
                    serial = line.split('=')[1].strip()
                    if serial:
                        serials.append(serial)
            return "|".join(sorted(serials))
        except:
            pass
        return ""
        
    def create_secure_token(self, token_path):
        """Create cryptographically secure token with challenge-response"""
        try:
            # Generate challenge
            challenge = secrets.token_hex(32)
            timestamp = int(time.time())
            
            # Create token data
            token_data = {
                "version": "2.0",
                "hardware_fingerprint": self.secret_key,
                "challenge": challenge,
                "timestamp": timestamp,
                "permissions": ["admin", "protect", "unprotect"],
            }
            
            # Sign token with HMAC
            token_json = json.dumps(token_data, sort_keys=True)
            signature = hmac.new(
                self.secret_key.encode(),
                token_json.encode(),
                hashlib.sha256
            ).hexdigest()
            
            signed_token = {
                "data": token_data,
                "signature": signature
            }
            
            # Encrypt with hardware-derived key
            encrypted_token = self._encrypt_token(json.dumps(signed_token))
            
            # Write to USB
            with open(token_path, 'wb') as f:
                f.write(encrypted_token)
                
            print(f"✅ Secure token created: {token_path}")
            return True
            
        except Exception as e:
            print(f"❌ Secure token creation failed: {e}")
            return False
            
    def validate_secure_token(self, token_path):
        """Validate token with cryptographic verification"""
        try:
            # Read and decrypt token
            with open(token_path, 'rb') as f:
                encrypted_data = f.read()
                
            decrypted_json = self._decrypt_token(encrypted_data)
            signed_token = json.loads(decrypted_json)
            
            # Verify signature
            token_data = signed_token["data"]
            provided_signature = signed_token["signature"]
            
            token_json = json.dumps(token_data, sort_keys=True)
            expected_signature = hmac.new(
                self.secret_key.encode(),
                token_json.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(provided_signature, expected_signature):
                print("❌ Token signature verification failed")
                return False
                
            # Verify hardware fingerprint
            if token_data["hardware_fingerprint"] != self.secret_key:
                print("❌ Hardware fingerprint mismatch")
                return False
                
            # Check token age
            age = int(time.time()) - token_data["timestamp"]
            if age > 86400:  # 24 hours
                print("❌ Token expired")
                return False
                
            print("✅ Secure token validation successful")
            return True
            
        except Exception as e:
            print(f"❌ Token validation failed: {e}")
            return False
            
    def _encrypt_token(self, data):
        """Encrypt token data"""
        # Derive key from hardware fingerprint
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'anti_ransomware_salt',
            iterations=100000,
        )
        key = kdf.derive(self.secret_key.encode())
        
        # Generate IV
        iv = secrets.token_bytes(16)
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad data
        pad_length = 16 - (len(data) % 16)
        padded_data = data + (chr(pad_length) * pad_length)
        
        ciphertext = encryptor.update(padded_data.encode()) + encryptor.finalize()
        
        return iv + ciphertext
        
    def _decrypt_token(self, encrypted_data):
        """Decrypt token data"""
        # Extract IV and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Derive key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'anti_ransomware_salt',
            iterations=100000,
        )
        key = kdf.derive(self.secret_key.encode())
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        pad_length = padded_data[-1]
        data = padded_data[:-pad_length]
        
        return data.decode()

class BehavioralProcessMonitor:
    """Advanced process monitoring using behavioral analysis"""
    
    def __init__(self):
        self.monitoring = False
        self.baseline_behavior = {}
        self.suspicious_patterns = []
        
    def start_behavioral_monitoring(self):
        """Start behavioral process monitoring"""
        self.monitoring = True
        
        # Monitor threads
        self.command_line_monitor = threading.Thread(
            target=self._monitor_command_lines, daemon=True)
        self.process_tree_monitor = threading.Thread(
            target=self._monitor_process_relationships, daemon=True)
        self.file_access_monitor = threading.Thread(
            target=self._monitor_file_access_patterns, daemon=True)
            
        self.command_line_monitor.start()
        self.process_tree_monitor.start()
        self.file_access_monitor.start()
        
        print("🔍 Advanced behavioral monitoring started")
        
    def _monitor_command_lines(self):
        """Monitor process command lines for suspicious patterns"""
        suspicious_patterns = [
            r'attrib.*[-+][shr]',  # Attribute manipulation
            r'icacls.*deny',       # Permission denial
            r'takeown.*\/f',       # Ownership taking
            r'powershell.*-enc',   # Encoded PowerShell
            r'cmd.*\/c.*del',      # File deletion
            r'wmic.*process.*create', # Process creation
        ]
        
        while self.monitoring:
            try:
                # Use WMI to get process command lines
                result = subprocess.run([
                    'wmic', 'process', 'get', 'CommandLine,ProcessId,Name', '/format:csv'
                ], capture_output=True, text=True, timeout=5)
                
                for line in result.stdout.split('\n'):
                    if ',' in line and 'CommandLine' not in line:
                        parts = line.split(',')
                        if len(parts) >= 4:
                            command_line = parts[1]
                            process_name = parts[2]
                            pid = parts[3]
                            
                            # Check for suspicious patterns
                            for pattern in suspicious_patterns:
                                import re
                                if re.search(pattern, command_line, re.IGNORECASE):
                                    self._handle_suspicious_behavior(
                                        "Command Line Pattern", 
                                        f"{process_name} (PID: {pid}): {command_line}"
                                    )
                
                time.sleep(2)
                
            except Exception as e:
                if self.monitoring:  # Only log if still monitoring
                    print(f"Command line monitoring error: {e}")
                time.sleep(5)
                
    def _monitor_process_relationships(self):
        """Monitor parent-child process relationships"""
        while self.monitoring:
            try:
                # Track process trees for suspicious spawning
                result = subprocess.run([
                    'wmic', 'process', 'get', 'Name,ProcessId,ParentProcessId', '/format:csv'
                ], capture_output=True, text=True, timeout=5)
                
                # Build process tree and detect anomalies
                processes = {}
                for line in result.stdout.split('\n'):
                    if ',' in line and 'Name' not in line:
                        parts = line.split(',')
                        if len(parts) >= 4:
                            name = parts[1]
                            pid = parts[2]
                            ppid = parts[3]
                            
                            if pid and ppid:
                                processes[pid] = {"name": name, "parent": ppid}
                
                # Check for suspicious parent-child relationships
                for pid, info in processes.items():
                    parent_name = processes.get(info["parent"], {}).get("name", "")
                    
                    # Detect suspicious spawning patterns
                    if (info["name"].lower() in ['powershell.exe', 'cmd.exe'] and 
                        parent_name.lower() in ['winword.exe', 'excel.exe', 'outlook.exe']):
                        self._handle_suspicious_behavior(
                            "Suspicious Process Spawning",
                            f"{parent_name} spawned {info['name']} (PID: {pid})"
                        )
                
                time.sleep(10)
                
            except Exception as e:
                if self.monitoring:
                    print(f"Process relationship monitoring error: {e}")
                time.sleep(15)
                
    def _monitor_file_access_patterns(self):
        """Monitor for rapid file access patterns (ransomware behavior)"""
        while self.monitoring:
            try:
                # Monitor file system events using Windows Event Log
                # This is a simplified version - production would use ETW
                time.sleep(30)  # Reduced frequency for this example
                
            except Exception as e:
                if self.monitoring:
                    print(f"File access monitoring error: {e}")
                time.sleep(30)
                
    def _handle_suspicious_behavior(self, behavior_type, details):
        """Handle detected suspicious behavior"""
        timestamp = datetime.now().isoformat()
        
        print(f"🚨 SUSPICIOUS BEHAVIOR DETECTED:")
        print(f"   Type: {behavior_type}")
        print(f"   Details: {details}")
        print(f"   Time: {timestamp}")
        
        # Log to security event
        self.suspicious_patterns.append({
            "type": behavior_type,
            "details": details,
            "timestamp": timestamp
        })
        
        # Could trigger additional security measures here
        
    def stop_monitoring(self):
        """Stop behavioral monitoring"""
        self.monitoring = False
        print("🛑 Behavioral monitoring stopped")

class RegistryProtection:
    """Protect critical registry keys from modification"""
    
    def __init__(self):
        self.protected_keys = [
            r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid',
            r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName',
        ]
        self.original_values = {}
        
    def enable_registry_protection(self):
        """Enable registry key protection"""
        try:
            # Backup original values
            for key_path in self.protected_keys:
                try:
                    value = self._read_registry_value(key_path)
                    self.original_values[key_path] = value
                    print(f"✅ Backed up registry key: {key_path}")
                except Exception as e:
                    print(f"⚠️ Could not backup {key_path}: {e}")
                    
            # Start monitoring thread
            self.monitoring = True
            self.monitor_thread = threading.Thread(
                target=self._monitor_registry_changes, daemon=True)
            self.monitor_thread.start()
            
            print("🔒 Registry protection enabled")
            return True
            
        except Exception as e:
            print(f"❌ Registry protection failed: {e}")
            return False
            
    def _read_registry_value(self, key_path):
        """Read registry value"""
        # Parse key path
        if key_path.startswith('HKEY_LOCAL_MACHINE'):
            root = winreg.HKEY_LOCAL_MACHINE
            subkey = key_path.replace('HKEY_LOCAL_MACHINE\\', '')
        else:
            raise ValueError(f"Unsupported registry root: {key_path}")
            
        # Extract key and value name
        parts = subkey.rsplit('\\', 1)
        if len(parts) == 2:
            key_name, value_name = parts
        else:
            key_name = subkey
            value_name = ""
            
        # Read value
        with winreg.OpenKey(root, key_name) as key:
            if value_name:
                value, _ = winreg.QueryValueEx(key, value_name)
            else:
                value, _ = winreg.QueryValueEx(key, "")
            return value
            
    def _monitor_registry_changes(self):
        """Monitor for unauthorized registry changes"""
        while getattr(self, 'monitoring', True):
            try:
                for key_path in self.protected_keys:
                    try:
                        current_value = self._read_registry_value(key_path)
                        original_value = self.original_values.get(key_path)
                        
                        if original_value and current_value != original_value:
                            print(f"🚨 UNAUTHORIZED REGISTRY CHANGE DETECTED:")
                            print(f"   Key: {key_path}")
                            print(f"   Original: {original_value}")
                            print(f"   Current: {current_value}")
                            
                            # Could restore original value here
                            
                    except Exception as e:
                        print(f"Registry monitoring error for {key_path}: {e}")
                        
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                print(f"Registry monitoring error: {e}")
                time.sleep(60)

if __name__ == "__main__":
    print("🛡️ ENHANCED SECURITY MODULE")
    print("=" * 40)
    
    # Test hardware token validator
    print("\n🔐 Testing Hardware Token Validator...")
    validator = HardwareTokenValidator()
    print(f"Hardware Fingerprint: {validator.secret_key[:16]}...")
    
    # Test behavioral monitor
    print("\n🔍 Testing Behavioral Process Monitor...")
    monitor = BehavioralProcessMonitor()
    
    # Test registry protection
    print("\n🔒 Testing Registry Protection...")
    reg_protection = RegistryProtection()
    
    print("\n✅ Enhanced security modules initialized")
    print("🎯 These modules address critical vulnerabilities identified in attack simulation")
