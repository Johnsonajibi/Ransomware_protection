"""
USB Token Management for Immune Folders
Handles USB token detection, validation, and secure key storage
"""

import os
import sys
import json
import time
import uuid
import hmac
import hashlib
import secrets  
import threading
from pathlib import Path
from typing import Optional, Dict, List, Callable, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

# Windows-specific imports for USB detection
try:
    import win32file
    import win32api
    import win32con
    import win32security
    import wmi
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False
    print("Warning: Windows modules not available. USB detection disabled.")

@dataclass 
class TokenInfo:
    """USB token information and metadata"""
    token_id: str
    device_serial: str
    device_path: str
    drive_letter: str
    volume_label: str
    folder_permissions: Dict[str, List[str]]
    created_timestamp: int
    last_used_timestamp: int
    use_count: int
    is_valid: bool

@dataclass
class TokenValidationResult:
    """Result of token validation"""
    is_valid: bool
    token_info: Optional[TokenInfo]
    error_message: str
    folders_accessible: List[str]

class USBDeviceMonitor:
    """Monitors USB device insertion/removal events"""
    
    def __init__(self, callback: Callable[[str, bool], None]):
        self.callback = callback
        self.monitoring = False
        self.monitor_thread = None
        
    def start_monitoring(self):
        """Start monitoring USB device events"""
        if not WINDOWS_AVAILABLE:
            print("USB monitoring not available on this system")
            return
            
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print("USB device monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring USB device events"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        print("USB device monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop using WMI events"""
        try:
            c = wmi.WMI()
            
            # Monitor for device arrival
            arrival_watcher = c.Win32_VolumeChangeEvent.watch_for(
                EventType=2,  # Device arrival
                timeout_ms=1000
            )
            
            # Monitor for device removal  
            removal_watcher = c.Win32_VolumeChangeEvent.watch_for(
                EventType=3,  # Device removal
                timeout_ms=1000
            )
            
            print("WMI event monitoring active")
            
            while self.monitoring:
                try:
                    # Check for device arrival
                    arrival_event = arrival_watcher(timeout_ms=500)
                    if arrival_event:
                        drive_name = arrival_event.DriveName
                        if self._is_removable_drive(drive_name):
                            print(f"USB device inserted: {drive_name}")
                            self.callback(drive_name, True)
                
                except wmi.x_wmi_timed_out:
                    pass  # Normal timeout, continue monitoring
                
                try:
                    # Check for device removal
                    removal_event = removal_watcher(timeout_ms=500)
                    if removal_event:
                        drive_name = removal_event.DriveName
                        print(f"USB device removed: {drive_name}")
                        self.callback(drive_name, False)
                        
                except wmi.x_wmi_timed_out:
                    pass  # Normal timeout, continue monitoring
                    
                except Exception as e:
                    if self.monitoring:  # Only log if we're still supposed to be monitoring
                        print(f"USB monitoring error: {e}")
                    
                time.sleep(0.1)  # Small delay to prevent excessive CPU usage
                
        except Exception as e:
            print(f"USB monitoring setup failed: {e}")
    
    def _is_removable_drive(self, drive_name: str) -> bool:
        """Check if a drive is a removable USB device"""
        try:
            drive_type = win32file.GetDriveType(drive_name)
            return drive_type == win32con.DRIVE_REMOVABLE
        except Exception:
            return False

class USBTokenManager:
    """Main USB token management class"""
    
    def __init__(self, token_store_path: str = None):
        self.token_store_path = Path(token_store_path or 
                                   os.path.join(os.getenv('PROGRAMDATA', 'C:\\ProgramData'),
                                              'ImmuneFolders', 'tokens'))
        self.token_store_path.mkdir(parents=True, exist_ok=True)
        
        self.device_monitor = USBDeviceMonitor(self._on_usb_event)
        self.token_callbacks: List[Callable[[TokenValidationResult], None]] = []
        self.current_token: Optional[TokenInfo] = None
        
        # Token validation settings
        self.token_timeout_minutes = 30
        self.max_failed_attempts = 5
        self.failed_attempts = {}
        
        # Start monitoring
        self.device_monitor.start_monitoring()
    
    def register_token_callback(self, callback: Callable[[TokenValidationResult], None]):
        """Register callback for token events"""
        self.token_callbacks.append(callback)
    
    def _on_usb_event(self, drive_name: str, inserted: bool):
        """Handle USB device insertion/removal"""
        if inserted:
            # Small delay to allow device to be ready
            time.sleep(2)
            self._check_token_on_drive(drive_name)
        else:
            # Handle token removal
            if self.current_token and self.current_token.drive_letter == drive_name:
                print(f"Current token removed from {drive_name}")
                self.current_token = None
                self._notify_callbacks(TokenValidationResult(
                    is_valid=False,
                    token_info=None,
                    error_message="Token removed",
                    folders_accessible=[]
                ))
    
    def _check_token_on_drive(self, drive_name: str):
        """Check if inserted drive contains a valid token"""
        try:
            token_file = Path(drive_name) / "immune_token.json"
            if token_file.exists():
                print(f"Found potential token on {drive_name}")
                result = self.validate_token(str(token_file))
                if result.is_valid:
                    self.current_token = result.token_info
                    print(f"Valid token detected: {result.token_info.token_id}")
                else:
                    print(f"Invalid token on {drive_name}: {result.error_message}")
                
                self._notify_callbacks(result)
            else:
                print(f"No token file found on {drive_name}")
                
        except Exception as e:
            print(f"Error checking token on {drive_name}: {e}")
    
    def _notify_callbacks(self, result: TokenValidationResult):
        """Notify all registered callbacks of token events"""
        for callback in self.token_callbacks:
            try:
                callback(result)
            except Exception as e:
                print(f"Token callback error: {e}")
    
    def create_token(self, drive_path: str, folder_permissions: Dict[str, List[str]], 
                    token_label: str = "ImmuneFolders") -> Optional[str]:
        """Create a new USB token"""
        try:
            drive_path = Path(drive_path)
            if not drive_path.exists():
                print(f"Drive path does not exist: {drive_path}")
                return None
            
            # Generate unique token ID
            token_id = str(uuid.uuid4())
            
            # Get device information
            device_info = self._get_device_info(str(drive_path))
            if not device_info:
                print("Could not get device information")
                return None
            
            # Create token data
            token_data = {
                "token_id": token_id,
                "device_serial": device_info["serial"],
                "device_path": str(drive_path),
                "drive_letter": str(drive_path)[0:2],  # E.g., "E:"
                "volume_label": token_label,
                "folder_permissions": folder_permissions,
                "created_timestamp": int(time.time()),
                "last_used_timestamp": int(time.time()),
                "use_count": 0,
                "is_valid": True,
                "version": 1
            }
            
            # Generate token signature
            token_signature = self._generate_token_signature(token_data)
            token_data["signature"] = token_signature
            
            # Write token file to USB drive
            token_file = drive_path / "immune_token.json"
            with open(token_file, 'w') as f:
                json.dump(token_data, f, indent=2)
            
            # Make file hidden and read-only
            self._secure_token_file(token_file)
            
            # Store token metadata locally  
            self._store_token_metadata(token_id, token_data)
            
            print(f"Token created successfully: {token_id}")
            return token_id
            
        except Exception as e:
            print(f"Token creation failed: {e}")
            return None
    
    def validate_token(self, token_file_path: str) -> TokenValidationResult:
        """Validate a USB token"""
        try:
            # Check rate limiting
            device_id = self._get_device_id_from_path(token_file_path)
            if self._is_rate_limited(device_id):
                return TokenValidationResult(
                    is_valid=False,
                    token_info=None,
                    error_message="Too many failed attempts. Try again later.",
                    folders_accessible=[]
                )
            
            # Load token data
            with open(token_file_path, 'r') as f:
                token_data = json.load(f)
            
            # Basic structure validation
            required_fields = ["token_id", "device_serial", "folder_permissions", 
                             "created_timestamp", "signature"]
            for field in required_fields:
                if field not in token_data:
                    self._record_failed_attempt(device_id)
                    return TokenValidationResult(
                        is_valid=False,
                        token_info=None,
                        error_message=f"Missing required field: {field}",
                        folders_accessible=[]
                    )
            
            # Verify token signature
            if not self._verify_token_signature(token_data):
                self._record_failed_attempt(device_id)
                return TokenValidationResult(
                    is_valid=False,
                    token_info=None,
                    error_message="Invalid token signature",
                    folders_accessible=[]
                )
            
            # Check if token is still valid
            if not token_data.get("is_valid", False):
                return TokenValidationResult(
                    is_valid=False,
                    token_info=None,
                    error_message="Token has been revoked",
                    folders_accessible=[]
                )
            
            # Verify device binding
            current_device_info = self._get_device_info(os.path.dirname(token_file_path))
            if (current_device_info and 
                current_device_info["serial"] != token_data["device_serial"]):
                self._record_failed_attempt(device_id)
                return TokenValidationResult(
                    is_valid=False,
                    token_info=None,
                    error_message="Token device binding mismatch",
                    folders_accessible=[]
                )
            
            # Check token timeout
            last_used = token_data.get("last_used_timestamp", 0)
            if time.time() - last_used > self.token_timeout_minutes * 60:
                return TokenValidationResult(
                    is_valid=False,
                    token_info=None,
                    error_message="Token session expired",
                    folders_accessible=[]
                )
            
            # Update usage statistics
            token_data["last_used_timestamp"] = int(time.time())
            token_data["use_count"] = token_data.get("use_count", 0) + 1
            
            # Save updated token data
            with open(token_file_path, 'w') as f:
                json.dump(token_data, f, indent=2)
            
            # Create TokenInfo object
            token_info = TokenInfo(
                token_id=token_data["token_id"],
                device_serial=token_data["device_serial"],
                device_path=os.path.dirname(token_file_path),
                drive_letter=token_data.get("drive_letter", ""),
                volume_label=token_data.get("volume_label", ""),
                folder_permissions=token_data["folder_permissions"],
                created_timestamp=token_data["created_timestamp"],
                last_used_timestamp=token_data["last_used_timestamp"],
                use_count=token_data["use_count"],
                is_valid=token_data["is_valid"]
            )
            
            # Reset failed attempts on successful validation
            if device_id in self.failed_attempts:
                del self.failed_attempts[device_id]
            
            folders_accessible = list(token_data["folder_permissions"].keys())
            
            return TokenValidationResult(
                is_valid=True,
                token_info=token_info,
                error_message="",
                folders_accessible=folders_accessible
            )
            
        except Exception as e:
            device_id = self._get_device_id_from_path(token_file_path)
            self._record_failed_attempt(device_id)
            return TokenValidationResult(
                is_valid=False,
                token_info=None,
                error_message=f"Token validation error: {str(e)}",
                folders_accessible=[]
            )
    
    def revoke_token(self, token_id: str) -> bool:
        """Revoke a USB token"""
        try:
            # Find token metadata
            metadata = self._load_token_metadata(token_id)
            if not metadata:
                print(f"Token metadata not found: {token_id}")
                return False
            
            # Mark as invalid in local storage
            metadata["is_valid"] = False
            metadata["revoked_timestamp"] = int(time.time())
            self._store_token_metadata(token_id, metadata)
            
            # Try to update token file if accessible
            try:
                device_path = Path(metadata["device_path"])
                token_file = device_path / "immune_token.json"
                
                if token_file.exists():
                    with open(token_file, 'r') as f:
                        token_data = json.load(f)
                    
                    token_data["is_valid"] = False
                    token_data["revoked_timestamp"] = int(time.time())
                    
                    with open(token_file, 'w') as f:
                        json.dump(token_data, f, indent=2)
                    
                    print(f"Token file updated: {token_id}")
                
            except Exception as e:
                print(f"Could not update token file (device may not be connected): {e}")
            
            print(f"Token revoked: {token_id}")
            return True
            
        except Exception as e:
            print(f"Token revocation failed: {e}")
            return False
    
    def list_tokens(self) -> List[TokenInfo]:
        """List all registered tokens"""
        tokens = []
        try:
            for token_file in self.token_store_path.glob("token_*.meta"):
                try:
                    with open(token_file, 'r') as f:
                        metadata = json.load(f)
                    
                    token_info = TokenInfo(
                        token_id=metadata["token_id"],
                        device_serial=metadata["device_serial"],
                        device_path=metadata["device_path"],
                        drive_letter=metadata.get("drive_letter", ""),
                        volume_label=metadata.get("volume_label", ""),
                        folder_permissions=metadata["folder_permissions"],
                        created_timestamp=metadata["created_timestamp"],
                        last_used_timestamp=metadata.get("last_used_timestamp", 0),
                        use_count=metadata.get("use_count", 0),
                        is_valid=metadata.get("is_valid", True)
                    )
                    
                    tokens.append(token_info)
                    
                except Exception as e:
                    print(f"Error loading token metadata from {token_file}: {e}")
            
        except Exception as e:
            print(f"Error listing tokens: {e}")
        
        return tokens
    
    def get_current_token(self) -> Optional[TokenInfo]:
        """Get currently active token"""
        return self.current_token
    
    def _generate_token_signature(self, token_data: Dict[str, Any]) -> str:
        """Generate HMAC signature for token data"""
        # Use device-specific key for signing
        signing_key = self._get_signing_key()
        
        # Create canonical representation of data for signing
        sign_data = {
            "token_id": token_data["token_id"],
            "device_serial": token_data["device_serial"],
            "folder_permissions": token_data["folder_permissions"],
            "created_timestamp": token_data["created_timestamp"]
        }
        
        canonical_data = json.dumps(sign_data, sort_keys=True, separators=(',', ':'))
        
        signature = hmac.new(
            signing_key.encode('utf-8'),
            canonical_data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def _verify_token_signature(self, token_data: Dict[str, Any]) -> bool:
        """Verify token HMAC signature"""
        try:
            stored_signature = token_data.get("signature", "")
            
            # Remove signature for verification
            token_copy = token_data.copy()
            del token_copy["signature"]
            
            # Remove fields that shouldn't affect signature
            fields_to_remove = ["last_used_timestamp", "use_count", "revoked_timestamp"]
            for field in fields_to_remove:
                token_copy.pop(field, None)
            
            expected_signature = self._generate_token_signature(token_copy)
            
            return hmac.compare_digest(stored_signature, expected_signature)
            
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False
    
    def _get_signing_key(self) -> str:
        """Get device-specific signing key"""
        # In production, this should be derived from hardware characteristics
        # and stored securely (e.g., using DPAPI)
        try:
            machine_guid = win32api.GetComputerName() if WINDOWS_AVAILABLE else "unknown"
            return f"ImmuneFolders-{machine_guid}-SigningKey"
        except:
            return "ImmuneFolders-Default-SigningKey"
    
    def _get_device_info(self, drive_path: str) -> Optional[Dict[str, str]]:
        """Get USB device information"""
        if not WINDOWS_AVAILABLE:
            return {"serial": "unknown", "model": "unknown"}
            
        try:
            c = wmi.WMI()
            
            # Get drive letter from path
            drive_letter = Path(drive_path).parts[0].rstrip('\\')
            
            # Find logical disk
            for disk in c.Win32_LogicalDisk():
                if disk.DeviceID == drive_letter:
                    # Get associated physical drive
                    for partition in c.Win32_LogicalDiskToPartition():
                        if partition.Dependent.DeviceID == disk.DeviceID:
                            for disk_drive in c.Win32_DiskDriveToDiskPartition():
                                if disk_drive.Dependent.DeviceID == partition.Antecedent.DeviceID:
                                    drive = disk_drive.Antecedent
                                    return {
                                        "serial": drive.SerialNumber or "unknown",
                                        "model": drive.Model or "unknown",
                                        "interface": drive.InterfaceType or "unknown"
                                    }
            
            return {"serial": "unknown", "model": "unknown"}
            
        except Exception as e:
            print(f"Error getting device info: {e}")
            return {"serial": "unknown", "model": "unknown"}
    
    def _get_device_id_from_path(self, token_file_path: str) -> str:
        """Extract device identifier from token file path"""
        try:
            device_info = self._get_device_info(os.path.dirname(token_file_path))
            return device_info.get("serial", "unknown")
        except:
            return "unknown"
    
    def _is_rate_limited(self, device_id: str) -> bool:
        """Check if device is rate limited due to failed attempts"""
        if device_id not in self.failed_attempts:
            return False
        
        attempts, last_attempt = self.failed_attempts[device_id]
        
        # Reset if enough time has passed
        if time.time() - last_attempt > 300:  # 5 minutes
            del self.failed_attempts[device_id]
            return False
        
        return attempts >= self.max_failed_attempts
    
    def _record_failed_attempt(self, device_id: str):
        """Record a failed token validation attempt"""
        current_time = time.time()
        
        if device_id in self.failed_attempts:
            attempts, _ = self.failed_attempts[device_id]
            self.failed_attempts[device_id] = (attempts + 1, current_time)
        else:
            self.failed_attempts[device_id] = (1, current_time)
    
    def _store_token_metadata(self, token_id: str, metadata: Dict[str, Any]):
        """Store token metadata locally"""
        metadata_file = self.token_store_path / f"token_{token_id}.meta"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def _load_token_metadata(self, token_id: str) -> Optional[Dict[str, Any]]:
        """Load token metadata from local storage"""
        try:
            metadata_file = self.token_store_path / f"token_{token_id}.meta"
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading token metadata: {e}")
        
        return None
    
    def _secure_token_file(self, token_file: Path):
        """Set secure attributes on token file"""
        try:
            if WINDOWS_AVAILABLE:
                # Set file as hidden and read-only
                win32api.SetFileAttributes(
                    str(token_file),
                    win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_READONLY
                )
        except Exception as e:
            print(f"Warning: Could not set secure file attributes: {e}")
    
    def cleanup(self):
        """Cleanup resources"""
        self.device_monitor.stop_monitoring()
        print("USB token manager cleanup complete")

# Token management utilities
class TokenUtils:
    """Utility functions for token management"""
    
    @staticmethod
    def generate_qr_recovery_data(token_info: TokenInfo, recovery_passphrase: str) -> str:
        """Generate QR code data for token recovery"""
        recovery_data = {
            "token_id": token_info.token_id,
            "folder_permissions": token_info.folder_permissions,
            "recovery_timestamp": int(time.time())
        }
        
        # Encrypt with recovery passphrase
        # This is a simplified version - production should use proper encryption
        import base64
        data_json = json.dumps(recovery_data)
        encoded_data = base64.b64encode(data_json.encode('utf-8')).decode('ascii')
        
        return f"ImmuneFolders:Recovery:{encoded_data}"
    
    @staticmethod
    def parse_qr_recovery_data(qr_data: str, recovery_passphrase: str) -> Optional[Dict[str, Any]]:
        """Parse QR recovery data"""
        try:
            if not qr_data.startswith("ImmuneFolders:Recovery:"):
                return None
            
            import base64
            encoded_data = qr_data[23:]  # Remove prefix
            data_json = base64.b64decode(encoded_data).decode('utf-8')
            recovery_data = json.loads(data_json)
            
            return recovery_data
            
        except Exception as e:
            print(f"QR recovery data parsing failed: {e}")
            return None
    
    @staticmethod
    def backup_token_to_file(token_info: TokenInfo, backup_path: str) -> bool:
        """Create encrypted backup of token"""
        try:
            backup_data = {
                "token_info": asdict(token_info),
                "backup_timestamp": int(time.time()),
                "backup_version": 1
            }
            
            with open(backup_path, 'w') as f:
                json.dump(backup_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Token backup failed: {e}")
            return False

# Test and example usage
if __name__ == "__main__":
    # Test USB token manager
    token_manager = USBTokenManager()
    
    # Example folder permissions
    folder_permissions = {
        "documents": ["read", "write"],
        "projects": ["read", "write"],
        "backup": ["read"]
    }
    
    print("USB Token Manager initialized")
    print("Insert a USB drive to test token creation...")
    
    # Register a callback to handle token events
    def token_event_handler(result: TokenValidationResult):
        if result.is_valid:
            print(f"✓ Valid token detected: {result.token_info.token_id}")
            print(f"  Accessible folders: {', '.join(result.folders_accessible)}")
        else:
            print(f"✗ Token validation failed: {result.error_message}")
    
    token_manager.register_token_callback(token_event_handler)
    
    # Keep program running to monitor USB events
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        token_manager.cleanup()
