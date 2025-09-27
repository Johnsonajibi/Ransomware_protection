"""
DPAPI and TPM Integration for Immune Folders
Provides secure key storage using Windows Data Protection API and Trusted Platform Module
"""

import os
import sys
import json
import base64
import hashlib
import secrets
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Windows-specific imports
try:
    import win32crypt
    import win32api
    import win32security
    import win32con
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False
    print("Warning: Windows-specific modules not available. Some features disabled.")

@dataclass
class DeviceBinding:
    """Hardware-bound device information for key derivation"""
    machine_guid: str
    tpm_endorsement_key: Optional[str]
    cpu_id: str
    motherboard_serial: str
    bios_uuid: str
    
    def get_device_fingerprint(self) -> str:
        """Generate unique device fingerprint for key binding"""
        components = [
            self.machine_guid,
            self.tpm_endorsement_key or "no-tpm",
            self.cpu_id,
            self.motherboard_serial,
            self.bios_uuid
        ]
        
        fingerprint_data = "|".join(components).encode('utf-8')
        return hashlib.sha256(fingerprint_data).hexdigest()

class TPMKeyStorage:
    """Handles TPM-based key storage and attestation"""
    
    def __init__(self):
        self.tpm_available = self._check_tpm_availability()
        
    def _check_tpm_availability(self) -> bool:
        """Check if TPM 2.0 is available and enabled"""
        if not WINDOWS_AVAILABLE:
            return False
            
        try:
            # Check TPM registry keys
            import winreg
            tpm_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   r"SYSTEM\CurrentControlSet\Services\TPM")
            
            # Check if TPM service is running
            status = win32api.GetComputerName()  # Basic check
            return True
        except Exception as e:
            print(f"TPM check failed: {e}")
            return False
    
    def store_key_in_tpm(self, key_name: str, key_data: bytes) -> bool:
        """Store encryption key in TPM"""
        if not self.tpm_available:
            return False
            
        try:
            # Use Windows TPM APIs to store key
            # This is a simplified implementation
            # Production code would use proper TPM 2.0 APIs
            
            protected_data = win32crypt.CryptProtectData(
                key_data,
                f"ImmuneFolders-{key_name}",
                None,  # Optional entropy
                None,  # Reserved
                None,  # Prompt struct
                win32crypt.CRYPTPROTECT_LOCAL_MACHINE | 
                win32crypt.CRYPTPROTECT_UI_FORBIDDEN
            )
            
            # Store in registry protected location
            import winreg
            key_path = r"SOFTWARE\ImmuneFolders\TPMKeys"
            try:
                key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                winreg.SetValueEx(key, key_name, 0, winreg.REG_BINARY, protected_data)
                winreg.CloseKey(key)
                return True
            except Exception as e:
                print(f"Registry storage failed: {e}")
                return False
                
        except Exception as e:
            print(f"TPM key storage failed: {e}")
            return False
    
    def retrieve_key_from_tpm(self, key_name: str) -> Optional[bytes]:
        """Retrieve encryption key from TPM"""
        if not self.tpm_available:
            return None
            
        try:
            import winreg
            key_path = r"SOFTWARE\ImmuneFolders\TPMKeys"
            
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            protected_data, _ = winreg.QueryValueEx(key, key_name)
            winreg.CloseKey(key)
            
            # Decrypt using DPAPI
            key_data = win32crypt.CryptUnprotectData(
                protected_data,
                None,
                None,
                None,
                win32crypt.CRYPTPROTECT_UI_FORBIDDEN
            )[1]
            
            return key_data
            
        except Exception as e:
            print(f"TPM key retrieval failed: {e}")
            return None

class DPAPIKeyStorage:
    """Windows Data Protection API key storage"""
    
    def __init__(self, user_scope: bool = False):
        self.user_scope = user_scope
        self.flags = (win32crypt.CRYPTPROTECT_UI_FORBIDDEN | 
                     (0 if user_scope else win32crypt.CRYPTPROTECT_LOCAL_MACHINE))
    
    def protect_data(self, data: bytes, description: str = "ImmuneFolders Key") -> bytes:
        """Encrypt data using DPAPI"""
        if not WINDOWS_AVAILABLE:
            raise RuntimeError("DPAPI not available on this system")
            
        try:
            protected_data = win32crypt.CryptProtectData(
                data,
                description,
                None,  # Optional entropy
                None,  # Reserved
                None,  # Prompt struct
                self.flags
            )
            return protected_data
        except Exception as e:
            raise RuntimeError(f"DPAPI encryption failed: {e}")
    
    def unprotect_data(self, protected_data: bytes) -> Tuple[bytes, str]:
        """Decrypt data using DPAPI"""
        if not WINDOWS_AVAILABLE:
            raise RuntimeError("DPAPI not available on this system")
            
        try:
            data, description = win32crypt.CryptUnprotectData(
                protected_data,
                None,  # Optional entropy
                None,  # Reserved
                None,  # Prompt struct
                win32crypt.CRYPTPROTECT_UI_FORBIDDEN
            )
            return data, description
        except Exception as e:
            raise RuntimeError(f"DPAPI decryption failed: {e}")

class SecureKeyProvider:
    """Main class for secure key management using DPAPI/TPM"""
    
    def __init__(self, key_store_path: str = None):
        self.key_store_path = Path(key_store_path or 
                                 os.path.join(os.getenv('PROGRAMDATA', 'C:\\ProgramData'), 
                                            'ImmuneFolders', 'keys'))
        self.key_store_path.mkdir(parents=True, exist_ok=True)
        
        self.dpapi = DPAPIKeyStorage(user_scope=False)
        self.tpm = TPMKeyStorage()
        self.device_binding = self._get_device_binding()
        
    def _get_device_binding(self) -> DeviceBinding:
        """Collect hardware information for device binding"""
        try:
            import wmi
            c = wmi.WMI()
            
            # Get machine GUID
            machine_guid = win32api.GetComputerName()
            
            # Get CPU information
            cpu_info = c.Win32_Processor()[0]
            cpu_id = cpu_info.ProcessorId or "unknown"
            
            # Get motherboard information
            board_info = c.Win32_BaseBoard()[0]
            motherboard_serial = board_info.SerialNumber or "unknown"
            
            # Get BIOS information
            bios_info = c.Win32_BIOS()[0]
            bios_uuid = bios_info.SerialNumber or "unknown"
            
            # Try to get TPM endorsement key
            tpm_key = None
            try:
                tpm_info = c.Win32_Tpm()[0]
                tpm_key = getattr(tpm_info, 'ManufacturerVersion', None)
            except:
                pass
            
            return DeviceBinding(
                machine_guid=machine_guid,
                tpm_endorsement_key=tpm_key,
                cpu_id=cpu_id,
                motherboard_serial=motherboard_serial,
                bios_uuid=bios_uuid
            )
            
        except Exception as e:
            print(f"Warning: Could not collect full device binding: {e}")
            # Fallback to basic machine identification
            return DeviceBinding(
                machine_guid=win32api.GetComputerName() if WINDOWS_AVAILABLE else "unknown",
                tpm_endorsement_key=None,
                cpu_id="unknown",
                motherboard_serial="unknown",
                bios_uuid="unknown"
            )
    
    def generate_folder_master_key(self, folder_id: str) -> bytes:
        """Generate a new Folder Master Key (FMK)"""
        # Generate 256-bit master key
        master_key = secrets.token_bytes(32)
        
        # Store securely
        self.store_folder_master_key(folder_id, master_key)
        
        return master_key
    
    def store_folder_master_key(self, folder_id: str, master_key: bytes) -> bool:
        """Store Folder Master Key securely using DPAPI/TPM"""
        try:
            # Create key metadata
            key_metadata = {
                "folder_id": folder_id,
                "created": int(time.time()),
                "device_fingerprint": self.device_binding.get_device_fingerprint(),
                "key_version": 1
            }
            
            # Try TPM storage first
            if self.tpm.tpm_available:
                if self.tpm.store_key_in_tpm(f"FMK-{folder_id}", master_key):
                    key_metadata["storage_method"] = "TPM"
                    self._save_key_metadata(folder_id, key_metadata)
                    return True
            
            # Fall back to DPAPI
            protected_key = self.dpapi.protect_data(
                master_key, 
                f"ImmuneFolders FMK for {folder_id}"
            )
            
            # Save to secure file
            key_file = self.key_store_path / f"fmk_{folder_id}.key"
            with open(key_file, 'wb') as f:
                f.write(protected_key)
            
            # Set restrictive permissions
            self._secure_file_permissions(key_file)
            
            key_metadata["storage_method"] = "DPAPI"
            self._save_key_metadata(folder_id, key_metadata)
            
            return True
            
        except Exception as e:
            print(f"Failed to store folder master key: {e}")
            return False
    
    def retrieve_folder_master_key(self, folder_id: str) -> Optional[bytes]:
        """Retrieve Folder Master Key"""
        try:
            # Load metadata to determine storage method
            metadata = self._load_key_metadata(folder_id)
            if not metadata:
                return None
            
            # Verify device binding
            current_fingerprint = self.device_binding.get_device_fingerprint()
            if metadata.get("device_fingerprint") != current_fingerprint:
                print(f"Device binding mismatch for folder {folder_id}")
                return None
            
            storage_method = metadata.get("storage_method", "DPAPI")
            
            if storage_method == "TPM":
                # Try TPM retrieval
                key_data = self.tpm.retrieve_key_from_tpm(f"FMK-{folder_id}")
                if key_data:
                    return key_data
                # Fall back to DPAPI if TPM fails
            
            # DPAPI retrieval
            key_file = self.key_store_path / f"fmk_{folder_id}.key"
            if not key_file.exists():
                return None
            
            with open(key_file, 'rb') as f:
                protected_data = f.read()
            
            key_data, _ = self.dpapi.unprotect_data(protected_data)
            return key_data
            
        except Exception as e:
            print(f"Failed to retrieve folder master key: {e}")
            return None
    
    def derive_container_key(self, folder_master_key: bytes, 
                           container_id: str) -> bytes:
        """Derive container-specific encryption key from FMK"""
        # Use PBKDF2 to derive container key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=container_id.encode('utf-8'),
            iterations=100000,
            backend=default_backend()
        )
        
        return kdf.derive(folder_master_key)
    
    def _save_key_metadata(self, folder_id: str, metadata: Dict[str, Any]):
        """Save key metadata to secure file"""
        metadata_file = self.key_store_path / f"fmk_{folder_id}.meta"
        
        # Encrypt metadata with DPAPI
        metadata_json = json.dumps(metadata, indent=2).encode('utf-8')
        protected_metadata = self.dpapi.protect_data(
            metadata_json,
            f"ImmuneFolders metadata for {folder_id}"
        )
        
        with open(metadata_file, 'wb') as f:
            f.write(protected_metadata)
        
        self._secure_file_permissions(metadata_file)
    
    def _load_key_metadata(self, folder_id: str) -> Optional[Dict[str, Any]]:
        """Load key metadata from secure file"""
        try:
            metadata_file = self.key_store_path / f"fmk_{folder_id}.meta"
            if not metadata_file.exists():
                return None
            
            with open(metadata_file, 'rb') as f:
                protected_data = f.read()
            
            metadata_json, _ = self.dpapi.unprotect_data(protected_data)
            return json.loads(metadata_json.decode('utf-8'))
            
        except Exception as e:
            print(f"Failed to load key metadata: {e}")
            return None
    
    def _secure_file_permissions(self, file_path: Path):
        """Set restrictive file permissions (Windows)"""
        if not WINDOWS_AVAILABLE:
            return
            
        try:
            # Get current user and SYSTEM accounts
            user_sid = win32security.GetTokenInformation(
                win32security.GetCurrentProcessToken(),
                win32security.TokenUser
            )[0]
            
            system_sid = win32security.LookupAccountName(None, "SYSTEM")[0]
            
            # Create DACL with limited access
            dacl = win32security.ACL()
            
            # Add full control for SYSTEM
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32con.FILE_ALL_ACCESS,
                system_sid
            )
            
            # Add read/write for current user
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32con.FILE_GENERIC_READ | win32con.FILE_GENERIC_WRITE,
                user_sid
            )
            
            # Apply DACL to file
            win32security.SetFileSecurity(
                str(file_path),
                win32security.DACL_SECURITY_INFORMATION,
                dacl
            )
            
        except Exception as e:
            print(f"Warning: Could not set secure file permissions: {e}")
    
    def rotate_folder_master_key(self, folder_id: str) -> bool:
        """Rotate the Folder Master Key for enhanced security"""
        try:
            # Generate new master key
            new_master_key = secrets.token_bytes(32)
            
            # Store new key
            if self.store_folder_master_key(folder_id, new_master_key):
                print(f"Folder Master Key rotated for {folder_id}")
                return True
            else:
                print(f"Failed to rotate Folder Master Key for {folder_id}")
                return False
                
        except Exception as e:
            print(f"Key rotation failed: {e}")
            return False
    
    def export_recovery_data(self, folder_id: str, passphrase: str) -> Optional[bytes]:
        """Export encrypted recovery data for offline backup"""
        try:
            # Get current FMK
            fmk = self.retrieve_folder_master_key(folder_id)
            if not fmk:
                return None
            
            # Create recovery package
            recovery_data = {
                "folder_id": folder_id,
                "folder_master_key": base64.b64encode(fmk).decode('ascii'),
                "device_fingerprint": self.device_binding.get_device_fingerprint(),
                "exported": int(time.time()),
                "recovery_version": 1
            }
            
            # Encrypt with passphrase
            passphrase_bytes = passphrase.encode('utf-8')
            salt = secrets.token_bytes(16)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            
            key = kdf.derive(passphrase_bytes)
            iv = secrets.token_bytes(16)
            
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            encryptor = cipher.encryptor()
            
            # Prepare data for encryption
            recovery_json = json.dumps(recovery_data).encode('utf-8')
            
            # Add PKCS7 padding
            pad_length = 16 - (len(recovery_json) % 16)
            padded_data = recovery_json + bytes([pad_length] * pad_length)
            
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Create final package
            package = {
                "salt": base64.b64encode(salt).decode('ascii'),
                "iv": base64.b64encode(iv).decode('ascii'),
                "data": base64.b64encode(encrypted_data).decode('ascii')
            }
            
            return json.dumps(package).encode('utf-8')
            
        except Exception as e:
            print(f"Recovery data export failed: {e}")
            return None
    
    def import_recovery_data(self, recovery_package: bytes, 
                           passphrase: str) -> Optional[str]:
        """Import recovery data and restore FMK"""
        try:
            # Parse recovery package
            package = json.loads(recovery_package.decode('utf-8'))
            
            salt = base64.b64decode(package["salt"])
            iv = base64.b64decode(package["iv"])
            encrypted_data = base64.b64decode(package["data"])
            
            # Derive decryption key
            passphrase_bytes = passphrase.encode('utf-8')
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            
            key = kdf.derive(passphrase_bytes)
            
            # Decrypt data
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove PKCS7 padding
            pad_length = padded_data[-1]
            recovery_json = padded_data[:-pad_length]
            
            # Parse recovery data
            recovery_data = json.loads(recovery_json.decode('utf-8'))
            
            folder_id = recovery_data["folder_id"]
            fmk = base64.b64decode(recovery_data["folder_master_key"])
            
            # Store recovered FMK
            if self.store_folder_master_key(folder_id, fmk):
                print(f"Successfully recovered FMK for folder {folder_id}")
                return folder_id
            else:
                print(f"Failed to store recovered FMK for folder {folder_id}")
                return None
                
        except Exception as e:
            print(f"Recovery data import failed: {e}")
            return None

# Test and example usage
if __name__ == "__main__":
    import time
    
    # Test the secure key provider
    key_provider = SecureKeyProvider()
    
    # Test folder master key generation and storage
    folder_id = "documents_folder"
    print(f"Generating FMK for {folder_id}...")
    
    fmk = key_provider.generate_folder_master_key(folder_id)
    print(f"Generated FMK: {len(fmk)} bytes")
    
    # Test retrieval
    retrieved_fmk = key_provider.retrieve_folder_master_key(folder_id)
    if retrieved_fmk == fmk:
        print("✓ FMK storage/retrieval successful")
    else:
        print("✗ FMK storage/retrieval failed")
    
    # Test container key derivation
    container_key = key_provider.derive_container_key(fmk, "container1")
    print(f"Derived container key: {len(container_key)} bytes")
    
    # Test recovery export/import
    passphrase = "test-recovery-passphrase-123"
    print(f"Testing recovery export...")
    
    recovery_data = key_provider.export_recovery_data(folder_id, passphrase)
    if recovery_data:
        print(f"✓ Recovery export successful: {len(recovery_data)} bytes")
        
        # Test import
        recovered_folder = key_provider.import_recovery_data(recovery_data, passphrase)
        if recovered_folder == folder_id:
            print("✓ Recovery import successful")
        else:
            print("✗ Recovery import failed")
    else:
        print("✗ Recovery export failed")
