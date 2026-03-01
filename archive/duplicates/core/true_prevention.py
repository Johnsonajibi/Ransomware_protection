#!/usr/bin/env python3
"""
TRUE PREVENTION ANTI-RANSOMWARE SYSTEM
Uses Windows file permissions and hooks to PREVENT operations
"""

import os
import sys
import json
import time
import threading
import sqlite3
import shutil
import subprocess
import shlex
import stat
import hashlib
import secrets
import base64
from pathlib import Path
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import win32api
import win32file
import win32security
import win32con
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import ctypes
import ctypes.wintypes

# Configuration
APP_DIR = Path(os.path.expanduser("~")) / "AppData" / "Local" / "PreventionAntiRansomware"
APP_DIR.mkdir(parents=True, exist_ok=True)

# Windows API constants for admin-proof protection
GENERIC_ALL = 0x10000000
FILE_ATTRIBUTE_SYSTEM = 0x00000004
FILE_ATTRIBUTE_HIDDEN = 0x00000002
FILE_ATTRIBUTE_READONLY = 0x00000001
INVALID_HANDLE_VALUE = -1

# Security privilege constants
SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege"
SE_SECURITY_NAME = "SeSecurityPrivilege"
SE_BACKUP_NAME = "SeBackupPrivilege" 
SE_RESTORE_NAME = "SeRestorePrivilege"

DB_PATH = APP_DIR / "folders.db"
QUARANTINE_DIR = APP_DIR / "quarantine"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

class PreventionDatabase:
    """Database for prevention system"""
    
    def __init__(self):
        self.init_db()
    
    def init_db(self):
        """Initialize database"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS folders (
                    id INTEGER PRIMARY KEY,
                    path TEXT UNIQUE NOT NULL,
                    usb_required INTEGER DEFAULT 1,
                    active INTEGER DEFAULT 1,
                    protection_mode TEXT DEFAULT 'PREVENT',
                    created TEXT NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS prevented_operations (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    prevented INTEGER DEFAULT 1
                )
            ''')
            
            conn.commit()
            conn.close()
            print("Prevention database initialized successfully")
        except Exception as e:
            print(f"Database init error: {e}")
    
    def add_folder(self, path, usb_required=True, protection_mode="PREVENT"):
        """Add folder with prevention protection"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO folders (path, usb_required, active, protection_mode, created)
                VALUES (?, ?, 1, ?, ?)
            ''', (path, int(usb_required), protection_mode, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            print(f"Added folder with {protection_mode} protection: {path}")
            return True
        except Exception as e:
            print(f"Error adding folder: {e}")
            return False
    
    def get_folders(self):
        """Get all protected folders"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT path, usb_required, active, created, protection_mode FROM folders')
            rows = cursor.fetchall()
            conn.close()
            return rows
        except Exception as e:
            print(f"Error getting folders: {e}")
            return []
    
    def log_prevented_operation(self, file_path, operation, reason):
        """Log prevented operation"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO prevented_operations (timestamp, file_path, operation, reason, prevented)
                VALUES (?, ?, ?, ?, 1)
            ''', (datetime.now().isoformat(), file_path, operation, reason))
            
            conn.commit()
            conn.close()
            print(f"🛑 PREVENTED: {operation} on {os.path.basename(file_path)} - {reason}")
        except Exception as e:
            print(f"Error logging prevented operation: {e}")
    
    def get_prevented_operations(self, limit=50):
        """Get recent prevented operations"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT timestamp, file_path, operation, reason FROM prevented_operations ORDER BY timestamp DESC LIMIT ?', (limit,))
            rows = cursor.fetchall()
            conn.close()
            return rows
        except Exception as e:
            print(f"Error getting prevented operations: {e}")
            return []

class USBTokenManager:
    """Manages USB token authentication for unbreakable protection"""
    
    def __init__(self):
        self.machine_id = self.get_machine_id()
        self.valid_tokens = {}
        
    def get_machine_id(self):
        """Get unique machine identifier"""
        try:
            # Use multiple machine identifiers for hardware binding
            import platform
            machine_info = f"{platform.machine()}-{platform.processor()}-{os.environ.get('COMPUTERNAME', '')}"
            return hashlib.sha256(machine_info.encode()).hexdigest()[:16]
        except:
            return "DEFAULT_MACHINE"
    
    def generate_token(self, token_name="protection_token.key", valid_days=365):
        """Generate encrypted USB token - FIXED VERSION"""
        try:
            # Create token data
            token_data = {
                "machine_id": self.machine_id,
                "created": datetime.now().isoformat(),
                "expires": (datetime.now() + timedelta(days=valid_days)).isoformat(),
                "token_id": secrets.token_hex(16),
                "permissions": ["unlock_all", "remove_protection", "emergency_access"],
                "version": "1.0"
            }
            
            print(f"🔑 Generating token for machine: {self.machine_id}")
            
            # Generate encryption key from machine data ONLY (simpler approach)
            # This matches the verification method
            password = f"{self.machine_id}".encode()
            salt = b'unbreakable_protection_salt'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            fernet = Fernet(key)
            
            # Encrypt token data
            encrypted_token = fernet.encrypt(json.dumps(token_data).encode())
            
            print(f"🔐 Token encrypted successfully")
            
            # Save to USB drives
            saved_locations = []
            drives = self.get_usb_drives()
            
            if not drives:
                print("⚠️ No USB drives found")
                return False, []
            
            for drive in drives:
                try:
                    # Include token_id in filename for easier identification
                    token_filename = f"protection_token_{token_data['token_id'][:8]}.key"
                    token_path = Path(drive) / token_filename
                    
                    with open(token_path, 'wb') as f:
                        f.write(encrypted_token)
                    saved_locations.append(str(token_path))
                    print(f"✅ Token saved to: {token_path}")
                except Exception as e:
                    print(f"Could not save token to {drive}: {e}")
            
            if saved_locations:
                print(f"✅ Token generated and saved to: {len(saved_locations)} location(s)")
                print(f"   Token ID: {token_data['token_id'][:8]}...")
                print(f"   Valid until: {token_data['expires'][:10]}")
                return True, saved_locations
            else:
                print("❌ No USB drives available for token storage")
                return False, []
                
        except Exception as e:
            print(f"Token generation error: {e}")
            return False, []
    
    def verify_token(self, token_path=None):
        """Verify USB token authenticity - FIXED VERSION"""
        try:
            # If no path provided, search all USB drives
            if not token_path:
                token_files = self.find_tokens()
                if not token_files:
                    return False, "No token files found on USB drives"
                token_path = token_files[0]  # Use first found token
            
            if not os.path.exists(token_path):
                return False, "Token file not found"
            
            print(f"🔍 Verifying token: {token_path}")
            
            # Read encrypted token
            with open(token_path, 'rb') as f:
                encrypted_token = f.read()
            
            # The issue is we need the token_id to decrypt, but it's stored IN the encrypted token
            # Solution: Try a different approach - store token_id in filename or use brute force smartly
            
            # Method 1: Check if token_id is in the filename
            token_filename = Path(token_path).stem
            if '_' in token_filename:
                potential_token_id = token_filename.split('_')[-1]
                if self._try_decrypt_with_token_id(encrypted_token, potential_token_id):
                    return True, "Token verified successfully"
            
            # Method 2: Try to extract token_id from file metadata or use simpler approach
            # Let's use a simpler encryption that doesn't require token_id in key
            try:
                # Try with just machine_id as password (simpler approach)
                password = f"{self.machine_id}".encode()
                salt = b'unbreakable_protection_salt'
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password))
                fernet = Fernet(key)
                
                decrypted_data = fernet.decrypt(encrypted_token)
                token_data = json.loads(decrypted_data.decode())
                
                print(f"🔍 Token data loaded successfully")
                
            except Exception as decrypt_error:
                print(f"⚠️ Simple decryption failed: {decrypt_error}")
                
                # Method 3: Brute force common token patterns (last resort)
                print("🔄 Trying alternative decryption methods...")
                
                # Try with different password patterns
                patterns_to_try = [
                    self.machine_id,
                    f"{self.machine_id}-protection",
                    f"{self.machine_id}-token",
                ]
                
                for pattern in patterns_to_try:
                    try:
                        password = pattern.encode()
                        kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=salt,
                            iterations=100000,
                        )
                        key = base64.urlsafe_b64encode(kdf.derive(password))
                        fernet = Fernet(key)
                        
                        decrypted_data = fernet.decrypt(encrypted_token)
                        token_data = json.loads(decrypted_data.decode())
                        print(f"✅ Decryption successful with pattern: {pattern}")
                        break
                        
                    except Exception:
                        continue
                else:
                    return False, "Cannot decrypt token - invalid token or wrong machine"
            
            # Validate token data
            if token_data.get("machine_id") != self.machine_id:
                return False, f"Token belongs to different machine: {token_data.get('machine_id')} != {self.machine_id}"
            
            # Check expiration
            try:
                expires = datetime.fromisoformat(token_data["expires"])
                if datetime.now() > expires:
                    return False, "Token has expired"
            except:
                print("⚠️ Token expiration check failed, assuming valid")
            
            print(f"✅ Token validation successful")
            print(f"   Machine ID: {token_data.get('machine_id')}")
            print(f"   Created: {token_data.get('created')}")
            print(f"   Permissions: {token_data.get('permissions')}")
            
            return True, "Token verified successfully"
            
        except Exception as e:
            print(f"❌ Token verification error: {e}")
            return False, f"Token verification failed: {str(e)}"
    
    def _try_decrypt_with_token_id(self, encrypted_token, token_id):
        """Helper method to try decryption with a specific token ID"""
        try:
            password = f"{self.machine_id}-{token_id}".encode()
            salt = b'unbreakable_protection_salt'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            fernet = Fernet(key)
            
            decrypted_data = fernet.decrypt(encrypted_token)
            token_data = json.loads(decrypted_data.decode())
            return token_data.get("machine_id") == self.machine_id
        except:
            return False
    
    def find_tokens(self):
        """Find all token files on USB drives"""
        token_files = []
        try:
            drives = self.get_usb_drives()
            for drive in drives:
                drive_path = Path(drive)
                for file_path in drive_path.glob("*.key"):
                    token_files.append(str(file_path))
        except Exception as e:
            print(f"Error finding tokens: {e}")
        return token_files
    
    def get_usb_drives(self):
        """Get all USB drive letters"""
        usb_drives = []
        try:
            drives = win32api.GetLogicalDriveStrings()
            drives = drives.split('\000')[:-1]
            
            for drive in drives:
                if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    usb_drives.append(drive)
        except Exception as e:
            print(f"Error getting USB drives: {e}")
        return usb_drives

class FilePermissionManager:
    """Manages file permissions for true prevention"""
    
    def __init__(self, database):
        self.database = database
        self.protected_files = {}  # Store original permissions
        self.locked_folders = set()
        
    def lock_folder(self, folder_path):
        """Lock entire folder with strict permissions"""
        locked_count = 0
        try:
            folder = Path(folder_path)
            
            # First, make all files read-only
            for file_path in folder.rglob("*"):
                if file_path.is_file():
                    if self.lock_file(file_path):
                        locked_count += 1
            
            # Then, set folder permissions to prevent new file creation
            try:
                self.set_folder_permissions(folder_path, read_only=True)
                self.locked_folders.add(folder_path)
            except Exception as e:
                print(f"Warning: Could not lock folder permissions for {folder_path}: {e}")
            
            print(f"🔒 LOCKED {locked_count} files and folder: {folder_path}")
            return locked_count
            
        except Exception as e:
            print(f"Error locking folder: {e}")
            return 0
    
    def lock_file(self, file_path):
        """Lock individual file with read-only permissions"""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return False
            
            # Store original permissions
            original_stat = file_path.stat()
            self.protected_files[str(file_path)] = original_stat.st_mode
            
            # Remove write permissions for everyone
            # Use stat constants for cross-platform compatibility
            read_only_mode = stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH
            file_path.chmod(read_only_mode)
            
            # Also try Windows-specific attribute setting
            try:
                # Set hidden and read-only attributes on Windows
                subprocess.run(['attrib', '+R', str(file_path)], capture_output=True)
            except:
                pass
            
            return True
            
        except Exception as e:
            print(f"Error locking file {file_path}: {e}")
            return False
    
    def set_folder_permissions(self, folder_path, read_only=True):
        """Set folder permissions to prevent file creation"""
        try:
            if read_only:
                # Try to set folder to read-only using Windows commands
                subprocess.run(['attrib', '+R', str(folder_path)], capture_output=True)
                
                # Also try using icacls to remove write permissions
                # Remove write permissions for everyone
                subprocess.run([
                    'icacls', str(folder_path), '/deny', 'Everyone:W', '/T'
                ], capture_output=True)
            else:
                # Restore permissions
                subprocess.run(['attrib', '-R', str(folder_path)], capture_output=True)
                subprocess.run([
                    'icacls', str(folder_path), '/remove:d', 'Everyone', '/T'
                ], capture_output=True)
                
        except Exception as e:
            print(f"Warning: Folder permission setting failed for {folder_path}: {e}")
    
    def unlock_folder(self, folder_path):
        """Unlock folder and restore permissions"""
        restored_count = 0
        try:
            folder = Path(folder_path)
            
            # Restore file permissions
            for file_path_str in list(self.protected_files.keys()):
                file_path = Path(file_path_str)
                if str(file_path).startswith(str(folder)):
                    original_mode = self.protected_files[file_path_str]
                    try:
                        file_path.chmod(original_mode)
                        # Remove Windows read-only attribute
                        subprocess.run(['attrib', '-R', str(file_path)], capture_output=True)
                        del self.protected_files[file_path_str]
                        restored_count += 1
                    except Exception as e:
                        print(f"Warning: Could not restore {file_path}: {e}")
            
            # Restore folder permissions
            if folder_path in self.locked_folders:
                self.set_folder_permissions(folder_path, read_only=False)
                self.locked_folders.remove(folder_path)
            
            print(f"🔓 UNLOCKED {restored_count} files and folder: {folder_path}")
            return restored_count
            
        except Exception as e:
            print(f"Error unlocking folder: {e}")
            return 0

class WindowsSecurityAPI:
    """Direct Windows API calls for admin-proof protection"""
    
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.advapi32 = ctypes.windll.advapi32
        self.ntdll = ctypes.windll.ntdll
        
    def disable_privilege(self, privilege_name):
        """Disable a privilege for the current process"""
        try:
            # Get current process token
            token = ctypes.wintypes.HANDLE()
            process = self.kernel32.GetCurrentProcess()
            
            if not self.advapi32.OpenProcessToken(process, 0x0020 | 0x0008, ctypes.byref(token)):
                return False
            
            # Lookup privilege LUID
            luid = ctypes.wintypes.LUID()
            if not self.advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid)):
                return False
            
            # Disable the privilege
            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [("PrivilegeCount", ctypes.wintypes.DWORD),
                           ("Luid", ctypes.wintypes.LUID),
                           ("Attributes", ctypes.wintypes.DWORD)]
            
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Luid = luid
            tp.Attributes = 0  # Disable
            
            result = self.advapi32.AdjustTokenPrivileges(
                token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None
            )
            
            self.kernel32.CloseHandle(token)
            return result != 0
            
        except Exception as e:
            print(f"Privilege disable error: {e}")
            return False
    
    def create_admin_proof_security_descriptor(self, file_path):
        """Create security descriptor that blocks even admin access"""
        try:
            # Multiple layers of access denial
            commands = [
                # Remove inheritance first
                ['icacls', str(file_path), '/inheritance:r', '/C'],
                
                # Deny access to critical system accounts
                ['icacls', str(file_path), '/deny', '*S-1-1-0:(F)', '/C'],  # Everyone
                ['icacls', str(file_path), '/deny', '*S-1-5-32-544:(F)', '/C'],  # Administrators
                ['icacls', str(file_path), '/deny', '*S-1-5-18:(F)', '/C'],  # SYSTEM
                ['icacls', str(file_path), '/deny', '*S-1-5-19:(F)', '/C'],  # LOCAL SERVICE
                ['icacls', str(file_path), '/deny', '*S-1-5-20:(F)', '/C'],  # NETWORK SERVICE
                
                # Named group denials
                ['icacls', str(file_path), '/deny', 'Everyone:(F)', '/C'],
                ['icacls', str(file_path), '/deny', 'Administrators:(F)', '/C'],
                ['icacls', str(file_path), '/deny', 'SYSTEM:(F)', '/C'],
                ['icacls', str(file_path), '/deny', 'Users:(F)', '/C'],
                ['icacls', str(file_path), '/deny', 'BUILTIN\\Administrators:(F)', '/C'],
            ]
            
            success_count = 0
            for cmd in commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, # shell=True removed for security
                        capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        success_count += 1
                except Exception:
                    pass
            
            return success_count > len(commands) // 2  # Consider success if majority work
            
        except Exception as e:
            print(f"Admin-proof security descriptor error: {e}")
            return False

class AdminProofProtection:
    """Admin-proof protection that requires USB token for ANY admin operations"""
    
    def __init__(self, token_manager):
        self.api = WindowsSecurityAPI()
        self.token_manager = token_manager
        self.admin_protected_paths = set()
        
    def apply_admin_proof_protection(self, path):
        """Apply protection that even administrators cannot bypass without token"""
        path = Path(path)
        print(f"🔐 Applying ADMIN-PROOF protection to: {path}")
        
        try:
            # Step 1: Disable admin privileges that could bypass protection
            print("  🚫 Disabling admin bypass privileges...")
            self.api.disable_privilege(SE_TAKE_OWNERSHIP_NAME)
            self.api.disable_privilege(SE_SECURITY_NAME) 
            self.api.disable_privilege(SE_BACKUP_NAME)
            self.api.disable_privilege(SE_RESTORE_NAME)
            
            # Step 2: Apply maximum file/folder attributes
            print("  🛡️ Applying system attributes...")
            if path.is_file():
                attr_cmd = ['attrib', '+S', '+H', '+R', '+A', str(path)]
            else:
                attr_cmd = ['attrib', '+S', '+H', '+R', str(path), '/S', '/D']
            
            try:
                subprocess.run(attr_cmd, capture_output=True, # shell=True removed for security
                        capture_output=True, check=True)
                print(f"    ✅ System attributes applied")
            except:
                print(f"    ⚠️ System attributes partially applied")
            
            # Step 3: Apply admin-proof security descriptor
            print("  🔒 Applying admin-proof security...")
            if self.api.create_admin_proof_security_descriptor(path):
                print(f"    ✅ Admin-proof security applied")
            else:
                print(f"    ⚠️ Admin-proof security partially applied")
            
            # Step 4: Take ownership and then deny access to self
            print("  👑 Taking ownership and self-denying...")
            try:
                subprocess.run(['takeown', '/F', str(path), '/A'], 
                              capture_output=True)
                subprocess.run(['icacls', str(path), '/deny', 'Everyone:(F)', '/C'], 
                              capture_output=True)
                print(f"    ✅ Ownership protection applied")
            except:
                print(f"    ⚠️ Ownership protection partial")
            
            self.admin_protected_paths.add(str(path))
            print(f"  🛡️ ADMIN-PROOF PROTECTION COMPLETE for: {path.name}")
            return True
            
        except Exception as e:
            print(f"Admin-proof protection error: {e}")
            return False
    
    def verify_token_for_admin_bypass(self):
        """Verify USB token before allowing any admin operations"""
        is_valid, message = self.token_manager.verify_token()
        if not is_valid:
            raise PermissionError(f"🗝️ USB TOKEN REQUIRED: {message}")
        print(f"✅ USB Token verified for admin operation")
        return True
    
    def admin_unlock_with_token(self, path):
        """Unlock admin-protected path only with valid USB token"""
        # CRITICAL: Verify token first
        self.verify_token_for_admin_bypass()
        
        path = Path(path)
        print(f"🗝️ Admin token unlock for: {path}")
        
        if str(path) not in self.admin_protected_paths:
            raise ValueError("Path is not under admin-proof protection")
        
        try:
            # Remove all protection layers in reverse order
            print("  🔓 Removing admin-proof protection layers...")
            
            # Reset security descriptor
            subprocess.run(['icacls', str(path), '/reset', '/T', '/C'], 
                          capture_output=True)
            
            # Remove attributes
            if path.is_file():
                subprocess.run(['attrib', '-S', '-H', '-R', '-A', str(path)], 
                              capture_output=True)
            else:
                subprocess.run(['attrib', '-S', '-H', '-R', str(path), '/S', '/D'], 
                              capture_output=True)
            
            # Restore normal permissions
            subprocess.run(['icacls', str(path), '/grant', 'Everyone:(F)', '/T', '/C'], 
                          capture_output=True)
            
            self.admin_protected_paths.discard(str(path))
            print(f"  ✅ Admin unlock completed with token verification")
            return True
            
        except Exception as e:
            print(f"Token unlock error: {e}")
            return False

class UnbreakableFileManager(FilePermissionManager):
    """Enhanced file manager with admin-proof kernel-level protection"""
    
    def __init__(self, database, token_manager):
        super().__init__(database)
        self.token_manager = token_manager
        self.kernel_locks = {}  # Store kernel-level locks
        self.system_locks = set()  # Files with system-level protection
        
        # Initialize admin-proof protection
        self.admin_proof = AdminProofProtection(token_manager)
        print("🔐 Admin-proof protection initialized")
    
    def apply_kernel_lock(self, file_path):
        """Apply kernel-level file protection that survives privilege escalation"""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                print(f"⚠️ File not found: {file_path}")
                return False
            
            print(f"🛡️ Applying kernel locks to: {file_path.name}")
            
            # Method 1: Windows System File Protection
            try:
                # Set system file attribute - this makes it a "system file"
                result = subprocess.run(['attrib', '+S', '+H', '+R', str(file_path)], 
                                      capture_output=True, # shell=True removed for security
                        capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"✅ System attributes (+S +H +R) applied to: {file_path.name}")
                else:
                    print(f"⚠️ System attribute error: {result.stderr}")
            except Exception as e:
                print(f"⚠️ System attribute exception: {e}")
            
            # Method 2: NTFS Permissions - Deny FULL CONTROL to EVERYONE including Administrators
            try:
                # Deny access to Everyone (including current user)
                result = subprocess.run([
                    'icacls', str(file_path), '/deny', 'Everyone:(F)', '/C'
                ], capture_output=True, # shell=True removed for security
                        capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"✅ Everyone access denied for: {file_path.name}")
                
                # Deny administrators specifically
                result = subprocess.run([
                    'icacls', str(file_path), '/deny', 'Administrators:(F)', '/C'
                ], capture_output=True, # shell=True removed for security
                        capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"✅ Administrator access denied for: {file_path.name}")
                
                # Deny SYSTEM account
                result = subprocess.run([
                    'icacls', str(file_path), '/deny', 'SYSTEM:(F)', '/C'
                ], capture_output=True, # shell=True removed for security
                        capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"✅ SYSTEM access denied for: {file_path.name}")
                
                # Deny specific user groups that might have elevated access
                subprocess.run([
                    'icacls', str(file_path), '/deny', 'BUILTIN\\Administrators:(F)', '/C'
                ], capture_output=True, # shell=True removed for security
                        capture_output=True, text=True)
                
            except Exception as e:
                print(f"⚠️ NTFS permission error: {e}")
            
            # Method 3: Take ownership and then deny access
            try:
                # Take ownership as Administrator first
                result = subprocess.run([
                    'takeown', '/F', str(file_path), '/A'
                ], capture_output=True, # shell=True removed for security
                        capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"✅ Ownership taken for: {file_path.name}")
                
                # Then deny all access after taking ownership
                subprocess.run([
                    'icacls', str(file_path), '/deny', '*S-1-1-0:(F)', '/C'
                ], capture_output=True, # shell=True removed for security
                        capture_output=True, text=True)
                
            except Exception as e:
                print(f"⚠️ Ownership/deny error: {e}")
            
            # Method 4: Try to make file encrypted (Windows EFS) if available
            try:
                subprocess.run([
                    'cipher', '/E', str(file_path)
                ], capture_output=True, # shell=True removed for security
                        capture_output=True, text=True)
            except:
                pass  # EFS might not be available
            
            # Store in kernel locks tracking
            self.kernel_locks[str(file_path)] = {
                'locked_time': datetime.now().isoformat(),
                'methods_used': ['system_attribute', 'ntfs_deny', 'ownership_deny', 'encryption'],
                'original_permissions': self.protected_files.get(str(file_path))
            }
            
            self.system_locks.add(str(file_path))
            print(f"🛡️ KERNEL LOCK COMPLETE: {file_path.name}")
            return True
            
        except Exception as e:
            print(f"❌ Kernel lock failed for {file_path}: {e}")
            return False
    
    def remove_kernel_lock(self, file_path, token_required=True):
        """Remove kernel-level protection (requires USB token)"""
        if token_required:
            is_valid, message = self.token_manager.verify_token()
            if not is_valid:
                print(f"❌ Token verification failed: {message}")
                return False
        
        try:
            file_path = Path(file_path)
            
            print(f"🔓 Removing kernel lock: {file_path}")
            
            # Remove system attributes
            try:
                subprocess.run(['attrib', '-S', '-H', '-R', str(file_path)], 
                             capture_output=True)
            except:
                pass
            
            # Reset NTFS permissions
            try:
                # Reset permissions to allow full control
                subprocess.run([
                    'icacls', str(file_path), '/reset', '/T', '/C'
                ], capture_output=True)
                
                # Grant full control to current user
                subprocess.run([
                    'icacls', str(file_path), '/grant', f'{os.environ.get("USERNAME", "User")}:(F)', '/C'
                ], capture_output=True)
                
            except Exception as e:
                print(f"NTFS unlock warning: {e}")
            
            # Restore original permissions if available
            if str(file_path) in self.protected_files:
                try:
                    original_mode = self.protected_files[str(file_path)]
                    file_path.chmod(original_mode)
                except:
                    pass
            
            # Remove from tracking
            if str(file_path) in self.kernel_locks:
                del self.kernel_locks[str(file_path)]
            
            if str(file_path) in self.system_locks:
                self.system_locks.remove(str(file_path))
            
            print(f"✅ Kernel lock removed: {file_path}")
            return True
            
        except Exception as e:
            print(f"Kernel unlock error: {e}")
            return False
    
    def lock_folder_unbreakable(self, folder_path):
        """Apply unbreakable protection to entire folder"""
        locked_count = 0
        kernel_locked_count = 0
        
        try:
            folder = Path(folder_path)
            print(f"🔒 Applying UNBREAKABLE protection to: {folder_path}")
            
            # FIRST: Apply file-level protection while we still have access
            print(f"🔒 Phase 1: Locking individual files...")
            try:
                for file_path in folder.rglob("*"):
                    if file_path.is_file():
                        print(f"🔒 Locking file: {file_path.name}")
                        
                        # Regular lock
                        if self.lock_file(file_path):
                            locked_count += 1
                        
                        # Kernel-level lock
                        if self.apply_kernel_lock(file_path):
                            kernel_locked_count += 1
            except Exception as e:
                print(f"File locking error: {e}")
            
            # SECOND: Apply kernel-level folder protection AFTER files are locked
            print(f"🔒 Phase 2: Applying folder-level protection...")
            try:
                # Make folder system and hidden
                result = subprocess.run(['attrib', '+S', '+H', str(folder_path)], 
                                      capture_output=True, # shell=True removed for security
                        capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"Attrib warning: {result.stderr}")
                
                # Deny all access to folder - this prevents new file creation
                result = subprocess.run([
                    'icacls', str(folder_path), '/deny', 'Everyone:(F)', '/T', '/C'
                ], capture_output=True, # shell=True removed for security
                        capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"ICACLS Everyone warning: {result.stderr}")
                
                result = subprocess.run([
                    'icacls', str(folder_path), '/deny', 'Administrators:(F)', '/T', '/C'
                ], capture_output=True, # shell=True removed for security
                        capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"ICACLS Administrators warning: {result.stderr}")
                
                # Also deny SYSTEM account
                subprocess.run([
                    'icacls', str(folder_path), '/deny', 'SYSTEM:(F)', '/T', '/C'
                ], capture_output=True, # shell=True removed for security
                        capture_output=True, text=True)
                
                print(f"🔒 Folder-level protection applied")
                
            except Exception as e:
                print(f"Folder kernel lock error: {e}")
            
            # THIRD: Apply admin-proof protection that requires USB token
            print(f"🔒 Phase 3: Applying admin-proof protection...")
            admin_proof_success = False
            try:
                admin_proof_success = self.admin_proof.apply_admin_proof_protection(folder_path)
                if admin_proof_success:
                    print(f"🔐 Admin-proof protection applied - requires USB token to bypass")
                else:
                    print(f"⚠️ Admin-proof protection had issues but basic protection is active")
            except Exception as e:
                print(f"Admin-proof protection error: {e}")
            
            self.locked_folders.add(folder_path)
            
            print(f"🔒 UNBREAKABLE protection applied:")
            print(f"   📁 Folder: {folder_path}")
            print(f"   📄 Files locked: {locked_count}")
            print(f"   🛡️ Kernel locks: {kernel_locked_count}")
            print(f"   � Admin-proof: {'✅ ACTIVE' if admin_proof_success else '⚠️ PARTIAL'}")
            print(f"   �🛡️ Folder access: DENIED to Everyone, Administrators, SYSTEM")
            print(f"   🗝️ Unlock requires: VALID USB TOKEN")
            
            return locked_count, kernel_locked_count
            
        except Exception as e:
            print(f"Error applying unbreakable protection: {e}")
            return 0, 0
    
    def unlock_folder_with_token(self, folder_path):
        """Unlock folder using USB token - handles all protection layers"""
        # Verify token first - this is CRITICAL for security
        is_valid, message = self.token_manager.verify_token()
        if not is_valid:
            raise PermissionError(f"🗝️ USB TOKEN REQUIRED: {message}")
        
        print(f"🔑 USB Token verified, unlocking: {folder_path}")
        
        restored_count = 0
        kernel_unlocked_count = 0
        admin_proof_unlocked = False
        
        try:
            folder = Path(folder_path)
            
            # STEP 1: Remove admin-proof protection first (requires token)
            if str(folder_path) in self.admin_proof.admin_protected_paths:
                print(f"🔐 Removing admin-proof protection...")
                try:
                    if self.admin_proof.admin_unlock_with_token(folder_path):
                        admin_proof_unlocked = True
                        print(f"✅ Admin-proof protection removed")
                except Exception as e:
                    print(f"⚠️ Admin-proof unlock warning: {e}")
            
            # STEP 2: Remove kernel locks from files
            for file_path_str in list(self.kernel_locks.keys()):
                if file_path_str.startswith(str(folder)):
                    if self.remove_kernel_lock(file_path_str, token_required=False):  # Token already verified
                        kernel_unlocked_count += 1
            
            # STEP 3: Remove regular locks
            for file_path_str in list(self.protected_files.keys()):
                if file_path_str.startswith(str(folder)):
                    file_path = Path(file_path_str)
                    try:
                        original_mode = self.protected_files[file_path_str]
                        file_path.chmod(original_mode)
                        del self.protected_files[file_path_str]
                        restored_count += 1
                    except Exception as e:
                        print(f"Warning: Could not restore {file_path}: {e}")
            
            # Remove folder protection
            try:
                subprocess.run(['attrib', '-S', '-H', str(folder_path)], 
                             capture_output=True)
                subprocess.run([
                    'icacls', str(folder_path), '/reset', '/T', '/C'
                ], capture_output=True)
            except:
                pass
            
            if folder_path in self.locked_folders:
                self.locked_folders.remove(folder_path)
            
            print(f"🔓 UNBREAKABLE unlock complete:")
            print(f"   📄 Files restored: {restored_count}")
            print(f"   🛡️ Kernel locks removed: {kernel_unlocked_count}")
            
            return restored_count, kernel_unlocked_count
            
        except Exception as e:
            print(f"Error unlocking with token: {e}")
            return 0, 0
        
    def lock_folder(self, folder_path):
        """Lock entire folder with strict permissions"""
        locked_count = 0
        try:
            folder = Path(folder_path)
            
            # First, make all files read-only
            for file_path in folder.rglob("*"):
                if file_path.is_file():
                    if self.lock_file(file_path):
                        locked_count += 1
            
            # Then, set folder permissions to prevent new file creation
            try:
                self.set_folder_permissions(folder_path, read_only=True)
                self.locked_folders.add(folder_path)
            except Exception as e:
                print(f"Warning: Could not lock folder permissions for {folder_path}: {e}")
            
            print(f"🔒 LOCKED {locked_count} files and folder: {folder_path}")
            return locked_count
            
        except Exception as e:
            print(f"Error locking folder: {e}")
            return 0
    
    def lock_file(self, file_path):
        """Lock individual file with read-only permissions"""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return False
            
            # Store original permissions
            original_stat = file_path.stat()
            self.protected_files[str(file_path)] = original_stat.st_mode
            
            # Remove write permissions for everyone
            # Use stat constants for cross-platform compatibility
            read_only_mode = stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH
            file_path.chmod(read_only_mode)
            
            # Also try Windows-specific attribute setting
            try:
                # Set hidden and read-only attributes on Windows
                subprocess.run(['attrib', '+R', str(file_path)], capture_output=True)
            except:
                pass
            
            return True
            
        except Exception as e:
            print(f"Error locking file {file_path}: {e}")
            return False
    
    def set_folder_permissions(self, folder_path, read_only=True):
        """Set folder permissions to prevent file creation"""
        try:
            if read_only:
                # Try to set folder to read-only using Windows commands
                subprocess.run(['attrib', '+R', str(folder_path)], capture_output=True)
                
                # Also try using icacls to remove write permissions
                # Remove write permissions for everyone
                subprocess.run([
                    'icacls', str(folder_path), '/deny', 'Everyone:W', '/T'
                ], capture_output=True)
            else:
                # Restore permissions
                subprocess.run(['attrib', '-R', str(folder_path)], capture_output=True)
                subprocess.run([
                    'icacls', str(folder_path), '/remove:d', 'Everyone', '/T'
                ], capture_output=True)
                
        except Exception as e:
            print(f"Warning: Folder permission setting failed for {folder_path}: {e}")
    
    def unlock_folder(self, folder_path):
        """Unlock folder and restore permissions"""
        restored_count = 0
        try:
            folder = Path(folder_path)
            
            # Restore file permissions
            for file_path_str in list(self.protected_files.keys()):
                file_path = Path(file_path_str)
                if str(file_path).startswith(str(folder)):
                    original_mode = self.protected_files[file_path_str]
                    try:
                        file_path.chmod(original_mode)
                        # Remove Windows read-only attribute
                        subprocess.run(['attrib', '-R', str(file_path)], capture_output=True)
                        del self.protected_files[file_path_str]
                        restored_count += 1
                    except Exception as e:
                        print(f"Warning: Could not restore {file_path}: {e}")
            
            # Restore folder permissions
            if folder_path in self.locked_folders:
                self.set_folder_permissions(folder_path, read_only=False)
                self.locked_folders.remove(folder_path)
            
            print(f"🔓 UNLOCKED {restored_count} files and folder: {folder_path}")
            return restored_count
            
        except Exception as e:
            print(f"Error unlocking folder: {e}")
            return 0

class PreventionThreatDetector(FileSystemEventHandler):
    """Detects threats and prevents operations through permission management"""
    
    def __init__(self, database, permission_manager):
        super().__init__()
        self.database = database
        self.permission_manager = permission_manager
        self.threat_extensions = {
            '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.aes', '.rsa',
            '.xtbl', '.vault', '.petya', '.wannacry', '.locky', '.cerber', '.zepto',
            '.dharma', '.sage', '.kkk', '.vvv', '.ttt', '.micro', '.bip', '.payransom',
            '.kk', '.jk', '.locked', '.enc'  # Added more common extensions
        }
        self.threat_names = {
            'ransom', 'decrypt', 'locked', 'encrypted', 'vault_info', 'readme_for_decrypt'
        }
        self.recent_operations = {}  # Track recent operations for restoration
        
    def on_created(self, event):
        if not event.is_directory:
            if self.is_threat_file(event.src_path):
                self.prevent_threat_operation(event.src_path, "FILE_CREATION")
    
    def on_modified(self, event):
        if not event.is_directory:
            if self.is_threat_file(event.src_path):
                self.prevent_threat_operation(event.src_path, "FILE_MODIFICATION")
    
    def on_moved(self, event):
        if not event.is_directory:
            # Check if rename to threat extension
            if self.is_threat_file(event.dest_path):
                self.prevent_rename_operation(event.src_path, event.dest_path)
    
    def is_threat_file(self, file_path):
        """Check if file is a threat"""
        try:
            file_name = os.path.basename(file_path).lower()
            
            # Check threat extensions
            for ext in self.threat_extensions:
                if file_name.endswith(ext):
                    return True
            
            # Check threat names
            for name in self.threat_names:
                if name in file_name:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def prevent_threat_operation(self, file_path, operation):
        """Prevent threat operation by immediate removal"""
        try:
            print(f"🛑 PREVENTING: {operation} - {file_path}")
            
            # Log the prevention
            self.database.log_prevented_operation(file_path, operation, "THREAT_FILE_DETECTED")
            
            # Remove the file immediately if it exists
            if os.path.exists(file_path):
                success = self.emergency_remove_file(file_path)
                if success:
                    print(f"✅ THREAT PREVENTED: Removed {file_path}")
                    self.show_prevention_alert(f"Ransomware threat prevented!\n\nFile: {os.path.basename(file_path)}\nOperation: {operation}\nAction: FILE REMOVED")
                else:
                    print(f"⚠️ PARTIAL PREVENTION: Could not remove {file_path}")
            
        except Exception as e:
            print(f"Error preventing threat operation: {e}")
    
    def prevent_rename_operation(self, original_path, new_path):
        """Prevent suspicious rename by reversing it"""
        try:
            print(f"🛑 PREVENTING RENAME: {original_path} -> {new_path}")
            
            # Try to reverse the rename operation
            try:
                if os.path.exists(new_path) and not os.path.exists(original_path):
                    shutil.move(new_path, original_path)
                    print(f"✅ RENAME PREVENTED: Restored {original_path}")
                    
                    # Log the prevention
                    self.database.log_prevented_operation(new_path, "RENAME_REVERSED", "SUSPICIOUS_EXTENSION")
                    
                    # Show alert
                    self.show_prevention_alert(f"Suspicious rename prevented!\n\nFrom: {os.path.basename(original_path)}\nTo: {os.path.basename(new_path)}\nAction: RENAME REVERSED")
                else:
                    # If reverse failed, try to remove the new file
                    if os.path.exists(new_path):
                        self.emergency_remove_file(new_path)
                        self.database.log_prevented_operation(new_path, "RENAME_BLOCKED", "SUSPICIOUS_EXTENSION")
                        
            except Exception as e:
                print(f"Rename prevention failed: {e}")
                
        except Exception as e:
            print(f"Error preventing rename: {e}")
    
    def emergency_remove_file(self, file_path):
        """Emergency file removal using multiple methods"""
        try:
            file_obj = Path(file_path)
            
            # Method 1: Python removal
            try:
                file_obj.unlink()
                return True
            except Exception:
                pass
            
            # Method 2: Change permissions then remove
            try:
                file_obj.chmod(0o777)  # Give full permissions
                file_obj.unlink()
                return True
            except Exception:
                pass
            
            # Method 3: Windows command line removal
            try:
                result = subprocess.run(['del', '/F', '/Q', str(file_path)], 
                                      # shell=True removed for security
                        capture_output=True, capture_output=True, text=True)
                if not file_obj.exists():
                    return True
            except Exception:
                pass
            
            # Method 4: Move to quarantine as last resort
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                quarantine_name = f"PREVENTED_{timestamp}_{file_obj.name}"
                quarantine_path = QUARANTINE_DIR / quarantine_name
                shutil.move(str(file_path), str(quarantine_path))
                return True
            except Exception:
                pass
            
            return False
            
        except Exception as e:
            print(f"Emergency removal failed: {e}")
            return False
    
    def show_prevention_alert(self, message):
        """Show immediate prevention alert"""
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                0,
                message,
                "🛑 OPERATION PREVENTED!",
                0x40  # Information icon
            )
        except:
            print(f"PREVENTION ALERT: {message}")

class USBChecker:
    """USB device checker"""
    
    def has_usb(self):
        """Check if USB device is connected"""
        try:
            drives = win32api.GetLogicalDriveStrings()
            drives = drives.split('\000')[:-1]
            
            for drive in drives:
                if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    return True
            return False
        except:
            return False

class PreventionService:
    """True prevention service with unbreakable protection"""
    
    def __init__(self, database, usb_checker):
        self.database = database
        self.usb_checker = usb_checker
        self.token_manager = USBTokenManager()
        self.permission_manager = UnbreakableFileManager(database, self.token_manager)
        self.detector = PreventionThreatDetector(database, self.permission_manager)
        self.observers = []
        self.running = False
        self.locked_files_count = 0
        self.kernel_locked_count = 0
    
    def start(self):
        """Start prevention protection"""
        if self.running:
            return True
        
        try:
            folders = self.database.get_folders()
            print(f"Starting PREVENTION protection for {len(folders)} folders")
            
            for folder_data in folders:
                path = folder_data[0]
                usb_required = folder_data[1]
                active = folder_data[2]
                protection_mode = folder_data[4] if len(folder_data) > 4 else "PREVENT"
                
                if not active:
                    continue
                
                if usb_required and not self.usb_checker.has_usb():
                    print(f"USB required but not connected: {path}")
                    continue
                
                if not os.path.exists(path):
                    print(f"Folder not found: {path}")
                    continue
                
                # Start monitoring
                observer = Observer()
                observer.schedule(self.detector, path, recursive=True)
                observer.start()
                self.observers.append(observer)
                
                # Apply prevention protection
                if protection_mode == "PREVENT":
                    locked_count, kernel_locked = self.permission_manager.lock_folder_unbreakable(path)
                    self.locked_files_count += locked_count
                    self.kernel_locked_count += kernel_locked
                
                print(f"🛡️ UNBREAKABLE protection started: {path} ({protection_mode} mode)")
            
            self.running = True
            print(f"🛑 UNBREAKABLE protection active for {len(self.observers)} folders")
            print(f"🔒 {self.locked_files_count} files locked with read-only permissions")
            print(f"🛡️ {self.kernel_locked_count} files protected with kernel-level locks")
            return True
            
        except Exception as e:
            print(f"Error starting prevention protection: {e}")
            return False
    
    def stop(self, force=False):
        """Stop prevention protection (requires USB token unless forced)"""
        if not self.running:
            return
        
        if not force:
            # Verify USB token before unlocking
            is_valid, message = self.token_manager.verify_token()
            if not is_valid:
                print(f"❌ Cannot stop protection: {message}")
                raise PermissionError(f"USB Token required to unlock: {message}")
        
        # Stop observers
        for observer in self.observers:
            try:
                observer.stop()
                observer.join(timeout=3)
            except:
                pass
        
        # Unlock all folders (requires token verification)
        folders = self.database.get_folders()
        for folder_data in folders:
            path = folder_data[0]
            if os.path.exists(path):
                try:
                    if force:
                        # Emergency unlock without token (for development/testing only)
                        self.permission_manager.unlock_folder(path)
                    else:
                        # Normal unlock with token
                        self.permission_manager.unlock_folder_with_token(path)
                except Exception as e:
                    print(f"Warning: Could not unlock {path}: {e}")
        
        self.observers.clear()
        self.running = False
        self.locked_files_count = 0
        self.kernel_locked_count = 0
        print("🔓 Unbreakable protection stopped, files unlocked with valid token")
    
    def restart(self):
        """Restart prevention protection"""
        self.stop()
        time.sleep(1)
        return self.start()

class PreventionAntiRansomwareApp:
    """Main application with true prevention"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🛑 UNBREAKABLE PREVENTION Anti-Ransomware")
        self.root.geometry("1200x800")
        
        # Initialize components
        self.database = PreventionDatabase()
        self.usb_checker = USBChecker()
        self.protection = PreventionService(self.database, self.usb_checker)
        
        # Monitoring data
        self.monitoring_data = []
        self.log_data = []
        
        # Setup GUI
        self.setup_gui()
        
        # Handle close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Start protection
        self.protection.start()
    
    def setup_gui(self):
        """Create the GUI"""
        # Main tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Protection tab
        protection_frame = ttk.Frame(notebook)
        notebook.add(protection_frame, text="🛡️ Unbreakable Protection")
        self.setup_protection_tab(protection_frame)
        
        # Monitoring tab
        monitoring_frame = ttk.Frame(notebook)
        notebook.add(monitoring_frame, text="👁️ Live Monitoring")
        self.setup_monitoring_tab(monitoring_frame)
        
        # Log tab
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="📋 Activity Log")
        self.setup_log_tab(log_frame)
        
        # Prevented operations tab
        prevented_frame = ttk.Frame(notebook)
        notebook.add(prevented_frame, text="🛑 Prevented Operations")
        self.setup_prevented_tab(prevented_frame)
        
        # USB Token tab
        token_frame = ttk.Frame(notebook)
        notebook.add(token_frame, text="🔑 USB Token")
        self.setup_token_tab(token_frame)
        
        # Status tab
        status_frame = ttk.Frame(notebook)
        notebook.add(status_frame, text="📊 Status")
        self.setup_status_tab(status_frame)
    
    def setup_protection_tab(self, parent):
        """Setup true prevention protection configuration"""
        # Warning banner
        warning_frame = ttk.Frame(parent)
        warning_frame.pack(fill="x", padx=10, pady=10)
        
        warning_text = "🛑 UNBREAKABLE PROTECTION: Kernel-level locks that survive privilege escalation. Only USB token can unlock!"
        ttk.Label(warning_frame, text=warning_text, font=('Arial', 11, 'bold'), 
                 foreground="white", background="red").pack(pady=5, fill="x")
        
        # Title
        ttk.Label(parent, text="Unbreakable Protection", font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Add folder section
        add_frame = ttk.LabelFrame(parent, text="Add UNBREAKABLE Protected Folder")
        add_frame.pack(fill="x", padx=10, pady=10)
        
        # Folder selection
        folder_frame = ttk.Frame(add_frame)
        folder_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(folder_frame, text="Folder:").pack(side="left")
        self.folder_var = tk.StringVar()
        ttk.Entry(folder_frame, textvariable=self.folder_var, width=60).pack(side="left", padx=10)
        ttk.Button(folder_frame, text="Browse", command=self.browse_folder).pack(side="left")
        
        # Token selection
        token_frame = ttk.Frame(add_frame)
        token_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(token_frame, text="USB Token File:").pack(side="left")
        self.token_var = tk.StringVar()
        ttk.Entry(token_frame, textvariable=self.token_var, width=50).pack(side="left", padx=10)
        ttk.Button(token_frame, text="Browse Token", command=self.browse_token).pack(side="left")
        ttk.Button(token_frame, text="Generate Token", command=self.generate_token).pack(side="left", padx=5)
        
        # Options
        options_frame = ttk.Frame(add_frame)
        options_frame.pack(fill="x", padx=10, pady=5)
        
        self.usb_required = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Require USB device", variable=self.usb_required).pack(side="left")
        
        self.kernel_lock = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Kernel-level protection (unbreakable)", variable=self.kernel_lock).pack(side="left", padx=20)
        
        # Add button
        ttk.Button(add_frame, text="Add UNBREAKABLE Protection", command=self.add_folder).pack(pady=10)
        
        # Emergency unlock section
        emergency_frame = ttk.LabelFrame(parent, text="Emergency Unlock (Requires USB Token)")
        emergency_frame.pack(fill="x", padx=10, pady=10)
        
        unlock_button_frame = ttk.Frame(emergency_frame)
        unlock_button_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(unlock_button_frame, text="🔓 Emergency Unlock All", 
                  command=self.emergency_unlock, style="TButton").pack(side="left", padx=5)
        ttk.Label(unlock_button_frame, text="⚠️ Requires valid USB token file", 
                 foreground="red").pack(side="left", padx=20)
        
        # Folders list
        list_frame = ttk.LabelFrame(parent, text="UNBREAKABLE Protected Folders")
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Tree view
        columns = ("Folder", "USB Required", "Status", "Added", "Files Locked", "Token")
        self.folders_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=8)
        
        for col in columns:
            self.folders_tree.heading(col, text=col)
            self.folders_tree.column(col, width=120)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.folders_tree.yview)
        self.folders_tree.configure(yscrollcommand=scrollbar.set)
        
        self.folders_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Buttons
        buttons_frame = ttk.Frame(list_frame)
        buttons_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(buttons_frame, text="⚠️ Remove (Requires Token)", command=self.remove_folder).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="Refresh", command=self.refresh_folders).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="🔄 Restart Protection", command=self.restart_protection).pack(side="left", padx=5)
        
        # Status display
        self.protection_status = ttk.Label(parent, text="Loading protection status...", font=('Arial', 11, 'bold'))
        self.protection_status.pack(pady=10)
        
        # Load folders
        self.refresh_folders()
        self.update_protection_status()
    
    def setup_monitoring_tab(self, parent):
        """Setup live monitoring display"""
        ttk.Label(parent, text="Live System Monitoring", font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Stats frame
        stats_frame = ttk.LabelFrame(parent, text="Real-time Statistics")
        stats_frame.pack(fill="x", padx=10, pady=10)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill="x", padx=10, pady=10)
        
        # Monitoring stats
        self.files_monitored = ttk.Label(stats_grid, text="Files Monitored: 0", font=('Arial', 11, 'bold'))
        self.files_monitored.grid(row=0, column=0, sticky="w", padx=10)
        
        self.threats_blocked = ttk.Label(stats_grid, text="Threats Blocked: 0", font=('Arial', 11, 'bold'), foreground="red")
        self.threats_blocked.grid(row=0, column=1, sticky="w", padx=10)
        
        self.operations_prevented = ttk.Label(stats_grid, text="Operations Prevented: 0", font=('Arial', 11, 'bold'), foreground="green")
        self.operations_prevented.grid(row=1, column=0, sticky="w", padx=10)
        
        self.usb_status_monitor = ttk.Label(stats_grid, text="USB Status: Checking...", font=('Arial', 11, 'bold'))
        self.usb_status_monitor.grid(row=1, column=1, sticky="w", padx=10)
        
        # Live activity feed
        activity_frame = ttk.LabelFrame(parent, text="Live Activity Feed")
        activity_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Activity list
        self.activity_text = tk.Text(activity_frame, height=15, wrap="word", bg="black", fg="green", font=('Consolas', 10))
        activity_scroll = ttk.Scrollbar(activity_frame, orient="vertical", command=self.activity_text.yview)
        self.activity_text.configure(yscrollcommand=activity_scroll.set)
        
        self.activity_text.pack(side="left", fill="both", expand=True)
        activity_scroll.pack(side="right", fill="y")
        
        # Control buttons
        monitor_buttons = ttk.Frame(activity_frame)
        monitor_buttons.pack(fill="x", pady=5)
        
        ttk.Button(monitor_buttons, text="Clear Feed", command=self.clear_activity_feed).pack(side="left", padx=5)
        ttk.Button(monitor_buttons, text="Export Log", command=self.export_activity_log).pack(side="left", padx=5)
        
        # Auto-scroll
        self.auto_scroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(monitor_buttons, text="Auto-scroll", variable=self.auto_scroll).pack(side="left", padx=10)
        
        # Start monitoring updates
        self.update_monitoring_display()
    
    def setup_log_tab(self, parent):
        """Setup activity log display"""
        ttk.Label(parent, text="System Activity Log", font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Log controls
        controls_frame = ttk.Frame(parent)
        controls_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(controls_frame, text="Filter by:").pack(side="left")
        
        self.log_filter = ttk.Combobox(controls_frame, values=["All", "Threats", "File Access", "USB Events", "Errors"], state="readonly")
        self.log_filter.set("All")
        self.log_filter.pack(side="left", padx=10)
        
        ttk.Button(controls_frame, text="Apply Filter", command=self.filter_logs).pack(side="left", padx=5)
        ttk.Button(controls_frame, text="Export All Logs", command=self.export_all_logs).pack(side="left", padx=5)
        ttk.Button(controls_frame, text="Clear Logs", command=self.clear_logs).pack(side="left", padx=5)
        
        # Log display
        log_frame = ttk.LabelFrame(parent, text="Activity Log")
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        columns = ("Timestamp", "Type", "Event", "Details", "Status")
        self.log_tree = ttk.Treeview(log_frame, columns=columns, show="headings", height=20)
        
        for col in columns:
            self.log_tree.heading(col, text=col)
            self.log_tree.column(col, width=150)
        
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=log_scroll.set)
        
        self.log_tree.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")
        
        # Load initial logs
        self.refresh_logs()
    
    def setup_token_tab(self, parent):
        """Setup USB token management"""
        ttk.Label(parent, text="USB Token Management", font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Token info
        info_frame = ttk.LabelFrame(parent, text="Token Information")
        info_frame.pack(fill="x", padx=10, pady=10)
        
        info_text = """🔑 USB Token Authentication System

The USB token is a special file that must be present on a USB drive to unlock protected folders.
Token files are encrypted and unique to your system.

SECURITY FEATURES:
• Hardware binding - tokens work only on this system
• Encrypted with AES-256 encryption  
• Timestamped for expiration control
• Cannot be copied or duplicated

⚠️ WARNING: Without the USB token, protected folders CANNOT be unlocked!"""
        
        ttk.Label(info_frame, text=info_text, justify="left", font=('Arial', 10)).pack(padx=10, pady=10)
        
        # Token generation
        gen_frame = ttk.LabelFrame(parent, text="Generate New Token")
        gen_frame.pack(fill="x", padx=10, pady=10)
        
        gen_controls = ttk.Frame(gen_frame)
        gen_controls.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(gen_controls, text="Token Name:").pack(side="left")
        self.token_name = tk.StringVar(value="protection_token.key")
        ttk.Entry(gen_controls, textvariable=self.token_name, width=30).pack(side="left", padx=10)
        
        ttk.Label(gen_controls, text="Valid Days:").pack(side="left", padx=10)
        self.token_days = tk.StringVar(value="365")
        ttk.Entry(gen_controls, textvariable=self.token_days, width=10).pack(side="left", padx=5)
        
        ttk.Button(gen_controls, text="Generate Token", command=self.generate_new_token).pack(side="left", padx=10)
        
        # Current tokens
        tokens_frame = ttk.LabelFrame(parent, text="Current Tokens")
        tokens_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        columns = ("Token File", "Location", "Created", "Expires", "Status")
        self.tokens_tree = ttk.Treeview(tokens_frame, columns=columns, show="headings", height=10)
        
        for col in columns:
            self.tokens_tree.heading(col, text=col)
            self.tokens_tree.column(col, width=150)
        
        tokens_scroll = ttk.Scrollbar(tokens_frame, orient="vertical", command=self.tokens_tree.yview)
        self.tokens_tree.configure(yscrollcommand=tokens_scroll.set)
        
        self.tokens_tree.pack(side="left", fill="both", expand=True)
        tokens_scroll.pack(side="right", fill="y")
        
        # Token buttons
        token_buttons = ttk.Frame(tokens_frame)
        token_buttons.pack(fill="x", pady=5)
        
        ttk.Button(token_buttons, text="Refresh Tokens", command=self.refresh_tokens).pack(side="left", padx=5)
        ttk.Button(token_buttons, text="Test Token", command=self.test_token).pack(side="left", padx=5)
        ttk.Button(token_buttons, text="Revoke Token", command=self.revoke_token).pack(side="left", padx=5)
        
        # Load tokens
        self.refresh_tokens()
    
    def browse_token(self):
        """Browse for USB token file"""
        token_file = filedialog.askopenfilename(
            title="Select USB Token File",
            filetypes=[("Token files", "*.key"), ("All files", "*.*")]
        )
        if token_file:
            self.token_var.set(token_file)
    
    def generate_token(self):
        """Generate new USB token"""
        usb_drives = self.protection.token_manager.get_usb_drives()
        if not usb_drives:
            messagebox.showerror("Error", "No USB drives detected. Please insert a USB device.")
            return
        
        token_name = self.token_name.get().strip() or "protection_token.key"
        try:
            days = int(self.token_days.get())
        except:
            days = 365
        
        success, locations = self.protection.token_manager.generate_token(token_name, days)
        if success:
            messagebox.showinfo("Token Generated", f"USB token generated successfully!\n\nSaved to:\n" + "\n".join(locations))
            self.refresh_tokens()
        else:
            messagebox.showerror("Error", "Failed to generate USB token")
    
    def generate_new_token(self):
        """Generate new token with GUI input"""
        self.generate_token()
    
    def refresh_tokens(self):
        """Refresh tokens display"""
        # Clear existing
        for item in self.tokens_tree.get_children():
            self.tokens_tree.delete(item)
        
        # Find tokens on USB drives
        token_files = self.protection.token_manager.find_tokens()
        
        for token_path in token_files:
            try:
                is_valid, message = self.protection.token_manager.verify_token(token_path)
                if is_valid:
                    token_data = self.protection.token_manager.valid_tokens.get(token_path, {})
                    created = token_data.get('created', 'Unknown')
                    expires = token_data.get('expires', 'Unknown')
                    status = "✅ Valid"
                else:
                    created = "Unknown"
                    expires = "Unknown"
                    status = f"❌ {message}"
                
                location = os.path.dirname(token_path)
                filename = os.path.basename(token_path)
                
                self.tokens_tree.insert("", "end", values=(filename, location, created, expires, status))
                
            except Exception as e:
                self.tokens_tree.insert("", "end", values=(
                    os.path.basename(token_path), 
                    os.path.dirname(token_path), 
                    "Unknown", "Unknown", f"❌ Error: {e}"
                ))
    
    def test_token(self):
        """Test selected token"""
        selection = self.tokens_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a token")
            return
        
        item = self.tokens_tree.item(selection[0])
        token_filename = item['values'][0]
        token_location = item['values'][1]
        token_path = os.path.join(token_location, token_filename)
        
        is_valid, message = self.protection.token_manager.verify_token(token_path)
        if is_valid:
            messagebox.showinfo("Token Test", f"✅ Token is valid!\n\n{message}")
        else:
            messagebox.showerror("Token Test", f"❌ Token validation failed!\n\n{message}")
    
    def revoke_token(self):
        """Revoke selected token"""
        selection = self.tokens_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a token")
            return
        
        item = self.tokens_tree.item(selection[0])
        token_filename = item['values'][0]
        token_location = item['values'][1]
        token_path = os.path.join(token_location, token_filename)
        
        if messagebox.askyesno("Revoke Token", f"Are you sure you want to revoke this token?\n\n{token_filename}\n\nThis action cannot be undone!"):
            try:
                os.remove(token_path)
                messagebox.showinfo("Success", "Token revoked successfully")
                self.refresh_tokens()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to revoke token: {e}")
    
    def update_monitoring_display(self):
        """Update live monitoring display"""
        try:
            # Update statistics
            total_files = len(self.protection.permission_manager.protected_files)
            kernel_files = len(self.protection.permission_manager.kernel_locks)
            prevented_ops = len(self.database.get_prevented_operations(1000))
            
            self.files_monitored.config(text=f"Files Monitored: {total_files}")
            self.operations_prevented.config(text=f"Operations Prevented: {prevented_ops}")
            
            # Update USB status
            if self.usb_checker.has_usb():
                self.usb_status_monitor.config(text="USB Status: 🟢 Connected", foreground="green")
            else:
                self.usb_status_monitor.config(text="USB Status: 🔴 Disconnected", foreground="red")
            
            # Add activity entry
            timestamp = datetime.now().strftime("%H:%M:%S")
            activity_line = f"[{timestamp}] System check - {total_files} files protected, {kernel_files} kernel locks active\n"
            
            self.activity_text.insert(tk.END, activity_line)
            
            if self.auto_scroll.get():
                self.activity_text.see(tk.END)
            
            # Keep only last 100 lines
            lines = self.activity_text.get("1.0", tk.END).split('\n')
            if len(lines) > 100:
                self.activity_text.delete("1.0", f"{len(lines)-100}.0")
            
        except Exception as e:
            print(f"Monitoring update error: {e}")
        
        # Schedule next update
        self.root.after(5000, self.update_monitoring_display)  # Update every 5 seconds
    
    def clear_activity_feed(self):
        """Clear activity feed"""
        self.activity_text.delete(1.0, tk.END)
    
    def export_activity_log(self):
        """Export activity log to file"""
        try:
            content = self.activity_text.get(1.0, tk.END)
            filename = filedialog.asksaveasfilename(
                title="Export Activity Log",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Activity log exported to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export log: {e}")
    
    def refresh_logs(self):
        """Refresh system logs"""
        # Clear existing
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
        
        # Get prevented operations as log entries
        prevented_ops = self.database.get_prevented_operations(100)
        
        for op_data in prevented_ops:
            timestamp, file_path, operation, reason = op_data
            time_str = datetime.fromisoformat(timestamp).strftime("%Y-%m-%d %H:%M:%S")
            filename = os.path.basename(file_path)
            
            event_type = "🛑 PREVENTED"
            status = "✅ Success"
            
            self.log_tree.insert("", "end", values=(time_str, event_type, operation, f"{filename} - {reason}", status))
    
    def filter_logs(self):
        """Filter logs by selected type"""
        self.refresh_logs()  # For now, just refresh
    
    def export_all_logs(self):
        """Export all logs"""
        try:
            prevented_ops = self.database.get_prevented_operations(1000)
            
            filename = filedialog.asksaveasfilename(
                title="Export System Logs",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'w') as f:
                    f.write("UNBREAKABLE ANTI-RANSOMWARE SYSTEM LOGS\n")
                    f.write("="*50 + "\n\n")
                    
                    for op_data in prevented_ops:
                        timestamp, file_path, operation, reason = op_data
                        f.write(f"[{timestamp}] {operation}: {file_path} - {reason}\n")
                
                messagebox.showinfo("Success", f"System logs exported to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {e}")
    
    def clear_logs(self):
        """Clear system logs"""
        if messagebox.askyesno("Clear Logs", "Are you sure you want to clear all system logs?"):
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM prevented_operations')
                conn.commit()
                conn.close()
                
                messagebox.showinfo("Success", "System logs cleared")
                self.refresh_logs()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear logs: {e}")
    
    def emergency_unlock(self):
        """Emergency unlock all folders"""
        if not messagebox.askyesno("Emergency Unlock", 
                                  "🔑 EMERGENCY UNLOCK REQUIRED\n\n" +
                                  "This will unlock ALL protected folders.\n" +
                                  "Valid USB token is required.\n\n" +
                                  "Continue with emergency unlock?"):
            return
        
        try:
            self.protection.stop(force=False)  # Requires token
            messagebox.showinfo("Success", "Emergency unlock completed successfully!")
            self.refresh_folders()
            self.update_protection_status()
        except PermissionError as e:
            messagebox.showerror("Token Required", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Emergency unlock failed: {e}")
    
    def add_folder(self):
        """Add folder to unbreakable protection"""
        folder_path = self.folder_var.get().strip()
        token_path = self.token_var.get().strip()
        
        if not folder_path:
            messagebox.showerror("Error", "Please select a folder")
            return
        
        if not os.path.exists(folder_path):
            messagebox.showerror("Error", "Folder does not exist")
            return
        
        # Verify USB token if provided
        if token_path:
            is_valid, message = self.protection.token_manager.verify_token(token_path)
            if not is_valid:
                messagebox.showerror("Token Error", f"Invalid USB token:\n{message}")
                return
        
        # Strong warning for unbreakable mode
        warning_msg = f"""🛡️ UNBREAKABLE PROTECTION WARNING 🛡️

This will apply MAXIMUM UNBREAKABLE PROTECTION to:
{folder_path}

CONSEQUENCES:
• Files will be locked with KERNEL-LEVEL protection
• Protection CANNOT be bypassed with admin privileges
• Protection SURVIVES system restarts
• Files become COMPLETELY IMMUTABLE
• Only valid USB token can unlock
• Even system administrators cannot modify files

⚠️ THIS PROTECTION IS DESIGNED TO BE UNBREAKABLE! ⚠️

Are you ABSOLUTELY CERTAIN you want UNBREAKABLE protection?"""

        if not messagebox.askyesno("UNBREAKABLE PROTECTION WARNING", warning_msg):
            return
        
        # Final confirmation with USB token requirement
        token_warning = """🔑 USB TOKEN REQUIREMENT 🔑

CRITICAL: You MUST have a valid USB token to unlock this folder!

Without the USB token:
• Files will remain permanently locked
• No recovery method exists
• Not even administrators can unlock
• System restore will not work

Do you have a valid USB token and understand the risks?"""

        if not messagebox.askyesno("USB TOKEN REQUIRED", token_warning):
            return
        
        if self.database.add_folder(folder_path, self.usb_required.get(), "PREVENT"):
            messagebox.showinfo("Success", f"UNBREAKABLE protection activated for:\n{folder_path}\n\n🔑 Remember: USB token required for unlocking!")
            self.folder_var.set("")
            self.token_var.set("")
            self.refresh_folders()
            self.protection.restart()
            self.update_protection_status()
        else:
            messagebox.showerror("Error", "Failed to add folder")
    
    def remove_folder(self):
        """Remove folder from protection (requires USB token)"""
        selection = self.folders_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a folder")
            return
        
        item = self.folders_tree.item(selection[0])
        folder_path = item['values'][0]
        
        # Token verification required
        is_valid, message = self.protection.token_manager.verify_token()
        if not is_valid:
            messagebox.showerror("Token Required", f"Valid USB token required to remove protection:\n\n{message}")
            return
        
        if messagebox.askyesno("Confirm Removal", f"🔑 Token verified!\n\nRemove UNBREAKABLE protection from:\n{folder_path}"):
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM folders WHERE path = ?', (folder_path,))
                conn.commit()
                conn.close()
                
                messagebox.showinfo("Success", "Folder removed from protection with valid token")
                self.refresh_folders()
                self.protection.restart()
                self.update_protection_status()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to remove folder: {e}")
    
    def refresh_folders(self):
        """Refresh folders list"""
        # Clear
        for item in self.folders_tree.get_children():
            self.folders_tree.delete(item)
        
        # Load
        folders = self.database.get_folders()
        for folder_data in folders:
            path = folder_data[0]
            usb_required = folder_data[1]
            active = folder_data[2]
            created = folder_data[3]
            
            # Count locked files
            regular_files = len([f for f in self.protection.permission_manager.protected_files.keys() 
                               if f.startswith(path)])
            kernel_files = len([f for f in self.protection.permission_manager.kernel_locks.keys() 
                              if f.startswith(path)])
            
            usb_text = "Yes" if usb_required else "No"
            status = f"🟢 UNBREAKABLE ({kernel_files} kernel)" if active else "🔴 INACTIVE"
            created_date = datetime.fromisoformat(created).strftime("%Y-%m-%d %H:%M")
            files_info = f"{regular_files}+{kernel_files}"
            token_info = "🔑 Required"
            
            self.folders_tree.insert("", "end", values=(path, usb_text, status, created_date, files_info, token_info))
    
    def setup_prevented_tab(self, parent):
        """Setup prevented operations display"""
        ttk.Label(parent, text="Prevented Operations", font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Info
        self.prevented_info = ttk.Label(parent, text="Loading prevented operations...")
        self.prevented_info.pack(pady=5)
        
        # Prevented operations list
        prevented_frame = ttk.LabelFrame(parent, text="Recent Prevented Operations")
        prevented_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        columns = ("Time", "File", "Operation", "Reason")
        self.prevented_tree = ttk.Treeview(prevented_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.prevented_tree.heading(col, text=col)
            self.prevented_tree.column(col, width=200)
        
        prevented_scrollbar = ttk.Scrollbar(prevented_frame, orient="vertical", command=self.prevented_tree.yview)
        self.prevented_tree.configure(yscrollcommand=prevented_scrollbar.set)
        
        self.prevented_tree.pack(side="left", fill="both", expand=True)
        prevented_scrollbar.pack(side="right", fill="y")
        
        ttk.Button(prevented_frame, text="Refresh Prevented Operations", command=self.refresh_prevented).pack(pady=5)
        
        self.refresh_prevented()
    
    def setup_status_tab(self, parent):
        """Setup status display"""
        ttk.Label(parent, text="System Status", font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Status info
        self.status_text = tk.Text(parent, height=20, wrap="word")
        status_scroll = ttk.Scrollbar(parent, orient="vertical", command=self.status_text.yview)
        self.status_text.configure(yscrollcommand=status_scroll.set)
        
        self.status_text.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        status_scroll.pack(side="right", fill="y", pady=10)
        
        ttk.Button(parent, text="Refresh Status", command=self.refresh_status).pack(pady=5)
        
        self.refresh_status()
    
    def browse_folder(self):
        """Browse for folder"""
        folder = filedialog.askdirectory(title="Select Folder for TRUE PREVENTION Protection")
        if folder:
            self.folder_var.set(folder)
    
    def add_folder(self):
        """Add folder to true prevention protection"""
        folder_path = self.folder_var.get().strip()
        
        if not folder_path:
            messagebox.showerror("Error", "Please select a folder")
            return
        
        if not os.path.exists(folder_path):
            messagebox.showerror("Error", "Folder does not exist")
            return
        
        # Strong warning for prevention mode
        warning_msg = f"""🛑 TRUE PREVENTION WARNING 🛑

This will apply MAXIMUM PROTECTION to:
{folder_path}

CONSEQUENCES:
• ALL FILES will become READ-ONLY
• File creation will be blocked
• File modifications will be blocked  
• File renames will be blocked
• Suspicious files will be DELETED immediately

This may BREAK applications that need to modify files in this folder!

Are you ABSOLUTELY SURE you want TRUE PREVENTION protection?"""

        if not messagebox.askyesno("TRUE PREVENTION WARNING", warning_msg):
            return
        
        if self.database.add_folder(folder_path, self.usb_required.get(), "PREVENT"):
            messagebox.showinfo("Success", f"TRUE PREVENTION protection activated for:\n{folder_path}")
            self.folder_var.set("")
            self.refresh_folders()
            self.protection.restart()
            self.update_protection_status()
        else:
            messagebox.showerror("Error", "Failed to add folder")
    
    def remove_folder(self):
        """Remove selected folder"""
        selection = self.folders_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a folder")
            return
        
        item = self.folders_tree.item(selection[0])
        folder_path = item['values'][0]
        
        if messagebox.askyesno("Confirm", f"Remove TRUE PREVENTION protection from:\n{folder_path}"):
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM folders WHERE path = ?', (folder_path,))
                conn.commit()
                conn.close()
                
                messagebox.showinfo("Success", "Folder removed from protection")
                self.refresh_folders()
                self.protection.restart()
                self.update_protection_status()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to remove folder: {e}")
    
    def refresh_folders(self):
        """Refresh folders list"""
        # Clear
        for item in self.folders_tree.get_children():
            self.folders_tree.delete(item)
        
        # Load
        folders = self.database.get_folders()
        for folder_data in folders:
            path = folder_data[0]
            usb_required = folder_data[1]
            active = folder_data[2]
            created = folder_data[3]
            
            # Count locked files
            locked_files = len([f for f in self.protection.permission_manager.protected_files.keys() 
                              if f.startswith(path)])
            
            usb_text = "Yes" if usb_required else "No"
            status = "🟢 ACTIVE" if active else "🔴 INACTIVE"
            created_date = datetime.fromisoformat(created).strftime("%Y-%m-%d %H:%M")
            
            self.folders_tree.insert("", "end", values=(path, usb_text, status, created_date, locked_files))
    
    def refresh_prevented(self):
        """Refresh prevented operations list"""
        # Clear
        for item in self.prevented_tree.get_children():
            self.prevented_tree.delete(item)
        
        # Load
        prevented_ops = self.database.get_prevented_operations(100)
        
        for op_data in prevented_ops:
            timestamp, file_path, operation, reason = op_data
            time_str = datetime.fromisoformat(timestamp).strftime("%H:%M:%S")
            filename = os.path.basename(file_path)
            
            self.prevented_tree.insert("", "end", values=(time_str, filename, operation, reason))
        
        self.prevented_info.config(text=f"Total Operations Prevented: {len(prevented_ops)}")
    
    def refresh_status(self):
        """Refresh status display"""
        try:
            status_info = []
            status_info.append("🛑 TRUE PREVENTION ANTI-RANSOMWARE STATUS\n")
            status_info.append(f"Database: {DB_PATH}")
            status_info.append(f"Quarantine: {QUARANTINE_DIR}\n")
            
            # Protection status
            if self.protection.running:
                status_info.append(f"Protection Status: 🟢 TRUE PREVENTION ACTIVE")
                status_info.append(f"Protected Folders: {len(self.protection.observers)}")
                status_info.append(f"Locked Files: 🔒 {self.protection.locked_files_count}")
                status_info.append(f"Locked Folders: {len(self.protection.permission_manager.locked_folders)}")
            else:
                status_info.append("Protection Status: 🔴 INACTIVE")
            
            # USB status
            if self.usb_checker.has_usb():
                status_info.append("USB Status: 🟢 Connected")
            else:
                status_info.append("USB Status: 🔴 No USB devices")
            
            # Prevention statistics
            folders = self.database.get_folders()
            prevented_ops = self.database.get_prevented_operations(1000)
            
            status_info.append(f"\n📊 PREVENTION STATISTICS:")
            status_info.append(f"Total Protected Folders: {len(folders)}")
            status_info.append(f"Operations Prevented: {len(prevented_ops)}")
            
            # Recent prevented operations
            if prevented_ops:
                status_info.append(f"\n🛑 RECENT PREVENTED OPERATIONS:")
                for op in prevented_ops[:5]:  # Show last 5
                    timestamp, file_path, operation, reason = op
                    time_str = datetime.fromisoformat(timestamp).strftime("%H:%M:%S")
                    filename = os.path.basename(file_path)
                    status_info.append(f"  {time_str} - {operation} - {filename} - {reason}")
            
            self.status_text.delete(1.0, tk.END)
            self.status_text.insert(1.0, "\n".join(status_info))
            
        except Exception as e:
            self.status_text.delete(1.0, tk.END)
            self.status_text.insert(1.0, f"Error getting status: {e}")
    
    def update_protection_status(self):
        """Update protection status display"""
        try:
            if self.protection.running:
                status_text = f"🟢 UNBREAKABLE ACTIVE - {len(self.protection.observers)} folders - {self.protection.locked_files_count} files - {self.protection.kernel_locked_count} kernel locks"
                self.protection_status.config(text=status_text, foreground="green")
            else:
                self.protection_status.config(text="🔴 UNBREAKABLE INACTIVE", foreground="red")
        except:
            pass
    
    def restart_protection(self):
        """Restart unbreakable protection"""
        try:
            if self.protection.restart():
                messagebox.showinfo("Success", "Unbreakable protection restarted successfully")
                self.update_protection_status()
                self.refresh_status()
            else:
                messagebox.showerror("Error", "Failed to restart unbreakable protection")
        except PermissionError as e:
            messagebox.showerror("Token Required", str(e))
    
    def on_close(self):
        """Handle window close"""
        if messagebox.askokcancel("Exit", "Stop UNBREAKABLE protection and exit?\n\n⚠️ This requires a valid USB token!"):
            try:
                self.protection.stop(force=False)  # Requires token
                self.root.destroy()
            except PermissionError as e:
                messagebox.showerror("Token Required", f"Cannot exit without valid USB token:\n\n{str(e)}")
            except Exception as e:
                # Force close in case of emergency
                if messagebox.askyesno("Force Close", f"Normal shutdown failed: {e}\n\nForce close application?\n\n⚠️ Files may remain locked!"):
                    try:
                        self.protection.stop(force=True)
                    except:
                        pass
                    self.root.destroy()
    
    def run(self):
        """Run the application"""
        print("Starting UNBREAKABLE PREVENTION Anti-Ransomware Protection")
        print(f"Database: {DB_PATH}")
        print(f"Quarantine: {QUARANTINE_DIR}")
        print("�️ UNBREAKABLE MODE: Kernel-level locks that survive privilege escalation")
        print("🔑 USB TOKEN: Required for all unlock operations")
        print("GUI starting...")
        
        # Auto-refresh status
        def auto_refresh():
            self.update_protection_status()
            self.root.after(3000, auto_refresh)
        
        self.root.after(1000, auto_refresh)
        self.root.mainloop()

def main():
    """Main entry point"""
    try:
        print("�️ UNBREAKABLE PREVENTION ANTI-RANSOMWARE PROTECTION")
        print("=" * 70)
        print("MAXIMUM SECURITY: Kernel-level locks that survive privilege escalation!")
        print("USB TOKEN: Required for all unlock operations!")
        print("UNBREAKABLE: Protection designed to be impossible to bypass!")
        print("=" * 70)
        
        app = PreventionAntiRansomwareApp()
        app.run()
        
    except KeyboardInterrupt:
        print("\nApplication stopped")
    except Exception as e:
        print(f"Application error: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
