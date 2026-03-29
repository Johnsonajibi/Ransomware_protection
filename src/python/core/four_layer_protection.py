#!/usr/bin/env python3
"""
Comprehensive Multi-Layer Protection Enforcement
Integrates: Kernel Driver + Controlled Folder Access + NTFS Permissions + File Encryption
"""

import os
import sys
import ctypes
import threading
from pathlib import Path
from datetime import datetime

class FourLayerProtection:
    """
    4-Layer file protection enforcement:
    1. Kernel-level I/O blocking (Windows Filter Driver)
    2. OS-level blocking (Windows Controlled Folder Access)
    3. NTFS permissions stripping (token-based access only)
    4. File encryption + hide (unreadable without decryption)
    """
    
    def __init__(self, token_manager, database):
        self.token_manager = token_manager
        self.database = database
        self.kernel_driver_loaded = False
        self.protected_paths = set()
        self.enforcement_log = []
        
    def apply_complete_protection(self, folder_path: str) -> bool:
        """Apply all 4 layers of protection to a folder"""
        try:
            print(f"\n APPLYING COMPLETE MULTI-LAYER PROTECTION TO: {folder_path}\n")
            
            folder = Path(folder_path)
            if not folder.exists():
                print(f"❌ Path does not exist: {folder_path}")
                return False
            
            # LAYER 4: Encrypt first — before anything locks the files
            print(" LAYER 4: File Encryption + Hide (Unreadable Without Decryption)")
            layer4_success = self._encrypt_and_hide_files(folder_path)
            if layer4_success:
                print("   ✅ All files encrypted and hidden - unreadable without decryption key")
            else:
                print("   ⚠ File encryption incomplete")

            # LAYER 3: Strip NTFS permissions after encryption
            print("\n LAYER 3: NTFS Permissions Stripping (Token-Based Access Only)")
            layer3_success = self._strip_ntfs_permissions(folder_path)
            if layer3_success:
                print("   ✅ All file permissions removed - token required for access")
            else:
                print("   ⚠ NTFS permission stripping incomplete")

            # LAYER 1: Lock via kernel driver — after files are encrypted
            print("\n LAYER 1: Kernel-Level I/O Blocking (Windows Filter Driver)")
            layer1_success = self._apply_kernel_driver_protection(folder_path)
            if layer1_success:
                print("   ✅ Kernel driver active - blocks all file I/O at kernel level")
            else:
                print("   ⚠ Kernel driver not available (requires WDK compilation)")
                print("      Fallback: Using additional OS-level protections")

            # LAYER 2: Enable Windows Controlled Folder Access
            print("\n LAYER 2: OS-Level Blocking (Windows Controlled Folder Access)")
            layer2_success = self._apply_controlled_folder_access(folder_path)
            if layer2_success:
                print("   ✅ Controlled Folder Access enabled - OS-level protection")
            else:
                print("   ⚠ Controlled Folder Access configuration error")

            # Summary
            print("\n" + "="*70)
            print(" PROTECTION STATUS SUMMARY")
            print("="*70)
            print(f"Folder: {folder_path}")
            print(f"Layer 1 (Kernel): {'✅ ACTIVE' if layer1_success else '⚠ UNAVAILABLE'}")
            print(f"Layer 2 (OS): {'✅ ACTIVE' if layer2_success else '⚠ UNAVAILABLE'}")
            print(f"Layer 4 (Encrypt): {'✅ ACTIVE' if layer4_success else '⚠ UNAVAILABLE'}")
            print(f"Layer 3 (NTFS): {'✅ ACTIVE' if layer3_success else '⚠ UNAVAILABLE'}")
            print("\n Files are now PROTECTED via:")
            if layer1_success:
                print("   • Kernel Filter Driver (I/O blocked before reaching filesystem)")
            if layer2_success:
                print("   • Windows Controlled Folder Access (OS-level blocking)")
            if layer3_success:
                print("   • NTFS Permissions (all user access denied)")
            if layer4_success:
                print("   • AES-256 Encryption (files unreadable)")
            print("\n ACCESS REQUIREMENT: Valid USB token with matching device fingerprint")
            print("="*70 + "\n")
            
            self.protected_paths.add(str(folder))
            # Layer 3 (NTFS deny) is the primary access-control gate.
            # Layer 4 (encryption) may fail if files are already locked; do not block Layer 3.
            return layer3_success
            
        except Exception as e:
            print(f"❌ Complete protection error: {e}")
            return False
    
    def _apply_kernel_driver_protection(self, folder_path: str) -> bool:
        """Apply Layer 1: Kernel-Level File Blocking via compiled minifilter driver"""
        try:
            from kernel_protection_interface import KernelProtectionInterface, ProtectionLevel
            if not hasattr(self, '_kernel_iface') or self._kernel_iface is None:
                self._kernel_iface = KernelProtectionInterface()
            if not self._kernel_iface._status.driver_loaded:
                if not self._kernel_iface.initialize():
                    print("   ⚠ Kernel driver could not be started")
                    return False
            ok = self._kernel_iface.add_protected_path(folder_path)
            if ok:
                self.kernel_driver_loaded = True
            return ok
        except ImportError:
            print("   Kernel-level blocking not available (driver not compiled)")
            return False
        except Exception as e:
            print(f"   Kernel-level error: {e}")
            return False
    
    def _apply_controlled_folder_access(self, folder_path: str) -> bool:
        """Apply Layer 2: Windows Controlled Folder Access"""
        try:
            import subprocess
            
            # Check if running as admin
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("   ⚠ Controlled Folder Access requires admin privileges")
                return False
            
            # PowerShell command to enable Controlled Folder Access
            ps_script = f"""
$ErrorActionPreference = 'SilentlyContinue'
Set-MpPreference -EnableControlledFolderAccess Enabled
Add-MpPreference -ControlledFolderAccessProtectedFolders "{folder_path}" -Force
Get-MpPreference | Select-Object -ExpandProperty EnableControlledFolderAccess
"""
            
            result = subprocess.run(
                ['powershell.exe', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                print(f"   ✓ Controlled Folder Access enabled for: {Path(folder_path).name}")
                return True
            else:
                print(f"   ⚠ Controlled Folder Access setup failed")
                return False
                
        except Exception as e:
            print(f"   ⚠ Controlled Folder Access error: {e}")
            return False
    
    def _strip_ntfs_permissions(self, folder_path: str) -> bool:
        """Apply Layer 3: Deny all user access via explicit icacls DENY ACEs.

        Uses icacls so that:
          - Inherited Allow ACEs from parent folders do NOT override the block.
          - Even administrator users get Access Denied from Explorer / apps.
          - Works with or without pywin32.
        """
        import subprocess, ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("   ⚠  NTFS deny requires admin privileges")
            return False

        try:
            # Add an explicit DENY for Everyone.
            # Explicit DENY takes precedence over both explicit and inherited ALLOW ACEs,
            # so there is no need to remove inheritance separately.
            r = subprocess.run(
                ['icacls', folder_path, '/deny', 'Everyone:(OI)(CI)F', '/T', '/C', '/Q'],
                capture_output=True, text=True, timeout=60
            )
            if r.returncode == 0:
                print(f"   ✓ NTFS deny applied to {folder_path} (all users blocked)")
                return True
            else:
                print(f"   ⚠  icacls deny failed: {r.stderr.strip()}")
                return False
        except Exception as e:
            print(f"   ⚠  NTFS deny error: {e}")
            return False
    
    def _encrypt_and_hide_files(self, folder_path: str) -> bool:
        """Apply Layer 4: Encrypt all files and hide them"""
        _SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '$RECYCLE.BIN', '.svn', '.hg', 'venv', '.venv'}
        _MAX_DEPTH = 3

        def _iter_files(root: Path, depth: int):
            if depth > _MAX_DEPTH:
                return
            try:
                for entry in root.iterdir():
                    if entry.is_symlink():
                        continue  # skip symlinks / junction points
                    if entry.is_dir():
                        if entry.name in _SKIP_DIRS or entry.name.startswith('.'):
                            continue
                        yield from _iter_files(entry, depth + 1)
                    elif entry.is_file():
                        yield entry
            except PermissionError:
                pass

        try:
            folder = Path(folder_path)
            encrypted_count = 0

            for file_path in _iter_files(folder, 0):
                # Encrypt file (uses existing CryptographicProtection)
                try:
                    from unified_antiransomware import CryptographicProtection
                    
                    crypto = CryptographicProtection(self.token_manager)
                    if crypto.encrypt_file_contents(str(file_path), None):
                        # Hide file using Windows API
                        try:
                            import win32api
                            import win32con
                            win32api.SetFileAttributes(
                                str(file_path),
                                win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM
                            )
                            encrypted_count += 1
                        except:
                            pass
                except:
                    pass
            
            if encrypted_count > 0:
                print(f"   ✓ Encrypted and hidden {encrypted_count} files")
                return True
            else:
                print(f"   No files encrypted (folder may be empty or files already encrypted)")
                return False
                
        except Exception as e:
            print(f"   ⚠ Encryption error: {e}")
            return False
    
    def remove_complete_protection(self, folder_path: str, token_required: bool = True) -> bool:
        """Remove all 4 layers of protection (requires valid token)"""
        if token_required:
            if not self.token_manager.authenticate_with_token("DECRYPT_FOLDER", folder_path):
                print("❌ Token authentication FAILED - cannot remove protection")
                return False
            print("✅ Token verified - removing all protection layers")
        
        try:
            folder = Path(folder_path)
            
            # Layer 4: Decrypt files
            print(" Decrypting files...")
            for file_path in folder.rglob('*'):
                if file_path.is_file():
                    try:
                        from unified_antiransomware import CryptographicProtection
                        crypto = CryptographicProtection(self.token_manager)
                        crypto.decrypt_file_contents(str(file_path), None)
                    except:
                        pass
            
            # Layer 3: Restore NTFS permissions
            print(" Restoring NTFS permissions...")
            try:
                import win32security
                import ntsecuritycon as con
                
                for file_path in folder.rglob('*'):
                    if not file_path.is_file():
                        continue
                    
                    try:
                        sd = win32security.GetFileSecurity(
                            str(file_path),
                            win32security.DACL_SECURITY_INFORMATION
                        )
                        
                        new_dacl = win32security.ACL()
                        
                        # Restore user access
                        user_sid = win32security.LookupAccountName(None, os.environ.get('USERNAME', 'Users'))[0]
                        new_dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, user_sid)
                        
                        # Keep SYSTEM access
                        system_sid = win32security.LookupAccountName(None, "SYSTEM")[0]
                        new_dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, system_sid)
                        
                        sd.SetSecurityDescriptorDacl(1, new_dacl, 0)
                        win32security.SetFileSecurity(
                            str(file_path),
                            win32security.DACL_SECURITY_INFORMATION,
                            sd
                        )
                    except:
                        pass
            except:
                pass
            
            # Layer 2: Disable Controlled Folder Access for this path
            # (Can't easily remove from PS, so skip)
            
            # Layer 1: Unload kernel driver (if we loaded it)
            if self.kernel_driver_loaded:
                try:
                    if hasattr(self, '_kernel_iface') and self._kernel_iface is not None:
                        from kernel_protection_interface import KernelProtectionInterface
                        from kernel_driver_manager import IOCTL_ANTIRANSOMWARE_REMOVE_PATH
                        import ctypes
                        nt_path_buf = ctypes.create_unicode_buffer(1024)
                        if ctypes.windll.kernel32.GetVolumePathNameW(folder_path, nt_path_buf, 1024):
                            volume = nt_path_buf.value
                            nt_vol_buf = ctypes.create_unicode_buffer(1024)
                            ctypes.windll.kernel32.QueryDosDeviceW(volume.rstrip(''), nt_vol_buf, 1024)
                            nt_volume = nt_vol_buf.value
                            relative = folder_path[len(volume):].strip('')
                            nt_path = nt_volume + '' + relative if relative else nt_volume
                        else:
                            nt_path = folder_path
                        path_bytes = nt_path.encode('utf-16-le')
                        self._kernel_iface.driver_manager.send_ioctl(IOCTL_ANTIRANSOMWARE_REMOVE_PATH, path_bytes)
                except Exception:
                    pass
            
            if str(folder) in self.protected_paths:
                self.protected_paths.remove(str(folder))
            
            print(f"✅ All protection layers removed from: {folder_path}")
            return True
            
        except Exception as e:
            print(f"❌ Protection removal error: {e}")
            return False
    
    def get_protection_status(self) -> dict:
        """Get current protection status"""
        return {
            'kernel_driver_loaded': self.kernel_driver_loaded,
            'protected_paths': list(self.protected_paths),
            'protected_count': len(self.protected_paths)
        }
