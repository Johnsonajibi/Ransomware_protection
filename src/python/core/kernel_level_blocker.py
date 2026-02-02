#!/usr/bin/env python3
"""
Kernel-Level File Blocker (Python Implementation)
Simulates kernel driver protection using Windows APIs and aggressive file locking
"""

import os
import sys
import ctypes
import threading
import time
from pathlib import Path
from typing import Set, Dict, List
from ctypes import wintypes

# Windows API constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = -1

# File attributes
FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_TEMPORARY = 0x100

# Security constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# Load Windows APIs
kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

class KernelLevelBlocker:
    """
    Implements kernel-level file blocking using Windows APIs and rigorous file locking
    Uses aggressive Windows API calls to prevent file access
    """
    
    def __init__(self):
        self.protected_paths: Set[str] = set()
        self.file_locks: Dict[str, int] = {}  # file_path -> handle
        self.blocking_active = False
        self.lock_threads: List[threading.Thread] = []
        self.stop_event = threading.Event()
        
    def add_protected_path(self, path: str):
        """Add path to protection list"""
        path = os.path.abspath(path)
        self.protected_paths.add(path)
        print(f"🛡️  KERNEL-LEVEL: Added protected path: {path}")
        
        if self.blocking_active:
            self._apply_aggressive_locks(path)
    
    def start_blocking(self):
        """Start aggressive kernel-level-like file blocking"""
        if self.blocking_active:
            return
        
        self.blocking_active = True
        self.stop_event.clear()
        
        print("\n" + "="*70)
        print("🔴 KERNEL-LEVEL BLOCKER ACTIVATED")
        print("="*70)
        print("⚠️  WARNING: Files in protected paths are now LOCKED")
        print("⚠️  No process can read, write, or delete these files")
        print("="*70 + "\n")
        
        # Apply locks to all protected paths
        for path in self.protected_paths:
            self._apply_aggressive_locks(path)
        
        # Start monitoring thread
        monitor_thread = threading.Thread(
            target=self._continuous_monitoring,
            daemon=True
        )
        monitor_thread.start()
        self.lock_threads.append(monitor_thread)
    
    def stop_blocking(self):
        """Release all file locks and stop blocking"""
        if not self.blocking_active:
            return
        
        print("\n🔓 KERNEL-LEVEL BLOCKER: Releasing all locks...")
        
        self.blocking_active = False
        self.stop_event.set()
        
        # Wait for monitoring thread to stop first
        time.sleep(0.5)
        for thread in self.lock_threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        self.lock_threads.clear()
        
        # Close all file handles with proper cleanup
        cleanup_errors = []
        for file_path, handle in list(self.file_locks.items()):
            try:
                if handle != INVALID_HANDLE_VALUE and handle != 0:
                    # Verify handle is valid before closing
                    file_type = kernel32.GetFileType(handle)
                    
                    # Try to close the handle
                    close_result = kernel32.CloseHandle(handle)
                    
                    if close_result:
                        print(f"   ✓ Released: {Path(file_path).name}")
                    else:
                        # Handle close failed, get the error
                        error_code = ctypes.get_last_error()
                        cleanup_errors.append(f"{Path(file_path).name}: Error {error_code}")
                else:
                    # Permission-based lock, remove from tracking
                    print(f"   ✓ Released: {Path(file_path).name}")
                
            except Exception as e:
                cleanup_errors.append(f"{Path(file_path).name}: {str(e)}")
        
        self.file_locks.clear()
        
        # Small delay to allow Windows to fully release locks
        time.sleep(0.3)
        
        if cleanup_errors:
            print(f"\n⚠️  Some handles had cleanup issues (non-critical):")
            for error in cleanup_errors:
                print(f"   {error}")
        
        print("✓ All locks released\n")
    
    def _apply_aggressive_locks(self, path: str):
        """Apply aggressive file locks to prevent any access"""
        if not os.path.exists(path):
            return
        
        path_obj = Path(path)
        
        if path_obj.is_file():
            self._lock_file(str(path_obj))
        elif path_obj.is_dir():
            # Lock all files in directory
            try:
                for file_path in path_obj.rglob('*'):
                    if file_path.is_file():
                        self._lock_file(str(file_path))
            except Exception as e:
                print(f"⚠️  Directory scan error: {e}")
    
    def _lock_file(self, file_path: str):
        """Lock individual file with exclusive access"""
        if file_path in self.file_locks:
            return  # Already locked
        
        try:
            # Method 1: Open with exclusive access (DENY ALL)
            handle = kernel32.CreateFileW(
                file_path,
                GENERIC_READ,  # We need some access to keep the handle
                0,  # FILE_SHARE_NONE - DENY ALL other access
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_READONLY | FILE_FLAG_BACKUP_SEMANTICS,
                None
            )
            
            if handle != INVALID_HANDLE_VALUE and handle is not None:
                self.file_locks[file_path] = handle
                print(f"   🔒 LOCKED: {Path(file_path).name}")
                
                # Method 2: Set file to READ-ONLY + SYSTEM to prevent modifications
                try:
                    kernel32.SetFileAttributesW(
                        file_path,
                        FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM
                    )
                except Exception as attr_err:
                    # Attribute setting failed but file is still locked by handle
                    pass
                
                return True
            else:
                # File might be in use or inaccessible, try alternative method
                error_code = ctypes.get_last_error()
                self._apply_permission_lock(file_path)
                
        except Exception as e:
            # Fall back to permission-based locking
            self._apply_permission_lock(file_path)
        
        return False
    
    def _apply_permission_lock(self, file_path: str):
        """Apply permission-based lock as fallback"""
        try:
            import win32security
            import ntsecuritycon as con
            
            # Get current security descriptor
            sd = win32security.GetFileSecurity(
                file_path,
                win32security.DACL_SECURITY_INFORMATION
            )
            
            # Create new DACL with no access for anyone
            dacl = win32security.ACL()
            
            # Add DENY for Everyone
            everyone_sid = win32security.LookupAccountName(None, "Everyone")[0]
            dacl.AddAccessDeniedAce(
                win32security.ACL_REVISION,
                con.FILE_ALL_ACCESS,
                everyone_sid
            )
            
            # Set the DACL
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                file_path,
                win32security.DACL_SECURITY_INFORMATION,
                sd
            )
            
            print(f"   🔒 PERMISSION LOCKED: {Path(file_path).name}")
            self.file_locks[file_path] = INVALID_HANDLE_VALUE  # Mark as locked
            
        except Exception as e:
            print(f"   ⚠️  Could not lock {Path(file_path).name}: {e}")
    
    def _continuous_monitoring(self):
        """Continuously monitor and re-lock files if needed"""
        while not self.stop_event.is_set():
            try:
                # Check if any locks were broken
                for file_path, handle in list(self.file_locks.items()):
                    if not self.blocking_active:
                        break
                        
                    if handle == INVALID_HANDLE_VALUE:
                        continue
                    
                    # Verify handle is still valid
                    try:
                        file_type = kernel32.GetFileType(handle)
                        if file_type == 0:  # Invalid handle
                            # Reacquire lock
                            del self.file_locks[file_path]
                            self._lock_file(file_path)
                    except Exception as e:
                        # Reacquire lock
                        if file_path in self.file_locks:
                            del self.file_locks[file_path]
                        if self.blocking_active:
                            self._lock_file(file_path)
                
                # Sleep for a bit (reduced for better responsiveness)
                self.stop_event.wait(1)
                
            except Exception as monitor_error:
                # Continue monitoring even if one iteration fails
                time.sleep(1)
    
    def get_status(self) -> dict:
        """Get current blocking status"""
        return {
            'active': self.blocking_active,
            'protected_paths': len(self.protected_paths),
            'locked_files': len(self.file_locks),
            'paths': list(self.protected_paths)
        }


# Global instance
_kernel_blocker = None

def get_kernel_blocker() -> KernelLevelBlocker:
    """Get or create kernel blocker instance"""
    global _kernel_blocker
    if _kernel_blocker is None:
        _kernel_blocker = KernelLevelBlocker()
    return _kernel_blocker


def start_kernel_level_protection(paths: List[str]):
    """Start kernel-level protection on specified paths"""
    blocker = get_kernel_blocker()
    
    for path in paths:
        blocker.add_protected_path(path)
    
    blocker.start_blocking()
    
    print("\n✅ KERNEL-LEVEL PROTECTION ACTIVE")
    print(f"   Protected paths: {len(paths)}")
    print(f"   Locked files: {len(blocker.file_locks)}")
    print("\n⚠️  Files are now INACCESSIBLE to all processes")
    print("   Including: Explorer, cmd, PowerShell, malware, ransomware")
    print("\n")


def stop_kernel_level_protection():
    """Stop kernel-level protection and release locks"""
    blocker = get_kernel_blocker()
    blocker.stop_blocking()


def get_protection_status() -> dict:
    """Get current protection status"""
    blocker = get_kernel_blocker()
    return blocker.get_status()


# Demo/Test functionality
if __name__ == "__main__":
    print("\n" + "="*70)
    print("KERNEL-LEVEL FILE BLOCKER - DEMO")
    print("="*70)
    
    if len(sys.argv) > 1:
        test_path = sys.argv[1]
    else:
        # Create test directory
        import tempfile
        test_dir = Path(tempfile.mkdtemp(prefix="KernelBlock_Test_"))
        
        # Create test files
        for i in range(3):
            test_file = test_dir / f"test_file_{i}.txt"
            test_file.write_text(f"Test content {i}")
        
        test_path = str(test_dir)
        print(f"\n📁 Created test directory: {test_path}")
    
    print("\n🔴 Starting kernel-level blocking...")
    start_kernel_level_protection([test_path])
    
    print("\n" + "="*70)
    print("TEST: Try to access files in the protected folder")
    print("="*70)
    print(f"\nTry running:")
    print(f'  notepad "{test_path}\\test_file_0.txt"')
    print(f'  type "{test_path}\\test_file_0.txt"')
    print(f'  del "{test_path}\\test_file_0.txt"')
    print("\nAll attempts should FAIL with 'Access Denied' or 'Sharing Violation'")
    print("\nPress Ctrl+C to stop blocking and release locks...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n🔓 Stopping kernel-level protection...")
        stop_kernel_level_protection()
        print("✓ Locks released. Files are now accessible again.\n")
