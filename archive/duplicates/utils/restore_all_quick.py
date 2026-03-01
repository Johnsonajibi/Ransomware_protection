#!/usr/bin/env python3
"""
Quickly restore access to all previously protected folders
"""

import os
from pathlib import Path

try:
    import win32security
    import ntsecuritycon as con
    import win32api
    import win32con
except ImportError:
    print("❌ pywin32 not available - install with: pip install pywin32")
    exit(1)

# List of folders that might have been protected
folders_to_restore = [
    r"C:\Users\ajibi\OneDrive\Desktop\Test",
    r"C:\Users\ajibi\OneDrive\Desktop\TestLogging",
    r"C:\Users\ajibi\Desktop\Test",
]

print("=" * 70)
print("RESTORING ACCESS TO PREVIOUSLY PROTECTED FOLDERS")
print("=" * 70)

total_restored = 0

for folder_path in folders_to_restore:
    folder = Path(folder_path)
    
    if not folder.exists():
        print(f"\n⊘ Skipped (not found): {folder_path}")
        continue
    
    print(f"\n🔓 Restoring: {folder_path}")
    files_restored = 0
    
    try:
        for file_path in folder.rglob('*'):
            if file_path.is_file():
                try:
                    # Restore ACLs
                    sd = win32security.GetFileSecurity(
                        str(file_path),
                        win32security.DACL_SECURITY_INFORMATION
                    )
                    
                    dacl = win32security.ACL()
                    everyone_sid = win32security.ConvertStringSidToSid("S-1-1-0")
                    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, everyone_sid)
                    
                    sd.SetSecurityDescriptorDacl(1, dacl, 0)
                    win32security.SetFileSecurity(str(file_path), win32security.DACL_SECURITY_INFORMATION, sd)
                    
                    # Remove attributes
                    win32api.SetFileAttributes(str(file_path), win32con.FILE_ATTRIBUTE_NORMAL)
                    
                    files_restored += 1
                except:
                    pass
        
        # Restore folder attributes
        try:
            win32api.SetFileAttributes(str(folder), win32con.FILE_ATTRIBUTE_NORMAL)
        except:
            pass
        
        print(f"   ✅ Restored {files_restored} files")
        total_restored += files_restored
        
    except Exception as e:
        print(f"   ⚠️ Error: {e}")

print("\n" + "=" * 70)
print(f"✅ COMPLETE - Restored access to {total_restored} total files")
print("=" * 70)
print("\nAll files should now be accessible normally.")
