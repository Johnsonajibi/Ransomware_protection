#!/usr/bin/env python3
"""
Restore access to folders that were protected before the fix
Removes ACLs, unhides files, and restores normal access
"""

import os
import sys
from pathlib import Path

try:
    import win32security
    import ntsecuritycon as con
    import win32api
    import win32con
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False
    print("⚠️ pywin32 not available - limited functionality")

def restore_folder_access(folder_path):
    """Restore normal access to a folder and all its files"""
    folder = Path(folder_path)
    
    if not folder.exists():
        print(f"❌ Folder not found: {folder_path}")
        return False
    
    print(f"\n🔓 Restoring access to: {folder_path}")
    files_restored = 0
    errors = []
    
    if not HAS_PYWIN32:
        print("❌ Cannot restore access - pywin32 is required")
        print("   Install with: pip install pywin32")
        return False
    
    try:
        # Process all files in the folder
        all_files = list(folder.rglob('*'))
        total_files = len([f for f in all_files if f.is_file()])
        
        print(f"📁 Found {total_files} files to restore...")
        
        for file_path in all_files:
            if file_path.is_file():
                try:
                    # Step 1: Restore ACLs - grant Everyone full access
                    try:
                        sd = win32security.GetFileSecurity(
                            str(file_path),
                            win32security.DACL_SECURITY_INFORMATION
                        )
                        
                        # Create new DACL with full access for Everyone
                        dacl = win32security.ACL()
                        everyone_sid = win32security.ConvertStringSidToSid("S-1-1-0")  # Everyone
                        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, everyone_sid)
                        
                        # Apply the new DACL
                        sd.SetSecurityDescriptorDacl(1, dacl, 0)
                        win32security.SetFileSecurity(str(file_path), win32security.DACL_SECURITY_INFORMATION, sd)
                    except Exception as e:
                        errors.append(f"ACL restore failed for {file_path.name}: {e}")
                    
                    # Step 2: Remove file attributes (hidden, read-only, system)
                    try:
                        win32api.SetFileAttributes(
                            str(file_path),
                            win32con.FILE_ATTRIBUTE_NORMAL
                        )
                    except Exception as e:
                        errors.append(f"Attribute restore failed for {file_path.name}: {e}")
                    
                    files_restored += 1
                    if files_restored % 10 == 0:
                        print(f"  ✓ Restored {files_restored}/{total_files} files...")
                    
                except Exception as e:
                    errors.append(f"Failed to restore {file_path.name}: {e}")
        
        # Restore folder attributes
        try:
            win32api.SetFileAttributes(
                str(folder),
                win32con.FILE_ATTRIBUTE_NORMAL
            )
        except Exception as e:
            print(f"⚠️ Could not restore folder attributes: {e}")
        
        print(f"\n✅ Restoration complete:")
        print(f"   📄 Files restored: {files_restored}/{total_files}")
        if errors:
            print(f"   ⚠️ Errors: {len(errors)}")
            print("\nError details:")
            for err in errors[:5]:  # Show first 5 errors
                print(f"   • {err}")
            if len(errors) > 5:
                print(f"   ... and {len(errors) - 5} more errors")
        
        return True
        
    except Exception as e:
        print(f"❌ Error restoring folder: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 70)
    print("RESTORE ACCESS TO PROTECTED FOLDERS")
    print("=" * 70)
    
    if not HAS_PYWIN32:
        print("\n❌ This script requires pywin32")
        print("Install with: pip install pywin32")
        return
    
    # Common protected folders
    common_paths = [
        r"C:\Users\ajibi\OneDrive\Desktop\Test",
        r"C:\Users\ajibi\OneDrive\Desktop\TestLogging",
        r"C:\Users\ajibi\Desktop\Test",
        r"C:\Users\ajibi\Documents",
        r"C:\Users\ajibi\Downloads",
    ]
    
    print("\nCommon protected folder locations:")
    for i, path in enumerate(common_paths, 1):
        exists = "✓" if Path(path).exists() else "✗"
        print(f"  {i}. [{exists}] {path}")
    
    print("\nOptions:")
    print("  1-5: Restore access to specific folder")
    print("  C: Enter custom path")
    print("  A: Restore all existing folders")
    print("  Q: Quit")
    
    choice = input("\nYour choice: ").strip().upper()
    
    if choice == 'Q':
        print("Cancelled.")
        return
    
    elif choice == 'A':
        print("\n🔄 Restoring all existing folders...")
        for path in common_paths:
            if Path(path).exists():
                restore_folder_access(path)
    
    elif choice == 'C':
        custom_path = input("\nEnter full folder path: ").strip().strip('"')
        restore_folder_access(custom_path)
    
    elif choice.isdigit() and 1 <= int(choice) <= len(common_paths):
        idx = int(choice) - 1
        path = common_paths[idx]
        if Path(path).exists():
            restore_folder_access(path)
        else:
            print(f"❌ Folder does not exist: {path}")
    
    else:
        print("Invalid choice.")
    
    print("\n" + "=" * 70)

if __name__ == "__main__":
    main()
