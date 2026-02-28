#!/usr/bin/env python3
"""
Simple folder unlocker utility for USB token authentication
"""
import os
import stat
import sys
from pathlib import Path
import subprocess
import shlex

class FolderUnlocker:
    def __init__(self):
        self.usb_drive = self.find_usb_tokens()
    
    def find_usb_tokens(self):
        """Find USB drive with protection tokens"""
        drives = ['E:', 'F:', 'G:', 'H:', 'I:', 'J:', 'K:']
        for drive in drives:
            if os.path.exists(drive):
                token_files = []
                try:
                    for file in os.listdir(drive):
                        if file.startswith('protection_token_') and file.endswith('.key'):
                            token_files.append(os.path.join(drive, file))
                    if token_files:
                        print(f"🔑 Found {len(token_files)} USB tokens on drive {drive}")
                        return drive
                except:
                    continue
        return None
    
    def unlock_folder(self, folder_path):
        """Unlock a protected folder by removing system attributes and restoring permissions"""
        if not self.usb_drive:
            print("❌ No USB tokens found! Please insert your authentication USB drive.")
            return False
        
        folder_path = Path(folder_path)
        if not folder_path.exists():
            print(f"❌ Folder not found: {folder_path}")
            return False
        
        try:
            print(f"🔓 Unlocking folder: {folder_path}")
            
            # Remove system attributes using attrib command
            # SAFE: Use list-based arguments to prevent injection
            cmd = ['attrib', '-R', '-H', '-S', str(folder_path)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ System attributes removed")
            else:
                print(f"⚠️  Attribute removal warning: {result.stderr}")
            
            # Try to restore normal permissions
            try:
                # Make folder readable and writable
                folder_path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | 
                                stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP |
                                stat.S_IROTH | stat.S_IXOTH)
                print("✅ Permissions restored")
            except Exception as e:
                print(f"⚠️  Permission warning: {e}")
            
            # Verify folder is now accessible
            try:
                files = list(folder_path.iterdir())
                print(f"✅ Folder unlocked successfully! Contains {len(files)} items:")
                for item in files[:10]:  # Show first 10 items
                    print(f"   📁 {item.name}")
                if len(files) > 10:
                    print(f"   ... and {len(files) - 10} more items")
                return True
                
            except Exception as e:
                print(f"❌ Folder still protected: {e}")
                return False
                
        except Exception as e:
            print(f"❌ Error unlocking folder: {e}")
            return False
    
    def show_hidden_folders(self, directory):
        """Show all folders including hidden/system ones using safe native Python"""
        try:
            target_dir = Path(directory)
            if not target_dir.exists():
                print(f"❌ Directory not found: {directory}")
                return

            print(f"📂 All folders in {target_dir} (including hidden/system):")
            count = 0
            # iterate using native path object which sees all files including hidden ones on Windows
            for item in target_dir.iterdir():
                if item.is_dir():
                    try:
                        # Check hidden attribute
                        is_hidden = False
                        if os.name == 'nt':
                            import ctypes
                            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(item))
                            if attrs != -1 and (attrs & 2):  # FILE_ATTRIBUTE_HIDDEN
                                is_hidden = True
                        
                        prefix = "🔒 " if is_hidden else "📁 "
                        suffix = " (Hidden)" if is_hidden else ""
                        print(f"{prefix}{item.name}{suffix}")
                        count += 1
                    except Exception as e:
                        print(f"⚠️  Error accessing {item.name}: {e}")
            
            if count == 0:
                print("   (No folders found)")
                
        except Exception as e:
            print(f"Error listing folders: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python unlock_folder.py <folder_path>")
        print("   or: python unlock_folder.py --show-all <directory>")
        sys.exit(1)
    
    unlocker = FolderUnlocker()
    
    if sys.argv[1] == "--show-all":
        directory = sys.argv[2] if len(sys.argv) > 2 else "."
        unlocker.show_hidden_folders(directory)
    else:
        folder_path = sys.argv[1]
        success = unlocker.unlock_folder(folder_path)
        if success:
            print("🎉 Folder successfully unlocked and accessible!")
        else:
            print("❌ Failed to unlock folder")

if __name__ == "__main__":
    main()
