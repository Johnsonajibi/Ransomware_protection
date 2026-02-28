#!/usr/bin/env python3
"""
Command-line tool for adding files to protected folders
"""
import os
import sys
import shutil
import subprocess
from pathlib import Path

def find_usb_tokens():
    """Find USB drives with protection tokens"""
    drives = ['E:', 'F:', 'G:', 'H:', 'I:', 'J:', 'K:']
    tokens = []
    
    for drive in drives:
        if os.path.exists(drive):
            try:
                for file in os.listdir(drive):
                    if file.startswith('protection_token_') and file.endswith('.key'):
                        tokens.append(os.path.join(drive, file))
            except:
                continue
    
    return tokens

def is_protected_folder(folder_path):
    """Check if folder has protection attributes"""
    try:
        result = subprocess.run(['attrib', folder_path], capture_output=True, text=True)
        return 'H' in result.stdout and 'S' in result.stdout
    except:
        return False

def temporarily_unlock_folder(folder_path):
    """Temporarily remove protection from folder"""
    try:
        subprocess.run(['attrib', '-H', '-S', '-R', folder_path], 
                      capture_output=True, check=True)
        return True
    except:
        return False

def re_protect_folder(folder_path):
    """Re-apply protection to folder"""
    try:
        subprocess.run(['attrib', '+H', '+S', '+R', folder_path], 
                      capture_output=True, check=True)
        return True
    except:
        return False

def protect_file(file_path):
    """Apply protection attributes to a file"""
    try:
        subprocess.run(['attrib', '+H', '+S', '+R', file_path], 
                      capture_output=True, check=True)
        return True
    except:
        return False

def add_files_to_protected_folder(folder_path, file_paths):
    """Add files to a protected folder with proper security"""
    
    print(f"🔐 PROTECTED FOLDER FILE ADDITION")
    print("=" * 50)
    
    # Check USB tokens
    tokens = find_usb_tokens()
    if not tokens:
        print("❌ No USB tokens found! Please insert your authentication USB drive.")
        return False
    
    print(f"✅ Found {len(tokens)} USB tokens")
    
    # Verify folder is protected
    if not is_protected_folder(folder_path):
        print(f"⚠️  Folder is not protected: {folder_path}")
        print("   Adding files to unprotected folder...")
    else:
        print(f"🛡️ Confirmed protected folder: {folder_path}")
    
    # Verify files exist
    valid_files = []
    for file_path in file_paths:
        if os.path.exists(file_path):
            valid_files.append(file_path)
            print(f"✅ File found: {os.path.basename(file_path)}")
        else:
            print(f"❌ File not found: {file_path}")
    
    if not valid_files:
        print("❌ No valid files to add")
        return False
    
    print(f"\n🔄 Processing {len(valid_files)} files...")
    
    try:
        # Step 1: Temporarily unlock folder
        print("🔓 Step 1: Temporarily unlocking folder...")
        if is_protected_folder(folder_path):
            if not temporarily_unlock_folder(folder_path):
                print("❌ Failed to unlock folder")
                return False
            print("✅ Folder temporarily unlocked")
        
        # Step 2: Copy files
        print("📋 Step 2: Copying files...")
        copied_files = []
        for file_path in valid_files:
            try:
                dest_path = os.path.join(folder_path, os.path.basename(file_path))
                shutil.copy2(file_path, dest_path)
                copied_files.append(dest_path)
                print(f"✅ Copied: {os.path.basename(file_path)}")
            except Exception as e:
                print(f"❌ Failed to copy {os.path.basename(file_path)}: {e}")
        
        # Step 3: Re-protect folder and files
        print("🔒 Step 3: Re-applying protection...")
        
        # Re-protect folder
        if not re_protect_folder(folder_path):
            print("⚠️  Warning: Could not re-protect folder")
        else:
            print("✅ Folder re-protected")
        
        # Protect new files
        for file_path in copied_files:
            if protect_file(file_path):
                print(f"🛡️ Protected: {os.path.basename(file_path)}")
            else:
                print(f"⚠️  Warning: Could not protect {os.path.basename(file_path)}")
        
        print(f"\n🎉 SUCCESS!")
        print(f"✅ Added {len(copied_files)} files to protected folder")
        print(f"📁 Folder: {folder_path}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during process: {e}")
        
        # Try to re-protect folder even if there was an error
        try:
            re_protect_folder(folder_path)
            print("🔒 Folder re-protected after error")
        except:
            print("⚠️  Warning: Could not re-protect folder after error")
        
        return False

def main():
    if len(sys.argv) < 3:
        print("Usage: python add_files_to_protected.py <folder_path> <file1> [file2] [file3] ...")
        print("\nExamples:")
        print('  python add_files_to_protected.py "C:\\Users\\ajibi\\OneDrive\\Desktop\\testnow" "document.pdf"')
        print('  python add_files_to_protected.py "C:\\Users\\ajibi\\OneDrive\\Desktop\\testnow" "file1.txt" "file2.jpg" "file3.pdf"')
        sys.exit(1)
    
    folder_path = sys.argv[1]
    file_paths = sys.argv[2:]
    
    if not os.path.exists(folder_path):
        print(f"❌ Folder does not exist: {folder_path}")
        sys.exit(1)
    
    success = add_files_to_protected_folder(folder_path, file_paths)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
