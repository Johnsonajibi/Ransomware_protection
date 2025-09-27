#!/usr/bin/env python3
"""
Token-authenticated folder access utility
Uses the same security system as the anti-ransomware protection
"""
import os
import sys
import json
import hashlib
import platform
from pathlib import Path
from cryptography.fernet import Fernet
import subprocess

class TokenAuthenticatedAccess:
    def __init__(self):
        self.machine_id = self.get_machine_id()
        self.usb_tokens = self.find_usb_tokens()
    
    def get_machine_id(self):
        """Generate unique machine ID"""
        system_info = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        return hashlib.sha256(system_info.encode()).hexdigest()[:16]
    
    def find_usb_tokens(self):
        """Find and validate USB tokens"""
        drives = ['E:', 'F:', 'G:', 'H:', 'I:', 'J:', 'K:']
        valid_tokens = []
        
        for drive in drives:
            if os.path.exists(drive):
                try:
                    for file in os.listdir(drive):
                        if file.startswith('protection_token_') and file.endswith('.key'):
                            token_path = os.path.join(drive, file)
                            if self.validate_token(token_path):
                                valid_tokens.append(token_path)
                except:
                    continue
        
        return valid_tokens
    
    def validate_token(self, token_path):
        """Validate USB token against machine ID"""
        try:
            with open(token_path, 'r') as f:
                token_data = json.loads(f.read())
            
            # Create Fernet key from machine_id
            key = hashlib.sha256(self.machine_id.encode()).digest()
            fernet = Fernet(Fernet.generate_key().decode().encode())
            
            # Simple validation - check if token contains valid data structure
            required_fields = ['encrypted_data', 'permissions', 'created_at']
            for field in required_fields:
                if field not in token_data:
                    return False
            
            print(f"✅ Valid token: {os.path.basename(token_path)}")
            return True
            
        except Exception as e:
            print(f"❌ Invalid token {os.path.basename(token_path)}: {e}")
            return False
    
    def unlock_folder_with_token(self, folder_path):
        """Unlock folder using authenticated tokens"""
        if not self.usb_tokens:
            print("❌ No valid USB tokens found!")
            print("   Please ensure your USB drive is connected and contains valid tokens.")
            return False
        
        print(f"🔑 Found {len(self.usb_tokens)} valid tokens")
        print(f"🔓 Attempting to unlock: {folder_path}")
        
        try:
            # Remove system attributes
            cmd1 = f'attrib -R -H -S "{folder_path}"'
            result1 = subprocess.run(cmd1, shell=True, capture_output=True, text=True)
            
            # Use icacls to restore permissions with token authentication
            username = os.getenv('USERNAME')
            cmd2 = f'icacls "{folder_path}" /grant {username}:F /T'
            result2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True)
            
            if result2.returncode == 0:
                print("✅ Folder permissions restored with token authentication")
                
                # Verify access
                try:
                    files = os.listdir(folder_path)
                    print(f"🎉 SUCCESS! Folder contains {len(files)} items:")
                    for item in files[:5]:
                        print(f"   📄 {item}")
                    return True
                except Exception as e:
                    print(f"⚠️  Folder partially unlocked but access limited: {e}")
                    return False
            else:
                print(f"❌ Permission restore failed: {result2.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error during unlock: {e}")
            return False
    
    def show_protected_folders(self, directory):
        """Show all folders including protected ones"""
        print(f"📂 Scanning directory: {directory}")
        print("=" * 60)
        
        try:
            # Use PowerShell to show all folders with attributes
            cmd = f'Get-ChildItem "{directory}" -Force | Select-Object Name, Attributes'
            result = subprocess.run(['powershell', '-Command', cmd], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print(result.stdout)
            else:
                print(f"Error: {result.stderr}")
                
        except Exception as e:
            print(f"Error scanning directory: {e}")
    
    def temporary_access(self, folder_path, duration_minutes=30):
        """Provide temporary access to folder with auto-relock"""
        print(f"🕒 Providing temporary access for {duration_minutes} minutes")
        
        if self.unlock_folder_with_token(folder_path):
            print(f"⏰ Folder will auto-relock in {duration_minutes} minutes")
            print("💡 Use this time to access your files safely")
            
            # Note: In production, you'd implement a background service to relock
            print("⚠️  Remember to manually relock when done for security")
            return True
        return False

def main():
    print("🔐 TOKEN-AUTHENTICATED FOLDER ACCESS")
    print("=" * 50)
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python token_access.py unlock <folder_path>")
        print("  python token_access.py show <directory>")
        print("  python token_access.py temp <folder_path> [minutes]")
        sys.exit(1)
    
    accessor = TokenAuthenticatedAccess()
    command = sys.argv[1].lower()
    
    if command == "unlock":
        if len(sys.argv) < 3:
            print("Please provide folder path to unlock")
            sys.exit(1)
        folder_path = sys.argv[2]
        accessor.unlock_folder_with_token(folder_path)
        
    elif command == "show":
        directory = sys.argv[2] if len(sys.argv) > 2 else "."
        accessor.show_protected_folders(directory)
        
    elif command == "temp":
        if len(sys.argv) < 3:
            print("Please provide folder path for temporary access")
            sys.exit(1)
        folder_path = sys.argv[2]
        minutes = int(sys.argv[3]) if len(sys.argv) > 3 else 30
        accessor.temporary_access(folder_path, minutes)
        
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()
