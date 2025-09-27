#!/usr/bin/env python3
"""Test script to verify file locking is working"""

import sys
import os
from pathlib import Path
import time
import subprocess

def test_file_write_protection():
    """Test if files are actually protected from writing"""
    test_folder = Path("c:/Users/ajibi/Music/Anti-Ransomeware/TestFolder")
    test_files = list(test_folder.glob("*.txt"))
    
    print(f"🧪 TESTING FILE PROTECTION")
    print(f"📂 Test folder: {test_folder}")
    print(f"📄 Found {len(test_files)} test files")
    print("="*60)
    
    for test_file in test_files:
        print(f"\n🔍 Testing: {test_file.name}")
        
        # Test 1: Try to write to the file
        try:
            with open(test_file, 'a') as f:
                f.write("\nRANSOMWARE ATTACK SIMULATION")
            print(f"❌ SECURITY BREACH: File {test_file.name} was writable!")
            return False
        except PermissionError as e:
            print(f"✅ PROTECTED: Write blocked - {e}")
        except Exception as e:
            print(f"✅ PROTECTED: Access denied - {e}")
        
        # Test 2: Try to delete the file
        try:
            test_file.unlink()
            print(f"❌ SECURITY BREACH: File {test_file.name} was deletable!")
            return False
        except PermissionError as e:
            print(f"✅ PROTECTED: Delete blocked - {e}")
        except Exception as e:
            print(f"✅ PROTECTED: Delete denied - {e}")
        
        # Test 3: Try to rename the file
        try:
            new_name = test_file.with_suffix('.encrypted')
            test_file.rename(new_name)
            print(f"❌ SECURITY BREACH: File {test_file.name} was renameable!")
            return False
        except PermissionError as e:
            print(f"✅ PROTECTED: Rename blocked - {e}")
        except Exception as e:
            print(f"✅ PROTECTED: Rename denied - {e}")
        
        # Test 4: Try admin-level access with icacls
        try:
            result = subprocess.run([
                'icacls', str(test_file), '/grant', 'Everyone:F'
            ], capture_output=True, shell=True, text=True)
            if result.returncode == 0:
                print(f"❌ SECURITY BREACH: Admin could modify permissions!")
                return False
            else:
                print(f"✅ PROTECTED: Admin permission change blocked")
        except Exception as e:
            print(f"✅ PROTECTED: Admin tools blocked - {e}")
    
    print("\n" + "="*60)
    print("🛡️ ALL TESTS PASSED: Files are properly protected!")
    return True

def test_folder_protection():
    """Test folder-level protection"""
    test_folder = Path("c:/Users/ajibi/Music/Anti-Ransomeware/TestFolder")
    
    print(f"\n📂 TESTING FOLDER PROTECTION")
    print(f"📂 Target: {test_folder}")
    print("="*60)
    
    # Try to create new file in protected folder
    try:
        new_file = test_folder / "ransomware_payload.txt"
        with open(new_file, 'w') as f:
            f.write("RANSOMWARE PAYLOAD")
        print(f"❌ SECURITY BREACH: Could create new file in protected folder!")
        return False
    except PermissionError as e:
        print(f"✅ PROTECTED: New file creation blocked - {e}")
    except Exception as e:
        print(f"✅ PROTECTED: Folder access denied - {e}")
    
    return True

if __name__ == "__main__":
    print("🚀 STARTING ANTI-RANSOMWARE PROTECTION TEST")
    print("="*60)
    
    # Give system time to apply protection
    print("⏳ Waiting for protection to be applied...")
    time.sleep(3)
    
    file_protected = test_file_write_protection()
    folder_protected = test_folder_protection()
    
    print("\n" + "="*60)
    print("🏁 FINAL RESULTS:")
    print(f"📄 File Protection: {'✅ WORKING' if file_protected else '❌ FAILED'}")
    print(f"📂 Folder Protection: {'✅ WORKING' if folder_protected else '❌ FAILED'}")
    
    if file_protected and folder_protected:
        print("🛡️ ANTI-RANSOMWARE PROTECTION IS WORKING!")
        sys.exit(0)
    else:
        print("⚠️ PROTECTION NEEDS ATTENTION!")
        sys.exit(1)
