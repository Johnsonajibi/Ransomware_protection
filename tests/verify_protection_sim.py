import os
import time

# --- CONFIGURATION ---
TEST_DIR = "C:\\AntiRansomware_Test_Lab"
DUMMY_FILES_COUNT = 5
MALICIOUS_EXTENSIONS = [".locked", ".encrypted", ".wannacry"]

def setup():
    if not os.path.exists(TEST_DIR):
        os.makedirs(TEST_DIR)
        print(f"✅ Created test directory: {TEST_DIR}")
    
    for i in range(DUMMY_FILES_COUNT):
        with open(os.path.join(TEST_DIR, f"important_data_{i}.txt"), "w") as f:
            f.write("This is critical user data that should be protected.")
    print(f"✅ Generated {DUMMY_FILES_COUNT} dummy files.")

def simulate_attack():
    print("\n🚀 Starting Ransomware Simulation...")
    print("---------------------------------------")
    blocked_count = 0
    success_count = 0
    
    for i in range(DUMMY_FILES_COUNT):
        old_path = os.path.join(TEST_DIR, f"important_data_{i}.txt")
        new_path = old_path + MALICIOUS_EXTENSIONS[i % len(MALICIOUS_EXTENSIONS)]
        
        print(f"⚠️ Attempting to encrypt: {os.path.basename(old_path)} -> {os.path.basename(new_path)}")
        
        try:
            os.rename(old_path, new_path)
            print("❌ FAILURE: File was successfully renamed. Protection IS NOT WORKING.")
            success_count += 1
        except PermissionError:
            print("🛡️ SUCCESS: Access Denied! The Kernel Driver blocked the operation.")
            blocked_count += 1
        except Exception as e:
            print(f"❓ Unexpected error: {e}")
            
    print("---------------------------------------")
    print(f"RESULTS:")
    print(f"- Files Protected: {blocked_count}")
    print(f"- Files Encrypted: {success_count}")
    
    if blocked_count == DUMMY_FILES_COUNT:
        print("\n⭐⭐⭐ VERIFICATION PASSED: The system is working correctly! ⭐⭐⭐")
    else:
        print("\n💥 VERIFICATION FAILED: Check if the driver is correctly loaded.")

if __name__ == "__main__":
    setup()
    simulate_attack()
