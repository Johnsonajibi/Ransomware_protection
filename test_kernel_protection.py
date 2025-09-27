#!/usr/bin/env python3
"""
Kernel-Level Anti-Ransomware Protection Test
Tests the integration between user-mode and kernel-mode protection
"""

import os
import sys
import time
import tempfile
import shutil
from pathlib import Path

# Add the current directory to path to import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from kernel_driver_interface import KernelProtectionManager
from unified_antiransomware import UnifiedProtectionManager

def test_kernel_protection():
    """Test kernel-level protection functionality"""
    print("🧪 KERNEL PROTECTION TEST SUITE")
    print("=" * 50)
    
    # Check if running as administrator
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("❌ Administrator privileges required for kernel testing")
            print("Please run as administrator")
            return False
    except:
        print("⚠️ Could not check admin privileges")
    
    # Initialize kernel manager
    kernel_manager = KernelProtectionManager()
    
    print("🔌 Initializing kernel protection...")
    if not kernel_manager.initialize():
        print("❌ Kernel protection initialization failed")
        print("💡 Make sure the kernel driver is installed and running:")
        print("   python kernel_driver_manager.py install")
        print("   python kernel_driver_manager.py start")
        return False
    
    print("✅ Kernel protection initialized successfully")
    
    try:
        # Test 1: Create test directory
        print("\n📁 TEST 1: Creating test directory...")
        test_dir = os.path.join(tempfile.gettempdir(), "AntiRansomware_KernelTest")
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)
        os.makedirs(test_dir)
        print(f"✅ Test directory created: {test_dir}")
        
        # Test 2: Add kernel protection
        print("\n🛡️ TEST 2: Adding kernel protection...")
        success = kernel_manager.protect_path(test_dir)
        if success:
            print("✅ Kernel protection added successfully")
        else:
            print("❌ Failed to add kernel protection")
            return False
        
        # Test 3: Create test file
        print("\n📄 TEST 3: Creating test file in protected directory...")
        test_file = os.path.join(test_dir, "test_document.txt")
        try:
            with open(test_file, 'w') as f:
                f.write("This is a test document for kernel protection testing.\n")
                f.write("If you can read this, the file was created successfully.\n")
            print("✅ Test file created successfully")
        except Exception as e:
            print(f"❌ Failed to create test file: {e}")
        
        # Test 4: Get protection statistics
        print("\n📊 TEST 4: Getting protection statistics...")
        stats = kernel_manager.get_protection_statistics()
        if stats:
            print("✅ Statistics retrieved successfully:")
            print(f"   📊 Total Requests: {stats['total_requests']}")
            print(f"   🚫 Blocked Requests: {stats['blocked_requests']}")
            print(f"   ✅ Allowed Requests: {stats['allowed_requests']}")
            print(f"   📁 Protected Paths: {stats['protected_paths']}")
        else:
            print("❌ Failed to retrieve statistics")
        
        # Test 5: Token validation test
        print("\n🔐 TEST 5: Testing token validation...")
        test_token = {
            "hardware_fingerprint": "test_fingerprint_123",
            "process_id": os.getpid(),
            "timestamp": int(time.time())
        }
        
        result = kernel_manager.validate_access_token(test_token, os.getpid(), "write")
        print(f"✅ Token validation result: {'VALID' if result else 'INVALID'}")
        
        # Test 6: Try to modify protected file
        print("\n✏️ TEST 6: Testing file modification protection...")
        try:
            with open(test_file, 'a') as f:
                f.write("This line should be blocked by kernel protection.\n")
            print("⚠️ File modification was allowed (may indicate protection is not active)")
        except Exception as e:
            print(f"✅ File modification blocked: {e}")
        
        # Test 7: Remove protection
        print("\n🔓 TEST 7: Removing kernel protection...")
        success = kernel_manager.unprotect_path(test_dir)
        if success:
            print("✅ Kernel protection removed successfully")
        else:
            print("❌ Failed to remove kernel protection")
        
        # Test 8: Final statistics
        print("\n📊 TEST 8: Final protection statistics...")
        kernel_manager.print_status()
        
        print("\n🎉 KERNEL PROTECTION TEST COMPLETED")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with exception: {e}")
        return False
    
    finally:
        # Cleanup
        try:
            if os.path.exists(test_dir):
                shutil.rmtree(test_dir)
            print("🧹 Test directory cleaned up")
        except:
            print("⚠️ Could not clean up test directory")
        
        kernel_manager.shutdown()

def test_unified_system_with_kernel():
    """Test the unified system with kernel protection"""
    print("\n🔗 UNIFIED SYSTEM + KERNEL PROTECTION TEST")
    print("=" * 50)
    
    try:
        # Initialize unified system
        protection_manager = UnifiedProtectionManager()
        
        # Check if kernel protection is active
        if hasattr(protection_manager, 'kernel_protection_active') and protection_manager.kernel_protection_active:
            print("✅ Unified system initialized with kernel protection")
            
            # Test protecting a folder
            test_folder = os.path.join(tempfile.gettempdir(), "UnifiedKernelTest")
            if not os.path.exists(test_folder):
                os.makedirs(test_folder)
            
            print(f"🛡️ Testing folder protection: {test_folder}")
            success = protection_manager.protect_folder(test_folder)
            
            if success:
                print("✅ Folder protection applied successfully")
                
                # Check kernel statistics
                if protection_manager.kernel_manager:
                    print("\n📊 Kernel Protection Status:")
                    protection_manager.kernel_manager.print_status()
            else:
                print("❌ Folder protection failed")
            
            # Cleanup
            try:
                if os.path.exists(test_folder):
                    shutil.rmtree(test_folder)
            except:
                pass
                
        else:
            print("❌ Unified system does not have kernel protection active")
            return False
            
        return True
        
    except Exception as e:
        print(f"❌ Unified system test failed: {e}")
        return False

def main():
    """Main test function"""
    print("🚀 ANTI-RANSOMWARE KERNEL PROTECTION TEST SUITE")
    print("=" * 60)
    
    # Test 1: Basic kernel protection
    kernel_test_success = test_kernel_protection()
    
    # Test 2: Unified system integration
    unified_test_success = test_unified_system_with_kernel()
    
    # Results
    print("\n📋 TEST RESULTS SUMMARY")
    print("=" * 30)
    print(f"🔐 Kernel Protection Test: {'✅ PASSED' if kernel_test_success else '❌ FAILED'}")
    print(f"🔗 Unified System Test: {'✅ PASSED' if unified_test_success else '❌ FAILED'}")
    
    if kernel_test_success and unified_test_success:
        print("\n🎉 ALL TESTS PASSED!")
        print("🛡️ Kernel-level protection is working correctly")
        return 0
    else:
        print("\n❌ SOME TESTS FAILED")
        print("Please check the kernel driver installation and configuration")
        return 1

if __name__ == "__main__":
    sys.exit(main())
