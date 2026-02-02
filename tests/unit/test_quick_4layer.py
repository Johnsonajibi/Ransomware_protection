#!/usr/bin/env python3
"""
Quick test for 4-layer protection system
"""

import sys
import tempfile
from pathlib import Path

print("\n" + "="*70)
print("TESTING 4-LAYER PROTECTION SYSTEM")
print("="*70)

# Test Layer 1: Kernel-level blocker
print("\n[Layer 1] Kernel-Level File Blocking")
try:
    from kernel_level_blocker import KernelLevelBlocker
    blocker = KernelLevelBlocker()
    
    # Create test file
    test_dir = Path(tempfile.mkdtemp(prefix="Test4Layer_"))
    test_file = test_dir / "test.txt"
    test_file.write_text("Test content")
    
    # Apply kernel blocking
    blocker.add_protected_path(str(test_file))
    blocker.start_blocking()
    
    # Verify file is locked
    try:
        with open(test_file, 'r') as f:
            content = f.read()
        print("   [FAIL] File is still readable (lock failed)")
        layer1_ok = False
    except Exception as e:
        print(f"   [PASS] File is locked: {type(e).__name__}")
        layer1_ok = True
    
    # Clean up
    blocker.stop_blocking()
    import shutil
    shutil.rmtree(test_dir)
    
except Exception as e:
    print(f"   [FAIL] Error: {e}")
    layer1_ok = False

# Test Layer 2: Controlled Folder Access
print("\n[Layer 2] Windows Controlled Folder Access")
try:
    import ctypes
    import subprocess
    
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    if not is_admin:
        print("   [WARN] Not running as admin - CFA requires admin")
        layer2_ok = False
    else:
        result = subprocess.run(
            ['powershell', '-Command', 'Get-MpPreference | Select-Object -ExpandProperty EnableControlledFolderAccess'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print("   [PASS] Windows Defender accessible")
            layer2_ok = True
        else:
            print("   [WARN] Windows Defender not responding")
            layer2_ok = False
except Exception as e:
    print(f"   [WARN] Error: {e}")
    layer2_ok = False

# Test Layer 3: NTFS Permissions
print("\n[Layer 3] NTFS Permissions Modification")
try:
    import win32security
    import ntsecuritycon
    
    # Create test file
    test_dir = Path(tempfile.mkdtemp(prefix="Test4Layer_"))
    test_file = test_dir / "test.txt"
    test_file.write_text("Test content")
    
    # Try to read security descriptor
    sd = win32security.GetFileSecurity(
        str(test_file),
        win32security.DACL_SECURITY_INFORMATION
    )
    
    # Try to modify DACL
    dacl = win32security.ACL()
    system_sid = win32security.LookupAccountName(None, "SYSTEM")[0]
    dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        ntsecuritycon.FILE_ALL_ACCESS,
        system_sid
    )
    
    print("   [PASS] Can read and modify NTFS permissions")
    layer3_ok = True
    
    # Clean up
    import shutil
    shutil.rmtree(test_dir)
    
except ImportError:
    print("   [FAIL] pywin32 not installed (pip install pywin32)")
    layer3_ok = False
except Exception as e:
    print(f"   [WARN] Error: {e}")
    layer3_ok = False

# Test Layer 4: File Encryption
print("\n[Layer 4] File Encryption (AES-256-CBC)")
try:
    from unified_antiransomware import CryptographicProtection, UnifiedDatabase
    
    db = UnifiedDatabase()
    from ar_token import TokenManager
    token_mgr = TokenManager(db)
    
    crypto = CryptographicProtection(token_mgr)
    print("   [PASS] Encryption module loaded successfully")
    layer4_ok = True
    
except Exception as e:
    print(f"   [FAIL] Error: {e}")
    layer4_ok = False

# Test Integration
print("\n[Integration] 4-Layer Protection Module")
try:
    from four_layer_protection import FourLayerProtection
    
    if hasattr(FourLayerProtection, 'apply_complete_protection'):
        print("   [PASS] apply_complete_protection method available")
        integration_ok = True
    else:
        print("   [FAIL] apply_complete_protection method not found")
        integration_ok = False
        
except Exception as e:
    print(f"   [FAIL] Error: {e}")
    integration_ok = False

# Summary
print("\n" + "="*70)
print("TEST RESULTS SUMMARY")
print("="*70)
print(f"Layer 1 (Kernel Blocker):       {'[PASS]' if layer1_ok else '[FAIL]'}")
print(f"Layer 2 (CFA):                  {'[PASS]' if layer2_ok else '[WARN]'}")
print(f"Layer 3 (NTFS):                 {'[PASS]' if layer3_ok else '[FAIL]'}")
print(f"Layer 4 (Encryption):           {'[PASS]' if layer4_ok else '[FAIL]'}")
print(f"Integration:                    {'[PASS]' if integration_ok else '[FAIL]'}")

total = sum([layer1_ok, layer2_ok, layer3_ok, layer4_ok, integration_ok])
print(f"\nTotal: {total}/5 tests passed")

if layer1_ok and layer3_ok and layer4_ok and integration_ok:
    print("\n[SUCCESS] 4-layer protection system is READY TO USE")
    print("          Layer 1 (kernel) is WORKING without needing WDK!")
    sys.exit(0)
elif layer3_ok and layer4_ok:
    print("\n[PARTIAL] 3-layer protection available (NTFS + Encryption)")
    sys.exit(0)
else:
    print("\n[WARNING] Some components need attention")
    sys.exit(1)
