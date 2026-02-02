#!/usr/bin/env python3
"""
Test Native Windows TPM 2.0 PCR-Bound Sealing
Tests the full integration with the TPM manager
"""

import sys
import os

# Add repo to path
sys.path.insert(0, os.path.dirname(__file__))

print("=" * 70)
print("Testing Native Windows TPM 2.0 PCR-Bound Sealing")
print("=" * 70)

# Test 1: Native TPM directly
print("\n[TEST 1] Native Windows TPM 2.0 (windows_tpm_native.py)")
print("-" * 70)

try:
    from windows_tpm_native import WindowsTPM
    
    tpm = WindowsTPM()
    
    if not tpm.available:
        print("[SKIP] TPM not available (run as Administrator)")
    else:
        # Test PCR reading
        print("\n[*] Reading PCRs...")
        for pcr_idx in [0, 7]:
            pcr_val = tpm.read_pcr(pcr_idx)
            if pcr_val:
                print(f"    ✓ PCR[{pcr_idx}] = {pcr_val.hex()[:32]}...")
        
        # Test sealing/unsealing
        print("\n[*] Testing PCR-bound sealing...")
        test_key = b"SuperSecretKey1234567890"
        sealed = tpm.seal_data_with_pcr(test_key, [0, 7])
        
        if sealed:
            print(f"    ✓ Sealed {len(test_key)} bytes → {len(sealed)} bytes")
            
            # Unseal
            unsealed = tpm.unseal_data_with_pcr(sealed, [0, 7])
            if unsealed == test_key:
                print(f"    ✓ Unsealed successfully - data matches!")
            else:
                print(f"    ✗ Unsealed data mismatch")
        else:
            print(f"    ✗ Sealing failed")
        
        tpm.close()
        
except Exception as e:
    print(f"[ERROR] {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()

# Test 2: TPM Manager integration
print("\n\n[TEST 2] TPM Manager Integration (tpm_pqc_integration.py)")
print("-" * 70)

try:
    from tpm_pqc_integration import TPMManager
    
    manager = TPMManager()
    
    print(f"\n[*] TPM Detection Results:")
    print(f"    Available: {manager.available}")
    print(f"    Operational: {manager.tpm_operational}")
    print(f"    Is Admin: {manager.is_admin}")
    if manager.tpm_info:
        print(f"    Method: {manager.tpm_info.get('method', 'unknown')}")
    
    if manager.available:
        # Test key sealing
        print(f"\n[*] Testing key sealing through manager...")
        test_key = b"EncryptionKeyTestData"
        
        success, sealed_data = manager.seal_key(test_key, [0, 7])
        if success and sealed_data:
            print(f"    ✓ Key sealed: {len(sealed_data)} bytes")
            
            # Test unsealing
            success, unsealed_data = manager.unseal_key(sealed_data, [0, 7])
            if success and unsealed_data == test_key:
                print(f"    ✓ Key unsealed successfully!")
            else:
                print(f"    ✗ Key unsealing failed")
        else:
            print(f"    ✗ Key sealing failed")
    else:
        print(f"\n[SKIP] TPM not available for manager test")
    
except Exception as e:
    print(f"[ERROR] {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 70)
print("Test Complete")
print("=" * 70)
print("\nNOTE: Run as Administrator for full TPM functionality")
print("      Native Windows TPM 2.0 requires admin privileges")
