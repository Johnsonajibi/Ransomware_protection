#!/usr/bin/env python3
"""Test improved TPM detection and functionality"""

from tpm_pqc_integration import TPMManager
import sys

print("\n" + "="*70)
print("TPM 2.0 DETECTION AND FUNCTIONALITY TEST")
print("="*70 + "\n")

# Initialize TPM Manager
tpm = TPMManager()

# Test 1: Check TPM availability
print("1. TPM Availability Status:")
print(f"   TPM Available: {tpm.available}")
print(f"   TPM Operational: {tpm.tpm_operational}")
if tpm.tpm_info:
    print(f"   Detection Method: {tpm.tpm_info.get('method', 'unknown')}")
    print(f"   Full Info: {tpm.tpm_info}")
else:
    print("   TPM Info: Not detected")

# Test 2: Create primary key
print("\n2. TPM Primary Key Creation:")
if tpm.available:
    success = tpm.create_primary_key()
    print(f"   Result: {'SUCCESS' if success else 'FAILED'}")
else:
    print("   Skipped (TPM not available)")

# Test 3: Key sealing and unsealing
print("\n3. TPM Key Sealing/Unsealing Test:")
test_key = b"Super-Secret-Encryption-Key-12345"
print(f"   Original key: {test_key[:20]}... ({len(test_key)} bytes)")

if tpm.available:
    success, sealed_key = tpm.seal_key(test_key)
    if success and sealed_key:
        print(f"   Sealed key: {sealed_key[:20].hex()}... ({len(sealed_key)} bytes)")
        
        # Try to unseal
        success_unseal, unsealed_key = tpm.unseal_key(sealed_key)
        if success_unseal and unsealed_key:
            if unsealed_key == test_key:
                print(f"   Unsealed key: MATCHES ORIGINAL (verification SUCCESS)")
            else:
                print(f"   Unsealed key: DOES NOT MATCH")
        else:
            print(f"   Unsealing: FAILED")
    else:
        print(f"   Sealing: FAILED")
else:
    print("   Skipped (TPM not available)")

# Test 4: System identifier
print("\n4. System Identifier (for fallback sealing):")
try:
    system_id = tpm._get_system_identifier()
    print(f"   System ID: {system_id}")
except Exception as e:
    print(f"   System ID retrieval: {e}")

print("\n" + "="*70)
print("TPM DETECTION TEST COMPLETE")
print("="*70 + "\n")

if tpm.available:
    print("[SUCCESS] TPM 2.0 is available on this system")
    if tpm.tpm_operational:
        print("[SUCCESS] TPM is fully operational via trustcore-tpm")
    else:
        print("[INFO] TPM detected but using fallback methods (normal on non-admin user)")
else:
    print("[INFO] TPM not detected - system will use PQC-only security")
    print("       This is secure; PQC is quantum-resistant without TPM")
    print("       For full TPM features, run as Administrator")
