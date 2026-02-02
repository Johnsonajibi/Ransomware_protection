#!/usr/bin/env python3
"""Test pqcdualusb integration in tpm_pqc_integration.py"""

from tpm_pqc_integration import PQCManager

print("\n" + "="*60)
print("Testing PQC Manager with pqcdualusb")
print("="*60 + "\n")

# Initialize PQC Manager
pqc_manager = PQCManager()

# Test 1: Generate keypair
print("TEST 1: Generate keypair")
success, keypair = pqc_manager.generate_keypair()
if not success:
    print("❌ Keypair generation failed")
    exit(1)

print(f"✅ Keypair generated")
print(f"   Type: {keypair['type']}")
print(f"   KEM: {keypair['kem_algorithm']} ({len(keypair['kem_public'])} byte public key)")
print(f"   Signature: {keypair['sig_algorithm']} ({len(keypair['sig_public'])} byte public key)")

# Get keys for testing
sig_public_key = keypair['sig_public']
sig_secret_key = keypair['sig_secret']

# Convert to hex for the API
sig_public_hex = sig_public_key.hex()
sig_secret_hex = sig_secret_key.hex()

# Test 2: Sign data
print("\nTEST 2: Sign data with pqcdualusb (Dilithium3)")
test_data = b"Anti-Ransomware Protection Test - Quantum Resistant Signature"
success, signature = pqc_manager.sign_data(test_data, sig_secret_hex)
if not success or signature is None:
    print(f"❌ Signing failed")
    exit(1)

print(f"✅ Signature created: {len(signature)} bytes")

# Test 3: Verify signature
print("\nTEST 3: Verify signature with pqcdualusb")
verified = pqc_manager.verify_signature(test_data, signature, sig_public_hex)
if not verified:
    print(f"❌ Signature verification failed")
    exit(1)

print(f"✅ Signature verified successfully")

# Test 4: Verify with wrong data (should fail)
print("\nTEST 4: Verify with wrong data (should reject)")
wrong_data = b"Different data"
verified_wrong = pqc_manager.verify_signature(wrong_data, signature, sig_public_hex)
if verified_wrong:
    print(f"❌ Wrong data was incorrectly verified")
    exit(1)

print(f"✅ Wrong data correctly rejected")

print("\n" + "="*60)
print("✅ ALL TESTS PASSED - pqcdualusb is fully functional!")
print("="*60 + "\n")
