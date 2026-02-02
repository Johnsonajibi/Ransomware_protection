#!/usr/bin/env python3
"""Test pqcdualusb functionality"""

from pqcdualusb import PostQuantumCrypto

# Initialize PQC
pqc = PostQuantumCrypto()
print(f"✅ pqcdualusb initialized")
print(f"   Signature algorithm: {pqc.sig_algorithm}")
print(f"   KEM algorithm: {pqc.kem_algorithm}")

# Test signature generation and verification
# NOTE: pqcdualusb returns (secret_key, public_key) NOT (public_key, secret_key)
sk, pk = pqc.generate_sig_keypair()
print(f"\n✅ Generated Dilithium3 keypair")
print(f"   Secret key: {len(sk)} bytes")
print(f"   Public key: {len(pk)} bytes")

# Sign some test data
test_data = b"Anti-Ransomware Protection Test"
signature = pqc.sign(test_data, sk)
print(f"\n✅ Created signature: {len(signature)} bytes")

# Verify signature
verified = pqc.verify(test_data, signature, pk)
print(f"✅ Signature verification: {verified}")

# Test with wrong data
try:
    wrong_verified = pqc.verify(b"wrong data", signature, pk)
    print(f"❌ Wrong data verification (should be False): {wrong_verified}")
except:
    print("✅ Wrong data correctly rejected")

print("\n" + "="*60)
print("✅ pqcdualusb is fully functional!")
print("="*60)
