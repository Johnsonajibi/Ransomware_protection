#!/usr/bin/env python3
"""Test token validation"""

import os
import hashlib
import base64
from cryptography.fernet import Fernet

def test_token_validation():
    # Check if tokens exist
    tokens_found = []
    for drive in ['E:', 'F:', 'G:', 'H:']:
        if os.path.exists(drive):
            try:
                for file in os.listdir(drive):
                    if file.startswith('protection_token_') and file.endswith('.key'):
                        token_path = os.path.join(drive, file)
                        tokens_found.append(token_path)
                        print(f"Found token: {token_path}")
            except Exception as e:
                print(f"Error scanning {drive}: {e}")
    
    if not tokens_found:
        print("❌ No tokens found")
        return
    
    # Test validation
    machine_id = "31e85af30fe98454"  # This should match the actual machine ID
    
    for token_path in tokens_found:
        print(f"\n🔍 Testing token: {os.path.basename(token_path)}")
        try:
            with open(token_path, 'r') as f:
                encrypted_data = f.read().strip()
            
            print(f"  Data length: {len(encrypted_data)}")
            print(f"  Data preview: {encrypted_data[:50]}...")
            
            # Create key from machine ID
            key = hashlib.sha256(machine_id.encode()).digest()
            key_b64 = hashlib.sha256(key).digest()[:32]
            key_final = hashlib.sha256(key_b64).digest()[:32]
            
            # Create Fernet cipher
            fernet_key = base64.urlsafe_b64encode(key_final)
            cipher = Fernet(fernet_key)
            
            # Try to decrypt - the encrypted data is already base64 encoded
            decrypted = cipher.decrypt(encrypted_data).decode()
            print(f"  ✅ Decrypted: {decrypted}")
            
            # Check content
            if machine_id in decrypted and "PROTECTION_TOKEN" in decrypted:
                print(f"  ✅ Valid token for this machine")
            else:
                print(f"  ❌ Token not valid for this machine")
                
        except Exception as e:
            print(f"  ❌ Validation failed: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    test_token_validation()
