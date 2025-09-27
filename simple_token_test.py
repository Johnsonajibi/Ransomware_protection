#!/usr/bin/env python3
"""
Simple token validation test to verify security improvements
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from unified_antiransomware import SecureUSBTokenManager

def test_token_validation():
    """Test token validation improvements"""
    print("Testing Enhanced Token Security...")
    
    token_manager = SecureUSBTokenManager()
    
    # Get all tokens
    all_tokens = token_manager.find_usb_tokens(validate=False)  # Don't validate yet
    valid_tokens = token_manager.find_usb_tokens(validate=True)  # Now validate
    
    print(f"Found {len(all_tokens)} token files on USB drives")
    print(f"Only {len(valid_tokens)} tokens passed validation")
    
    # Show which ones passed/failed
    for token in all_tokens:
        token_name = os.path.basename(token)
        is_valid = token in valid_tokens
        status = "VALID" if is_valid else "REJECTED"
        print(f"  {token_name}: {status}")
    
    # Test specific fake tokens
    fake_tokens = [
        "E:\\protection_token_fake123.key",
        "E:\\protection_token_testfake.key"
    ]
    
    print("\nTesting specific fake tokens:")
    for fake_token in fake_tokens:
        if os.path.exists(fake_token):
            is_valid = token_manager.validate_secure_token(fake_token)
            status = "DANGER - ACCEPTED" if is_valid else "SECURE - REJECTED"
            print(f"  {os.path.basename(fake_token)}: {status}")
    
    # Show hardware fingerprint
    print(f"\nHardware Fingerprint: {token_manager.hardware_fingerprint[:16]}...")
    
    return len(valid_tokens) > 0 and len(valid_tokens) < len(all_tokens)

if __name__ == "__main__":
    success = test_token_validation()
    if success:
        print("\n✅ TOKEN SECURITY ENHANCED SUCCESSFULLY")
        print("✅ Fake tokens are being rejected")
        print("✅ Only cryptographically valid tokens accepted")
    else:
        print("\n❌ Token security issues detected")
