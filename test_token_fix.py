#!/usr/bin/env python3
"""
Test script to fix USB token generation and verification
"""

import sys
import os
from pathlib import Path

# Add the current directory to path so we can import from true_prevention
sys.path.append(str(Path(__file__).parent))

try:
    from true_prevention import USBTokenManager
    
    def test_token_system():
        print("🧪 TESTING USB TOKEN SYSTEM")
        print("="*50)
        
        # Initialize token manager
        token_manager = USBTokenManager()
        print(f"Machine ID: {token_manager.machine_id}")
        
        # Check for existing tokens
        print("\n🔍 Checking for existing tokens...")
        existing_tokens = token_manager.find_tokens()
        print(f"Found {len(existing_tokens)} existing tokens")
        
        for token in existing_tokens:
            print(f"  📄 {token}")
        
        # Test verification of existing tokens
        if existing_tokens:
            print(f"\n🔍 Testing verification of existing token...")
            is_valid, message = token_manager.verify_token(existing_tokens[0])
            print(f"Result: {'✅ VALID' if is_valid else '❌ INVALID'}")
            print(f"Message: {message}")
        
        # Generate a new token
        print(f"\n🔑 Generating new token...")
        success, locations = token_manager.generate_token()
        
        if success:
            print(f"✅ Token generation successful!")
            print(f"Saved to {len(locations)} locations:")
            for loc in locations:
                print(f"  📄 {loc}")
            
            # Test verification of new token
            print(f"\n🔍 Testing verification of new token...")
            is_valid, message = token_manager.verify_token(locations[0])
            print(f"Result: {'✅ VALID' if is_valid else '❌ INVALID'}")
            print(f"Message: {message}")
            
            if is_valid:
                print(f"\n🎉 TOKEN SYSTEM IS WORKING CORRECTLY!")
                return True
            else:
                print(f"\n❌ Token verification failed after generation")
                return False
        else:
            print(f"❌ Token generation failed")
            print("Make sure you have a USB drive connected")
            return False

    if __name__ == "__main__":
        success = test_token_system()
        if success:
            print("\n✅ USB Token system is working correctly!")
        else:
            print("\n❌ USB Token system needs attention")
            
except ImportError as e:
    print(f"Cannot import USBTokenManager: {e}")
    print("Make sure true_prevention.py is in the same directory")
except Exception as e:
    print(f"Error testing token system: {e}")
