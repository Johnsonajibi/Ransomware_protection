"""Test crypto imports"""
import sys

print("Testing Cryptodome...")
try:
    from Cryptodome.Cipher import AES
    print("✅ Cryptodome.Cipher.AES works")
except ImportError as e:
    print(f"❌ Cryptodome failed: {e}")

print("\nTesting Crypto...")
try:
    from Crypto.Cipher import AES
    print("✅ Crypto.Cipher.AES works")
except ImportError as e:
    print(f"❌ Crypto failed: {e}")

print("\nTesting PyCryptodome...")
try:
    import Cryptodome
    print(f"✅ Cryptodome module found at: {Cryptodome.__file__}")
except ImportError:
    print("❌ Cryptodome module not found")

try:
    import Crypto
    print(f"✅ Crypto module found at: {Crypto.__file__}")
except ImportError:
    print("❌ Crypto module not found")

print("\nInstalled packages:")
import subprocess
result = subprocess.run([sys.executable, "-m", "pip", "list"], capture_output=True, text=True)
for line in result.stdout.split('\n'):
    if 'crypt' in line.lower():
        print(f"  {line}")
