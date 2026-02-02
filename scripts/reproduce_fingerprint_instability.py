
import time
import sys
import logging

# Configure logging to suppress other output
logging.basicConfig(level=logging.CRITICAL)

try:
    from device_fingerprinting import generate_fingerprint
except ImportError:
    # Use the local path if installed there
    sys.path.append(r"C:\Users\ajibi\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages")
    from device_fingerprinting import generate_fingerprint

print("Generating fingerprints...")
fp1 = generate_fingerprint()
print(f"Fingerprint 1: {fp1}")

time.sleep(1.1)

fp2 = generate_fingerprint()
print(f"Fingerprint 2: {fp2}")

if fp1 != fp2:
    print("\n❌ FINGERPRINT INSTABILITY DETECTED!")
    print("The fingerprint changed between calls.")
else:
    print("\n✅ Fingerprint is stable.")
