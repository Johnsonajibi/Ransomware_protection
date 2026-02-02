
import time
import sys
import logging

print("Starting debug reproduction script...")

# Configure logging to console
logging.basicConfig(level=logging.DEBUG)

try:
    print("Importing device_fingerprinting...")
    import device_fingerprinting
    print(f"Imported from: {device_fingerprinting.__file__}")
    from device_fingerprinting import generate_fingerprint
except ImportError:
    print("Module not found in standard path, adding site-packages...")
    sys.path.append(r"C:\Users\ajibi\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages")
    import device_fingerprinting
    print(f"Imported from: {device_fingerprinting.__file__}")
    from device_fingerprinting import generate_fingerprint

print("Generating fingerprint 1...")
try:
    fp1 = generate_fingerprint()
    print(f"Fingerprint 1: {fp1}")
except Exception as e:
    print(f"Error generating fp1: {e}")
    sys.exit(1)

print("Sleeping...")
time.sleep(1.1)

print("Generating fingerprint 2...")
try:
    fp2 = generate_fingerprint()
    print(f"Fingerprint 2: {fp2}")
except Exception as e:
    print(f"Error generating fp2: {e}")
    sys.exit(1)

if fp1 != fp2:
    print("\n❌ FINGERPRINT INSTABILITY DETECTED!")
    print(f"FP1: {fp1}")
    print(f"FP2: {fp2}")
else:
    print("\n✅ Fingerprint is stable.")
