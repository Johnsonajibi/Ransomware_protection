import sys
from pathlib import Path

print("="*60)
print("Anti-Ransomware System Component Check")
print("="*60)

components = {
    "Core Protection Engine": "src/python/core/unified_antiransomware.py",
    "ML Ransomware Detector": "src/python/core/ml_detector.py",
    "Honeypot Monitor": "src/python/monitoring/honeypot_monitor.py",
    "Threat Intelligence": "src/python/core/threat_intelligence.py",
    "TPM Integration": "src/python/tpm/tpm_pqc_integration.py",
    "Device Fingerprinting": "src/python/utils/device_fingerprint_enhanced.py",
    "Token Security": "src/python/auth/enhanced_token_security.py",
    "SIEM Integration": "src/python/enterprise/siem_integration.py",
    "Shadow Copy Protection": "src/python/enterprise/shadow_copy_protection.py",
    "Kernel Minifilter (C)": "src/kernel/antiransomware_minifilter.c",
    "Kernel CPP Version": "CPP-Kernel-Version/src/antiransomware_kernel.c",
    "Desktop GUI": "src/python/desktop_app.py"
}

passed = 0
total = len(components)

for name, filepath in components.items():
    exists = Path(filepath).exists()
    status = "OK" if exists else "MISSING"
    print(f"{name:<30} {status}")
    if exists:
        passed += 1

print("="*60)
print(f"Components Found: {passed}/{total} ({100*passed/total:.1f}%)")
print("="*60)

# Test critical dependencies
print("\nDependency Check:")
deps = ['PyQt6', 'cryptography', 'psutil', 'wmi', 'pqcdualusb', 'device_fingerprinting']
dep_ok = 0
for dep in deps:
    try:
        __import__(dep.replace('-', '_'))
        print(f"{dep:<25} OK")
        dep_ok += 1
    except:
        print(f"{dep:<25} MISSING")

print(f"\nDependencies: {dep_ok}/{len(deps)}")

# Check if app is running
print("\nApplication Status:")
try:
    import psutil
    found_app = False
    for proc in psutil.process_iter(['name', 'cmdline']):
        try:
            if proc.info['cmdline'] and 'run_app.py' in str(proc.info['cmdline']):
                print(f"  Desktop App Running: PID {proc.pid}")
                found_app = True
                break
        except:
            pass
    if not found_app:
        print("  Desktop App: Not running")
except Exception as e:
    print(f"  Could not check: {e}")

sys.exit(0 if (passed == total and dep_ok == len(deps)) else 1)
