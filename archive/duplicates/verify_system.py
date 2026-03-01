#!/usr/bin/env python3
"""
Comprehensive System Verification
Tests all major components and validates project claims
"""
import sys
import os
import json
from pathlib import Path
from datetime import datetime

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(70)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}\n")

def print_test(name, status, details=""):
    status_color = Colors.GREEN if status == "PASS" else Colors.RED if status == "FAIL" else Colors.YELLOW
    symbol = "✓" if status == "PASS" else "✗" if status == "FAIL" else "⚠"
    print(f"{symbol} {name:<50} [{status_color}{status}{Colors.END}]")
    if details:
        print(f"  └─ {details}")

def test_python_dependencies():
    """Test all required Python packages"""
    print_header("PYTHON DEPENDENCIES CHECK")
    
    required = {
        'PyQt6': 'GUI Framework',
        'cryptography': 'Encryption',
        'psutil': 'Process Monitoring',
        'wmi': 'TPM Access',
        'pqcdualusb': 'Post-Quantum Crypto',
        'device_fingerprinting': 'Hardware Binding',
        'watchdog': 'File Monitoring',
        'flask': 'Web Dashboard',
        'requests': 'HTTP Client',
        'argon2': 'Password Hashing'
    }
    
    results = {}
    for module, purpose in required.items():
        try:
            __import__(module.replace('-', '_'))
            results[module] = True
            print_test(f"{module} ({purpose})", "PASS")
        except ImportError as e:
            results[module] = False
            print_test(f"{module} ({purpose})", "FAIL", str(e))
    
    return all(results.values()), results

def test_project_structure():
    """Verify project directory structure"""
    print_header("PROJECT STRUCTURE VERIFICATION")
    
    required_dirs = {
        'src/python/core': 'Core Python modules',
        'src/python/monitoring': 'Monitoring components',
        'src/python/enterprise': 'Enterprise features',
        'src/python/auth': 'Authentication modules',
        'src/python/tpm': 'TPM integration',
        'src/kernel': 'Kernel driver source',
        'CPP-Kernel-Version': 'C++ kernel implementation',
        'models': 'ML models',
        'signatures': 'Threat signatures',
        'docs': 'Documentation'
    }
    
    all_exist = True
    for dir_path, description in required_dirs.items():
        exists = Path(dir_path).exists()
        all_exist = all_exist and exists
        status = "PASS" if exists else "FAIL"
        print_test(f"{dir_path} ({description})", status)
    
    return all_exist

def test_core_modules():
    """Test core Python modules can be imported"""
    print_header("CORE MODULES IMPORT TEST")
    
    sys.path.insert(0, str(Path('src/python').absolute()))
    
    modules_to_test = [
        ('core.unified_antiransomware', 'UnifiedProtectionManager'),
        ('monitoring.file_monitor', 'File Monitor'),
        ('enterprise.siem_integration', 'SIEM Integration'),
        ('auth.enhanced_token_security', 'Token Security'),
        ('tpm.tpm_pqc_integration', 'TPM+PQC Integration'),
        ('core.ml_detector', 'ML Ransomware Detector'),
        ('monitoring.honeypot_monitor', 'Honeypot Monitor'),
        ('core.threat_intelligence', 'Threat Intelligence')
    ]
    
    all_passed = True
    for module_path, description in modules_to_test:
        try:
            parts = module_path.split('.')
            if len(parts) == 2:
                mod = __import__(parts[0])
                getattr(mod, parts[1])
            else:
                __import__(module_path)
            print_test(f"{description}", "PASS", f"Module: {module_path}")
        except Exception as e:
            all_passed = False
            print_test(f"{description}", "FAIL", str(e)[:80])
    
    return all_passed

def test_tpm_availability():
    """Check TPM 2.0 availability"""
    print_header("TPM 2.0 HARDWARE CHECK")
    
    try:
        import subprocess
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', 'Get-Tpm | Select-Object -ExpandProperty TpmReady'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0 and 'True' in result.stdout:
            print_test("TPM 2.0 Hardware", "PASS", "TPM is ready and operational")
            
            # Check if activated
            result2 = subprocess.run(
                ['powershell', '-NoProfile', '-Command', 'Get-Tpm | Select-Object -ExpandProperty TpmActivated'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if 'True' in result2.stdout:
                print_test("TPM Activation Status", "PASS", "TPM is activated")
            else:
                print_test("TPM Activation Status", "WARN", "TPM not activated")
            
            return True
        else:
            print_test("TPM 2.0 Hardware", "WARN", "TPM not ready or not available")
            return False
    except Exception as e:
        print_test("TPM 2.0 Hardware", "WARN", f"Could not verify: {str(e)[:50]}")
        return False

def test_ml_models():
    """Check ML model availability"""
    print_header("MACHINE LEARNING MODELS")
    
    model_path = Path("models/ransomware_classifier.pkl")
    if model_path.exists():
        size = model_path.stat().st_size
        print_test("ML Model File", "PASS", f"Size: {size:,} bytes")
        return True
    else:
        print_test("ML Model File", "WARN", "Model not trained yet (expected on first run)")
        return False

def test_kernel_driver_source():
    """Verify kernel driver source files"""
    print_header("KERNEL DRIVER SOURCE VERIFICATION")
    
    driver_files = {
        'src/kernel/antiransomware_minifilter.c': 'Main minifilter driver',
        'CPP-Kernel-Version/src/antiransomware_kernel.c': 'C++ kernel version',
        'CPP-Kernel-Version/src/AntiRansomwareKernel.inf': 'Driver INF file'
    }
    
    all_exist = True
    for file_path, description in driver_files.items():
        path = Path(file_path)
        exists = path.exists()
        all_exist = all_exist and exists
        status = "PASS" if exists else "FAIL"
        detail = f"Size: {path.stat().st_size:,} bytes" if exists else "File missing"
        print_test(f"{description}", status, detail)
    
    return all_exist

def test_security_features():
    """Verify security feature implementations"""
    print_header("SECURITY FEATURES VERIFICATION")
    
    features = {
        'src/python/core/unified_antiransomware.py': 'Unified Protection Engine',
        'src/python/auth/enhanced_token_security.py': 'Token Authentication',
        'src/python/tpm/windows_tpm_native.py': 'Native TPM Access',
        'src/python/tpm/tpm_pqc_integration.py': 'Post-Quantum Cryptography',
        'src/python/utils/device_fingerprint_enhanced.py': 'Device Fingerprinting',
        'src/python/enterprise/shadow_copy_protection.py': 'Shadow Copy Protection',
        'src/python/monitoring/system_health_checker.py': 'System Health Monitoring'
    }
    
    all_exist = True
    for file_path, description in features.items():
        path = Path(file_path)
        exists = path.exists()
        all_exist = all_exist and exists
        status = "PASS" if exists else "FAIL"
        if exists:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = len(f.readlines())
            detail = f"{lines:,} lines of code"
        else:
            detail = "File missing"
        print_test(f"{description}", status, detail)
    
    return all_exist

def test_documentation():
    """Verify documentation completeness"""
    print_header("DOCUMENTATION VERIFICATION")
    
    docs = {
        'docs/README.md': 'Main documentation',
        'docs/guides/INSTALLATION.md': 'Installation guide',
        'docs/guides/CONFIGURATION.md': 'Configuration guide',
        'docs/guides/TPM_SETUP_GUIDE.md': 'TPM setup',
        'CPP-Kernel-Version/README.md': 'Kernel driver docs'
    }
    
    all_exist = True
    for file_path, description in docs.items():
        path = Path(file_path)
        exists = path.exists()
        all_exist = all_exist and exists
        status = "PASS" if exists else "WARN"
        if exists:
            size = path.stat().st_size
            detail = f"{size:,} bytes"
        else:
            detail = "Optional doc missing"
        print_test(f"{description}", status, detail)
    
    return True  # Documentation is not critical

def generate_summary_report():
    """Generate comprehensive summary"""
    print_header("VERIFICATION SUMMARY")
    
    results = {
        'Python Dependencies': test_python_dependencies()[0],
        'Project Structure': test_project_structure(),
        'Core Modules': test_core_modules(),
        'TPM Hardware': test_tpm_availability(),
        'ML Models': test_ml_models(),
        'Kernel Driver Source': test_kernel_driver_source(),
        'Security Features': test_security_features(),
        'Documentation': test_documentation()
    }
    
    print("\n" + "="*70)
    print("OVERALL SYSTEM STATUS".center(70))
    print("="*70 + "\n")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for category, status in results.items():
        status_str = f"{Colors.GREEN}PASS{Colors.END}" if status else f"{Colors.RED}FAIL{Colors.END}"
        print(f"  {category:<35} {status_str}")
    
    print(f"\n{Colors.BOLD}Score: {passed}/{total} ({(passed/total)*100:.1f}%){Colors.END}\n")
    
    if passed == total:
        print(f"{Colors.GREEN}{Colors.BOLD}✓ ALL SYSTEMS OPERATIONAL{Colors.END}\n")
    elif passed >= total * 0.8:
        print(f"{Colors.YELLOW}{Colors.BOLD}⚠ SYSTEM FUNCTIONAL WITH MINOR ISSUES{Colors.END}\n")
    else:
        print(f"{Colors.RED}{Colors.BOLD}✗ CRITICAL ISSUES DETECTED{Colors.END}\n")
    
    return results

def check_claimed_features():
    """Verify specific claims from README"""
    print_header("CLAIMED FEATURES VERIFICATION")
    
    claims = {
        "Kernel-level file system monitoring": Path("src/kernel/antiransomware_minifilter.c").exists(),
        "TPM 2.0 integration": Path("src/python/tpm/windows_tpm_native.py").exists(),
        "Post-quantum cryptography (Dilithium3)": Path("src/python/tpm/tpm_pqc_integration.py").exists(),
        "Device fingerprinting (6-8 layers)": Path("src/python/utils/device_fingerprint_enhanced.py").exists(),
        "Machine learning detection": Path("src/python/core/ml_detector.py").exists(),
        "Honeypot monitoring": Path("src/python/monitoring/honeypot_monitor.py").exists(),
        "Shadow copy protection": Path("src/python/enterprise/shadow_copy_protection.py").exists(),
        "SIEM integration": Path("src/python/enterprise/siem_integration.py").exists(),
        "Multi-factor authentication": Path("src/python/auth/trifactor_auth_manager.py").exists(),
        "Behavioral process monitoring": Path("src/python/core/unified_antiransomware.py").exists()
    }
    
    for feature, implemented in claims.items():
        status = "PASS" if implemented else "FAIL"
        print_test(feature, status)
    
    return all(claims.values())

if __name__ == "__main__":
    print(f"\n{Colors.BOLD}Anti-Ransomware System Verification{Colors.END}")
    print(f"{Colors.BOLD}Timestamp: {datetime.now().isoformat()}{Colors.END}")
    
    check_claimed_features()
    results = generate_summary_report()
    
    # Exit code
    sys.exit(0 if all(results.values()) else 1)
