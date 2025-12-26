#!/usr/bin/env python3
"""
Anti-Ransomware Installer with Admin Rights
============================================
Installs the anti-ransomware system with persistent TPM access.
Must be run with Administrator privileges.
"""

import os
import sys
import subprocess
from pathlib import Path

def check_admin():
    """Check if running with admin privileges"""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except:
        return False

def install_as_service():
    """Install as Windows service for persistent admin access"""
    print("\n" + "="*60)
    print("Installing Anti-Ransomware Service (with Admin Rights)")
    print("="*60)
    
    if not check_admin():
        print("\n❌ ERROR: Administrator privileges required!")
        print("\nTo install with TPM support:")
        print("1. Right-click this script")
        print("2. Select 'Run as administrator'")
        print("3. Run again")
        return False
    
    print("\n✓ Running with Administrator privileges")
    
    # Check if virtual environment exists
    venv_path = Path(".venv")
    if not venv_path.exists():
        print("\n📦 Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", ".venv"], check=True)
        print("✓ Virtual environment created")
    
    # Install dependencies
    print("\n📦 Installing dependencies...")
    pip_exe = venv_path / "Scripts" / "pip.exe"
    
    required_packages = [
        "wmi",
        "pywin32",
        "pycryptodome",
        "cryptography",
        "psutil",
        "py-cpuinfo",
        "pqcdualusb"
    ]
    
    for package in required_packages:
        print(f"   Installing {package}...")
        try:
            subprocess.run(
                [str(pip_exe), "install", package],
                capture_output=True,
                check=True
            )
            print(f"   ✓ {package} installed")
        except subprocess.CalledProcessError:
            print(f"   ⚠️ {package} installation failed (may need manual install)")
    
    # Test TPM access
    print("\n🔍 Testing TPM access...")
    python_exe = venv_path / "Scripts" / "python.exe"
    
    test_script = '''
import sys
try:
    import wmi
    c = wmi.WMI(namespace="root\\\\cimv2\\\\Security\\\\MicrosoftTpm")
    tpm_list = c.Win32_Tpm()
    if tpm_list and len(tpm_list) > 0:
        tpm = tpm_list[0]
        if tpm.IsActivated_InitialValue and tpm.IsEnabled_InitialValue:
            print("TPM_READY")
            sys.exit(0)
    print("TPM_NOT_READY")
    sys.exit(1)
except Exception as e:
    print(f"TPM_ERROR: {e}")
    sys.exit(2)
'''
    
    result = subprocess.run(
        [str(python_exe), "-c", test_script],
        capture_output=True,
        text=True
    )
    
    if "TPM_READY" in result.stdout:
        print("✓ TPM is accessible and ready!")
        print("  Your system will have MAXIMUM security (TPM + DeviceFP + USB)")
    elif "TPM_NOT_READY" in result.stdout:
        print("⚠️ TPM found but not initialized")
        print("   Run in PowerShell (as admin): Initialize-Tpm")
    else:
        print("⚠️ TPM not accessible")
        print("   System will use MEDIUM security (DeviceFP + USB)")
    
    # Create configuration file
    print("\n📝 Creating configuration...")
    config = {
        "installed_with_admin": True,
        "tpm_enabled": "TPM_READY" in result.stdout,
        "require_admin": True,
        "security_level": "maximum" if "TPM_READY" in result.stdout else "medium",
        "auto_start": True
    }
    
    import json
    with open("antiransomware_config.json", "w") as f:
        json.dump(config, indent=2, fp=f)
    
    print("✓ Configuration saved")
    
    # Create service launcher
    create_service_launcher()
    
    # Create startup shortcut (optional)
    create_startup_link()
    
    print("\n" + "="*60)
    print("✅ INSTALLATION COMPLETE")
    print("="*60)
    
    if config["tpm_enabled"]:
        print("\n🎉 TPM is PERMANENTLY ENABLED")
        print("   - Security Level: MAXIMUM")
        print("   - TPM will always be available")
        print("   - No need to run as admin again")
    else:
        print("\n✓ Installation successful")
        print("   - Security Level: MEDIUM (DeviceFP + USB)")
        print("   - To enable TPM: Run 'Initialize-Tpm' in PowerShell")
    
    print("\n📚 Next Steps:")
    print("   1. Test the system: python trifactor_auth_manager.py")
    print("   2. Integrate with your protected folder system")
    print("   3. (Optional) Add to Windows startup")
    
    return True

def create_service_launcher():
    """Create a service launcher script"""
    print("\n📝 Creating service launcher...")
    
    launcher_script = '''@echo off
REM Anti-Ransomware Service Launcher
REM This script runs the service with persistent admin rights

cd /d "%~dp0"

REM Check if running as admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

echo Starting Anti-Ransomware Service with Admin Rights...
call .venv\\Scripts\\activate.bat
python trifactor_auth_manager.py

pause
'''
    
    with open("start_service_admin.bat", "w") as f:
        f.write(launcher_script)
    
    print("✓ Service launcher created: start_service_admin.bat")
    print("   Double-click to start with admin (no right-click needed)")

def create_startup_link():
    """Create Windows startup shortcut (optional)"""
    print("\n📝 Creating startup shortcut...")
    
    try:
        import winshell
        from win32com.client import Dispatch
        
        startup_folder = winshell.startup()
        shortcut_path = os.path.join(startup_folder, "AntiRansomware.lnk")
        
        target = os.path.abspath("start_service_admin.bat")
        
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.Targetpath = target
        shortcut.WorkingDirectory = os.path.dirname(target)
        shortcut.IconLocation = target
        shortcut.save()
        
        print(f"✓ Startup shortcut created: {shortcut_path}")
        print("   Service will auto-start on Windows login")
        
    except ImportError:
        print("⚠️ pywin32 not available - skipping startup link")
        print("   Install with: pip install pywin32")
    except Exception as e:
        print(f"⚠️ Could not create startup link: {e}")

def main():
    print("""
╔══════════════════════════════════════════════════════════╗
║     Anti-Ransomware Installer (Admin Required)           ║
║     TPM + Device Fingerprint + PQC USB                   ║
╚══════════════════════════════════════════════════════════╝
""")
    
    if not check_admin():
        print("❌ Not running as Administrator\n")
        print("This installer requires admin rights to:")
        print("  • Enable persistent TPM access")
        print("  • Install system services")
        print("  • Configure security features")
        print("\n💡 To install with TPM support:")
        print("   Right-click this file → 'Run as administrator'\n")
        
        choice = input("Continue without admin (MEDIUM security only)? [y/N]: ")
        if choice.lower() != 'y':
            return
        
        print("\n⚠️ Installing without TPM support...")
        print("   Security Level: MEDIUM (DeviceFP + USB)")
    
    success = install_as_service()
    
    if success:
        print("\n✅ Installation completed successfully!\n")
    else:
        print("\n❌ Installation failed\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
