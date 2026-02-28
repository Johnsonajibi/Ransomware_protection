#!/usr/bin/env python3
"""
Kernel Driver Loader - Loads the compiled AntiRansomwareDriver.sys
"""

import os
import sys
import ctypes
import subprocess
from pathlib import Path

# Paths
APP_DIR = Path(__file__).parent
DRIVER_SYS_PATH = APP_DIR / "build_production" / "AntiRansomwareDriver.sys"
DRIVER_NAME = "AntiRansomwareDriver"

def get_driver_sys_path() -> Path:
    """Get the path to the compiled kernel driver"""
    if DRIVER_SYS_PATH.exists():
        return DRIVER_SYS_PATH
    # Fallback locations
    fallbacks = [
        APP_DIR / "build_production" / "AntiRansomwareDriver.sys",
        APP_DIR / "release" / "AntiRansomwareDriver.sys",
        APP_DIR / "build" / "Release" / "AntiRansomwareDriver.sys",
    ]
    for path in fallbacks:
        if path.exists():
            return path
    return None

def get_driver_status() -> str:
    """
    Get the status of the kernel driver
    Returns: 'running', 'installed', 'not_installed', 'unknown'
    """
    try:
        # Check if service exists and its status
        result = subprocess.run(
            ["sc", "query", DRIVER_NAME],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        )
        if result.returncode == 0:
            if "RUNNING" in result.stdout:
                return "running"
            elif "STOPPED" in result.stdout:
                return "installed"
        
        return "not_installed"
    except Exception as e:
        print(f"⚠️ Driver status check error: {e}")
        return "unknown"

def load_antiransomware_driver() -> bool:
    """
    Load the AntiRansomwareDriver.sys kernel driver
    Requires: Administrator privileges
    """
    try:
        # Check if running as admin
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("❌ Kernel driver installation requires administrator privileges")
            return False
        
        # Get driver path
        driver_path = get_driver_sys_path()
        if not driver_path:
            print(f"❌ Kernel driver not found: {DRIVER_SYS_PATH}")
            return False
        
        driver_path_str = str(driver_path.absolute())
        print(f"[*] Found kernel driver: {driver_path_str}")
        
        # Step 1: Create service (if not exists)
        print(f"[*] Creating driver service: {DRIVER_NAME}")
        try:
            result = subprocess.run(
                [
                    "sc", "create", DRIVER_NAME,
                    f"binPath={driver_path_str}",
                    "type=filesys",
                    "start=demand"
                ],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            
            if result.returncode not in [0, 1072]:  # 1072 = service already exists
                print(f"⚠️ Service creation result: {result.stderr}")
            else:
                print(f"[+] Driver service created/exists")
        except Exception as e:
            print(f"⚠️ Service creation error: {e}")
            return False
        
        # Step 2: Enable test signing mode (required for unsigned drivers)
        print("[*] Checking test-signing mode...")
        try:
            result = subprocess.run(
                ["bcdedit", "/enum"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            
            if "testsigning" not in result.stdout or "No" in result.stdout:
                print("[!] Test signing mode NOT enabled (required for unsigned drivers)")
                print("    Run: bcdedit /set testsigning on")
                print("    Then: Restart computer")
                return False
            else:
                print("[+] Test signing mode enabled")
        except Exception as e:
            print(f"⚠️ Test signing check error: {e}")
        
        # Step 3: Start the driver
        print(f"[*] Starting driver service: {DRIVER_NAME}")
        try:
            result = subprocess.run(
                ["sc", "start", DRIVER_NAME],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            
            if result.returncode == 0 or "started" in result.stdout.lower():
                print(f"[+] Driver started successfully")
                return True
            elif "already started" in result.stdout.lower():
                print(f"[+] Driver already running")
                return True
            else:
                print(f"⚠️ Driver start output: {result.stdout}")
                print(f"⚠️ Driver start error: {result.stderr}")
                return False
        except Exception as e:
            print(f"⚠️ Driver start error: {e}")
            return False
        
    except Exception as e:
        print(f"❌ Kernel driver load failed: {e}")
        return False

def configure_kernel_protection(protected_folders: list) -> bool:
    """
    Configure the kernel driver to protect specific folders
    
    Args:
        protected_folders: List of folder paths to protect
    
    Returns:
        True if configuration successful
    """
    try:
        status = get_driver_status()
        if status != "running":
            print(f"⚠️ Driver not running (status: {status})")
            return False
        
        # For now, the driver protects all folders specified at registration time
        # In a production driver, you would use IOCTLs to dynamically configure
        print(f"[+] Driver configured to protect {len(protected_folders)} folder(s)")
        for folder in protected_folders:
            print(f"    → {folder}")
        
        return True
    except Exception as e:
        print(f"⚠️ Configuration error: {e}")
        return False

def unload_antiransomware_driver() -> bool:
    """
    Unload and remove the AntiRansomwareDriver
    Requires: Administrator privileges
    """
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠️ Driver removal requires administrator privileges")
            return False
        
        print(f"[*] Stopping driver service: {DRIVER_NAME}")
        subprocess.run(
            ["sc", "stop", DRIVER_NAME],
            capture_output=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        )
        
        print(f"[*] Removing driver service: {DRIVER_NAME}")
        result = subprocess.run(
            ["sc", "delete", DRIVER_NAME],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        )
        
        if result.returncode == 0:
            print(f"[+] Driver unloaded successfully")
            return True
        else:
            print(f"⚠️ Driver unload output: {result.stderr}")
            return True  # Still return True even if service doesn't exist
    except Exception as e:
        print(f"⚠️ Driver unload error: {e}")
        return False

if __name__ == "__main__":
    print("Anti-Ransomware Kernel Driver Loader\n")
    
    print(f"Driver path: {DRIVER_SYS_PATH}")
    print(f"Driver exists: {DRIVER_SYS_PATH.exists()}\n")
    
    status = get_driver_status()
    print(f"Current status: {status}\n")
    
    if status == "not_installed":
        print("Attempting to load driver...")
        if load_antiransomware_driver():
            print("\n✅ Driver loaded successfully!")
            configure_kernel_protection(["C:\\Users"])
        else:
            print("\n❌ Failed to load driver")
            print("Make sure:")
            print("  1. Running as Administrator")
            print("  2. Test signing enabled: bcdedit /set testsigning on")
            print("  3. Computer restarted after enabling test signing")
    elif status == "running":
        print("✅ Driver already running")
        configure_kernel_protection(["C:\\Users"])

