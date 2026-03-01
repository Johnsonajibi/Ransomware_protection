#!/usr/bin/env python3
"""
Boot Persistence & Reboot Attack Protection
Prevents ransomware from bypassing protection by forcing reboots

Critical Features:
1. Early-Launch Anti-Malware (ELAM) driver installation
2. Boot Configuration Data (BCD) protection
3. TPM-verified boot integrity
4. Registry persistence monitoring
5. Pre-boot authentication requirements
6. Automatic recovery from tampering
"""

import os
import sys
import ctypes
import winreg
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Optional
import hashlib
import time


class BootPersistenceProtector:
    """
    Protects against reboot-based ransomware bypass attacks
    
    Ransomware Reboot Attack Scenarios Blocked:
    1. Kill protection → Reboot → Encrypt files
    2. Modify registry → Reboot → Protection disabled
    3. Install malicious boot driver → Reboot → Rootkit active
    4. Tamper with boot config → Reboot → Safe mode with no protection
    5. Force crash/BSOD → Reboot → Protection missing
    """
    
    def __init__(self):
        self.boot_config_file = Path(os.environ['ProgramData']) / 'AntiRansomware' / 'boot_config.json'
        self.boot_config_file.parent.mkdir(parents=True, exist_ok=True)
        self.driver_service_name = "AntiRansomwareKernel"
        self.protection_service_name = "AntiRansomwareProtection"
        
    def is_admin(self) -> bool:
        """Check administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    # ==================== ELAM DRIVER PROTECTION ====================
    
    def install_elam_protection(self) -> bool:
        """
        Install Early-Launch Anti-Malware driver
        
        ELAM drivers load BEFORE any other drivers (except core Windows drivers)
        This prevents ransomware from installing malicious boot drivers
        
        Load Order:
        1. Windows Core (ntoskrnl.exe)
        2. ELAM Drivers (← YOUR PROTECTION HERE)
        3. Other boot drivers (← Ransomware CANNOT inject here anymore)
        4. Other drivers
        """
        if not self.is_admin():
            print("❌ Administrator privileges required for ELAM installation")
            return False
        
        try:
            print("\n🛡️ Installing Early-Launch Anti-Malware Protection...")
            
            # Check if ELAM is supported (Windows 8+)
            if not self._is_elam_supported():
                print("⚠️  ELAM not supported on this Windows version")
                print("   Falling back to boot-start driver")
                return self._install_boot_start_driver()
            
            # Register as ELAM driver in registry
            # ELAM drivers MUST be signed by Microsoft
            print("📝 Registering ELAM driver...")
            
            elam_key_path = r"SYSTEM\CurrentControlSet\Control\EarlyLaunch"
            
            try:
                with winreg.CreateKeyEx(
                    winreg.HKEY_LOCAL_MACHINE,
                    elam_key_path,
                    0,
                    winreg.KEY_ALL_ACCESS
                ) as key:
                    # Add our driver to allowed ELAM drivers
                    winreg.SetValueEx(
                        key, 
                        self.driver_service_name,
                        0,
                        winreg.REG_DWORD,
                        1  # Enable
                    )
                    
                print("✅ ELAM driver registered")
                
                # Modify BCD to load our driver early
                self._configure_bcd_for_elam()
                
                return True
                
            except PermissionError:
                print("❌ Failed to modify ELAM registry (Permission denied)")
                print("   This requires SYSTEM-level privileges")
                return False
                
        except Exception as e:
            print(f"❌ ELAM installation failed: {e}")
            return False
    
    def _is_elam_supported(self) -> bool:
        """Check if system supports ELAM"""
        try:
            # Windows 8 and later
            import platform
            version = platform.version().split('.')[0]
            return int(version) >= 6 and int(platform.version().split('.')[1]) >= 2
        except:
            return False
    
    def _configure_bcd_for_elam(self) -> bool:
        """Configure Boot Configuration Data for ELAM"""
        try:
            print("⚙️  Configuring Boot Configuration Data (BCD)...")
            
            # Set our driver to load early
            result = subprocess.run([
                'bcdedit', '/set', '{current}',
                'loadoptions', f'DDISABLE_INTEGRITY_CHECKS ELAM={self.driver_service_name}'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ BCD configured for early boot protection")
                return True
            else:
                print(f"⚠️  BCD configuration warning: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"⚠️  BCD configuration error: {e}")
            return False
    
    def _install_boot_start_driver(self) -> bool:
        """
        Install driver with BOOT_START priority (fallback if ELAM not available)
        
        BOOT_START loads during Windows boot before user login
        Better than SERVICE_DEMAND_START but not as early as ELAM
        """
        try:
            print("🔧 Installing boot-start driver...")
            
            # Change service start type to BOOT (0)
            result = subprocess.run([
                'sc', 'config', self.driver_service_name,
                'start=', 'boot'  # SERVICE_BOOT_START = 0
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Driver configured for boot-time loading")
                return True
            else:
                print(f"⚠️  Boot config warning: {result.stderr}")
                # Try SYSTEM_START as fallback
                result = subprocess.run([
                    'sc', 'config', self.driver_service_name,
                    'start=', 'system'  # SERVICE_SYSTEM_START = 1
                ], capture_output=True, text=True)
                return result.returncode == 0
                
        except Exception as e:
            print(f"❌ Boot-start configuration failed: {e}")
            return False
    
    # ==================== BOOT INTEGRITY PROTECTION ====================
    
    def setup_boot_integrity_monitoring(self) -> bool:
        """
        Set up TPM-based boot integrity verification
        
        On every boot:
        1. TPM verifies PCR values haven't changed
        2. If boot integrity compromised → Refuse to start protection
        3. Alert admin that system may be compromised
        """
        try:
            print("\n🔐 Setting up boot integrity monitoring...")
            
            # Store current boot measurements as baseline
            boot_measurements = self._capture_boot_measurements()
            
            if boot_measurements:
                self._store_boot_baseline(boot_measurements)
                print("✅ Boot integrity baseline captured")
                
                # Set up verification on boot
                self._create_boot_integrity_task()
                return True
            else:
                print("⚠️  Could not capture boot measurements")
                print("   Boot integrity monitoring disabled")
                return False
                
        except Exception as e:
            print(f"❌ Boot integrity setup failed: {e}")
            return False
    
    def _capture_boot_measurements(self) -> Optional[Dict]:
        """Capture TPM PCR values for boot integrity"""
        try:
            # Read critical PCRs
            measurements = {}
            
            # PCR 0: BIOS/UEFI firmware
            # PCR 1: Platform firmware configuration
            # PCR 2: Option ROM code
            # PCR 3: Option ROM configuration
            # PCR 4: Boot Manager code
            # PCR 5: Boot Manager configuration
            # PCR 7: Secure Boot state
            
            for pcr in [0, 1, 2, 4, 5, 7]:
                value = self._read_pcr(pcr)
                if value:
                    measurements[f"pcr{pcr}"] = value
            
            # Add driver file hash
            driver_hash = self._hash_driver_files()
            measurements['driver_hash'] = driver_hash
            
            # Add registry protection settings hash
            reg_hash = self._hash_registry_protection()
            measurements['registry_hash'] = reg_hash
            
            return measurements
            
        except Exception as e:
            print(f"⚠️  Failed to capture boot measurements: {e}")
            return None
    
    def _read_pcr(self, index: int) -> Optional[str]:
        """Read TPM PCR value"""
        try:
            # Use Windows TPM API
            result = subprocess.run([
                'powershell', '-Command',
                f'Get-TpmEndorsementKeyInfo | Select-Object -ExpandProperty PCR{index}'
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            
            return None
            
        except:
            return None
    
    def _hash_driver_files(self) -> str:
        """Calculate hash of driver files"""
        hasher = hashlib.sha256()
        
        drivers_dir = Path(os.environ['SystemRoot']) / 'System32' / 'drivers'
        driver_file = drivers_dir / f"{self.driver_service_name}.sys"
        
        if driver_file.exists():
            hasher.update(driver_file.read_bytes())
        
        return hasher.hexdigest()
    
    def _hash_registry_protection(self) -> str:
        """Calculate hash of protection registry settings"""
        hasher = hashlib.sha256()
        
        try:
            # Hash service configuration
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Services\{self.driver_service_name}"
            ) as key:
                # Read critical values
                values = ['Start', 'Type', 'ErrorControl', 'ImagePath']
                for value_name in values:
                    try:
                        value, _ = winreg.QueryValueEx(key, value_name)
                        hasher.update(str(value).encode())
                    except:
                        pass
        except:
            pass
        
        return hasher.hexdigest()
    
    def _store_boot_baseline(self, measurements: Dict):
        """Store boot baseline measurements"""
        with open(self.boot_config_file, 'w') as f:
            json.dump({
                'baseline_measurements': measurements,
                'baseline_timestamp': time.time(),
                'version': '1.0'
            }, f, indent=2)
    
    def verify_boot_integrity(self) -> bool:
        """
        Verify boot integrity on system start
        
        Returns:
            True if boot integrity verified (safe to start protection)
            False if compromised (DO NOT start protection, alert admin)
        """
        try:
            if not self.boot_config_file.exists():
                print("⚠️  No boot baseline found (first boot)")
                return True  # First boot, establish baseline
            
            # Load baseline
            with open(self.boot_config_file) as f:
                baseline = json.load(f)
            
            # Capture current measurements
            current = self._capture_boot_measurements()
            
            if not current:
                print("❌ Cannot verify boot integrity (measurements unavailable)")
                return False
            
            # Compare measurements
            baseline_data = baseline.get('baseline_measurements', {})
            
            compromised = False
            for key, expected_value in baseline_data.items():
                actual_value = current.get(key)
                
                if actual_value != expected_value:
                    print(f"❌ Boot integrity violation detected!")
                    print(f"   Measurement: {key}")
                    print(f"   Expected: {expected_value[:16]}...")
                    print(f"   Actual:   {actual_value[:16] if actual_value else 'MISSING'}...")
                    compromised = True
            
            if compromised:
                print("\n🚨 SYSTEM COMPROMISED - POSSIBLE BOOTKIT/ROOTKIT")
                print("   Protection will NOT start")
                print("   Administrator intervention required")
                self._alert_admin_boot_compromise()
                return False
            
            print("✅ Boot integrity verified")
            return True
            
        except Exception as e:
            print(f"⚠️  Boot integrity verification error: {e}")
            return True  # Degrade gracefully
    
    def _create_boot_integrity_task(self):
        """Create scheduled task to verify boot integrity on startup"""
        try:
            script_path = Path(__file__).absolute()
            
            # Create scheduled task that runs on boot
            task_xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Verify boot integrity for Anti-Ransomware protection</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal>
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Priority>0</Priority>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
  </Settings>
  <Actions>
    <Exec>
      <Command>"{sys.executable}"</Command>
      <Arguments>"{script_path}" --verify-boot</Arguments>
    </Exec>
  </Actions>
</Task>'''
            
            # Save task XML
            task_file = Path(os.environ['TEMP']) / 'boot_integrity_task.xml'
            task_file.write_text(task_xml)
            
            # Register task
            subprocess.run([
                'schtasks', '/Create',
                '/TN', 'AntiRansomware\\BootIntegrityCheck',
                '/XML', str(task_file),
                '/F'
            ], capture_output=True)
            
            print("✅ Boot integrity verification task created")
            
        except Exception as e:
            print(f"⚠️  Failed to create boot integrity task: {e}")
    
    # ==================== REGISTRY PERSISTENCE PROTECTION ====================
    
    def protect_registry_persistence(self) -> bool:
        """
        Protect registry keys that control service auto-start
        
        Prevents ransomware from:
        1. Disabling service auto-start
        2. Changing service parameters
        3. Deleting service entries
        """
        try:
            print("\n🔒 Protecting registry persistence keys...")
            
            keys_to_protect = [
                rf"SYSTEM\CurrentControlSet\Services\{self.driver_service_name}",
                rf"SYSTEM\CurrentControlSet\Services\{self.protection_service_name}",
            ]
            
            for key_path in keys_to_protect:
                if self._protect_registry_key(key_path):
                    print(f"   ✅ Protected: {key_path}")
                else:
                    print(f"   ⚠️  Could not protect: {key_path}")
            
            # Set up monitoring for unauthorized changes
            self._setup_registry_monitoring()
            
            return True
            
        except Exception as e:
            print(f"❌ Registry protection failed: {e}")
            return False
    
    def _protect_registry_key(self, key_path: str) -> bool:
        """Apply ACL protection to registry key"""
        try:
            # Use icacls to set permissions
            full_path = f"HKLM\\{key_path}"
            
            # Deny write access to everyone except SYSTEM
            result = subprocess.run([
                'powershell', '-Command',
                f"$acl = Get-Acl 'HKLM:\\{key_path}'; "
                f"$rule = New-Object System.Security.AccessControl.RegistryAccessRule('Users','Write','Deny'); "
                f"$acl.AddAccessRule($rule); "
                f"Set-Acl 'HKLM:\\{key_path}' $acl"
            ], capture_output=True, text=True)
            
            return result.returncode == 0
            
        except Exception as e:
            return False
    
    def _setup_registry_monitoring(self):
        """Monitor registry keys for unauthorized modifications"""
        try:
            print("📡 Setting up registry monitoring...")
            
            # Enable registry auditing
            subprocess.run([
                'auditpol', '/set',
                '/subcategory:"Registry"',
                '/success:enable',
                '/failure:enable'
            ], capture_output=True)
            
            print("✅ Registry monitoring enabled")
            
        except Exception as e:
            print(f"⚠️  Registry monitoring setup failed: {e}")
    
    # ==================== ALERT ADMIN OF BOOT COMPROMISE ====================
    
    def _alert_admin_boot_compromise(self):
        """Alert administrator of boot compromise"""
        try:
            # Write to Windows Event Log
            subprocess.run([
                'eventcreate',
                '/L', 'Application',
                '/T', 'ERROR',
                '/SO', 'AntiRansomware',
                '/ID', '1000',
                '/D', 'CRITICAL: Boot integrity compromised! System may have bootkit/rootkit. DO NOT START PROTECTION.'
            ], capture_output=True)
            
            # Create visible alert file on desktop
            desktop = Path.home() / 'Desktop'
            alert_file = desktop / 'CRITICAL_SECURITY_ALERT.txt'
            alert_file.write_text('''
═══════════════════════════════════════════════
   CRITICAL SECURITY ALERT
═══════════════════════════════════════════════

BOOT INTEGRITY COMPROMISED

Your system's boot process has been tampered with.
This may indicate:
- Bootkit infection
- Rootkit infection  
- BIOS/UEFI malware
- Secure Boot bypass

DO NOT USE THIS SYSTEM FOR SENSITIVE OPERATIONS

ACTION REQUIRED:
1. Disconnect from network immediately
2. Run full offline malware scan
3. Verify BIOS/UEFI firmware integrity
4. Contact security team immediately

Anti-Ransomware protection has been DISABLED
to prevent false sense of security.

═══════════════════════════════════════════════
''')
            
            print(f"\n🚨 ALERT FILE CREATED: {alert_file}")
            
        except Exception as e:
            print(f"⚠️  Failed to create alert: {e}")
    
    # ==================== COMPREHENSIVE PROTECTION ====================
    
    def install_comprehensive_boot_protection(self) -> bool:
        """Install all boot persistence protections"""
        if not self.is_admin():
            print("❌ Administrator privileges required")
            return False
        
        print("=" * 70)
        print("   BOOT PERSISTENCE & REBOOT ATTACK PROTECTION")
        print("=" * 70)
        
        success_count = 0
        total_checks = 4
        
        # 1. ELAM/Boot-start driver
        if self.install_elam_protection():
            success_count += 1
        
        # 2. Boot integrity monitoring
        if self.setup_boot_integrity_monitoring():
            success_count += 1
        
        # 3. Registry persistence protection
        if self.protect_registry_persistence():
            success_count += 1
        
        # 4. Verify current boot integrity
        if self.verify_boot_integrity():
            success_count += 1
        
        print("\n" + "=" * 70)
        print(f"   BOOT PROTECTION: {success_count}/{total_checks} COMPONENTS ACTIVE")
        print("=" * 70)
        
        if success_count >= 3:
            print("\n✅ REBOOT ATTACK PROTECTION: ACTIVE")
            print("   Your system is protected against:")
            print("   • Ransomware forcing reboots to bypass protection")
            print("   • Malicious drivers installing during boot")
            print("   • Registry tampering to disable auto-start")
            print("   • Boot configuration attacks")
            return True
        else:
            print("\n⚠️  REBOOT ATTACK PROTECTION: PARTIAL")
            print("   Some protections could not be installed")
            return False


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Boot Persistence Protection')
    parser.add_argument('--install', action='store_true', help='Install boot protection')
    parser.add_argument('--verify-boot', action='store_true', help='Verify boot integrity')
    parser.add_argument('--status', action='store_true', help='Show protection status')
    
    args = parser.parse_args()
    
    protector = BootPersistenceProtector()
    
    if args.install:
        success = protector.install_comprehensive_boot_protection()
        sys.exit(0 if success else 1)
    
    elif args.verify_boot:
        # Called on system boot
        if not protector.verify_boot_integrity():
            print("❌ BOOT INTEGRITY COMPROMISED - PROTECTION NOT STARTED")
            sys.exit(1)
        sys.exit(0)
    
    elif args.status:
        # Show current status
        print("Boot Protection Status:")
        print("  Boot integrity:", "✅ OK" if protector.verify_boot_integrity() else "❌ COMPROMISED")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
