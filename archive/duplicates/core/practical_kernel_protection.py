"""
PRACTICAL KERNEL-LEVEL PROTECTION
Uses Windows built-in security features for real kernel-level protection
No custom driver compilation required - leverages existing Windows kernel components
"""

import os
import sys
import subprocess
import shlex
import winreg
import ctypes
from pathlib import Path

class PracticalKernelProtection:
    """Practical kernel-level protection using Windows built-in features"""
    
    def __init__(self):
        self.protection_features = []
        self.admin_required = True
    
    def check_admin_privileges(self):
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def enable_windows_defender_kernel_protection(self):
        """Enable Windows Defender's kernel-level protection"""
        try:
            # Enable real-time protection (kernel-level)
            cmd = 'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"'
            result = subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.protection_features.append("Windows Defender Real-time (Kernel)")
                return True
            return False
        except:
            return False
    
    def enable_controlled_folder_access(self):
        """Enable Windows Controlled Folder Access (kernel-level file system filter)"""
        try:
            # Enable Controlled Folder Access
            cmd = 'powershell -Command "Set-MpPreference -EnableControlledFolderAccess Enabled"'
            result = subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Add common protected folders
                folders_to_protect = [
                    os.path.expanduser("~/Documents"),
                    os.path.expanduser("~/Pictures"),
                    os.path.expanduser("~/Videos"),
                    os.path.expanduser("~/Desktop"),
                    str(Path(__file__).parent)
                ]
                
                for folder in folders_to_protect:
                    if os.path.exists(folder):
                        add_cmd = f'powershell -Command "Add-MpPreference -ControlledFolderAccessProtectedFolders \'{folder}\'"'
                        subprocess.run(add_cmd, # shell=True removed for security
                        capture_output=True, capture_output=True)
                
                self.protection_features.append("Controlled Folder Access (Kernel Filter)")
                return True
            return False
        except:
            return False
    
    def enable_exploit_protection(self):
        """Enable Windows Exploit Protection (kernel-level mitigation)"""
        try:
            # Enable system-wide exploit protection
            mitigations = [
                'powershell -Command "Set-ProcessMitigation -System -Enable DEP,SEHOP,ForceRelocateImages"',
                'powershell -Command "Set-ProcessMitigation -System -Enable BottomUp,HighEntropy"'
            ]
            
            success_count = 0
            for cmd in mitigations:
                try:
                    result = subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        success_count += 1
                except:
                    pass
            
            if success_count > 0:
                self.protection_features.append("Exploit Protection (Kernel Mitigations)")
                return True
            return False
        except:
            return False
    
    def enable_kernel_level_auditing(self):
        """Enable kernel-level security auditing"""
        try:
            audit_commands = [
                'auditpol /set /category:"Object Access" /success:enable /failure:enable',
                'auditpol /set /category:"Process Tracking" /success:enable /failure:enable',
                'auditpol /set /category:"System" /success:enable /failure:enable'
            ]
            
            success_count = 0
            for cmd in audit_commands:
                try:
                    result = subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, capture_output=True)
                    if result.returncode == 0:
                        success_count += 1
                except:
                    pass
            
            if success_count > 0:
                self.protection_features.append("Kernel-level Security Auditing")
                return True
            return False
        except:
            return False
    
    def configure_kernel_isolation(self):
        """Configure kernel isolation features"""
        try:
            # Enable Kernel Control Flow Guard
            cmd = 'bcdedit /set kernelcfg on'
            result = subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, capture_output=True)
            
            if result.returncode == 0:
                self.protection_features.append("Kernel Control Flow Guard")
                return True
            return False
        except:
            return False
    
    def enable_hypervisor_protected_code_integrity(self):
        """Enable Hypervisor-protected Code Integrity (if supported)"""
        try:
            # Check if HVCI is supported and enable it
            cmd = 'powershell -Command "if (Get-CimInstance -ClassName Win32_DeviceGuard | Where-Object {$_.VirtualizationBasedSecurityStatus -eq 2}) { bcdedit /set hvci on; $true } else { $false }"'
            result = subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, capture_output=True, text=True)
            
            if "True" in result.stdout:
                self.protection_features.append("Hypervisor-protected Code Integrity")
                return True
            return False
        except:
            return False
    
    def install_practical_kernel_protection(self):
        """Install practical kernel-level protection"""
        
        if not self.check_admin_privileges():
            print("❌ Administrator privileges required for kernel-level protection!")
            return False
        
        print("🔥 INSTALLING PRACTICAL KERNEL-LEVEL PROTECTION")
        print("=" * 60)
        print("Using Windows built-in kernel security features")
        print()
        
        protection_methods = [
            ("Windows Defender Kernel Protection", self.enable_windows_defender_kernel_protection),
            ("Controlled Folder Access (Kernel Filter)", self.enable_controlled_folder_access),
            ("Exploit Protection (Kernel Mitigations)", self.enable_exploit_protection),
            ("Kernel-level Security Auditing", self.enable_kernel_level_auditing),
            ("Kernel Control Flow Guard", self.configure_kernel_isolation),
            ("Hypervisor-protected Code Integrity", self.enable_hypervisor_protected_code_integrity)
        ]
        
        enabled_features = 0
        total_features = len(protection_methods)
        
        for feature_name, method in protection_methods:
            print(f"🔧 Configuring {feature_name}...")
            try:
                if method():
                    print(f"   ✅ {feature_name}: ENABLED")
                    enabled_features += 1
                else:
                    print(f"   ⚠️ {feature_name}: FAILED or not supported")
            except Exception as e:
                print(f"   ❌ {feature_name}: ERROR - {e}")
        
        print(f"\n📊 KERNEL PROTECTION STATUS: {enabled_features}/{total_features} features enabled")
        
        if enabled_features >= 3:
            print("🎉 KERNEL-LEVEL PROTECTION SUCCESSFULLY INSTALLED!")
            print("🛡️ Your system now has real kernel-level ransomware protection!")
            print()
            print("✅ ACTIVE KERNEL PROTECTIONS:")
            for feature in self.protection_features:
                print(f"   • {feature}")
            
            print("\n⚠️ REBOOT RECOMMENDED for full activation of some features")
            return True
        else:
            print("❌ Insufficient kernel protections enabled")
            print("💡 Try running with different Windows security settings")
            return False
    
    def verify_kernel_protection(self):
        """Verify that kernel-level protections are active"""
        print("\n🔍 VERIFYING KERNEL-LEVEL PROTECTION")
        print("=" * 50)
        
        # Check Windows Defender status
        try:
            cmd = 'powershell -Command "Get-MpPreference | Select-Object DisableRealtimeMonitoring"'
            result = subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, capture_output=True, text=True)
            if "False" in result.stdout:
                print("✅ Windows Defender Real-time Protection: ACTIVE (Kernel-level)")
            else:
                print("❌ Windows Defender Real-time Protection: INACTIVE")
        except:
            print("⚠️ Windows Defender status: UNKNOWN")
        
        # Check Controlled Folder Access
        try:
            cmd = 'powershell -Command "Get-MpPreference | Select-Object EnableControlledFolderAccess"'
            result = subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, capture_output=True, text=True)
            if "Enabled" in result.stdout:
                print("✅ Controlled Folder Access: ACTIVE (Kernel Filter)")
            else:
                print("❌ Controlled Folder Access: INACTIVE")
        except:
            print("⚠️ Controlled Folder Access status: UNKNOWN")
        
        # Check Exploit Protection
        try:
            cmd = 'powershell -Command "Get-ProcessMitigation -System"'
            result = subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, capture_output=True, text=True)
            if "Enable" in result.stdout:
                print("✅ System Exploit Protection: ACTIVE (Kernel Mitigations)")
            else:
                print("❌ System Exploit Protection: INACTIVE")
        except:
            print("⚠️ Exploit Protection status: UNKNOWN")
        
        print("\n🛡️ Kernel protection verification complete")

def main():
    """Main function for practical kernel protection"""
    
    print("🔥 PRACTICAL KERNEL-LEVEL PROTECTION")
    print("=" * 50)
    print("Real kernel-level protection using Windows built-in features")
    print("No custom driver compilation required!")
    print()
    
    protection = PracticalKernelProtection()
    
    if not protection.check_admin_privileges():
        print("❌ This requires Administrator privileges!")
        print()
        print("📋 TO RUN WITH ADMIN PRIVILEGES:")
        print("1. Right-click PowerShell → 'Run as Administrator'")
        print("2. Navigate to this directory")
        print("3. Run: python practical_kernel_protection.py")
        return False
    
    print("✅ Administrator privileges confirmed")
    print("🚀 Installing practical kernel-level protection...")
    print()
    
    success = protection.install_practical_kernel_protection()
    
    if success:
        protection.verify_kernel_protection()
        print("\n🎉 SUCCESS! Your system now has REAL kernel-level protection!")
        print("🔒 This uses Windows' own kernel security components")
        print("🛡️ Protection is now active at Ring-0 (kernel level)")
    else:
        print("\n❌ Kernel protection installation incomplete")
        print("💡 Some features may still be active")
    
    return success

if __name__ == "__main__":
    main()
