#!/usr/bin/env python3
"""
ENTERPRISE INSTALLATION AND DEPLOYMENT SCRIPT
Installs enterprise anti-ransomware as Windows service with security hardening
"""

import os
import sys
import subprocess
import shlex
import ctypes
import winreg
from pathlib import Path
import json
import shutil

class EnterpriseInstaller:
    def __init__(self):
        self.install_dir = Path("C:/Program Files/Enterprise AntiRansomware")
        self.data_dir = Path("C:/ProgramData/AntiRansomware")
        self.service_name = "EnterpriseAntiRansomware"
        self.is_admin = self.check_admin()
        
    def check_admin(self):
        """Check if running as administrator"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def install_enterprise_system(self):
        """Install complete enterprise system"""
        print("🏢 ENTERPRISE ANTI-RANSOMWARE INSTALLER")
        print("=" * 50)
        
        if not self.is_admin:
            print("❌ ERROR: Administrator privileges required")
            print("Please run this installer as Administrator")
            return False
        
        steps = [
            ("Installing Python dependencies", self.install_dependencies),
            ("Creating secure directories", self.create_secure_directories),
            ("Installing service files", self.install_service_files),
            ("Registering Windows service", self.register_service),
            ("Configuring security policies", self.configure_security),
            ("Setting up monitoring", self.setup_monitoring),
            ("Starting enterprise service", self.start_service),
            ("Verifying installation", self.verify_installation)
        ]
        
        for step_name, step_func in steps:
            print(f"\n📋 {step_name}...")
            if not step_func():
                print(f"❌ Failed: {step_name}")
                return False
            print(f"✅ Completed: {step_name}")
        
        print("\n" + "=" * 50)
        print("✅ ENTERPRISE INSTALLATION COMPLETED SUCCESSFULLY!")
        print(f"📁 Service installed to: {self.install_dir}")
        print(f"📊 Data directory: {self.data_dir}")
        print("🌐 Secure web interface: https://localhost:8443")
        print("🛡️  Enterprise protection is now ACTIVE")
        print("=" * 50)
        
        return True
    
    def install_dependencies(self):
        """Install required Python packages"""
        try:
            packages = [
                'flask==3.0.0',
                'watchdog==3.0.0',
                'psutil==5.9.6',
                'cryptography==41.0.7',
                'pywin32==306'
            ]
            
            for package in packages:
                result = subprocess.run([
                    sys.executable, '-m', 'pip', 'install', package
                ], capture_output=True, text=True)
                
                if result.returncode != 0:
                    print(f"Warning: Failed to install {package}")
                    
            return True
            
        except Exception as e:
            print(f"Dependency installation error: {e}")
            return False
    
    def create_secure_directories(self):
        """Create secure directory structure"""
        try:
            # Main directories
            self.install_dir.mkdir(parents=True, exist_ok=True)
            self.data_dir.mkdir(parents=True, exist_ok=True)
            
            # Subdirectories
            (self.data_dir / "logs").mkdir(exist_ok=True)
            (self.data_dir / "quarantine").mkdir(exist_ok=True)
            (self.data_dir / "secure").mkdir(exist_ok=True)
            (self.data_dir / "certs").mkdir(exist_ok=True)
            (self.data_dir / "config").mkdir(exist_ok=True)
            (self.data_dir / "backups").mkdir(exist_ok=True)
            
            # Set restrictive permissions
            self._secure_directory_permissions()
            
            return True
            
        except Exception as e:
            print(f"Directory creation error: {e}")
            return False
    
    def _secure_directory_permissions(self):
        """Apply secure permissions to directories"""
        try:
            # Use icacls to set secure permissions
            secure_dirs = [
                str(self.data_dir / "secure"),
                str(self.data_dir / "certs"),
                str(self.data_dir / "quarantine")
            ]
            
            for dir_path in secure_dirs:
                # Remove inherited permissions and set restrictive access
                cmd = f'icacls "{dir_path}" /inheritance:r /grant:r "NT AUTHORITY\\SYSTEM:(OI)(CI)F" /grant:r "BUILTIN\\Administrators:(OI)(CI)F"'
                subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, capture_output=True)
                
        except Exception as e:
            print(f"Permission setting warning: {e}")
    
    def install_service_files(self):
        """Install service executable and support files"""
        try:
            # Copy main service file
            shutil.copy2("enterprise_service.py", self.install_dir / "AntiRansomwareService.py")
            
            # Create service wrapper executable
            service_wrapper = f'''
import sys
import os
sys.path.insert(0, r"{self.install_dir}")
os.chdir(r"{self.install_dir}")

from AntiRansomwareService import AntiRansomwareService
import win32serviceutil

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(AntiRansomwareService)
'''
            
            wrapper_path = self.install_dir / "service_wrapper.py"
            with open(wrapper_path, 'w') as f:
                f.write(service_wrapper)
            
            # Create configuration files
            config = {
                "service": {
                    "name": self.service_name,
                    "version": "1.0.0",
                    "install_date": "2024-01-01",
                    "security_level": "enterprise"
                },
                "protection": {
                    "behavioral_analysis": True,
                    "process_verification": True,
                    "entropy_threshold": 7.5,
                    "emergency_response": True
                },
                "web": {
                    "host": "127.0.0.1",
                    "port": 8443,
                    "https_only": True,
                    "auto_cert": True
                }
            }
            
            config_file = self.data_dir / "config" / "enterprise_config.json"
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Service file installation error: {e}")
            return False
    
    def register_service(self):
        """Register Windows service"""
        try:
            # Install service using sc command
            service_path = f'"{sys.executable}" "{self.install_dir / "service_wrapper.py"}"'
            
            cmd = f'sc create "{self.service_name}" binPath= "{service_path}" DisplayName= "Enterprise Anti-Ransomware Service" start= auto'
            result = subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Service registration failed: {result.stderr}")
                return False
            
            # Set service description
            desc_cmd = f'sc description "{self.service_name}" "Enterprise-grade anti-ransomware protection with behavioral analysis and kernel-level monitoring"'
            subprocess.run(desc_cmd, # shell=True removed for security
                        capture_output=True, capture_output=True)
            
            # Set service to delayed auto-start
            delayed_cmd = f'sc config "{self.service_name}" start= delayed-auto'
            subprocess.run(delayed_cmd, # shell=True removed for security
                        capture_output=True, capture_output=True)
            
            return True
            
        except Exception as e:
            print(f"Service registration error: {e}")
            return False
    
    def configure_security(self):
        """Configure Windows security policies"""
        try:
            # Add Windows Firewall rule for HTTPS
            firewall_cmd = 'netsh advfirewall firewall add rule name="AntiRansomware HTTPS" dir=in action=allow protocol=TCP localport=8443'
            subprocess.run(firewall_cmd, # shell=True removed for security
                        capture_output=True, capture_output=True)
            
            # Configure service recovery options
            recovery_cmd = f'sc failure "{self.service_name}" reset= 3600 actions= restart/60000/restart/60000/restart/60000'
            subprocess.run(recovery_cmd, # shell=True removed for security
                        capture_output=True, capture_output=True)
            
            # Set service to run as LocalSystem
            account_cmd = f'sc config "{self.service_name}" obj= LocalSystem'
            subprocess.run(account_cmd, # shell=True removed for security
                        capture_output=True, capture_output=True)
            
            return True
            
        except Exception as e:
            print(f"Security configuration error: {e}")
            return False
    
    def setup_monitoring(self):
        """Setup Windows Event Log monitoring"""
        try:
            # Create custom event log source
            eventlog_cmd = 'eventcreate /ID 1 /L APPLICATION /T INFORMATION /SO "AntiRansomware" /D "Enterprise Anti-Ransomware service initialized"'
            subprocess.run(eventlog_cmd, # shell=True removed for security
                        capture_output=True, capture_output=True)
            
            # Setup Windows Performance Counters (if available)
            # This would require additional setup in production
            
            return True
            
        except Exception as e:
            print(f"Monitoring setup warning: {e}")
            return True  # Non-critical
    
    def start_service(self):
        """Start the enterprise service"""
        try:
            # Start the service
            start_cmd = f'net start "{self.service_name}"'
            result = subprocess.run(start_cmd, # shell=True removed for security
                        capture_output=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Service start failed: {result.stderr}")
                return False
            
            # Wait a moment for service to initialize
            import time
            time.sleep(3)
            
            return True
            
        except Exception as e:
            print(f"Service start error: {e}")
            return False
    
    def verify_installation(self):
        """Verify the installation is working"""
        try:
            # Check service status
            status_cmd = f'sc query "{self.service_name}"'
            result = subprocess.run(status_cmd, # shell=True removed for security
                        capture_output=True, capture_output=True, text=True)
            
            if "RUNNING" not in result.stdout:
                print("Service is not running properly")
                return False
            
            # Test HTTPS endpoint (basic connectivity)
            try:
                import requests
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
                response = requests.get('https://localhost:8443', verify=False, timeout=5)
                if response.status_code == 200:
                    print("✅ HTTPS interface accessible")
                else:
                    print("⚠️  HTTPS interface not fully ready")
            except:
                print("⚠️  HTTPS interface starting up...")
            
            # Check log files
            log_file = self.data_dir / "logs" / "service.log"
            if log_file.exists():
                print("✅ Service logging active")
            
            return True
            
        except Exception as e:
            print(f"Verification error: {e}")
            return False
    
    def uninstall_service(self):
        """Uninstall the enterprise service"""
        try:
            print("🗑️  UNINSTALLING ENTERPRISE ANTI-RANSOMWARE")
            print("=" * 50)
            
            if not self.is_admin:
                print("❌ Administrator privileges required for uninstallation")
                return False
            
            # Stop service
            print("🛑 Stopping service...")
            stop_cmd = f'net stop "{self.service_name}"'
            subprocess.run(stop_cmd, # shell=True removed for security
                        capture_output=True, capture_output=True)
            
            # Delete service
            print("🗑️  Removing service registration...")
            delete_cmd = f'sc delete "{self.service_name}"'
            result = subprocess.run(delete_cmd, # shell=True removed for security
                        capture_output=True, capture_output=True, text=True)
            
            # Remove firewall rule
            print("🔥 Removing firewall rules...")
            fw_cmd = 'netsh advfirewall firewall delete rule name="AntiRansomware HTTPS"'
            subprocess.run(fw_cmd, # shell=True removed for security
                        capture_output=True, capture_output=True)
            
            # Option to remove data directory
            response = input("Remove all data and logs? (y/N): ")
            if response.lower() == 'y':
                shutil.rmtree(self.data_dir, ignore_errors=True)
                shutil.rmtree(self.install_dir, ignore_errors=True)
                print("✅ All files removed")
            
            print("✅ Uninstallation completed")
            return True
            
        except Exception as e:
            print(f"Uninstallation error: {e}")
            return False

def main():
    """Main installer interface"""
    installer = EnterpriseInstaller()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'uninstall':
            installer.uninstall_service()
            return
        elif sys.argv[1] == 'status':
            # Check service status
            cmd = f'sc query "{installer.service_name}"'
            result = subprocess.run(cmd, # shell=True removed for security
                        capture_output=True, capture_output=True, text=True)
            print(result.stdout)
            return
    
    # Default: install
    success = installer.install_enterprise_system()
    
    if success:
        print("\n🎉 INSTALLATION SUCCESSFUL!")
        print("Next steps:")
        print("1. Open https://localhost:8443 (ignore certificate warning)")
        print("2. Configure protected folders through web interface")
        print("3. Monitor logs in C:/ProgramData/AntiRansomware/logs/")
        print("4. Check Windows Event Viewer for security events")
        
        print("\nService management commands:")
        print(f"• Start:   net start \"{installer.service_name}\"")
        print(f"• Stop:    net stop \"{installer.service_name}\"")
        print(f"• Status:  sc query \"{installer.service_name}\"")
        print(f"• Uninstall: python {__file__} uninstall")
    else:
        print("\n❌ INSTALLATION FAILED")
        print("Check error messages above and ensure you're running as Administrator")

if __name__ == '__main__':
    main()
