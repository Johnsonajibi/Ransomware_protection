"""
Anti-Ransomware Service Split
Separates GUI from service for better security isolation
"""
import sys
import os
import subprocess
import json
from pathlib import Path

class ServiceManager:
    def __init__(self):
        self.service_name = "AntiRansomwareService"
        self.service_path = Path(__file__).parent / "antiransomware_service.py"
        
    def install_service(self):
        """Install as Windows service"""
        try:
            # Create service script
            service_code = '''
import win32serviceutil
import win32service
import win32event
import servicemanager
import logging
from unified_antiransomware import UnifiedProtectionManager

class AntiRansomwareService(win32serviceutil.ServiceFramework):
    _svc_name_ = "AntiRansomwareService"
    _svc_display_name_ = "Anti-Ransomware Protection Service"
    _svc_description_ = "Enterprise anti-ransomware protection service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.protection_manager = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.protection_manager:
            self.protection_manager.stop_monitoring()
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()

    def main(self):
        self.protection_manager = UnifiedProtectionManager()
        self.protection_manager.start_monitoring()
        
        # Wait for stop signal
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(AntiRansomwareService)
'''
            
            with open(self.service_path, 'w') as f:
                f.write(service_code)
                
            print("✅ Service script created")
            print(f"📝 Install service with: python {self.service_path} install")
            print(f"▶️  Start service with: python {self.service_path} start")
            
        except Exception as e:
            print(f"❌ Service installation failed: {e}")

if __name__ == "__main__":
    manager = ServiceManager()
    manager.install_service()
