#!/usr/bin/env python3
"""
Kernel Protection Integration Module
Interfaces between user-mode anti-ransomware application and kernel driver
"""

import os
import sys
import ctypes
import ctypes.wintypes
import logging
import threading
import time
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass
from enum import Enum

# Import the kernel driver manager
try:
    from kernel_driver_manager import (
        KernelDriverManager, 
        IOCTL_ANTIRANSOMWARE_SET_PROTECTION, 
        IOCTL_ANTIRANSOMWARE_GET_STATUS,
        IOCTL_ANTIRANSOMWARE_ADD_EXCLUSION
    )
except ImportError:
    print("Error: kernel_driver_manager.py not found")
    sys.exit(1)

class ProtectionLevel(Enum):
    """Kernel protection levels"""
    DISABLED = 0
    MONITORING = 1
    ACTIVE_PROTECTION = 2
    MAXIMUM_PROTECTION = 3

@dataclass
class KernelStatus:
    """Kernel driver status information"""
    driver_loaded: bool = False
    protection_active: bool = False
    protection_level: ProtectionLevel = ProtectionLevel.DISABLED
    files_blocked: int = 0
    processes_monitored: int = 0
    threats_detected: int = 0

class KernelProtectionInterface:
    """Interface for kernel-level ransomware protection"""
    
    def __init__(self, event_callback: Optional[Callable] = None):
        self.driver_manager = KernelDriverManager()
        self.event_callback = event_callback
        self.logger = self._setup_logging()
        self.monitoring_thread = None
        self.monitoring_active = False
        self._status = KernelStatus()
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for kernel interface"""
        logger = logging.getLogger('KernelInterface')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def initialize(self) -> bool:
        """Initialize kernel protection system"""
        try:
            self.logger.info("Initializing kernel protection...")
            
            # Check admin privileges
            if not self.driver_manager.check_admin_privileges():
                self.logger.error("Administrator privileges required for kernel protection")
                return False
            
            # Check if driver is installed
            status = self.driver_manager.get_driver_status()
            
            if not status['installed']:
                self.logger.warning("Kernel driver not installed - installing now...")
                if not self._install_driver():
                    return False
            
            # Start driver if not running
            if not status['running']:
                self.logger.info("Starting kernel driver...")
                if not self.driver_manager.start_driver():
                    self.logger.error("Failed to start kernel driver")
                    return False
            
            # Establish communication
            if not self.driver_manager.open_device():
                self.logger.error("Failed to establish kernel communication")
                return False
            
            self._status.driver_loaded = True
            self.logger.info("✅ Kernel protection initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Kernel initialization failed: {e}")
            return False
    
    def _install_driver(self) -> bool:
        """Install the kernel driver"""
        try:
            # Create driver source
            source_dir = self.driver_manager.create_minifilter_driver()
            
            # Build driver
            driver_path = self.driver_manager.build_driver(source_dir)
            if not driver_path:
                return False
            
            # Enable test signing
            self.driver_manager.enable_test_signing()
            
            # Install driver
            return self.driver_manager.install_driver(driver_path)
            
        except Exception as e:
            self.logger.error(f"Driver installation failed: {e}")
            return False
    
    def enable_protection(self, level: ProtectionLevel = ProtectionLevel.ACTIVE_PROTECTION) -> bool:
        """Enable kernel-level protection"""
        try:
            if not self._status.driver_loaded:
                if not self.initialize():
                    return False
            
            # Send protection enable command to kernel
            protection_data = bytes([level.value])
            result = self.driver_manager.send_ioctl(IOCTL_ANTIRANSOMWARE_SET_PROTECTION, protection_data)
            
            if result is not None:
                self._status.protection_active = True
                self._status.protection_level = level
                
                # Start monitoring thread
                if not self.monitoring_active:
                    self.start_monitoring()
                
                self.logger.info(f"✅ Kernel protection enabled at level: {level.name}")
                
                if self.event_callback:
                    self.event_callback("protection_enabled", {"level": level})
                
                return True
            else:
                self.logger.error("Failed to enable kernel protection")
                return False
                
        except Exception as e:
            self.logger.error(f"Protection enable failed: {e}")
            return False
    
    def disable_protection(self) -> bool:
        """Disable kernel-level protection"""
        try:
            if not self._status.driver_loaded:
                return True  # Already disabled
            
            # Send protection disable command to kernel
            protection_data = bytes([ProtectionLevel.DISABLED.value])
            result = self.driver_manager.send_ioctl(IOCTL_ANTIRANSOMWARE_SET_PROTECTION, protection_data)
            
            if result is not None:
                self._status.protection_active = False
                self._status.protection_level = ProtectionLevel.DISABLED
                
                # Stop monitoring
                self.stop_monitoring()
                
                self.logger.info("Kernel protection disabled")
                
                if self.event_callback:
                    self.event_callback("protection_disabled", {})
                
                return True
            else:
                self.logger.error("Failed to disable kernel protection")
                return False
                
        except Exception as e:
            self.logger.error(f"Protection disable failed: {e}")
            return False
    
    def get_status(self) -> KernelStatus:
        """Get current kernel protection status"""
        try:
            if self._status.driver_loaded:
                # Query kernel for latest status
                result = self.driver_manager.send_ioctl(IOCTL_ANTIRANSOMWARE_GET_STATUS)
                
                if result and len(result) >= 12:  # Expected status structure size
                    # Parse status from kernel (simplified)
                    self._status.files_blocked = int.from_bytes(result[0:4], 'little')
                    self._status.processes_monitored = int.from_bytes(result[4:8], 'little')
                    self._status.threats_detected = int.from_bytes(result[8:12], 'little')
            
            return self._status
            
        except Exception as e:
            self.logger.error(f"Status query failed: {e}")
            return self._status
    
    def start_monitoring(self) -> bool:
        """Start background monitoring thread"""
        try:
            if self.monitoring_active:
                return True
            
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
            
            self.logger.info("Kernel monitoring started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        try:
            self.monitoring_active = False
            
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                self.monitoring_thread.join(timeout=5.0)
            
            self.logger.info("Kernel monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Failed to stop monitoring: {e}")
    
    def _monitoring_loop(self):
        """Background monitoring loop"""
        last_status = KernelStatus()
        
        while self.monitoring_active:
            try:
                current_status = self.get_status()
                
                # Check for status changes
                if current_status.files_blocked != last_status.files_blocked:
                    if self.event_callback:
                        self.event_callback("file_blocked", {
                            "count": current_status.files_blocked - last_status.files_blocked
                        })
                
                if current_status.threats_detected != last_status.threats_detected:
                    if self.event_callback:
                        self.event_callback("threat_detected", {
                            "count": current_status.threats_detected - last_status.threats_detected
                        })
                
                last_status = current_status
                time.sleep(1.0)  # Check every second
                
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                time.sleep(5.0)  # Wait longer on error
    
    def add_exclusion(self, path: str) -> bool:
        """Add path exclusion to kernel protection"""
        try:
            if not self._status.driver_loaded:
                return False
            
            # Convert path to bytes and send to kernel
            path_bytes = path.encode('utf-16le')
            result = self.driver_manager.send_ioctl(IOCTL_ANTIRANSOMWARE_ADD_EXCLUSION, path_bytes)
            
            if result is not None:
                self.logger.info(f"Added exclusion: {path}")
                return True
            else:
                self.logger.error(f"Failed to add exclusion: {path}")
                return False
                
        except Exception as e:
            self.logger.error(f"Add exclusion failed: {e}")
            return False
    
    def shutdown(self):
        """Shutdown kernel protection interface"""
        try:
            self.logger.info("Shutting down kernel protection...")
            
            # Stop monitoring
            self.stop_monitoring()
            
            # Close device handle
            if self.driver_manager.device_handle and self.driver_manager.device_handle != -1:
                ctypes.windll.kernel32.CloseHandle(self.driver_manager.device_handle)
                self.driver_manager.device_handle = None
            
            self.logger.info("Kernel protection shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Shutdown failed: {e}")
    
    def is_kernel_protection_available(self) -> bool:
        """Check if kernel protection is available"""
        try:
            # Check admin rights
            if not self.driver_manager.check_admin_privileges():
                return False
            
            # Check driver status
            status = self.driver_manager.get_driver_status()
            return status['installed'] or status['admin_rights']
            
        except Exception:
            return False
    
    def get_protection_info(self) -> Dict[str, Any]:
        """Get comprehensive protection information"""
        status = self.get_status()
        driver_status = self.driver_manager.get_driver_status()
        
        return {
            'kernel_available': self.is_kernel_protection_available(),
            'driver_loaded': status.driver_loaded,
            'protection_active': status.protection_active,
            'protection_level': status.protection_level.name,
            'admin_rights': driver_status['admin_rights'],
            'driver_installed': driver_status['installed'],
            'driver_running': driver_status['running'],
            'test_signing': driver_status['test_signing'],
            'stats': {
                'files_blocked': status.files_blocked,
                'processes_monitored': status.processes_monitored,
                'threats_detected': status.threats_detected
            }
        }

# Test functions for standalone usage
def test_kernel_protection():
    """Test kernel protection functionality"""
    print("🧪 TESTING KERNEL PROTECTION")
    print("=" * 40)
    
    def event_handler(event_type, data):
        print(f"📢 Kernel Event: {event_type} - {data}")
    
    kernel = KernelProtectionInterface(event_handler)
    
    # Test initialization
    print("Initializing kernel protection...")
    if kernel.initialize():
        print("✅ Initialization successful")
    else:
        print("❌ Initialization failed")
        return
    
    # Test enable protection
    print("Enabling protection...")
    if kernel.enable_protection(ProtectionLevel.ACTIVE_PROTECTION):
        print("✅ Protection enabled")
    else:
        print("❌ Protection enable failed")
        return
    
    # Show status
    status = kernel.get_status()
    print(f"Protection Status: {status}")
    
    # Test for a few seconds
    print("Testing for 10 seconds...")
    time.sleep(10)
    
    # Final status
    final_status = kernel.get_status()
    print(f"Final Status: {final_status}")
    
    # Shutdown
    kernel.shutdown()
    print("✅ Test completed")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_kernel_protection()
    else:
        print("Kernel Protection Interface Module")
        print("Usage: python kernel_protection_interface.py test")
