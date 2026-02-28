#!/usr/bin/env python3
"""
Kernel Driver Communication Interface
Provides user-mode to kernel-mode communication for token validation
"""

import ctypes
import ctypes.wintypes
from ctypes import windll
import struct
import os
import hashlib
import json

# Import our driver common definitions
class ProtectedPathRequest(ctypes.Structure):
    _fields_ = [
        ("Path", ctypes.c_wchar * 260),
        ("PathLength", ctypes.c_ulong)
    ]

class TokenValidationRequest(ctypes.Structure):
    _fields_ = [
        ("TokenData", ctypes.c_ubyte * 1024),
        ("TokenLength", ctypes.c_ulong),
        ("ProcessId", ctypes.c_ulong),
        ("RequestedAccess", ctypes.c_ulong)
    ]

class DriverStatistics(ctypes.Structure):
    _fields_ = [
        ("TotalRequests", ctypes.c_ulong),
        ("BlockedRequests", ctypes.c_ulong),
        ("AllowedRequests", ctypes.c_ulong),
        ("InvalidTokens", ctypes.c_ulong),
        ("ProtectedPaths", ctypes.c_ulong)
    ]

class KernelDriverInterface:
    def __init__(self):
        self.device_name = "\\\\.\\AntiRansomwareDriver"
        self.device_handle = None
        
        # IOCTL codes (matching driver_common.h)
        self.IOCTL_ADD_PROTECTED_PATH = self._ctl_code(0x800)
        self.IOCTL_REMOVE_PROTECTED_PATH = self._ctl_code(0x801)
        self.IOCTL_VALIDATE_TOKEN = self._ctl_code(0x802)
        self.IOCTL_GET_STATISTICS = self._ctl_code(0x803)
    
    def _ctl_code(self, function):
        """Generate IOCTL control code"""
        FILE_DEVICE_UNKNOWN = 0x00000022
        METHOD_BUFFERED = 0
        FILE_ANY_ACCESS = 0
        return (FILE_DEVICE_UNKNOWN << 16) | (FILE_ANY_ACCESS << 14) | (function << 2) | METHOD_BUFFERED
    
    def connect(self):
        """Connect to the kernel driver"""
        try:
            self.device_handle = windll.kernel32.CreateFileW(
                self.device_name,
                0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
                0,  # No sharing
                None,  # Default security
                3,  # OPEN_EXISTING
                0,  # No flags
                None  # No template
            )
            
            if self.device_handle == -1:  # INVALID_HANDLE_VALUE
                self.device_handle = None
                return False
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to connect to kernel driver: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the kernel driver"""
        if self.device_handle:
            windll.kernel32.CloseHandle(self.device_handle)
            self.device_handle = None
    
    def add_protected_path(self, path):
        """Add a path to kernel-level protection"""
        if not self.device_handle:
            return False
        
        try:
            request = ProtectedPathRequest()
            request.Path = path
            request.PathLength = len(path)
            
            bytes_returned = ctypes.c_ulong()
            
            success = windll.kernel32.DeviceIoControl(
                self.device_handle,
                self.IOCTL_ADD_PROTECTED_PATH,
                ctypes.byref(request),
                ctypes.sizeof(request),
                None,
                0,
                ctypes.byref(bytes_returned),
                None
            )
            
            return bool(success)
            
        except Exception as e:
            print(f"❌ Failed to add protected path: {e}")
            return False
    
    def remove_protected_path(self, path):
        """Remove a path from kernel-level protection"""
        if not self.device_handle:
            return False
        
        try:
            request = ProtectedPathRequest()
            request.Path = path
            request.PathLength = len(path)
            
            bytes_returned = ctypes.c_ulong()
            
            success = windll.kernel32.DeviceIoControl(
                self.device_handle,
                self.IOCTL_REMOVE_PROTECTED_PATH,
                ctypes.byref(request),
                ctypes.sizeof(request),
                None,
                0,
                ctypes.byref(bytes_returned),
                None
            )
            
            return bool(success)
            
        except Exception as e:
            print(f"❌ Failed to remove protected path: {e}")
            return False
    
    def validate_token(self, token_data, process_id, requested_access):
        """Validate a token at kernel level"""
        if not self.device_handle:
            return False
        
        try:
            request = TokenValidationRequest()
            
            # Convert token data to bytes if it's a string
            if isinstance(token_data, str):
                token_bytes = token_data.encode('utf-8')
            elif isinstance(token_data, dict):
                token_bytes = json.dumps(token_data).encode('utf-8')
            else:
                token_bytes = token_data
            
            # Copy token data (max 1024 bytes)
            token_length = min(len(token_bytes), 1024)
            ctypes.memmove(request.TokenData, token_bytes, token_length)
            request.TokenLength = token_length
            request.ProcessId = process_id
            request.RequestedAccess = requested_access
            
            bytes_returned = ctypes.c_ulong()
            result = ctypes.c_bool()
            
            success = windll.kernel32.DeviceIoControl(
                self.device_handle,
                self.IOCTL_VALIDATE_TOKEN,
                ctypes.byref(request),
                ctypes.sizeof(request),
                ctypes.byref(result),
                ctypes.sizeof(result),
                ctypes.byref(bytes_returned),
                None
            )
            
            return bool(success) and bool(result.value)
            
        except Exception as e:
            print(f"❌ Failed to validate token: {e}")
            return False
    
    def get_statistics(self):
        """Get kernel driver statistics"""
        if not self.device_handle:
            return None
        
        try:
            stats = DriverStatistics()
            bytes_returned = ctypes.c_ulong()
            
            success = windll.kernel32.DeviceIoControl(
                self.device_handle,
                self.IOCTL_GET_STATISTICS,
                None,
                0,
                ctypes.byref(stats),
                ctypes.sizeof(stats),
                ctypes.byref(bytes_returned),
                None
            )
            
            if success:
                return {
                    'total_requests': stats.TotalRequests,
                    'blocked_requests': stats.BlockedRequests,
                    'allowed_requests': stats.AllowedRequests,
                    'invalid_tokens': stats.InvalidTokens,
                    'protected_paths': stats.ProtectedPaths
                }
            
            return None
            
        except Exception as e:
            print(f"❌ Failed to get statistics: {e}")
            return None

class KernelProtectionManager:
    """High-level interface for kernel protection management"""
    
    def __init__(self):
        self.driver_interface = KernelDriverInterface()
        self.is_connected = False
    
    def initialize(self):
        """Initialize kernel protection"""
        print("🔌 Connecting to kernel driver...")
        
        if not self.driver_interface.connect():
            print("❌ Failed to connect to kernel driver")
            print("💡 Make sure the driver is installed and running:")
            print("   python kernel_driver_manager.py install")
            print("   python kernel_driver_manager.py start")
            return False
        
        self.is_connected = True
        print("✅ Connected to kernel driver successfully")
        return True
    
    def shutdown(self):
        """Shutdown kernel protection"""
        if self.is_connected:
            self.driver_interface.disconnect()
            self.is_connected = False
            print("🔌 Disconnected from kernel driver")
    
    def protect_path(self, path):
        """Add kernel-level protection to a path"""
        if not self.is_connected:
            return False
        
        print(f"🛡️ Adding kernel protection to: {path}")
        success = self.driver_interface.add_protected_path(path)
        
        if success:
            print(f"✅ Kernel protection enabled for: {path}")
        else:
            print(f"❌ Failed to enable kernel protection for: {path}")
        
        return success
    
    def unprotect_path(self, path):
        """Remove kernel-level protection from a path"""
        if not self.is_connected:
            return False
        
        print(f"🔓 Removing kernel protection from: {path}")
        success = self.driver_interface.remove_protected_path(path)
        
        if success:
            print(f"✅ Kernel protection removed from: {path}")
        else:
            print(f"❌ Failed to remove kernel protection from: {path}")
        
        return success
    
    def validate_access_token(self, token_data, process_id, access_type):
        """Validate token at kernel level"""
        if not self.is_connected:
            return False
        
        # Convert access type to flags
        access_flags = 0
        if 'read' in access_type.lower():
            access_flags |= 0x01  # OP_READ
        if 'write' in access_type.lower():
            access_flags |= 0x02  # OP_WRITE
        if 'delete' in access_type.lower():
            access_flags |= 0x04  # OP_DELETE
        if 'rename' in access_type.lower():
            access_flags |= 0x08  # OP_RENAME
        
        return self.driver_interface.validate_token(token_data, process_id, access_flags)
    
    def get_protection_statistics(self):
        """Get kernel protection statistics"""
        if not self.is_connected:
            return None
        
        return self.driver_interface.get_statistics()
    
    def print_status(self):
        """Print kernel protection status"""
        if not self.is_connected:
            print("❌ Kernel protection: NOT CONNECTED")
            return
        
        stats = self.get_protection_statistics()
        if stats:
            print("🛡️ KERNEL PROTECTION STATUS")
            print("=" * 40)
            print(f"📊 Total Requests: {stats['total_requests']}")
            print(f"🚫 Blocked Requests: {stats['blocked_requests']}")
            print(f"✅ Allowed Requests: {stats['allowed_requests']}")
            print(f"🔐 Invalid Tokens: {stats['invalid_tokens']}")
            print(f"📁 Protected Paths: {stats['protected_paths']}")
            
            if stats['total_requests'] > 0:
                block_rate = (stats['blocked_requests'] / stats['total_requests']) * 100
                print(f"🎯 Block Rate: {block_rate:.1f}%")
        else:
            print("❌ Could not retrieve kernel statistics")

def main():
    """Test the kernel driver interface"""
    print("🧪 KERNEL DRIVER INTERFACE TEST")
    print("=" * 40)
    
    manager = KernelProtectionManager()
    
    if not manager.initialize():
        return 1
    
    try:
        # Test adding protected paths
        test_paths = [
            "C:\\Protected\\Documents",
            "C:\\Protected\\Photos",
            "C:\\Protected\\Important"
        ]
        
        for path in test_paths:
            manager.protect_path(path)
        
        # Show statistics
        manager.print_status()
        
        # Test token validation
        print("\n🔍 Testing token validation...")
        test_token = {"hardware_fingerprint": "test123", "process_id": 1234}
        result = manager.validate_access_token(test_token, 1234, "write")
        print(f"Token validation result: {'✅ VALID' if result else '❌ INVALID'}")
        
    finally:
        manager.shutdown()
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
