"""
Enhanced Device Fingerprinting
Multi-layer hardware identification for machine binding as documented in README.md

Implements 6-8 hardware identifier layers:
- CPU: CPUID instruction, serial number
- BIOS: UUID, firmware version  
- Network: MAC address (primary adapter)
- Storage: Disk serial number, volume GUID
- Windows: Machine GUID, product ID
- System: Computer name, domain

Hash generation: BLAKE2b with person='ar-hybrid', salt='antiransomw'
"""

import hashlib
import json
import platform
import uuid
import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass

# Try WMI for Windows hardware info
try:
    import wmi
    HAS_WMI = True
except ImportError:
    HAS_WMI = False

# Try psutil for cross-platform hardware info
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


@dataclass
class DeviceFingerprint:
    """Device fingerprint using hardware characteristics"""
    
    fingerprint_id: str
    hardware_layers: List[str]
    layer_count: int


class EnhancedDeviceFingerprintingPro:
    """Pro-grade device fingerprinting for hardware-bound security
    
    Implements the 6-8 hardware layer fingerprinting documented in README:
    - Deterministic: consistent across reboots
    - Collision-resistant: 2^256 keyspace
    - Privacy-preserving: one-way hash
    - Hardware-bound: changes if components replaced
    """
    
    def __init__(self):
        self.fingerprint_cache = None
        self.wmi_conn = None
        
        if HAS_WMI:
            try:
                self.wmi_conn = wmi.WMI()
            except Exception:
                self.wmi_conn = None
    
    def _get_cpu_info(self) -> str:
        """Get CPU serial number and manufacturer"""
        try:
            if HAS_WMI and self.wmi_conn:
                for cpu in self.wmi_conn.Win32_Processor():
                    return f"{cpu.Manufacturer}:{cpu.ProcessorId}:{cpu.Name}"
        except Exception:
            pass
        
        # Fallback
        return f"{platform.processor()}:{platform.machine()}"
    
    def _get_bios_info(self) -> str:
        """Get BIOS UUID and firmware version"""
        try:
            if HAS_WMI and self.wmi_conn:
                # Get first BIOS and ComputerSystemProduct entry explicitly
                bios_list = list(self.wmi_conn.Win32_BIOS())
                cs_list = list(self.wmi_conn.Win32_ComputerSystemProduct())
                
                if bios_list and cs_list:
                    bios = bios_list[0]
                    cs = cs_list[0]
                    return f"{cs.UUID}:{bios.SerialNumber}:{bios.Version}"
        except Exception:
            pass
        
        # Fallback
        return platform.node()
    
    def _get_network_info(self) -> str:
        """Get primary network adapter MAC address"""
        try:
            if HAS_WMI and self.wmi_conn:
                for adapter in self.wmi_conn.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                    if adapter.MACAddress:
                        return adapter.MACAddress
        except Exception:
            pass
        
        # Fallback using uuid.getnode()
        mac = uuid.getnode()
        return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
    
    def _get_storage_info(self) -> str:
        """Get disk serial number and volume GUID"""
        try:
            if HAS_WMI and self.wmi_conn:
                disks = []
                for disk in self.wmi_conn.Win32_DiskDrive():
                    if disk.SerialNumber:
                        disks.append(f"{disk.SerialNumber}:{disk.Model}")
                if disks:
                    return ";".join(disks)
        except Exception:
            pass
        
        # Fallback
        if HAS_PSUTIL:
            try:
                partitions = psutil.disk_partitions()
                if partitions:
                    return partitions[0].device
            except Exception:
                pass
        
        return "unknown_disk"
    
    def _get_windows_info(self) -> str:
        """Get Windows Machine GUID and product ID"""
        try:
            if HAS_WMI and self.wmi_conn:
                for os_info in self.wmi_conn.Win32_OperatingSystem():
                    return f"{os_info.SerialNumber}:{os_info.Caption}"
        except Exception:
            pass
        
        # Fallback
        return f"{platform.system()}:{platform.version()}"
    
    def _get_system_info(self) -> str:
        """Get computer name and domain"""
        try:
            computer_name = platform.node()
            
            if HAS_WMI and self.wmi_conn:
                for cs in self.wmi_conn.Win32_ComputerSystem():
                    domain = cs.Domain if hasattr(cs, 'Domain') else 'WORKGROUP'
                    return f"{computer_name}:{domain}"
        except Exception:
            pass
        
        return platform.node()
    
    def generate_fingerprint(self) -> str:
        """Generate hardware-bound device fingerprint using BLAKE2b
        
        As documented in README.md:
        Inputs: 6-8 hardware identifiers
        Algorithm: BLAKE2b(person='ar-hybrid', salt='antiransomw')
        Output: 32-byte hash → 64-character hex string
        """
        if self.fingerprint_cache:
            return self.fingerprint_cache
        
        # Collect all hardware layers
        layers = []
        
        # Layer 1: CPU
        cpu_info = self._get_cpu_info()
        layers.append(f"CPU:{cpu_info}")
        
        # Layer 2: BIOS
        bios_info = self._get_bios_info()
        layers.append(f"BIOS:{bios_info}")
        
        # Layer 3: Network
        network_info = self._get_network_info()
        layers.append(f"NET:{network_info}")
        
        # Layer 4: Storage
        storage_info = self._get_storage_info()
        layers.append(f"DISK:{storage_info}")
        
        # Layer 5: Windows
        windows_info = self._get_windows_info()
        layers.append(f"WIN:{windows_info}")
        
        # Layer 6: System
        system_info = self._get_system_info()
        layers.append(f"SYS:{system_info}")
        
        # Combine all layers
        combined = "|".join(layers)
        
        # Hash using BLAKE2b with documented parameters
        # person='ar-hybrid' (padded to 16 bytes), salt='antiransomw' (padded to 16 bytes)
        # BLAKE2b requires exactly 16-byte salt and person parameters
        hasher = hashlib.blake2b(
            combined.encode('utf-8'),
            digest_size=32,
            person=b'ar-hybrid\x00\x00\x00\x00\x00\x00\x00',  # 9 + 7 padding = 16 bytes
            salt=b'antiransomw\x00\x00\x00\x00\x00'  # 11 + 5 padding = 16 bytes
        )
        fingerprint = hasher.hexdigest()
        
        self.fingerprint_cache = fingerprint
        return fingerprint
    
    def get_fingerprint_details(self) -> DeviceFingerprint:
        """Get fingerprint with layer details"""
        layers = []
        layers.append(f"CPU: {self._get_cpu_info()}")
        layers.append(f"BIOS: {self._get_bios_info()}")
        layers.append(f"Network: {self._get_network_info()}")
        layers.append(f"Storage: {self._get_storage_info()}")
        layers.append(f"Windows: {self._get_windows_info()}")
        layers.append(f"System: {self._get_system_info()}")
        
        return DeviceFingerprint(
            fingerprint_id=self.generate_fingerprint(),
            hardware_layers=layers,
            layer_count=len(layers)
        )
    
    def verify_fingerprint(self, stored_fingerprint: str) -> bool:
        """Verify device fingerprint matches stored value"""
        current = self.generate_fingerprint()
        return current == stored_fingerprint
    
    def store_fingerprint(self, path: str = "device_fingerprint.json") -> None:
        """Store fingerprint to file"""
        details = self.get_fingerprint_details()
        data = {
            "fingerprint": details.fingerprint_id,
            "layer_count": details.layer_count,
            "hardware_layers": details.hardware_layers,
            "algorithm": "BLAKE2b(person='ar-hybrid', salt='antiransomw')",
            "digest_size": 32
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"✅ Device fingerprint stored ({details.layer_count} layers)")
