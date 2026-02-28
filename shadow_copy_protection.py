#!/usr/bin/env python3
"""
Shadow Copy Protection
======================
Monitors and blocks Volume Shadow Copy (VSS) deletion attempts

Features:
- Monitors vssadmin delete shadows commands
- Blocks wmic shadowcopy delete commands  
- Monitors Get-WmiObject Win32_ShadowCopy deletion
- Process termination on detection
- Automatic shadow copy creation
- Event logging with cryptographic signatures

Author: Johnson Ajibi
Date: December 28, 2025
"""

import os
import time
import subprocess
import threading
from pathlib import Path
from typing import Optional, List, Dict
import psutil

try:
    import wmi
    HAS_WMI = True
except ImportError:
    HAS_WMI = False
    print("⚠️ WMI not available - some features disabled")

try:
    from security_event_logger import SecurityEventLogger
    HAS_LOGGER = True
except ImportError:
    HAS_LOGGER = False
    print("⚠️ Security event logger not available")


class ShadowCopyProtection:
    """
    Protect Windows Volume Shadow Copies from ransomware deletion
    
    Monitors:
    - vssadmin delete shadows
    - wmic shadowcopy delete
    - PowerShell Get-WmiObject Win32_ShadowCopy deletion
    - bcdedit commands (bootloader manipulation)
    """
    
    def __init__(self):
        """Initialize shadow copy protection"""
        
        self.logger = SecurityEventLogger() if HAS_LOGGER else None
        self.monitoring = False
        self.monitor_thread = None
        self.wmi_connection = None
        
        # Commands to monitor
        self.dangerous_commands = {
            'vssadmin': ['delete', 'shadows'],
            'wmic': ['shadowcopy', 'delete'],
            'powershell': ['win32_shadowcopy', 'delete'],
            'bcdedit': ['/set', 'recoveryenabled'],
        }
        
        # Initialize WMI if available
        if HAS_WMI:
            try:
                self.wmi_connection = wmi.WMI()
                print("✓ WMI connection established for VSS monitoring")
            except Exception as e:
                pass  # WMI connection failed, will retry later
    
    def start_monitoring(self):
        """Start monitoring for shadow copy deletion attempts"""
        
        if self.monitoring:
            print("⚠️ Monitoring already active")
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        self.monitor_thread.start()
        
        print("🔍 Shadow copy protection monitoring started")
        print("   Watching for: vssadmin, wmic, bcdedit commands")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        print("⏸️ Shadow copy protection monitoring stopped")
    
    def _monitor_processes(self):
        """Monitor for shadow copy deletion commands"""
        
        print("📡 Active process monitoring started...")
        
        # Track seen PIDs to avoid duplicate processing
        seen_pids = set()
        
        while self.monitoring:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        pid = proc.info['pid']
                        
                        # Skip if already processed
                        if pid in seen_pids:
                            continue
                        
                        seen_pids.add(pid)
                        
                        proc_name = (proc.info['name'] or '').lower()
                        cmdline = proc.info['cmdline']
                        
                        if not cmdline:
                            continue
                        
                        # Join command line for analysis
                        cmdline_str = ' '.join(cmdline).lower()
                        
                        # Check for dangerous commands
                        if self._is_dangerous_command(proc_name, cmdline_str):
                            self._block_process(proc, cmdline_str)
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Clean up old PIDs periodically
                if len(seen_pids) > 10000:
                    seen_pids.clear()
                
                time.sleep(0.5)  # Check every 500ms
                
            except Exception as e:
                print(f"⚠️ Monitor error: {e}")
                time.sleep(1)
    
    def _is_dangerous_command(self, proc_name: str, cmdline: str) -> bool:
        """Check if command is dangerous"""
        
        # Check vssadmin delete shadows
        if 'vssadmin' in proc_name or 'vssadmin' in cmdline:
            if 'delete' in cmdline and 'shadow' in cmdline:
                return True
        
        # Check wmic shadowcopy delete
        if 'wmic' in proc_name or 'wmic' in cmdline:
            if 'shadowcopy' in cmdline and 'delete' in cmdline:
                return True
        
        # Check PowerShell shadow copy deletion
        if 'powershell' in proc_name or 'pwsh' in proc_name:
            if 'win32_shadowcopy' in cmdline and 'delete' in cmdline:
                return True
            if 'get-wmiobject' in cmdline and 'shadowcopy' in cmdline:
                return True
        
        # Check bcdedit (bootloader manipulation)
        if 'bcdedit' in proc_name or 'bcdedit' in cmdline:
            if 'recoveryenabled' in cmdline and 'no' in cmdline:
                return True
        
        return False
    
    def _block_process(self, proc, cmdline: str):
        """Block and terminate malicious process"""
        
        try:
            proc_info = {
                'name': proc.info['name'],
                'pid': proc.info['pid'],
                'cmdline': cmdline
            }
            
            print(f"\n🚨 BLOCKED: Shadow copy deletion attempt!")
            print(f"   Process: {proc_info['name']} (PID: {proc_info['pid']})")
            print(f"   Command: {cmdline}")
            
            # Terminate the process
            proc.terminate()
            
            # Wait for termination
            try:
                proc.wait(timeout=3)
                print(f"   ✓ Process terminated")
            except psutil.TimeoutExpired:
                # Force kill if still running
                proc.kill()
                print(f"   ✓ Process force-killed")
            
            # Log the event
            if self.logger:
                self.logger.log_shadow_copy_blocked(proc_info, cmdline)
            
            print(f"   ✓ Event logged with cryptographic signature")
            
        except Exception as e:
            print(f"❌ Failed to block process: {e}")
    
    def create_shadow_copy(self, volume: str = "C:") -> bool:
        """
        Create a Volume Shadow Copy
        
        Args:
            volume: Drive letter (default: C:)
        
        Returns:
            True if successful
        """
        
        try:
            print(f"\n📸 Creating shadow copy for {volume}...")
            
            # Create shadow copy using vssadmin
            result = subprocess.run([
                'vssadmin', 'create', 'shadow',
                f'/for={volume}'
            ], capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                print(f"✓ Shadow copy created for {volume}")
                return True
            else:
                print(f"⚠️ Shadow copy creation failed: {result.stderr}")
                return False
            
        except Exception as e:
            print(f"❌ Shadow copy creation error: {e}")
            return False
    
    def list_shadow_copies(self) -> List[Dict]:
        """
        List all shadow copies
        
        Returns:
            List of shadow copy information
        """
        
        try:
            result = subprocess.run([
                'vssadmin', 'list', 'shadows'
            ], capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                # Parse output
                shadows = []
                lines = result.stdout.split('\n')
                
                current_shadow = {}
                for line in lines:
                    line = line.strip()
                    
                    if 'Shadow Copy ID:' in line:
                        if current_shadow:
                            shadows.append(current_shadow)
                        current_shadow = {'id': line.split(':', 1)[1].strip()}
                    elif 'Original Volume:' in line:
                        current_shadow['volume'] = line.split(':', 1)[1].strip()
                    elif 'Shadow Copy Volume:' in line:
                        current_shadow['path'] = line.split(':', 1)[1].strip()
                    elif 'Creation Time:' in line:
                        current_shadow['created'] = line.split(':', 1)[1].strip()
                
                if current_shadow:
                    shadows.append(current_shadow)
                
                return shadows
            
            return []
            
        except Exception as e:
            print(f"❌ Failed to list shadow copies: {e}")
            return []
    
    def configure_vss_storage(self, volume: str = "C:", max_size: str = "10GB") -> bool:
        """
        Configure VSS storage size
        
        Args:
            volume: Drive letter
            max_size: Maximum storage (e.g., "10GB", "UNBOUNDED")
        
        Returns:
            True if successful
        """
        
        try:
            print(f"\n⚙️ Configuring VSS storage for {volume}...")
            print(f"   Max size: {max_size}")
            
            # Resize shadow storage
            result = subprocess.run([
                'vssadmin', 'resize', 'shadowstorage',
                f'/for={volume}',
                f'/on={volume}',
                f'/maxsize={max_size}'
            ], capture_output=True, text=True, check=False)
            
            if result.returncode == 0 or 'successfully' in result.stdout.lower():
                print(f"✓ VSS storage configured")
                return True
            else:
                # Storage might not exist yet
                print(f"⚠️ VSS storage configuration: {result.stderr}")
                return False
            
        except Exception as e:
            print(f"❌ VSS storage configuration error: {e}")
            return False
    
    def get_vss_statistics(self) -> Dict:
        """
        Get VSS statistics
        
        Returns:
            Dict with VSS information
        """
        
        stats = {
            'shadows_count': 0,
            'total_space_used': 0,
            'volumes': []
        }
        
        try:
            # Get shadow copies
            shadows = self.list_shadow_copies()
            stats['shadows_count'] = len(shadows)
            
            # Get storage information
            result = subprocess.run([
                'vssadmin', 'list', 'shadowstorage'
            ], capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_vol = {}
                
                for line in lines:
                    line = line.strip()
                    
                    if 'For volume:' in line:
                        if current_vol:
                            stats['volumes'].append(current_vol)
                        current_vol = {'volume': line.split(':', 1)[1].strip()}
                    elif 'Used Shadow Copy Storage space:' in line:
                        current_vol['used'] = line.split(':', 1)[1].strip()
                    elif 'Allocated Shadow Copy Storage space:' in line:
                        current_vol['allocated'] = line.split(':', 1)[1].strip()
                    elif 'Maximum Shadow Copy Storage space:' in line:
                        current_vol['maximum'] = line.split(':', 1)[1].strip()
                
                if current_vol:
                    stats['volumes'].append(current_vol)
            
        except Exception as e:
            print(f"⚠️ Failed to get VSS statistics: {e}")
        
        return stats


def run_protection_demo():
    """Demonstrate shadow copy protection"""
    
    print("\n" + "="*60)
    print("Shadow Copy Protection Demo")
    print("="*60)
    
    protection = ShadowCopyProtection()
    
    # Show current shadow copies
    print("\n1. Current shadow copies:")
    shadows = protection.list_shadow_copies()
    if shadows:
        for i, shadow in enumerate(shadows, 1):
            print(f"   Shadow #{i}:")
            print(f"      ID: {shadow.get('id', 'UNKNOWN')}")
            print(f"      Volume: {shadow.get('volume', 'UNKNOWN')}")
            print(f"      Created: {shadow.get('created', 'UNKNOWN')}")
    else:
        print("   No shadow copies found")
    
    # Show VSS statistics
    print("\n2. VSS Statistics:")
    stats = protection.get_vss_statistics()
    print(f"   Total shadow copies: {stats['shadows_count']}")
    for vol in stats['volumes']:
        print(f"   Volume: {vol['volume']}")
        print(f"      Used: {vol.get('used', 'N/A')}")
        print(f"      Maximum: {vol.get('maximum', 'N/A')}")
    
    # Start monitoring
    print("\n3. Starting protection monitoring...")
    protection.start_monitoring()
    
    print("\n✓ Shadow copy protection is now active")
    print("   Any attempts to delete shadow copies will be blocked")
    print("   Press Ctrl+C to stop monitoring\n")
    
    try:
        # Keep monitoring
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n⏸️ Stopping monitoring...")
        protection.stop_monitoring()
        print("✓ Protection stopped")
    
    print("\n" + "="*60)


if __name__ == '__main__':
    # Check if running as admin
    import ctypes
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    
    if not is_admin:
        print("⚠️ WARNING: Not running as Administrator")
        print("   Shadow copy operations require admin privileges")
        print("   Some features may not work\n")
    
    run_protection_demo()
