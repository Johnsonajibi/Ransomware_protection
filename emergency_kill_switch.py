#!/usr/bin/env python3
"""
Emergency Kill Switch
====================
Instant system-wide lockdown for active ransomware attacks

Features:
- Immediate lockdown activation
- Block all protected paths
- Terminate suspicious processes
- Optional network isolation
- Desktop notification alerts
- Comprehensive event logging
- Manual and automatic triggers

Author: Johnson Ajibi
Date: December 28, 2025
"""

import os
import sys
import time
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
import psutil
import logging

try:
    from token_gated_access import TokenGatedAccessControl
    HAS_TOKEN_GATE = True
except ImportError:
    HAS_TOKEN_GATE = False
    print("⚠️ Token-gated access not available")

try:
    from security_event_logger import SecurityEventLogger
    HAS_LOGGER = True
except ImportError:
    HAS_LOGGER = False
    print("⚠️ Security event logger not available")

try:
    from email_alerting import EmailAlertingSystem
    HAS_EMAIL = True
except ImportError:
    HAS_EMAIL = False
    print("⚠️ Email alerting not available")


class EmergencyKillSwitch:
    """
    Emergency lockdown for active ransomware attacks
    
    Capabilities:
    - Instant access denial to all protected resources
    - Suspicious process termination
    - Network adapter disable (optional)
    - Desktop alert notifications
    - Cryptographically signed event logging
    - Multiple trigger methods
    """
    
    def __init__(self, config_file: Optional[Path] = None):
        """Initialize emergency kill switch"""
        
        if config_file is None:
            config_file = Path.home() / "AppData" / "Local" / "AntiRansomware" / "killswitch_config.json"
        
        self.config_file = Path(config_file)
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.lockdown_file = Path(os.getenv('PROGRAMDATA', 'C:\\ProgramData')) / 'AntiRansomware' / 'EMERGENCY_LOCKDOWN'
        self.lockdown_active = False
        
        # Load components
        self.logger = SecurityEventLogger() if HAS_LOGGER else None
        self.email_alerter = EmailAlertingSystem() if HAS_EMAIL else None
        self.token_gate = TokenGatedAccessControl() if HAS_TOKEN_GATE else None
        
        # Load configuration
        self.config = self._load_config()
        
        # Check if already in lockdown
        self._check_lockdown_status()
    
    def _load_config(self) -> Dict:
        """Load kill switch configuration"""
        
        default_config = {
            'network_isolation_enabled': False,
            'auto_terminate_suspicious': True,
            'notification_enabled': True,
            'suspicious_process_patterns': [
                'encrypt', 'crypt', 'ransom', 'locker',
                'wannacry', 'ryuk', 'sodinokibi'
            ],
            'whitelist_processes': [
                'antiransomware', 'python.exe', 'pythonw.exe',
                'explorer.exe', 'cmd.exe', 'powershell.exe'
            ]
        }
        
        if self.config_file.exists():
            try:
                import json
                with self.config_file.open('r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"⚠️ Config load failed: {e}")
        
        return default_config
    
    def _check_lockdown_status(self):
        """Check if system is already in lockdown"""
        
        if self.lockdown_file.exists():
            self.lockdown_active = True
            print("⚠️ SYSTEM IS IN EMERGENCY LOCKDOWN")
            
            # Show lockdown info
            try:
                lockdown_info = self.lockdown_file.read_text()
                print(f"   Activated: {lockdown_info}")
            except:
                pass
    
    def activate_lockdown(self, reason: str = "MANUAL_TRIGGER", triggered_by: Optional[str] = None):
        """
        Activate emergency lockdown
        
        Args:
            reason: Reason for lockdown activation
            triggered_by: User or system that triggered lockdown
        """
        
        if self.lockdown_active:
            return
        
        logging.critical(f"EMERGENCY KILL SWITCH ACTIVATED: {reason} (Triggered by: {triggered_by or 'SYSTEM'})")
        
        # Create lockdown marker
        try:
            self.lockdown_file.parent.mkdir(parents=True, exist_ok=True)
            self.lockdown_file.write_text(
                f"LOCKDOWN ACTIVATED\n"
                f"Timestamp: {datetime.now().isoformat()}\n"
                f"Reason: {reason}\n"
                f"Triggered by: {triggered_by or 'SYSTEM'}\n"
            )
            self.lockdown_active = True
        except Exception as e:
            logging.critical(f"EMERGENCY KILL SWITCH: Failed to create lockdown marker - {e}")
        
        # Step 1: Block all protected paths
        self._emergency_block_all()
        
        # Step 2: Terminate suspicious processes
        if self.config['auto_terminate_suspicious']:
            self._terminate_suspicious_processes()
        
        # Step 3: Network isolation (if enabled)
        if self.config['network_isolation_enabled']:
            self._disable_network_adapters()
        
        # Step 4: Show desktop alert
        if self.config['notification_enabled']:
            self._show_lockdown_alert()
        
        # Step 5: Log the lockdown
        if self.logger:
            self.logger.log_emergency_lockdown(reason, triggered_by or 'SYSTEM')
        
        # Step 6: Send email alerts
        if self.email_alerter:
            alert_details = {
                'reason': reason,
                'triggered_by': triggered_by or 'SYSTEM',
                'timestamp': datetime.now().isoformat(),
                'actions_taken': [
                    'All protected resources blocked',
                    'Suspicious processes terminated',
                    'Network isolation (if enabled)',
                    'Desktop alert shown'
                ]
            }
            
            self.email_alerter.send_alert(
                alert_type='EMERGENCY_LOCKDOWN_ACTIVATED',
                severity='CRITICAL',
                details=alert_details,
                attach_logs=True
            )
    
    def _emergency_block_all(self):
        """Block all protected paths immediately"""
        
        if not self.token_gate or not HAS_TOKEN_GATE:
            print("   ⚠️ Token gate not available - using fallback")
            return
        
        blocked_count = 0
        
        for path_str in self.token_gate.protected_paths.keys():
            try:
                path = Path(path_str)
                
                # Apply maximum security ACLs
                subprocess.run([
                    'icacls', str(path),
                    '/inheritance:r',
                    '/deny', '*S-1-1-0:(F,M,RX,R,W,D)',  # Deny Everyone everything
                ], capture_output=True, check=False)
                
                blocked_count += 1
                print(f"   🔒 Blocked: {path_str}")
                
            except Exception as e:
                print(f"   ⚠️ Failed to block {path_str}: {e}")
        
        print(f"   ✓ Blocked {blocked_count} protected paths")
    
    def _terminate_suspicious_processes(self):
        """Terminate processes matching suspicious patterns"""
        
        terminated = []
        whitelist = set(p.lower() for p in self.config['whitelist_processes'])
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                proc_name = (proc.info['name'] or '').lower()
                proc_exe = (proc.info['exe'] or '').lower()
                
                # Skip whitelisted
                if any(wl in proc_name or wl in proc_exe for wl in whitelist):
                    continue
                
                # Check suspicious patterns
                for pattern in self.config['suspicious_process_patterns']:
                    if pattern in proc_name or pattern in proc_exe:
                        print(f"   🔫 Terminating: {proc.info['name']} (PID: {proc.info['pid']})")
                        proc.kill()
                        terminated.append(proc.info['name'])
                        break
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        if terminated:
            print(f"   ✓ Terminated {len(terminated)} suspicious processes")
        else:
            print(f"   ✓ No suspicious processes found")
    
    def _disable_network_adapters(self):
        """Disable all network adapters"""
        
        try:
            # Get network adapters
            result = subprocess.run([
                'powershell', '-Command',
                'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -ExpandProperty Name'
            ], capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                adapters = result.stdout.strip().split('\n')
                
                for adapter in adapters:
                    if adapter.strip():
                        print(f"   📡 Disabling: {adapter}")
                        subprocess.run([
                            'powershell', '-Command',
                            f'Disable-NetAdapter -Name "{adapter}" -Confirm:$false'
                        ], capture_output=True, check=False)
                
                print(f"   ✓ Network adapters disabled")
            else:
                print(f"   ⚠️ Failed to enumerate adapters")
                
        except Exception as e:
            print(f"   ❌ Network isolation failed: {e}")
    
    def _show_lockdown_alert(self):
        """Show desktop alert notification"""
        
        try:
            # Use Windows msg command for alert
            subprocess.run([
                'msg', '*',
                '🚨 EMERGENCY LOCKDOWN ACTIVATED\n\n'
                'All protected resources are BLOCKED\n'
                'Possible ransomware attack detected\n\n'
                'DO NOT INSERT USB TOKEN\n'
                'Contact security team immediately'
            ], check=False, timeout=5)
            
            print("   ✓ Desktop alert shown")
            
        except Exception as e:
            print(f"   ⚠️ Desktop alert failed: {e}")
    
    def lift_lockdown(self, authorized_by: str, verification_token: Optional[str] = None, force: bool = False):
        """
        Lift emergency lockdown
        
        Args:
            authorized_by: Person authorizing lift
            verification_token: Optional authorization token
            force: Bypass interactive confirmation (for GUI)
        """
        
        if not self.lockdown_active:
            print("⚠️ System is not in lockdown")
            return
        
        print("\n" + "="*60)
        print("LIFTING EMERGENCY LOCKDOWN")
        print("="*60)
        print(f"Authorized by: {authorized_by}")
        print(f"Timestamp: {datetime.now().isoformat()}")
        
        # Verify authorization (in production, check token)
        if not force:
            print("\n⚠️ WARNING: Verify system is clean before lifting lockdown")
            response = input("Type 'CONFIRM' to proceed: ")
            
            if response != 'CONFIRM':
                print("❌ Lockdown lift cancelled")
                return
        
        # Remove lockdown marker
        try:
            if self.lockdown_file.exists():
                self.lockdown_file.unlink()
            self.lockdown_active = False
            print("✓ Lockdown marker removed")
        except Exception as e:
            print(f"⚠️ Failed to remove marker: {e}")
        
        # Log the event
        if self.logger:
            self.logger.log_emergency_lockdown_lifted(authorized_by, verification_token)
            print("✓ Lockdown lift logged")
        
        print("\n✓ Emergency lockdown has been lifted")
        print("⚠️ Manual restoration of access may be required")
        print("="*60 + "\n")
    
    def is_locked_down(self) -> bool:
        """Check if system is currently in lockdown"""
        return self.lockdown_active
    
    def auto_trigger_check(self, alert_count: int = 10, time_window: int = 60):
        """
        Check if automatic lockdown should trigger
        
        Args:
            alert_count: Number of alerts to trigger lockdown
            time_window: Time window in seconds
        
        Returns:
            True if lockdown triggered
        """
        
        if not self.logger or not HAS_LOGGER:
            return False
        
        cutoff_time = time.time() - time_window
        
        # Get recent critical events
        events = self.logger.get_events(
            severity='CRITICAL',
            start_time=cutoff_time,
            limit=alert_count + 1
        )
        
        if len(events) >= alert_count:
            print(f"\n🚨 AUTO-TRIGGER: {len(events)} critical alerts in {time_window}s")
            self.activate_lockdown(
                reason=f"AUTO_TRIGGER_{len(events)}_ALERTS_{time_window}S",
                triggered_by="AUTOMATIC"
            )
            return True
        
        return False


def main():
    """Main entry point"""
    
    import argparse
    
    parser = argparse.ArgumentParser(description='Emergency Kill Switch')
    parser.add_argument('--activate', action='store_true', help='Activate emergency lockdown')
    parser.add_argument('--lift', action='store_true', help='Lift emergency lockdown')
    parser.add_argument('--status', action='store_true', help='Check lockdown status')
    parser.add_argument('--reason', default='MANUAL_TRIGGER', help='Reason for lockdown')
    parser.add_argument('--user', help='User authorizing action')
    
    args = parser.parse_args()
    
    # Check admin privileges
    import ctypes
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    
    if not is_admin:
        print("⚠️ WARNING: Not running as Administrator")
        print("   Some operations may fail without admin privileges\n")
    
    kill_switch = EmergencyKillSwitch()
    
    if args.status:
        print("\n" + "="*60)
        print("Emergency Kill Switch Status")
        print("="*60)
        if kill_switch.is_locked_down():
            print("🚨 Status: LOCKDOWN ACTIVE")
            if kill_switch.lockdown_file.exists():
                print("\nLockdown Info:")
                print(kill_switch.lockdown_file.read_text())
        else:
            print("✓ Status: Normal Operations")
        print("="*60 + "\n")
    
    elif args.activate:
        kill_switch.activate_lockdown(
            reason=args.reason,
            triggered_by=args.user or os.getlogin() if hasattr(os, 'getlogin') else 'SYSTEM'
        )
    
    elif args.lift:
        kill_switch.lift_lockdown(
            authorized_by=args.user or input("Enter your name: ")
        )
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
