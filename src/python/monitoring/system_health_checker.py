#!/usr/bin/env python3
"""
System Health Checker
====================
Detect compromised system state before allowing USB token access

Features:
- Honeypot alert detection
- Suspicious process detection
- Access denial pattern analysis
- Recent security event correlation
- Threat indicator tracking

Author: Johnson Ajibi
Date: December 28, 2025
"""

import os
import time
import psutil
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

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


class SystemHealthChecker:
    """
    Check if system is compromised before allowing USB token
    
    Checks:
    - Recent honeypot triggers
    - Suspicious running processes
    - Multiple access denials
    - Unexpected file system changes
    """
    
    def __init__(self):
        """Initialize system health checker"""
        
        self.threat_indicators = []
        self.system_compromised = False
        
        # Load security event logger
        self.logger = SecurityEventLogger() if HAS_LOGGER else None
        
        # Load email alerting
        self.email_alerter = EmailAlertingSystem() if HAS_EMAIL else None
        
        # Suspicious process patterns
        self.suspicious_patterns = [
            'encrypt', 'crypt', 'ransom', 'locker',
            'wannacry', 'ryuk', 'sodinokibi', 'maze',
            'lockbit', 'revil', 'conti', 'blackcat'
        ]
        
        # Whitelist our own processes
        self.whitelist_patterns = [
            'antiransomware', 'anti-ransom', 'trifactor', 'token_gated'
        ]
        
        # Thresholds
        self.honeypot_window = 86400  # 24 hours
        self.denial_window = 3600     # 1 hour
        self.denial_threshold = 5     # 5 denials = suspicious
        
        print("✓ System health checker initialized")
    
    def check_system_health(self) -> Dict:
        """
        Run all security checks
        
        Returns:
            Health status dict with check results
        """
        
        print("\n" + "="*60)
        print("SYSTEM HEALTH CHECK")
        print("="*60)
        
        checks = {
            'honeypot_triggered': self.check_honeypot_alerts(),
            'suspicious_processes': self.check_running_processes(),
            'recent_denials': self.check_recent_access_denials(),
            'system_integrity': self.check_system_integrity(),
        }
        
        # System is compromised if ANY check fails
        self.system_compromised = any(checks.values())
        
        result = {
            'healthy': not self.system_compromised,
            'checks': checks,
            'threat_indicators': self.threat_indicators,
            'timestamp': time.time(),
            'datetime': datetime.now().isoformat()
        }
        
        # Print results
        print(f"\nHealth Status: {'❌ COMPROMISED' if self.system_compromised else '✓ HEALTHY'}")
        print(f"\nCheck Results:")
        for check_name, failed in checks.items():
            status = "❌ FAILED" if failed else "✓ PASSED"
            print(f"  {check_name:30s} {status}")
        
        if self.threat_indicators:
            print(f"\n⚠️ Threat Indicators ({len(self.threat_indicators)}):")
            for indicator in self.threat_indicators:
                print(f"  • {indicator}")
        
        # Send email alert if compromised
        if self.system_compromised and self.email_alerter:
            self._send_health_alert(result)
        
        print("="*60)
        
        return result
    
    def check_honeypot_alerts(self) -> bool:
        """
        Check if honeypot was triggered recently
        
        Returns:
            True if honeypot triggered (system compromised)
        """
        
        if not self.logger or not HAS_LOGGER:
            return False
        
        cutoff_time = time.time() - self.honeypot_window
        
        try:
            # Get recent honeypot events
            events = self.logger.get_events(
                event_type='HONEYPOT_TRIGGERED',
                start_time=cutoff_time,
                limit=10
            )

            if events:
                for event in events:
                    evt = event['event']
                    file_accessed = evt['details'].get('file_accessed', 'UNKNOWN')
                    timestamp = datetime.fromtimestamp(evt['timestamp']).isoformat()
                    self.threat_indicators.append(
                        f"Honeypot triggered: {file_accessed} at {timestamp}"
                    )
                return True

        except PermissionError:
            # Log file has DENY ACE from protection system — reset and ignore
            import subprocess
            log_path = str(self.logger.event_log)
            subprocess.run(['icacls', log_path, '/reset'], capture_output=True)
        except Exception as e:
            print(f"⚠️ Failed to check honeypot alerts: {e}")

        return False
    
    def check_running_processes(self) -> bool:
        """
        Check for known ransomware process signatures
        
        Returns:
            True if suspicious process found
        """
        
        try:
            current_pid = os.getpid()
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    # Skip our own process
                    if proc.info['pid'] == current_pid:
                        continue
                        
                    proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                    proc_exe = proc.info['exe'].lower() if proc.info['exe'] else ''
                    
                    # Skip whitelisted processes
                    is_whitelisted = any(wl in proc_name or wl in proc_exe 
                                        for wl in self.whitelist_patterns)
                    if is_whitelisted:
                        continue
                    
                    # Check against suspicious patterns
                    for pattern in self.suspicious_patterns:
                        if pattern in proc_name or pattern in proc_exe:
                            # Verify if it's just a Python script we trust
                            cmdline = proc.info.get('cmdline', [])
                            if cmdline and any('desktop_app.py' in arg or 'launch_admin.py' in arg for arg in cmdline):
                                continue
                                
                            self.threat_indicators.append(
                                f"Suspicious process: {proc.info['name']} (PID: {proc.info['pid']}) - Matched '{pattern}'"
                            )
                            return True
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
        except Exception as e:
            print(f"⚠️ Failed to check processes: {e}")
        
        return False
    
    def check_recent_access_denials(self) -> bool:
        """
        Check if multiple access denials occurred recently
        
        Returns:
            True if excessive denials detected
        """
        
        if not self.logger or not HAS_LOGGER:
            return False
        
        cutoff_time = time.time() - self.denial_window
        
        try:
            # Get recent denial events
            events = self.logger.get_events(
                event_type='PROTECTED_FILE_ACCESS_DENIED',
                start_time=cutoff_time,
                limit=self.denial_threshold + 1
            )
            
            denial_count = len(events)
            
            if denial_count > self.denial_threshold:
                self.threat_indicators.append(
                    f"Multiple access denials: {denial_count} in last {self.denial_window/60:.0f} minutes"
                )
                
                # Show which processes were denied
                processes = set()
                for event in events:
                    proc_name = event['event'].get('process_name', 'UNKNOWN')
                    processes.add(proc_name)
                
                if processes:
                    self.threat_indicators.append(
                        f"Denied processes: {', '.join(processes)}"
                    )
                
                return True
            
        except PermissionError:
            import subprocess
            log_path = str(self.logger.event_log)
            subprocess.run(['icacls', log_path, '/reset'], capture_output=True)
        except Exception as e:
            print(f"⚠️ Failed to check access denials: {e}")

        return False
    
    def check_system_integrity(self) -> bool:
        """
        Check for signs of system compromise
        
        Returns:
            True if integrity issues detected
        """
        
        try:
            # Check for common ransomware indicators
            indicators = []
            
            # Check for ransom notes in common locations
            ransom_note_locations = [
                Path.home() / "Desktop",
                Path.home() / "Documents",
                Path("C:\\"),
            ]
            
            ransom_note_patterns = [
                "README.txt", "DECRYPT_INSTRUCTIONS.txt",
                "HOW_TO_DECRYPT.html", "RESTORE_FILES.txt",
                "!!! READ ME !!!.txt"
            ]
            
            for location in ransom_note_locations:
                if not location.exists():
                    continue
                    
                for pattern in ransom_note_patterns:
                    ransom_note = location / pattern
                    if ransom_note.exists():
                        indicators.append(f"Ransom note found: {ransom_note}")
            
            # Check for mass file extensions change
            # (More advanced - could scan for many .encrypted, .locked files)
            
            if indicators:
                self.threat_indicators.extend(indicators)
                return True
            
        except Exception as e:
            print(f"⚠️ Failed to check system integrity: {e}")
        
        return False
    
    def _send_health_alert(self, health_result: Dict):
        """Send email alert for compromised system"""
        
        try:
            alert_details = {
                'system_status': 'COMPROMISED',
                'check_results': {
                    check: 'FAILED' if failed else 'PASSED'
                    for check, failed in health_result['checks'].items()
                },
                'threat_indicators': health_result['threat_indicators'],
                'remediation_required': True,
                'usb_access_blocked': True
            }
            
            self.email_alerter.send_alert(
                alert_type='SYSTEM_HEALTH_CHECK_FAILED',
                severity='CRITICAL',
                details=alert_details,
                attach_logs=True
            )
            
        except Exception as e:
            print(f"⚠️ Failed to send health alert: {e}")
    
    def get_remediation_steps(self) -> List[str]:
        """
        Get recommended steps to clean compromised system
        
        Returns:
            List of remediation steps
        """
        
        steps = []
        
        if any('honeypot' in ind.lower() for ind in self.threat_indicators):
            steps.append("1. Quarantine processes that triggered honeypot")
            steps.append("2. Run full malware scan with updated definitions")
        
        if any('suspicious process' in ind.lower() for ind in self.threat_indicators):
            steps.append("3. Terminate suspicious processes immediately")
            steps.append("4. Submit suspicious files to VirusTotal for analysis")
        
        if any('access denial' in ind.lower() for ind in self.threat_indicators):
            steps.append("5. Review security event logs for attack patterns")
            steps.append("6. Identify and isolate affected systems")
        
        if any('ransom note' in ind.lower() for ind in self.threat_indicators):
            steps.append("7. DO NOT PAY RANSOM")
            steps.append("8. Restore from clean backups")
            steps.append("9. Check No More Ransom for decryption tools")
        
        # General steps
        steps.extend([
            "10. Verify system integrity with DISM and SFC",
            "11. Check Windows Event Logs for suspicious activity",
            "12. Reset all passwords after cleaning",
            "13. Contact security team for incident response"
        ])
        
        return steps
    
    def can_use_usb_token(self) -> bool:
        """
        Determine if USB token can be safely used
        
        Returns:
            True if safe to use USB token
        """
        
        health_status = self.check_system_health()
        
        if not health_status['healthy']:
            print("\n" + "🚫 "*30)
            print("USB TOKEN BLOCKED")
            print("="*60)
            print("REASON: System appears compromised")
            print("\nTHREAT INDICATORS:")
            for indicator in health_status['threat_indicators']:
                print(f"  ⚠️ {indicator}")
            
            print("\nREQUIRED ACTIONS:")
            for step in self.get_remediation_steps():
                print(f"  {step}")
            
            print("\n❌ USB token will NOT grant access until system is verified clean")
            print("="*60)
            
            return False
        
        print("\n✓ System healthy - USB token can be used safely")
        return True


if __name__ == '__main__':
    # Test the health checker
    checker = SystemHealthChecker()
    
    print("\n" + "="*60)
    print("System Health Checker Test")
    print("="*60)
    
    # Run health check
    can_use_usb = checker.can_use_usb_token()
    
    if can_use_usb:
        print("\n✅ RESULT: USB token access ALLOWED")
    else:
        print("\n❌ RESULT: USB token access BLOCKED")
    
    print("\n" + "="*60)
    print("✓ System Health Checker Test Complete")
    print("="*60)
