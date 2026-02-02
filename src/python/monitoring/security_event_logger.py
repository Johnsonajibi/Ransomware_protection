#!/usr/bin/env python3
"""
Security Event Logger with Cryptographic Signing
================================================
Tamper-proof event logging using Dilithium3 signatures

Features:
- Post-quantum cryptographic signatures (Dilithium3)
- JSONL format for easy parsing
- Event integrity verification
- Tamper detection
- Chronological audit trail

Author: Johnson Ajibi
Date: December 28, 2025
"""

import os
import json
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from dataclasses import dataclass, asdict

try:
    from trifactor_auth_manager import PQCUSBAuthenticator
    HAS_PQC = True
except ImportError:
    HAS_PQC = False


@dataclass
class SecurityEvent:
    """Security event structure"""
    timestamp: float
    event_type: str
    severity: str
    details: Dict
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    user_account: Optional[str] = None
    source_ip: Optional[str] = None


class SecurityEventLogger:
    """
    Tamper-proof security event logging with cryptographic signatures
    
    Features:
    - Dilithium3 post-quantum signatures
    - JSONL format for stream processing
    - Event integrity verification
    - Automatic log rotation
    """
    
    def __init__(self, log_dir: Optional[Path] = None):
        """Initialize security event logger"""
        
        # Log directory
        if log_dir is None:
            # Try ProgramData first, fall back to user AppData
            try:
                log_dir = Path(os.getenv('PROGRAMDATA', 'C:\\ProgramData')) / 'AntiRansomware'
                log_dir.mkdir(parents=True, exist_ok=True)
                # Test write permission
                test_file = log_dir / '.test'
                test_file.touch()
                test_file.unlink()
            except (PermissionError, OSError):
                # Fall back to user directory
                log_dir = Path(os.getenv('LOCALAPPDATA', os.path.expanduser('~'))) / 'AntiRansomware'
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Log files
        self.event_log = self.log_dir / 'signed_events.jsonl'
        self.integrity_log = self.log_dir / 'integrity_verification.jsonl'
        
        # Initialize PQC authenticator for signing
        self.authenticator = None
        if HAS_PQC:
            self.authenticator = PQCUSBAuthenticator()
    
    def log_event(self, event: SecurityEvent) -> bool:
        """
        Log security event with cryptographic signature
        
        Args:
            event: SecurityEvent to log
        
        Returns:
            True if logged successfully
        """
        
        try:
            # Create signed event
            signed_event = self._sign_event(event)
            
            # Append to log file
            with self.event_log.open('a', encoding='utf-8') as f:
                f.write(json.dumps(signed_event) + '\n')
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to log event: {e}")
            return False
    
    def _sign_event(self, event: SecurityEvent) -> Dict:
        """Sign event with Dilithium3"""
        
        # Convert event to dict
        event_dict = asdict(event)
        
        # Serialize event
        event_json = json.dumps(event_dict, sort_keys=True)
        event_bytes = event_json.encode('utf-8')
        
        # Hash event
        event_hash = hashlib.sha256(event_bytes).digest()
        
        # Sign with Dilithium3 if available
        signature = None
        public_key = None
        
        if self.authenticator and self.authenticator.keypair:
            try:
                # Use private key from memory (not USB)
                private_key = self.authenticator.keypair[1]
                signature_bytes = self.authenticator.pqc_crypto.sign(
                    event_hash,
                    private_key
                )
                signature = signature_bytes.hex()
                public_key = self.authenticator.keypair[0].hex()
            except Exception as e:
                print(f"⚠️ Signature failed: {e}")
        
        # Create signed event structure
        signed_event = {
            'event': event_dict,
            'event_hash': event_hash.hex(),
            'signature': signature,
            'signature_algorithm': 'dilithium3' if signature else None,
            'public_key': public_key,
            'signed_at': time.time(),
            'signed_datetime': datetime.now().isoformat()
        }
        
        return signed_event
    
    def verify_event(self, signed_event: Dict) -> bool:
        """
        Verify event signature
        
        Args:
            signed_event: Signed event dict
        
        Returns:
            True if signature valid
        """
        
        if not signed_event.get('signature'):
            print("⚠️ Event not signed")
            return False
        
        try:
            # Reconstruct event hash
            event_json = json.dumps(signed_event['event'], sort_keys=True)
            event_hash = hashlib.sha256(event_json.encode('utf-8')).digest()
            
            # Verify hash matches
            if event_hash.hex() != signed_event['event_hash']:
                return False
            
            # Verify signature
            if self.authenticator and self.authenticator.pqc_crypto:
                is_valid = self.authenticator.pqc_crypto.verify(
                    event_hash,
                    bytes.fromhex(signed_event['signature']),
                    bytes.fromhex(signed_event['public_key'])
                )
                
                if not is_valid:
                    return False
                
                return True
            
            return False
            
        except Exception as e:
            return False
    
    def get_events(self, 
                   event_type: Optional[str] = None,
                   severity: Optional[str] = None,
                   start_time: Optional[float] = None,
                   end_time: Optional[float] = None,
                   limit: int = 100) -> List[Dict]:
        """
        Retrieve security events with filtering
        
        Args:
            event_type: Filter by event type
            severity: Filter by severity
            start_time: Start timestamp
            end_time: End timestamp
            limit: Maximum events to return
        
        Returns:
            List of matching events
        """
        
        if not self.event_log.exists():
            return []
        
        events = []
        
        with self.event_log.open('r', encoding='utf-8') as f:
            for line in f:
                try:
                    signed_event = json.loads(line.strip())
                    event = signed_event['event']
                    
                    # Apply filters
                    if event_type and event['event_type'] != event_type:
                        continue
                    
                    if severity and event['severity'] != severity:
                        continue
                    
                    if start_time and event['timestamp'] < start_time:
                        continue
                    
                    if end_time and event['timestamp'] > end_time:
                        continue
                    
                    events.append(signed_event)
                    
                    if len(events) >= limit:
                        break
                    
                except Exception as e:
                    print(f"⚠️ Failed to parse event: {e}")
        
        return events
    
    def verify_all_events(self) -> Dict:
        """
        Verify integrity of all logged events
        
        Returns:
            Verification results dict
        """
        
        if not self.event_log.exists():
            return {'total': 0, 'valid': 0, 'invalid': 0, 'unsigned': 0, 'tampered_events': []}
        
        results = {
            'total': 0,
            'valid': 0,
            'invalid': 0,
            'unsigned': 0,
            'tampered_events': []
        }
        
        with self.event_log.open('r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    signed_event = json.loads(line.strip())
                    results['total'] += 1
                    
                    if not signed_event.get('signature'):
                        results['unsigned'] += 1
                        continue
                    
                    if self.verify_event(signed_event):
                        results['valid'] += 1
                    else:
                        results['invalid'] += 1
                        results['tampered_events'].append({
                            'line': line_num,
                            'timestamp': signed_event['event']['timestamp'],
                            'event_type': signed_event['event']['event_type']
                        })
                    
                except Exception as e:
                    print(f"⚠️ Failed to verify line {line_num}: {e}")
                    results['invalid'] += 1
        
        return results
    
    def log_honeypot_trigger(self, file_path: str, process_info: Dict):
        """Log honeypot triggered event"""
        
        event = SecurityEvent(
            timestamp=time.time(),
            event_type='HONEYPOT_TRIGGERED',
            severity='CRITICAL',
            details={
                'file_accessed': file_path,
                'action_attempted': process_info.get('action', 'UNKNOWN'),
                'threat_level': 'DEFINITE_MALWARE'
            },
            process_name=process_info.get('name'),
            process_id=process_info.get('pid'),
            user_account=process_info.get('user')
        )
        
        self.log_event(event)
    
    def log_access_denied(self, file_path: str, process_info: Dict, token_present: bool = False):
        """Log protected file access denied"""
        
        event = SecurityEvent(
            timestamp=time.time(),
            event_type='PROTECTED_FILE_ACCESS_DENIED',
            severity='HIGH',
            details={
                'file_path': file_path,
                'access_type': 'READ_DATA',
                'denied_by': 'WINDOWS_ACL',
                'token_present': token_present,
                'recommended_action': 'QUARANTINE_PROCESS'
            },
            process_name=process_info.get('name'),
            process_id=process_info.get('pid'),
            user_account=process_info.get('user')
        )
        
        self.log_event(event)
    
    def log_usb_blocked(self, device_id: str, threat_indicators: List[str]):
        """Log USB token blocked due to system compromise"""
        
        event = SecurityEvent(
            timestamp=time.time(),
            event_type='USB_TOKEN_BLOCKED_SYSTEM_COMPROMISED',
            severity='CRITICAL',
            details={
                'usb_device_id': device_id,
                'threat_indicators': threat_indicators,
                'recommended_action': 'CLEAN_SYSTEM_BEFORE_USB_ACCESS'
            },
            user_account=os.getlogin() if hasattr(os, 'getlogin') else 'UNKNOWN'
        )
        
        self.log_event(event)
    
    def log_shadow_copy_blocked(self, process_info: Dict, command_line: str):
        """Log shadow copy deletion attempt blocked"""
        
        event = SecurityEvent(
            timestamp=time.time(),
            event_type='SHADOW_COPY_DELETION_BLOCKED',
            severity='CRITICAL',
            details={
                'command_line': command_line,
                'action': 'PROCESS_TERMINATED',
                'threat_level': 'RANSOMWARE_INDICATOR'
            },
            process_name=process_info.get('name'),
            process_id=process_info.get('pid'),
            user_account=process_info.get('user')
        )
        
        self.log_event(event)
    
    def log_emergency_lockdown(self, reason: str, triggered_by: str):
        """Log emergency lockdown activation"""
        
        event = SecurityEvent(
            timestamp=time.time(),
            event_type='EMERGENCY_LOCKDOWN_ACTIVATED',
            severity='CRITICAL',
            details={
                'reason': reason,
                'triggered_by': triggered_by,
                'action': 'SYSTEM_WIDE_LOCKDOWN',
                'all_access_denied': True,
                'network_isolated': True,
                'processes_terminated': True
            },
            user_account=triggered_by
        )
        
        self.log_event(event)
    
    def log_emergency_lockdown_lifted(self, authorized_by: str, verification_token: Optional[str] = None):
        """Log emergency lockdown lifted"""
        
        event = SecurityEvent(
            timestamp=time.time(),
            event_type='EMERGENCY_LOCKDOWN_LIFTED',
            severity='HIGH',
            details={
                'authorized_by': authorized_by,
                'verification_token': verification_token or 'NONE',
                'action': 'LOCKDOWN_RELEASED',
                'manual_restoration_required': True
            },
            user_account=authorized_by
        )
        
        self.log_event(event)
    
    def log_emergency_lockdown(self, reason: str, triggered_by: str):
        """Log emergency lockdown activation"""
        
        event = SecurityEvent(
            timestamp=time.time(),
            event_type='EMERGENCY_LOCKDOWN_ACTIVATED',
            severity='CRITICAL',
            details={
                'reason': reason,
                'triggered_by': triggered_by,
                'action': 'ALL_ACCESS_DENIED'
            },
            user_account=triggered_by
        )
        
        self.log_event(event)


# Global logger instance
_global_logger = None

def get_logger() -> SecurityEventLogger:
    """Get global security event logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = SecurityEventLogger()
    return _global_logger


if __name__ == '__main__':
    # Test the logger
    logger = SecurityEventLogger()
    
    print("\n" + "="*60)
    print("Security Event Logger Test")
    print("="*60)
    
    # Test logging various events
    print("\n1. Logging honeypot trigger...")
    logger.log_honeypot_trigger(
        "C:\\Users\\test\\Documents\\Banking_Passwords.xlsx",
        {'name': 'ransomware.exe', 'pid': 1234, 'user': 'SYSTEM', 'action': 'READ'}
    )
    
    print("\n2. Logging access denied...")
    logger.log_access_denied(
        "C:\\Protected\\important.docx",
        {'name': 'malware.exe', 'pid': 5678, 'user': 'SYSTEM'},
        token_present=False
    )
    
    print("\n3. Logging USB blocked...")
    logger.log_usb_blocked(
        "USB_E:\\_12345678_VID0781_PID5581",
        ["Honeypot triggered", "Multiple access denials"]
    )
    
    # Verify all events
    print("\n4. Verifying event integrity...")
    results = logger.verify_all_events()
    print(f"\nVerification Results:")
    print(f"  Total events: {results['total']}")
    print(f"  Valid signatures: {results['valid']}")
    print(f"  Invalid signatures: {results['invalid']}")
    print(f"  Unsigned events: {results['unsigned']}")
    
    if results['tampered_events']:
        print(f"\n⚠️ WARNING: {len(results['tampered_events'])} tampered events detected!")
        for tampered in results['tampered_events']:
            print(f"  Line {tampered['line']}: {tampered['event_type']}")
    
    # Get recent critical events
    print("\n5. Recent critical events:")
    critical_events = logger.get_events(severity='CRITICAL', limit=10)
    for event in critical_events:
        evt = event['event']
        print(f"  [{evt['event_type']}] {datetime.fromtimestamp(evt['timestamp']).isoformat()}")
    
    print("\n" + "="*60)
    print("Security Event Logger Test Complete")
    print("="*60)
    print(f"\nLog file: {logger.event_log}")
