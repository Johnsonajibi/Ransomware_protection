"""
Tamper-Evident Audit Logging for Immune Folders
Provides cryptographically secure, tamper-evident audit trail
"""

import os
import sys
import json
import time
import hmac
import hashlib
import threading
from pathlib import Path
from typing import Optional, Dict, List, Any, Iterator
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum

@dataclass
class AuditEvent:
    """Individual audit event"""
    event_id: str
    timestamp: float
    event_type: str
    user_context: str
    process_id: int
    process_name: str
    details: Dict[str, Any]
    security_level: str
    previous_hash: str
    event_hash: str

class AuditLevel(Enum):
    """Audit event security levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    SECURITY = "security"

class AuditEventType(Enum):
    """Types of audit events"""
    # Authentication events
    TOKEN_INSERTED = "token_inserted"
    TOKEN_REMOVED = "token_removed"
    TOKEN_VALIDATION_SUCCESS = "token_validation_success"
    TOKEN_VALIDATION_FAILURE = "token_validation_failure"
    
    # Container operations
    CONTAINER_CREATED = "container_created"
    CONTAINER_MOUNTED = "container_mounted" 
    CONTAINER_UNMOUNTED = "container_unmounted"
    CONTAINER_DELETED = "container_deleted"
    CONTAINER_ACCESS_DENIED = "container_access_denied"
    
    # File operations
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"
    FILE_ACCESSED = "file_accessed"
    FILE_PERMISSION_CHANGED = "file_permission_changed"
    
    # System events
    SERVICE_STARTED = "service_started"
    SERVICE_STOPPED = "service_stopped"
    CONFIGURATION_CHANGED = "configuration_changed"
    EMERGENCY_LOCK_ACTIVATED = "emergency_lock_activated"
    
    # Security events
    INTRUSION_DETECTED = "intrusion_detected"
    UNAUTHORIZED_ACCESS_ATTEMPT = "unauthorized_access_attempt"
    PRIVILEGE_ESCALATION_DETECTED = "privilege_escalation_detected"
    SUSPICIOUS_PROCESS_DETECTED = "suspicious_process_detected"
    
    # Recovery events
    RECOVERY_INITIATED = "recovery_initiated"
    RECOVERY_COMPLETED = "recovery_completed"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"

class TamperEvidentLogger:
    """Main tamper-evident audit logging class"""
    
    def __init__(self, log_directory: str = None, signing_key: str = None):
        self.log_directory = Path(log_directory or 
                                os.path.join(os.getenv('PROGRAMDATA', 'C:\\ProgramData'),
                                           'ImmuneFolders', 'audit'))
        
        self.log_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize signing key for tamper evidence
        self.signing_key = signing_key or self._generate_signing_key()
        
        # Current log file and chain state
        self.current_log_file = None
        self.last_event_hash = ""
        self.event_counter = 0
        
        # Thread safety
        self.log_lock = threading.Lock()
        
        # Initialize log chain
        self._initialize_log_chain()
        
        print(f"Tamper-evident audit logger initialized")
        print(f"Log directory: {self.log_directory}")
    
    def _generate_signing_key(self) -> str:
        """Generate or retrieve signing key for log integrity"""
        try:
            key_file = self.log_directory / "audit.key"
            
            if key_file.exists():
                # Load existing key
                with open(key_file, 'r') as f:
                    return f.read().strip()
            else:
                # Generate new key
                import secrets
                key = secrets.token_hex(32)
                
                # Save key securely
                with open(key_file, 'w') as f:
                    f.write(key)
                
                # Set restrictive permissions
                self._secure_file_permissions(key_file)
                
                return key
                
        except Exception as e:
            print(f"Signing key generation error: {e}")
            # Fall back to a deterministic key based on system
            import socket
            hostname = socket.gethostname()
            return hashlib.sha256(f"ImmuneFolders-{hostname}".encode()).hexdigest()
    
    def _initialize_log_chain(self):
        """Initialize the tamper-evident log chain"""
        try:
            # Find the latest log file
            log_files = sorted(self.log_directory.glob("audit_*.jsonl"))
            
            if log_files:
                # Load last event from latest log file
                latest_log = log_files[-1]
                self.current_log_file = latest_log
                
                # Read last line to get previous hash
                with open(latest_log, 'r') as f:
                    lines = f.readlines()
                    if lines:
                        last_line = lines[-1].strip()
                        if last_line:
                            last_event = json.loads(last_line)
                            self.last_event_hash = last_event.get("event_hash", "")
                            self.event_counter = last_event.get("event_counter", 0)
            else:
                # Create initial log file
                self._create_new_log_file()
                
        except Exception as e:
            print(f"Log chain initialization error: {e}")
            self._create_new_log_file()
    
    def _create_new_log_file(self):
        """Create a new log file for the current day"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d")
            log_filename = f"audit_{timestamp}.jsonl"
            self.current_log_file = self.log_directory / log_filename
            
            # Create file if it doesn't exist
            if not self.current_log_file.exists():
                self.current_log_file.touch()
                self._secure_file_permissions(self.current_log_file)
            
            # Initialize chain if this is the first log
            if not self.last_event_hash:
                self.last_event_hash = "GENESIS"
                self.event_counter = 0
                
        except Exception as e:
            print(f"Log file creation error: {e}")
    
    def log_event(self, event_type: AuditEventType, details: Dict[str, Any],
                  security_level: AuditLevel = AuditLevel.INFO,
                  user_context: str = None) -> bool:
        """Log a tamper-evident audit event"""
        with self.log_lock:
            try:
                # Generate unique event ID
                import uuid
                event_id = str(uuid.uuid4())
                
                # Get current context
                user_context = user_context or self._get_current_user_context()
                process_id = os.getpid()
                process_name = self._get_process_name()
                
                # Create timestamp
                timestamp = time.time()
                
                # Increment counter
                self.event_counter += 1
                
                # Create event data (without hash initially)
                event_data = {
                    "event_id": event_id,
                    "event_counter": self.event_counter,
                    "timestamp": timestamp,
                    "timestamp_iso": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
                    "event_type": event_type.value,
                    "user_context": user_context,
                    "process_id": process_id,
                    "process_name": process_name,
                    "details": details,
                    "security_level": security_level.value,
                    "previous_hash": self.last_event_hash,
                    "log_version": 1
                }
                
                # Calculate tamper-evident hash
                event_hash = self._calculate_event_hash(event_data)
                event_data["event_hash"] = event_hash
                
                # Check if we need a new log file (daily rotation)
                current_date = datetime.now().strftime("%Y%m%d")
                expected_filename = f"audit_{current_date}.jsonl"
                
                if not self.current_log_file or self.current_log_file.name != expected_filename:
                    self._create_new_log_file()
                
                # Write event to log file
                with open(self.current_log_file, 'a') as f:
                    json.dump(event_data, f, separators=(',', ':'))
                    f.write('\n')  # JSONL format
                    f.flush()
                    os.fsync(f.fileno())  # Force write to disk
                
                # Update chain state
                self.last_event_hash = event_hash
                
                return True
                
            except Exception as e:
                print(f"Audit logging error: {e}")
                return False
    
    def _calculate_event_hash(self, event_data: Dict[str, Any]) -> str:
        """Calculate tamper-evident hash for an event"""
        try:
            # Create canonical representation for hashing
            hash_data = {
                "event_id": event_data["event_id"],
                "event_counter": event_data["event_counter"],
                "timestamp": event_data["timestamp"],
                "event_type": event_data["event_type"],
                "user_context": event_data["user_context"],
                "process_id": event_data["process_id"],
                "details": event_data["details"],
                "previous_hash": event_data["previous_hash"]
            }
            
            # Create deterministic JSON representation
            canonical_json = json.dumps(hash_data, sort_keys=True, separators=(',', ':'))
            
            # Calculate HMAC hash
            hmac_hash = hmac.new(
                self.signing_key.encode('utf-8'),
                canonical_json.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            return hmac_hash
            
        except Exception as e:
            print(f"Hash calculation error: {e}")
            return "ERROR"
    
    def verify_log_integrity(self, log_file_path: str = None) -> bool:
        """Verify the integrity of the audit log chain"""
        try:
            if not log_file_path:
                if not self.current_log_file:
                    return False
                log_file_path = str(self.current_log_file)
            
            print(f"Verifying log integrity: {log_file_path}")
            
            with open(log_file_path, 'r') as f:
                previous_hash = "GENESIS"
                event_counter = 0
                
                for line_num, line in enumerate(f, 1):
                    try:
                        line = line.strip()
                        if not line:
                            continue
                        
                        event_data = json.loads(line)
                        
                        # Verify event counter sequence
                        expected_counter = event_counter + 1
                        actual_counter = event_data.get("event_counter", 0)
                        
                        if actual_counter != expected_counter:
                            print(f"Counter mismatch at line {line_num}: expected {expected_counter}, got {actual_counter}")
                            return False
                        
                        # Verify hash chain
                        if event_data.get("previous_hash") != previous_hash:
                            print(f"Chain break at line {line_num}: previous hash mismatch")
                            return False
                        
                        # Verify event hash
                        stored_hash = event_data.get("event_hash", "")
                        event_copy = event_data.copy()
                        del event_copy["event_hash"]
                        
                        calculated_hash = self._calculate_event_hash(event_copy)
                        
                        if stored_hash != calculated_hash:
                            print(f"Hash verification failed at line {line_num}")
                            return False
                        
                        # Update for next iteration
                        previous_hash = stored_hash
                        event_counter = actual_counter
                        
                    except json.JSONDecodeError as e:
                        print(f"JSON parsing error at line {line_num}: {e}")
                        return False
            
            print("✓ Log integrity verification passed")
            return True
            
        except Exception as e:
            print(f"Log verification error: {e}")
            return False
    
    def search_events(self, event_type: AuditEventType = None,
                     start_time: float = None, end_time: float = None,
                     user_context: str = None, security_level: AuditLevel = None,
                     limit: int = 100) -> List[Dict[str, Any]]:
        """Search audit events with filters"""
        try:
            events = []
            search_count = 0
            
            # Search through all log files (newest first)
            log_files = sorted(self.log_directory.glob("audit_*.jsonl"), reverse=True)
            
            for log_file in log_files:
                with open(log_file, 'r') as f:
                    # Read lines in reverse order (newest first)
                    lines = f.readlines()
                    for line in reversed(lines):
                        if search_count >= limit:
                            break
                        
                        try:
                            line = line.strip()
                            if not line:
                                continue
                            
                            event = json.loads(line)
                            
                            # Apply filters
                            if event_type and event.get("event_type") != event_type.value:
                                continue
                            
                            if start_time and event.get("timestamp", 0) < start_time:
                                continue
                            
                            if end_time and event.get("timestamp", 0) > end_time:
                                continue
                            
                            if user_context and event.get("user_context") != user_context:
                                continue
                            
                            if security_level and event.get("security_level") != security_level.value:
                                continue
                            
                            events.append(event)
                            search_count += 1
                            
                        except json.JSONDecodeError:
                            continue  # Skip malformed lines
                
                if search_count >= limit:
                    break
            
            return events
            
        except Exception as e:
            print(f"Event search error: {e}")
            return []
    
    def get_security_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get security event summary for the specified time period"""
        try:
            cutoff_time = time.time() - (hours * 3600)
            
            # Count events by type and level
            event_counts = {}
            security_events = []
            critical_events = []
            
            log_files = sorted(self.log_directory.glob("audit_*.jsonl"), reverse=True)
            
            for log_file in log_files:
                with open(log_file, 'r') as f:
                    for line in f:
                        try:
                            line = line.strip()
                            if not line:
                                continue
                            
                            event = json.loads(line)
                            event_time = event.get("timestamp", 0)
                            
                            if event_time < cutoff_time:
                                continue  # Too old
                            
                            # Count by type
                            event_type = event.get("event_type", "unknown")
                            event_counts[event_type] = event_counts.get(event_type, 0) + 1
                            
                            # Collect security events
                            security_level = event.get("security_level", "")
                            if security_level == "security":
                                security_events.append(event)
                            elif security_level == "critical":
                                critical_events.append(event)
                                
                        except json.JSONDecodeError:
                            continue
            
            return {
                "time_period_hours": hours,
                "total_events": sum(event_counts.values()),
                "event_counts_by_type": event_counts,
                "security_events_count": len(security_events),
                "critical_events_count": len(critical_events),
                "recent_security_events": security_events[:10],  # Last 10
                "recent_critical_events": critical_events[:5]    # Last 5
            }
            
        except Exception as e:
            print(f"Security summary error: {e}")
            return {}
    
    def export_logs(self, output_path: str, start_time: float = None,
                   end_time: float = None, include_verification: bool = True) -> bool:
        """Export audit logs to a file with integrity verification"""
        try:
            exported_events = []
            
            log_files = sorted(self.log_directory.glob("audit_*.jsonl"))
            
            for log_file in log_files:
                with open(log_file, 'r') as f:
                    for line in f:
                        try:
                            line = line.strip()
                            if not line:
                                continue
                            
                            event = json.loads(line)
                            event_time = event.get("timestamp", 0)
                            
                            # Apply time filters
                            if start_time and event_time < start_time:
                                continue
                            if end_time and event_time > end_time:
                                continue
                            
                            exported_events.append(event)
                            
                        except json.JSONDecodeError:
                            continue
            
            # Create export package
            export_data = {
                "export_timestamp": time.time(),
                "export_timestamp_iso": datetime.now(timezone.utc).isoformat(),
                "total_events": len(exported_events),
                "events": exported_events
            }
            
            if include_verification:
                # Add integrity verification data
                export_data["integrity_verified"] = all(
                    self.verify_log_integrity(str(log_file)) for log_file in log_files
                )
                export_data["signing_key_hash"] = hashlib.sha256(
                    self.signing_key.encode('utf-8')
                ).hexdigest()
            
            # Write export file
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"Exported {len(exported_events)} events to {output_path}")
            return True
            
        except Exception as e:
            print(f"Log export error: {e}")
            return False
    
    def _get_current_user_context(self) -> str:
        """Get current user context information"""
        try:
            import getpass
            username = getpass.getuser()
            
            # Add domain information if available
            try:
                import win32api
                domain = win32api.GetUserNameEx(2)  # Domain\Username format
                return domain
            except:
                return username
                
        except Exception:
            return "unknown"
    
    def _get_process_name(self) -> str:
        """Get current process name"""
        try:
            import psutil
            return psutil.Process().name()
        except Exception:
            return os.path.basename(sys.argv[0]) if sys.argv else "unknown"
    
    def _secure_file_permissions(self, file_path: Path):
        """Set secure file permissions (Windows)"""
        try:
            if sys.platform == "win32":
                import win32security
                import win32con
                
                # Get current user and SYSTEM accounts
                user_sid = win32security.GetTokenInformation(
                    win32security.GetCurrentProcessToken(),
                    win32security.TokenUser
                )[0]
                
                system_sid = win32security.LookupAccountName(None, "SYSTEM")[0]
                
                # Create DACL with limited access
                dacl = win32security.ACL()
                
                # Add full control for SYSTEM
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    win32con.FILE_ALL_ACCESS,
                    system_sid
                )
                
                # Add read/write for current user
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    win32con.FILE_GENERIC_READ | win32con.FILE_GENERIC_WRITE,
                    user_sid
                )
                
                # Apply DACL to file
                win32security.SetFileSecurity(
                    str(file_path),
                    win32security.DACL_SECURITY_INFORMATION,
                    dacl
                )
                
        except Exception as e:
            print(f"Warning: Could not set secure file permissions: {e}")
    
    def cleanup(self):
        """Cleanup resources"""
        print("Audit logger cleanup complete")

# Audit event helper functions
class AuditHelper:
    """Helper functions for common audit operations"""
    
    def __init__(self, logger: TamperEvidentLogger):
        self.logger = logger
    
    def log_authentication(self, success: bool, token_id: str = None, 
                         error_message: str = None):
        """Log authentication event"""
        if success:
            self.logger.log_event(
                AuditEventType.TOKEN_VALIDATION_SUCCESS,
                {"token_id": token_id},
                AuditLevel.SECURITY
            )
        else:
            self.logger.log_event(
                AuditEventType.TOKEN_VALIDATION_FAILURE,
                {"token_id": token_id, "error": error_message},
                AuditLevel.WARNING
            )
    
    def log_container_operation(self, operation: str, container_id: str,
                              success: bool, details: Dict[str, Any] = None):
        """Log container operation"""
        event_types = {
            "mount": AuditEventType.CONTAINER_MOUNTED,
            "unmount": AuditEventType.CONTAINER_UNMOUNTED,
            "create": AuditEventType.CONTAINER_CREATED,
            "delete": AuditEventType.CONTAINER_DELETED
        }
        
        event_type = event_types.get(operation, AuditEventType.CONTAINER_MOUNTED)
        security_level = AuditLevel.INFO if success else AuditLevel.WARNING
        
        log_details = {
            "container_id": container_id,
            "operation": operation,
            "success": success
        }
        
        if details:
            log_details.update(details)
        
        self.logger.log_event(event_type, log_details, security_level)
    
    def log_security_incident(self, incident_type: str, severity: str,
                            details: Dict[str, Any]):
        """Log security incident"""
        event_types = {
            "intrusion": AuditEventType.INTRUSION_DETECTED,
            "unauthorized_access": AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
            "privilege_escalation": AuditEventType.PRIVILEGE_ESCALATION_DETECTED,
            "suspicious_process": AuditEventType.SUSPICIOUS_PROCESS_DETECTED
        }
        
        event_type = event_types.get(incident_type, AuditEventType.INTRUSION_DETECTED)
        
        security_levels = {
            "low": AuditLevel.WARNING,
            "medium": AuditLevel.CRITICAL,
            "high": AuditLevel.SECURITY,
            "critical": AuditLevel.SECURITY
        }
        
        security_level = security_levels.get(severity.lower(), AuditLevel.CRITICAL)
        
        log_details = {
            "incident_type": incident_type,
            "severity": severity,
            **details
        }
        
        self.logger.log_event(event_type, log_details, security_level)
    
    def log_file_operation(self, operation: str, file_path: str,
                          success: bool, details: Dict[str, Any] = None):
        """Log file operation"""
        event_types = {
            "create": AuditEventType.FILE_CREATED,
            "modify": AuditEventType.FILE_MODIFIED,
            "delete": AuditEventType.FILE_DELETED,
            "access": AuditEventType.FILE_ACCESSED
        }
        
        event_type = event_types.get(operation, AuditEventType.FILE_ACCESSED)
        
        log_details = {
            "operation": operation,
            "file_path": file_path,
            "success": success
        }
        
        if details:
            log_details.update(details)
        
        self.logger.log_event(event_type, log_details, AuditLevel.INFO)

# Test and example usage
if __name__ == "__main__":
    # Test tamper-evident logging
    logger = TamperEvidentLogger()
    helper = AuditHelper(logger)
    
    print("Testing tamper-evident audit logging...")
    
    # Test various event types
    helper.log_authentication(True, "test_token_123")
    helper.log_container_operation("mount", "container_456", True, 
                                 {"mount_point": "X:", "size_mb": 100})
    
    helper.log_security_incident("unauthorized_access", "medium", {
        "source_ip": "192.168.1.100",
        "attempted_resource": "confidential_folder",
        "user_agent": "suspicious_tool"
    })
    
    helper.log_file_operation("create", "X:\\sensitive_document.docx", True, {
        "file_size": 15360,
        "mime_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    })
    
    # Test integrity verification
    if logger.verify_log_integrity():
        print("✓ Log integrity verification passed")
    else:
        print("✗ Log integrity verification failed")
    
    # Test event search
    recent_events = logger.search_events(limit=5)
    print(f"Found {len(recent_events)} recent events")
    
    # Test security summary
    summary = logger.get_security_summary(hours=1)
    print(f"Security summary: {summary.get('total_events', 0)} events in last hour")
    
    # Test log export
    export_path = "test_audit_export.json"
    if logger.export_logs(export_path):
        print(f"✓ Logs exported to {export_path}")
        # Clean up
        try:
            os.remove(export_path)
        except:
            pass
    
    logger.cleanup()
    print("Audit logging test completed")
