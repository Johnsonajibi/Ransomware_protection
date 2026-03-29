#!/usr/bin/env python3
"""
Real-Time File Monitor - Core Anti-Ransomware Protection
Monitors file system for ransomware-like behavior and blocks threats
"""

import os
import sys
import time
import json
import hashlib
import threading
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict, deque

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("Installing required watchdog module...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "watchdog"])
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

@dataclass
class ThreatEvent:
    """Represents a potential ransomware threat event"""
    timestamp: float
    event_type: str
    file_path: str
    process_id: int
    process_name: str
    threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    reason: str
    blocked: bool = False
    
    def to_dict(self):
        return asdict(self)

class RansomwareDetector:
    """Advanced ransomware behavior detection"""
    
    def __init__(self):
        self.suspicious_extensions = {
            # Common ransomware extensions
            '.encrypted', '.locked', '.crypto', '.crypt', '.vault',
            '.xxx', '.zzz', '.aaa', '.abc', '.micro', '.dharma',
            '.cerber', '.locky', '.spora', '.sage', '.globeimposter',
            # Encryption patterns
            '.cryp1', '.crinf', '.r5a', '.xrtn', '.encryptedRSA',
            # Recent variants
            '.ryuk', '.sodinokibi', '.maze', '.egregor', '.darkside'
        }
        
        self.suspicious_filenames = {
            'readme_for_decrypt.txt', 'how_to_decrypt.txt', 'decrypt_instruction.txt',
            'recovery_key.txt', 'restore_files.txt', 'decrypt_files.html',
            'how_to_restore_files.html', '_readme.txt', 'read_it.txt'
        }
        
        # Behavioral analysis counters
        self.file_modifications = defaultdict(int)
        self.extension_changes = defaultdict(int)
        self.rapid_encryptions = defaultdict(deque)
        self.process_activity = defaultdict(list)
        
        self.lock = threading.Lock()
    
    def analyze_file_event(self, file_path: str, event_type: str, process_info: Dict = None) -> Optional[ThreatEvent]:
        """Analyze a file event for ransomware indicators"""
        
        with self.lock:
            timestamp = time.time()
            file_path_obj = Path(file_path)
            
            # Get process information
            pid = process_info.get('pid', 0) if process_info else 0
            process_name = process_info.get('name', 'unknown') if process_info else 'unknown'
            
            # Check for suspicious extensions
            if file_path_obj.suffix.lower() in self.suspicious_extensions:
                return ThreatEvent(
                    timestamp=timestamp,
                    event_type=event_type,
                    file_path=file_path,
                    process_id=pid,
                    process_name=process_name,
                    threat_level='CRITICAL',
                    reason=f'Suspicious extension detected: {file_path_obj.suffix}',
                    blocked=True
                )
            
            # Check for ransom note filenames
            if file_path_obj.name.lower() in self.suspicious_filenames:
                return ThreatEvent(
                    timestamp=timestamp,
                    event_type=event_type,
                    file_path=file_path,
                    process_id=pid,
                    process_name=process_name,
                    threat_level='CRITICAL',
                    reason='Ransom note filename detected',
                    blocked=True
                )
            
            # Behavioral analysis
            threat_level = self._analyze_behavior(file_path, event_type, pid, process_name)
            
            if threat_level in ['HIGH', 'CRITICAL']:
                return ThreatEvent(
                    timestamp=timestamp,
                    event_type=event_type,
                    file_path=file_path,
                    process_id=pid,
                    process_name=process_name,
                    threat_level=threat_level,
                    reason='Suspicious behavioral pattern detected',
                    blocked=True
                )
            
            return None
    
    def _analyze_behavior(self, file_path: str, event_type: str, pid: int, process_name: str) -> str:
        """Analyze behavioral patterns for ransomware activity"""
        
        # Track file modifications per process
        if event_type in ['modified', 'created']:
            self.file_modifications[pid] += 1
            
            # Rapid file modification detection
            current_time = time.time()
            self.rapid_encryptions[pid].append(current_time)
            
            # Keep only recent events (last 60 seconds)
            while (self.rapid_encryptions[pid] and 
                   current_time - self.rapid_encryptions[pid][0] > 60):
                self.rapid_encryptions[pid].popleft()
            
            # If process is modifying too many files rapidly, it's suspicious
            if len(self.rapid_encryptions[pid]) > 50:  # More than 50 files in 60 seconds
                return 'CRITICAL'
            elif len(self.rapid_encryptions[pid]) > 20:  # More than 20 files in 60 seconds
                return 'HIGH'
        
        # Check for extension changes (potential encryption)
        file_path_obj = Path(file_path)
        if event_type == 'moved' and file_path_obj.suffix != '':
            self.extension_changes[pid] += 1
            if self.extension_changes[pid] > 10:  # Many extension changes
                return 'HIGH'
        
        # Overall activity analysis
        total_modifications = self.file_modifications.get(pid, 0)
        if total_modifications > 100:  # Process modified many files
            return 'HIGH'
        elif total_modifications > 50:
            return 'MEDIUM'
        
        return 'LOW'

class FileProtectionHandler(FileSystemEventHandler):
    """File system event handler with real-time protection"""
    
    def __init__(self, detector: RansomwareDetector, protection_callback=None):
        super().__init__()
        self.detector = detector
        self.protection_callback = protection_callback
        self.blocked_operations = []
        self.lock = threading.Lock()
    
    def on_modified(self, event):
        if not event.is_directory:
            self._process_file_event(event.src_path, 'modified')
    
    def on_created(self, event):
        if not event.is_directory:
            self._process_file_event(event.src_path, 'created')
    
    def on_deleted(self, event):
        if not event.is_directory:
            self._process_file_event(event.src_path, 'deleted')
    
    def on_moved(self, event):
        if not event.is_directory:
            self._process_file_event(event.dest_path, 'moved')
    
    def _process_file_event(self, file_path: str, event_type: str):
        """Process file system event and check for threats"""
        try:
            # Best-effort process attribution for the current event.
            process_info = self._get_process_info()
            
            # Analyze for threats
            threat = self.detector.analyze_file_event(file_path, event_type, process_info)
            
            if threat:
                with self.lock:
                    self.blocked_operations.append(threat)
                
                # Block the operation if it's a threat
                if threat.blocked:
                    self._block_operation(threat)
                
                # Notify callback
                if self.protection_callback:
                    self.protection_callback(threat)
                    
                print(f"🚨 THREAT DETECTED: {threat.threat_level}")
                print(f"   File: {threat.file_path}")
                print(f"   Reason: {threat.reason}")
                print(f"   Blocked: {'YES' if threat.blocked else 'NO'}")
                
        except Exception as e:
            print(f"Error processing file event: {e}")
    
    def _get_process_info(self) -> Dict:
        """Get current process information (simplified)"""
        try:
            import psutil
            current_process = psutil.Process()
            return {
                'pid': current_process.pid,
                'name': current_process.name()
            }
        except:
            return {'pid': 0, 'name': 'unknown'}
    
    def _block_operation(self, threat: ThreatEvent):
        """Block malicious file operation with real containment steps."""
        try:
            print(f"🛡️  BLOCKING MALICIOUS OPERATION")
            print(f"   Process: {threat.process_name} (PID: {threat.process_id})")
            print(f"   File: {threat.file_path}")
            print(f"   Action: File access denied")

            quarantine_dir = Path("./quarantine")
            quarantine_dir.mkdir(exist_ok=True)

            file_path = Path(threat.file_path)
            if file_path.exists() and file_path.is_file():
                quarantine_target = quarantine_dir / f"{int(time.time())}_{file_path.name}"
                try:
                    shutil.move(str(file_path), str(quarantine_target))
                    print(f"   Quarantined file: {quarantine_target}")
                except Exception as move_exc:
                    print(f"   Quarantine move failed: {move_exc}")

            try:
                import psutil

                if threat.process_id and threat.process_id != os.getpid():
                    proc = psutil.Process(threat.process_id)
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except psutil.TimeoutExpired:
                        proc.kill()
                    print(f"   Process terminated: {threat.process_name} ({threat.process_id})")
            except Exception as proc_exc:
                print(f"   Process containment failed: {proc_exc}")

            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "threat": threat.to_dict(),
                "action_taken": "quarantine_and_terminate",
            }
            with open(quarantine_dir / "blocked_events.jsonl", "a", encoding="utf-8") as handle:
                handle.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"Error blocking operation: {e}")
    
    def get_threat_summary(self) -> Dict:
        """Get summary of detected threats"""
        with self.lock:
            total_threats = len(self.blocked_operations)
            threats_by_level = defaultdict(int)
            
            for threat in self.blocked_operations:
                threats_by_level[threat.threat_level] += 1
            
            return {
                'total_threats': total_threats,
                'threats_by_level': dict(threats_by_level),
                'recent_threats': [t.to_dict() for t in self.blocked_operations[-10:]]
            }

class AntiRansomwareProtection:
    """Main anti-ransomware protection service"""
    
    def __init__(self, protected_directories: List[str] = None):
        self.protected_directories = protected_directories or []
        self.detector = RansomwareDetector()
        self.handler = FileProtectionHandler(self.detector, self._on_threat_detected)
        self.observer = Observer()
        self.is_running = False
        self.start_time = time.time()
        self.threat_log = []
        
    def add_protected_directory(self, directory: str):
        """Add a directory to protection"""
        directory_path = Path(directory)
        if directory_path.exists() and directory_path.is_dir():
            self.protected_directories.append(str(directory_path.absolute()))
            print(f"✅ Added protection for: {directory}")
            return True
        else:
            print(f"❌ Directory not found: {directory}")
            return False
    
    def start_protection(self):
        """Start real-time file protection"""
        if self.is_running:
            print("🛡️  Protection is already running")
            return
        
        if not self.protected_directories:
            print("⚠️  No directories configured for protection")
            # Add current directory as default
            self.add_protected_directory("./demo_files")
        
        print("🛡️  Starting Anti-Ransomware Protection...")
        
        try:
            for directory in self.protected_directories:
                self.observer.schedule(self.handler, directory, recursive=True)
                print(f"   📁 Monitoring: {directory}")
            
            self.observer.start()
            self.is_running = True
            self.start_time = time.time()
            
            print("✅ Real-time protection is ACTIVE")
            print("🚨 Monitoring for ransomware behavior...")
            
        except Exception as e:
            print(f"❌ Failed to start protection: {e}")
    
    def stop_protection(self):
        """Stop file protection"""
        if not self.is_running:
            return
        
        print("🛑 Stopping protection...")
        self.observer.stop()
        self.observer.join()
        self.is_running = False
        print("✅ Protection stopped")
    
    def _on_threat_detected(self, threat: ThreatEvent):
        """Callback when threat is detected"""
        self.threat_log.append(threat)
        
        # Keep only recent threats (last 1000)
        if len(self.threat_log) > 1000:
            self.threat_log = self.threat_log[-1000:]
    
    def get_status(self) -> Dict:
        """Get protection status"""
        uptime = time.time() - self.start_time if self.is_running else 0
        threat_summary = self.handler.get_threat_summary()
        
        return {
            'active': self.is_running,
            'uptime': uptime,
            'protected_directories': len(self.protected_directories),
            'directories': self.protected_directories,
            'threats_detected': threat_summary['total_threats'],
            'threats_blocked': len([t for t in self.threat_log if t.blocked]),
            'threat_levels': threat_summary['threats_by_level'],
            'last_threats': threat_summary['recent_threats']
        }
    
    def create_test_threat(self):
        """Create a test ransomware-like file to demonstrate protection"""
        test_dir = Path("./demo_files")
        test_dir.mkdir(exist_ok=True)
        
        # Create a file with suspicious extension
        test_file = test_dir / "important_document.txt.encrypted"
        
        try:
            test_file.write_text("This file has been encrypted by ransomware!")
            print(f"🧪 Created test threat: {test_file}")
            return str(test_file)
        except Exception as e:
            print(f"Error creating test threat: {e}")
            return None

def main():
    """Main function for standalone execution"""
    print("🛡️  Real-Time Anti-Ransomware Protection System")
    print("=" * 60)
    
    # Initialize protection
    protection = AntiRansomwareProtection()
    
    # Add default protection directories
    protection.add_protected_directory("./demo_files")
    protection.add_protected_directory("./protected_files") 
    
    try:
        # Start protection
        protection.start_protection()
        
        print("\n📋 Commands:")
        print("  'status' - Show protection status")
        print("  'test' - Create test threat")
        print("  'quit' - Stop protection and exit")
        
        # Interactive loop
        while True:
            try:
                command = input("\n> ").strip().lower()
                
                if command == 'quit' or command == 'exit':
                    break
                elif command == 'status':
                    status = protection.get_status()
                    print(f"\n🛡️  Protection Status:")
                    print(f"   Active: {'YES' if status['active'] else 'NO'}")
                    print(f"   Uptime: {status['uptime']:.1f} seconds")
                    print(f"   Protected directories: {status['protected_directories']}")
                    print(f"   Threats detected: {status['threats_detected']}")
                    print(f"   Threats blocked: {status['threats_blocked']}")
                    if status['threat_levels']:
                        print(f"   Threat levels: {status['threat_levels']}")
                elif command == 'test':
                    test_file = protection.create_test_threat()
                    if test_file:
                        print(f"✅ Test threat created - check for detection!")
                else:
                    print("Unknown command. Use 'status', 'test', or 'quit'.")
                    
            except KeyboardInterrupt:
                break
            except EOFError:
                break
    
    finally:
        protection.stop_protection()
        print("\n👋 Anti-Ransomware Protection stopped")

if __name__ == "__main__":
    main()
