"""
Forensics Module
Incident analysis, evidence collection, and forensic timeline
"""

import os
import sys
import json
import logging
import sqlite3
import hashlib
from datetime import datetime
from typing import List, Dict, Optional
import subprocess
import tempfile
try:
    from urllib.parse import unquote
except ImportError:
    from urllib import unquote

def validate_path(path: str, base_dir: str = None) -> bool:
    """
    Validate path to prevent directory traversal attacks.
    
    Args:
        path: The path to validate
        base_dir: Optional base directory that path must be within
        
    Returns:
        True if path is safe, False otherwise
    """
    if not path or not isinstance(path, str):
        return False
    
    # Decode URL-encoded characters to catch %2e%2e attacks
    decoded_path = unquote(path)
    
    # Get absolute and normalized path
    abs_path = os.path.abspath(decoded_path)
    normalized = os.path.normpath(abs_path)
    
    # Check for directory traversal patterns
    if '..' in normalized or '..' in decoded_path:
        return False
    
    # Check for home directory expansion
    if '~' in decoded_path:
        return False
    
    # If base_dir specified, ensure path is within it
    if base_dir:
        base_abs = os.path.abspath(base_dir)
        # Ensure the normalized path is within base_abs (with proper separator check)
        if not (normalized.startswith(base_abs) and 
                (len(normalized) == len(base_abs) or 
                 normalized[len(base_abs):len(base_abs)+1] in (os.sep, os.altsep) or
                 normalized[len(base_abs):len(base_abs)+1] == '')):
            return False
    
    # Validate Windows paths
    if os.name == 'nt':
        # Check for valid drive letter
        if len(normalized) >= 2 and normalized[1] == ':':
            if not normalized[0].isalpha():
                return False
        # Block UNC paths for security (per requirement - prevents network share attacks)
        if normalized.startswith('\\\\'):
            return False
    
    return True

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ForensicsManager:
    """
    Manages forensic data collection and incident analysis
    """
    
    def __init__(self, forensics_dir: str = "C:\\ProgramData\\AntiRansomware\\forensics"):
        """
        Initialize forensics manager
        
        Args:
            forensics_dir: Directory for forensic data
        """
        # Validate forensics_dir to prevent path traversal attacks
        if not validate_path(forensics_dir):
            logger.warning(f"Invalid forensics_dir rejected: {forensics_dir}")
            forensics_dir = "C:\\ProgramData\\AntiRansomware\\forensics"
        
        self.forensics_dir = forensics_dir
        os.makedirs(forensics_dir, exist_ok=True)
        
        self.db_path = os.path.join(forensics_dir, "forensics.db")
        self._init_database()
        
    def _init_database(self):
        """Initialize forensics database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    process_id INTEGER,
                    process_name TEXT,
                    file_path TEXT,
                    details TEXT,
                    evidence_collected INTEGER DEFAULT 0
                )
            ''')
            
            # Evidence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER,
                    evidence_type TEXT NOT NULL,
                    evidence_path TEXT,
                    file_hash TEXT,
                    collected_at TEXT NOT NULL,
                    metadata TEXT,
                    FOREIGN KEY (event_id) REFERENCES events (id)
                )
            ''')
            
            # Network activity table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    process_id INTEGER,
                    process_name TEXT,
                    local_address TEXT,
                    remote_address TEXT,
                    remote_port INTEGER,
                    protocol TEXT,
                    status TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Forensics database initialized")
            
        except Exception as e:
            logger.error(f"Error initializing forensics database: {e}")
    
    def record_event(self, event_type: str, severity: str, 
                    process_id: Optional[int] = None,
                    process_name: Optional[str] = None,
                    file_path: Optional[str] = None,
                    details: Optional[str] = None) -> Optional[int]:
        """
        Record a forensic event
        
        Args:
            event_type: Type of event (file_modified, process_started, etc.)
            severity: Event severity (low, medium, high, critical)
            process_id: Process ID involved
            process_name: Process name
            file_path: File path involved
            details: Additional details (JSON string)
            
        Returns:
            Event ID or None
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO events (timestamp, event_type, severity, process_id, 
                                  process_name, file_path, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (datetime.now().isoformat(), event_type, severity, process_id,
                 process_name, file_path, details))
            
            event_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            logger.info(f"Recorded event #{event_id}: {event_type} ({severity})")
            return event_id
            
        except Exception as e:
            logger.error(f"Error recording event: {e}")
            return None
    
    def collect_memory_dump(self, process_id: int, dump_type: str = 'full') -> Optional[str]:
        """
        Collect full memory dump of a process using Windows debugging APIs
        
        Args:
            process_id: Process ID to dump
            dump_type: Type of dump ('mini', 'full', 'heap')
            
        Returns:
            Path to dump file or None
        """
        try:
            # Try to use full memory dump implementation
            try:
                from memory_dump import MemoryDumper
                
                dumper = MemoryDumper(dump_dir=self.forensics_dir)
                dump_path = dumper.create_minidump(
                    process_id,
                    dump_type=dump_type,
                    include_handles=True,
                    include_threads=True
                )
                
                if dump_path:
                    logger.info(f"Full memory dump created: {dump_path}")
                    return dump_path
            
            except ImportError:
                logger.warning("Full memory dump module not available, using fallback")
            except Exception as e:
                logger.warning(f"Full memory dump failed: {e}, using fallback")
            
            # Fallback to basic metadata collection
            if not HAS_PSUTIL:
                logger.error("psutil required for memory dumps")
                return None
            
            proc = psutil.Process(process_id)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dump_path = os.path.join(self.forensics_dir, 
                                    f"memdump_{process_id}_{timestamp}.txt")
            
            logger.info(f"Creating metadata dump for PID {process_id}")
            
            with open(dump_path, 'w') as f:
                f.write(f"Memory Dump Metadata\n")
                f.write(f"="*50 + "\n")
                f.write(f"Process ID: {process_id}\n")
                f.write(f"Process Name: {proc.name()}\n")
                f.write(f"Executable: {proc.exe()}\n")
                f.write(f"Cmdline: {' '.join(proc.cmdline())}\n")
                f.write(f"CWD: {proc.cwd()}\n")
                f.write(f"Username: {proc.username()}\n")
                f.write(f"Create Time: {datetime.fromtimestamp(proc.create_time())}\n")
                f.write(f"CPU Percent: {proc.cpu_percent()}\n")
                f.write(f"Memory: {proc.memory_info().rss / 1024 / 1024:.2f} MB\n")
                f.write(f"Threads: {proc.num_threads()}\n")
                f.write(f"Timestamp: {timestamp}\n")
            
            return dump_path
            
        except Exception as e:
            logger.error(f"Error collecting memory dump: {e}")
            return None
    
    def collect_process_evidence(self, process_id: int, event_id: Optional[int] = None) -> bool:
        """
        Collect evidence about a process
        
        Args:
            process_id: Process ID
            event_id: Associated event ID
            
        Returns:
            True if successful
        """
        try:
            if not HAS_PSUTIL:
                return False
            
            proc = psutil.Process(process_id)
            
            evidence = {
                'pid': process_id,
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': proc.cmdline(),
                'cwd': proc.cwd(),
                'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                'username': proc.username(),
                'connections': []
            }
            
            # Get network connections
            try:
                for conn in proc.connections():
                    evidence['connections'].append({
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status
                    })
            except:
                pass
            
            # Save evidence
            evidence_path = os.path.join(self.forensics_dir, 
                                        f"process_{process_id}_{int(datetime.now().timestamp())}.json")
            
            with open(evidence_path, 'w') as f:
                json.dump(evidence, f, indent=2)
            
            # Record in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO evidence (event_id, evidence_type, evidence_path, 
                                    collected_at, metadata)
                VALUES (?, ?, ?, ?, ?)
            ''', (event_id, 'process_snapshot', evidence_path,
                 datetime.now().isoformat(), json.dumps(evidence)))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Collected process evidence for PID {process_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error collecting process evidence: {e}")
            return False
    
    def collect_file_evidence(self, file_path: str, event_id: Optional[int] = None) -> bool:
        """
        Collect evidence about a file
        
        Args:
            file_path: File to collect evidence about
            event_id: Associated event ID
            
        Returns:
            True if successful
        """
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return False
            
            # Calculate file hash
            file_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    file_hash.update(chunk)
            
            stat_info = os.stat(file_path)
            
            evidence = {
                'path': file_path,
                'size': stat_info.st_size,
                'sha256': file_hash.hexdigest(),
                'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat()
            }
            
            # Save evidence
            evidence_path = os.path.join(self.forensics_dir, 
                                        f"file_{file_hash.hexdigest()[:16]}.json")
            
            with open(evidence_path, 'w') as f:
                json.dump(evidence, f, indent=2)
            
            # Record in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO evidence (event_id, evidence_type, evidence_path, 
                                    file_hash, collected_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (event_id, 'file_metadata', evidence_path, file_hash.hexdigest(),
                 datetime.now().isoformat(), json.dumps(evidence)))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Collected file evidence for {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error collecting file evidence: {e}")
            return False
    
    def create_incident_timeline(self, hours: int = 24) -> List[Dict]:
        """
        Create a timeline of forensic events
        
        Args:
            hours: Number of hours to include
            
        Returns:
            List of events in chronological order
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff = datetime.now().timestamp() - (hours * 3600)
            cutoff_str = datetime.fromtimestamp(cutoff).isoformat()
            
            cursor.execute('''
                SELECT timestamp, event_type, severity, process_id, 
                       process_name, file_path, details
                FROM events
                WHERE timestamp >= ?
                ORDER BY timestamp ASC
            ''', (cutoff_str,))
            
            timeline = []
            for row in cursor.fetchall():
                timeline.append({
                    'timestamp': row[0],
                    'event_type': row[1],
                    'severity': row[2],
                    'process_id': row[3],
                    'process_name': row[4],
                    'file_path': row[5],
                    'details': row[6]
                })
            
            conn.close()
            logger.info(f"Created timeline with {len(timeline)} events")
            return timeline
            
        except Exception as e:
            logger.error(f"Error creating timeline: {e}")
            return []
    
    def generate_incident_report(self, event_id: int) -> Optional[str]:
        """
        Generate comprehensive incident report
        
        Args:
            event_id: Event ID to report on
            
        Returns:
            Path to report file or None
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get event details
            cursor.execute('SELECT * FROM events WHERE id = ?', (event_id,))
            event = cursor.fetchone()
            
            if not event:
                logger.error(f"Event {event_id} not found")
                return None
            
            # Get related evidence
            cursor.execute('SELECT * FROM evidence WHERE event_id = ?', (event_id,))
            evidence_list = cursor.fetchall()
            
            conn.close()
            
            # Generate report
            report = {
                'incident_id': event_id,
                'timestamp': event[1],
                'event_type': event[2],
                'severity': event[3],
                'process_id': event[4],
                'process_name': event[5],
                'file_path': event[6],
                'details': event[7],
                'evidence_collected': event[8],
                'evidence_items': len(evidence_list),
                'evidence': [
                    {
                        'type': e[2],
                        'path': e[3],
                        'hash': e[4],
                        'collected_at': e[5]
                    } for e in evidence_list
                ]
            }
            
            # Save report
            report_path = os.path.join(self.forensics_dir, 
                                      f"incident_{event_id}_report.json")
            
            # Validate report path to prevent path traversal
            if not validate_path(report_path, self.forensics_dir):
                logger.error(f"Invalid report path rejected: {report_path}")
                return None
            
            # SAFE: Ensure absolute path
            report_path = os.path.abspath(report_path)
            
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Generated incident report: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return None


if __name__ == "__main__":
    # Test forensics manager
    print("Testing Forensics Manager...")
    
    forensics = ForensicsManager()
    
    # Record test events
    print("\nRecording test events...")
    event1 = forensics.record_event("file_modified", "high", 
                                    process_id=1234, 
                                    process_name="test.exe",
                                    file_path="C:\\test.txt",
                                    details='{"action": "encrypted"}')
    
    event2 = forensics.record_event("process_started", "medium",
                                    process_id=5678,
                                    process_name="suspicious.exe")
    
    # Collect evidence
    print(f"\nCollecting file evidence...")
    test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    test_file.write("Test evidence file")
    test_file.close()
    
    forensics.collect_file_evidence(test_file.name, event1)
    
    # Create timeline
    print(f"\nCreating incident timeline...")
    timeline = forensics.create_incident_timeline(hours=24)
    print(f"Timeline events: {len(timeline)}")
    
    # Generate report
    if event1:
        print(f"\nGenerating incident report for event #{event1}...")
        report_path = forensics.generate_incident_report(event1)
        print(f"Report generated: {report_path}")
    
    # Cleanup
    os.unlink(test_file.name)
    
    print("\nForensics test complete!")
