"""
Real Anti-Ransomware File Monitor
Real-time file system monitoring for ransomware detection

Features:
- Monitor file modifications, creations, deletions, renames
- Integration with detection engine for threat analysis
- Configurable watch paths and exclusions
- Event logging and alerting
"""

import os
import time
import logging
import threading
from typing import List, Set, Callable, Optional
from datetime import datetime
from pathlib import Path
import sys

# Try to import watchdog, fall back to polling if unavailable
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logging.warning("watchdog not available, using polling mode")

# Import detection engine
try:
    from detection_engine import BehavioralAnalysisEngine, FileEvent, ThreatScore
except ImportError:
    # Create dummy classes if detection_engine not available
    class FileEvent:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    class BehavioralAnalysisEngine:
        def analyze_file_event(self, event):
            return type('obj', (object,), {'total_score': 0, 'get_risk_level': lambda: 'LOW'})()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RansomwareFileHandler(FileSystemEventHandler):
    """File system event handler for ransomware detection"""
    
    def __init__(self, detection_engine: BehavioralAnalysisEngine,
                 on_threat_detected: Optional[Callable] = None):
        super().__init__()
        self.detection_engine = detection_engine
        self.on_threat_detected = on_threat_detected
        self.monitored_events = 0
        self.threats_detected = 0
        
        # Track file operations for DELETE_ON_CLOSE pattern detection
        self.recent_deletes: Set[str] = set()
        self.recent_creates: Set[str] = set()
    
    def _get_process_info(self) -> tuple:
        """Get current process ID and name"""
        try:
            import psutil
            process = psutil.Process()
            return process.pid, process.name()
        except:
            return os.getpid(), "unknown"
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate file entropy"""
        try:
            return self.detection_engine.calculate_file_entropy(file_path)
        except:
            return 0.0
    
    def _analyze_event(self, event_type: str, src_path: str, 
                      dest_path: Optional[str] = None):
        """Analyze file event for threats"""
        try:
            self.monitored_events += 1
            
            # Get process info
            pid, process_name = self._get_process_info()
            
            # Get file size
            file_size = 0
            try:
                if os.path.exists(src_path):
                    file_size = os.path.getsize(src_path)
            except:
                pass
            
            # Calculate entropy for new/modified files
            entropy = 0.0
            if event_type in ['created', 'modified'] and os.path.exists(src_path):
                entropy = self._calculate_entropy(src_path)
            
            # Create file event
            file_event = FileEvent(
                timestamp=datetime.now(),
                path=src_path,
                event_type=event_type,
                process_id=pid,
                process_name=process_name,
                old_path=dest_path if event_type == 'renamed' else None,
                file_size=file_size,
                entropy=entropy
            )
            
            # Analyze with detection engine
            score = self.detection_engine.analyze_file_event(file_event)
            
            # Log based on risk level
            risk_level = score.get_risk_level()
            if risk_level in ['HIGH', 'CRITICAL']:
                self.threats_detected += 1
                logger.warning(
                    f"THREAT DETECTED [{risk_level}]: {src_path} "
                    f"(Score: {score.total_score}) - Process: {process_name} (PID: {pid})"
                )
                
                # Trigger callback
                if self.on_threat_detected:
                    self.on_threat_detected(file_event, score)
            elif risk_level == 'MEDIUM':
                logger.info(
                    f"Suspicious activity [{risk_level}]: {src_path} "
                    f"(Score: {score.total_score})"
                )
            
            # Track for pattern detection
            if event_type == 'deleted':
                self.recent_deletes.add(src_path)
            elif event_type == 'created':
                self.recent_creates.add(src_path)
            
        except Exception as e:
            logger.error(f"Error analyzing event for {src_path}: {e}")
    
    def on_modified(self, event: FileSystemEvent):
        """Handle file modification"""
        if not event.is_directory:
            self._analyze_event('modified', event.src_path)
    
    def on_created(self, event: FileSystemEvent):
        """Handle file creation"""
        if not event.is_directory:
            self._analyze_event('created', event.src_path)
    
    def on_deleted(self, event: FileSystemEvent):
        """Handle file deletion"""
        if not event.is_directory:
            self._analyze_event('deleted', event.src_path)
    
    def on_moved(self, event: FileSystemEvent):
        """Handle file rename/move"""
        if not event.is_directory:
            # Treat as rename which is suspicious for ransomware
            self._analyze_event('renamed', event.dest_path, event.src_path)


class FileMonitor:
    """Real-time file system monitor"""
    
    def __init__(self, watch_paths: Optional[List[str]] = None,
                 exclude_paths: Optional[List[str]] = None,
                 on_threat_detected: Optional[Callable] = None):
        """
        Initialize file monitor
        
        Args:
            watch_paths: List of paths to monitor (default: user directories)
            exclude_paths: List of paths to exclude from monitoring
            on_threat_detected: Callback function for threat detection
        """
        self.watch_paths = watch_paths or self._get_default_watch_paths()
        self.exclude_paths = exclude_paths or self._get_default_exclude_paths()
        self.on_threat_detected = on_threat_detected
        
        # Initialize detection engine
        self.detection_engine = BehavioralAnalysisEngine()
        
        # Create event handler
        self.event_handler = RansomwareFileHandler(
            self.detection_engine,
            on_threat_detected
        )
        
        # Observer for file system monitoring
        self.observer = None
        self.is_running = False
        self.monitor_thread = None
        
        logger.info(f"File Monitor initialized with {len(self.watch_paths)} watch paths")
    
    def _get_default_watch_paths(self) -> List[str]:
        """Get default paths to monitor"""
        paths = []
        
        # User home directory
        home = str(Path.home())
        paths.append(home)
        
        # Common user data directories
        common_dirs = [
            os.path.join(home, 'Documents'),
            os.path.join(home, 'Desktop'),
            os.path.join(home, 'Pictures'),
            os.path.join(home, 'Downloads'),
        ]
        
        for dir_path in common_dirs:
            if os.path.exists(dir_path):
                paths.append(dir_path)
        
        return paths
    
    def _get_default_exclude_paths(self) -> List[str]:
        """Get default paths to exclude from monitoring"""
        exclude = []
        
        # System directories
        if sys.platform == 'win32':
            exclude.extend([
                'C:\\Windows',
                'C:\\Program Files',
                'C:\\Program Files (x86)',
                'C:\\ProgramData\\Microsoft',
                os.path.join(Path.home(), 'AppData', 'Local', 'Temp'),
            ])
        else:
            exclude.extend([
                '/proc',
                '/sys',
                '/dev',
                '/tmp',
            ])
        
        return exclude
    
    def _should_exclude(self, path: str) -> bool:
        """Check if path should be excluded from monitoring"""
        path = os.path.abspath(path)
        for exclude_path in self.exclude_paths:
            if path.startswith(exclude_path):
                return True
        return False
    
    def start(self):
        """Start monitoring file system"""
        if self.is_running:
            logger.warning("File monitor already running")
            return
        
        if WATCHDOG_AVAILABLE:
            self._start_watchdog()
        else:
            self._start_polling()
        
        logger.info("File monitor started")
    
    def _start_watchdog(self):
        """Start monitoring using watchdog library"""
        self.observer = Observer()
        
        for path in self.watch_paths:
            if os.path.exists(path) and not self._should_exclude(path):
                try:
                    self.observer.schedule(
                        self.event_handler,
                        path,
                        recursive=True
                    )
                    logger.info(f"Watching: {path}")
                except Exception as e:
                    logger.error(f"Error watching {path}: {e}")
        
        self.observer.start()
        self.is_running = True
    
    def _start_polling(self):
        """Start monitoring using polling (fallback)"""
        self.is_running = True
        self.monitor_thread = threading.Thread(
            target=self._polling_monitor,
            daemon=True
        )
        self.monitor_thread.start()
        logger.info("File monitor started in polling mode")
    
    def _polling_monitor(self):
        """Polling-based file monitoring"""
        file_states = {}  # path -> (mtime, size)
        
        while self.is_running:
            try:
                for watch_path in self.watch_paths:
                    if not os.path.exists(watch_path):
                        continue
                    
                    for root, dirs, files in os.walk(watch_path):
                        # Skip excluded directories
                        if self._should_exclude(root):
                            dirs.clear()
                            continue
                        
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            
                            try:
                                stat = os.stat(filepath)
                                current_state = (stat.st_mtime, stat.st_size)
                                
                                if filepath in file_states:
                                    old_state = file_states[filepath]
                                    if current_state != old_state:
                                        # File modified
                                        self.event_handler._analyze_event(
                                            'modified',
                                            filepath
                                        )
                                else:
                                    # New file
                                    self.event_handler._analyze_event(
                                        'created',
                                        filepath
                                    )
                                
                                file_states[filepath] = current_state
                            
                            except (OSError, FileNotFoundError):
                                # File deleted or inaccessible
                                if filepath in file_states:
                                    self.event_handler._analyze_event(
                                        'deleted',
                                        filepath
                                    )
                                    del file_states[filepath]
                
                # Check for deleted files
                for filepath in list(file_states.keys()):
                    if not os.path.exists(filepath):
                        self.event_handler._analyze_event('deleted', filepath)
                        del file_states[filepath]
                
                time.sleep(2)  # Poll every 2 seconds
            
            except Exception as e:
                logger.error(f"Error in polling monitor: {e}")
                time.sleep(5)
    
    def stop(self):
        """Stop monitoring"""
        self.is_running = False
        
        if self.observer:
            self.observer.stop()
            self.observer.join()
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        logger.info("File monitor stopped")
    
    def get_statistics(self) -> dict:
        """Get monitoring statistics"""
        stats = self.detection_engine.get_statistics()
        stats.update({
            'monitored_events': self.event_handler.monitored_events,
            'threats_detected': self.event_handler.threats_detected,
            'watch_paths': len(self.watch_paths),
            'exclude_paths': len(self.exclude_paths),
        })
        return stats


def threat_detected_callback(file_event, threat_score):
    """Example callback for threat detection"""
    print(f"\n⚠️  THREAT DETECTED!")
    print(f"   File: {file_event.path}")
    print(f"   Process: {file_event.process_name} (PID: {file_event.process_id})")
    print(f"   Risk Level: {threat_score.get_risk_level()}")
    print(f"   Score: {threat_score.total_score}")
    print(f"   Event Type: {file_event.event_type}")
    if threat_score.details:
        print(f"   Details:")
        for detail in threat_score.details:
            print(f"     - {detail}")


if __name__ == "__main__":
    print("=" * 60)
    print("Real Anti-Ransomware File Monitor")
    print("=" * 60)
    
    # Create monitor with callback
    monitor = FileMonitor(on_threat_detected=threat_detected_callback)
    
    print(f"\n[*] Monitoring {len(monitor.watch_paths)} paths:")
    for path in monitor.watch_paths:
        print(f"    - {path}")
    
    print(f"\n[*] Excluding {len(monitor.exclude_paths)} paths:")
    for path in monitor.exclude_paths[:5]:  # Show first 5
        print(f"    - {path}")
    if len(monitor.exclude_paths) > 5:
        print(f"    ... and {len(monitor.exclude_paths) - 5} more")
    
    print("\n[*] Starting file monitor...")
    print("    Press Ctrl+C to stop\n")
    
    try:
        monitor.start()
        
        # Keep running
        while True:
            time.sleep(10)
            stats = monitor.get_statistics()
            print(f"\r[{datetime.now().strftime('%H:%M:%S')}] "
                  f"Events: {stats['monitored_events']} | "
                  f"Threats: {stats['threats_detected']} | "
                  f"Processes: {stats['monitored_processes']}", end='')
    
    except KeyboardInterrupt:
        print("\n\n[*] Stopping file monitor...")
        monitor.stop()
        
        final_stats = monitor.get_statistics()
        print("\n" + "=" * 60)
        print("Final Statistics:")
        print("=" * 60)
        for key, value in final_stats.items():
            print(f"  {key}: {value}")
        
        print("\n✅ File monitor stopped")
