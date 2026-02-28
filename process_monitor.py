"""
Real Anti-Ransomware Process Monitor
Monitor running processes for suspicious behavior

Features:
- Track process creation and termination
- Detect suspicious process spawning patterns
- Monitor process file access patterns
- Integration with detection engine
"""

import os
import time
import logging
import threading
from typing import Dict, List, Set, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict

try:
    import psutil
    import wmi
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logging.warning("psutil/wmi not available, limited functionality")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class ProcessInfo:
    """Process information"""
    pid: int
    name: str
    exe_path: str
    cmdline: str
    parent_pid: int
    create_time: datetime
    username: str = "unknown"
    suspicious_score: int = 0
    file_operations: int = 0


class ProcessMonitor:
    """Monitor system processes for ransomware behavior"""
    
    def __init__(self, on_suspicious_process: Optional[Callable] = None):
        """Initialize process monitor"""
        self.on_suspicious_process = on_suspicious_process
        self.is_running = False
        self.monitor_thread = None
        
        # Process tracking
        self.processes: Dict[int, ProcessInfo] = {}
        self.suspicious_processes: Set[int] = set()
        self.terminated_processes: List[ProcessInfo] = []
        
        # Suspicious patterns
        self.suspicious_names = {
            'encrypt.exe', 'locker.exe', 'cryptolocker.exe',
            'wannacry.exe', 'wcry.exe', 'locky.exe', 'cerber.exe'
        }
        
        self.suspicious_paths = {
            'temp', 'appdata\\local\\temp', 'downloads'
        }
        
        logger.info("Process Monitor initialized")
    
    def _is_suspicious_process(self, proc_info: ProcessInfo) -> tuple:
        """Check if process exhibits suspicious behavior"""
        score = 0
        reasons = []
        
        # Check process name
        if proc_info.name.lower() in self.suspicious_names:
            score += 100
            reasons.append(f"Known malicious process name: {proc_info.name}")
            return score, reasons
        
        # Check if spawned from suspicious location
        exe_lower = proc_info.exe_path.lower()
        for susp_path in self.suspicious_paths:
            if susp_path in exe_lower:
                score += 30
                reasons.append(f"Executed from suspicious location: {susp_path}")
                break
        
        # Check if downloaded recently
        if 'downloads' in exe_lower:
            score += 20
            reasons.append("Executed from Downloads folder")
        
        # Check command line for suspicious patterns
        cmdline_lower = proc_info.cmdline.lower()
        if any(pattern in cmdline_lower for pattern in ['encrypt', 'decrypt', 'crypto', 'ransom']):
            score += 25
            reasons.append("Suspicious command line parameters")
        
        # Check if process has no digital signature (would need additional implementation)
        # For now, just check if it's in system directories
        if not exe_lower.startswith('c:\\windows') and not exe_lower.startswith('c:\\program files'):
            score += 10
            reasons.append("Not in protected system directory")
        
        return score, reasons
    
    def _get_process_info(self, proc: 'psutil.Process') -> Optional[ProcessInfo]:
        """Get detailed process information"""
        try:
            proc_info = ProcessInfo(
                pid=proc.pid,
                name=proc.name(),
                exe_path=proc.exe(),
                cmdline=' '.join(proc.cmdline()),
                parent_pid=proc.ppid(),
                create_time=datetime.fromtimestamp(proc.create_time())
            )
            
            try:
                proc_info.username = proc.username()
            except:
                pass
            
            return proc_info
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as e:
            logger.debug(f"Error getting process info for PID {proc.pid}: {e}")
            return None
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        if not PSUTIL_AVAILABLE:
            logger.error("psutil not available, cannot monitor processes")
            return
        
        known_pids = set()
        
        while self.is_running:
            try:
                current_pids = set()
                
                for proc in psutil.process_iter(['pid']):
                    try:
                        pid = proc.pid
                        current_pids.add(pid)
                        
                        # New process detected
                        if pid not in known_pids and pid not in self.processes:
                            proc_info = self._get_process_info(proc)
                            if proc_info:
                                self.processes[pid] = proc_info
                                
                                # Check if suspicious
                                score, reasons = self._is_suspicious_process(proc_info)
                                proc_info.suspicious_score = score
                                
                                if score >= 30:
                                    self.suspicious_processes.add(pid)
                                    logger.warning(
                                        f"Suspicious process detected: {proc_info.name} "
                                        f"(PID: {pid}, Score: {score})"
                                    )
                                    
                                    if self.on_suspicious_process:
                                        self.on_suspicious_process(proc_info, score, reasons)
                                else:
                                    logger.debug(f"New process: {proc_info.name} (PID: {pid})")
                    
                    except Exception as e:
                        logger.debug(f"Error processing process: {e}")
                        continue
                
                # Detect terminated processes
                terminated = known_pids - current_pids
                for pid in terminated:
                    if pid in self.processes:
                        proc_info = self.processes.pop(pid)
                        self.terminated_processes.append(proc_info)
                        logger.debug(f"Process terminated: {proc_info.name} (PID: {pid})")
                    
                    if pid in self.suspicious_processes:
                        self.suspicious_processes.remove(pid)
                
                known_pids = current_pids
                
                # Cleanup old terminated processes (keep last 1000)
                if len(self.terminated_processes) > 1000:
                    self.terminated_processes = self.terminated_processes[-1000:]
                
                time.sleep(2)  # Check every 2 seconds
            
            except Exception as e:
                logger.error(f"Error in process monitor loop: {e}")
                time.sleep(5)
    
    def start(self):
        """Start process monitoring"""
        if self.is_running:
            logger.warning("Process monitor already running")
            return
        
        if not PSUTIL_AVAILABLE:
            logger.error("Cannot start process monitor: psutil not available")
            return
        
        self.is_running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )
        self.monitor_thread.start()
        
        logger.info("Process monitor started")
    
    def stop(self):
        """Stop process monitoring"""
        self.is_running = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        logger.info("Process monitor stopped")
    
    def get_process_tree(self, pid: int) -> List[ProcessInfo]:
        """Get process tree for a given PID"""
        tree = []
        
        def get_children(parent_pid):
            children = [p for p in self.processes.values() if p.parent_pid == parent_pid]
            for child in children:
                tree.append(child)
                get_children(child.pid)
        
        if pid in self.processes:
            tree.append(self.processes[pid])
            get_children(pid)
        
        return tree
    
    def get_suspicious_processes(self) -> List[ProcessInfo]:
        """Get list of currently suspicious processes"""
        return [
            self.processes[pid]
            for pid in self.suspicious_processes
            if pid in self.processes
        ]
    
    def kill_process(self, pid: int, force: bool = False) -> bool:
        """Kill a process by PID"""
        if not PSUTIL_AVAILABLE:
            logger.error("Cannot kill process: psutil not available")
            return False
        
        try:
            proc = psutil.Process(pid)
            if force:
                proc.kill()
            else:
                proc.terminate()
            
            logger.info(f"Process {'killed' if force else 'terminated'}: PID {pid}")
            return True
        
        except psutil.NoSuchProcess:
            logger.warning(f"Process not found: PID {pid}")
            return False
        except psutil.AccessDenied:
            logger.error(f"Access denied to kill process: PID {pid}")
            return False
        except Exception as e:
            logger.error(f"Error killing process {pid}: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get monitoring statistics"""
        return {
            'active_processes': len(self.processes),
            'suspicious_processes': len(self.suspicious_processes),
            'terminated_processes': len(self.terminated_processes),
            'total_monitored': len(self.processes) + len(self.terminated_processes)
        }


def suspicious_process_callback(proc_info: ProcessInfo, score: int, reasons: List[str]):
    """Example callback for suspicious process detection"""
    print(f"\n⚠️  SUSPICIOUS PROCESS DETECTED!")
    print(f"   Name: {proc_info.name}")
    print(f"   PID: {proc_info.pid}")
    print(f"   Path: {proc_info.exe_path}")
    print(f"   Score: {score}")
    print(f"   Reasons:")
    for reason in reasons:
        print(f"     - {reason}")


if __name__ == "__main__":
    print("=" * 60)
    print("Real Anti-Ransomware Process Monitor")
    print("=" * 60)
    
    if not PSUTIL_AVAILABLE:
        print("\n❌ psutil not installed. Install with: pip install psutil")
        exit(1)
    
    monitor = ProcessMonitor(on_suspicious_process=suspicious_process_callback)
    
    print("\n[*] Starting process monitor...")
    print("    Press Ctrl+C to stop\n")
    
    try:
        monitor.start()
        
        while True:
            time.sleep(10)
            stats = monitor.get_statistics()
            print(f"\r[{datetime.now().strftime('%H:%M:%S')}] "
                  f"Active: {stats['active_processes']} | "
                  f"Suspicious: {stats['suspicious_processes']} | "
                  f"Total: {stats['total_monitored']}", end='')
    
    except KeyboardInterrupt:
        print("\n\n[*] Stopping process monitor...")
        monitor.stop()
        
        print("\n" + "=" * 60)
        print("Suspicious Processes Detected:")
        print("=" * 60)
        
        susp_procs = monitor.get_suspicious_processes()
        if susp_procs:
            for proc in susp_procs:
                print(f"\n  {proc.name} (PID: {proc.pid})")
                print(f"    Path: {proc.exe_path}")
                print(f"    Score: {proc.suspicious_score}")
        else:
            print("  None")
        
        print("\n✅ Process monitor stopped")
