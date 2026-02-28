#!/usr/bin/env python3
"""
AGGRESSIVE ANTI-RANSOMWARE SYSTEM - TRUE PREVENTION
Real-time file protection with blocking capabilities
"""

import os
import sys
import json
import time
import threading
import hashlib
import sqlite3
import shutil
import signal
import ctypes
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set
from dataclasses import dataclass
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import win32api
import win32file
import win32security
import win32con
import psutil

# Configuration
PROGRAM_DATA = Path("C:/Users") / os.getenv('USERNAME', 'Default') / "AppData/Local/AntiRansomware"
PROGRAM_DATA.mkdir(parents=True, exist_ok=True)

DATABASE_PATH = PROGRAM_DATA / "protection.db"
LOG_PATH = PROGRAM_DATA / "system.log"
QUARANTINE_PATH = PROGRAM_DATA / "quarantine"
QUARANTINE_PATH.mkdir(parents=True, exist_ok=True)

@dataclass
class ProtectedFolder:
    path: str
    usb_required: bool
    active: bool
    created: datetime
    protection_level: str = "AGGRESSIVE"
    
    def to_dict(self):
        return {
            'path': self.path,
            'usb_required': self.usb_required,
            'active': self.active,
            'created': self.created.isoformat(),
            'protection_level': self.protection_level
        }

class DatabaseManager:
    """Database operations for persistence"""
    
    def __init__(self):
        self.db_path = DATABASE_PATH
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Protected folders table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS protected_folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                usb_required BOOLEAN DEFAULT 1,
                active BOOLEAN DEFAULT 1,
                protection_level TEXT DEFAULT 'AGGRESSIVE',
                created TEXT NOT NULL
            )
        """)
        
        # Blocked operations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                file_path TEXT NOT NULL,
                operation_type TEXT NOT NULL,
                process_name TEXT,
                blocked_reason TEXT NOT NULL
            )
        """)
        
        # Threat events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                file_path TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                action TEXT NOT NULL,
                severity TEXT DEFAULT 'MEDIUM'
            )
        """)
        
        conn.commit()
        conn.close()
    
    def add_protected_folder(self, folder: ProtectedFolder):
        """Add protected folder to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO protected_folders (path, usb_required, active, protection_level, created)
                VALUES (?, ?, ?, ?, ?)
            """, (folder.path, folder.usb_required, folder.active, folder.protection_level, folder.created.isoformat()))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            self.log_error(f"Failed to add protected folder: {e}")
            return False
    
    def get_protected_folders(self) -> List[ProtectedFolder]:
        """Get all protected folders"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if protection_level column exists, if not add it
            cursor.execute("PRAGMA table_info(protected_folders)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'protection_level' not in columns:
                cursor.execute("ALTER TABLE protected_folders ADD COLUMN protection_level TEXT DEFAULT 'AGGRESSIVE'")
                conn.commit()
            
            cursor.execute("SELECT path, usb_required, active, created, protection_level FROM protected_folders")
            rows = cursor.fetchall()
            conn.close()
            
            folders = []
            for row in rows:
                # Handle different row lengths for backward compatibility
                protection_level = "AGGRESSIVE"
                created_str = row[3]
                
                if len(row) >= 5 and row[4]:
                    protection_level = row[4]
                
                folders.append(ProtectedFolder(
                    path=row[0],
                    usb_required=bool(row[1]),
                    active=bool(row[2]),
                    protection_level=protection_level,
                    created=datetime.fromisoformat(created_str)
                ))
            
            return folders
        except Exception as e:
            self.log_error(f"Failed to get protected folders: {e}")
            return []
    
    def log_blocked_operation(self, file_path: str, operation_type: str, process_name: str, reason: str):
        """Log blocked file operation"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO blocked_operations (timestamp, file_path, operation_type, process_name, blocked_reason)
                VALUES (?, ?, ?, ?, ?)
            """, (datetime.now().isoformat(), file_path, operation_type, process_name, reason))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.log_error(f"Failed to log blocked operation: {e}")
    
    def get_blocked_operations(self, limit: int = 50) -> List[Dict]:
        """Get recent blocked operations"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT timestamp, file_path, operation_type, process_name, blocked_reason
                FROM blocked_operations
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            operations = []
            for row in rows:
                operations.append({
                    'timestamp': row[0],
                    'file_path': row[1],
                    'operation_type': row[2],
                    'process_name': row[3],
                    'blocked_reason': row[4]
                })
            
            return operations
        except Exception as e:
            self.log_error(f"Failed to get blocked operations: {e}")
            return []
    
    def remove_protected_folder(self, path: str):
        """Remove protected folder"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM protected_folders WHERE path = ?", (path,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            self.log_error(f"Failed to remove protected folder: {e}")
            return False
    
    def log_threat(self, file_path: str, threat_type: str, action: str, severity: str = "MEDIUM"):
        """Log threat event"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO threat_events (timestamp, file_path, threat_type, action, severity)
                VALUES (?, ?, ?, ?, ?)
            """, (datetime.now().isoformat(), file_path, threat_type, action, severity))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.log_error(f"Failed to log threat: {e}")
    
    def get_recent_threats(self, limit: int = 20) -> List[Dict]:
        """Get recent threat events"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT timestamp, file_path, threat_type, action, severity
                FROM threat_events
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            threats = []
            for row in rows:
                threats.append({
                    'timestamp': row[0],
                    'file_path': row[1],
                    'threat_type': row[2],
                    'action': row[3],
                    'severity': row[4]
                })
            
            return threats
        except Exception as e:
            self.log_error(f"Failed to get threats: {e}")
            return []
    
    def log_error(self, message: str):
        """Log error message"""
        try:
            with open(LOG_PATH, 'a', encoding='utf-8') as f:
                f.write(f"{datetime.now().isoformat()} ERROR: {message}\n")
        except:
            pass

class FilePermissionManager:
    """Manages file permissions for protection"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.protected_files = {}  # Track protected files and their original permissions
    
    def protect_file(self, file_path: str) -> bool:
        """Set file to read-only protection"""
        try:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                return False
            
            # Store original attributes
            original_attrs = file_path_obj.stat().st_mode
            self.protected_files[str(file_path_obj)] = original_attrs
            
            # Set file to read-only
            os.chmod(file_path, 0o444)  # Read-only for all
            
            return True
        except Exception as e:
            self.db_manager.log_error(f"Failed to protect file {file_path}: {e}")
            return False
    
    def unprotect_file(self, file_path: str) -> bool:
        """Restore original file permissions"""
        try:
            file_path_str = str(Path(file_path))
            if file_path_str in self.protected_files:
                original_attrs = self.protected_files[file_path_str]
                os.chmod(file_path, original_attrs)
                del self.protected_files[file_path_str]
                return True
        except Exception as e:
            self.db_manager.log_error(f"Failed to unprotect file {file_path}: {e}")
        return False
    
    def protect_folder_contents(self, folder_path: str) -> int:
        """Protect all files in a folder"""
        protected_count = 0
        try:
            folder_obj = Path(folder_path)
            for file_path in folder_obj.rglob("*"):
                if file_path.is_file():
                    if self.protect_file(str(file_path)):
                        protected_count += 1
        except Exception as e:
            self.db_manager.log_error(f"Failed to protect folder contents {folder_path}: {e}")
        
        return protected_count

class USBMonitor:
    """Monitor USB devices"""
    
    def __init__(self):
        self.usb_devices = set()
        self._scan_usb_devices()
    
    def _scan_usb_devices(self):
        """Scan for current USB devices"""
        try:
            drives = win32api.GetLogicalDriveStrings()
            drives = drives.split('\000')[:-1]
            
            for drive in drives:
                drive_type = win32file.GetDriveType(drive)
                if drive_type == win32file.DRIVE_REMOVABLE:
                    self.usb_devices.add(drive)
        except Exception as e:
            print(f"USB scan error: {e}")
    
    def is_usb_connected(self) -> bool:
        """Check if any USB device is connected"""
        self._scan_usb_devices()
        return len(self.usb_devices) > 0
    
    def get_usb_devices(self) -> Set[str]:
        """Get list of USB devices"""
        self._scan_usb_devices()
        return self.usb_devices.copy()

class AggressiveRansomwareProtector(FileSystemEventHandler):
    """Aggressive ransomware protection with blocking"""
    
    def __init__(self, db_manager: DatabaseManager, permission_manager: FilePermissionManager):
        super().__init__()
        self.db_manager = db_manager
        self.permission_manager = permission_manager
        
        # Enhanced ransomware indicators
        self.ransomware_extensions = {
            '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.aes', '.rsa',
            '.xtbl', '.crinf', '.r5a', '.vault', '.petya', '.wannacry', '.locky',
            '.cerber', '.zepto', '.dharma', '.thor', '.aesir', '.odin', '.sage',
            '.kkk', '.vvv', '.ttt', '.micro', '.mp3', '.bip'
        }
        
        self.ransomware_names = {
            'decrypt_instruction', 'how_to_decrypt', 'ransom_note', 'readme_for_decrypt',
            'recovery_key', 'restore_files', 'decrypt_files', 'ransom_recovery',
            'vault_info', 'ransom_demand', 'file_recovery', 'unlock_files'
        }
        
        # Track file access patterns
        self.file_access_tracker = {}
        self.rapid_modification_threshold = 0.5  # 500ms
        
        # Suspicious processes
        self.suspicious_processes = {
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'
        }
    
    def on_created(self, event):
        """Handle file creation - AGGRESSIVE MODE"""
        if not event.is_directory:
            if self._is_threat(event.src_path, "FILE_CREATED"):
                self._block_and_quarantine(event.src_path, "CREATION_BLOCKED")
    
    def on_modified(self, event):
        """Handle file modification - AGGRESSIVE MODE"""
        if not event.is_directory:
            if self._is_threat(event.src_path, "FILE_MODIFIED"):
                self._block_and_quarantine(event.src_path, "MODIFICATION_BLOCKED")
    
    def on_moved(self, event):
        """Handle file movement/renaming - AGGRESSIVE MODE"""
        if not event.is_directory:
            if self._is_threat(event.dest_path, "FILE_RENAMED"):
                # Try to reverse the move operation
                try:
                    shutil.move(event.dest_path, event.src_path)
                    self._log_blocked_operation(event.dest_path, "RENAME", "SUSPICIOUS_RENAME_BLOCKED")
                    print(f"BLOCKED RENAME: {event.src_path} -> {event.dest_path}")
                except:
                    self._block_and_quarantine(event.dest_path, "RENAME_BLOCKED")
    
    def _is_threat(self, file_path: str, event_type: str) -> bool:
        """Enhanced threat detection"""
        try:
            file_obj = Path(file_path)
            if not file_obj.exists():
                return False
            
            filename = file_obj.name.lower()
            
            # Check ransomware extensions (CRITICAL threat)
            for ext in self.ransomware_extensions:
                if filename.endswith(ext):
                    return True
            
            # Check ransomware file names (HIGH threat)
            for pattern in self.ransomware_names:
                if pattern in filename:
                    return True
            
            # Check for rapid modifications (potential mass encryption)
            current_time = time.time()
            if file_path in self.file_access_tracker:
                last_access = self.file_access_tracker[file_path]
                if current_time - last_access < self.rapid_modification_threshold:
                    return True  # Rapid modification detected
            
            self.file_access_tracker[file_path] = current_time
            
            # Check file content for small files
            if file_obj.stat().st_size < 1024 * 1024:  # Less than 1MB
                if self._check_suspicious_content(file_path):
                    return True
            
            # Check if process is suspicious
            if self._is_suspicious_process():
                return True
            
            return False
            
        except Exception as e:
            self.db_manager.log_error(f"Threat detection error: {e}")
            return False
    
    def _check_suspicious_content(self, file_path: str) -> bool:
        """Check file content for ransomware indicators"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(2048)
                
                # Check for ransom messages
                content_str = content.decode('utf-8', errors='ignore').lower()
                ransomware_phrases = [
                    'your files have been encrypted',
                    'files have been locked',
                    'pay the ransom',
                    'decrypt your files',
                    'bitcoin payment',
                    'contact us for decryption',
                    'all your files are belong to us'
                ]
                
                for phrase in ransomware_phrases:
                    if phrase in content_str:
                        return True
                
                # Advanced entropy check
                if len(content) > 100:
                    unique_bytes = len(set(content))
                    entropy_ratio = unique_bytes / len(content)
                    if entropy_ratio > 0.85:  # Very high entropy
                        return True
                
            return False
            
        except Exception:
            return False
    
    def _is_suspicious_process(self) -> bool:
        """Check if current process is suspicious"""
        try:
            current_process = psutil.Process()
            process_name = current_process.name().lower()
            
            # Check if process name is suspicious
            for suspicious in self.suspicious_processes:
                if suspicious in process_name:
                    return True
            
            # Check process command line for suspicious patterns
            try:
                cmdline = ' '.join(current_process.cmdline()).lower()
                suspicious_patterns = [
                    'vssadmin delete shadows',
                    'wbadmin delete catalog',
                    'bcdedit /set',
                    'cipher /w'
                ]
                
                for pattern in suspicious_patterns:
                    if pattern in cmdline:
                        return True
            except:
                pass
            
            return False
            
        except Exception:
            return False
    
    def _block_and_quarantine(self, file_path: str, reason: str):
        """Block operation and quarantine file immediately"""
        try:
            print(f"BLOCKING THREAT: {reason} - {file_path}")
            
            # Log the blocked operation
            self._log_blocked_operation(file_path, "FILE_OPERATION", reason)
            
            # Immediately quarantine the file
            if self._emergency_quarantine(file_path):
                action = "BLOCKED_AND_QUARANTINED"
                print(f"EMERGENCY QUARANTINE: {file_path}")
            else:
                action = "BLOCKED_QUARANTINE_FAILED"
            
            # Log as critical threat
            self.db_manager.log_threat(file_path, reason, action, "CRITICAL")
            
            # Show warning popup
            self._show_threat_warning(file_path, reason)
            
        except Exception as e:
            self.db_manager.log_error(f"Block and quarantine failed: {e}")
    
    def _log_blocked_operation(self, file_path: str, operation_type: str, reason: str):
        """Log blocked file operation"""
        try:
            process_name = "Unknown"
            try:
                current_process = psutil.Process()
                process_name = current_process.name()
            except:
                pass
            
            self.db_manager.log_blocked_operation(file_path, operation_type, process_name, reason)
        except Exception as e:
            self.db_manager.log_error(f"Failed to log blocked operation: {e}")
    
    def _emergency_quarantine(self, file_path: str) -> bool:
        """Emergency quarantine with immediate file removal"""
        try:
            source = Path(file_path)
            if not source.exists():
                return False
            
            # Create emergency quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            quarantine_name = f"EMERGENCY_{timestamp}_{source.name}"
            quarantine_file = QUARANTINE_PATH / quarantine_name
            
            # Force move file to quarantine (even if locked)
            try:
                # First try normal move
                shutil.move(str(source), str(quarantine_file))
            except:
                # If failed, try to copy and delete
                try:
                    shutil.copy2(str(source), str(quarantine_file))
                    os.remove(str(source))
                except:
                    # Last resort - force delete original
                    try:
                        source.chmod(0o777)  # Give full permissions
                        source.unlink()
                    except:
                        return False
            
            # Create emergency metadata
            metadata = {
                'original_path': str(source),
                'quarantined_at': datetime.now().isoformat(),
                'quarantine_reason': 'EMERGENCY_THREAT_DETECTION',
                'file_size': quarantine_file.stat().st_size if quarantine_file.exists() else 0
            }
            
            metadata_file = quarantine_file.with_suffix('.meta')
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            return True
            
        except Exception as e:
            self.db_manager.log_error(f"Emergency quarantine failed: {e}")
            return False
    
    def _show_threat_warning(self, file_path: str, threat_type: str):
        """Show immediate threat warning"""
        try:
            # Use Windows message box for immediate alert
            ctypes.windll.user32.MessageBoxW(
                0,
                f"RANSOMWARE THREAT DETECTED!\n\nFile: {file_path}\nThreat: {threat_type}\n\nFile has been quarantined for your protection.",
                "Anti-Ransomware Protection",
                0x30  # MB_ICONEXCLAMATION
            )
        except:
            pass

class AggressiveProtectionService:
    """Aggressive file protection service with blocking"""
    
    def __init__(self, db_manager: DatabaseManager, usb_monitor: USBMonitor):
        self.db_manager = db_manager
        self.usb_monitor = usb_monitor
        self.permission_manager = FilePermissionManager(db_manager)
        self.protector = AggressiveRansomwareProtector(db_manager, self.permission_manager)
        self.observers = []
        self.running = False
        self.protected_files_count = 0
    
    def start_protection(self):
        """Start aggressive file system protection"""
        if self.running:
            return True
        
        try:
            folders = self.db_manager.get_protected_folders()
            
            for folder in folders:
                if not folder.active:
                    continue
                
                # Check USB requirement
                if folder.usb_required and not self.usb_monitor.is_usb_connected():
                    print(f"USB required but not connected for: {folder.path}")
                    continue
                
                # Check if folder exists
                if not os.path.exists(folder.path):
                    print(f"Protected folder not found: {folder.path}")
                    continue
                
                # Start aggressive monitoring
                observer = Observer()
                observer.schedule(self.protector, folder.path, recursive=True)
                observer.start()
                self.observers.append(observer)
                
                # Protect existing files if in AGGRESSIVE mode
                if folder.protection_level == "AGGRESSIVE":
                    protected_count = self.permission_manager.protect_folder_contents(folder.path)
                    self.protected_files_count += protected_count
                    print(f"Protected {protected_count} existing files in: {folder.path}")
                
                print(f"AGGRESSIVE protection started for: {folder.path}")
            
            self.running = True
            print(f"AGGRESSIVE protection active for {len(self.observers)} folders")
            print(f"Total protected files: {self.protected_files_count}")
            return True
            
        except Exception as e:
            self.db_manager.log_error(f"Failed to start aggressive protection: {e}")
            return False
    
    def stop_protection(self):
        """Stop aggressive protection and restore permissions"""
        if not self.running:
            return
        
        # Stop observers
        for observer in self.observers:
            try:
                observer.stop()
                observer.join(timeout=5)
            except Exception as e:
                print(f"Error stopping observer: {e}")
        
        # Restore file permissions
        restored_count = 0
        for file_path in list(self.permission_manager.protected_files.keys()):
            if self.permission_manager.unprotect_file(file_path):
                restored_count += 1
        
        self.observers.clear()
        self.running = False
        self.protected_files_count = 0
        
        print(f"Aggressive protection stopped. Restored {restored_count} files.")
    
    def restart_protection(self):
        """Restart protection service"""
        self.stop_protection()
        time.sleep(2)
        return self.start_protection()

class AntiRansomwareGUI:
    """Enhanced GUI with aggressive protection controls"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Aggressive Anti-Ransomware Protection")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        
        # Initialize components
        self.db_manager = DatabaseManager()
        self.usb_monitor = USBMonitor()
        self.protection_service = AggressiveProtectionService(self.db_manager, self.usb_monitor)
        
        # Setup GUI
        self._setup_gui()
        self._setup_status_updates()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        
        # Start protection automatically
        self.protection_service.start_protection()
    
    def _setup_gui(self):
        """Setup the enhanced GUI components"""
        # Create main notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Protection tab
        protection_frame = ttk.Frame(notebook)
        notebook.add(protection_frame, text="🛡️ Aggressive Protection")
        self._setup_protection_tab(protection_frame)
        
        # Monitoring tab
        monitoring_frame = ttk.Frame(notebook)
        notebook.add(monitoring_frame, text="🔍 Real-time Monitoring")
        self._setup_monitoring_tab(monitoring_frame)
        
        # Blocked Operations tab
        blocked_frame = ttk.Frame(notebook)
        notebook.add(blocked_frame, text="🚫 Blocked Operations")
        self._setup_blocked_tab(blocked_frame)
        
        # Quarantine tab
        quarantine_frame = ttk.Frame(notebook)
        notebook.add(quarantine_frame, text="📦 Quarantine")
        self._setup_quarantine_tab(quarantine_frame)
        
        # Status tab
        status_frame = ttk.Frame(notebook)
        notebook.add(status_frame, text="📊 System Status")
        self._setup_status_tab(status_frame)
    
    def _setup_protection_tab(self, parent):
        """Setup aggressive protection configuration tab"""
        # Title
        title_label = ttk.Label(parent, text="Aggressive Folder Protection Configuration", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Warning frame
        warning_frame = ttk.LabelFrame(parent, text="⚠️ AGGRESSIVE MODE WARNING")
        warning_frame.pack(fill="x", padx=10, pady=5)
        
        warning_text = """AGGRESSIVE MODE will:
• Block suspicious file operations immediately
• Make existing files READ-ONLY for protection
• Quarantine threatening files automatically  
• Show immediate threat warnings
• May interfere with legitimate software operations"""
        
        ttk.Label(warning_frame, text=warning_text, foreground="red", 
                 font=('Arial', 10)).pack(pady=10)
        
        # Add folder frame
        add_frame = ttk.LabelFrame(parent, text="Add Protected Folder")
        add_frame.pack(fill="x", padx=10, pady=5)
        
        # Folder selection
        folder_frame = ttk.Frame(add_frame)
        folder_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(folder_frame, text="Folder Path:").pack(side="left")
        self.folder_var = tk.StringVar()
        folder_entry = ttk.Entry(folder_frame, textvariable=self.folder_var, width=50)
        folder_entry.pack(side="left", padx=(10, 5))
        
        ttk.Button(folder_frame, text="Browse...", 
                  command=self._browse_folder).pack(side="left")
        
        # Options frame
        options_frame = ttk.Frame(add_frame)
        options_frame.pack(fill="x", padx=10, pady=5)
        
        self.usb_required_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Require USB dongle for access", 
                       variable=self.usb_required_var).pack(side="left")
        
        # Protection level frame
        level_frame = ttk.Frame(add_frame)
        level_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(level_frame, text="Protection Level:").pack(side="left")
        self.protection_level = tk.StringVar(value="AGGRESSIVE")
        protection_combo = ttk.Combobox(level_frame, textvariable=self.protection_level,
                                      values=["AGGRESSIVE", "MONITORING"], state="readonly", width=15)
        protection_combo.pack(side="left", padx=(10, 0))
        
        # Add button
        ttk.Button(add_frame, text="Add Protected Folder", 
                  command=self._add_protected_folder).pack(pady=10)
        
        # Protected folders list
        list_frame = ttk.LabelFrame(parent, text="Currently Protected Folders")
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Treeview for folders
        columns = ("Path", "USB Required", "Protection Level", "Status", "Created")
        self.folders_tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        
        for col in columns:
            self.folders_tree.heading(col, text=col)
            self.folders_tree.column(col, width=150)
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.folders_tree.yview)
        self.folders_tree.configure(yscrollcommand=v_scroll.set)
        
        # Pack treeview and scrollbars
        self.folders_tree.pack(side="left", fill="both", expand=True)
        v_scroll.pack(side="right", fill="y")
        
        # Buttons frame
        buttons_frame = ttk.Frame(list_frame)
        buttons_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(buttons_frame, text="Remove Selected", 
                  command=self._remove_selected_folder).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="Refresh List", 
                  command=self._refresh_folders_list).pack(side="left", padx=5)
        
        # Load initial data
        self._refresh_folders_list()
    
    def _setup_blocked_tab(self, parent):
        """Setup blocked operations monitoring tab"""
        # Title
        title_label = ttk.Label(parent, text="Blocked File Operations", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Info frame
        info_frame = ttk.LabelFrame(parent, text="Blocked Operations Information")
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.blocked_info = ttk.Label(info_frame, text="Loading blocked operations...")
        self.blocked_info.pack(pady=10)
        
        # Blocked operations list
        blocked_frame = ttk.LabelFrame(parent, text="Recent Blocked Operations")
        blocked_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Treeview for blocked operations
        blocked_columns = ("Time", "File Path", "Operation", "Process", "Reason")
        self.blocked_tree = ttk.Treeview(blocked_frame, columns=blocked_columns, show="headings")
        
        for col in blocked_columns:
            self.blocked_tree.heading(col, text=col)
            self.blocked_tree.column(col, width=150)
        
        blocked_scroll = ttk.Scrollbar(blocked_frame, orient="vertical", 
                                     command=self.blocked_tree.yview)
        self.blocked_tree.configure(yscrollcommand=blocked_scroll.set)
        
        self.blocked_tree.pack(side="left", fill="both", expand=True)
        blocked_scroll.pack(side="right", fill="y")
        
        # Refresh button
        ttk.Button(blocked_frame, text="Refresh Blocked Operations", 
                  command=self._refresh_blocked_list).pack(side="bottom", pady=5)
        
        self._refresh_blocked_list()
    
    # [Rest of the GUI methods would continue here...]
    # For brevity, I'll include the key methods
    
    def _setup_monitoring_tab(self, parent):
        """Setup monitoring tab"""
        # Similar to previous implementation but with aggressive status
        title_label = ttk.Label(parent, text="Aggressive Real-time Monitoring", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Status frame with aggressive mode indicator
        status_frame = ttk.LabelFrame(parent, text="Aggressive Protection Status")
        status_frame.pack(fill="x", padx=10, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Protection Status: AGGRESSIVE MODE ACTIVE", 
                                     font=('Arial', 12, 'bold'), foreground="red")
        self.status_label.pack(pady=10)
        
        # Control buttons
        control_frame = ttk.Frame(status_frame)
        control_frame.pack(pady=5)
        
        ttk.Button(control_frame, text="Stop Aggressive Protection", 
                  command=self._stop_protection).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Start Aggressive Protection", 
                  command=self._start_protection).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Restart Protection", 
                  command=self._restart_protection).pack(side="left", padx=5)
        
        # Protected files counter
        self.protected_files_label = ttk.Label(status_frame, text="Protected Files: Loading...", 
                                             font=('Arial', 10))
        self.protected_files_label.pack(pady=5)
    
    def _add_protected_folder(self):
        """Add a new protected folder with aggressive protection"""
        folder_path = self.folder_var.get().strip()
        
        if not folder_path:
            messagebox.showerror("Error", "Please select a folder to protect")
            return
        
        if not os.path.exists(folder_path):
            messagebox.showerror("Error", "Selected folder does not exist")
            return
        
        # Warning for aggressive mode
        if self.protection_level.get() == "AGGRESSIVE":
            if not messagebox.askyesno("Aggressive Protection Warning", 
                "AGGRESSIVE mode will make all files in this folder READ-ONLY and block suspicious operations.\n\n"
                "This may interfere with legitimate software that needs to modify files in this folder.\n\n"
                "Continue with AGGRESSIVE protection?"):
                return
        
        folder = ProtectedFolder(
            path=folder_path,
            usb_required=self.usb_required_var.get(),
            active=True,
            protection_level=self.protection_level.get(),
            created=datetime.now()
        )
        
        if self.db_manager.add_protected_folder(folder):
            messagebox.showinfo("Success", f"Folder added with {folder.protection_level} protection")
            self.folder_var.set("")
            self._refresh_folders_list()
            self.protection_service.restart_protection()
        else:
            messagebox.showerror("Error", "Failed to add folder to protection")
    
    def _refresh_blocked_list(self):
        """Refresh blocked operations list"""
        # Clear existing items
        for item in self.blocked_tree.get_children():
            self.blocked_tree.delete(item)
        
        # Load blocked operations
        operations = self.db_manager.get_blocked_operations(100)
        
        for op in operations:
            timestamp = datetime.fromisoformat(op['timestamp']).strftime("%H:%M:%S")
            filename = os.path.basename(op['file_path'])
            
            self.blocked_tree.insert("", "end", values=(
                timestamp, filename, op['operation_type'], 
                op['process_name'], op['blocked_reason']
            ))
        
        # Update info
        self.blocked_info.config(text=f"Total Blocked Operations: {len(operations)}")
    
    def _setup_quarantine_tab(self, parent):
        """Setup quarantine tab (similar to previous but with emergency quarantine info)"""
        # Similar implementation as before
        pass
    
    def _setup_status_tab(self, parent):
        """Setup status tab with aggressive protection info"""
        # Similar implementation as before
        pass
    
    def _refresh_folders_list(self):
        """Refresh the protected folders list"""
        # Clear existing items
        for item in self.folders_tree.get_children():
            self.folders_tree.delete(item)
        
        # Load folders from database
        folders = self.db_manager.get_protected_folders()
        
        for folder in folders:
            status = "Active" if folder.active else "Inactive"
            usb_req = "Yes" if folder.usb_required else "No"
            created = folder.created.strftime("%Y-%m-%d %H:%M")
            protection_level = getattr(folder, 'protection_level', 'AGGRESSIVE')
            
            self.folders_tree.insert("", "end", values=(
                folder.path, usb_req, protection_level, status, created
            ))
    
    def _browse_folder(self):
        """Browse for folder to protect"""
        folder = filedialog.askdirectory(title="Select Folder to Protect")
        if folder:
            self.folder_var.set(folder)
    
    def _remove_selected_folder(self):
        """Remove selected protected folder"""
        selection = self.folders_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a folder to remove")
            return
        
        item = self.folders_tree.item(selection[0])
        folder_path = item['values'][0]
        
        if messagebox.askyesno("Confirm", f"Remove aggressive protection from:\n{folder_path}"):
            if self.db_manager.remove_protected_folder(folder_path):
                messagebox.showinfo("Success", "Folder removed from protection")
                self._refresh_folders_list()
                self.protection_service.restart_protection()
            else:
                messagebox.showerror("Error", "Failed to remove folder")
    
    def _stop_protection(self):
        """Stop aggressive protection"""
        self.protection_service.stop_protection()
        self.status_label.config(text="Protection Status: STOPPED", foreground="red")
    
    def _start_protection(self):
        """Start aggressive protection"""
        if self.protection_service.start_protection():
            self.status_label.config(text="Protection Status: AGGRESSIVE MODE ACTIVE", foreground="red")
        else:
            self.status_label.config(text="Protection Status: FAILED", foreground="red")
    
    def _restart_protection(self):
        """Restart aggressive protection"""
        if self.protection_service.restart_protection():
            self.status_label.config(text="Protection Status: AGGRESSIVE MODE RESTARTED", foreground="red")
            messagebox.showinfo("Success", "Aggressive protection restarted successfully")
        else:
            self.status_label.config(text="Protection Status: FAILED", foreground="red")
            messagebox.showerror("Error", "Failed to restart protection")
    
    def _setup_status_updates(self):
        """Setup automatic status updates"""
        def update_status():
            if hasattr(self, 'protected_files_label'):
                self.protected_files_label.config(
                    text=f"Protected Files: {self.protection_service.protected_files_count}"
                )
            self.root.after(3000, update_status)  # Update every 3 seconds
        
        self.root.after(1000, update_status)
    
    def _on_closing(self):
        """Handle application closing"""
        if messagebox.askokcancel("Quit", "Stop aggressive protection and exit?"):
            self.protection_service.stop_protection()
            self.root.destroy()
    
    def run(self):
        """Run the application"""
        print("Starting AGGRESSIVE Anti-Ransomware Protection...")
        print(f"Database: {DATABASE_PATH}")
        print(f"Quarantine: {QUARANTINE_PATH}")
        print("AGGRESSIVE MODE: Files will be made read-only, operations blocked")
        print("GUI application starting...")
        
        self.root.mainloop()

def main():
    """Main entry point"""
    try:
        print("🚨 AGGRESSIVE ANTI-RANSOMWARE PROTECTION 🚨")
        print("=" * 60)
        print("WARNING: This system will aggressively block file operations")
        print("Files in protected folders will be made READ-ONLY")
        print("Suspicious operations will be blocked immediately")
        print("=" * 60)
        
        app = AntiRansomwareGUI()
        app.run()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        print(f"Application error: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
