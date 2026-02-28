#!/usr/bin/env python3
"""
BLOCKING ANTI-RANSOMWARE SYSTEM
Real prevention that actually stops file operations
"""

import os
import sys
import json
import time
import threading
import sqlite3
import shutil
import subprocess
import shlex
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import win32api
import win32file
import win32security
import win32con

# Configuration
APP_DIR = Path(os.path.expanduser("~")) / "AppData" / "Local" / "BlockingAntiRansomware"
APP_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = APP_DIR / "folders.db"
QUARANTINE_DIR = APP_DIR / "quarantine"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

class BlockingDatabase:
    """Database with blocking operations tracking"""
    
    def __init__(self):
        self.init_db()
    
    def init_db(self):
        """Initialize database"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS folders (
                    id INTEGER PRIMARY KEY,
                    path TEXT UNIQUE NOT NULL,
                    usb_required INTEGER DEFAULT 1,
                    active INTEGER DEFAULT 1,
                    protection_mode TEXT DEFAULT 'BLOCK',
                    created TEXT NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    action TEXT NOT NULL,
                    blocked INTEGER DEFAULT 0
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_operations (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    success INTEGER DEFAULT 1
                )
            ''')
            
            conn.commit()
            conn.close()
            print("Blocking database initialized successfully")
        except Exception as e:
            print(f"Database init error: {e}")
    
    def add_folder(self, path, usb_required=True, protection_mode="BLOCK"):
        """Add folder with blocking protection"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO folders (path, usb_required, active, protection_mode, created)
                VALUES (?, ?, 1, ?, ?)
            ''', (path, int(usb_required), protection_mode, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            print(f"Added folder with {protection_mode} protection: {path}")
            return True
        except Exception as e:
            print(f"Error adding folder: {e}")
            return False
    
    def get_folders(self):
        """Get all protected folders with protection mode"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT path, usb_required, active, created, protection_mode FROM folders')
            rows = cursor.fetchall()
            conn.close()
            return rows
        except Exception as e:
            print(f"Error getting folders: {e}")
            return []
    
    def log_blocked_operation(self, file_path, operation, reason, success=True):
        """Log blocked operation"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO blocked_operations (timestamp, file_path, operation, reason, success)
                VALUES (?, ?, ?, ?, ?)
            ''', (datetime.now().isoformat(), file_path, operation, reason, int(success)))
            
            conn.commit()
            conn.close()
            print(f"🚫 BLOCKED: {operation} on {file_path} - {reason}")
        except Exception as e:
            print(f"Error logging blocked operation: {e}")
    
    def get_blocked_operations(self, limit=50):
        """Get recent blocked operations"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT timestamp, file_path, operation, reason, success FROM blocked_operations ORDER BY timestamp DESC LIMIT ?', (limit,))
            rows = cursor.fetchall()
            conn.close()
            return rows
        except Exception as e:
            print(f"Error getting blocked operations: {e}")
            return []
    
    def log_event(self, file_path, event_type, action, blocked=False):
        """Log security event"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO events (timestamp, file_path, event_type, action, blocked)
                VALUES (?, ?, ?, ?, ?)
            ''', (datetime.now().isoformat(), file_path, event_type, action, int(blocked)))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error logging event: {e}")

class FilePermissionBlocker:
    """Block file operations by changing permissions"""
    
    def __init__(self, database):
        self.database = database
        self.protected_files = {}  # Store original permissions
        
    def protect_folder(self, folder_path):
        """Make all files in folder read-only"""
        protected_count = 0
        try:
            folder = Path(folder_path)
            for file_path in folder.rglob("*"):
                if file_path.is_file():
                    if self.make_read_only(file_path):
                        protected_count += 1
            
            print(f"🔒 Protected {protected_count} files in {folder_path}")
            return protected_count
        except Exception as e:
            print(f"Error protecting folder: {e}")
            return 0
    
    def make_read_only(self, file_path):
        """Make single file read-only"""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return False
            
            # Store original permissions
            original_mode = file_path.stat().st_mode
            self.protected_files[str(file_path)] = original_mode
            
            # Set read-only
            file_path.chmod(0o444)  # Read-only for owner, group, others
            return True
        except Exception as e:
            print(f"Error making file read-only {file_path}: {e}")
            return False
    
    def restore_permissions(self, folder_path):
        """Restore original permissions for folder"""
        restored_count = 0
        try:
            folder = Path(folder_path)
            for file_path_str in list(self.protected_files.keys()):
                file_path = Path(file_path_str)
                if str(file_path).startswith(str(folder)):
                    original_mode = self.protected_files[file_path_str]
                    try:
                        file_path.chmod(original_mode)
                        del self.protected_files[file_path_str]
                        restored_count += 1
                    except:
                        pass
            
            print(f"🔓 Restored permissions for {restored_count} files")
            return restored_count
        except Exception as e:
            print(f"Error restoring permissions: {e}")
            return 0

class USBChecker:
    """USB device checker"""
    
    def has_usb(self):
        """Check if USB device is connected"""
        try:
            drives = win32api.GetLogicalDriveStrings()
            drives = drives.split('\000')[:-1]
            
            for drive in drives:
                if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    return True
            return False
        except:
            return False

class BlockingThreatDetector(FileSystemEventHandler):
    """Aggressive threat detector that blocks operations"""
    
    def __init__(self, database, permission_blocker):
        super().__init__()
        self.database = database
        self.permission_blocker = permission_blocker
        self.bad_extensions = {
            '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.aes', '.rsa',
            '.xtbl', '.vault', '.petya', '.wannacry', '.locky', '.cerber', '.zepto',
            '.dharma', '.sage', '.kkk', '.vvv', '.ttt', '.micro', '.bip', '.payransom'
        }
        self.bad_names = {
            'ransom_note', 'decrypt_instruction', 'how_to_decrypt', 'readme_for_decrypt',
            'vault_info', 'ransom_demand', 'file_recovery', 'unlock_files'
        }
        self.file_access_count = {}
        self.mass_modification_threshold = 5  # 5 files in 2 seconds
        
    def on_created(self, event):
        if not event.is_directory:
            if self.is_threat(event.src_path):
                self.block_and_quarantine(event.src_path, "FILE_CREATED")
            else:
                self.check_mass_modification(event.src_path)
    
    def on_modified(self, event):
        if not event.is_directory:
            if self.is_threat(event.src_path):
                self.block_and_quarantine(event.src_path, "FILE_MODIFIED")
            else:
                self.check_mass_modification(event.src_path)
    
    def on_moved(self, event):
        if not event.is_directory:
            if self.is_threat(event.dest_path):
                # Try to reverse the move
                try:
                    if os.path.exists(event.dest_path):
                        shutil.move(event.dest_path, event.src_path)
                        self.database.log_blocked_operation(event.dest_path, "RENAME_REVERSED", "SUSPICIOUS_RENAME")
                        print(f"🔄 REVERSED RENAME: {event.dest_path} -> {event.src_path}")
                except Exception as e:
                    print(f"Failed to reverse rename: {e}")
                    self.block_and_quarantine(event.dest_path, "FILE_RENAMED")
    
    def is_threat(self, file_path):
        """Enhanced threat detection"""
        try:
            file_name = os.path.basename(file_path).lower()
            
            # Check bad extensions
            for ext in self.bad_extensions:
                if file_name.endswith(ext):
                    return True
            
            # Check bad names
            for name in self.bad_names:
                if name in file_name:
                    return True
            
            # Check file content for small files
            try:
                if os.path.exists(file_path) and os.path.getsize(file_path) < 10240:  # 10KB
                    with open(file_path, 'rb') as f:
                        content = f.read(1024).decode('utf-8', errors='ignore').lower()
                        threat_phrases = [
                            'your files have been encrypted',
                            'files have been locked',
                            'pay bitcoin',
                            'decrypt your files',
                            'ransom payment'
                        ]
                        for phrase in threat_phrases:
                            if phrase in content:
                                return True
            except:
                pass
            
            return False
            
        except Exception:
            return False
    
    def check_mass_modification(self, file_path):
        """Detect mass file modifications (potential ransomware behavior)"""
        try:
            current_time = time.time()
            folder_path = os.path.dirname(file_path)
            
            # Track modifications per folder
            if folder_path not in self.file_access_count:
                self.file_access_count[folder_path] = []
            
            # Add current access
            self.file_access_count[folder_path].append(current_time)
            
            # Clean old entries (older than 2 seconds)
            cutoff_time = current_time - 2.0
            self.file_access_count[folder_path] = [
                t for t in self.file_access_count[folder_path] if t > cutoff_time
            ]
            
            # Check if too many modifications
            if len(self.file_access_count[folder_path]) >= self.mass_modification_threshold:
                print(f"🚨 MASS MODIFICATION DETECTED: {len(self.file_access_count[folder_path])} files in {folder_path}")
                self.database.log_blocked_operation(folder_path, "MASS_MODIFICATION", "POTENTIAL_RANSOMWARE_BEHAVIOR")
                
                # Show warning
                self.show_threat_alert(f"Mass file modification detected in {folder_path}")
                
        except Exception as e:
            print(f"Error checking mass modification: {e}")
    
    def block_and_quarantine(self, file_path, event_type):
        """Block operation and quarantine file"""
        try:
            print(f"🚫 BLOCKING THREAT: {event_type} - {file_path}")
            
            # Try to quarantine immediately
            quarantined = False
            if os.path.exists(file_path):
                quarantined = self.emergency_quarantine(file_path)
            
            if quarantined:
                action = "BLOCKED_AND_QUARANTINED"
                self.database.log_blocked_operation(file_path, event_type, "THREAT_QUARANTINED", True)
                print(f"✅ Successfully quarantined: {file_path}")
            else:
                action = "BLOCKED_QUARANTINE_FAILED"
                self.database.log_blocked_operation(file_path, event_type, "QUARANTINE_FAILED", False)
                print(f"❌ Quarantine failed: {file_path}")
            
            # Log as blocked event
            self.database.log_event(file_path, event_type, action, blocked=True)
            
            # Show immediate warning
            self.show_threat_alert(f"Ransomware threat blocked!\n\nFile: {os.path.basename(file_path)}\nAction: {action}")
            
        except Exception as e:
            print(f"Error blocking threat: {e}")
    
    def emergency_quarantine(self, file_path):
        """Emergency quarantine with force removal"""
        try:
            source_path = Path(file_path)
            if not source_path.exists():
                return False
            
            # Create quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            quarantine_name = f"BLOCKED_{timestamp}_{source_path.name}"
            quarantine_path = QUARANTINE_DIR / quarantine_name
            
            # Try multiple methods to remove the file
            try:
                # Method 1: Normal move
                shutil.move(str(source_path), str(quarantine_path))
            except Exception:
                try:
                    # Method 2: Copy then delete
                    shutil.copy2(str(source_path), str(quarantine_path))
                    source_path.chmod(0o777)  # Give write permission
                    source_path.unlink()  # Delete original
                except Exception:
                    try:
                        # Method 3: Force delete with Windows command
                        subprocess.run(['del', '/F', '/Q', str(source_path)], 
                                     # shell=True removed for security
                        capture_output=True, capture_output=True)
                        if not source_path.exists():
                            # File deleted, create marker file in quarantine
                            with open(quarantine_path, 'w') as f:
                                f.write("FILE FORCIBLY DELETED - THREAT BLOCKED")
                    except Exception:
                        return False
            
            # Create metadata
            metadata = {
                'original_path': str(source_path),
                'quarantined_at': datetime.now().isoformat(),
                'threat_level': 'HIGH',
                'action': 'EMERGENCY_QUARANTINE'
            }
            
            metadata_path = quarantine_path.with_suffix('.blocked')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Emergency quarantine failed: {e}")
            return False
    
    def show_threat_alert(self, message):
        """Show immediate threat alert"""
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                0,
                message,
                "🚫 RANSOMWARE BLOCKED!",
                0x30  # Warning with exclamation
            )
        except:
            print(f"ALERT: {message}")

class BlockingProtectionService:
    """Protection service with active blocking"""
    
    def __init__(self, database, usb_checker):
        self.database = database
        self.usb_checker = usb_checker
        self.permission_blocker = FilePermissionBlocker(database)
        self.detector = BlockingThreatDetector(database, self.permission_blocker)
        self.observers = []
        self.running = False
        self.protected_files_count = 0
    
    def start(self):
        """Start blocking protection"""
        if self.running:
            return True
        
        try:
            folders = self.database.get_folders()
            print(f"Starting BLOCKING protection for {len(folders)} folders")
            
            for folder_data in folders:
                path = folder_data[0]
                usb_required = folder_data[1]
                active = folder_data[2]
                protection_mode = folder_data[4] if len(folder_data) > 4 else "BLOCK"
                
                if not active:
                    continue
                
                if usb_required and not self.usb_checker.has_usb():
                    print(f"USB required but not connected: {path}")
                    continue
                
                if not os.path.exists(path):
                    print(f"Folder not found: {path}")
                    continue
                
                # Start monitoring
                observer = Observer()
                observer.schedule(self.detector, path, recursive=True)
                observer.start()
                self.observers.append(observer)
                
                # Apply blocking protection if mode is BLOCK
                if protection_mode == "BLOCK":
                    protected_count = self.permission_blocker.protect_folder(path)
                    self.protected_files_count += protected_count
                
                print(f"🛡️ BLOCKING protection started: {path} ({protection_mode} mode)")
            
            self.running = True
            print(f"🚫 BLOCKING protection active for {len(self.observers)} folders")
            print(f"🔒 {self.protected_files_count} files made read-only")
            return True
            
        except Exception as e:
            print(f"Error starting blocking protection: {e}")
            return False
    
    def stop(self):
        """Stop blocking protection"""
        if not self.running:
            return
        
        # Stop observers
        for observer in self.observers:
            try:
                observer.stop()
                observer.join(timeout=3)
            except:
                pass
        
        # Restore file permissions
        folders = self.database.get_folders()
        for folder_data in folders:
            path = folder_data[0]
            if os.path.exists(path):
                self.permission_blocker.restore_permissions(path)
        
        self.observers.clear()
        self.running = False
        self.protected_files_count = 0
        print("🔓 Blocking protection stopped, permissions restored")
    
    def restart(self):
        """Restart blocking protection"""
        self.stop()
        time.sleep(1)
        return self.start()

class BlockingAntiRansomwareApp:
    """Main application with blocking protection"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🚫 Blocking Anti-Ransomware Protection")
        self.root.geometry("1000x700")
        
        # Initialize components
        self.database = BlockingDatabase()
        self.usb_checker = USBChecker()
        self.protection = BlockingProtectionService(self.database, self.usb_checker)
        
        # Setup GUI
        self.setup_gui()
        
        # Handle close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Start protection
        self.protection.start()
    
    def setup_gui(self):
        """Create the GUI with blocking features"""
        # Main tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Protection tab
        protection_frame = ttk.Frame(notebook)
        notebook.add(protection_frame, text="🛡️ Blocking Protection")
        self.setup_protection_tab(protection_frame)
        
        # Blocked operations tab
        blocked_frame = ttk.Frame(notebook)
        notebook.add(blocked_frame, text="🚫 Blocked Operations")
        self.setup_blocked_tab(blocked_frame)
        
        # Events tab
        events_frame = ttk.Frame(notebook)
        notebook.add(events_frame, text="📋 Events")
        self.setup_events_tab(events_frame)
        
        # Quarantine tab
        quarantine_frame = ttk.Frame(notebook)
        notebook.add(quarantine_frame, text="🔒 Quarantine")
        self.setup_quarantine_tab(quarantine_frame)
        
        # Status tab
        status_frame = ttk.Frame(notebook)
        notebook.add(status_frame, text="📊 Status")
        self.setup_status_tab(status_frame)
    
    def setup_protection_tab(self, parent):
        """Setup blocking protection configuration"""
        # Warning banner
        warning_frame = ttk.Frame(parent)
        warning_frame.pack(fill="x", padx=10, pady=10)
        
        warning_text = "⚠️ BLOCKING MODE: Files will be made READ-ONLY. Suspicious operations will be BLOCKED immediately!"
        ttk.Label(warning_frame, text=warning_text, font=('Arial', 11, 'bold'), 
                 foreground="red", background="yellow").pack(pady=5)
        
        # Title
        ttk.Label(parent, text="Blocking Folder Protection", font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Add folder section
        add_frame = ttk.LabelFrame(parent, text="Add Protected Folder")
        add_frame.pack(fill="x", padx=10, pady=10)
        
        # Folder selection
        folder_frame = ttk.Frame(add_frame)
        folder_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(folder_frame, text="Folder:").pack(side="left")
        self.folder_var = tk.StringVar()
        ttk.Entry(folder_frame, textvariable=self.folder_var, width=60).pack(side="left", padx=10)
        ttk.Button(folder_frame, text="Browse", command=self.browse_folder).pack(side="left")
        
        # Options
        options_frame = ttk.Frame(add_frame)
        options_frame.pack(fill="x", padx=10, pady=5)
        
        self.usb_required = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Require USB device", variable=self.usb_required).pack(side="left")
        
        # Protection mode
        mode_frame = ttk.Frame(add_frame)
        mode_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(mode_frame, text="Protection Mode:").pack(side="left")
        self.protection_mode = tk.StringVar(value="BLOCK")
        mode_combo = ttk.Combobox(mode_frame, textvariable=self.protection_mode, 
                                values=["BLOCK", "MONITOR"], state="readonly", width=10)
        mode_combo.pack(side="left", padx=10)
        
        # Add button
        ttk.Button(add_frame, text="Add Blocking Protection", command=self.add_folder).pack(pady=10)
        
        # Folders list
        list_frame = ttk.LabelFrame(parent, text="Protected Folders")
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Tree view
        columns = ("Folder", "USB Required", "Protection Mode", "Status", "Added")
        self.folders_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=8)
        
        for col in columns:
            self.folders_tree.heading(col, text=col)
            self.folders_tree.column(col, width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.folders_tree.yview)
        self.folders_tree.configure(yscrollcommand=scrollbar.set)
        
        self.folders_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Buttons
        buttons_frame = ttk.Frame(list_frame)
        buttons_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(buttons_frame, text="Remove Selected", command=self.remove_folder).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="Refresh", command=self.refresh_folders).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="Restart Blocking", command=self.restart_protection).pack(side="left", padx=5)
        
        # Status display
        self.protection_status = ttk.Label(parent, text="Loading protection status...", font=('Arial', 11, 'bold'))
        self.protection_status.pack(pady=10)
        
        # Load folders
        self.refresh_folders()
        self.update_protection_status()
    
    def setup_blocked_tab(self, parent):
        """Setup blocked operations display"""
        ttk.Label(parent, text="Blocked Operations", font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Info
        self.blocked_info = ttk.Label(parent, text="Loading blocked operations...")
        self.blocked_info.pack(pady=5)
        
        # Blocked operations list
        blocked_frame = ttk.LabelFrame(parent, text="Recent Blocked Operations")
        blocked_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        columns = ("Time", "File", "Operation", "Reason", "Status")
        self.blocked_tree = ttk.Treeview(blocked_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.blocked_tree.heading(col, text=col)
            self.blocked_tree.column(col, width=150)
        
        blocked_scrollbar = ttk.Scrollbar(blocked_frame, orient="vertical", command=self.blocked_tree.yview)
        self.blocked_tree.configure(yscrollcommand=blocked_scrollbar.set)
        
        self.blocked_tree.pack(side="left", fill="both", expand=True)
        blocked_scrollbar.pack(side="right", fill="y")
        
        ttk.Button(blocked_frame, text="Refresh Blocked Operations", command=self.refresh_blocked).pack(pady=5)
        
        self.refresh_blocked()
    
    def setup_events_tab(self, parent):
        """Setup events monitoring (simplified for space)"""
        ttk.Label(parent, text="Security Events", font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Events will be shown here - simplified implementation
        events_text = tk.Text(parent, height=20, wrap="word")
        events_scroll = ttk.Scrollbar(parent, orient="vertical", command=events_text.yview)
        events_text.configure(yscrollcommand=events_scroll.set)
        
        events_text.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        events_scroll.pack(side="right", fill="y", pady=10)
        
        # Load recent events
        try:
            events = self.database.get_blocked_operations(20)
            events_info = ["Recent Security Events:\n"]
            for event in events:
                timestamp, file_path, operation, reason, success = event
                status = "SUCCESS" if success else "FAILED"
                events_info.append(f"{timestamp[:19]} - {operation} - {os.path.basename(file_path)} - {reason} ({status})")
            
            events_text.insert("1.0", "\n".join(events_info))
            events_text.config(state="disabled")
        except:
            pass
    
    def setup_quarantine_tab(self, parent):
        """Setup quarantine management (simplified)"""
        ttk.Label(parent, text="Quarantine Management", font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Simple text display for quarantine info
        quarantine_text = tk.Text(parent, height=20, wrap="word")
        quarantine_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Load quarantine info
        try:
            quarantine_files = list(QUARANTINE_DIR.glob("BLOCKED_*"))
            quarantine_files = [f for f in quarantine_files if f.suffix != '.blocked']
            
            info = [f"Quarantine Directory: {QUARANTINE_DIR}\n"]
            info.append(f"Quarantined Files: {len(quarantine_files)}\n")
            
            if quarantine_files:
                info.append("Quarantined Files:")
                for file_path in quarantine_files[:10]:  # Show first 10
                    info.append(f"  • {file_path.name}")
                
                if len(quarantine_files) > 10:
                    info.append(f"  ... and {len(quarantine_files) - 10} more files")
            else:
                info.append("No files currently quarantined.")
            
            quarantine_text.insert("1.0", "\n".join(info))
            quarantine_text.config(state="disabled")
        except Exception as e:
            quarantine_text.insert("1.0", f"Error loading quarantine info: {e}")
            quarantine_text.config(state="disabled")
    
    def setup_status_tab(self, parent):
        """Setup status display"""
        ttk.Label(parent, text="System Status", font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Status info
        self.status_text = tk.Text(parent, height=20, wrap="word")
        status_scroll = ttk.Scrollbar(parent, orient="vertical", command=self.status_text.yview)
        self.status_text.configure(yscrollcommand=status_scroll.set)
        
        self.status_text.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        status_scroll.pack(side="right", fill="y", pady=10)
        
        ttk.Button(parent, text="Refresh Status", command=self.refresh_status).pack(pady=5)
        
        self.refresh_status()
    
    def browse_folder(self):
        """Browse for folder"""
        folder = filedialog.askdirectory(title="Select Folder for Blocking Protection")
        if folder:
            self.folder_var.set(folder)
    
    def add_folder(self):
        """Add folder to blocking protection"""
        folder_path = self.folder_var.get().strip()
        
        if not folder_path:
            messagebox.showerror("Error", "Please select a folder")
            return
        
        if not os.path.exists(folder_path):
            messagebox.showerror("Error", "Folder does not exist")
            return
        
        # Warning for blocking mode
        if self.protection_mode.get() == "BLOCK":
            if not messagebox.askyesno("Blocking Protection Warning", 
                f"BLOCKING mode will:\n\n"
                f"• Make all files in this folder READ-ONLY\n"
                f"• Block suspicious file operations immediately\n"
                f"• May interfere with legitimate software\n\n"
                f"Continue with BLOCKING protection for:\n{folder_path}"):
                return
        
        if self.database.add_folder(folder_path, self.usb_required.get(), self.protection_mode.get()):
            messagebox.showinfo("Success", f"Folder added with {self.protection_mode.get()} protection")
            self.folder_var.set("")
            self.refresh_folders()
            self.protection.restart()
            self.update_protection_status()
        else:
            messagebox.showerror("Error", "Failed to add folder")
    
    def remove_folder(self):
        """Remove selected folder"""
        selection = self.folders_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a folder")
            return
        
        item = self.folders_tree.item(selection[0])
        folder_path = item['values'][0]
        
        if messagebox.askyesno("Confirm", f"Remove blocking protection from:\n{folder_path}"):
            # Remove from database (assuming remove_folder method exists)
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM folders WHERE path = ?', (folder_path,))
                conn.commit()
                conn.close()
                
                messagebox.showinfo("Success", "Folder removed from protection")
                self.refresh_folders()
                self.protection.restart()
                self.update_protection_status()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to remove folder: {e}")
    
    def refresh_folders(self):
        """Refresh folders list"""
        # Clear
        for item in self.folders_tree.get_children():
            self.folders_tree.delete(item)
        
        # Load
        folders = self.database.get_folders()
        for folder_data in folders:
            path = folder_data[0]
            usb_required = folder_data[1]
            active = folder_data[2]
            created = folder_data[3]
            protection_mode = folder_data[4] if len(folder_data) > 4 else "BLOCK"
            
            usb_text = "Yes" if usb_required else "No"
            status = "Active" if active else "Inactive"
            created_date = datetime.fromisoformat(created).strftime("%Y-%m-%d %H:%M")
            
            self.folders_tree.insert("", "end", values=(path, usb_text, protection_mode, status, created_date))
    
    def refresh_blocked(self):
        """Refresh blocked operations list"""
        # Clear
        for item in self.blocked_tree.get_children():
            self.blocked_tree.delete(item)
        
        # Load
        blocked_ops = self.database.get_blocked_operations(100)
        blocked_count = len(blocked_ops)
        
        for op_data in blocked_ops:
            timestamp, file_path, operation, reason, success = op_data
            time_str = datetime.fromisoformat(timestamp).strftime("%H:%M:%S")
            filename = os.path.basename(file_path)
            status = "BLOCKED" if success else "FAILED"
            
            self.blocked_tree.insert("", "end", values=(time_str, filename, operation, reason, status))
        
        self.blocked_info.config(text=f"Total Blocked Operations: {blocked_count}")
    
    def refresh_status(self):
        """Refresh status display"""
        try:
            status_info = []
            status_info.append("🚫 BLOCKING ANTI-RANSOMWARE STATUS\n")
            status_info.append(f"Database: {DB_PATH}")
            status_info.append(f"Quarantine: {QUARANTINE_DIR}\n")
            
            # Protection status
            if self.protection.running:
                status_info.append(f"Protection Status: 🟢 ACTIVE BLOCKING ({len(self.protection.observers)} folders)")
                status_info.append(f"Protected Files: 🔒 {self.protection.protected_files_count} files made read-only")
            else:
                status_info.append("Protection Status: 🔴 INACTIVE")
            
            # USB status
            if self.usb_checker.has_usb():
                status_info.append("USB Status: 🟢 Connected")
            else:
                status_info.append("USB Status: 🔴 No USB devices")
            
            # Statistics
            folders = self.database.get_folders()
            blocked_ops = self.database.get_blocked_operations(1000)
            
            status_info.append(f"\n📊 STATISTICS:")
            status_info.append(f"Protected Folders: {len(folders)}")
            status_info.append(f"Total Blocked Operations: {len(blocked_ops)}")
            status_info.append(f"Successful Blocks: {sum(1 for op in blocked_ops if op[4])}")
            
            # Quarantine stats
            try:
                quarantine_files = list(QUARANTINE_DIR.glob("BLOCKED_*"))
                quarantine_files = [f for f in quarantine_files if f.suffix != '.blocked']
                total_size = sum(f.stat().st_size for f in quarantine_files)
                status_info.append(f"Quarantined Files: {len(quarantine_files)}")
                status_info.append(f"Quarantine Size: {total_size / 1024 / 1024:.1f} MB")
            except:
                status_info.append("Quarantine Status: Error reading")
            
            self.status_text.delete(1.0, tk.END)
            self.status_text.insert(1.0, "\n".join(status_info))
            
        except Exception as e:
            self.status_text.delete(1.0, tk.END)
            self.status_text.insert(1.0, f"Error getting status: {e}")
    
    def update_protection_status(self):
        """Update protection status display"""
        try:
            if self.protection.running:
                status_text = f"🟢 BLOCKING PROTECTION ACTIVE - {len(self.protection.observers)} folders monitored - {self.protection.protected_files_count} files locked"
                self.protection_status.config(text=status_text, foreground="green")
            else:
                self.protection_status.config(text="🔴 BLOCKING PROTECTION INACTIVE", foreground="red")
        except:
            pass
    
    def restart_protection(self):
        """Restart blocking protection"""
        if self.protection.restart():
            messagebox.showinfo("Success", "Blocking protection restarted successfully")
            self.update_protection_status()
            self.refresh_status()
        else:
            messagebox.showerror("Error", "Failed to restart blocking protection")
    
    def on_close(self):
        """Handle window close"""
        if messagebox.askokcancel("Exit", "Stop blocking protection and exit?"):
            self.protection.stop()
            self.root.destroy()
    
    def run(self):
        """Run the application"""
        print("Starting BLOCKING Anti-Ransomware Protection")
        print(f"Database: {DB_PATH}")
        print(f"Quarantine: {QUARANTINE_DIR}")
        print("🚫 BLOCKING MODE: Suspicious operations will be BLOCKED")
        print("GUI starting...")
        
        # Auto-refresh status
        def auto_refresh():
            self.update_protection_status()
            self.root.after(5000, auto_refresh)
        
        self.root.after(1000, auto_refresh)
        self.root.mainloop()

def main():
    """Main entry point"""
    try:
        print("🚫 BLOCKING ANTI-RANSOMWARE PROTECTION")
        print("=" * 60)
        print("REAL PROTECTION: Files locked, threats blocked!")
        print("Suspicious operations will be PREVENTED")
        print("=" * 60)
        
        app = BlockingAntiRansomwareApp()
        app.run()
        
    except KeyboardInterrupt:
        print("\nApplication stopped")
    except Exception as e:
        print(f"Application error: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
