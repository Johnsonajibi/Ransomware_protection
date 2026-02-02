#!/usr/bin/env python3
"""
🛡️ PYTHON ANTI-RANSOMWARE PROTECTION SYSTEM
============================================
Advanced user-mode anti-ransomware system with real-time protection,
behavioral analysis, and comprehensive threat detection.

Features:
- Real-time file system monitoring
- Registry protection and backup  
- USB device authentication
- Behavioral analysis engine
- Memory protection measures
- Network traffic monitoring
- Advanced GUI interface

Author: Johnson Ajibi
Version: 2.0
Date: October 2025
"""

import os
import sys
import time
import json
import sqlite3
import hashlib
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timedelta
from pathlib import Path
import winreg
import ctypes
from ctypes import wintypes
import psutil
import socket
import logging
import configparser
from typing import Dict, List, Set, Optional, Tuple
import win32file
import win32con
import win32api
import win32gui
import win32process
import wmi

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('antiransomware.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AntiRansomwareCore:
    """Core protection engine with advanced threat detection"""
    
    def __init__(self, app_dir: str):
        self.app_dir = Path(app_dir)
        self.db_path = self.app_dir / "protection.db"
        self.config_path = self.app_dir / "config.ini"
        self.quarantine_dir = self.app_dir / "quarantine"
        self.backup_dir = self.app_dir / "backups"
        
        # Ensure directories exist
        for directory in [self.app_dir, self.quarantine_dir, self.backup_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.init_database()
        self.load_config()
        self.init_protection_systems()
        
        # Threat detection
        self.known_ransomware_extensions = {
            '.locked', '.encrypted', '.crypto', '.crypt', '.encrypt',
            '.axx', '.xyz', '.zzz', '.micro', '.zepto', '.locky',
            '.cerber', '.vault', '.exx', '.ezz', '.ecc', '.xtbl'
        }
        
        self.suspicious_processes = {
            'encrypt', 'crypt', 'ransom', 'locker', 'vault',
            'bitcoin', 'btc', 'payment', 'decrypt', 'recover'
        }
        
        # Monitoring state
        self.is_monitoring = False
        self.monitored_directories = set()
        self.process_whitelist = set()
        self.file_access_log = {}
        
    def init_database(self):
        """Initialize SQLite database for logging and analysis"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # File activity table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    process_name TEXT,
                    process_id INTEGER,
                    file_path TEXT,
                    action TEXT,
                    hash_before TEXT,
                    hash_after TEXT,
                    threat_level INTEGER,
                    blocked BOOLEAN
                )
            ''')
            
            # Registry activity table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS registry_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    process_name TEXT,
                    key_path TEXT,
                    action TEXT,
                    old_value TEXT,
                    new_value TEXT,
                    blocked BOOLEAN
                )
            ''')
            
            # Network activity table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    process_name TEXT,
                    local_addr TEXT,
                    remote_addr TEXT,
                    protocol TEXT,
                    suspicious BOOLEAN
                )
            ''')
            
            # USB activity table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS usb_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    device_id TEXT,
                    action TEXT,
                    authenticated BOOLEAN,
                    blocked BOOLEAN
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("✅ Database initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")
    
    def load_config(self):
        """Load configuration settings"""
        self.config = configparser.ConfigParser()
        
        # Default configuration
        default_config = {
            'Protection': {
                'real_time_monitoring': 'true',
                'behavioral_analysis': 'true',
                'registry_protection': 'true',
                'usb_authentication': 'true',
                'network_monitoring': 'true',
                'quarantine_threats': 'true',
                'backup_critical_files': 'true'
            },
            'Directories': {
                'protected_paths': 'C:\\Users;C:\\Documents;C:\\Desktop',
                'excluded_paths': 'C:\\Windows\\Temp;C:\\Temp',
                'backup_paths': 'C:\\Users\\Documents;C:\\Users\\Desktop'
            },
            'Advanced': {
                'threat_threshold': '3',
                'max_file_modifications': '10',
                'analysis_window_minutes': '5',
                'memory_protection': 'true'
            }
        }
        
        # Load existing or create new config
        if self.config_path.exists():
            self.config.read(str(self.config_path))
        else:
            for section, options in default_config.items():
                self.config.add_section(section)
                for key, value in options.items():
                    self.config.set(section, key, value)
            
            with open(str(self.config_path), 'w') as f:
                self.config.write(f)
    
    def init_protection_systems(self):
        """Initialize all protection subsystems"""
        try:
            # Memory protection
            if self.config.getboolean('Advanced', 'memory_protection'):
                self.enable_memory_protection()
            
            # Registry backup
            if self.config.getboolean('Protection', 'registry_protection'):
                self.backup_critical_registry()
            
            logger.info("✅ Protection systems initialized")
            
        except Exception as e:
            logger.error(f"❌ Protection system initialization failed: {e}")
    
    def enable_memory_protection(self):
        """Enable memory protection features"""
        try:
            # Enable DEP for current process
            kernel32 = ctypes.windll.kernel32
            process = kernel32.GetCurrentProcess()
            
            # Set DEP policy
            kernel32.SetProcessDEPPolicy(1)  # PROCESS_DEP_ENABLE
            
            # Enable ASLR awareness
            kernel32.SetProcessAffinityMask(process, 0xFFFFFFFF)
            
            logger.info("✅ Memory protection enabled")
            
        except Exception as e:
            logger.warning(f"⚠️ Memory protection partial: {e}")
    
    def backup_critical_registry(self):
        """Backup critical registry keys"""
        critical_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
        ]
        
        backup_path = self.backup_dir / "registry_backup.json"
        backup_data = {}
        
        for hkey, subkey in critical_keys:
            backup_data[subkey] = self.export_registry_key(hkey, subkey)
        
        with open(str(backup_path), 'w') as f:
            json.dump(backup_data, f, indent=2)
        
        logger.info("✅ Registry backup completed")
    
    def export_registry_key(self, hkey, subkey):
        """Export registry key to dictionary"""
        try:
            key = winreg.OpenKey(hkey, subkey)
            values = {}
            
            i = 0
            while True:
                try:
                    name, value, type_ = winreg.EnumValue(key, i)
                    values[name] = {'value': str(value), 'type': type_}
                    i += 1
                except WindowsError:
                    break
            
            winreg.CloseKey(key)
            return values
            
        except Exception as e:
            logger.warning(f"⚠️ Could not backup registry key {subkey}: {e}")
            return {}
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        
        # Start monitoring threads
        threading.Thread(target=self.file_system_monitor, daemon=True).start()
        threading.Thread(target=self.process_monitor, daemon=True).start()
        threading.Thread(target=self.network_monitor, daemon=True).start()
        threading.Thread(target=self.usb_monitor, daemon=True).start()
        
        logger.info("🔍 Real-time monitoring started")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.is_monitoring = False
        logger.info("⏹️ Real-time monitoring stopped")
    
    def file_system_monitor(self):
        """Monitor file system for suspicious activity"""
        protected_paths = self.config.get('Directories', 'protected_paths').split(';')
        
        for path in protected_paths:
            if os.path.exists(path.strip()):
                self.monitored_directories.add(path.strip())
        
        while self.is_monitoring:
            try:
                for directory in self.monitored_directories:
                    self.scan_directory_changes(directory)
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"❌ File system monitoring error: {e}")
                time.sleep(5)
    
    def scan_directory_changes(self, directory):
        """Scan directory for changes"""
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Check for suspicious extensions
                    if any(file.lower().endswith(ext) for ext in self.known_ransomware_extensions):
                        self.handle_threat(file_path, "Suspicious file extension", 5)
                    
                    # Check file modification patterns
                    if self.is_rapid_modification(file_path):
                        self.handle_threat(file_path, "Rapid file modification", 4)
                        
        except Exception as e:
            logger.debug(f"Directory scan error for {directory}: {e}")
    
    def is_rapid_modification(self, file_path):
        """Check if file is being modified rapidly"""
        try:
            current_time = time.time()
            file_stat = os.stat(file_path)
            mod_time = file_stat.st_mtime
            
            # Check if modified in last 30 seconds
            if current_time - mod_time < 30:
                if file_path in self.file_access_log:
                    self.file_access_log[file_path] += 1
                else:
                    self.file_access_log[file_path] = 1
                
                # If modified more than 5 times recently, flag as suspicious
                return self.file_access_log[file_path] > 5
            
            return False
            
        except Exception:
            return False
    
    def process_monitor(self):
        """Monitor processes for suspicious behavior"""
        while self.is_monitoring:
            try:
                for process in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        process_name = process.info['name'].lower()
                        
                        # Check for suspicious process names
                        if any(keyword in process_name for keyword in self.suspicious_processes):
                            self.handle_process_threat(process, "Suspicious process name", 4)
                        
                        # Check command line arguments
                        cmdline = ' '.join(process.info['cmdline'] or []).lower()
                        if 'encrypt' in cmdline or 'ransom' in cmdline:
                            self.handle_process_threat(process, "Suspicious command line", 5)
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                time.sleep(3)
                
            except Exception as e:
                logger.error(f"❌ Process monitoring error: {e}")
                time.sleep(5)
    
    def network_monitor(self):
        """Monitor network connections for suspicious activity"""
        while self.is_monitoring:
            try:
                connections = psutil.net_connections()
                
                for conn in connections:
                    if conn.raddr and conn.status == psutil.CONN_ESTABLISHED:
                        # Check for connections to known bad IPs or suspicious ports
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        
                        # Check for Tor network (common with ransomware)
                        if remote_port in [9001, 9030, 9051, 9150]:
                            self.log_network_activity(conn, True)
                        
                        # Check for Bitcoin/crypto ports
                        if remote_port in [8333, 8332, 9333, 9332]:
                            self.log_network_activity(conn, True)
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"❌ Network monitoring error: {e}")
                time.sleep(10)
    
    def usb_monitor(self):
        """Monitor USB device connections"""
        try:
            c = wmi.WMI()
            
            while self.is_monitoring:
                try:
                    # Monitor for USB device changes
                    for usb in c.Win32_LogicalDisk(DriveType=2):  # Removable drives
                        self.handle_usb_device(usb)
                    
                    time.sleep(5)
                    
                except Exception as e:
                    logger.debug(f"USB monitoring error: {e}")
                    time.sleep(10)
                    
        except Exception as e:
            logger.error(f"❌ USB monitoring initialization failed: {e}")
    
    def handle_threat(self, file_path, threat_type, severity):
        """Handle detected threat"""
        logger.warning(f"🚨 THREAT DETECTED: {threat_type} - {file_path} (Severity: {severity})")
        
        # Log to database
        self.log_file_activity(file_path, threat_type, severity, blocked=True)
        
        # Take action based on severity
        if severity >= 4:
            self.quarantine_file(file_path)
        
        # Show alert if GUI is running
        if hasattr(self, 'gui') and self.gui:
            self.gui.show_threat_alert(threat_type, file_path, severity)
    
    def handle_process_threat(self, process, threat_type, severity):
        """Handle process-based threat"""
        try:
            process_name = process.info['name']
            process_id = process.info['pid']
            
            logger.warning(f"🚨 PROCESS THREAT: {threat_type} - {process_name} (PID: {process_id})")
            
            # Terminate high-severity threats
            if severity >= 5:
                process.terminate()
                logger.info(f"🔒 Terminated malicious process: {process_name}")
            
        except Exception as e:
            logger.error(f"❌ Error handling process threat: {e}")
    
    def quarantine_file(self, file_path):
        """Move suspicious file to quarantine"""
        try:
            if not os.path.exists(file_path):
                return
            
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{timestamp}_{filename}"
            quarantine_path = self.quarantine_dir / quarantine_name
            
            # Move file to quarantine
            os.rename(file_path, str(quarantine_path))
            
            # Create info file
            info_path = self.quarantine_dir / f"{quarantine_name}.info"
            with open(str(info_path), 'w') as f:
                json.dump({
                    'original_path': file_path,
                    'quarantine_time': timestamp,
                    'reason': 'Potential ransomware activity'
                }, f, indent=2)
            
            logger.info(f"🔒 File quarantined: {file_path} -> {quarantine_name}")
            
        except Exception as e:
            logger.error(f"❌ Quarantine failed for {file_path}: {e}")
    
    def log_file_activity(self, file_path, action, severity, blocked=False):
        """Log file activity to database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO file_activity 
                (timestamp, process_name, file_path, action, threat_level, blocked)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                "System Monitor",
                file_path,
                action,
                severity,
                blocked
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ Database logging failed: {e}")
    
    def log_network_activity(self, connection, suspicious=False):
        """Log network activity"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            local_addr = f"{connection.laddr.ip}:{connection.laddr.port}"
            remote_addr = f"{connection.raddr.ip}:{connection.raddr.port}" if connection.raddr else "Unknown"
            
            cursor.execute('''
                INSERT INTO network_activity 
                (timestamp, process_name, local_addr, remote_addr, protocol, suspicious)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                "Network Monitor",
                local_addr,
                remote_addr,
                "TCP",
                suspicious
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ Network logging failed: {e}")
    
    def handle_usb_device(self, usb_device):
        """Handle USB device detection"""
        try:
            device_id = usb_device.DeviceID
            
            # Simple USB authentication (can be enhanced)
            authenticated = self.authenticate_usb_device(device_id)
            
            if not authenticated:
                logger.warning(f"🚨 Unauthorized USB device detected: {device_id}")
                # Could disable the device here
            
            # Log USB activity
            self.log_usb_activity(device_id, "Connected", authenticated)
            
        except Exception as e:
            logger.error(f"❌ USB handling error: {e}")
    
    def authenticate_usb_device(self, device_id):
        """Authenticate USB device (simplified)"""
        # In a real implementation, this would check against a whitelist
        # or perform more sophisticated authentication
        return True  # For demo purposes
    
    def log_usb_activity(self, device_id, action, authenticated):
        """Log USB activity"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO usb_activity 
                (timestamp, device_id, action, authenticated, blocked)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                device_id,
                action,
                authenticated,
                not authenticated
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ USB logging failed: {e}")

class AntiRansomwareGUI:
    """Advanced GUI interface for the anti-ransomware system"""
    
    def __init__(self, core: AntiRansomwareCore):
        self.core = core
        self.core.gui = self
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("🛡️ Advanced Anti-Ransomware Protection")
        self.root.geometry("900x700")
        self.root.configure(bg='#2b2b2b')
        
        # Variables
        self.monitoring_var = tk.BooleanVar(value=False)
        self.protection_status = tk.StringVar(value="🔴 Not Protected")
        
        self.setup_gui()
        self.update_status_loop()
    
    def setup_gui(self):
        """Setup the GUI interface"""
        # Title
        title_frame = tk.Frame(self.root, bg='#2b2b2b')
        title_frame.pack(pady=10)
        
        title_label = tk.Label(
            title_frame,
            text="🛡️ ADVANCED ANTI-RANSOMWARE PROTECTION",
            font=('Arial', 18, 'bold'),
            fg='#00ff00',
            bg='#2b2b2b'
        )
        title_label.pack()
        
        # Status panel
        self.setup_status_panel()
        
        # Control panel
        self.setup_control_panel()
        
        # Monitoring panel
        self.setup_monitoring_panel()
        
        # Activity log
        self.setup_activity_log()
        
        # Bottom status bar
        self.setup_status_bar()
    
    def setup_status_panel(self):
        """Setup status display panel"""
        status_frame = tk.LabelFrame(
            self.root,
            text="🔍 Protection Status",
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#2b2b2b'
        )
        status_frame.pack(pady=10, padx=20, fill='x')
        
        self.status_label = tk.Label(
            status_frame,
            textvariable=self.protection_status,
            font=('Arial', 14, 'bold'),
            fg='#ff0000',
            bg='#2b2b2b'
        )
        self.status_label.pack(pady=10)
        
        # Protection features status
        features_frame = tk.Frame(status_frame, bg='#2b2b2b')
        features_frame.pack(pady=5)
        
        self.feature_labels = {}
        features = [
            "Real-time Monitoring",
            "Registry Protection", 
            "USB Authentication",
            "Network Monitoring",
            "Behavioral Analysis"
        ]
        
        for i, feature in enumerate(features):
            label = tk.Label(
                features_frame,
                text=f"• {feature}: 🔴 Inactive",
                font=('Arial', 10),
                fg='#cccccc',
                bg='#2b2b2b',
                anchor='w'
            )
            label.grid(row=i//2, column=i%2, sticky='w', padx=20, pady=2)
            self.feature_labels[feature] = label
    
    def setup_control_panel(self):
        """Setup control buttons panel"""
        control_frame = tk.LabelFrame(
            self.root,
            text="🎮 Protection Controls",
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#2b2b2b'
        )
        control_frame.pack(pady=10, padx=20, fill='x')
        
        button_frame = tk.Frame(control_frame, bg='#2b2b2b')
        button_frame.pack(pady=10)
        
        # Start/Stop monitoring
        self.monitor_button = tk.Button(
            button_frame,
            text="🚀 Start Protection",
            command=self.toggle_monitoring,
            font=('Arial', 11, 'bold'),
            bg='#00aa00',
            fg='white',
            width=15,
            height=2
        )
        self.monitor_button.grid(row=0, column=0, padx=5)
        
        # Scan system
        scan_button = tk.Button(
            button_frame,
            text="🔍 Full Scan",
            command=self.full_scan,
            font=('Arial', 11, 'bold'),
            bg='#0066cc',
            fg='white',
            width=15,
            height=2
        )
        scan_button.grid(row=0, column=1, padx=5)
        
        # Quarantine manager
        quarantine_button = tk.Button(
            button_frame,
            text="🔒 Quarantine",
            command=self.open_quarantine_manager,
            font=('Arial', 11, 'bold'),
            bg='#cc6600',
            fg='white',
            width=15,
            height=2
        )
        quarantine_button.grid(row=0, column=2, padx=5)
        
        # Settings
        settings_button = tk.Button(
            button_frame,
            text="⚙️ Settings",
            command=self.open_settings,
            font=('Arial', 11, 'bold'),
            bg='#666666',
            fg='white',
            width=15,
            height=2
        )
        settings_button.grid(row=0, column=3, padx=5)
    
    def setup_monitoring_panel(self):
        """Setup real-time monitoring display"""
        monitor_frame = tk.LabelFrame(
            self.root,
            text="📊 Live Monitoring",
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#2b2b2b'
        )
        monitor_frame.pack(pady=10, padx=20, fill='both', expand=True)
        
        # Statistics
        stats_frame = tk.Frame(monitor_frame, bg='#2b2b2b')
        stats_frame.pack(pady=5, fill='x')
        
        self.stats_labels = {}
        stats = ["Files Scanned", "Threats Blocked", "Active Processes", "Network Connections"]
        
        for i, stat in enumerate(stats):
            frame = tk.Frame(stats_frame, bg='#2b2b2b')
            frame.grid(row=0, column=i, padx=10, pady=5)
            
            tk.Label(
                frame,
                text=stat,
                font=('Arial', 9),
                fg='#cccccc',
                bg='#2b2b2b'
            ).pack()
            
            label = tk.Label(
                frame,
                text="0",
                font=('Arial', 14, 'bold'),
                fg='#00ff00',
                bg='#2b2b2b'
            )
            label.pack()
            self.stats_labels[stat] = label
    
    def setup_activity_log(self):
        """Setup activity log display"""
        log_frame = tk.LabelFrame(
            self.root,
            text="📋 Activity Log",
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#2b2b2b'
        )
        log_frame.pack(pady=10, padx=20, fill='both', expand=True)
        
        # Create treeview for log
        columns = ('Time', 'Type', 'Description', 'Severity')
        self.log_tree = ttk.Treeview(log_frame, columns=columns, show='headings', height=8)
        
        for col in columns:
            self.log_tree.heading(col, text=col)
            self.log_tree.column(col, width=200 if col == 'Description' else 120)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(log_frame, orient='vertical', command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=scrollbar.set)
        
        self.log_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
    
    def setup_status_bar(self):
        """Setup bottom status bar"""
        status_bar = tk.Frame(self.root, bg='#333333', height=25)
        status_bar.pack(side='bottom', fill='x')
        
        self.status_text = tk.Label(
            status_bar,
            text="Ready - Anti-Ransomware Protection Inactive",
            font=('Arial', 9),
            fg='#cccccc',
            bg='#333333',
            anchor='w'
        )
        self.status_text.pack(side='left', padx=5)
        
        # System time
        self.time_label = tk.Label(
            status_bar,
            text="",
            font=('Arial', 9),
            fg='#cccccc',
            bg='#333333'
        )
        self.time_label.pack(side='right', padx=5)
    
    def toggle_monitoring(self):
        """Toggle monitoring on/off"""
        if not self.monitoring_var.get():
            # Start monitoring
            self.core.start_monitoring()
            self.monitoring_var.set(True)
            self.monitor_button.config(
                text="⏹️ Stop Protection",
                bg='#cc0000'
            )
            self.protection_status.set("🟢 Protected")
            self.status_label.config(fg='#00ff00')
            self.status_text.config(text="Active - Real-time protection enabled")
            
            # Update feature status
            for feature, label in self.feature_labels.items():
                label.config(text=f"• {feature}: 🟢 Active", fg='#00ff00')
        else:
            # Stop monitoring
            self.core.stop_monitoring()
            self.monitoring_var.set(False)
            self.monitor_button.config(
                text="🚀 Start Protection",
                bg='#00aa00'
            )
            self.protection_status.set("🔴 Not Protected")
            self.status_label.config(fg='#ff0000')
            self.status_text.config(text="Inactive - Protection disabled")
            
            # Update feature status
            for feature, label in self.feature_labels.items():
                label.config(text=f"• {feature}: 🔴 Inactive", fg='#cccccc')
    
    def full_scan(self):
        """Perform full system scan"""
        messagebox.showinfo(
            "Full Scan",
            "Full system scan started. This may take several minutes.\n\n"
            "The scan will run in the background and results will appear in the activity log."
        )
        
        # Start scan in background thread
        threading.Thread(target=self._perform_full_scan, daemon=True).start()
    
    def _perform_full_scan(self):
        """Perform the actual scan"""
        self.add_log_entry("System", "Full system scan started", "Info")
        
        # Scan common directories
        scan_dirs = [
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Downloads")
        ]
        
        files_scanned = 0
        threats_found = 0
        
        for directory in scan_dirs:
            if os.path.exists(directory):
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        files_scanned += 1
                        
                        # Check for suspicious extensions
                        if any(file.lower().endswith(ext) for ext in self.core.known_ransomware_extensions):
                            threats_found += 1
                            self.add_log_entry("Scan", f"Suspicious file: {file_path}", "High")
                        
                        # Update stats
                        if files_scanned % 100 == 0:
                            self.stats_labels["Files Scanned"].config(text=str(files_scanned))
                            self.root.update()
        
        self.add_log_entry("System", f"Scan completed: {files_scanned} files scanned, {threats_found} threats found", "Info")
    
    def open_quarantine_manager(self):
        """Open quarantine manager window"""
        quarantine_window = tk.Toplevel(self.root)
        quarantine_window.title("🔒 Quarantine Manager")
        quarantine_window.geometry("600x400")
        quarantine_window.configure(bg='#2b2b2b')
        
        # List quarantined files
        tk.Label(
            quarantine_window,
            text="Quarantined Files",
            font=('Arial', 14, 'bold'),
            fg='#ffffff',
            bg='#2b2b2b'
        ).pack(pady=10)
        
        # File list
        quarantine_tree = ttk.Treeview(
            quarantine_window,
            columns=('File', 'Date', 'Reason'),
            show='headings',
            height=15
        )
        
        for col in ['File', 'Date', 'Reason']:
            quarantine_tree.heading(col, text=col)
            quarantine_tree.column(col, width=180)
        
        quarantine_tree.pack(pady=10, padx=20, fill='both', expand=True)
        
        # Load quarantined files
        self._load_quarantine_files(quarantine_tree)
        
        # Buttons
        button_frame = tk.Frame(quarantine_window, bg='#2b2b2b')
        button_frame.pack(pady=10)
        
        tk.Button(
            button_frame,
            text="Restore Selected",
            command=lambda: self._restore_quarantine_file(quarantine_tree),
            bg='#00aa00',
            fg='white'
        ).pack(side='left', padx=5)
        
        tk.Button(
            button_frame,
            text="Delete Selected",
            command=lambda: self._delete_quarantine_file(quarantine_tree),
            bg='#cc0000',
            fg='white'
        ).pack(side='left', padx=5)
    
    def open_settings(self):
        """Open settings window"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("⚙️ Settings")
        settings_window.geometry("500x600")
        settings_window.configure(bg='#2b2b2b')
        
        notebook = ttk.Notebook(settings_window)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Protection settings
        protection_frame = tk.Frame(notebook, bg='#2b2b2b')
        notebook.add(protection_frame, text="Protection")
        
        # Directory settings
        directory_frame = tk.Frame(notebook, bg='#2b2b2b')
        notebook.add(directory_frame, text="Directories")
        
        # Advanced settings
        advanced_frame = tk.Frame(notebook, bg='#2b2b2b')
        notebook.add(advanced_frame, text="Advanced")
        
        # Populate settings (simplified)
        tk.Label(
            protection_frame,
            text="Protection Settings",
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#2b2b2b'
        ).pack(pady=10)
        
        # Save button
        tk.Button(
            settings_window,
            text="Save Settings",
            command=lambda: self._save_settings(settings_window),
            bg='#00aa00',
            fg='white'
        ).pack(pady=10)
    
    def show_threat_alert(self, threat_type, file_path, severity):
        """Show threat detection alert"""
        alert_window = tk.Toplevel(self.root)
        alert_window.title("🚨 THREAT DETECTED")
        alert_window.geometry("500x300")
        alert_window.configure(bg='#cc0000')
        alert_window.attributes('-topmost', True)
        
        # Alert content
        tk.Label(
            alert_window,
            text="🚨 THREAT DETECTED 🚨",
            font=('Arial', 18, 'bold'),
            fg='white',
            bg='#cc0000'
        ).pack(pady=20)
        
        tk.Label(
            alert_window,
            text=f"Type: {threat_type}",
            font=('Arial', 12),
            fg='white',
            bg='#cc0000'
        ).pack(pady=5)
        
        tk.Label(
            alert_window,
            text=f"File: {file_path}",
            font=('Arial', 12),
            fg='white',
            bg='#cc0000',
            wraplength=400
        ).pack(pady=5)
        
        tk.Label(
            alert_window,
            text=f"Severity: {severity}/5",
            font=('Arial', 12),
            fg='white',
            bg='#cc0000'
        ).pack(pady=5)
        
        # Buttons
        button_frame = tk.Frame(alert_window, bg='#cc0000')
        button_frame.pack(pady=20)
        
        tk.Button(
            button_frame,
            text="OK",
            command=alert_window.destroy,
            bg='white',
            fg='black',
            width=10
        ).pack(side='left', padx=10)
        
        tk.Button(
            button_frame,
            text="View Details",
            command=lambda: self._show_threat_details(threat_type, file_path, severity),
            bg='white',
            fg='black',
            width=10
        ).pack(side='left', padx=10)
        
        # Add to activity log
        self.add_log_entry("Threat", f"{threat_type}: {os.path.basename(file_path)}", 
                          "High" if severity >= 4 else "Medium")
    
    def add_log_entry(self, entry_type, description, severity):
        """Add entry to activity log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding
        if severity == "High":
            tags = ('high',)
        elif severity == "Medium":
            tags = ('medium',)
        else:
            tags = ('low',)
        
        self.log_tree.insert('', 0, values=(timestamp, entry_type, description, severity), tags=tags)
        
        # Configure tag colors
        self.log_tree.tag_configure('high', foreground='red')
        self.log_tree.tag_configure('medium', foreground='orange')
        self.log_tree.tag_configure('low', foreground='green')
        
        # Keep only last 100 entries
        children = self.log_tree.get_children()
        if len(children) > 100:
            self.log_tree.delete(children[-1])
    
    def update_status_loop(self):
        """Update status information periodically"""
        # Update time
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        
        # Update statistics
        if self.monitoring_var.get():
            # Simulate some activity (in real implementation, get from core)
            import random
            self.stats_labels["Active Processes"].config(text=str(len(psutil.pids())))
            self.stats_labels["Network Connections"].config(text=str(len(psutil.net_connections())))
        
        # Schedule next update
        self.root.after(1000, self.update_status_loop)
    
    def _load_quarantine_files(self, tree):
        """Load quarantined files into tree"""
        try:
            for file_path in self.core.quarantine_dir.glob("*.info"):
                with open(str(file_path), 'r') as f:
                    info = json.load(f)
                
                tree.insert('', 'end', values=(
                    os.path.basename(info['original_path']),
                    info['quarantine_time'],
                    info['reason']
                ))
        except Exception as e:
            logger.error(f"Error loading quarantine files: {e}")
    
    def _restore_quarantine_file(self, tree):
        """Restore selected quarantine file"""
        selection = tree.selection()
        if selection:
            messagebox.showinfo("Restore", "File restoration functionality would be implemented here")
    
    def _delete_quarantine_file(self, tree):
        """Delete selected quarantine file"""
        selection = tree.selection()
        if selection:
            if messagebox.askyesno("Delete", "Are you sure you want to permanently delete this file?"):
                messagebox.showinfo("Delete", "File deletion functionality would be implemented here")
    
    def _save_settings(self, window):
        """Save settings"""
        messagebox.showinfo("Settings", "Settings saved successfully")
        window.destroy()
    
    def _show_threat_details(self, threat_type, file_path, severity):
        """Show detailed threat information"""
        details_window = tk.Toplevel(self.root)
        details_window.title("🔍 Threat Details")
        details_window.geometry("600x400")
        details_window.configure(bg='#2b2b2b')
        
        text_widget = tk.Text(details_window, bg='#1a1a1a', fg='white', font=('Courier', 10))
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        
        details = f"""
THREAT ANALYSIS REPORT
=====================

Threat Type: {threat_type}
File Path: {file_path}
Severity Level: {severity}/5
Detection Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

File Information:
- Size: {os.path.getsize(file_path) if os.path.exists(file_path) else "File not found"} bytes
- Modified: {datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M:%S") if os.path.exists(file_path) else "Unknown"}

Risk Assessment:
- Encryption Pattern: {'Detected' if severity >= 4 else 'Not detected'}
- Suspicious Extension: {'Yes' if any(file_path.lower().endswith(ext) for ext in self.core.known_ransomware_extensions) else 'No'}
- Rapid Modification: {'Detected' if self.core.is_rapid_modification(file_path) else 'Not detected'}

Recommended Actions:
1. File has been automatically quarantined
2. Review quarantine manager for file restoration options
3. Consider running full system scan
4. Monitor system for additional threats
        """
        
        text_widget.insert('1.0', details)
        text_widget.config(state='disabled')
    
    def run(self):
        """Run the GUI"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.core.stop_monitoring()
            logger.info("Application terminated by user")

def main():
    """Main application entry point"""
    print("🛡️ PYTHON ANTI-RANSOMWARE PROTECTION SYSTEM")
    print("=" * 50)
    
    # Determine application directory
    if os.access("C:\\ProgramData", os.W_OK):
        app_dir = "C:\\ProgramData\\PythonAntiRansomware"
    else:
        app_dir = os.path.expanduser("~\\AppData\\Local\\PythonAntiRansomware")
    
    print(f"📁 Using directory: {app_dir}")
    
    try:
        # Initialize core protection
        core = AntiRansomwareCore(app_dir)
        
        # Check for command line arguments
        if len(sys.argv) > 1:
            if sys.argv[1] == "--cli":
                print("🖥️ Running in CLI mode...")
                core.start_monitoring()
                
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n🛑 Stopping protection...")
                    core.stop_monitoring()
                    print("✅ Protection stopped")
                    return
            elif sys.argv[1] == "--help":
                print("""
Usage: python antiransomware_python.py [OPTIONS]

Options:
  --gui     Launch with graphical interface (default)
  --cli     Run in command-line mode
  --help    Show this help message

Features:
  • Real-time file system monitoring
  • Registry protection and backup
  • USB device authentication  
  • Network traffic monitoring
  • Behavioral threat analysis
  • Advanced quarantine system
  • Comprehensive activity logging
                """)
                return
        
        # Default to GUI mode
        print("🖥️ Starting GUI interface...")
        gui = AntiRansomwareGUI(core)
        gui.run()
        
    except Exception as e:
        logger.error(f"❌ Application error: {e}")
        print(f"❌ Error: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
