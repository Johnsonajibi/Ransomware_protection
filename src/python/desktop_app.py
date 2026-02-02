"""
Anti-Ransomware Desktop Application
Modern GUI for ransomware protection management
"""

import sys
import os
import sqlite3
import json
import traceback
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path

# Add backend paths
current_dir = Path(__file__).parent.absolute()
sys.path.append(str(current_dir / "src" / "python" / "core"))
sys.path.append(str(current_dir / "src" / "python" / "monitoring"))
sys.path.append(str(current_dir / "src" / "python" / "enterprise"))
sys.path.append(str(current_dir / "src" / "python" / "utils"))

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QListWidget, QTextEdit, QTabWidget,
    QLineEdit, QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QDialog, QFormLayout, QCheckBox, QSpinBox, QSystemTrayIcon,
    QMenu, QProgressBar, QGroupBox, QScrollArea, QStyle
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QIcon, QPixmap, QFont, QColor, QPalette, QAction
import subprocess
import psutil
import threading

# Configure comprehensive logging
def setup_logging():
    """Setup rotating file handler for comprehensive logging"""
    log_dir = Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData' / 'Local')) / 'AntiRansomware' / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / 'antiransomware.log'
    
    # Create formatter for detailed logs
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(name)s:%(funcName)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Rotating file handler (10 MB max, keep 5 backup files)
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10 MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Console handler - ONLY show CRITICAL process confirmations
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.CRITICAL)  # Only CRITICAL level to console
    console_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Create app-specific logger
    app_logger = logging.getLogger('AntiRansomware')
    
    return str(log_file)

# Initialize logging
LOG_FILE_PATH = setup_logging()
logger = logging.getLogger('AntiRansomware')

# Suppress noisy third-party library warnings - BUT ALLOW info for enhanced logging
logging.getLogger('device_fingerprinting').setLevel(logging.INFO)
logging.getLogger('pqcdualusb').setLevel(logging.INFO)

# Import backend functionality
try:
    from unified_antiransomware import (
        UnifiedProtectionManager, UnifiedDatabase
    )
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    ProtectionEngine = UnifiedProtectionManager  # Alias for compatibility
    ProtectionDatabase = UnifiedDatabase  # Alias for compatibility
    print("[SUCCESS] Backend modules loaded successfully!")
except ImportError as e:
    print(f"[ERROR] Backend modules import failed: {e}")
    traceback.print_exc()
    ProtectionEngine = None
    ProtectionDatabase = None
    Observer = None
except Exception as e:
    print(f"[ERROR] Unexpected error during import: {e}")
    traceback.print_exc()
    ProtectionEngine = None
    ProtectionDatabase = None
    Observer = None

# Import new security features
try:
    from emergency_kill_switch import EmergencyKillSwitch
    HAS_KILL_SWITCH = True
except ImportError:
    HAS_KILL_SWITCH = False
    EmergencyKillSwitch = None

try:
    from email_alerting import EmailAlertingSystem
    HAS_EMAIL = True
except ImportError:
    HAS_EMAIL = False
    EmailAlertingSystem = None

try:
    from siem_integration import SIEMIntegration
    HAS_SIEM = True
except ImportError:
    HAS_SIEM = False
    SIEMIntegration = None

try:
    from shadow_copy_protection import ShadowCopyProtection
    HAS_SHADOW = True
except ImportError:
    HAS_SHADOW = False
    ShadowCopyProtection = None

# TPM integration (hardware-backed keys/attestation)
try:
    from tpm_integration import TPMManager
    HAS_TPM_MANAGER = True
except ImportError:
    HAS_TPM_MANAGER = False
    TPMManager = None

# Kernel protection (filter driver)
try:
    from kernel_protection_interface import KernelProtectionInterface, ProtectionLevel
    HAS_KERNEL_PROTECTION = True
except ImportError:
    HAS_KERNEL_PROTECTION = False
    KernelProtectionInterface = None

try:
    from system_health_checker import SystemHealthChecker
    HAS_HEALTH = True
except ImportError:
    HAS_HEALTH = False
    SystemHealthChecker = None


class MonitorThread(QThread):
    """Background monitoring thread"""
    event_detected = pyqtSignal(dict)
    stats_updated = pyqtSignal(dict)
    
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.running = True
        
    def run(self):
        """Monitor system activity"""
        while self.running:
            try:
                # Get current stats
                stats = {
                    'cpu': psutil.cpu_percent(interval=1),
                    'memory': psutil.virtual_memory().percent,
                    'disk': psutil.disk_usage('/').percent,
                    'protected_files': self.get_protected_count(),
                    'threats_blocked': self.get_threat_count()
                }
                self.stats_updated.emit(stats)
                
            except Exception as e:
                print(f"Monitor error: {e}")
            
            self.msleep(5000)  # Update every 5 seconds
    
    def get_protected_count(self):
        """Count protected files"""
        try:
            if ProtectionDatabase:
                db = ProtectionDatabase()
                paths = db.get_protected_paths()
                count = 0
                for path_info in paths:
                    path = Path(path_info['path'])
                    if path.exists() and path.is_dir():
                        count += sum(1 for _ in path.rglob('*') if _.is_file())
                return count
        except:
            pass
        return 0
    
    def get_threat_count(self):
        """Count blocked threats"""
        try:
            if ProtectionDatabase:
                db = ProtectionDatabase()
                events = db.get_events(limit=1000)
                return sum(1 for e in events if e.get('action') == 'blocked')
        except:
            pass
        return 0
    
    def stop(self):
        """Stop monitoring"""
        self.running = False


class AddPathDialog(QDialog):
    """Dialog for adding protected paths"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Protected Path")
        self.setMinimumWidth(500)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QFormLayout()
        
        # Path selection
        path_layout = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Select folder to protect...")
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_path)
        path_layout.addWidget(self.path_edit)
        path_layout.addWidget(browse_btn)
        layout.addRow("Path:", path_layout)
        
        # Options
        self.recursive_cb = QCheckBox("Include subdirectories")
        self.recursive_cb.setChecked(True)
        layout.addRow("", self.recursive_cb)
        
        self.monitor_creates_cb = QCheckBox("Monitor file creations")
        self.monitor_creates_cb.setChecked(True)
        layout.addRow("", self.monitor_creates_cb)
        
        self.monitor_modifies_cb = QCheckBox("Monitor file modifications")
        self.monitor_modifies_cb.setChecked(True)
        layout.addRow("", self.monitor_modifies_cb)
        
        self.monitor_deletes_cb = QCheckBox("Monitor file deletions")
        self.monitor_deletes_cb.setChecked(True)
        layout.addRow("", self.monitor_deletes_cb)
        
        # Buttons
        button_layout = QHBoxLayout()
        add_btn = QPushButton("Add Path")
        add_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(add_btn)
        button_layout.addWidget(cancel_btn)
        layout.addRow("", button_layout)
        
        self.setLayout(layout)
    
    def browse_path(self):
        """Browse for directory"""
        path = QFileDialog.getExistingDirectory(self, "Select Protected Directory")
        if path:
            self.path_edit.setText(path)
    
    def get_path_info(self):
        """Get path configuration"""
        return {
            'path': self.path_edit.text(),
            'recursive': self.recursive_cb.isChecked(),
            'monitor_creates': self.monitor_creates_cb.isChecked(),
            'monitor_modifies': self.monitor_modifies_cb.isChecked(),
            'monitor_deletes': self.monitor_deletes_cb.isChecked()
        }


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Anti-Ransomware Protection")
        self.setMinimumSize(1000, 700)
        
        # Initialize backend
        self.engine = None
        self.db = None
        self.monitor_thread = None
        self.protection_active = False
        self.observer = None
        
        # Initialize new security features
        self.kill_switch = EmergencyKillSwitch() if HAS_KILL_SWITCH else None
        self.email_alerter = EmailAlertingSystem() if HAS_EMAIL else None
        self.siem = SIEMIntegration() if HAS_SIEM else None
        self.shadow_protection = ShadowCopyProtection() if HAS_SHADOW else None
        self.health_checker = SystemHealthChecker() if HAS_HEALTH else None
        self.kernel_protection = KernelProtectionInterface() if HAS_KERNEL_PROTECTION else None
        self.tpm_manager = TPMManager() if HAS_TPM_MANAGER else None
        self.ml_model_path = Path.cwd() / "models" / "ransomware_classifier.pkl"
        self.tpm_status_label = None
        self.ml_status_label = None
        
        if ProtectionEngine and ProtectionDatabase:
            try:
                print(f"DEBUG: Initializing database...")
                self.db = ProtectionDatabase()
                print(f"DEBUG: Database initialized: {self.db}")
                print(f"DEBUG: Initializing engine...")
                self.engine = ProtectionEngine()
                print(f"DEBUG: Engine initialized: {self.engine}")
                # Initialize default protected paths
                self._init_default_paths()
                print(f"DEBUG: Initialization complete!")
            except Exception as e:
                error_msg = f"Backend initialization failed: {e}\n{traceback.format_exc()}"
                print(error_msg)
                QMessageBox.critical(self, "Initialization Error", error_msg)
        else:
            error_msg = f"Backend modules not available!\nProtectionEngine: {ProtectionEngine}\nProtectionDatabase: {ProtectionDatabase}"
            print(error_msg)
            QMessageBox.critical(self, "Missing Backend", error_msg)
        
        # Setup UI
        self.setup_ui()
        self.setup_system_tray()
        
        # Auto-run health check after UI loads
        QTimer.singleShot(1000, self.run_health_check)
        QTimer.singleShot(1200, self.update_ui)  # initial hardware/ML status paint
        self.setup_timers()
        self.load_settings()
        
        # Load initial data
        self.refresh_protected_paths()
        self.refresh_events()
        
        # Don't auto-start protection - wait for user to click button
        # Start monitoring thread for stats
        if self.engine:
            self.start_monitoring()
    
    def _init_default_paths(self):
        """Initialize default protected paths"""
        try:
            default_paths = [
                str(Path.home() / "Pictures")
            ]
            for path in default_paths:
                if Path(path).exists():
                    try:
                        self.db.add_protected_path(path, recursive=True)
                    except:
                        pass  # Path may already exist
        except Exception as e:
            print(f"Error initializing default paths: {e}")
    
    def setup_ui(self):
        """Setup user interface"""
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_dashboard_tab(), "Dashboard")
        self.tabs.addTab(self.create_token_tab(), "🔑 USB Token")
        self.tabs.addTab(self.create_protection_tab(), "Protected Paths")
        self.tabs.addTab(self.create_events_tab(), "Security Events")
        self.tabs.addTab(self.create_logs_tab(), "📋 Application Logs")
        self.tabs.addTab(self.create_health_tab(), "🏥 System Health")
        self.tabs.addTab(self.create_emergency_tab(), "🚨 Emergency")
        self.tabs.addTab(self.create_alerts_tab(), "📧 Alerts")
        self.tabs.addTab(self.create_shadow_tab(), "💾 Shadow Copies")
        self.tabs.addTab(self.create_settings_tab(), "Settings")
        layout.addWidget(self.tabs)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
        # Apply dark theme
        self.apply_theme()
    
    def check_drives_for_tokens(self, drives):
        """Auto-scan drives for valid tokens"""
        found_token = False
        try:
            import glob
            import os
            
            for drive in drives:
                drive_path = str(drive)
                # Look for tokens
                quantum_tokens = glob.glob(os.path.join(drive_path, "quantum_token_*.qkey"))
                legacy_tokens = glob.glob(os.path.join(drive_path, "protection_token_*.key"))
                all_tokens = quantum_tokens + legacy_tokens
                
                for token_path in all_tokens:
                    if self.engine and self.engine.token_manager.validate_secure_token(token_path):
                        self.token_status_label.setText(f"✅ Valid token detected: {os.path.basename(token_path)}")
                        self.token_info_text.append(f"\n[Auto-Detect] Found valid token on {drive_path}")
                        found_token = True
                        
                        # Auto-select this drive in the list
                        items = self.usb_drives_list.findItems(f"📀 {drive_path}", Qt.MatchFlag.MatchContains)
                        if items:
                            self.usb_drives_list.setCurrentItem(items[0])
                        return
            
            if not found_token:
                self.token_status_label.setText("❌ No USB token detected")
                
        except Exception as e:
            print(f"Token auto-scan error: {e}")
    
    def create_header(self):
        """Create header with status"""
        header = QGroupBox()
        layout = QHBoxLayout()
        
        # Logo/Title
        title = QLabel("🛡️ Anti-Ransomware Protection")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        layout.addStretch()
        
        # Status indicator
        self.status_label = QLabel("● PROTECTED")
        self.status_label.setStyleSheet("color: #00ff00; font-weight: bold;")
        layout.addWidget(self.status_label)
        
        # Control buttons
        self.start_btn = QPushButton("Start Protection")
        self.start_btn.clicked.connect(self.start_protection)
        self.stop_btn = QPushButton("Stop Protection")
        self.stop_btn.clicked.connect(self.stop_protection)
        self.stop_btn.setEnabled(False)
        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        
        header.setLayout(layout)
        return header
    
    def create_token_tab(self):
        """Create USB token management tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Token status
        status_group = QGroupBox("🔐 Token Status")
        status_layout = QVBoxLayout()
        
        self.token_status_label = QLabel("❌ No USB token detected")
        self.token_status_label.setObjectName("token_status")
        status_layout.addWidget(self.token_status_label)
        
        self.device_fingerprint_label = QLabel("Device Fingerprint: Loading...")
        status_layout.addWidget(self.device_fingerprint_label)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # USB drives
        drives_group = QGroupBox("📀 Available USB Drives")
        drives_layout = QVBoxLayout()
        
        self.usb_drives_list = QListWidget()
        drives_layout.addWidget(self.usb_drives_list)
        
        btn_layout = QHBoxLayout()
        self.refresh_usb_btn = QPushButton("🔄 Refresh USB Drives")
        self.refresh_usb_btn.clicked.connect(self.refresh_usb_drives)
        btn_layout.addWidget(self.refresh_usb_btn)
        drives_layout.addLayout(btn_layout)
        
        drives_group.setLayout(drives_layout)
        layout.addWidget(drives_group)
        
        # Token actions
        actions_group = QGroupBox("🔑 Token Management")
        actions_layout = QVBoxLayout()
        
        create_btn_layout = QHBoxLayout()
        self.create_token_btn = QPushButton("✨ Create New USB Token")
        self.create_token_btn.clicked.connect(self.create_usb_token)
        create_btn_layout.addWidget(self.create_token_btn)
        actions_layout.addLayout(create_btn_layout)
        
        validate_btn_layout = QHBoxLayout()
        self.validate_token_btn = QPushButton("✅ Validate USB Token")
        self.validate_token_btn.clicked.connect(self.validate_usb_token)
        validate_btn_layout.addWidget(self.validate_token_btn)
        actions_layout.addLayout(validate_btn_layout)
        
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        # Token info
        info_group = QGroupBox("ℹ️ Token Information")
        info_layout = QVBoxLayout()
        
        self.token_info_text = QTextEdit()
        self.token_info_text.setReadOnly(True)
        self.token_info_text.setMaximumHeight(150)
        self.token_info_text.setPlainText(
            "🔐 ENTERPRISE QUANTUM-RESISTANT USB TOKEN\n\n"
            "Security Features:\n"
            "  • Kyber1024 KEM (NIST-approved post-quantum key exchange)\n"
            "  • Dilithium3 signatures (quantum-resistant authentication)\n"
            "  • AES-256-GCM hybrid encryption\n"
            "  • Device fingerprint binding (CPU, BIOS, TPM, Network)\n"
            "  • Hardware-bound authentication\n\n"
            "Insert USB drive and click 'Create New USB Token' to begin."
        )
        info_layout.addWidget(self.token_info_text)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        widget.setLayout(layout)
        
        # Initial refresh
        QTimer.singleShot(500, self.refresh_usb_drives)
        QTimer.singleShot(600, self.update_device_fingerprint)
        
        return widget
    
    def create_dashboard_tab(self):
        """Create dashboard overview"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        self.protected_files_card = self.create_stat_card("Protected Files", "0")
        self.threats_blocked_card = self.create_stat_card("Threats Blocked", "0")
        self.cpu_usage_card = self.create_stat_card("CPU Usage", "0%")
        self.memory_usage_card = self.create_stat_card("Memory", "0%")
        
        stats_layout.addWidget(self.protected_files_card)
        stats_layout.addWidget(self.threats_blocked_card)
        stats_layout.addWidget(self.cpu_usage_card)
        stats_layout.addWidget(self.memory_usage_card)
        
        layout.addLayout(stats_layout)
        
        # Recent events
        recent_group = QGroupBox("Recent Security Events")
        recent_layout = QVBoxLayout()
        self.recent_events_list = QListWidget()
        recent_layout.addWidget(self.recent_events_list)
        recent_group.setLayout(recent_layout)
        layout.addWidget(recent_group)
        
        widget.setLayout(layout)
        return widget
    
    def create_stat_card(self, title, value):
        """Create statistics card"""
        card = QGroupBox(title)
        layout = QVBoxLayout()
        
        value_label = QLabel(value)
        value_label.setObjectName("stat_value")
        value_font = QFont()
        value_font.setPointSize(24)
        value_font.setBold(True)
        value_label.setFont(value_font)
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(value_label)
        card.setLayout(layout)
        return card
    
    def create_protection_tab(self):
        """Create protected paths management tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Folder Management Toolbar
        folder_toolbar = QHBoxLayout()
        add_btn = QPushButton("➕ Add Path")
        add_btn.clicked.connect(self.add_protected_path)
        remove_btn = QPushButton("➖ Remove Path")
        remove_btn.clicked.connect(self.remove_protected_path)
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_protected_paths)
        debug_btn = QPushButton("🐛 Debug")
        debug_btn.clicked.connect(self.debug_table)
        
        folder_toolbar.addWidget(add_btn)
        folder_toolbar.addWidget(remove_btn)
        folder_toolbar.addWidget(refresh_btn)
        folder_toolbar.addWidget(debug_btn)
        folder_toolbar.addStretch()
        
        layout.addLayout(folder_toolbar)
        
        # Paths table
        self.paths_table = QTableWidget()
        self.paths_table.setColumnCount(4)
        self.paths_table.setHorizontalHeaderLabels(["Path", "Recursive", "Status", "Added"])
        self.paths_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.paths_table)
        
        # File Operations Toolbar (NEW)
        file_toolbar = QHBoxLayout()
        
        file_ops_label = QLabel("🔐 Protected File Operations (Requires USB Token):")
        file_ops_label.setStyleSheet("font-weight: bold; color: #14a085; margin-top: 10px;")
        
        open_file_btn = QPushButton("📂 Open Protected File")
        open_file_btn.clicked.connect(self.open_protected_file)
        open_file_btn.setToolTip("Open a protected file with token verification")
        
        edit_file_btn = QPushButton("✏️ Edit Protected File")
        edit_file_btn.clicked.connect(self.edit_protected_file)
        edit_file_btn.setToolTip("Edit a protected file with token verification")
        
        list_files_btn = QPushButton("📋 List Protected Files")
        list_files_btn.clicked.connect(self.list_protected_files)
        list_files_btn.setToolTip("Show all protected files in selected folder")
        
        copy_file_btn = QPushButton("📄 Copy Protected File")
        copy_file_btn.clicked.connect(self.copy_protected_file)
        copy_file_btn.setToolTip("Copy a protected file with token verification")
        
        file_toolbar.addWidget(file_ops_label)
        file_toolbar.addWidget(open_file_btn)
        file_toolbar.addWidget(edit_file_btn)
        file_toolbar.addWidget(list_files_btn)
        file_toolbar.addWidget(copy_file_btn)
        file_toolbar.addStretch()
        
        layout.addLayout(file_toolbar)
        
        widget.setLayout(layout)
        return widget
    
    def create_events_tab(self):
        """Create security events tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Toolbar
        toolbar = QHBoxLayout()
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_events)
        clear_btn = QPushButton("🗑️ Clear Events")
        clear_btn.clicked.connect(self.clear_events)
        
        toolbar.addWidget(refresh_btn)
        toolbar.addWidget(clear_btn)
        toolbar.addStretch()
        
        layout.addLayout(toolbar)
        
        # Events table
        self.events_table = QTableWidget()
        self.events_table.setColumnCount(6)
        self.events_table.setHorizontalHeaderLabels(["Time", "Event", "Path", "Process", "Action", "Severity"])
        self.events_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.events_table)
        
        widget.setLayout(layout)
        return widget
    
    def create_settings_tab(self):
        """Create settings tab"""
        # Wrap settings content in a scroll area to handle smaller viewports
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)

        widget = QWidget()
        layout = QVBoxLayout()
        
        # Protection settings
        protection_group = QGroupBox("Protection Settings")
        protection_layout = QFormLayout()
        
        self.auto_quarantine_cb = QCheckBox("Auto-quarantine suspicious files")
        self.auto_quarantine_cb.setChecked(True)
        protection_layout.addRow("", self.auto_quarantine_cb)
        
        self.block_encryption_cb = QCheckBox("Block rapid encryption patterns")
        self.block_encryption_cb.setChecked(True)
        protection_layout.addRow("", self.block_encryption_cb)
        
        protection_group.setLayout(protection_layout)
        layout.addWidget(protection_group)

        # Enterprise access controls
        access_group = QGroupBox("Enterprise Access Control")
        access_layout = QFormLayout()

        self.require_token_cb = QCheckBox("Require token for protected file access")
        self.require_token_cb.setChecked(True)
        access_layout.addRow("", self.require_token_cb)

        self.bind_fek_cb = QCheckBox("Bind file encryption keys to inserted token")
        self.bind_fek_cb.setChecked(True)
        access_layout.addRow("", self.bind_fek_cb)

        self.auto_block_token_loss_cb = QCheckBox("Auto-block when token removed")
        self.auto_block_token_loss_cb.setChecked(True)
        access_layout.addRow("", self.auto_block_token_loss_cb)

        access_group.setLayout(access_layout)
        layout.addWidget(access_group)

        # Detection policy
        detection_group = QGroupBox("Detection Policies")
        detection_layout = QFormLayout()

        self.max_mods_spin = QSpinBox()
        self.max_mods_spin.setRange(1, 1000)
        self.max_mods_spin.setValue(50)

        self.entropy_threshold_spin = QSpinBox()
        self.entropy_threshold_spin.setRange(10, 100)
        self.entropy_threshold_spin.setValue(80)
        detection_layout.addRow("Entropy alert threshold (0-100):", self.entropy_threshold_spin)

        detection_layout.addRow("Rapid modifications/min:", self.max_mods_spin)

        detection_group.setLayout(detection_layout)
        layout.addWidget(detection_group)

        # SIEM / alerting
        siem_group = QGroupBox("SIEM & Alerting")
        siem_layout = QFormLayout()

        self.siem_enable_cb = QCheckBox("Forward events to SIEM HTTP webhook")
        siem_layout.addRow("", self.siem_enable_cb)

        self.siem_url_edit = QLineEdit()
        self.siem_url_edit.setPlaceholderText("https://siem.example.com/webhook")
        siem_layout.addRow("Webhook URL:", self.siem_url_edit)

        self.siem_token_edit = QLineEdit()
        self.siem_token_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.siem_token_edit.setPlaceholderText("Optional bearer/API token")
        siem_layout.addRow("Bearer token:", self.siem_token_edit)

        self.siem_sign_cb = QCheckBox("Sign events with HMAC-SHA256 (uses bearer token as key)")
        siem_layout.addRow("", self.siem_sign_cb)

        siem_group.setLayout(siem_layout)
        layout.addWidget(siem_group)

        # Hardware security & ML status
        status_group = QGroupBox("Hardware Security & ML")
        status_layout = QFormLayout()

        self.tpm_status_label = QLabel("Detecting...")
        self.ml_status_label = QLabel("Checking model...")
        status_layout.addRow("TPM status:", self.tpm_status_label)
        status_layout.addRow("ML model:", self.ml_status_label)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Startup settings
        startup_group = QGroupBox("Startup Settings")
        startup_layout = QFormLayout()
        
        self.start_with_windows_cb = QCheckBox("Start with Windows")
        startup_layout.addRow("", self.start_with_windows_cb)
        
        self.minimize_to_tray_cb = QCheckBox("Minimize to system tray")
        self.minimize_to_tray_cb.setChecked(True)
        startup_layout.addRow("", self.minimize_to_tray_cb)
        
        startup_group.setLayout(startup_layout)
        layout.addWidget(startup_group)
        
        # Save button
        save_btn = QPushButton("💾 Save Settings")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        layout.addStretch()
        widget.setLayout(layout)

        scroll_area.setWidget(widget)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        return scroll_area
    
    def create_logs_tab(self):
        """Create application logs viewer tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("📋 Application Logs")
        header.setStyleSheet("font-size: 18px; font-weight: bold; padding: 10px;")
        layout.addWidget(header)
        
        # Info label
        info_label = QLabel(f"Log file: {LOG_FILE_PATH}")
        info_label.setStyleSheet("color: #666; padding: 5px;")
        layout.addWidget(info_label)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh Logs")
        refresh_btn.clicked.connect(self.refresh_logs)
        button_layout.addWidget(refresh_btn)
        
        clear_view_btn = QPushButton("🗑️ Clear View")
        clear_view_btn.clicked.connect(lambda: self.log_viewer.clear())
        button_layout.addWidget(clear_view_btn)
        
        open_file_btn = QPushButton("📂 Open Log File")
        open_file_btn.clicked.connect(self.open_log_file)
        button_layout.addWidget(open_file_btn)
        
        button_layout.addStretch()
        
        # Auto-refresh checkbox
        self.auto_refresh_logs_cb = QCheckBox("Auto-refresh (every 5s)")
        self.auto_refresh_logs_cb.setChecked(True)
        button_layout.addWidget(self.auto_refresh_logs_cb)
        
        layout.addLayout(button_layout)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter Level:"))
        
        self.log_level_filter = QLineEdit()
        self.log_level_filter.setPlaceholderText("DEBUG, INFO, WARNING, ERROR (leave empty for all)")
        self.log_level_filter.textChanged.connect(self.refresh_logs)
        filter_layout.addWidget(self.log_level_filter)
        
        filter_layout.addWidget(QLabel("Search:"))
        self.log_search_filter = QLineEdit()
        self.log_search_filter.setPlaceholderText("Search in logs...")
        self.log_search_filter.textChanged.connect(self.refresh_logs)
        filter_layout.addWidget(self.log_search_filter)
        
        layout.addLayout(filter_layout)
        
        # Log viewer (text edit with monospace font)
        self.log_viewer = QTextEdit()
        self.log_viewer.setReadOnly(True)
        self.log_viewer.setFont(QFont("Consolas", 9))
        self.log_viewer.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3c3c3c;
                padding: 5px;
            }
        """)
        layout.addWidget(self.log_viewer)
        
        # Stats label
        self.log_stats_label = QLabel("Lines: 0")
        self.log_stats_label.setStyleSheet("color: #666; padding: 5px;")
        layout.addWidget(self.log_stats_label)
        
        widget.setLayout(layout)
        
        # Initial load
        self.refresh_logs()
        
        return widget
    
    def create_health_tab(self):
        """Create system health check tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("System Health Monitor")
        header.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # Health status
        status_group = QGroupBox("Health Status")
        status_layout = QVBoxLayout()
        
        self.health_status_label = QLabel("Status: Running health check...")
        self.health_status_label.setFont(QFont("Arial", 12))
        status_layout.addWidget(self.health_status_label)
        
        # Check results
        self.health_results = QTextEdit()
        self.health_results.setReadOnly(True)
        self.health_results.setMaximumHeight(200)
        status_layout.addWidget(self.health_results)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Threat indicators
        threats_group = QGroupBox("Threat Indicators")
        threats_layout = QVBoxLayout()
        
        self.threat_list = QListWidget()
        threats_layout.addWidget(self.threat_list)
        
        threats_group.setLayout(threats_layout)
        layout.addWidget(threats_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        check_btn = QPushButton("🔍 Run Health Check")
        check_btn.clicked.connect(self.run_health_check)
        button_layout.addWidget(check_btn)
        
        auto_check_btn = QPushButton("⏰ Enable Auto-Check")
        auto_check_btn.setCheckable(True)
        auto_check_btn.clicked.connect(self.toggle_auto_health_check)
        button_layout.addWidget(auto_check_btn)
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget
    
    def create_emergency_tab(self):
        """Create emergency kill switch tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Warning header
        warning = QLabel("🚨 EMERGENCY KILL SWITCH")
        warning.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        warning.setStyleSheet("color: #ff0000;")
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(warning)
        
        info = QLabel("Activates system-wide lockdown in case of active ransomware attack")
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(info)
        
        # Status
        status_group = QGroupBox("Lockdown Status")
        status_layout = QVBoxLayout()
        
        self.lockdown_status_label = QLabel("Status: Normal Operations")
        self.lockdown_status_label.setFont(QFont("Arial", 12))
        self.lockdown_status_label.setStyleSheet("color: #00ff00;")
        status_layout.addWidget(self.lockdown_status_label)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Configuration
        config_group = QGroupBox("Lockdown Configuration")
        config_layout = QFormLayout()
        
        self.network_isolation_cb = QCheckBox("Enable network isolation")
        config_layout.addRow("", self.network_isolation_cb)
        
        self.auto_terminate_cb = QCheckBox("Auto-terminate suspicious processes")
        self.auto_terminate_cb.setChecked(True)
        config_layout.addRow("", self.auto_terminate_cb)
        
        self.desktop_alert_cb = QCheckBox("Show desktop alerts")
        self.desktop_alert_cb.setChecked(True)
        config_layout.addRow("", self.desktop_alert_cb)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Emergency actions
        actions_group = QGroupBox("Emergency Actions")
        actions_layout = QVBoxLayout()
        
        activate_btn = QPushButton("🚨 ACTIVATE EMERGENCY LOCKDOWN")
        activate_btn.setStyleSheet("background-color: #ff0000; color: white; font-weight: bold; padding: 15px;")
        activate_btn.clicked.connect(self.activate_emergency_lockdown)
        actions_layout.addWidget(activate_btn)
        
        lift_btn = QPushButton("🔓 Lift Lockdown")
        lift_btn.setStyleSheet("background-color: #00aa00; color: white; font-weight: bold; padding: 10px;")
        lift_btn.clicked.connect(self.lift_emergency_lockdown)
        actions_layout.addWidget(lift_btn)
        
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    
    def create_alerts_tab(self):
        """Create email/SIEM alerts configuration tab"""
        widget = QWidget()
        
        # Wrap in Scroll Area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        
        content_widget = QWidget()
        content_layout = QVBoxLayout()
        
        # Email alerting
        email_group = QGroupBox("📧 Email Alerting")
        email_layout = QFormLayout()
        
        self.email_enabled_cb = QCheckBox("Enable email alerts")
        email_layout.addRow("", self.email_enabled_cb)
        
        self.email_provider_combo = self.create_combo(["Gmail", "Office 365", "Outlook", "Custom SMTP"])
        email_layout.addRow("Provider:", self.email_provider_combo)
        
        self.email_from = QLineEdit()
        email_layout.addRow("From Email:", self.email_from)
        
        self.email_username = QLineEdit()
        email_layout.addRow("SMTP Username:", self.email_username)
        
        self.email_password = QLineEdit()
        self.email_password.setEchoMode(QLineEdit.EchoMode.Password)
        email_layout.addRow("SMTP Password:", self.email_password)
        
        self.email_recipients = QTextEdit()
        self.email_recipients.setMaximumHeight(60)
        self.email_recipients.setPlaceholderText("Enter recipient emails, one per line")
        email_layout.addRow("Recipients:", self.email_recipients)
        
        test_email_btn = QPushButton("📨 Send Test Email")
        test_email_btn.clicked.connect(self.send_test_email)
        email_layout.addRow("", test_email_btn)
        
        email_group.setLayout(email_layout)
        content_layout.addWidget(email_group)
        
        # SIEM integration
        siem_group = QGroupBox("🔍 SIEM Integration")
        siem_layout = QFormLayout()
        
        self.siem_enabled_cb = QCheckBox("Enable SIEM forwarding")
        siem_layout.addRow("", self.siem_enabled_cb)
        
        self.siem_platform_combo = self.create_combo(["Splunk", "ELK", "QRadar", "Azure Sentinel", "Generic Syslog"])
        siem_layout.addRow("Platform:", self.siem_platform_combo)
        
        self.siem_server = QLineEdit()
        siem_layout.addRow("SIEM Server:", self.siem_server)
        
        self.siem_port = QSpinBox()
        self.siem_port.setRange(1, 65535)
        self.siem_port.setValue(514)
        siem_layout.addRow("Port:", self.siem_port)
        
        self.siem_protocol_combo = self.create_combo(["UDP", "TCP", "TLS"])
        siem_layout.addRow("Protocol:", self.siem_protocol_combo)
        
        self.siem_format_combo = self.create_combo(["RFC 5424", "CEF", "JSON"])
        siem_layout.addRow("Format:", self.siem_format_combo)
        
        test_siem_btn = QPushButton("🧪 Send Test Event")
        test_siem_btn.clicked.connect(self.send_test_siem_event)
        siem_layout.addRow("", test_siem_btn)
        
        siem_group.setLayout(siem_layout)
        content_layout.addWidget(siem_group)
        
        # Rate limiting
        rate_group = QGroupBox("⏱️ Rate Limiting")
        rate_layout = QFormLayout()
        
        self.max_emails_hour = QSpinBox()
        self.max_emails_hour.setRange(1, 100)
        self.max_emails_hour.setValue(10)
        rate_layout.addRow("Max emails per hour:", self.max_emails_hour)
        
        self.max_emails_day = QSpinBox()
        self.max_emails_day.setRange(1, 1000)
        self.max_emails_day.setValue(50)
        rate_layout.addRow("Max emails per day:", self.max_emails_day)
        
        rate_group.setLayout(rate_layout)
        content_layout.addWidget(rate_group)
        
        # Save button
        save_alerts_btn = QPushButton("💾 Save Alert Settings")
        save_alerts_btn.clicked.connect(self.save_alert_settings)
        content_layout.addWidget(save_alerts_btn)
        
        content_layout.addStretch()
        content_widget.setLayout(content_layout)
        
        scroll_area.setWidget(content_widget)
        
        # Main layout for the tab
        main_layout = QVBoxLayout()
        main_layout.addWidget(scroll_area)
        widget.setLayout(main_layout)
        
        return widget
    
    def create_shadow_tab(self):
        """Create shadow copy protection tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("💾 Shadow Copy Protection")
        header.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # Protection status
        status_group = QGroupBox("Protection Status")
        status_layout = QVBoxLayout()
        
        self.shadow_protection_label = QLabel("Monitoring: Inactive")
        self.shadow_protection_label.setFont(QFont("Arial", 12))
        status_layout.addWidget(self.shadow_protection_label)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_shadow_btn = QPushButton("▶️ Start Monitoring")
        self.start_shadow_btn.clicked.connect(self.start_shadow_protection)
        button_layout.addWidget(self.start_shadow_btn)
        
        self.stop_shadow_btn = QPushButton("⏸️ Stop Monitoring")
        self.stop_shadow_btn.clicked.connect(self.stop_shadow_protection)
        self.stop_shadow_btn.setEnabled(False)
        button_layout.addWidget(self.stop_shadow_btn)
        
        status_layout.addLayout(button_layout)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Current shadow copies
        copies_group = QGroupBox("Current Shadow Copies")
        copies_layout = QVBoxLayout()
        
        self.shadow_copies_table = QTableWidget()
        self.shadow_copies_table.setColumnCount(4)
        self.shadow_copies_table.setHorizontalHeaderLabels(["ID", "Volume", "Created", "Path"])
        self.shadow_copies_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        copies_layout.addWidget(self.shadow_copies_table)
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh Shadow Copies")
        refresh_btn.clicked.connect(self.refresh_shadow_copies)
        copies_layout.addWidget(refresh_btn)
        
        copies_group.setLayout(copies_layout)
        layout.addWidget(copies_group)
        
        # Shadow copy management
        management_group = QGroupBox("Shadow Copy Management")
        management_layout = QHBoxLayout()
        
        create_btn = QPushButton("📸 Create Shadow Copy")
        create_btn.clicked.connect(self.create_shadow_copy)
        management_layout.addWidget(create_btn)
        
        configure_btn = QPushButton("⚙️ Configure VSS Storage")
        configure_btn.clicked.connect(self.configure_vss_storage)
        management_layout.addWidget(configure_btn)
        
        management_group.setLayout(management_layout)
        layout.addWidget(management_group)
        
        # Statistics
        stats_group = QGroupBox("VSS Statistics")
        stats_layout = QVBoxLayout()
        
        self.vss_stats = QTextEdit()
        self.vss_stats.setReadOnly(True)
        self.vss_stats.setMaximumHeight(150)
        stats_layout.addWidget(self.vss_stats)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def apply_theme(self):
        """Apply dark theme"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QWidget {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QGroupBox {
                border: 2px solid #3f3f3f;
                border-radius: 5px;
                margin-top: 10px;
                font-weight: bold;
                padding: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QPushButton {
                background-color: #0d7377;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #14a085;
            }
            QPushButton:pressed {
                background-color: #0a5f63;
            }
            QTableWidget {
                background-color: #2d2d2d;
                border: 1px solid #3f3f3f;
                gridline-color: #3f3f3f;
                color: #ffffff;
            }
            QTableWidget::item {
                padding: 5px;
                color: #ffffff;
                background-color: #2d2d2d;
            }
            QTableWidget::item:selected {
                background-color: #0d7377;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #3f3f3f;
                color: white;
                padding: 5px;
                border: none;
                font-weight: bold;
            }
            QListWidget {
                background-color: #2d2d2d;
                border: 1px solid #3f3f3f;
            }
            QLineEdit, QSpinBox {
                background-color: #2d2d2d;
                border: 1px solid #3f3f3f;
                padding: 5px;
                border-radius: 3px;
                color: #e8e8e8;
                selection-background-color: #0d7377;
                selection-color: #ffffff;
            }
            QCheckBox, QLabel {
                color: #e8e8e8;
            }
            QTabWidget::pane {
                border: 1px solid #3f3f3f;
            }
            QTabBar::tab {
                background-color: #2d2d2d;
                color: white;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #0d7377;
            }
            #stat_value {
                color: #00ff00;
            }
        """)
    
    def setup_system_tray(self):
        """Setup system tray icon"""
        self.tray_icon = QSystemTrayIcon(self)
        # Set an application icon if available; fall back to a built-in
        icon_path = Path(__file__).parent / "icons" / "shield.png"
        if icon_path.exists():
            self.tray_icon.setIcon(QIcon(str(icon_path)))
        else:
            # Use SP_DialogYesButton as fallback (green checkmark closest to shield)
            self.tray_icon.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogYesButton))
        self.tray_icon.setToolTip("Anti-Ransomware Protection")
        
        # Tray menu
        tray_menu = QMenu()
        show_action = QAction("Show Window", self)
        show_action.triggered.connect(self.show)
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.quit_application)
        
        tray_menu.addAction(show_action)
        tray_menu.addSeparator()
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
    
    def setup_timers(self):
        """Setup update timers"""
        # Refresh UI every 5 seconds
        self.ui_timer = QTimer()
        self.ui_timer.timeout.connect(self.update_ui)
        self.ui_timer.start(5000)
    
    def start_monitoring(self):
        """Start background monitoring"""
        if self.engine and not self.monitor_thread:
            self.monitor_thread = MonitorThread(self.engine)
            self.monitor_thread.stats_updated.connect(self.update_stats)
            self.monitor_thread.event_detected.connect(self.handle_event)
            self.monitor_thread.start()
    
    def start_protection(self):
        """Start 4-layer multi-level protection: Kernel + OS + NTFS + Encrypt"""
        # Check if running as admin
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            QMessageBox.critical(
                self, "Administrator Required",
                "This application requires Administrator privileges to start protection.\n\n"
                "Please:\n"
                "1. Close this application\n"
                "2. Right-click the application shortcut or script\n"
                "3. Select 'Run as Administrator'\n\n"
                "Without admin rights, protection cannot be activated."
            )
            return
        
        if not self.engine:
            QMessageBox.warning(self, "Error", "Protection engine not initialized!")
            return
        
        if not self.db:
            QMessageBox.warning(self, "Error", "Database not initialized!")
            return
        
        try:
            # Import four-layer protection module
            try:
                from four_layer_protection import FourLayerProtection
                four_layer = FourLayerProtection(self.engine.token_manager, self.db)
                print("\n" + "="*70)
                print("🛡️ STARTING COMPREHENSIVE 4-LAYER PROTECTION SYSTEM")
                print("="*70)
            except ImportError:
                print("⚠️ Four-layer protection module not available")
                four_layer = None
            
            # Get protected paths from database
            paths = self.db.get_protected_paths()
            if not paths:
                reply = QMessageBox.question(
                    self, "No Protected Paths",
                    "No protected paths configured. Add default paths?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.Yes:
                    self._init_default_paths()
                    paths = self.db.get_protected_paths()
            
            if paths:
                # Apply four-layer protection to each path
                if four_layer:
                    for path_info in paths:
                        path = path_info['path']
                        if Path(path).exists():
                            # Apply all 4 protection layers
                            four_layer.apply_complete_protection(path)
                
                # CRITICAL: Start real-time file blocker for token-based access control
                if hasattr(self.engine, 'file_blocker') and self.engine.file_blocker:
                    for path_info in paths:
                        path = path_info['path']
                        if Path(path).exists():
                            # Register path with real-time blocker
                            self.engine.file_blocker.add_protected_path(path)
                    
                    # Start the blocker - this will prevent ALL file access without USB token
                    try:
                        self.engine.file_blocker.start_monitoring()
                        print(f"\n🛡️ REAL-TIME FILE BLOCKER ACTIVATED")
                        print(f"🔒 Files in protected paths are BLOCKED without valid USB token")
                    except PermissionError as pe:
                        print(f"\n⚠️  Real-time blocker unavailable for this path (OneDrive/cloud paths may have access restrictions)")
                        print(f"   Other protection layers (NTFS, encryption) remain active")
                    except Exception as e:
                        print(f"\n⚠️  Real-time blocker error: {e}")
                        print(f"   Other protection layers (NTFS, encryption) remain active")
                
                # Start legacy file system monitoring with watchdog
                if Observer:
                    self.observer = Observer()
                    for path_info in paths:
                        path = path_info['path']
                        if Path(path).exists():
                            try:
                                # Create event handler for this path
                                handler = self.create_file_handler(path)
                                self.observer.schedule(handler, path, recursive=path_info.get('recursive', True))
                            except PermissionError:
                                # Skip this path if not accessible
                                print(f"   ⚠️  Skipping watchdog for {path} (permission denied)")
                                continue
                    
                    try:
                        self.observer.start()
                    except PermissionError as pe:
                        print(f"⚠️  Watchdog monitoring unavailable (path access restricted)")
                        print(f"   Other protection layers remain active")
                
                self.protection_active = True
                self.status_label.setText("● PROTECTED + BLOCKED (4-Layer)")
                self.status_label.setStyleSheet("color: #ff0000; font-weight: bold;")
                self.start_btn.setEnabled(False)
                self.stop_btn.setEnabled(True)
                self.statusBar().showMessage(f"🛡️ 4-LAYER PROTECTION ACTIVE - USB TOKEN REQUIRED - {len(paths)} paths protected")
                
                # Log event
                self.db.log_event("protection_started", "", "System", "4-Layer protection activated: Kernel + OS + NTFS + Encryption")
                
                # Refresh events to show the start event
                self.refresh_events()
                
                print("\n✅ Protection startup complete")
                print("="*70 + "\n")
            else:
                QMessageBox.warning(self, "Error", "No valid paths to protect!")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start protection: {e}")
            import traceback
            traceback.print_exc()
    
    def create_file_handler(self, path):
        """Create file system event handler"""
        from watchdog.events import FileSystemEventHandler
        
        class ProtectionHandler(FileSystemEventHandler):
            def __init__(self, db, main_window):
                self.db = db
                self.main_window = main_window
                self.modification_counts = {}
                self.last_check = {}
            
            def on_modified(self, event):
                if not event.is_directory:
                    self.check_suspicious_activity(event.src_path, "modified")
            
            def on_created(self, event):
                if not event.is_directory:
                    self.check_suspicious_activity(event.src_path, "created")
            
            def on_deleted(self, event):
                if not event.is_directory:
                    self.check_suspicious_activity(event.src_path, "deleted")
            
            def check_suspicious_activity(self, file_path, event_type):
                try:
                    # Log the event
                    self.db.log_event(event_type, file_path, "FileSystem", f"File {event_type}")
                    
                    # Check for rapid modifications (ransomware indicator)
                    import time
                    current_time = time.time()
                    
                    # Count modifications in last minute
                    if event_type == "modified":
                        if file_path not in self.modification_counts:
                            self.modification_counts[file_path] = []
                        
                        # Remove old entries (older than 60 seconds)
                        self.modification_counts[file_path] = [
                            t for t in self.modification_counts[file_path] 
                            if current_time - t < 60
                        ]
                        
                        # Add current modification
                        self.modification_counts[file_path].append(current_time)
                        
                        # Check if too many modifications
                        if len(self.modification_counts[file_path]) > 10:
                            # Suspicious! Log as threat
                            self.db.log_event(
                                "threat_detected", 
                                file_path, 
                                "RansomwareDetector", 
                                f"Rapid modifications detected: {len(self.modification_counts[file_path])} in 60s"
                            )
                            # Emit signal to update UI
                            if hasattr(self.main_window, 'refresh_events'):
                                QTimer.singleShot(0, self.main_window.refresh_events)
                            
                except Exception as e:
                    print(f"Error in file handler: {e}")
        
        return ProtectionHandler(self.db, self)
    
    def stop_protection(self):
        """Stop protection engine"""
        try:
            # Stop real-time file blocker
            if self.engine and hasattr(self.engine, 'file_blocker') and self.engine.file_blocker:
                self.engine.file_blocker.stop_monitoring()
                print("🛡️ Real-time file blocker stopped")
            
            if hasattr(self, 'observer'):
                self.observer.stop()
                self.observer.join(timeout=2)

            # Disable kernel protection if active
            if HAS_KERNEL_PROTECTION and self.kernel_protection:
                try:
                    self.kernel_protection.disable_protection()
                except Exception:
                    pass
            
            self.protection_active = False
            self.status_label.setText("● STOPPED")
            self.status_label.setStyleSheet("color: #ff0000; font-weight: bold;")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.statusBar().showMessage("Protection stopped")
            
            # Log event
            if self.db:
                self.db.log_event("protection_stopped", "", "System", "Protection deactivated")
                self.refresh_events()
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to stop protection: {e}")
    
    def add_protected_path(self):
        """Add new protected path"""
        dialog = AddPathDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            path_info = dialog.get_path_info()
            print(f"[DEBUG] add_protected_path: Adding path: {path_info['path']}")
            if path_info['path'] and self.db:
                try:
                    # Step 1: Add to database
                    result = self.db.add_protected_path(
                        path_info['path'],
                        recursive=path_info['recursive']
                    )
                    print(f"[DEBUG] add_protected_path: Database result = {result}")
                    
                    # Step 2: CRITICAL - Apply file encryption protection
                    if result and self.engine:
                        print(f"🔒 [GUI] Triggering file encryption for: {path_info['path']}")
                        self.engine.file_manager.apply_unbreakable_protection(path_info['path'])
                    
                    self.db.log_event("path_added", path_info['path'], "User", "Protected path added")
                    self.refresh_protected_paths()
                    self.refresh_events()
                    QMessageBox.information(self, "Success", "Path added and encrypted successfully!")
                except Exception as e:
                    print(f"[ERROR] add_protected_path failed: {e}")
                    import traceback
                    traceback.print_exc()
                    QMessageBox.critical(self, "Error", f"Failed to add path: {e}")
    
    def remove_protected_path(self):
        """Remove selected protected path"""
        selected = self.paths_table.currentRow()
        if selected >= 0 and self.db:
            path = self.paths_table.item(selected, 0).text()
            reply = QMessageBox.question(
                self, "Confirm", f"Remove protection from:\n{path}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    self.db.remove_protected_path(path)
                    self.db.log_event("path_removed", path, "User", "Protected path removed")
                    self.refresh_protected_paths()
                    self.refresh_events()
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to remove path: {e}")
    
    def debug_table(self):
        """Debug table contents"""
        msg = f"Table Debug Info:\n"
        msg += f"Rows: {self.paths_table.rowCount()}\n"
        msg += f"Columns: {self.paths_table.columnCount()}\n"
        msg += f"Visible: {self.paths_table.isVisible()}\n"
        msg += f"Enabled: {self.paths_table.isEnabled()}\n\n"
        
        for row in range(self.paths_table.rowCount()):
            for col in range(self.paths_table.columnCount()):
                item = self.paths_table.item(row, col)
                if item:
                    msg += f"[{row},{col}]: {item.text()}\n"
                else:
                    msg += f"[{row},{col}]: None\n"
        
        paths = self.db.get_protected_paths() if self.db else []
        msg += f"\nDatabase has {len(paths)} paths"
        
        QMessageBox.information(self, "Table Debug", msg)
        print(msg)
    
    def open_protected_file(self):
        """Open a protected file with token verification"""
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Protected File to Open",
                "",
                "All Files (*.*)"
            )
            
            if not file_path:
                return
            
            if not ProtectionEngine:
                QMessageBox.warning(self, "Error", "Protection engine not available")
                return
            
            # Use the safe file reading API
            content = self.engine.safe_read_file(file_path)
            
            if content is not None:
                # Display content in a dialog
                dialog = QDialog(self)
                dialog.setWindowTitle(f"File: {Path(file_path).name}")
                dialog.resize(800, 600)
                
                layout = QVBoxLayout()
                
                text_edit = QTextEdit()
                text_edit.setPlainText(content)
                text_edit.setReadOnly(True)
                layout.addWidget(text_edit)
                
                close_btn = QPushButton("Close")
                close_btn.clicked.connect(dialog.accept)
                layout.addWidget(close_btn)
                
                dialog.setLayout(layout)
                dialog.exec()
                
                QMessageBox.information(
                    self,
                    "Success",
                    f"Successfully opened protected file:\n{Path(file_path).name}"
                )
            else:
                QMessageBox.critical(
                    self,
                    "Access Denied",
                    f"Cannot open protected file. Ensure:\n"
                    f"1. Valid USB token is inserted\n"
                    f"2. File is protected by this system\n"
                    f"3. Token has proper permissions"
                )
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error opening protected file: {e}")
    
    def edit_protected_file(self):
        """Edit a protected file with token verification"""
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Protected File to Edit",
                "",
                "All Files (*.*)"
            )
            
            if not file_path:
                return
            
            if not ProtectionEngine:
                QMessageBox.warning(self, "Error", "Protection engine not available")
                return
            
            # Use the safe file edit API
            if self.engine.safe_edit_file(file_path):
                QMessageBox.information(
                    self,
                    "Success",
                    f"Protected file opened for editing:\n{Path(file_path).name}\n\n"
                    f"⚠️ Note: Protection will be restored when you close this application."
                )
            else:
                QMessageBox.critical(
                    self,
                    "Access Denied",
                    f"Cannot edit protected file. Ensure:\n"
                    f"1. Valid USB token is inserted\n"
                    f"2. File is protected by this system\n"
                    f"3. Token has proper permissions"
                )
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error editing protected file: {e}")
    
    def list_protected_files(self):
        """List all protected files in selected folder"""
        try:
            # Get selected folder from table
            current_row = self.paths_table.currentRow()
            if current_row < 0:
                QMessageBox.information(
                    self,
                    "No Selection",
                    "Please select a protected folder from the table first"
                )
                return
            
            folder_path = self.paths_table.item(current_row, 0).text()
            
            if not ProtectionEngine:
                QMessageBox.warning(self, "Error", "Protection engine not available")
                return
            
            # Get list of protected files
            protected_files = self.engine.list_protected_files(folder_path)
            
            if not protected_files:
                QMessageBox.information(
                    self,
                    "No Protected Files",
                    f"No protected files found in:\n{folder_path}"
                )
                return
            
            # Display list in dialog
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Protected Files in: {Path(folder_path).name}")
            dialog.resize(700, 500)
            
            layout = QVBoxLayout()
            
            info_label = QLabel(f"📁 Folder: {folder_path}\n🔒 Protected Files: {len(protected_files)}")
            info_label.setStyleSheet("font-weight: bold; margin: 10px;")
            layout.addWidget(info_label)
            
            list_widget = QListWidget()
            for file_path in protected_files:
                list_widget.addItem(f"🔐 {file_path}")
            layout.addWidget(list_widget)
            
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.accept)
            layout.addWidget(close_btn)
            
            dialog.setLayout(layout)
            dialog.exec()
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error listing protected files: {e}")
    
    def copy_protected_file(self):
        """Copy a protected file with token verification"""
        try:
            source_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Protected File to Copy",
                "",
                "All Files (*.*)"
            )
            
            if not source_path:
                return
            
            dest_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Copy As",
                Path(source_path).name,
                "All Files (*.*)"
            )
            
            if not dest_path:
                return
            
            if not ProtectionEngine:
                QMessageBox.warning(self, "Error", "Protection engine not available")
                return
            
            # Use the safe file copy API
            if self.engine.copy_protected_file(source_path, dest_path):
                QMessageBox.information(
                    self,
                    "Success",
                    f"Successfully copied protected file:\n"
                    f"From: {Path(source_path).name}\n"
                    f"To: {dest_path}"
                )
            else:
                QMessageBox.critical(
                    self,
                    "Access Denied",
                    f"Cannot copy protected file. Ensure:\n"
                    f"1. Valid USB token is inserted\n"
                    f"2. File is protected by this system\n"
                    f"3. Token has proper permissions"
                )
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error copying protected file: {e}")
    
    def refresh_protected_paths(self):
        """Refresh protected paths list"""
        if not self.db:
            print("[DEBUG] refresh_protected_paths: No database connection!")
            return
        
        if not hasattr(self, 'paths_table'):
            print("[DEBUG] refresh_protected_paths: paths_table not initialized yet!")
            return
        
        try:
            paths = self.db.get_protected_paths()
            print(f"[DEBUG] refresh_protected_paths: Got {len(paths)} paths from database")
            if paths:
                print(f"[DEBUG] First path: {paths[0]}")
            
            # Clear the table first
            self.paths_table.clearContents()
            self.paths_table.setRowCount(len(paths))
            
            for i, path_info in enumerate(paths):
                path_item = QTableWidgetItem(path_info['path'])
                recursive_item = QTableWidgetItem("Yes" if path_info.get('recursive') else "No")
                status_item = QTableWidgetItem("Active")
                added_item = QTableWidgetItem(path_info.get('added_at', 'N/A'))
                
                self.paths_table.setItem(i, 0, path_item)
                self.paths_table.setItem(i, 1, recursive_item)
                self.paths_table.setItem(i, 2, status_item)
                self.paths_table.setItem(i, 3, added_item)
                
                print(f"[DEBUG] Added row {i}: {path_info['path']}")
            
            # Force table to update display
            self.paths_table.viewport().update()
            self.paths_table.update()
            
            print(f"[DEBUG] refresh_protected_paths: Table now has {self.paths_table.rowCount()} rows")
            print(f"[DEBUG] Table column count: {self.paths_table.columnCount()}")
            print(f"[DEBUG] Table visible: {self.paths_table.isVisible()}")
        except Exception as e:
            print(f"[ERROR] Error refreshing paths: {e}")
            import traceback
            traceback.print_exc()
    
    def refresh_events(self):
        """Refresh security events"""
        if not self.db:
            return
        
        try:
            events = self.db.get_events(limit=100)
            self.events_table.setRowCount(len(events))
            
            for i, event in enumerate(events):
                self.events_table.setItem(i, 0, QTableWidgetItem(event.get('timestamp', 'N/A')))
                self.events_table.setItem(i, 1, QTableWidgetItem(event.get('event_type', 'N/A')))
                self.events_table.setItem(i, 2, QTableWidgetItem(event.get('file_path', 'N/A')))
                self.events_table.setItem(i, 3, QTableWidgetItem(event.get('process_name', 'N/A')))
                self.events_table.setItem(i, 4, QTableWidgetItem(event.get('action', 'N/A')))
                self.events_table.setItem(i, 5, QTableWidgetItem(event.get('severity', 'N/A')))
        except Exception as e:
            print(f"Error refreshing events: {e}")
    
    def clear_events(self):
        """Clear all security events"""
        reply = QMessageBox.question(
            self, "Confirm", "Clear all security events?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes and self.db:
            try:
                # Clear events from database
                self.db.clear_events()
                self.refresh_events()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to clear events: {e}")
    
    def save_settings(self):
        """Save application settings"""
        settings = {
            'auto_quarantine': self.auto_quarantine_cb.isChecked(),
            'block_encryption': self.block_encryption_cb.isChecked(),
            'max_modifications': self.max_mods_spin.value(),
            'entropy_threshold': self.entropy_threshold_spin.value(),
            'require_token_for_access': self.require_token_cb.isChecked(),
            'bind_fek_to_token': self.bind_fek_cb.isChecked(),
            'auto_block_on_token_removal': self.auto_block_token_loss_cb.isChecked(),
            'siem_enabled': self.siem_enable_cb.isChecked(),
            'siem_url': self.siem_url_edit.text().strip(),
            'siem_token': self.siem_token_edit.text().strip(),
            'start_with_windows': self.start_with_windows_cb.isChecked(),
            'minimize_to_tray': self.minimize_to_tray_cb.isChecked()
        }
        
        # Save to config file
        config_path = Path.home() / '.antiransomware' / 'gui_config.json'
        config_path.parent.mkdir(exist_ok=True)
        
        with open(config_path, 'w') as f:
            json.dump(settings, f, indent=2)

        self.apply_runtime_settings(settings)
        
        QMessageBox.information(self, "Success", "Settings saved successfully!")

    def load_settings(self):
        """Load settings from disk and apply to UI"""
        config_path = Path.home() / '.antiransomware' / 'gui_config.json'
        if not config_path.exists():
            return

        try:
            with open(config_path, 'r') as f:
                settings = json.load(f)
        except Exception as e:
            print(f"⚠️ Failed to read settings: {e}")
            return

        self.auto_quarantine_cb.setChecked(settings.get('auto_quarantine', True))
        self.block_encryption_cb.setChecked(settings.get('block_encryption', True))
        self.max_mods_spin.setValue(settings.get('max_modifications', 50))
        self.entropy_threshold_spin.setValue(settings.get('entropy_threshold', 80))
        self.require_token_cb.setChecked(settings.get('require_token_for_access', True))
        self.bind_fek_cb.setChecked(settings.get('bind_fek_to_token', True))
        self.auto_block_token_loss_cb.setChecked(settings.get('auto_block_on_token_removal', True))
        self.siem_enable_cb.setChecked(settings.get('siem_enabled', False))
        self.siem_url_edit.setText(settings.get('siem_url', ""))
        self.siem_token_edit.setText(settings.get('siem_token', ""))
        self.start_with_windows_cb.setChecked(settings.get('start_with_windows', False))
        self.minimize_to_tray_cb.setChecked(settings.get('minimize_to_tray', True))

        self.apply_runtime_settings(settings)

    def apply_runtime_settings(self, settings: dict):
        """Push selected settings into the running engine where possible."""
        if not self.engine:
            return

        try:
            file_manager = getattr(self.engine, 'file_manager', None)
            if file_manager:
                setattr(file_manager, 'require_token_for_access', settings.get('require_token_for_access', True))
                setattr(file_manager, 'bind_fek_to_token', settings.get('bind_fek_to_token', True))
                setattr(file_manager, 'auto_block_on_token_removal', settings.get('auto_block_on_token_removal', True))
        except Exception as e:
            print(f"⚠️ Failed to apply access-control settings: {e}")

        if settings.get('siem_enabled'):
            webhook = settings.get('siem_url', "")
            token = settings.get('siem_token', "")
            try:
                if hasattr(self.engine, 'update_siem_config'):
                    self.engine.update_siem_config(webhook, token)
                else:
                    # Fallback: set environment so next engine init picks it up
                    if webhook:
                        os.environ['SIEM_HTTP_URL'] = webhook
                    if token:
                        os.environ['SIEM_HTTP_BEARER'] = token
            except Exception as e:
                print(f"⚠️ Failed to reconfigure SIEM: {e}")
        else:
            os.environ.pop('SIEM_HTTP_URL', None)
            os.environ.pop('SIEM_HTTP_BEARER', None)
    
    def update_stats(self, stats):
        """Update statistics display"""
        # Update stat cards
        protected_value = self.protected_files_card.findChild(QLabel, "stat_value")
        if protected_value:
            protected_value.setText(str(stats.get('protected_files', 0)))
        
        threats_value = self.threats_blocked_card.findChild(QLabel, "stat_value")
        if threats_value:
            threats_value.setText(str(stats.get('threats_blocked', 0)))
        
        cpu_value = self.cpu_usage_card.findChild(QLabel, "stat_value")
        if cpu_value:
            cpu_value.setText(f"{stats.get('cpu', 0):.1f}%")
        
        memory_value = self.memory_usage_card.findChild(QLabel, "stat_value")
        if memory_value:
            memory_value.setText(f"{stats.get('memory', 0):.1f}%")
    
    def handle_event(self, event):
        """Handle security event"""
        # Add to recent events list
        event_text = f"[{event.get('timestamp')}] {event.get('event_type')} - {event.get('file_path')}"
        self.recent_events_list.insertItem(0, event_text)
        
        # Keep only last 50 events
        while self.recent_events_list.count() > 50:
            self.recent_events_list.takeItem(self.recent_events_list.count() - 1)
    
    def update_ui(self):
        """Periodic UI update"""
        # Refresh current tab
        current_index = self.tabs.currentIndex()
        if current_index == 1:  # Protected Paths
            self.refresh_protected_paths()
        elif current_index == 2:  # Events
            self.refresh_events()

        # Update TPM/ML status indicators
        try:
            if self.tpm_status_label:
                if self.tpm_manager and getattr(self.tpm_manager, "tpm_available", False):
                    self.tpm_status_label.setText("TPM 2.0 active (NCrypt)")
                    self.tpm_status_label.setStyleSheet("color: #0a8f08; font-weight: 600;")
                elif self.tpm_manager is None and HAS_TPM_MANAGER:
                    self.tpm_status_label.setText("TPM manager not initialized")
                    self.tpm_status_label.setStyleSheet("color: #d48806;")
                else:
                    self.tpm_status_label.setText("TPM unavailable")
                    self.tpm_status_label.setStyleSheet("color: #c0392b;")

            if self.ml_status_label:
                if self.ml_model_path.exists():
                    self.ml_status_label.setText(f"Model loaded: {self.ml_model_path.name}")
                    self.ml_status_label.setStyleSheet("color: #0a8f08; font-weight: 600;")
                else:
                    self.ml_status_label.setText("Model missing – train or place .pkl in models/")
                    self.ml_status_label.setStyleSheet("color: #c0392b;")
        except Exception:
            # Keep UI resilient
            pass
    
    def closeEvent(self, event):
        """Handle window close"""
        if self.minimize_to_tray_cb.isChecked():
            event.ignore()
            self.hide()
            self.tray_icon.showMessage(
                "Anti-Ransomware Protection",
                "Application minimized to tray",
                QSystemTrayIcon.MessageIcon.Information,
                2000
            )
        else:
            self.quit_application()
    
    def quit_application(self):
        """Quit application"""
        # Restore protection to all files before closing
        if self.engine:
            try:
                print("🔒 Restoring file protection before shutdown...")
                self.engine.restore_all_file_access()
            except Exception as e:
                print(f"⚠️ Error restoring file protection: {e}")
        
        # Stop monitoring
        if self.monitor_thread:
            self.monitor_thread.stop()
            self.monitor_thread.wait()
        
        # Stop engine
        if self.engine:
            try:
                self.engine.stop()
            except:
                pass
        
        QApplication.quit()
    
    def refresh_usb_drives(self):
        """Refresh list of USB drives"""
        try:
            self.usb_drives_list.clear()
            
            if self.engine and hasattr(self.engine, 'token_manager'):
                if hasattr(self.engine.token_manager, 'enterprise_mode') and self.engine.token_manager.enterprise_mode:
                    # Use enterprise USB detection
                    drives = self.engine.token_manager.enterprise_manager.get_available_usb_drives()
                    
                    if drives:
                        for drive in drives:
                            drive_str = str(drive)
                            self.usb_drives_list.addItem(f"📀 {drive_str}")
                        self.statusBar().showMessage(f"Found {len(drives)} USB drive(s)")
                        # Auto-check for tokens
                        self.check_drives_for_tokens(drives)
                    else:
                        self.usb_drives_list.addItem("No USB drives detected")
                        self.statusBar().showMessage("No USB drives found")
                else:
                    # Legacy USB detection
                    import psutil
                    drives = []
                    for partition in psutil.disk_partitions():
                        if 'removable' in partition.opts.lower():
                            drives.append(partition.mountpoint)
                    
                    if drives:
                        for drive in drives:
                            self.usb_drives_list.addItem(f"📀 {drive}")
                        self.statusBar().showMessage(f"Found {len(drives)} USB drive(s)")
                        # Auto-check for tokens
                        self.check_drives_for_tokens(drives)
                    else:
                        self.usb_drives_list.addItem("No USB drives detected")
                        self.statusBar().showMessage("No USB drives found")
            else:
                self.usb_drives_list.addItem("Engine not initialized")
                
        except Exception as e:
            self.usb_drives_list.addItem(f"Error: {str(e)}")
            self.statusBar().showMessage(f"USB scan error: {str(e)}")
    
    def update_device_fingerprint(self):
        """Update device fingerprint display"""
        try:
            if self.engine and hasattr(self.engine, 'token_manager'):
                if hasattr(self.engine.token_manager, 'enterprise_mode') and self.engine.token_manager.enterprise_mode:
                    # Enterprise fingerprint
                    fp = self.engine.token_manager.enterprise_manager.device_fingerprint
                    self.device_fingerprint_label.setText(f"🔐 Device Fingerprint: {fp[:48]}...")
                else:
                    # Legacy fingerprint
                    fp = self.engine.token_manager.hardware_fingerprint
                    self.device_fingerprint_label.setText(f"Device Fingerprint: {fp[:32]}...")
        except Exception as e:
            self.device_fingerprint_label.setText(f"Device Fingerprint: Error - {str(e)}")
    
    def create_usb_token(self):
        """Create new USB token"""
        try:
            # Get selected USB drive
            selected_items = self.usb_drives_list.selectedItems()
            if not selected_items:
                QMessageBox.warning(self, "No Selection", "Please select a USB drive first!")
                return
            
            # Extract drive path
            drive_text = selected_items[0].text()
            drive_path = drive_text.replace("📀 ", "").strip()
            
            if not self.engine or not hasattr(self.engine, 'token_manager'):
                QMessageBox.critical(self, "Error", "Engine not initialized!")
                return
            
            # Confirm action
            reply = QMessageBox.question(
                self,
                "Create USB Token",
                f"Create quantum-resistant USB token on {drive_path}?\n\n"
                "This token will be bound to this device's hardware and use:\n"
                "  • Kyber1024 (post-quantum key exchange)\n"
                "  • Dilithium3 (post-quantum signatures)\n"
                "  • AES-256-GCM (hybrid encryption)\n\n"
                "Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.statusBar().showMessage("Creating quantum-resistant token...")
                
                # Create token
                token_path = self.engine.token_manager.create_token(drive_path)
                
                if token_path:
                    self.token_status_label.setText(f"✅ Token created: {token_path}")
                    self.token_info_text.append(f"\n✅ Token created successfully!\n   Path: {token_path}")
                    QMessageBox.information(
                        self,
                        "Success",
                        f"USB token created successfully!\n\nLocation: {token_path}\n\n"
                        "Keep this USB drive safe - it's your master key!"
                    )
                    self.statusBar().showMessage("Token created successfully!")
                else:
                    self.token_status_label.setText("❌ Token creation failed")
                    QMessageBox.critical(self, "Error", "Failed to create USB token. Check console for details.")
                    self.statusBar().showMessage("Token creation failed!")
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create token: {str(e)}")
            self.statusBar().showMessage(f"Token creation error: {str(e)}")
    
    def validate_usb_token(self):
        """Validate USB token"""
        try:
            # Get selected USB drive
            selected_items = self.usb_drives_list.selectedItems()
            if not selected_items:
                QMessageBox.warning(self, "No Selection", "Please select a USB drive first!")
                return
            
            # Extract drive path
            drive_text = selected_items[0].text()
            drive_path = drive_text.replace("📀 ", "").strip()
            
            if not self.engine or not hasattr(self.engine, 'token_manager'):
                QMessageBox.critical(self, "Error", "Engine not initialized!")
                return
            
            self.statusBar().showMessage("Validating token...")
            
            # Find token files on drive
            import glob
            import os
            
            # Look for both quantum tokens and legacy tokens
            quantum_tokens = glob.glob(os.path.join(drive_path, "quantum_token_*.qkey"))
            legacy_tokens = glob.glob(os.path.join(drive_path, "protection_token_*.key"))
            
            all_tokens = quantum_tokens + legacy_tokens
            
            if not all_tokens:
                QMessageBox.warning(
                    self,
                    "No Token Found",
                    f"No USB tokens found on {drive_path}\n\n"
                    "Please insert a USB drive with a valid token or create a new one."
                )
                self.token_status_label.setText("❌ No token found on drive")
                self.statusBar().showMessage("No token found")
                return
            
            # Validate each token
            valid_tokens = []
            for token_path in all_tokens:
                is_valid = self.engine.token_manager.validate_secure_token(token_path)
                if is_valid:
                    valid_tokens.append(token_path)
            
            if valid_tokens:
                token_info = "\n".join([f"  • {os.path.basename(t)}" for t in valid_tokens])
                self.token_status_label.setText(f"✅ {len(valid_tokens)} valid token(s) detected")
                self.token_info_text.append(f"\n✅ Token validation successful!\n{token_info}")
                QMessageBox.information(
                    self,
                    "Token Valid",
                    f"Found {len(valid_tokens)} valid token(s):\n\n{token_info}\n\n"
                    "✅ You can now access protected files!"
                )
                self.statusBar().showMessage(f"{len(valid_tokens)} valid token(s) found!")
            else:
                self.token_status_label.setText("⚠️ Token(s) not valid for this device")
                
                reply = QMessageBox.question(
                    self,
                    "Invalid Token - Create New?",
                    f"Found {len(all_tokens)} token(s) but none are valid for THIS device.\n\n"
                    "❌ Tokens are hardware-bound and were created on a different device.\n\n"
                    "📝 Possible reasons:\n"
                    "  • Token was created on another computer\n"
                    "  • Device hardware has changed (CPU, BIOS, network card)\n"
                    "  • Token file is corrupted\n\n"
                    "💡 Would you like to create a NEW token for this device?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                
                if reply == QMessageBox.StandardButton.Yes:
                    # Automatically trigger token creation
                    self.create_usb_token()
                else:
                    self.statusBar().showMessage("Token validation failed - create a new token for this device")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to validate token: {str(e)}")
            self.statusBar().showMessage(f"Validation error: {str(e)}")
    
    def create_combo(self, items):
        """Helper to create combo box"""
        from PyQt6.QtWidgets import QComboBox
        combo = QComboBox()
        combo.addItems(items)
        return combo
    
    # New feature action handlers
    
    def run_health_check(self):
        """Run system health check"""
        if not HAS_HEALTH or not self.health_checker:
            self.health_status_label.setText("Status: [WARN] Health checker unavailable")
            self.health_status_label.setStyleSheet("color: #ffaa00; font-weight: bold;")
            return
        
        try:
            result = self.health_checker.check_system_health()
            
            # Update status
            if result['healthy']:
                self.health_status_label.setText("Status: [OK] HEALTHY")
                self.health_status_label.setStyleSheet("color: #00ff00; font-weight: bold;")
            else:
                self.health_status_label.setText("Status: [ERROR] COMPROMISED")
                self.health_status_label.setStyleSheet("color: #ff0000; font-weight: bold;")
            
            # Update results
            results_text = "Check Results:\n"
            for check, failed in result['checks'].items():
                status = "[ERROR] FAILED" if failed else "[OK] PASSED"
                results_text += f"  {check}: {status}\n"
            
            self.health_results.setText(results_text)
            
            # Update threat indicators
            self.threat_list.clear()
            for indicator in result['threat_indicators']:
                self.threat_list.addItem(indicator)
            
            self.statusBar().showMessage("Health check complete")
            
        except Exception as e:
            self.health_status_label.setText("Status: [ERROR] Check failed")
            self.health_status_label.setStyleSheet("color: #ff0000; font-weight: bold;")
            QMessageBox.critical(self, "Error", f"Health check failed: {e}")
    
    def toggle_auto_health_check(self, checked):
        """Toggle automatic health checking"""
        if checked:
            QMessageBox.information(self, "Auto-Check Enabled", "Health checks will run every 5 minutes")
        else:
            QMessageBox.information(self, "Auto-Check Disabled", "Automatic health checks disabled")
    
    def activate_emergency_lockdown(self):
        """Activate emergency kill switch"""
        if not HAS_KILL_SWITCH or not self.kill_switch:
            QMessageBox.warning(self, "Not Available", "Emergency kill switch not available")
            return
        
        reply = QMessageBox.critical(
            self,
            "⚠️ EMERGENCY LOCKDOWN",
            "This will:\n"
            "  • Block ALL protected file access\n"
            "  • Terminate suspicious processes\n"
            "  • Isolate network (if enabled)\n"
            "  • Send security alerts\n\n"
            "Are you SURE you want to activate emergency lockdown?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                import os
                user = os.getlogin() if hasattr(os, 'getlogin') else 'GUI_USER'
                self.kill_switch.activate_lockdown(reason="GUI_MANUAL_TRIGGER", triggered_by=user)
                
                self.lockdown_status_label.setText("Status: 🚨 LOCKDOWN ACTIVE")
                self.lockdown_status_label.setStyleSheet("color: #ff0000; font-weight: bold;")
                
                QMessageBox.information(self, "Lockdown Activated", "Emergency lockdown is now active")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to activate lockdown: {e}")
    
    def lift_emergency_lockdown(self):
        """Lift emergency lockdown"""
        if not HAS_KILL_SWITCH or not self.kill_switch:
            QMessageBox.warning(self, "Not Available", "Emergency kill switch not available")
            return
        
        if not self.kill_switch.is_locked_down():
            QMessageBox.information(self, "Not in Lockdown", "System is not currently in lockdown")
            return
        
        reply = QMessageBox.question(
            self,
            "Lift Lockdown",
            "Verify system is clean before lifting lockdown.\n\n"
            "Type 'CONFIRM' in the next dialog to proceed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            from PyQt6.QtWidgets import QInputDialog
            text, ok = QInputDialog.getText(self, "Confirmation", "Type CONFIRM:")
            
            if ok and text == "CONFIRM":
                try:
                    import os
                    user = os.getlogin() if hasattr(os, 'getlogin') else 'GUI_USER'
                    self.kill_switch.lift_lockdown(authorized_by=user, force=True)
                    
                    self.lockdown_status_label.setText("Status: Normal Operations")
                    self.lockdown_status_label.setStyleSheet("color: #00ff00; font-weight: bold;")
                    
                    QMessageBox.information(self, "Lockdown Lifted", "Emergency lockdown has been lifted")
                    
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to lift lockdown: {e}")
    
    def send_test_email(self):
        """Send test email alert"""
        if not HAS_EMAIL or not self.email_alerter:
            QMessageBox.warning(self, "Not Available", "Email alerting not available")
            return
        
        try:
            # Update config from GUI
            self.email_alerter.config['enabled'] = self.email_enabled_cb.isChecked()
            self.email_alerter.config['from_email'] = self.email_from.text()
            self.email_alerter.config['username'] = self.email_username.text()
            self.email_alerter.config['password'] = self.email_password.text()
            self.email_alerter.config['recipients'] = [
                r.strip() for r in self.email_recipients.toPlainText().split('\n') if r.strip()
            ]
            
            success = self.email_alerter.send_alert(
                alert_type='TEST_ALERT',
                severity='INFO',
                details={'message': 'Test email from Anti-Ransomware GUI'},
                attach_logs=False
            )
            
            if success:
                QMessageBox.information(self, "Success", "Test email sent successfully!")
            else:
                QMessageBox.warning(self, "Failed", "Failed to send test email. Check configuration.")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Email test failed: {e}")
    
    def send_test_siem_event(self):
        """Send test event to SIEM"""
        if not HAS_SIEM or not self.siem:
            QMessageBox.warning(self, "Not Available", "SIEM integration not available")
            return
        
        try:
            # Update config from GUI
            self.siem.config['enabled'] = self.siem_enabled_cb.isChecked()
            self.siem.config['siem_server'] = self.siem_server.text()
            self.siem.config['siem_port'] = self.siem_port.value()
            self.siem.config['protocol'] = self.siem_protocol_combo.currentText().lower()
            self.siem.config['format'] = self.siem_format_combo.currentText().lower().replace(' ', '')
            
            import time
            test_event = {
                'timestamp': time.time(),
                'event_type': 'TEST_EVENT',
                'severity': 'INFO',
                'details': {'message': 'Test event from Anti-Ransomware GUI'}
            }
            
            success = self.siem.send_event(test_event)
            
            if success:
                QMessageBox.information(self, "Success", "Test event sent to SIEM successfully!")
            else:
                QMessageBox.warning(self, "Failed", "Failed to send test event. Check configuration.")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"SIEM test failed: {e}")
    
    def save_alert_settings(self):
        """Save alert configuration"""
        try:
            # Save email config
            if HAS_EMAIL and self.email_alerter:
                self.email_alerter.config['enabled'] = self.email_enabled_cb.isChecked()
                self.email_alerter.config['from_email'] = self.email_from.text()
                self.email_alerter.config['username'] = self.email_username.text()
                self.email_alerter.config['password'] = self.email_password.text()
                self.email_alerter.config['recipients'] = [
                    r.strip() for r in self.email_recipients.toPlainText().split('\n') if r.strip()
                ]
                self.email_alerter.config['rate_limit']['max_emails_per_hour'] = self.max_emails_hour.value()
                self.email_alerter.config['rate_limit']['max_emails_per_day'] = self.max_emails_day.value()
                
                # Save to file
                import json
                with self.email_alerter.config_file.open('w') as f:
                    json.dump(self.email_alerter.config, f, indent=2)
            
            # Save SIEM config
            if HAS_SIEM and self.siem:
                self.siem.config['enabled'] = self.siem_enabled_cb.isChecked()
                self.siem.config['siem_server'] = self.siem_server.text()
                self.siem.config['siem_port'] = self.siem_port.value()
                self.siem.config['protocol'] = self.siem_protocol_combo.currentText().lower()
                
                # Save to file
                with self.siem.config_file.open('w') as f:
                    json.dump(self.siem.config, f, indent=2)
            
            QMessageBox.information(self, "Success", "Alert settings saved successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {e}")
    
    def start_shadow_protection(self):
        """Start shadow copy monitoring"""
        if not HAS_SHADOW or not self.shadow_protection:
            QMessageBox.warning(self, "Not Available", "Shadow copy protection not available")
            return
        
        try:
            self.shadow_protection.start_monitoring()
            self.shadow_protection_label.setText("Monitoring: ✅ Active")
            self.shadow_protection_label.setStyleSheet("color: #00ff00; font-weight: bold;")
            self.start_shadow_btn.setEnabled(False)
            self.stop_shadow_btn.setEnabled(True)
            QMessageBox.information(self, "Started", "Shadow copy protection monitoring started")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start monitoring: {e}")
    
    def stop_shadow_protection(self):
        """Stop shadow copy monitoring"""
        if not HAS_SHADOW or not self.shadow_protection:
            return
        
        try:
            self.shadow_protection.stop_monitoring()
            self.shadow_protection_label.setText("Monitoring: Inactive")
            self.shadow_protection_label.setStyleSheet("color: #ff6600;")
            self.start_shadow_btn.setEnabled(True)
            self.stop_shadow_btn.setEnabled(False)
            QMessageBox.information(self, "Stopped", "Shadow copy protection monitoring stopped")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to stop monitoring: {e}")
    
    def refresh_shadow_copies(self):
        """Refresh shadow copies list"""
        if not HAS_SHADOW or not self.shadow_protection:
            QMessageBox.warning(self, "Not Available", "Shadow copy protection not available")
            return
        
        try:
            shadows = self.shadow_protection.list_shadow_copies()
            
            self.shadow_copies_table.setRowCount(len(shadows))
            
            for i, shadow in enumerate(shadows):
                self.shadow_copies_table.setItem(i, 0, QTableWidgetItem(shadow.get('id', 'N/A')[:50]))
                self.shadow_copies_table.setItem(i, 1, QTableWidgetItem(shadow.get('volume', 'N/A')))
                self.shadow_copies_table.setItem(i, 2, QTableWidgetItem(shadow.get('created', 'N/A')))
                self.shadow_copies_table.setItem(i, 3, QTableWidgetItem(shadow.get('path', 'N/A')))
            
            # Update statistics
            stats = self.shadow_protection.get_vss_statistics()
            stats_text = f"Shadow Copies: {stats['shadows_count']}\n\n"
            
            for vol in stats['volumes']:
                stats_text += f"Volume: {vol['volume']}\n"
                stats_text += f"  Used: {vol.get('used', 'N/A')}\n"
                stats_text += f"  Allocated: {vol.get('allocated', 'N/A')}\n"
                stats_text += f"  Maximum: {vol.get('maximum', 'N/A')}\n\n"
            
            self.vss_stats.setText(stats_text)
            
            self.statusBar().showMessage(f"Found {len(shadows)} shadow copies")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to refresh: {e}")
    
    def create_shadow_copy(self):
        """Create a new shadow copy"""
        if not HAS_SHADOW or not self.shadow_protection:
            QMessageBox.warning(self, "Not Available", "Shadow copy protection not available")
            return
        
        reply = QMessageBox.question(
            self,
            "Create Shadow Copy",
            "Create a shadow copy for C: drive?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                success = self.shadow_protection.create_shadow_copy("C:")
                
                if success:
                    QMessageBox.information(self, "Success", "Shadow copy created successfully!")
                    self.refresh_shadow_copies()
                else:
                    QMessageBox.warning(self, "Failed", "Failed to create shadow copy")
                    
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Shadow copy creation failed: {e}")
    
    def configure_vss_storage(self):
        """Configure VSS storage"""
        if not HAS_SHADOW or not self.shadow_protection:
            QMessageBox.warning(self, "Not Available", "Shadow copy protection not available")
            return
        
        from PyQt6.QtWidgets import QInputDialog
        size, ok = QInputDialog.getText(
            self,
            "Configure VSS Storage",
            "Enter maximum storage size (e.g., 10GB, UNBOUNDED):",
            text="10GB"
        )
        
        if ok and size:
            try:
                success = self.shadow_protection.configure_vss_storage("C:", size)
                
                if success:
                    QMessageBox.information(self, "Success", "VSS storage configured successfully!")
                else:
                    QMessageBox.warning(self, "Failed", "Failed to configure VSS storage")
                    
            except Exception as e:
                QMessageBox.critical(self, "Error", f"VSS configuration failed: {e}")
    
    def refresh_logs(self):
        """Refresh log viewer with current log content"""
        try:
            if not Path(LOG_FILE_PATH).exists():
                self.log_viewer.setPlainText("No log file found yet...")
                self.log_stats_label.setText("Status: Log file not created")
                return
            
            # Read log file
            with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
            
            # Apply filters
            level_filter = self.log_level_filter.text().upper().strip()
            search_filter = self.log_search_filter.text().strip()
            
            filtered_lines = []
            for line in all_lines:
                if level_filter and level_filter not in line:
                    continue
                if search_filter and search_filter.lower() not in line.lower():
                    continue
                filtered_lines.append(line)
            
            display_lines = filtered_lines[-1000:]
            content = ''.join(display_lines)
            self.log_viewer.setPlainText(content)
            
            self.log_viewer.verticalScrollBar().setValue(
                self.log_viewer.verticalScrollBar().maximum()
            )
            
            self.log_stats_label.setText(
                f"Lines displayed: {len(display_lines)} / Total: {len(all_lines)} | Filtered: {len(filtered_lines)}"
            )
            
            logger.debug(f'Log viewer refreshed: {len(display_lines)} lines displayed')
            
        except Exception as e:
            self.log_viewer.setPlainText(f"Error reading log file: {e}")
            logger.error(f'Error refreshing logs: {e}')
    
    def open_log_file(self):
        """Open log file in default text editor"""
        try:
            import subprocess
            if Path(LOG_FILE_PATH).exists():
                if sys.platform == 'win32':
                    subprocess.Popen(['notepad', LOG_FILE_PATH])
                elif sys.platform == 'darwin':
                    subprocess.Popen(['open', '-a', 'TextEdit', LOG_FILE_PATH])
                else:
                    subprocess.Popen(['xdg-open', LOG_FILE_PATH])
                logger.info(f'Opened log file in editor: {LOG_FILE_PATH}')
            else:
                QMessageBox.warning(self, "Not Found", f"Log file not found: {LOG_FILE_PATH}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open log file: {e}")
            logger.error(f'Error opening log file: {e}')
    
    def auto_refresh_logs(self):
        """Auto-refresh logs if checkbox is enabled"""
        try:
            if hasattr(self, 'auto_refresh_logs_cb') and self.auto_refresh_logs_cb.isChecked():
                self.refresh_logs()
        except Exception as e:
            logger.error(f'Error in auto-refresh logs: {e}')





def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Anti-Ransomware Protection")
    app.setOrganizationName("AntiRansomware")
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
