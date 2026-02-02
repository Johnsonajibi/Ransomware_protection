# 🐍 PYTHON ANTI-RANSOMWARE VERSION

Advanced user-mode anti-ransomware protection with comprehensive threat detection and modern GUI interface.

## 🚀 Quick Start

```bash
# Run with GUI (Recommended)
python antiransomware_python.py --gui

# Run in command-line mode
python antiransomware_python.py --cli

# Show help
python antiransomware_python.py --help
```

## ✨ Features

### 🛡️ Core Protection
- **Real-time file monitoring** - Detects encryption attempts instantly
- **Behavioral analysis** - Identifies ransomware patterns and behaviors
- **Registry protection** - Backs up and monitors critical registry keys
- **USB authentication** - Controls removable device access
- **Network monitoring** - Detects suspicious connections (Tor, Bitcoin)
- **Process monitoring** - Tracks malicious process behaviors

### 🎨 Advanced GUI
- **Dark theme interface** - Modern, professional appearance
- **Real-time statistics** - Live monitoring counters and graphs
- **Activity logging** - Comprehensive threat and system activity logs
- **Quarantine manager** - Secure isolation and restoration of files
- **Settings management** - Configurable protection policies
- **Threat alerts** - Immediate notification of detected threats

### Monitoring Capabilities
- **File system events** - Create, modify, delete, rename operations
- **Process creation/termination** - Suspicious executable monitoring
- **Registry modifications** - Critical system key protection
- **Network connections** - Outbound traffic analysis
- **USB device insertions** - Removable media control
- **Memory protection** - DEP, ASLR, and heap protection

## 📋 Requirements

- **Python 3.8+** (Recommended: Python 3.11)
- **Windows 10/11** (Primary support)
- **Memory**: 200MB RAM minimum
- **Storage**: 50MB free space

### Dependencies
```bash
pip install psutil wmi pywin32
```

## 🔧 Installation

### Method 1: Simple Installation
```bash
# Navigate to Python-Version directory
cd Python-Version

# Install dependencies (if not already installed)
pip install psutil wmi pywin32

# Run the application
python antiransomware_python.py --gui
```

### Method 2: Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv antiransomware_env

# Activate environment
# Windows:
antiransomware_env\Scripts\activate
# Linux:
source antiransomware_env/bin/activate

# Install dependencies
pip install psutil wmi pywin32

# Run application
python antiransomware_python.py --gui
```

## 🎮 Usage Guide

### GUI Mode (Default)
The graphical interface provides comprehensive control and monitoring:

1. **Launch Application**
   ```bash
   python antiransomware_python.py --gui
   ```

2. **Start Protection**
   - Click "START PROTECTION" button
   - Monitor real-time statistics
   - Review activity log for threats

3. **System Scan**
   - Click "🔍 FULL SCAN" for comprehensive analysis
   - Monitor progress in real-time
   - Review scan results in activity log

4. **Quarantine Management**
   - Click "QUARANTINE" to manage isolated files
   - Restore false positives or delete threats
   - Export quarantine reports

### Command Line Mode
For headless or automated deployments:

```bash
# Start CLI monitoring
python antiransomware_python.py --cli

# The application will run in background
# Press Ctrl+C to stop monitoring
```

### Available Command Line Arguments
```bash
python antiransomware_python.py [OPTIONS]

Options:
  --gui     Launch with graphical interface (default)
  --cli     Run in command-line mode
  --help    Show help message and exit
```

## ⚙️ Configuration

### Application Directory
The application automatically creates its directory:
- **System-wide**: `C:\ProgramData\PythonAntiRansomware` (if admin)
- **User-specific**: `%LOCALAPPDATA%\PythonAntiRansomware` (if not admin)

### Configuration Files
- `config.ini` - Application settings
- `protection.db` - SQLite database for activity logging
- `antiransomware.log` - Text-based activity log
- `quarantine/` - Directory for isolated threats
- `backups/` - Registry and file backups

### Default Configuration
```ini
[Protection]
real_time_monitoring = true
behavioral_analysis = true
registry_protection = true
usb_authentication = true
network_monitoring = true
quarantine_threats = true
backup_critical_files = true

[Directories]
protected_paths = C:\Users;C:\Documents;C:\Desktop
excluded_paths = C:\Windows\Temp;C:\Temp
backup_paths = C:\Users\Documents;C:\Users\Desktop

[Advanced]
threat_threshold = 3
max_file_modifications = 10
analysis_window_minutes = 5
memory_protection = true
```

## 🔍 Threat Detection

### Ransomware Extensions Detected
```
.locked, .encrypted, .crypto, .crypt, .encrypt
.axx, .xyz, .zzz, .micro, .zepto, .locky
.cerber, .vault, .exx, .ezz, .ecc, .xtbl
.wannacry, .wcry, .wncry, .onion, .dharma
```

### Suspicious Process Names
```
encrypt, crypt, ransom, locker, vault
bitcoin, btc, payment, decrypt, recover
restore, cipher, rsa, aes, tor
```

### Behavioral Patterns
- Rapid file modification (>10 files in 30 seconds)
- Extension changes to known ransomware extensions
- Process creation with suspicious names
- Network connections to Tor or Bitcoin ports
- Registry modifications to startup entries

## GUI Interface Guide

### Main Window Components

#### 🎛️ Control Panel
- **Start Protection**: Enables real-time monitoring
- **Stop Protection**: Disables monitoring
- **Full Scan**: Comprehensive system analysis
- **Quarantine**: Manage isolated threats
- **Settings**: Configure protection options

#### 📈 Statistics Panel
- **Files Scanned**: Total files analyzed
- **Threats Blocked**: Prevented malicious actions
- **Active Processes**: Currently monitored processes
- **Network Connections**: Active network monitoring

#### 📋 Activity Log
- **Real-time events**: Live threat detection log
- **Severity levels**: Info, Medium, High threat indicators
- **Detailed information**: File paths, process names, timestamps
- **Action status**: Blocked, Quarantined, Allowed

#### 🔍 Status Bar
- **Protection status**: Active/Inactive indicator
- **Current statistics**: Quick overview of protection metrics
- **System time**: Current timestamp
- **Mode indicator**: Shows if running with admin privileges

## 🚨 Alert System

### Threat Detection Alerts
When threats are detected, the system shows:
- **Popup alert** - Immediate threat notification
- **Activity log entry** - Detailed threat information
- **Status update** - Updated protection statistics
- **Optional actions** - View details, quarantine, or ignore

### Alert Severity Levels
- **🟢 Low (1-2)**: Suspicious activity, monitoring
- **🟡 Medium (3)**: Potential threat, increased monitoring
- **🔴 High (4)**: Likely threat, file quarantined
- **⚫ Critical (5)**: Confirmed threat, immediate action

## Security Features

### Memory Protection
- **DEP (Data Execution Prevention)** - Prevents code execution in data areas
- **ASLR (Address Space Layout Randomization)** - Randomizes memory layouts
- **Heap Protection** - Guards against heap corruption attacks
- **Stack Protection** - Python interpreter-level stack guards

### File System Protection
- **Real-time monitoring** - Immediate file operation detection
- **Hash verification** - File integrity checking
- **Backup creation** - Automatic file backups before modification
- **Quarantine system** - Secure threat isolation

### Registry Protection
- **Critical key backup** - Automatic registry snapshots
- **Modification monitoring** - Real-time registry change detection
- **Restoration capability** - Rollback malicious changes
- **Startup protection** - Monitor autorun entries

## 🛠️ Troubleshooting

### Common Issues

#### Dependencies Not Found
```bash
# Error: ModuleNotFoundError: No module named 'psutil'
# Solution:
pip install psutil wmi pywin32
```

#### Permission Errors
```bash
# Error: PermissionError: [Errno 13] Permission denied
# Solution: Run as Administrator
# Right-click Command Prompt → "Run as administrator"
```

#### High CPU Usage
```python
# Adjust monitoring intervals in config.ini:
[Advanced]
monitoring_interval = 2.0  # Increase from default 1.0
max_log_entries = 500      # Reduce from default 1000
```

#### GUI Not Responding
```bash
# Restart application
# Check system resources
# Reduce monitoring scope in settings
```

### Debug Mode
Enable debug logging by modifying the script:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Performance Optimization
```python
# Recommended settings for better performance:
- Exclude non-critical directories from monitoring
- Increase monitoring intervals
- Disable network monitoring if not needed
- Limit log entry retention
```

## 📁 File Structure

```
Python-Version/
├── antiransomware_python.py    # Main application file
├── README.md                   # This documentation
├── requirements.txt            # Python dependencies
├── config.ini                  # Configuration file (auto-created)
├── protection.db              # SQLite database (auto-created)
├── antiransomware.log         # Application log (auto-created)
├── quarantine/                # Quarantined files (auto-created)
└── backups/                   # System backups (auto-created)
```

## 🔄 Updates and Maintenance

### Updating the Application
```bash
# Get latest version from repository
git pull origin main

# Update dependencies
pip install --upgrade psutil wmi pywin32

# Restart application
python antiransomware_python.py --gui
```

### Database Maintenance
The SQLite database automatically manages size, but you can manually clean it:
```bash
# Backup current database
copy protection.db protection.db.backup

# The application will recreate tables if needed
```

### Log Rotation
Logs are automatically rotated when they exceed size limits. Manual cleanup:
```bash
# Archive old logs
move antiransomware.log antiransomware_old.log

# Application will create new log file
```

## 🎯 Best Practices

### Deployment Recommendations
1. **Run as Administrator** for full system access
2. **Create system exclusions** for trusted applications
3. **Regular backups** of important data
4. **Monitor activity logs** for threat patterns
5. **Update regularly** for latest threat signatures

### Security Recommendations
1. **Enable all protection features** in configuration
2. **Use strong authentication** for USB devices
3. **Monitor network connections** regularly
4. **Review quarantine** contents periodically
5. **Maintain system updates** alongside application

### Performance Recommendations
1. **Exclude system directories** from intensive monitoring
2. **Adjust monitoring intervals** based on system resources
3. **Use SSD storage** for better I/O performance
4. **Close unnecessary applications** during full scans
5. **Schedule scans** during low-usage periods

## 🆘 Support

### Getting Help
1. Check this documentation first
2. Review application logs for error details
3. Run with debug logging enabled
4. Check system requirements and dependencies
5. Verify administrator privileges

### Reporting Issues
Include the following information:
- Python version (`python --version`)
- Operating system details
- Error messages from logs
- Steps to reproduce the issue
- System resource usage during issue

---

**🛡️ Stay Protected!** The Python version provides excellent user-mode protection with immediate deployment capabilities. For maximum security, consider the C++ kernel version.
