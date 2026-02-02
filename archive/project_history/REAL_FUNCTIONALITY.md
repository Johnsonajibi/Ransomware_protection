# Anti-Ransomware System - Real Functionality

## What This System Actually Does

### Core Functions:
1. **File Protection**: Encrypts files in designated folders using AES encryption
2. **USB Token Authentication**: Requires USB drive presence for file access
3. **Process Monitoring**: Watches for suspicious process behavior
4. **File System Monitoring**: Monitors file operations for encryption patterns
5. **Database Storage**: SQLite database for protected files and settings

### Security Features:
- AES-256 encryption for protected files
- Hardware fingerprinting for token validation
- Basic behavioral analysis for threat detection
- File integrity checking with checksums
- Secure configuration storage

### Limitations:
- **User-mode only**: Can be bypassed by admin or kernel-level malware
- **Python-based**: Performance limitations, requires Python runtime
- **Subprocess calls**: Some command injection surface remains
- **Local protection**: No network-based threat intelligence
- **Basic detection**: Simple pattern matching, not ML-based

### Windows Integration:
- Can configure Windows Defender settings (with admin privileges)
- Uses Windows APIs where possible
- Integrates with Windows security features

### What It Is NOT:
- Not kernel-level protection
- Not enterprise-grade security
- Not immune to determined attackers
- Not a replacement for professional security solutions

## Usage

### Basic Protection:
```bash
python unified_antiransomware.py --gui
```

### Configure Windows Defender (requires admin):
```bash
python unified_antiransomware.py --configure-defender
```

### Command Line:
```bash
python unified_antiransomware.py --command protect --folder "C:\MyFolder"
```

## Architecture

### Database:
- SQLite database stores protected files list
- Token validation records
- Configuration settings

### Encryption:
- AES-256 encryption for file content
- Key derivation from hardware fingerprint + token
- Individual file encryption (not full disk)

### Monitoring:
- File system change detection
- Process creation monitoring
- USB device insertion detection

This is a basic anti-ransomware tool with user-mode protection capabilities.
It provides reasonable protection against common ransomware but has significant limitations against advanced threats.
