# Real Anti-Ransomware - Python Implementation

Complete Python-based ransomware protection suite with real-time monitoring, behavioral analysis, and forensic capabilities.

## Features Implemented

### Core Detection
- ✅ **Behavioral Analysis Engine** (`detection_engine.py`)
  - Multi-layer threat detection (signatures, behavioral, heuristics)
  - Entropy-based encryption detection
  - Risk scoring system (LOW/MEDIUM/HIGH/CRITICAL)
  - Event tracking with time-window analysis

- ✅ **File Monitoring** (`file_monitor.py`)
  - Real-time file system monitoring via watchdog
  - Polling fallback for compatibility
  - Configurable watch/exclude paths
  - DELETE_ON_CLOSE pattern detection

- ✅ **Process Monitoring** (`process_monitor.py`)
  - Suspicious process detection
  - Process tree tracking
  - Command-line analysis
  - Process termination capabilities

### Protection & Response
- ✅ **Quarantine Manager** (`quarantine_manager.py`)
  - SQLite-based quarantine database
  - File hash verification (SHA256)
  - Automatic cleanup of old files
  - Restore/delete capabilities

- ✅ **Threat Intelligence** (`threat_intelligence.py`)
  - Signature database management
  - IOC (Indicators of Compromise) tracking
  - Remote signature updates
  - Pattern matching for known threats

### Recovery & Forensics
- ✅ **Recovery Manager** (`recovery.py`)
  - VSS (Volume Shadow Copy) snapshot integration
  - File backup/restore operations
  - Automated backup scheduling
  - Old backup cleanup

- ✅ **Forensics Manager** (`forensics.py`)
  - Incident timeline creation
  - Evidence collection (files, processes)
  - Forensic database with SQLite
  - Incident report generation
  - Memory dump placeholders

### Infrastructure
- ✅ **Windows Service** (`service_manager.py`)
  - Full Windows service implementation
  - Auto-start on boot
  - Service install/remove/control
  - Component orchestration

- ✅ **Web Dashboard** (`dashboard.py`)
  - Flask-based web interface
  - Real-time metrics via WebSocket
  - Threat visualization
  - Quarantine management
  - Configuration editor

- ✅ **Main Orchestrator** (`main.py`)
  - Unified component management
  - CLI and GUI modes
  - Signal handling
  - Statistics tracking

### Configuration
- ✅ **YAML Configuration** (`config.yaml`)
  - Detection thresholds
  - Monitoring paths
  - Alert settings (email, syslog, webhook)
  - Dashboard configuration
  - Performance tuning

- ✅ **Signature Files** (`signatures/`)
  - `ransomware_patterns.json` - Known ransomware indicators
  - `behavioral_rules.json` - Behavioral scoring rules

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run protection (console mode)
python main.py

# Run with dashboard
python main.py --dashboard

# Install as Windows service (admin required)
python service_manager.py install
net start RealAntiRansomware
```

Dashboard: http://127.0.0.1:8080 (admin/admin)

## Architecture Overview

```
Python-Version/
├── main.py                    # Main orchestrator
├── detection_engine.py        # Behavioral analysis
├── file_monitor.py            # File system monitoring
├── process_monitor.py         # Process tracking
├── quarantine_manager.py      # File quarantine
├── threat_intelligence.py     # Signature management
├── recovery.py                # Backup/restore
├── forensics.py               # Incident analysis
├── service_manager.py         # Windows service
├── dashboard.py               # Web interface
├── config.yaml                # Configuration
├── requirements.txt           # Dependencies
├── signatures/
│   ├── ransomware_patterns.json
│   └── behavioral_rules.json
└── templates/
    └── dashboard.html
```

## Detection System

### Threat Scoring
- Rapid modification: +30
- Extension change: +40
- High entropy: +35
- DELETE_ON_CLOSE: +25
- Suspicious origin: +15
- Network activity: +20

### Risk Levels
- **LOW**: 0-30
- **MEDIUM**: 31-60
- **HIGH**: 61-90
- **CRITICAL**: 91+

Auto-quarantine triggers at score ≥ 80.

## Documentation

See full documentation in this README for:
- Installation & Setup
- Configuration Reference
- API Documentation
- Database Schema
- Performance Tuning
- Troubleshooting

## System Requirements

- Windows 10/11 or Server 2016+
- Python 3.8+
- Administrator privileges
- 200 MB RAM minimum
- 1 GB disk space

## License

Enterprise license - All rights reserved.
