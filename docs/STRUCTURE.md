# Anti-Ransomware Protection Platform

## Project Structure (Industry Standard)

```
Ransomware_protection/
├── src/
│   └── antiransomware/
│       ├── __init__.py              # Package initialization
│       ├── core/                    # Core protection logic
│       │   ├── __init__.py
│       │   ├── protection.py        # Main protection engine
│       │   ├── token_manager.py     # Tri-factor authentication
│       │   ├── audit.py             # Audit logging
│       │   ├── policy.py            # Policy engine
│       │   ├── detection.py         # Threat detection
│       │   ├── four_layer.py        # 4-layer protection
│       │   ├── health.py            # Health monitoring
│       │   └── gated_access.py      # Token-gated file access
│       ├── api/                     # REST API & integrations
│       │   ├── __init__.py
│       │   ├── dashboard.py         # Web dashboard
│       │   ├── backup.py            # Backup integration
│       │   ├── siem.py              # SIEM integration
│       │   └── email.py             # Email alerting
│       ├── cli/                     # Command-line tools
│       │   ├── __init__.py
│       │   ├── protect_files.py     # File protection CLI
│       │   ├── check_events.py      # Event checking
│       │   ├── kill_switch.py       # Emergency shutdown
│       │   └── deploy_monitor.py    # Deployment monitoring
│       ├── drivers/                 # Kernel drivers
│       │   ├── __init__.py
│       │   ├── minifilter.c         # Windows minifilter
│       │   ├── kernel.c             # Kernel mode driver
│       │   ├── common.h             # Common headers
│       │   ├── windows.c            # Windows-specific
│       │   ├── linux.c              # Linux-specific
│       │   └── macos.swift          # macOS-specific
│       └── utils/                   # Utility functions
│           ├── __init__.py
│           ├── service.py           # Service management
│           ├── config.py            # Configuration
│           ├── fingerprint.py       # Device fingerprinting
│           ├── shadow_copy.py       # VSS protection
│           └── boot_protection.py   # Boot persistence
├── tests/
│   ├── unit/                        # Unit tests
│   │   ├── test_token_manager.py
│   │   ├── test_tpm.py
│   │   ├── test_device_fingerprint.py
│   │   └── test_*.py
│   └── integration/                 # Integration tests
│       ├── security_validation.py
│       └── test_trifactor_integration.py
├── scripts/                         # Build & deployment
│   ├── build_exe.py
│   ├── deploy.py
│   ├── cicd.py
│   ├── install.py
│   └── build_*.bat
├── config/                          # Configuration files
│   ├── config.json
│   ├── config.yaml
│   └── admin.json
├── examples/                        # Example usage
│   ├── demo.py
│   └── demo_advanced.py
├── docs/                            # Documentation
│   ├── index.md
│   ├── architecture.md
│   ├── security-model.md
│   └── guides/
├── Python-Version/                  # Legacy/alternative implementation
├── pyproject.toml                   # Python package configuration
├── MANIFEST.in                      # Package manifest
├── requirements.txt                 # Dependencies
├── LICENSE                          # License file
└── README.md                        # This file
```

## Installation

### From Source
```bash
git clone https://github.com/johnsonajibi/Ransomware_protection.git
cd Ransomware_protection
pip install -e .
```

### From PyPI (future)
```bash
pip install antiransomware
```

## Usage

### Command Line
```bash
# Protect files
ar-protect --path "C:\Important" --level high

# Check security events
ar-events --since "1 hour ago" --severity critical

# Start dashboard
ar-dashboard --port 8080

# Emergency kill switch
ar-kill --activate
```

### Python API
```python
from antiransomware.core import ProtectionEngine, TokenManager
from antiransomware.core import PolicyEngine

# Initialize protection
engine = ProtectionEngine()
token_mgr = TokenManager()

# Create tri-factor token
token = token_mgr.create_token(
    require_tpm=True,
    require_usb=True,
    require_fingerprint=True
)

# Protect path
engine.protect_path("C:\\Data", token=token)
```

## Development

### Setup Development Environment
```bash
pip install -e ".[dev]"
```

### Run Tests
```bash
pytest tests/
pytest tests/unit/ -v
pytest tests/integration/ --cov=antiransomware
```

### Code Quality
```bash
black src/
flake8 src/
mypy src/
```

## Architecture

- **4-Layer Defense**:
  1. Kernel driver (minifilter)
  2. Filesystem monitoring
  3. Cryptographic protection
  4. Behavioral analysis

- **Tri-Factor Authentication**:
  - TPM hardware attestation
  - Device fingerprinting
  - USB token (Dilithium3 PQC)

## Documentation

- [Architecture](docs/architecture.md)
- [Security Model](docs/security-model.md)
- [API Reference](docs/api-reference.md)
- [Quick Start](docs/guides/QUICK_START_GUIDE.md)
- [Deployment Guide](docs/guides/deployment.md)

## License

MIT License - see [LICENSE](LICENSE) for details.
