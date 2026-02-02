# Windows Installer Guide

## Overview

The Anti-Ransomware Protection Platform now includes a complete Windows installer built with NSIS (Nullsoft Scriptable Install System).

## Prerequisites

### For Building the Installer

1. **NSIS 3.08 or later**
   - Download: https://nsis.sourceforge.io/Download
   - Install to default location: `C:\Program Files (x86)\NSIS\`

2. **NSIS Plugins** (install via NSIS package manager):
   - **NSISunzU** - For ZIP extraction
   - **Inetc** - For downloading Python runtime

3. **Required project files**:
   - All Python source files
   - `requirements.txt`
   - `README.md`
   - Compiled kernel driver (optional): `build_production\AntiRansomwareDriver.sys`

### For Using the Installer

- Windows 10/11 64-bit
- Administrator privileges
- Internet connection (for Python dependencies download)
- TPM 2.0 chip (recommended)

## Building the Installer

### Method 1: PowerShell Script (Recommended)

```powershell
# Simple build
.\build_installer.ps1

# Test mode (includes validation)
.\build_installer.ps1 -TestMode
```

### Method 2: Manual NSIS Compilation

```powershell
& "C:\Program Files (x86)\NSIS\makensis.exe" installer.nsi
```

## Installer Features

### What Gets Installed

1. **Core Application**
   - All Python source files
   - Configuration files
   - Database schema
   - ML models (if available)

2. **Python Runtime**
   - Embedded Python 3.11 (downloaded during installation)
   - All required packages via pip
   - Virtual environment setup

3. **Kernel Driver** (optional)
   - AntiRansomwareDriver.sys
   - Driver service registration
   - Test-signing mode enablement (if needed)

4. **Windows Service**
   - Background protection service
   - Auto-start configuration
   - Event log integration

5. **Desktop Integration**
   - Start Menu shortcuts
   - Desktop shortcut
   - Startup entry (auto-launch)

6. **Registry Keys**
   - Installation path
   - Configuration settings
   - Uninstall information

7. **Firewall Rules**
   - Automatic firewall exception

### Installation Directories

```
C:\Program Files\AntiRansomware\
├── python\                      # Embedded Python runtime
├── driver\                      # Kernel driver files
├── models\                      # ML models
├── policies\                    # Protection policies
├── keys\                        # Cryptographic keys
├── certs\                       # Certificates
├── .audit_logs\                 # Security audit logs
├── logs\                        # Application logs
├── quarantine\                  # Quarantined files
├── protected\                   # Protected file metadata
├── *.py                         # Application files
├── config.json                  # Configuration
├── protection_db.sqlite         # Protection database
└── uninst.exe                   # Uninstaller
```

## Using the Installer

### Installation Steps

1. **Download** the installer: `AntiRansomware-Setup-1.0.0.exe`

2. **Verify checksum** (optional but recommended):
   ```powershell
   Get-FileHash -Path "AntiRansomware-Setup-1.0.0.exe" -Algorithm SHA256
   ```
   Compare with value in `.checksums.txt` file

3. **Run as Administrator**:
   - Right-click the installer
   - Select "Run as administrator"

4. **Follow the wizard**:
   - Accept license agreement
   - Select components to install
   - Choose installation directory
   - Wait for installation to complete

5. **Reboot if prompted** (required if test-signing was enabled for kernel driver)

6. **Launch the application**:
   - From Start Menu: Anti-Ransomware Protection
   - Or from Desktop shortcut

### Silent Installation

For enterprise deployment:

```powershell
# Silent install all components
.\AntiRansomware-Setup-1.0.0.exe /S

# Silent install without kernel driver
.\AntiRansomware-Setup-1.0.0.exe /S /D=C:\CustomPath
```

### Component Selection

During installation, you can choose:

- ✓ **Core Files** (Required) - Cannot be deselected
- ✓ **Python Runtime** (Required) - Cannot be deselected
- ☐ **Kernel Driver** - Optional, requires test-signing
- ☐ **Windows Service** - Recommended for automatic protection
- ☐ **Desktop Integration** - Shortcuts and startup
- ☐ **Registry Integration** - System integration

## Uninstallation

### Method 1: Control Panel

1. Open **Settings** → **Apps** → **Installed apps**
2. Find "Anti-Ransomware Protection"
3. Click **Uninstall**
4. Follow the wizard

### Method 2: Start Menu

1. Go to Start Menu → Anti-Ransomware Protection
2. Click **Uninstall**
3. Follow the wizard

### Method 3: Silent Uninstall

```powershell
& "C:\Program Files\AntiRansomware\uninst.exe" /S
```

### What Gets Removed

The uninstaller will:
- Stop and remove the Windows service
- Stop and remove the kernel driver
- Remove all application files
- Remove shortcuts
- Remove firewall rules
- Clean up registry entries

**User data preservation:**
- You'll be prompted whether to keep logs and protected file lists
- Answering "No" preserves: `.audit_logs`, `logs`, `quarantine`, `protected`, `keys`

## Post-Installation Configuration

### First Run

1. **Launch the GUI**:
   ```
   Start Menu → Anti-Ransomware Protection
   ```

2. **Configure protected folders**:
   - Click "Protected Paths" tab
   - Add folders you want to protect
   - Enable monitoring

3. **Create USB token**:
   - Click "USB Token" tab
   - Insert USB drive
   - Click "Create New USB Token"
   - Follow prompts

4. **Start protection**:
   - Click "Start Protection" button
   - System is now actively protecting

### Service Management

**Start service:**
```powershell
Start-Service AntiRansomwareProtection
```

**Stop service:**
```powershell
Stop-Service AntiRansomwareProtection
```

**Check service status:**
```powershell
Get-Service AntiRansomwareProtection
```

**Service logs:**
```
Event Viewer → Windows Logs → Application
Filter by source: "AntiRansomwareProtection"
```

### Driver Management

**Check if driver is loaded:**
```powershell
sc query AntiRansomwareDriver
```

**Start driver:**
```powershell
sc start AntiRansomwareDriver
```

**Stop driver:**
```powershell
sc stop AntiRansomwareDriver
```

## Troubleshooting

### Installation Issues

**Problem:** "Administrator rights required"
- **Solution**: Right-click installer, select "Run as administrator"

**Problem:** "This software requires 64-bit Windows 10 or later"
- **Solution**: Upgrade to Windows 10/11 64-bit

**Problem:** "Failed to download Python runtime"
- **Solution**: 
  1. Check internet connection
  2. Install Python 3.11 manually from python.org
  3. Run installer again

**Problem:** "Test-signing mode is not enabled"
- **Solution**: 
  1. Click "Yes" to enable test-signing
  2. Reboot computer
  3. Run installer again

### Runtime Issues

**Problem:** Service won't start
- **Solution**:
  ```powershell
  # Check event logs
  Get-EventLog -LogName Application -Source "AntiRansomwareProtection" -Newest 10
  
  # Check service configuration
  sc qc AntiRansomwareProtection
  
  # Try manual start
  & "C:\Program Files\AntiRansomware\python\python.exe" "C:\Program Files\AntiRansomware\desktop_app.py"
  ```

**Problem:** Driver won't load
- **Solution**:
  ```powershell
  # Check test-signing
  bcdedit /enum {current} | findstr testsigning
  
  # Enable if needed
  bcdedit /set testsigning on
  # Then reboot
  
  # Check driver status
  sc query AntiRansomwareDriver
  ```

**Problem:** "Access Denied" errors
- **Solution**: Ensure you're running as administrator

## Advanced Configuration

### Custom Installation Path

```powershell
.\AntiRansomware-Setup-1.0.0.exe /D=D:\Security\AntiRansomware
```

### Modify Installation

To add/remove components after installation:
1. Run the installer again
2. Select "Modify" when prompted
3. Check/uncheck components
4. Click "Install"

### Configuration Files

**Main config:**
```
C:\Program Files\AntiRansomware\config.json
```

**Enterprise config:**
```
C:\Program Files\AntiRansomware\enterprise_config.json
```

**Protection database:**
```
C:\Program Files\AntiRansomware\protection_db.sqlite
```

## Code Signing (Optional)

For production deployment, sign the installer:

### Using SignTool

```powershell
# Sign with certificate
signtool sign /f MyCert.pfx /p MyPassword /t http://timestamp.digicert.com /v AntiRansomware-Setup-1.0.0.exe

# Verify signature
signtool verify /pa /v AntiRansomware-Setup-1.0.0.exe
```

### Using osslsigncode (Cross-platform)

```bash
osslsigncode sign -certs cert.pem -key key.pem -t http://timestamp.digicert.com -in AntiRansomware-Setup-1.0.0.exe -out AntiRansomware-Setup-1.0.0-signed.exe
```

## Distribution

### Checksums

Always distribute the `.checksums.txt` file alongside the installer so users can verify integrity.

### Recommended Distribution Channels

1. **Official website** with HTTPS
2. **GitHub Releases** with checksum verification
3. **Enterprise software repositories**
4. **USB drives** for air-gapped environments

### Update Mechanism

For future updates:
1. Users download new installer
2. Run installer (detects existing installation)
3. Choose "Upgrade" option
4. Preserves configuration and data

## Support

For installation issues:
1. Check logs: `C:\Program Files\AntiRansomware\logs\`
2. Review documentation: `C:\Program Files\AntiRansomware\README.md`
3. GitHub issues: https://github.com/Johnsonajibi/Ransomeware_protection/issues

## Security Notes

- The installer requires administrator privileges (UAC prompt)
- Kernel driver installation requires test-signing mode or valid signature
- All network downloads use HTTPS
- Installation paths cannot be changed after installation
- Firewall rules are automatically configured
- Service runs with SYSTEM privileges (required for kernel driver)

## License

The installer and all components are distributed under the MIT License. See LICENSE.txt for details.
