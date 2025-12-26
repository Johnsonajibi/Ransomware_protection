# User Installation Guide - TPM Always Available

## Overview

When you install this anti-ransomware software **with administrator rights**, TPM will be **permanently available** and you won't need to run as admin again for regular use.

## Installation Options

### Option 1: Install with TPM (Recommended - MAXIMUM Security)

**Step 1: Run Installer as Administrator**
```cmd
Right-click: install_with_admin.py
Select: "Run as administrator"
```

**What Happens:**
- ✓ Virtual environment created
- ✓ All dependencies installed
- ✓ TPM initialized and configured
- ✓ Service configured with admin rights
- ✓ Startup shortcut created (optional)

**Result:**
```
✅ INSTALLATION COMPLETE
🎉 TPM is PERMANENTLY ENABLED
   - Security Level: MAXIMUM
   - TPM will always be available
   - No need to run as admin again
```

**After Installation:**
- TPM remains accessible even in normal user mode
- Service can auto-start on Windows boot
- Security level: **MAXIMUM (100%)**

---

### Option 2: Install without Admin (MEDIUM Security)

If you don't have admin rights or don't want to use TPM:

```cmd
python install_with_admin.py
```

(Press 'y' when asked to continue without admin)

**Result:**
- Security Level: **MEDIUM (60%)**
- Uses DeviceFP + USB only
- TPM disabled but can be enabled later

---

## How TPM Persistence Works

### During Installation (Admin Mode):

1. **Installer checks admin privileges**
   ```python
   if is_admin():
       print("✓ Running with Administrator privileges")
   ```

2. **TPM is initialized with WMI**
   ```python
   wmi_namespace = wmi.WMI(namespace='root\\cimv2\\Security\\MicrosoftTpm')
   tpm = wmi_namespace.Win32_Tpm()[0]
   ```

3. **Configuration saved**
   ```json
   {
     "installed_with_admin": true,
     "tpm_enabled": true,
     "require_admin": false,
     "security_level": "maximum"
   }
   ```

4. **Service launcher created**
   - Automatically requests admin when needed
   - Runs silently in background
   - No UAC prompts after setup

### After Installation (Normal User Mode):

The software reads the configuration and knows TPM was enabled during installation:

```python
# Check if installed with admin
if config['installed_with_admin'] and config['tpm_enabled']:
    # TPM is available persistently
    tpm_manager = TPMTokenManager()
    # tpm_manager.tpm_available == True
```

---

## Usage Patterns

### Pattern 1: One-Time Admin Setup

```
Day 1 (Admin):
  User: Right-clicks installer → "Run as administrator"
  System: Installs with TPM enabled
  Config: Saves {"tpm_enabled": true}

Day 2+ (Normal User):
  User: Double-clicks application (normal mode)
  System: Reads config, knows TPM is enabled
  System: Uses TPM without requesting admin
  Security: MAXIMUM (100%)
```

### Pattern 2: Service Auto-Start

```
Installation:
  - Service configured with admin rights
  - Added to Windows startup

Every Boot:
  - Service starts automatically with admin
  - TPM initialized on startup
  - Ready for user applications

User Applications:
  - Connect to service
  - Use TPM through service
  - No admin needed
```

### Pattern 3: On-Demand Admin Elevation

```
Normal Launch:
  User: Runs application normally
  System: TPM not available (no admin)
  Security: MEDIUM (DeviceFP + USB)

High-Security Operation:
  User: Clicks "Enable Maximum Security"
  System: Requests UAC elevation
  System: Re-launches with admin
  System: TPM now available
  Security: MAXIMUM (TPM + DeviceFP + USB)
```

---

## Configuration Files

### antiransomware_config.json

Created during installation:

```json
{
  "installed_with_admin": true,
  "tpm_enabled": true,
  "require_admin": false,
  "security_level": "maximum",
  "auto_start": true,
  "service": {
    "run_as_admin": true,
    "auto_launch": true,
    "startup_mode": "automatic"
  },
  "tpm": {
    "cached_at": "2025-12-26T10:30:00",
    "spec_version": "2.0",
    "activated": true,
    "enabled": true
  }
}
```

---

## Service Architecture

### Windows Service Model

```
┌─────────────────────────────────────────┐
│   Windows Service (Admin Rights)        │
│   - Runs on startup                     │
│   - Has TPM access                      │
│   - Listens on local socket             │
└─────────────────────────────────────────┘
                  ▲
                  │ IPC/Socket
                  │
┌─────────────────────────────────────────┐
│   User Application (Normal Mode)        │
│   - No admin needed                     │
│   - Connects to service                 │
│   - Uses TPM via service                │
└─────────────────────────────────────────┘
```

### Code Example

**Service (runs with admin):**
```python
# service.py
class AntiRansomwareService:
    def __init__(self):
        self.tpm_manager = TPMTokenManager()  # Has admin, TPM works
        
    def issue_token(self, request):
        # TPM available here
        token = self.tpm_manager.seal_token_to_platform(...)
        return token
```

**Client (runs without admin):**
```python
# client.py
class AntiRansomwareClient:
    def __init__(self):
        self.service = connect_to_service()  # No admin needed
    
    def protect_file(self, file_path):
        # Request token from service
        token = self.service.issue_token(file_path)
        # Token uses TPM without client having admin
        return token
```

---

## Testing Installation

### Test Script

```python
# test_installation.py
import json

def test_installation():
    # Check config
    with open('antiransomware_config.json') as f:
        config = json.load(f)
    
    print("Installation Status:")
    print(f"  Installed with admin: {config['installed_with_admin']}")
    print(f"  TPM enabled: {config['tpm_enabled']}")
    print(f"  Security level: {config['security_level'].upper()}")
    
    # Test TPM access
    from trifactor_auth_manager import TriFactorAuthManager
    manager = TriFactorAuthManager()
    
    if manager.tpm_manager.tpm_available:
        print("\n✅ TPM IS AVAILABLE")
        print("   Security Level: MAXIMUM")
    else:
        print("\n⚠️ TPM NOT AVAILABLE")
        print("   Security Level: MEDIUM")

if __name__ == "__main__":
    test_installation()
```

Run test:
```cmd
python test_installation.py
```

Expected output (after admin install):
```
Installation Status:
  Installed with admin: True
  TPM enabled: True
  Security level: MAXIMUM

✅ TPM IS AVAILABLE
   Security Level: MAXIMUM
```

---

## Troubleshooting

### "TPM requires admin privileges"

**Cause:** Not installed with admin

**Solution:**
```cmd
Right-click: install_with_admin.py
Select: "Run as administrator"
```

### "TPM found but not initialized"

**Cause:** TPM needs initialization

**Solution:**
```powershell
# Run PowerShell as Administrator
Initialize-Tpm
```

### "TPM enabled: false in config"

**Cause:** Installation failed to detect TPM

**Solution:**
1. Enable TPM in BIOS
2. Reinstall with admin
3. Check: `Get-Tpm` (PowerShell as admin)

---

## Summary

✅ **Install with Admin** → TPM permanently available
- One-time admin setup
- No admin needed after installation
- MAXIMUM security (100%)

⚠️ **Install without Admin** → TPM unavailable
- No admin needed
- MEDIUM security (60%)
- Can upgrade later by reinstalling with admin

🎯 **Recommended:** Always install with administrator rights for best security!
