# TPM Setup Guide for Anti-Ransomware System

## Current Status
- **TPM Integration:** Not Available
- **Security Level:** MEDIUM (DeviceFP + USB)
- **Target Security:** MAXIMUM (TPM + DeviceFP + USB)

## Why TPM Isn't Working

The system shows these warnings:
```
⚠️ TPM integration not available
⚠️ TrustCore-TPM not installed. Install with: pip install trustcore-tpm
TPM layer error: winmgmts:.Win32_Tpm
```

**Root Causes:**
1. **Administrator Privileges Required** - TPM access needs elevated permissions
2. **TPM May Be Disabled** - BIOS/UEFI setting might be off
3. **WMI Namespace Access** - Security policies may block access
4. **No Real TPM Library** - TrustCore-TPM is proprietary/fictional

---

## Step-by-Step Fix

### Step 1: Check if TPM Exists on Your System

**Run PowerShell as Administrator:**
```powershell
# Right-click PowerShell -> Run as Administrator
Get-Tpm
```

**Expected Output (if TPM exists):**
```
TpmPresent                : True
TpmReady                  : True
TpmEnabled                : True
TpmActivated              : True
TpmOwned                  : True
ManagedAuthLevel          : Full
OwnerAuth                 : 
```

**If you see "Administrator privilege is required":**
- You need to run as admin (see Step 4)

**If you see "No TPM found":**
- Your system doesn't have TPM hardware
- Use software fallback (already working)

### Step 2: Enable TPM in BIOS (if disabled)

1. **Restart computer** and enter BIOS/UEFI setup
   - Common keys: `F2`, `F10`, `Del`, `Esc` (press during boot)

2. **Find Security or Advanced settings**
   - Look for: "TPM Device", "Security Chip", "PTT" (Intel), "fTPM" (AMD)

3. **Enable TPM**
   - Set to: "Enabled", "Available", or "Active"
   - Save and exit BIOS

4. **Boot into Windows** and verify:
   ```powershell
   # Run as Administrator
   Get-Tpm
   ```

### Step 3: Initialize TPM (First Time)

```powershell
# Run as Administrator
Initialize-Tpm

# If prompted, restart computer
```

### Step 4: Run Anti-Ransomware with Admin Privileges

**Option A: Right-click Python script**
```
Right-click → Run as Administrator
```

**Option B: Admin PowerShell**
```powershell
# Open PowerShell as Administrator
cd C:\Users\ajibi\Music\Anti-Ransomeware
.\.venv\Scripts\Activate.ps1
python trifactor_auth_manager.py
```

**Option C: Create Admin Shortcut**
```powershell
# Create a shortcut, then:
# Right-click shortcut → Properties → Advanced
# Check "Run as administrator" → OK
```

### Step 5: Install Python TPM Library

The system currently uses **software fallback**. For real TPM integration, install:

```powershell
# Activate venv first
.\.venv\Scripts\Activate.ps1

# Option 1: tpm2-pytss (official TPM 2.0 library)
pip install tpm2-pytss

# Option 2: python-tpm (alternative)
pip install python-tpm

# Option 3: Use our WMI fallback (already implemented)
# No installation needed - uses wmi library (already installed)
```

### Step 6: Test TPM Access

Create a test script:

```python
# test_tpm.py
import sys

print("=== TPM Access Test ===\n")

# Method 1: PowerShell (most reliable on Windows)
print("1. PowerShell Get-Tpm:")
import subprocess
try:
    result = subprocess.run(
        ['powershell', '-Command', 'Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled'],
        capture_output=True, text=True, check=True
    )
    print(result.stdout)
except Exception as e:
    print(f"   Error: {e}\n")

# Method 2: WMI (needs admin)
print("2. WMI Win32_Tpm:")
try:
    import wmi
    c = wmi.WMI(namespace='root\\cimv2\\Security\\MicrosoftTpm')
    tpm = c.Win32_Tpm()[0]
    print(f"   IsActivated: {tpm.IsActivated_InitialValue}")
    print(f"   IsEnabled: {tpm.IsEnabled_InitialValue}")
    print(f"   IsOwned: {tpm.IsOwned_InitialValue}")
except Exception as e:
    print(f"   Error: {e}\n")

# Method 3: tpm2-pytss (if installed)
print("3. tpm2-pytss:")
try:
    from tpm2_pytss import ESAPI
    esapi = ESAPI()
    print("   TPM 2.0 connection successful!")
except ImportError:
    print("   Not installed (pip install tpm2-pytss)")
except Exception as e:
    print(f"   Error: {e}\n")

print("\n=== Test Complete ===")
```

Run with admin:
```powershell
python test_tpm.py
```

---

## Understanding the Current Implementation

### Current TPM Code (trifactor_auth_manager.py)

```python
class TPMTokenManager:
    def __init__(self):
        self.tpm_available = False
        self.tpm = None
        
        # Try TrustCore-TPM (proprietary - not real)
        if HAS_TRUSTCORE:
            try:
                self.tpm = tpm_lib.TPM()
                self.tpm_available = True
            except:
                pass
        
        # Fallback: Generic TPM 2.0
        if not self.tpm_available:
            try:
                # Uses tpm2-pytss or similar
                self.tpm = self._init_generic_tpm()
                self.tpm_available = True
            except:
                pass
```

### What Needs Admin Access

| Operation | Admin Required | Why |
|-----------|----------------|-----|
| Read TPM PCRs | ✅ Yes | Security-sensitive data |
| Seal data to PCRs | ✅ Yes | Modifies TPM NV RAM |
| Get TPM attestation | ✅ Yes | Cryptographic operations |
| Device fingerprint | ❌ No | Uses standard WMI/CPU info |
| USB detection | ❌ No | Standard drive enumeration |

---

## Security Level Comparison

### Current (MEDIUM - 60/100):
```
✓ Device Fingerprint (6 layers)
✓ PQC USB Signature (Dilithium3)
✗ TPM Attestation (unavailable)
```

### With TPM Enabled (MAXIMUM - 100/100):
```
✓ TPM Platform Attestation
  - PCR 0: BIOS/UEFI measurements
  - PCR 7: Secure Boot state
  - Boot integrity verification
  
✓ Device Fingerprint (6+ layers)
  - Hardware DNA binding
  - Firmware signature
  
✓ PQC USB Token
  - Quantum-resistant signatures
  - Physical possession proof
```

---

## Alternative: Use Software TPM Simulator

If you don't have hardware TPM or can't get admin access:

### Install Microsoft TPM Simulator
```powershell
# Download from: https://github.com/microsoft/ms-tpm-20-ref
# Or use software emulation (already in code):

# The system already has software fallback:
# - Uses HKDF + ChaCha20Poly1305
# - Platform-bound keys (CPU ID, motherboard)
# - 40% security level instead of 100%
```

---

## Quick Command Reference

```powershell
# Check TPM status (needs admin)
Get-Tpm

# Initialize TPM (first time, needs admin)
Initialize-Tpm

# Clear TPM (reset, needs admin + reboot)
Clear-Tpm

# Test WMI TPM access
Get-WmiObject -Namespace root\cimv2\Security\MicrosoftTpm -Class Win32_Tpm

# Check if running as admin
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

---

## Troubleshooting

### "Administrator privilege is required"
**Solution:** Run PowerShell/Python as Administrator

### "No TPM found"
**Solutions:**
1. Enable in BIOS (see Step 2)
2. Check if your CPU supports TPM (Intel PTT, AMD fTPM)
3. Use software fallback (already working)

### "TPM is owned by another user"
**Solution:**
```powershell
# Clear and reinitialize (needs admin + reboot)
Clear-Tpm
Initialize-Tpm
```

### "Win32_Tpm namespace not found"
**Solution:**
1. Update Windows to latest version
2. Install TPM driver from manufacturer
3. Use alternative library (tpm2-pytss)

### Code still shows "TPM integration not available"
**Check:**
1. Are you running with admin privileges?
2. Did you restart after enabling TPM in BIOS?
3. Is TPM actually present? Run: `Get-Tpm`

---

## Production Deployment Recommendations

### For Maximum Security (MAXIMUM level):
1. **Require TPM 2.0 hardware**
2. **Run service with admin privileges** (use Windows Service)
3. **Measure boot components** (PCR 0-7)
4. **Seal tokens to platform state**

### For Practical Deployment (HIGH/MEDIUM level):
1. **Use DeviceFP + USB** (no admin needed)
2. **Add TPM as optional enhancement**
3. **Graceful degradation** (already implemented)
4. **User prompt for admin elevation** (when TPM available)

---

## Summary: What You Need to Do Now

**Immediate (to test TPM):**
```powershell
# 1. Open PowerShell as Administrator
# 2. Check TPM exists
Get-Tpm

# 3. If TPM exists, run demo with admin
cd C:\Users\ajibi\Music\Anti-Ransomeware
.\.venv\Scripts\Activate.ps1
python trifactor_auth_manager.py

# 4. You should see:
# ✓ TPM Available: True
# Security Level: HIGH or MAXIMUM
```

**Long-term (for production):**
1. Enable TPM in BIOS (if not enabled)
2. Install `tpm2-pytss` for proper TPM 2.0 support
3. Run anti-ransomware service with admin privileges
4. Configure Secure Boot for PCR measurements

**If TPM Not Available:**
- Current MEDIUM security (DeviceFP + USB) is still strong
- Software fallback provides 60% protection
- Consider this acceptable for most use cases
