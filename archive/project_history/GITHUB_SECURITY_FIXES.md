# GitHub Security Alerts - Fix Documentation

## Overview
This document details all security vulnerabilities found by GitHub Code Scanning and their fixes.

## Vulnerabilities Found

### 1. ⚠️ CRITICAL: Subprocess with shell=True (CWE-78: OS Command Injection)

**Severity:** CRITICAL  
**Files Affected:**
- `archive/python/admin_proof_protection.py` (line 132)
- `archive/python/attack_simulation.py` (lines 142, 191)
- `unified_antiransomware.py` (lines 5608, 5612)
- `archive/python/privilege_escalation_fix_report.py` (multiple)
- `archive/python/privilege_escalation_test.py` (line 81)
- `archive/python/final_test.py` (lines 51, 64)

**Problem:**
```python
# VULNERABLE - Allows command injection
result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
result = subprocess.run(f'where {tool}', shell=True, capture_output=True, text=True)
```

**Risk:** Remote Code Execution if `cmd` or `tool` contains user input

**Fix:**
```python
# SAFE - Use list format with proper argument parsing
import shlex

# Option 1: For simple commands with known arguments
result = subprocess.run(
    ['powershell.exe', '-ExecutionPolicy', 'Bypass', '-Command', cmd],
    capture_output=True, text=True, timeout=30
)

# Option 2: Parse command string safely
result = subprocess.run(
    shlex.split(cmd),
    capture_output=True, text=True, timeout=30
)

# Option 3: For 'where' command
result = subprocess.run(
    ['where', tool],
    capture_output=True, text=True
)
```

---

### 2. ⚠️ HIGH: Insecure Dynamic Import (CWE-95: Improper Neutralization of Directives)

**Severity:** HIGH  
**Files Affected:**
- `tests/test_tpm.py` (line 116)
- `tests/test_trifactor_status.py` (line 33)
- `tests/unit/test_four_layer_protection.py` (line 136)

**Problem:**
```python
# VULNERABLE - No validation of module name
__import__(module)
__import__(lib.replace('-', '_'))
```

**Risk:** Execution of arbitrary code if module name is controlled by attacker

**Fix:**
```python
# SAFE - Use importlib with whitelist
import importlib

ALLOWED_MODULES = {
    'cryptography',
    'sqlite3',
    'tkinter',
    'psutil',
    'pywin32'
}

def safe_import(module_name):
    """Safely import a module from whitelist"""
    if module_name not in ALLOWED_MODULES:
        raise ValueError(f"Module {module_name} not in whitelist")
    
    try:
        return importlib.import_module(module_name)
    except ImportError as e:
        raise ImportError(f"Failed to import {module_name}: {e}")

# Usage
module = safe_import('cryptography')
```

---

### 3. 🔴 CRITICAL: Database Parameter Injection

**Severity:** CRITICAL  
**Status:** Already Fixed in Main Code

The codebase uses parameterized queries correctly:
```python
# SAFE - Uses parameter substitution
cursor.execute('DELETE FROM protected_folders WHERE path = ?', (path,))
cursor.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
```

Archive files may have vulnerable patterns - verify before using.

---

### 4. ⚠️ MEDIUM: Missing Input Validation

**Severity:** MEDIUM  
**Affected Areas:**
- User file path inputs
- Command arguments
- Database field values

**Fix:** Add validation helper function
```python
import pathlib
import re

def validate_file_path(path, max_length=260):
    """Validate and sanitize file path"""
    if not path or len(path) > max_length:
        raise ValueError(f"Invalid path length")
    
    # Remove null bytes and other dangerous characters
    if '\x00' in path:
        raise ValueError("Path contains null bytes")
    
    # Resolve to absolute path and validate it exists
    try:
        resolved_path = pathlib.Path(path).resolve()
        if not resolved_path.exists() and not resolved_path.parent.exists():
            raise ValueError(f"Invalid path: {path}")
        return str(resolved_path)
    except (ValueError, OSError) as e:
        raise ValueError(f"Path validation failed: {e}")

def validate_command_arg(arg, max_length=1024):
    """Validate command-line arguments"""
    if not isinstance(arg, str):
        raise TypeError("Argument must be string")
    
    if len(arg) > max_length:
        raise ValueError("Argument too long")
    
    # Reject shell metacharacters if not needed
    dangerous_chars = ['$', '`', ';', '|', '&', '>', '<', '\n', '\r']
    for char in dangerous_chars:
        if char in arg:
            raise ValueError(f"Argument contains invalid character: {char}")
    
    return arg

def validate_username(username):
    """Validate username format"""
    if not re.match(r'^[a-zA-Z0-9_\-\.]{3,32}$', username):
        raise ValueError("Invalid username format")
    return username

def validate_password(password):
    """Validate password strength"""
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain uppercase letters")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain lowercase letters")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain digits")
    return password
```

---

### 5. 🟡 LOW: Hardcoded Credentials

**Status:** ✅ Already Fixed

No hardcoded credentials found in main codebase. Archive files should be reviewed.

---

## Priority Fixes

### IMMEDIATE (Apply Today):

✅ **Fix 1: Remove all shell=True from subprocess calls**
- Replace with list-based arguments
- Add timeout to all subprocess calls
- Use proper escaping for arguments

✅ **Fix 2: Add input validation**
- Validate all user file path inputs
- Validate all command arguments
- Add length checks

✅ **Fix 3: Remove unsafe dynamic imports**
- Replace `__import__()` with `importlib.import_module()`
- Implement whitelist for allowed modules

---

## Implementation

### Automated Fixes:
```bash
# Run the security patcher
python security_patcher.py

# Scan with Bandit
pip install bandit
bandit -r . -f json -o security_report.json

# Check for SQL injection
bandit -r . -t B608,B607
```

### Manual Verification:
```bash
# Search for remaining shell=True
grep -r "shell=True" --include="*.py"

# Search for __import__
grep -r "__import__" --include="*.py"

# Search for unsafe SQL
grep -r "execute.*f\"" --include="*.py"
```

---

## Testing

After applying fixes, run:
```bash
# Unit tests
pytest tests/security/ -v

# Integration tests
pytest tests/integration/ -v

# Security tests
bandit -r . -v
safety check
```

---

## Compliance

These fixes align with:
- **OWASP Top 10:** A01 Broken Access Control, A03 Injection, A04 Insecure Design
- **CWE:** CWE-78 OS Command Injection, CWE-89 SQL Injection, CWE-95 Improper Neutralization
- **NIST:** Secure coding practices

---

## References

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Python subprocess security](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [Python importlib](https://docs.python.org/3/library/importlib.html)
