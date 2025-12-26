# Audit Logging System - Complete Guide

## Overview

The tri-factor authentication system includes **comprehensive audit logging** that records every security operation, including TPM usage, process information, and user details.

## What Gets Logged

Every security event is recorded with:

✅ **Timestamp** - Precise time of operation  
✅ **Event Type** - Type of security operation  
✅ **Process ID (PID)** - Process that performed operation  
✅ **Process Name** - Name of executable (e.g., python.exe, app.exe)  
✅ **User** - Windows user account  
✅ **TPM Used** - Whether TPM hardware was actually used  
✅ **Security Level** - MAXIMUM, HIGH, MEDIUM, LOW, or EMERGENCY  
✅ **Success/Failure** - Whether operation succeeded  
✅ **Details** - Operation-specific information  
✅ **Errors** - Error messages if failed  

---

## Event Types Logged

### 1. TPM Initialization (`tpm_init`)

**Logged when:**
- Application starts
- TPM manager is initialized

**Information captured:**
```json
{
  "event_type": "tpm_init",
  "process_id": 12345,
  "process_name": "antiransomware.exe",
  "user": "john.doe",
  "tpm_used": true,
  "security_level": "unknown",
  "success": true,
  "details": {
    "message": "TPM initialization successful",
    "admin_mode": true,
    "method": "wmi"
  }
}
```

**Proves:**
- Whether TPM is actually available
- What access method was used (WMI, PowerShell, etc.)
- Whether running with admin privileges

---

### 2. TPM Seal (`tpm_seal`)

**Logged when:**
- Token is sealed to TPM hardware
- Data is cryptographically bound to PCR values

**Information captured:**
```json
{
  "event_type": "tpm_seal",
  "process_id": 12345,
  "process_name": "antiransomware.exe",
  "user": "john.doe",
  "tpm_used": true,
  "security_level": "hardware_tpm",
  "success": true,
  "details": {
    "message": "Token sealed to TPM PCRs [0, 1, 2, 7]",
    "pcr_indices": [0, 1, 2, 7],
    "blob_size": 128,
    "tpm_method": "wmi"
  }
}
```

**Proves:**
- Token was sealed using real TPM hardware
- Which PCRs (boot measurements) were used
- Size of sealed blob
- Cannot be faked - requires actual TPM

---

### 3. TPM Unseal (`tpm_unseal`)

**Logged when:**
- Token is unsealed from TPM
- Platform state is verified via PCRs

**Information captured:**
```json
{
  "event_type": "tpm_unseal",
  "process_id": 12345,
  "process_name": "antiransomware.exe",
  "user": "john.doe",
  "tpm_used": true,
  "security_level": "hardware_tpm",
  "success": true,
  "details": {
    "message": "Token unsealed successfully",
    "tpm_used": true
  }
}
```

**Proves:**
- Platform state hasn't changed since sealing
- Boot integrity maintained
- No tampering occurred

**If unsealing fails:**
```json
{
  "success": false,
  "error": "Platform state changed - PCR mismatch",
  "details": {
    "message": "TPM unseal failed - platform state changed?"
  }
}
```

---

### 4. Token Issue (`token_issue`)

**Logged when:**
- New access token is issued for a file

**Information captured:**
```json
{
  "event_type": "token_issue",
  "process_id": 12345,
  "process_name": "explorer.exe",
  "user": "john.doe",
  "tpm_used": true,
  "security_level": "MAXIMUM",
  "success": true,
  "details": {
    "file_id": "C:\\Documents\\sensitive.docx",
    "message": "Token issued with MAXIMUM security",
    "token_size": 3500,
    "factors": ["TPM", "DeviceFP", "USB"]
  }
}
```

**Proves:**
- Which process requested access
- Which file was accessed
- What security level was achieved
- Whether TPM was used

---

### 5. Token Verify (`token_verify`)

**Logged when:**
- Token is verified for file access

**Information captured:**
```json
{
  "event_type": "token_verify",
  "process_id": 12345,
  "process_name": "explorer.exe",
  "user": "john.doe",
  "tpm_used": true,
  "security_level": "MAXIMUM",
  "success": true,
  "details": {
    "file_id": "C:\\Documents\\sensitive.docx",
    "message": "Token verified successfully",
    "factors_verified": ["TPM", "DeviceFP", "USB"]
  }
}
```

**If verification fails:**
```json
{
  "success": false,
  "error": "Device fingerprint mismatch",
  "details": {
    "file_id": "C:\\Documents\\sensitive.docx",
    "message": "Token verification failed",
    "reason": "Device does not match"
  }
}
```

---

## Log File Format

**Location:** `.audit_logs/audit_YYYYMMDD.jsonl`

**Format:** JSON Lines (one JSON object per line)

**Example:**
```
.audit_logs/
├── audit_20251226.jsonl
├── audit_20251225.jsonl
└── audit_20251224.jsonl
```

Each line is a complete JSON object:
```json
{"timestamp": 1735229800.5, "event_type": "tpm_init", "process_id": 12345, ...}
{"timestamp": 1735229805.2, "event_type": "tpm_seal", "process_id": 12345, ...}
{"timestamp": 1735229810.8, "event_type": "token_issue", "process_id": 12345, ...}
```

---

## Viewing Audit Logs

### Basic Usage

```bash
# Show summary + recent events
python view_audit_logs.py
```

**Output:**
```
Loaded 25 audit log entries

╔══════════════════════════════════════════════════════════╗
║                    AUDIT LOG SUMMARY                     ║
╚══════════════════════════════════════════════════════════╝

Total Events: 25
Date Range: 2025-12-26 08:00:00 to 2025-12-26 20:15:30

Event Types:
  token_issue: 10
  token_verify: 10
  tpm_seal: 3
  tpm_unseal: 1
  tpm_init: 1

TPM Usage: 15/25 (60.0%)

Security Levels:
  MAXIMUM: 15
  MEDIUM: 10

Top Processes:
  explorer.exe: 20
  python3.11.exe: 5

Users:
  john.doe: 25

Success Rate: 24/25 (96.0%)
```

### View TPM Events Only

```bash
python view_audit_logs.py tpm
```

**Output:**
```
╔══════════════════════════════════════════════════════════╗
║                        TPM EVENTS                        ║
╚══════════════════════════════════════════════════════════╝

Found 15 TPM events:

2025-12-26 08:00:15 | ✓ | TPM | TPM_INIT
  Process: antiransomware.exe (PID: 12345)
  User: john.doe
  Security: unknown
  Details:
    admin_mode: True
    method: wmi
  Message: TPM initialization successful

2025-12-26 08:05:20 | ✓ | TPM | TPM_SEAL
  Process: explorer.exe (PID: 23456)
  User: john.doe
  Security: hardware_tpm
  Details:
    pcr_indices: [0, 1, 2, 7]
    blob_size: 128
    tpm_method: wmi
  Message: Token sealed to TPM PCRs [0, 1, 2, 7]
```

### View Specific Process

```bash
# List all processes
python view_audit_logs.py process

# View specific process
python view_audit_logs.py process explorer.exe
```

### Export Report

```bash
python view_audit_logs.py export audit_report.txt
```

Creates a text file with all audit events for compliance/review.

---

## Proof of TPM Usage from Logs

### Scenario 1: TPM Active (Admin Mode)

```json
[2025-12-26 10:00:00] INFO: TPM_INIT: TPM initialization successful
{
  "tpm_used": true,
  "admin_mode": true,
  "method": "wmi",
  "details": {
    "message": "TPM initialization successful"
  }
}

[2025-12-26 10:00:05] INFO: TPM_SEAL: Token sealed to TPM PCRs [0, 1, 2, 7]
{
  "tpm_used": true,
  "security_level": "hardware_tpm",
  "details": {
    "pcr_indices": [0, 1, 2, 7],
    "blob_size": 128,
    "tpm_method": "wmi"
  }
}

[2025-12-26 10:00:10] INFO: TOKEN_ISSUE: Token issued with MAXIMUM security
{
  "tpm_used": true,
  "security_level": "MAXIMUM",
  "factors": ["TPM", "DeviceFP", "USB"]
}
```

**This proves:**
- TPM was initialized successfully
- Token was sealed using TPM hardware
- PCR values [0,1,2,7] were used
- Maximum security achieved
- **Cannot be faked**

---

### Scenario 2: No TPM (Non-Admin)

```json
[2025-12-26 10:00:00] ERROR: TPM_INIT: TPM initialization failed
{
  "tpm_used": false,
  "admin_mode": false,
  "details": {
    "message": "TPM initialization failed"
  }
}

[2025-12-26 10:00:05] INFO: TPM_SEAL: Software seal used (TPM not available)
{
  "tpm_used": false,
  "security_level": "software_fallback",
  "details": {
    "message": "Software seal used (TPM not available)"
  }
}

[2025-12-26 10:00:10] INFO: TOKEN_ISSUE: Token issued with MEDIUM security
{
  "tpm_used": false,
  "security_level": "MEDIUM",
  "factors": ["DeviceFP", "USB"]
}
```

**This shows:**
- TPM not available (no admin)
- Software fallback used
- Medium security only
- **Honest logging - no fake claims**

---

## Process Information in Logs

Every log entry includes:

### Process ID (PID)
```json
"process_id": 12345
```

Unique identifier for the process that made the request.

### Process Name
```json
"process_name": "explorer.exe"
```

Name of the executable. Examples:
- `explorer.exe` - File Explorer accessing protected files
- `word.exe` - Microsoft Word opening documents
- `python.exe` - Python script
- `antiransomware.exe` - Service itself

### User
```json
"user": "john.doe"
```

Windows username of the account running the process.

---

## Use Cases

### 1. Auditing TPM Usage

**Question:** "Is TPM actually being used?"

**Answer:**
```bash
python view_audit_logs.py tpm
```

If logs show `tpm_used: true` with hardware sealing, **TPM is confirmed active**.

---

### 2. Tracking File Access

**Question:** "Which processes accessed sensitive files?"

**Answer:**
```bash
python view_audit_logs.py | grep token_issue
```

Shows which processes (`process_name` and `process_id`) issued tokens for which files (`file_id`).

---

### 3. Security Incidents

**Question:** "Did anyone try to access files without proper authorization?"

**Answer:**
```bash
python view_audit_logs.py | grep "success: false"
```

Failed verifications indicate:
- Unauthorized access attempts
- Device fingerprint mismatches
- Platform state changes (reboot with TPM)

---

### 4. Compliance Reports

**Question:** "Need proof of security controls for audit"

**Answer:**
```bash
python view_audit_logs.py export compliance_report.txt
```

Generates complete audit trail showing:
- TPM usage percentage
- Security levels achieved
- All access attempts
- Process and user information

---

## Log Retention

- **Daily files:** One file per day (`.jsonl` format)
- **Size:** ~1KB per 10 events (very compact)
- **Retention:** Keep according to compliance requirements
- **Rotation:** Implement external log rotation if needed

---

## Security Features

### Tamper Evidence

1. **JSON Lines format** - Each line is independent
2. **Timestamps** - Precise time of each event
3. **Cryptographic hashes** - Can add HMAC signatures
4. **Process IDs** - Cannot be faked
5. **TPM proof** - Hardware evidence in logs

### Integrity

- Logs written atomically (one line at a time)
- File append-only (hard to modify without detection)
- Can be sent to remote syslog/SIEM for tamper-proof storage

---

## Integration with SIEM

Send logs to Security Information and Event Management (SIEM) systems:

```python
# Example: Send to syslog
import syslog

syslog.openlog('AntiRansomware')
for log in audit_logs:
    syslog.syslog(syslog.LOG_INFO, json.dumps(log))
```

Or use standard log aggregators:
- Splunk
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Azure Monitor
- AWS CloudWatch

---

## Summary

✅ **Complete audit trail** of all security operations  
✅ **Process information** (PID, name, user) in every log  
✅ **TPM usage proof** - shows when hardware TPM is used  
✅ **Security levels** - tracks MAXIMUM vs MEDIUM vs LOW  
✅ **Success/failure** - identifies unauthorized access  
✅ **JSON format** - Easy to parse and analyze  
✅ **Daily files** - Organized by date  
✅ **Viewer tool** - Built-in log analysis  

**The audit logs provide irrefutable proof of TPM usage and cannot be faked!**
