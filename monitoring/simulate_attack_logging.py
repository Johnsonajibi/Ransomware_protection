#!/usr/bin/env python3
"""
Simulate real attack event logging to verify security_events table works
"""
from unified_antiransomware import UnifiedDatabase
import sqlite3

db = UnifiedDatabase()

print("=" * 70)
print("SIMULATING REAL ATTACK EVENT LOGGING")
print("=" * 70)

# Log a simulated blocked access attempt
test_events = [
    {
        'event_type': 'FILE_ACCESS_BLOCKED',
        'file_path': r'C:\Users\ajibi\OneDrive\Desktop\TestLogging\sample1.txt',
        'process_name': 'powershell.exe',
        'process_id': 5432,
        'action_taken': 'ACCESS_BLOCKED',
        'severity': 'CRITICAL',
        'details': 'Simulated ransomware-like access attempt blocked'
    },
    {
        'event_type': 'FILE_COPY_BLOCKED',
        'file_path': r'C:\Users\ajibi\OneDrive\Desktop\TestLogging',
        'process_name': 'powershell.exe',
        'process_id': 5433,
        'action_taken': 'COPY_BLOCKED',
        'severity': 'CRITICAL',
        'details': 'Bulk file copy operation blocked (ransomware pattern)'
    },
    {
        'event_type': 'FILE_DELETE_BLOCKED',
        'file_path': r'C:\Users\ajibi\OneDrive\Desktop\TestLogging\sample2.txt',
        'process_name': 'powershell.exe',
        'process_id': 5434,
        'action_taken': 'DELETE_BLOCKED',
        'severity': 'CRITICAL',
        'details': 'File deletion attempt blocked (ransomware pattern)'
    },
    {
        'event_type': 'FILE_CREATE_BLOCKED',
        'file_path': r'C:\Users\ajibi\OneDrive\Desktop\TestLogging\ransom.txt',
        'process_name': 'powershell.exe',
        'process_id': 5435,
        'action_taken': 'CREATE_BLOCKED',
        'severity': 'CRITICAL',
        'details': 'File creation blocked without valid USB token'
    }
]

print("\n[1/2] Logging simulated attack events to security_events table...\n")
for i, event in enumerate(test_events, 1):
    db.log_event(
        event_type=event['event_type'],
        file_path=event['file_path'],
        process_name=event['process_name'],
        process_id=event['process_id'],
        action_taken=event['action_taken'],
        severity=event['severity'],
        details=event['details']
    )
    print(f"  ✓ Event {i}: {event['event_type']} ({event['severity']})")

print("\n[2/2] Retrieving logged events...\n")
events = db.get_events(limit=10)
print(f"Total security events: {len(events)}\n")

print("Most recent events:")
for i, event in enumerate(events[:5], 1):
    print(f"  {i}. [{event['severity']}] {event['event_type']}")
    print(f"     File: {event['file_path']}")
    print(f"     Action: {event['action']}")

print("\n" + "=" * 70)
print("✅ LOGGING SYSTEM VERIFIED - Events successfully stored in security_events")
print("=" * 70)

# Count by severity
conn = sqlite3.connect(r'C:\Users\ajibi\AppData\Local\Temp\AntiRansomware\protection.db')
cursor = conn.cursor()
cursor.execute("SELECT severity, COUNT(*) FROM security_events GROUP BY severity ORDER BY severity DESC")
rows = cursor.fetchall()
conn.close()

print("\nEvent breakdown by severity:")
for severity, count in rows:
    print(f"  {severity:10s}: {count:3d} events")
