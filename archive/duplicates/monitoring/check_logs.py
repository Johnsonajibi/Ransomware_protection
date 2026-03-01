#!/usr/bin/env python3
"""Check protection logs and security events"""
import sqlite3
import sys
from pathlib import Path
from datetime import datetime

db_path = Path.home() / "AppData" / "Local" / "Temp" / "AntiRansomware" / "protection.db"

if not db_path.exists():
    print(f"Database not found: {db_path}")
    sys.exit(1)

conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

# Show all tables
print("="*70)
print("DATABASE TABLES")
print("="*70)
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
for table in tables:
    print(f"  • {table[0]}")

print("\n" + "="*70)
print("SECURITY EVENTS LOG")
print("="*70)

# Check if security_events table exists
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'")
if cursor.fetchone():
    cursor.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 50")
    events = cursor.fetchall()
    
    if events:
        # Get column names
        cursor.execute("PRAGMA table_info(security_events)")
        columns = [col[1] for col in cursor.fetchall()]
        
        print(f"\nFound {len(events)} recent events:\n")
        for event in events:
            print("-" * 70)
            for i, col in enumerate(columns):
                print(f"  {col}: {event[i]}")
    else:
        print("\n  No events logged yet")
else:
    print("\n  security_events table doesn't exist")

print("\n" + "="*70)
print("FILE ACCESS ATTEMPTS")
print("="*70)

# Check for blocked_attempts or similar table
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE '%block%' OR name LIKE '%attempt%' OR name LIKE '%access%')")
attempt_tables = cursor.fetchall()

if attempt_tables:
    for table_name in attempt_tables:
        print(f"\nTable: {table_name[0]}")
        cursor.execute(f"SELECT * FROM {table_name[0]} ORDER BY rowid DESC LIMIT 20")
        attempts = cursor.fetchall()
        
        if attempts:
            cursor.execute(f"PRAGMA table_info({table_name[0]})")
            columns = [col[1] for col in cursor.fetchall()]
            
            print(f"Found {len(attempts)} records:\n")
            for attempt in attempts:
                print("-" * 70)
                for i, col in enumerate(columns):
                    print(f"  {col}: {attempt[i]}")
        else:
            print("  No records")
else:
    print("\n  No access attempt tables found")

print("\n" + "="*70)
print("PROTECTED FOLDERS")
print("="*70)

cursor.execute("SELECT * FROM protected_folders")
folders = cursor.fetchall()

if folders:
    cursor.execute("PRAGMA table_info(protected_folders)")
    columns = [col[1] for col in cursor.fetchall()]
    
    for folder in folders:
        print("-" * 70)
        for i, col in enumerate(columns):
            print(f"  {col}: {folder[i]}")
else:
    print("\n  No protected folders")

conn.close()
print("\n" + "="*70)
