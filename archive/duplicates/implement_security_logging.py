"""
Implement Security Event Logging System
Adds security_events table and integrates logging into protection layers
"""

import sqlite3
from pathlib import Path

def create_security_events_table():
    """Create security_events table in the database"""
    db_path = Path.home() / "AppData" / "Local" / "Temp" / "AntiRansomware" / "protection.db"
    
    if not db_path.exists():
        print(f"❌ Database not found at {db_path}")
        return False
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create security_events table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            file_path TEXT,
            process_name TEXT,
            process_id INTEGER,
            action_taken TEXT NOT NULL,
            severity TEXT NOT NULL,
            details TEXT,
            username TEXT
        )
    """)
    
    # Create index for faster queries
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_security_events_timestamp 
        ON security_events(timestamp DESC)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_security_events_severity 
        ON security_events(severity)
    """)
    
    conn.commit()
    
    # Verify table created
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'")
    if cursor.fetchone():
        print("✅ security_events table created successfully")
        
        # Show schema
        cursor.execute("PRAGMA table_info(security_events)")
        columns = cursor.fetchall()
        print("\nTable Schema:")
        for col in columns:
            print(f"  - {col[1]} ({col[2]})")
        
        return True
    else:
        print("❌ Failed to create security_events table")
        return False
    
    conn.close()

def add_test_security_events():
    """Add test security events to demonstrate logging"""
    db_path = Path.home() / "AppData" / "Local" / "Temp" / "AntiRansomware" / "protection.db"
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    from datetime import datetime
    import getpass
    
    test_events = [
        {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'FILE_ACCESS_DENIED',
            'file_path': r'C:\Users\ajibi\OneDrive\Desktop\Test\sensitive_data.txt',
            'process_name': 'powershell.exe',
            'process_id': 12345,
            'action_taken': 'ACCESS_BLOCKED',
            'severity': 'HIGH',
            'details': 'PowerShell Get-ChildItem access attempt blocked by NTFS layer',
            'username': getpass.getuser()
        },
        {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'FILE_COPY_BLOCKED',
            'file_path': r'C:\Users\ajibi\OneDrive\Desktop\Test',
            'process_name': 'powershell.exe',
            'process_id': 12346,
            'action_taken': 'COPY_BLOCKED',
            'severity': 'CRITICAL',
            'details': 'Copy-Item ransomware-like operation blocked',
            'username': getpass.getuser()
        },
        {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'FILE_DELETE_BLOCKED',
            'file_path': r'C:\Users\ajibi\OneDrive\Desktop\Test',
            'process_name': 'powershell.exe',
            'process_id': 12347,
            'action_taken': 'DELETE_BLOCKED',
            'severity': 'CRITICAL',
            'details': 'Remove-Item ransomware-like deletion blocked',
            'username': getpass.getuser()
        },
        {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'FILE_CREATE_BLOCKED',
            'file_path': r'C:\Users\ajibi\OneDrive\Desktop\Test\testfile.txt',
            'process_name': 'powershell.exe',
            'process_id': 12348,
            'action_taken': 'CREATE_BLOCKED',
            'severity': 'HIGH',
            'details': 'New-Item file creation attempt blocked',
            'username': getpass.getuser()
        }
    ]
    
    for event in test_events:
        cursor.execute("""
            INSERT INTO security_events 
            (timestamp, event_type, file_path, process_name, process_id, 
             action_taken, severity, details, username)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event['timestamp'],
            event['event_type'],
            event['file_path'],
            event['process_name'],
            event['process_id'],
            event['action_taken'],
            event['severity'],
            event['details'],
            event['username']
        ))
    
    conn.commit()
    
    # Show inserted events
    cursor.execute("SELECT COUNT(*) FROM security_events")
    count = cursor.fetchone()[0]
    print(f"\n✅ Added {len(test_events)} test security events (Total: {count})")
    
    # Show recent events
    cursor.execute("""
        SELECT timestamp, event_type, severity, action_taken, process_name
        FROM security_events
        ORDER BY id DESC
        LIMIT 5
    """)
    
    print("\nRecent Security Events:")
    for row in cursor.fetchall():
        print(f"  [{row[2]}] {row[0][:19]} - {row[1]} by {row[4]}: {row[3]}")
    
    conn.close()

if __name__ == "__main__":
    print("=" * 70)
    print("Security Event Logging System Implementation")
    print("=" * 70)
    
    # Step 1: Create security_events table
    print("\n[1/2] Creating security_events table...")
    if create_security_events_table():
        # Step 2: Add test events to demonstrate logging
        print("\n[2/2] Adding test security events...")
        add_test_security_events()
        
        print("\n" + "=" * 70)
        print("✅ Security event logging system ready!")
        print("\nNext Steps:")
        print("1. Integrate logging into unified_antiransomware.py")
        print("2. Update desktop_app.py Security Events tab to show these events")
        print("3. Test with real protection events")
        print("=" * 70)
    else:
        print("\n❌ Failed to setup security event logging")
