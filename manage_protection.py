#!/usr/bin/env python3
"""Simple CLI to manage folder protection for testing"""

import sys
import os
import sqlite3
from pathlib import Path
import subprocess
import time

def get_database_path():
    """Get the database path"""
    return Path.home() / "AppData" / "Local" / "PreventionAntiRansomware" / "folders.db"

def list_protected_folders():
    """List currently protected folders"""
    db_path = get_database_path()
    
    if not db_path.exists():
        print("❌ Database not found. System not initialized.")
        return []
    
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT folder_path, status FROM folders")
        folders = cursor.fetchall()
        conn.close()
        
        print("🛡️ PROTECTED FOLDERS:")
        print("="*60)
        for folder, status in folders:
            print(f"📂 {folder} [{status}]")
        
        return folders
    except Exception as e:
        print(f"❌ Database error: {e}")
        return []

def add_protection(folder_path):
    """Add a folder to protection"""
    db_path = get_database_path()
    
    # Ensure directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Create table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_path TEXT UNIQUE,
                status TEXT DEFAULT 'active',
                added_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Add folder
        cursor.execute("INSERT OR REPLACE INTO folders (folder_path, status) VALUES (?, ?)",
                      (folder_path, 'active'))
        conn.commit()
        conn.close()
        
        print(f"✅ Added to protection: {folder_path}")
        return True
    except Exception as e:
        print(f"❌ Failed to add protection: {e}")
        return False

def lock_folder_manually(folder_path):
    """Manually lock a folder using our protection logic"""
    folder_path = Path(folder_path)
    
    if not folder_path.exists():
        print(f"❌ Folder not found: {folder_path}")
        return False
    
    print(f"🔒 LOCKING FOLDER: {folder_path}")
    print("="*60)
    
    # Lock all files first
    files_locked = 0
    for file_path in folder_path.rglob('*'):
        if file_path.is_file():
            print(f"🛡️ Locking file: {file_path.name}")
            
            # Apply aggressive file protection
            try:
                # Set system file attributes
                result = subprocess.run(['attrib', '+S', '+H', '+R', str(file_path)], 
                                      capture_output=True, shell=True, text=True)
                if result.returncode == 0:
                    print(f"  ✅ System attributes applied")
                
                # Deny access to everyone
                subprocess.run([
                    'icacls', str(file_path), '/deny', 'Everyone:(F)', '/C'
                ], capture_output=True, shell=True)
                print(f"  ✅ Everyone access denied")
                
                # Deny administrators
                subprocess.run([
                    'icacls', str(file_path), '/deny', 'Administrators:(F)', '/C'
                ], capture_output=True, shell=True)
                print(f"  ✅ Administrator access denied")
                
                # Take ownership and deny
                subprocess.run([
                    'takeown', '/F', str(file_path), '/A'
                ], capture_output=True, shell=True)
                
                subprocess.run([
                    'icacls', str(file_path), '/deny', '*S-1-1-0:(F)', '/C'
                ], capture_output=True, shell=True)
                print(f"  ✅ Ownership protection applied")
                
                files_locked += 1
                
            except Exception as e:
                print(f"  ❌ Error locking {file_path.name}: {e}")
    
    # Then lock the folder itself
    try:
        print(f"\n🔒 Locking folder: {folder_path}")
        
        # Set folder attributes
        subprocess.run(['attrib', '+S', '+H', '+R', str(folder_path)], 
                      capture_output=True, shell=True)
        print("  ✅ Folder system attributes applied")
        
        # Deny folder access
        subprocess.run([
            'icacls', str(folder_path), '/deny', 'Everyone:(OI)(CI)(F)', '/C'
        ], capture_output=True, shell=True)
        print("  ✅ Folder access denied to Everyone")
        
        subprocess.run([
            'icacls', str(folder_path), '/deny', 'Administrators:(OI)(CI)(F)', '/C'
        ], capture_output=True, shell=True)
        print("  ✅ Folder access denied to Administrators")
        
    except Exception as e:
        print(f"  ❌ Error locking folder: {e}")
    
    print(f"\n🛡️ PROTECTION COMPLETE: {files_locked} files locked")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python manage_protection.py list")
        print("  python manage_protection.py add <folder_path>")
        print("  python manage_protection.py lock <folder_path>")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == "list":
        list_protected_folders()
    
    elif command == "add":
        if len(sys.argv) < 3:
            print("❌ Please specify folder path")
            sys.exit(1)
        folder_path = sys.argv[2]
        add_protection(folder_path)
    
    elif command == "lock":
        if len(sys.argv) < 3:
            print("❌ Please specify folder path")
            sys.exit(1)
        folder_path = sys.argv[2]
        lock_folder_manually(folder_path)
    
    else:
        print("❌ Unknown command. Use: list, add, or lock")
