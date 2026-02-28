#!/usr/bin/env python3
"""
Remove Desktop, Downloads, and Documents from protected paths database
"""
import os
import sys
import sqlite3
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Find the database (check both possible locations)
db_paths = [
    Path.home() / "AppData" / "Local" / "AntiRansomware" / "protected_folders.db",
    Path.home() / "AppData" / "Local" / "Temp" / "AntiRansomware" / "protection.db"
]

db_path = None
for path in db_paths:
    if path.exists():
        db_path = path
        break

if db_path is None:
    print("Database not found. Tried:")
    for path in db_paths:
        print(f"  {path}")
    sys.exit(1)

if db_path is None:
    print("Database not found. Tried:")
    for path in db_paths:
        print(f"  {path}")
    sys.exit(1)

print(f"Database found: {db_path}")

# Connect to database
conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

# Get current protected paths
cursor.execute("SELECT id, path FROM protected_folders")
paths = cursor.fetchall()

print("\nCurrent protected paths:")
for id, path in paths:
    print(f"  {id}: {path}")

# Identify paths to remove
home = str(Path.home())
paths_to_remove = [
    str(Path.home() / "Documents"),
    str(Path.home() / "Desktop"),
    str(Path.home() / "Downloads")
]

removed_count = 0
for path_to_remove in paths_to_remove:
    # Case-insensitive check
    cursor.execute("SELECT id, path FROM protected_folders WHERE LOWER(path) = LOWER(?)", (path_to_remove,))
    matches = cursor.fetchall()
    
    for id, path in matches:
        print(f"\nRemoving: {path}")
        cursor.execute("DELETE FROM protected_folders WHERE id = ?", (id,))
        removed_count += 1

conn.commit()

print(f"\n✓ Removed {removed_count} paths")

# Show remaining paths
cursor.execute("SELECT id, path FROM protected_folders")
remaining = cursor.fetchall()

print("\nRemaining protected paths:")
if remaining:
    for id, path in remaining:
        print(f"  {id}: {path}")
else:
    print("  (none)")

conn.close()

print("\n✓ Database updated successfully")
print("Restart the application to see the changes")
