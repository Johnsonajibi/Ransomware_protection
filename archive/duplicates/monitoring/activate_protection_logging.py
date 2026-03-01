#!/usr/bin/env python3
"""
Activate protection on test folder and start monitoring with logging
"""
from unified_antiransomware import UnifiedProtectionManager
import time

print("=" * 70)
print("INITIALIZING ATTACK SIMULATION WITH LOGGING")
print("=" * 70)

# Initialize protection manager
mgr = UnifiedProtectionManager()

# Add test folder to database
test_folder = r'C:\Users\ajibi\OneDrive\Desktop\TestLogging'
print(f"\n[1/4] Adding {test_folder} to protection database...")
mgr.database.add_protected_folder(test_folder, protection_level="MAXIMUM")
print("✅ Folder added to database")

# Register all files as protected
print(f"\n[2/4] Registering files in {test_folder}...")
from pathlib import Path
for file_path in Path(test_folder).rglob('*'):
    if file_path.is_file():
        mgr.file_manager.access_control.register_protected_file(file_path)
        print(f"  ✓ Registered: {file_path.name}")
print("✅ Files registered as protected")

# Add to real-time blocker
print(f"\n[3/4] Starting real-time file blocker...")
mgr.file_blocker.add_protected_path(test_folder)
mgr.file_blocker.start_monitoring()
print("✅ Real-time blocker active")

# Wait for monitoring to stabilize
print(f"\n[4/4] Stabilizing blocker (3 seconds)...")
time.sleep(3)

print("\n" + "=" * 70)
print("✅ PROTECTION ACTIVE - Ready for attack simulation")
print("=" * 70)
print(f"\nTarget folder: {test_folder}")
print(f"Protection level: MAXIMUM")
print(f"Logging enabled: YES (events → security_events table)")
print(f"\nNow run PowerShell attacks from another terminal:")
print(f"  1. Get-ChildItem '{test_folder}'")
print(f"  2. Copy-Item '{test_folder}\\sample1.txt' '{test_folder}\\copy.txt'")
print(f"  3. Remove-Item '{test_folder}\\sample1.txt'")
print(f"  4. New-Item -Path '{test_folder}\\new.txt' -ItemType File")
print(f"\nEach blocked attempt will be logged to security_events table")
print("=" * 70)

# Keep monitoring alive
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n\n⛔ Stopping blocker...")
    mgr.file_blocker.stop_monitoring()
    print("✅ Blocker stopped")
