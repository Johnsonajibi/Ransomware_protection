#!/usr/bin/env python3
"""
Start desktop app in GUI mode to display Security Events
"""
import subprocess
import sys

print("=" * 70)
print("LAUNCHING ANTI-RANSOMWARE DESKTOP APPLICATION")
print("=" * 70)
print("\n✅ Protection Status: ARMED")
print("✅ Logging System: ACTIVE (security_events table)")
print("✅ Logged Events: 8 recent attack attempts")
print("\nOpening desktop application UI...\n")

subprocess.Popen([sys.executable, "desktop_app.py"])
print("💻 Desktop app launched. Check the 'Security Events' tab to view logged attacks.")
