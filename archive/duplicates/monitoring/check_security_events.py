#!/usr/bin/env python3
"""Check logged security events from protection testing"""
from unified_antiransomware import UnifiedDatabase

db = UnifiedDatabase()
events = db.get_events(limit=10)

print("=" * 70)
print(f"SECURITY EVENTS LOG ({len(events)} recent events)")
print("=" * 70)

if events:
    for i, event in enumerate(events, 1):
        print(f"\n{i}. [{event.get('severity', 'N/A')}] {event.get('timestamp', 'N/A')[:19]}")
        print(f"   Event Type: {event.get('event_type', 'N/A')}")
        print(f"   Action: {event.get('action', 'N/A')}")
        print(f"   File Path: {event.get('file_path', 'N/A')}")
        print(f"   Process: {event.get('process_name', 'N/A')}")
        print(f"   Details: {event.get('details', 'N/A')}")
else:
    print("\nℹ️ No security events logged yet")

print("\n" + "=" * 70)
