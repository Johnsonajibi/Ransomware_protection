#!/usr/bin/env python3
"""
Audit Log Viewer
================
View and analyze audit logs from tri-factor authentication system
Shows TPM usage, process information, and security events
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict
from collections import Counter

def load_audit_logs(log_dir: Path = None) -> List[Dict]:
    """Load all audit logs"""
    if log_dir is None:
        log_dir = Path(".audit_logs")
    
    if not log_dir.exists():
        print(f"❌ Audit log directory not found: {log_dir}")
        return []
    
    logs = []
    for log_file in sorted(log_dir.glob("audit_*.jsonl")):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        logs.append(json.loads(line))
                    except:
                        pass
        except Exception as e:
            print(f"⚠️ Error reading {log_file}: {e}")
    
    return logs

def format_timestamp(ts: float) -> str:
    """Format timestamp"""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

def print_log_entry(log: Dict, verbose: bool = False):
    """Print a single log entry"""
    ts = format_timestamp(log['timestamp'])
    event = log['event_type'].upper()
    success = "✓" if log['success'] else "✗"
    tpm = "TPM" if log['tpm_used'] else "SW"
    
    print(f"\n{ts} | {success} | {tpm} | {event}")
    print(f"  Process: {log['process_name']} (PID: {log['process_id']})")
    print(f"  User: {log['user']}")
    print(f"  Security: {log['security_level']}")
    
    if verbose and 'details' in log:
        print(f"  Details:")
        for key, value in log['details'].items():
            if key not in ['message']:
                print(f"    {key}: {value}")
    
    if 'message' in log.get('details', {}):
        print(f"  Message: {log['details']['message']}")
    
    if log.get('error'):
        print(f"  Error: {log['error']}")

def show_summary(logs: List[Dict]):
    """Show summary statistics"""
    if not logs:
        print("No logs found")
        return
    
    print("╔" + "═"*58 + "╗")
    print("║" + " AUDIT LOG SUMMARY ".center(58) + "║")
    print("╚" + "═"*58 + "╝")
    print()
    
    # Basic stats
    print(f"Total Events: {len(logs)}")
    print(f"Date Range: {format_timestamp(logs[0]['timestamp'])} to {format_timestamp(logs[-1]['timestamp'])}")
    print()
    
    # Event type breakdown
    event_types = Counter(log['event_type'] for log in logs)
    print("Event Types:")
    for event_type, count in event_types.most_common():
        print(f"  {event_type}: {count}")
    print()
    
    # TPM usage
    tpm_used = sum(1 for log in logs if log['tpm_used'])
    tpm_percentage = (tpm_used / len(logs) * 100) if logs else 0
    print(f"TPM Usage: {tpm_used}/{len(logs)} ({tpm_percentage:.1f}%)")
    print()
    
    # Security levels
    security_levels = Counter(log['security_level'] for log in logs)
    print("Security Levels:")
    for level, count in security_levels.most_common():
        print(f"  {level}: {count}")
    print()
    
    # Process breakdown
    processes = Counter(log['process_name'] for log in logs)
    print("Top Processes:")
    for process, count in processes.most_common(5):
        print(f"  {process}: {count}")
    print()
    
    # Users
    users = Counter(log['user'] for log in logs)
    print("Users:")
    for user, count in users.items():
        print(f"  {user}: {count}")
    print()
    
    # Success rate
    successes = sum(1 for log in logs if log['success'])
    success_rate = (successes / len(logs) * 100) if logs else 0
    print(f"Success Rate: {successes}/{len(logs)} ({success_rate:.1f}%)")

def show_tpm_events(logs: List[Dict]):
    """Show only TPM-related events"""
    tpm_logs = [log for log in logs if log['tpm_used']]
    
    print("╔" + "═"*58 + "╗")
    print("║" + " TPM EVENTS ".center(58) + "║")
    print("╚" + "═"*58 + "╝")
    
    if not tpm_logs:
        print("\n⚠️ No TPM events found")
        print("   TPM may not be enabled or not running as admin")
        return
    
    print(f"\nFound {len(tpm_logs)} TPM events:\n")
    
    for log in tpm_logs:
        print_log_entry(log, verbose=True)

def show_recent(logs: List[Dict], count: int = 10):
    """Show recent events"""
    print("╔" + "═"*58 + "╗")
    print("║" + f" RECENT EVENTS (Last {count}) ".center(58) + "║")
    print("╚" + "═"*58 + "╝")
    
    recent = logs[-count:]
    
    for log in recent:
        print_log_entry(log)

def show_process(logs: List[Dict], process_name: str = None):
    """Show events for a specific process"""
    if process_name:
        filtered = [log for log in logs if process_name.lower() in log['process_name'].lower()]
        title = f" EVENTS FOR: {process_name} "
    else:
        # Show all processes
        processes = set(log['process_name'] for log in logs)
        print("\nAvailable processes:")
        for proc in sorted(processes):
            count = sum(1 for log in logs if log['process_name'] == proc)
            print(f"  {proc}: {count} events")
        return
    
    print("╔" + "═"*58 + "╗")
    print("║" + title.center(58) + "║")
    print("╚" + "═"*58 + "╝")
    
    if not filtered:
        print(f"\n⚠️ No events found for process: {process_name}")
        return
    
    print(f"\nFound {len(filtered)} events:\n")
    
    for log in filtered:
        print_log_entry(log, verbose=True)

def export_report(logs: List[Dict], output_file: str):
    """Export audit report to file"""
    report = []
    report.append("=" * 70)
    report.append("AUDIT LOG REPORT")
    report.append(f"Generated: {datetime.now().isoformat()}")
    report.append("=" * 70)
    report.append("")
    
    # Summary
    report.append("SUMMARY:")
    report.append(f"  Total Events: {len(logs)}")
    if logs:
        report.append(f"  Date Range: {format_timestamp(logs[0]['timestamp'])} to {format_timestamp(logs[-1]['timestamp'])}")
    report.append("")
    
    # TPM usage
    tpm_used = sum(1 for log in logs if log['tpm_used'])
    tpm_percentage = (tpm_used / len(logs) * 100) if logs else 0
    report.append(f"  TPM Usage: {tpm_used}/{len(logs)} ({tpm_percentage:.1f}%)")
    report.append("")
    
    # Detailed logs
    report.append("=" * 70)
    report.append("DETAILED LOGS:")
    report.append("=" * 70)
    report.append("")
    
    for log in logs:
        ts = format_timestamp(log['timestamp'])
        success = "SUCCESS" if log['success'] else "FAILED"
        tpm = "TPM" if log['tpm_used'] else "SOFTWARE"
        
        report.append(f"{ts} | {log['event_type'].upper()} | {success} | {tpm}")
        report.append(f"  Process: {log['process_name']} (PID: {log['process_id']})")
        report.append(f"  User: {log['user']}")
        report.append(f"  Security Level: {log['security_level']}")
        
        if 'message' in log.get('details', {}):
            report.append(f"  Message: {log['details']['message']}")
        
        if log.get('error'):
            report.append(f"  Error: {log['error']}")
        
        report.append("")
    
    # Write to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report))
    
    print(f"✓ Report exported to: {output_file}")

def main():
    """Main function"""
    logs = load_audit_logs()
    
    if not logs:
        print("\n⚠️ No audit logs found")
        print("   Run the anti-ransomware system to generate logs")
        print("   Logs are stored in: .audit_logs/")
        return
    
    print(f"\nLoaded {len(logs)} audit log entries\n")
    
    if len(sys.argv) == 1:
        # No arguments - show summary
        show_summary(logs)
        print("\n" + "─"*60)
        show_recent(logs, count=10)
    
    elif sys.argv[1] == 'summary':
        show_summary(logs)
    
    elif sys.argv[1] == 'tpm':
        show_tpm_events(logs)
    
    elif sys.argv[1] == 'recent':
        count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        show_recent(logs, count=count)
    
    elif sys.argv[1] == 'process':
        process_name = sys.argv[2] if len(sys.argv) > 2 else None
        show_process(logs, process_name)
    
    elif sys.argv[1] == 'export':
        output = sys.argv[2] if len(sys.argv) > 2 else 'audit_report.txt'
        export_report(logs, output)
    
    elif sys.argv[1] == 'all':
        print("╔" + "═"*58 + "╗")
        print("║" + " ALL AUDIT LOGS ".center(58) + "║")
        print("╚" + "═"*58 + "╝")
        for log in logs:
            print_log_entry(log, verbose=True)
    
    else:
        print("Usage:")
        print("  python view_audit_logs.py                  # Show summary + recent")
        print("  python view_audit_logs.py summary          # Show summary stats")
        print("  python view_audit_logs.py tpm              # Show TPM events only")
        print("  python view_audit_logs.py recent [count]   # Show recent N events")
        print("  python view_audit_logs.py process [name]   # Show events for process")
        print("  python view_audit_logs.py export [file]    # Export report")
        print("  python view_audit_logs.py all              # Show all events")

if __name__ == "__main__":
    main()
