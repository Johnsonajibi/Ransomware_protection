#!/usr/bin/env python3
"""
System Health Checker
Comprehensive system health and protection status verification.
"""

import os
import sys
import json
import logging
import argparse
import shutil
import sqlite3
import subprocess
from typing import Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SystemHealthChecker:
    def __init__(self):
        self.checks = []

    def check_disk_space(self) -> Dict:
        """Check available disk space"""
        try:
            system_drive = os.environ.get("SystemDrive", "C:")
            total, used, free = shutil.disk_usage(system_drive)
            return {
                'check': 'disk_space',
                'free_gb': round(free / (1024**3), 2),
                'total_gb': round(total / (1024**3), 2),
                'status': 'ok' if free > 1024**3 else 'warning'
            }
        except Exception as e:
            return {'error': str(e)}

    def check_memory(self) -> Dict:
        """Check available memory"""
        try:
            import psutil
            mem = psutil.virtual_memory()
            return {
                'check': 'memory',
                'available_mb': round(mem.available / (1024**2)),
                'total_mb': round(mem.total / (1024**2)),
                'percent_used': mem.percent,
                'status': 'ok' if mem.percent < 80 else 'warning'
            }
        except Exception as e:
            return {'error': str(e)}

    def check_protection_services(self) -> Dict:
        """Check if protection services are running"""
        services = ['AntiRansomwareDriver', 'AntiRansomwareMonitor']
        status_map = {}
        for svc in services:
            try:
                result = subprocess.run(
                    ['sc', 'query', svc],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                stdout = (result.stdout or '').upper()
                if 'RUNNING' in stdout:
                    status_map[svc] = 'running'
                elif 'STOPPED' in stdout:
                    status_map[svc] = 'stopped'
                else:
                    status_map[svc] = 'unknown'
            except Exception:
                status_map[svc] = 'unknown'
        return {
            'check': 'protection_services',
            'services': status_map,
            'status': 'ok' if all(v == 'running' for v in status_map.values()) else 'warning'
        }

    def check_database_integrity(self) -> Dict:
        """Check database integrity"""
        try:
            dbs = ['admin.db', 'protection_db.sqlite']
            checked = {}
            for db in dbs:
                if os.path.exists(db):
                    conn = sqlite3.connect(db)
                    cursor = conn.cursor()
                    cursor.execute('PRAGMA integrity_check')
                    result = cursor.fetchone()
                    conn.close()
                    checked[db] = result[0] if result else 'unknown'
            status = 'ok' if all(value == 'ok' for value in checked.values()) else 'warning'
            return {'check': 'database_integrity', 'status': status, 'databases': checked}
        except Exception as e:
            return {'check': 'database_integrity', 'status': 'error', 'error': str(e)}

    def check_all(self) -> Dict:
        """Run all health checks"""
        all_checks = {
            'disk': self.check_disk_space(),
            'memory': self.check_memory(),
            'services': self.check_protection_services(),
            'database': self.check_database_integrity()
        }
        overall = 'healthy' if all(c.get('status') in ['ok', 'running'] for c in all_checks.values()) else 'issues_detected'
        return {
            'timestamp': __import__('datetime').datetime.now().isoformat(),
            'overall_status': overall,
            'checks': all_checks
        }


def main():
    parser = argparse.ArgumentParser(description='System Health Checker')
    sub = parser.add_subparsers(dest='command')

    sub.add_parser('disk', help='Check disk space')
    sub.add_parser('memory', help='Check memory')
    sub.add_parser('services', help='Check protection services')
    sub.add_parser('database', help='Check database integrity')
    sub.add_parser('all', help='Run all checks')

    args = parser.parse_args()
    shc = SystemHealthChecker()

    if args.command == 'disk':
        print(json.dumps(shc.check_disk_space(), indent=2))
        return 0

    if args.command == 'memory':
        print(json.dumps(shc.check_memory(), indent=2))
        return 0

    if args.command == 'services':
        print(json.dumps(shc.check_protection_services(), indent=2))
        return 0

    if args.command == 'database':
        print(json.dumps(shc.check_database_integrity(), indent=2))
        return 0

    if args.command == 'all':
        print(json.dumps(shc.check_all(), indent=2))
        return 0

    parser.print_help()
    return 0

if __name__ == '__main__':
    sys.exit(main())
