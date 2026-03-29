#!/usr/bin/env python3
"""
Health Monitor
System-wide health checks for protection, performance, and status.
"""

import os
import sys
import json
import logging
import argparse
import sqlite3
import psutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('health_monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class HealthMonitor:
    def __init__(self, db_path: str = 'protection_db.sqlite'):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS health_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    component TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f'DB init failed: {e}')

    def check_system_resources(self) -> Dict:
        try:
            cpu_pct = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            return {
                'cpu_percent': cpu_pct,
                'memory_percent': mem.percent,
                'disk_percent': disk.percent,
                'status': 'healthy' if cpu_pct < 80 and mem.percent < 85 and disk.percent < 90 else 'warning'
            }
        except Exception as e:
            logger.error(f'Resource check failed: {e}')
            return { 'status': 'error', 'message': str(e) }

    def check_database(self) -> Dict:
        try:
            if not self.db_path.exists():
                return { 'status': 'error', 'message': 'database not found' }
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM sqlite_master WHERE type="table"')
            table_count = cursor.fetchone()[0]
            conn.close()
            return { 'status': 'healthy', 'tables': table_count }
        except Exception as e:
            return { 'status': 'error', 'message': str(e) }

    def check_protection_components(self) -> Dict:
        components = ['kernel_driver', 'monitor', 'siem', 'token_gating']
        result = {}
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='protection_status'"
            )
            if cursor.fetchone()[0] == 0:
                conn.close()
                return {'status': 'warning', 'message': 'protection_status table not initialized', 'components': {}}
            cursor.execute('SELECT component, enabled FROM protection_status')
            enabled_map = {row[0]: bool(row[1]) for row in cursor.fetchall()}
            conn.close()
            for comp in components:
                result[comp] = 'enabled' if enabled_map.get(comp) else 'disabled'
            return { 'status': 'healthy', 'components': result }
        except Exception as e:
            return { 'status': 'error', 'message': str(e) }

    def check_event_rate(self, minutes: int = 60) -> Dict:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='security_events'"
            )
            if cursor.fetchone()[0] == 0:
                conn.close()
                return {'status': 'warning', 'message': 'security_events table not initialized'}
            cursor.execute('''
                SELECT COUNT(*) FROM security_events 
                WHERE timestamp > datetime('now', '-' || ? || ' minutes')
            ''', (minutes,))
            count = cursor.fetchone()[0] or 0
            conn.close()
            rate = count / minutes if minutes > 0 else 0
            return { 'events_' + str(minutes) + 'min': count, 'events_per_min': round(rate, 2) }
        except Exception as e:
            return { 'status': 'error', 'message': str(e) }

    def full_check(self) -> Dict:
        system_resources = self.check_system_resources()
        database = self.check_database()
        protection_components = self.check_protection_components()
        event_rate = self.check_event_rate()
        statuses = [
            system_resources.get('status', 'unknown'),
            database.get('status', 'unknown'),
            protection_components.get('status', 'unknown'),
            event_rate.get('status', 'healthy'),
        ]
        overall = 'healthy' if all(status in ('healthy', 'warning') for status in statuses) else 'error'
        return {
            'timestamp': datetime.now().isoformat(),
            'system_resources': system_resources,
            'database': database,
            'protection_components': protection_components,
            'event_rate': event_rate,
            'overall': overall
        }

    def save_check(self, name: str, result: Dict):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            status = result.get('status', 'unknown')
            msg = json.dumps(result)
            cursor.execute('''
                INSERT INTO health_checks (component, status, message)
                VALUES (?, ?, ?)
            ''', (name, status, msg))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f'Save check failed: {e}')

    def get_history(self, limit: int = 20) -> List[Dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT component, status, timestamp, message FROM health_checks
                ORDER BY id DESC LIMIT ?
            ''', (limit,))
            cols = ['component', 'status', 'timestamp', 'message']
            rows = [dict(zip(cols, r)) for r in cursor.fetchall()]
            conn.close()
            return rows
        except Exception as e:
            logger.error(f'History query failed: {e}')
            return []


def main():
    parser = argparse.ArgumentParser(description='Health Monitor')
    sub = parser.add_subparsers(dest='command')

    sub.add_parser('full', help='Full system health check')
    sub.add_parser('resources', help='Check system resources')
    sub.add_parser('database', help='Check database')
    sub.add_parser('components', help='Check protection components')

    events = sub.add_parser('events', help='Check event rate')
    events.add_argument('--minutes', type=int, default=60)

    hist = sub.add_parser('history', help='Health check history')
    hist.add_argument('--limit', type=int, default=20)

    args = parser.parse_args()
    hm = HealthMonitor()

    if args.command == 'full':
        result = hm.full_check()
        hm.save_check('full_check', result)
        print(json.dumps(result, indent=2))
        return 0

    if args.command == 'resources':
        print(json.dumps(hm.check_system_resources(), indent=2))
        return 0

    if args.command == 'database':
        print(json.dumps(hm.check_database(), indent=2))
        return 0

    if args.command == 'components':
        print(json.dumps(hm.check_protection_components(), indent=2))
        return 0

    if args.command == 'events':
        print(json.dumps(hm.check_event_rate(args.minutes), indent=2))
        return 0

    if args.command == 'history':
        print(json.dumps(hm.get_history(args.limit), indent=2))
        return 0

    parser.print_help()
    return 0

if __name__ == '__main__':
    sys.exit(main())
