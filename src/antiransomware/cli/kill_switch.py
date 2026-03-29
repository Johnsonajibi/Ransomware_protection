#!/usr/bin/env python3
"""
Emergency Kill Switch
Immediately disable protections, stop services, and mark system as safe mode.
"""

import os
import sys
import json
import logging
import argparse
import subprocess
import sqlite3
from pathlib import Path
from typing import Dict

from antiransomware.core.engine import ProtectionEngine

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('emergency.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class KillSwitch:
    def __init__(self, protection_db: str = 'protection_db.sqlite'):
        self.db_path = Path(protection_db)
        self.engine = ProtectionEngine(str(self.db_path))
        self._init_db()

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS protection_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    component TEXT UNIQUE NOT NULL,
                    enabled BOOLEAN DEFAULT FALSE,
                    last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS emergency_state (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    active BOOLEAN DEFAULT FALSE,
                    reason TEXT,
                    activated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f'DB init failed: {e}')

    def activate(self, reason: str = 'manual') -> bool:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            # Disable all components
            cursor.execute('UPDATE protection_status SET enabled = 0, last_checked = datetime("now")')
            # Mark emergency
            cursor.execute('INSERT INTO emergency_state (active, reason) VALUES (1, ?)', (reason,))
            conn.commit()
            conn.close()
            self.engine.log_event(
                'emergency_kill_switch',
                severity='critical',
                action='activate',
                details={'reason': reason},
            )
            logger.info('Emergency state activated in DB')
            return True
        except Exception as e:
            logger.error(f'Failed to activate emergency: {e}')
            return False

    def stop_services(self):
        # Attempt to stop Windows services related to protection
        services = ['AntiRansomware', 'AntiRansomwareDriver']
        for svc in services:
            try:
                subprocess.run(['sc', 'stop', svc], capture_output=True, text=True, timeout=10)
                logger.info(f'Service stop requested: {svc}')
            except Exception as e:
                logger.warning(f'Failed to stop {svc}: {e}')

    def kill_processes(self, names=None):
        names = names or ['RealAntiRansomwareManager.exe']
        for name in names:
            try:
                subprocess.run(['taskkill', '/IM', name, '/F'], capture_output=True, text=True, timeout=5)
                logger.info(f'Process kill requested: {name}')
            except Exception as e:
                logger.warning(f'Failed to kill {name}: {e}')

    def status(self) -> Dict:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT active, reason, activated_at FROM emergency_state ORDER BY id DESC LIMIT 1')
            row = cursor.fetchone()
            conn.close()
            if not row:
                return { 'active': False }
            return { 'active': bool(row[0]), 'reason': row[1], 'activated_at': row[2] }
        except Exception as e:
            return { 'error': str(e) }


def main():
    parser = argparse.ArgumentParser(description='Emergency Kill Switch')
    parser.add_argument('--activate', action='store_true', help='Activate kill switch')
    parser.add_argument('--reason', help='Reason for activation')
    parser.add_argument('--stop-services', action='store_true', help='Stop services')
    parser.add_argument('--kill-processes', action='store_true', help='Kill manager processes')
    parser.add_argument('--status', action='store_true', help='Show emergency status')

    args = parser.parse_args()
    ks = KillSwitch()

    if args.activate:
        ok = ks.activate(args.reason or 'manual')
        print('Emergency activated' if ok else 'Activation failed')
        if ok:
            ks.stop_services()
            ks.kill_processes()
        return 0 if ok else 1

    if args.stop_services:
        ks.stop_services()
        print('Service stop requested')
        return 0

    if args.kill_processes:
        ks.kill_processes()
        print('Process kill requested')
        return 0

    if args.status:
        print(json.dumps(ks.status(), indent=2))
        return 0

    parser.print_help()
    return 0

if __name__ == '__main__':
    sys.exit(main())
