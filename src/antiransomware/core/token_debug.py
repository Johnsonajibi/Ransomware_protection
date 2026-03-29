#!/usr/bin/env python3
"""
Debug Token Validation
Scan tokens for expiry, mismatches, and potential validation issues.
"""

import os
import sys
import json
import logging
import argparse
import sqlite3
import platform
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('token_debug.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class TokenDebugger:
    def __init__(self, db_path: str = 'admin.db'):
        self.db_path = Path(db_path)
        self._ensure_db()

    def _ensure_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id TEXT UNIQUE NOT NULL,
                    process_id INTEGER,
                    process_name TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME,
                    status TEXT DEFAULT 'active',
                    hardware_signature TEXT,
                    tpm_verified BOOLEAN DEFAULT FALSE
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS token_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id TEXT,
                    action TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f'DB init failed: {e}')

    def scan(self) -> List[Dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT token_id, status, created_at, expires_at, hardware_signature, tpm_verified FROM tokens')
            rows = cursor.fetchall()
            conn.close()
            issues = []
            now = datetime.now()
            for token_id, status, created_at, expires_at, hw_sig, tpm_ok in rows:
                item = { 'token_id': token_id, 'status': status, 'issues': [] }
                try:
                    if expires_at and datetime.fromisoformat(str(expires_at)) < now:
                        item['issues'].append('expired')
                except Exception:
                    pass
                if status == 'revoked':
                    item['issues'].append('revoked')
                if not hw_sig:
                    item['issues'].append('missing_hardware_signature')
                if not tpm_ok:
                    item['issues'].append('tpm_not_verified')
                if item['issues']:
                    issues.append(item)
            return issues
        except Exception as e:
            logger.error(f'Scan failed: {e}')
            return []

    def fix_tolerance(self, days: int = 1) -> int:
        """Extend expiry by days for tokens in grace period"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE tokens SET expires_at = datetime(expires_at, ?) 
                WHERE status = 'active' AND expires_at < datetime('now', '+1 day')
            ''', (f'+{days} day',))
            count = cursor.rowcount
            conn.commit()
            conn.close()
            return count or 0
        except Exception as e:
            logger.error(f'Fix tolerance failed: {e}')
            return 0

    def check_tpm_status(self) -> Dict:
        """Check TPM status using Windows TPM tooling when available."""
        result = {
            'platform': platform.system(),
            'tpm_present': False,
            'tpm_ready': False,
            'detail': 'TPM not detected',
        }
        if platform.system() != 'Windows':
            result['detail'] = 'TPM probing only implemented for Windows'
            return result

        try:
            ps = subprocess.run(
                [
                    'powershell',
                    '-NoProfile',
                    '-Command',
                    'Get-Tpm | Select-Object TpmPresent,TpmReady,ManagedAuthLevel,ManufacturerIdTxt | ConvertTo-Json -Compress'
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if ps.returncode == 0 and ps.stdout.strip():
                payload = json.loads(ps.stdout.strip())
                result.update(
                    {
                        'tpm_present': bool(payload.get('TpmPresent')),
                        'tpm_ready': bool(payload.get('TpmReady')),
                        'managed_auth_level': payload.get('ManagedAuthLevel'),
                        'manufacturer': payload.get('ManufacturerIdTxt'),
                    }
                )
                result['detail'] = 'TPM status retrieved from Get-Tpm'
                return result
        except Exception as exc:
            result['detail'] = f'Get-Tpm probe failed: {exc}'

        try:
            wmic = subprocess.run(
                ['wmic', '/namespace:\\\\root\\cimv2\\security\\microsofttpm', 'path', 'win32_tpm', 'get', 'IsEnabled_InitialValue,IsActivated_InitialValue', '/value'],
                capture_output=True,
                text=True,
                timeout=10,
            )
            text = (wmic.stdout or '').lower()
            if wmic.returncode == 0 and ('isenabled_initialvalue' in text or 'isactivated_initialvalue' in text):
                result['tpm_present'] = True
                result['tpm_ready'] = 'true' in text
                result['detail'] = 'TPM status retrieved from WMI'
        except Exception:
            pass

        return result


def main():
    parser = argparse.ArgumentParser(description='Debug Token Validation')
    parser.add_argument('--scan', action='store_true', help='Scan tokens for issues')
    parser.add_argument('--fix-tolerance', action='store_true', help='Extend expiry window')
    parser.add_argument('--days', type=int, default=1, help='Days to extend for grace')
    parser.add_argument('--check-tpm', action='store_true', help='Check TPM status')

    args = parser.parse_args()
    dbg = TokenDebugger()

    if args.scan:
        issues = dbg.scan()
        print(json.dumps({ 'count': len(issues), 'issues': issues }, indent=2))
        return 0

    if args.fix_tolerance:
        count = dbg.fix_tolerance(args.days)
        print(json.dumps({ 'extended': count }, indent=2))
        return 0

    if args.check_tpm:
        print(json.dumps(dbg.check_tpm_status(), indent=2))
        return 0

    parser.print_help()
    return 0

if __name__ == '__main__':
    sys.exit(main())
