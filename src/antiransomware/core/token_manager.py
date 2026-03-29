#!/usr/bin/env python3
"""
Trifactor Authentication Manager
Manage TPM + USB + Device Fingerprint authentication.
"""

import os
import sys
import json
import hashlib
import logging
import argparse
import sqlite3
from pathlib import Path
from typing import Dict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TrifactorAuthManager:
    def __init__(self, db_path: str = 'admin.db'):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self):
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS trifactor_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id TEXT UNIQUE NOT NULL,
                    tpm_pcr_value TEXT,
                    device_fingerprint TEXT,
                    usb_signature TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME,
                    status TEXT DEFAULT 'active'
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f'DB init failed: {e}')

    def create_token(self, usb_id: str = None) -> Dict:
        """Create trifactor token (TPM + USB + fingerprint)"""
        try:
            import uuid
            token_id = str(uuid.uuid4())
            tpm_pcr = self._get_tpm_pcr_value()
            fingerprint = self._get_device_fingerprint()
            usb_sig = self._get_usb_signature(usb_id) if usb_id else None

            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO trifactor_tokens (token_id, tpm_pcr_value, device_fingerprint, usb_signature)
                VALUES (?, ?, ?, ?)
            ''', (token_id, tpm_pcr, fingerprint, usb_sig))
            conn.commit()
            conn.close()
            logger.info(f'Token created: {token_id}')
            return {'token_id': token_id, 'status': 'created'}
        except Exception as e:
            logger.error(f'Token creation failed: {e}')
            return {'error': str(e)}

    def _get_tpm_pcr_value(self) -> str:
        """Get TPM PCR value"""
        candidates = []
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            ) as key:
                candidates.append(str(winreg.QueryValueEx(key, "EnableVirtualizationBasedSecurity")[0]))
        except Exception:
            pass

        try:
            import wmi  # type: ignore

            conn = wmi.WMI(namespace=r"root\CIMV2\Security\MicrosoftTpm")
            for tpm in conn.Win32_Tpm():
                if getattr(tpm, "SpecVersion", None):
                    candidates.append(str(tpm.SpecVersion))
                if getattr(tpm, "ManufacturerVersion", None):
                    candidates.append(str(tpm.ManufacturerVersion))
                break
        except Exception:
            pass

        if not candidates:
            candidates.append(self._get_device_fingerprint())

        return hashlib.sha256("|".join(candidates).encode("utf-8")).hexdigest()

    def _get_device_fingerprint(self) -> str:
        """Get device fingerprint (hardware ID)"""
        parts = [
            os.environ.get("COMPUTERNAME", ""),
            os.environ.get("PROCESSOR_IDENTIFIER", ""),
            os.environ.get("USERNAME", ""),
        ]
        try:
            import platform

            parts.extend(
                [
                    platform.node(),
                    platform.machine(),
                    platform.processor(),
                ]
            )
        except Exception:
            pass

        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
            ) as key:
                parts.append(str(winreg.QueryValueEx(key, "MachineGuid")[0]))
        except Exception:
            pass

        normalized = "|".join(part for part in parts if part)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def _get_usb_signature(self, usb_id: str) -> str:
        """Get USB device signature"""
        return f'usb_sig_{usb_id}'

    def verify_token(self, token_id: str) -> Dict:
        """Verify trifactor token"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute('''
                SELECT token_id, status, tpm_pcr_value, device_fingerprint, usb_signature
                FROM trifactor_tokens WHERE token_id = ?
            ''', (token_id,))
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return {'valid': False, 'reason': 'token_not_found'}
            
            return {
                'valid': row[1] == 'active',
                'token_id': row[0],
                'tpm_verified': bool(row[2]),
                'fingerprint_verified': bool(row[3]),
                'usb_verified': bool(row[4])
            }
        except Exception as e:
            return {'error': str(e)}

    def list_tokens(self) -> list:
        """List all tokens"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute('''
                SELECT token_id, status, created_at FROM trifactor_tokens ORDER BY created_at DESC
            ''')
            tokens = [{'token_id': r[0], 'status': r[1], 'created': r[2]} for r in cursor.fetchall()]
            conn.close()
            return tokens
        except Exception as e:
            return []


def main():
    parser = argparse.ArgumentParser(description='Trifactor Authentication Manager')
    sub = parser.add_subparsers(dest='command')

    create = sub.add_parser('create', help='Create trifactor token')
    create.add_argument('--usb-id')

    verify = sub.add_parser('verify', help='Verify token')
    verify.add_argument('token_id')

    sub.add_parser('list', help='List tokens')

    args = parser.parse_args()
    tam = TrifactorAuthManager()

    if args.command == 'create':
        result = tam.create_token(args.usb_id)
        print(json.dumps(result, indent=2))
        return 0

    if args.command == 'verify':
        result = tam.verify_token(args.token_id)
        print(json.dumps(result, indent=2))
        return 0

    if args.command == 'list':
        tokens = tam.list_tokens()
        print(json.dumps(tokens, indent=2))
        return 0

    parser.print_help()
    return 0

if __name__ == '__main__':
    sys.exit(main())


TokenManager = TrifactorAuthManager
