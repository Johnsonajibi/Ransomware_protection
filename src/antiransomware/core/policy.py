#!/usr/bin/env python3
"""
Policy Engine Test Harness
Test and validate protection policies.
"""

import os
import sys
import json
import logging
import argparse
import sqlite3
from pathlib import Path
from typing import Dict, List

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('policy_engine.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class PolicyEngine:
    def __init__(self, db_path: str = 'admin.db'):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    enabled BOOLEAN DEFAULT TRUE,
                    rules TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    version INTEGER DEFAULT 1
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS policy_tests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_id INTEGER,
                    test_name TEXT NOT NULL,
                    result TEXT DEFAULT 'pending',
                    message TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(policy_id) REFERENCES policies(id)
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f'DB init failed: {e}')

    def create_policy(self, name: str, rules: Dict, enabled: bool = True) -> bool:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO policies (name, rules, enabled, version)
                VALUES (?, ?, ?, 1)
            ''', (name, json.dumps(rules), int(enabled)))
            conn.commit()
            conn.close()
            logger.info(f'Policy created: {name}')
            return True
        except Exception as e:
            logger.error(f'Create policy failed: {e}')
            return False

    def list_policies(self) -> List[Dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, enabled, version, created_at FROM policies ORDER BY created_at DESC')
            cols = ['id', 'name', 'enabled', 'version', 'created_at']
            rows = [dict(zip(cols, r)) for r in cursor.fetchall()]
            conn.close()
            return rows
        except Exception as e:
            logger.error(f'List failed: {e}')
            return []

    def test_policy(self, policy_name: str, test_name: str, test_case: Dict) -> Dict:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT id, rules FROM policies WHERE name = ?', (policy_name,))
            row = cursor.fetchone()
            if not row:
                return { 'status': 'error', 'message': f'Policy not found: {policy_name}' }
            policy_id, rules_str = row
            rules = json.loads(rules_str)

            # Simulate test: evaluate test case against policy rules
            result = 'pass' if self._evaluate_test(rules, test_case) else 'fail'
            message = f'Test case evaluated: {test_case.get("description", test_name)}'

            cursor.execute('''
                INSERT INTO policy_tests (policy_id, test_name, result, message)
                VALUES (?, ?, ?, ?)
            ''', (policy_id, test_name, result, message))
            conn.commit()
            conn.close()
            logger.info(f'Policy test {policy_name}/{test_name}: {result}')
            return { 'status': 'success', 'result': result, 'message': message }
        except Exception as e:
            logger.error(f'Test policy failed: {e}')
            return { 'status': 'error', 'message': str(e) }

    def _evaluate_test(self, rules: Dict, test_case: Dict) -> bool:
        operation = str(test_case.get('operation', '')).lower()
        path = str(test_case.get('path', '')).lower()
        process_name = str(test_case.get('process_name', '')).lower()
        threat_score = float(test_case.get('threat_score', 0) or 0)

        blocked_ops = {str(item).lower() for item in rules.get('blocked_operations', [])}
        allowed_ops = {str(item).lower() for item in rules.get('allowed_operations', [])}
        blocked_processes = {str(item).lower() for item in rules.get('blocked_processes', [])}
        allowed_processes = {str(item).lower() for item in rules.get('allowed_processes', [])}
        protected_paths = [str(item).lower() for item in rules.get('protected_paths', [])]
        min_threat_score = float(rules.get('min_threat_score', 0) or 0)

        if blocked_processes and process_name in blocked_processes:
            return bool(test_case.get('should_block', True))

        if blocked_ops and operation in blocked_ops:
            return bool(test_case.get('should_block', True))

        if protected_paths and path:
            if any(path.startswith(prefix) for prefix in protected_paths):
                if rules.get('block_mode') and operation in {'write', 'delete', 'rename'}:
                    return bool(test_case.get('should_block', True))

        if min_threat_score and threat_score >= min_threat_score:
            return bool(test_case.get('should_block', True))

        if allowed_processes and process_name and process_name not in allowed_processes:
            return not bool(test_case.get('should_allow', False))

        if allowed_ops:
            return operation in allowed_ops if operation else bool(test_case.get('expected', False))

        if rules.get('allow_unknown'):
            return bool(test_case.get('should_allow', True))

        return bool(test_case.get('expected', False))

    def get_test_results(self, policy_name: str = None) -> List[Dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            if policy_name:
                cursor.execute('''
                    SELECT p.name, t.test_name, t.result, t.timestamp, t.message
                    FROM policy_tests t JOIN policies p ON t.policy_id = p.id
                    WHERE p.name = ? ORDER BY t.id DESC
                ''', (policy_name,))
            else:
                cursor.execute('''
                    SELECT p.name, t.test_name, t.result, t.timestamp, t.message
                    FROM policy_tests t JOIN policies p ON t.policy_id = p.id
                    ORDER BY t.id DESC LIMIT 50
                ''')
            cols = ['policy', 'test', 'result', 'timestamp', 'message']
            rows = [dict(zip(cols, r)) for r in cursor.fetchall()]
            conn.close()
            return rows
        except Exception as e:
            logger.error(f'Get results failed: {e}')
            return []


def main():
    parser = argparse.ArgumentParser(description='Policy Engine Test Harness')
    sub = parser.add_subparsers(dest='command')

    create = sub.add_parser('create', help='Create policy')
    create.add_argument('--name', required=True)
    create.add_argument('--rules-json', required=True)

    sub.add_parser('list', help='List policies')

    test = sub.add_parser('test', help='Test policy')
    test.add_argument('--policy', required=True)
    test.add_argument('--test-name', required=True)
    test.add_argument('--test-case-json', required=True)

    results = sub.add_parser('results', help='Get test results')
    results.add_argument('--policy')

    args = parser.parse_args()
    pe = PolicyEngine()

    if args.command == 'create':
        try:
            rules = json.loads(args.rules_json)
            ok = pe.create_policy(args.name, rules)
            print('Created' if ok else 'Failed')
            return 0 if ok else 1
        except json.JSONDecodeError as e:
            print(f'Invalid JSON: {e}')
            return 1

    if args.command == 'list':
        policies = pe.list_policies()
        print(json.dumps(policies, indent=2))
        return 0

    if args.command == 'test':
        try:
            test_case = json.loads(args.test_case_json)
            result = pe.test_policy(args.policy, args.test_name, test_case)
            print(json.dumps(result, indent=2))
            return 0 if result.get('status') == 'success' else 1
        except json.JSONDecodeError as e:
            print(f'Invalid JSON: {e}')
            return 1

    if args.command == 'results':
        results_list = pe.get_test_results(args.policy)
        print(json.dumps(results_list, indent=2))
        return 0

    parser.print_help()
    return 0

if __name__ == '__main__':
    sys.exit(main())
