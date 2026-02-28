#!/usr/bin/env python3
"""
Admin Configuration Manager
Manage policies, users, and system configuration
"""

import os
import sys
import json
import logging
import argparse
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('admin.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class AdminConfigManager:
    """Manage admin configuration, policies, and users"""
    
    def __init__(self, db_path: str = "admin.db", config_path: str = "admin_config.json"):
        self.db_path = Path(db_path)
        self.config_path = Path(config_path)
        self.init_database()
        self.load_config()
    
    def init_database(self):
        """Initialize admin database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Policies table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    policy_json TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    enabled BOOLEAN DEFAULT TRUE
                )
            ''')
            
            # Admin users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admin_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'admin',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_login DATETIME,
                    enabled BOOLEAN DEFAULT TRUE
                )
            ''')
            
            # Configuration table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admin_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    config_key TEXT UNIQUE NOT NULL,
                    config_value TEXT NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Admin database initialized")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
    
    def load_config(self):
        """Load admin configuration from JSON file"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
                logger.info(f"Loaded config from {self.config_path}")
            else:
                self.config = self._default_config()
                self.save_config()
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            self.config = self._default_config()
    
    def _default_config(self) -> Dict:
        """Get default configuration"""
        return {
            "server": {
                "host": "127.0.0.1",
                "port": 8080,
                "tls_enabled": False
            },
            "database": {
                "type": "sqlite",
                "path": "admin.db"
            },
            "logging": {
                "level": "INFO",
                "path": "logs/",
                "retention_days": 90
            },
            "policies": {
                "default_protection_level": "high",
                "quarantine_on_suspension": True,
                "alert_threshold": 60
            }
        }
    
    def save_config(self):
        """Save configuration to JSON file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info(f"Configuration saved to {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
    
    def create_policy(self, policy_name: str, policy_file: str = None, 
                     policy_json: str = None, description: str = None) -> bool:
        """Create a new protection policy"""
        try:
            # Load policy from file or string
            if policy_file and Path(policy_file).exists():
                with open(policy_file, 'r') as f:
                    policy_json = f.read()
            elif not policy_json:
                logger.error("No policy data provided")
                return False
            
            # Validate JSON
            try:
                json.loads(policy_json)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON policy: {e}")
                return False
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO policies 
                (policy_name, description, policy_json, updated_at)
                VALUES (?, ?, ?, datetime('now'))
            ''', (policy_name, description, policy_json))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Policy created: {policy_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create policy: {e}")
            return False
    
    def delete_policy(self, policy_name: str) -> bool:
        """Delete a policy"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM policies WHERE policy_name = ?', (policy_name,))
            
            if cursor.rowcount == 0:
                logger.warning(f"Policy not found: {policy_name}")
                conn.close()
                return False
            
            conn.commit()
            conn.close()
            
            logger.info(f"Policy deleted: {policy_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete policy: {e}")
            return False
    
    def list_policies(self) -> List[Dict]:
        """List all policies"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, policy_name, description, created_at, enabled
                FROM policies
                ORDER BY created_at DESC
            ''')
            
            columns = ['id', 'policy_name', 'description', 'created_at', 'enabled']
            policies = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return policies
        except Exception as e:
            logger.error(f"Failed to list policies: {e}")
            return []
    
    def get_policy(self, policy_name: str) -> Optional[Dict]:
        """Get a specific policy"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT policy_name, description, policy_json, created_at
                FROM policies
                WHERE policy_name = ?
            ''', (policy_name,))
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None
            
            return {
                'policy_name': row[0],
                'description': row[1],
                'policy_json': row[2],
                'created_at': row[3]
            }
        except Exception as e:
            logger.error(f"Failed to get policy: {e}")
            return None
    
    def archive_logs(self, archive_path: str = "log_archive/") -> bool:
        """Archive log files"""
        try:
            archive_dir = Path(archive_path)
            archive_dir.mkdir(parents=True, exist_ok=True)
            
            log_files = Path("logs/").glob("*.log") if Path("logs/").exists() else []
            
            archived = 0
            for log_file in log_files:
                if log_file.stat().st_size > 0:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    new_path = archive_dir / f"{log_file.stem}_{timestamp}.log"
                    log_file.rename(new_path)
                    archived += 1
            
            logger.info(f"Archived {archived} log file(s)")
            return True
        except Exception as e:
            logger.error(f"Failed to archive logs: {e}")
            return False
    
    def print_policies(self):
        """Print all policies"""
        policies = self.list_policies()
        
        if not policies:
            print("No policies configured.")
            return
        
        print("\n" + "="*100)
        print(f"{'ID':>3} {'POLICY NAME':<30} {'DESCRIPTION':<40} {'STATUS':<10}")
        print("="*100)
        
        for p in policies:
            status = "ENABLED" if p['enabled'] else "DISABLED"
            desc = (p['description'] or 'N/A')[:39]
            print(f"{p['id']:>3} {p['policy_name']:<30} {desc:<40} {status:<10}")
        
        print("="*100 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="Admin Configuration Manager"
    )
    parser.add_argument('--create-policy', metavar='NAME', help='Create a new policy')
    parser.add_argument('--policy-file', help='Path to policy JSON/YAML file')
    parser.add_argument('--policy-json', help='Inline policy JSON string')
    parser.add_argument('--description', help='Policy description')
    parser.add_argument('--delete-policy', metavar='NAME', help='Delete a policy')
    parser.add_argument('--list-policies', action='store_true', help='List all policies')
    parser.add_argument('--get-policy', metavar='NAME', help='Get a specific policy')
    parser.add_argument('--archive-logs', action='store_true', help='Archive log files')
    parser.add_argument('--config', default='admin_config.json', help='Config file path')
    parser.add_argument('--db', default='admin.db', help='Database file path')
    
    args = parser.parse_args()
    
    manager = AdminConfigManager(args.db, args.config)
    
    if args.create_policy:
        logger.info(f"Creating policy: {args.create_policy}")
        if manager.create_policy(args.create_policy, args.policy_file, 
                                args.policy_json, args.description):
            print(f"✓ Policy created: {args.create_policy}")
        else:
            print(f"✗ Failed to create policy")
            sys.exit(1)
    
    elif args.delete_policy:
        logger.info(f"Deleting policy: {args.delete_policy}")
        if manager.delete_policy(args.delete_policy):
            print(f"✓ Policy deleted: {args.delete_policy}")
        else:
            print(f"✗ Failed to delete policy")
            sys.exit(1)
    
    elif args.list_policies:
        manager.print_policies()
    
    elif args.get_policy:
        policy = manager.get_policy(args.get_policy)
        if policy:
            print("\nPolicy Details:")
            print("="*60)
            print(f"Name: {policy['policy_name']}")
            print(f"Description: {policy['description']}")
            print(f"Created: {policy['created_at']}")
            print(f"Policy:\n{policy['policy_json']}")
            print("="*60 + "\n")
        else:
            print(f"Policy not found: {args.get_policy}")
            sys.exit(1)
    
    elif args.archive_logs:
        logger.info("Archiving logs...")
        if manager.archive_logs():
            print("✓ Logs archived")
        else:
            print("✗ Failed to archive logs")
            sys.exit(1)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
