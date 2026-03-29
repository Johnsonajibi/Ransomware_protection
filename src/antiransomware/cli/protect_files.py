#!/usr/bin/env python3
"""
Add Files to Protected Paths
Manages which paths/folders are protected by the anti-ransomware system
"""

import os
import sys
import json
import logging
import argparse
import sqlite3
from pathlib import Path
from typing import List, Dict, Optional

from antiransomware.core.engine import ProtectionEngine

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('protected_paths.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class ProtectedPathManager:
    """Manage protected file paths and folders"""
    
    def __init__(self, db_path: str = "protection_db.sqlite", config_path: str = "config.yaml"):
        self.db_path = Path(db_path)
        self.config_path = Path(config_path)
        self.engine = ProtectionEngine(str(self.db_path))
        self.init_database()
        self.load_protected_paths()
    
    def init_database(self):
        """Initialize protected paths database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS protected_paths (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT UNIQUE NOT NULL,
                    protection_level TEXT DEFAULT 'high',
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    description TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database ready")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
    
    def load_protected_paths(self) -> List[Dict]:
        """Load all protected paths from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, path, protection_level, enabled, created_at, description
                FROM protected_paths
                ORDER BY created_at DESC
            ''')
            
            columns = ['id', 'path', 'protection_level', 'enabled', 'created_at', 'description']
            paths = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return paths
        except Exception as e:
            logger.error(f"Failed to load protected paths: {e}")
            return []
    
    def add_protected_path(self, path: str, protection_level: str = 'high', 
                          description: str = None) -> bool:
        """Add a path to protection"""
        try:
            path = str(Path(path).absolute())
            self.engine.protect_path(path, protection_level, description)
            logger.info(f"Added protected path: {path} (level: {protection_level})")
            return True
        except sqlite3.IntegrityError:
            logger.warning(f"Path already protected: {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to add protected path: {e}")
            return False
    
    def remove_protected_path(self, path: str) -> bool:
        """Remove a path from protection"""
        try:
            path = str(Path(path).absolute())
            if not self.engine.unprotect_path(path):
                logger.warning(f"Path not found in protection: {path}")
                return False
            logger.info(f"Removed protected path: {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove protected path: {e}")
            return False
    
    def set_protection_level(self, path: str, level: str) -> bool:
        """Set protection level for a path (high/medium/low/custom)"""
        try:
            path = str(Path(path).absolute())
            
            if level not in ['high', 'medium', 'low', 'custom']:
                logger.error(f"Invalid protection level: {level}")
                return False
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                'UPDATE protected_paths SET protection_level = ? WHERE path = ?',
                (level, path)
            )
            
            if cursor.rowcount == 0:
                logger.error(f"Path not found: {path}")
                conn.close()
                return False
            
            conn.commit()
            conn.close()
            
            logger.info(f"Set protection level for {path} to {level}")
            return True
        except Exception as e:
            logger.error(f"Failed to set protection level: {e}")
            return False
    
    def enable_path(self, path: str) -> bool:
        """Enable protection for a path"""
        try:
            path = str(Path(path).absolute())
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('UPDATE protected_paths SET enabled = 1 WHERE path = ?', (path,))
            updated = cursor.rowcount > 0
            conn.commit()
            conn.close()
            if not updated:
                logger.error(f"Path not found: {path}")
                return False
            self.engine.log_event('path_enabled', severity='info', file_path=path, action='enable')
            logger.info(f"Enabled protection for: {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to enable protection: {e}")
            return False
    
    def disable_path(self, path: str) -> bool:
        """Disable protection for a path"""
        try:
            path = str(Path(path).absolute())
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('UPDATE protected_paths SET enabled = 0 WHERE path = ?', (path,))
            updated = cursor.rowcount > 0
            conn.commit()
            conn.close()
            if not updated:
                logger.error(f"Path not found: {path}")
                return False
            self.engine.log_event('path_disabled', severity='warning', file_path=path, action='disable')
            logger.info(f"Disabled protection for: {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to disable protection: {e}")
            return False
    
    def list_protected_paths(self, enabled_only: bool = False):
        """List all protected paths"""
        paths = self.load_protected_paths()
        
        if not paths:
            print("No protected paths configured.")
            return
        
        print("\n" + "="*100)
        print(f"{'ID':>3} {'PATH':<50} {'LEVEL':<10} {'STATUS':<10} {'CREATED':<20}")
        print("="*100)
        
        for p in paths:
            if enabled_only and not p['enabled']:
                continue
            
            status = "ENABLED" if p['enabled'] else "DISABLED"
            created = p['created_at'].split(' ')[0] if p['created_at'] else 'N/A'
            
            print(f"{p['id']:>3} {p['path']:<50} {p['protection_level']:<10} {status:<10} {created:<20}")
        
        print("="*100 + "\n")
    
    def load_from_config(self) -> bool:
        """Load protected paths from config.yaml if available"""
        try:
            import yaml
            
            if not self.config_path.exists():
                logger.warning(f"Config file not found: {self.config_path}")
                return False
            
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
            
            protection_config = config.get('protection', {})
            paths = protection_config.get('paths', [])
            
            if not paths:
                logger.info("No paths found in config")
                return False
            
            added = 0
            for path_entry in paths:
                if isinstance(path_entry, str):
                    if self.add_protected_path(path_entry):
                        added += 1
                elif isinstance(path_entry, dict):
                    if self.add_protected_path(
                        path_entry.get('path'),
                        protection_level=path_entry.get('level', 'high'),
                        description=path_entry.get('description')
                    ):
                        added += 1
            
            logger.info(f"Loaded {added} protected path(s) from config")
            return added > 0
        except Exception as e:
            logger.error(f"Failed to load from config: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(
        description="Manage Protected Paths"
    )
    parser.add_argument('--path', help='File path to protect/unprotect')
    parser.add_argument('--protect', action='store_true', help='Add path to protection')
    parser.add_argument('--unprotect', action='store_true', help='Remove path from protection')
    parser.add_argument('--level', default='high', help='Protection level (high/medium/low/custom)')
    parser.add_argument('--list', action='store_true', help='List all protected paths')
    parser.add_argument('--enable', metavar='PATH', help='Enable protection for path')
    parser.add_argument('--disable', metavar='PATH', help='Disable protection for path')
    parser.add_argument('--load-config', action='store_true', help='Load paths from config.yaml')
    parser.add_argument('--config', default='config.yaml', help='Config file path')
    parser.add_argument('--db', default='protection_db.sqlite', help='Database file path')
    
    args = parser.parse_args()
    
    manager = ProtectedPathManager(args.db, args.config)
    
    if args.protect and args.path:
        logger.info(f"Protecting path: {args.path} (level: {args.level})")
        if manager.add_protected_path(args.path, args.level):
            print(f"✓ Path protected: {args.path}")
        else:
            print(f"✗ Failed to protect path: {args.path}")
            sys.exit(1)
    
    elif args.unprotect and args.path:
        logger.info(f"Unprotecting path: {args.path}")
        if manager.remove_protected_path(args.path):
            print(f"✓ Path unprotected: {args.path}")
        else:
            print(f"✗ Failed to unprotect path: {args.path}")
            sys.exit(1)
    
    elif args.enable:
        if manager.enable_path(args.enable):
            print(f"✓ Protection enabled: {args.enable}")
        else:
            print(f"✗ Failed to enable protection: {args.enable}")
            sys.exit(1)
    
    elif args.disable:
        if manager.disable_path(args.disable):
            print(f"✓ Protection disabled: {args.disable}")
        else:
            print(f"✗ Failed to disable protection: {args.disable}")
            sys.exit(1)
    
    elif args.load_config:
        manager.load_from_config()
        manager.list_protected_paths()
    
    elif args.list:
        manager.list_protected_paths()
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
