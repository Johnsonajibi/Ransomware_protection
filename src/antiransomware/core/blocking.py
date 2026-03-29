#!/usr/bin/env python3
"""
Blocking Protection
Block and unblock suspicious processes and executables
"""

import os
import sys
import json
import logging
import argparse
import subprocess
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('blocking.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class ProcessBlocker:
    """Block and manage process execution"""
    
    def __init__(self, db_path: str = "admin.db"):
        self.db_path = Path(db_path)
        self.init_database()
    
    def init_database(self):
        """Initialize blocking database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_processes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    process_name TEXT UNIQUE NOT NULL,
                    process_hash TEXT,
                    block_reason TEXT,
                    action TEXT DEFAULT 'block',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    blocked_by TEXT,
                    active BOOLEAN DEFAULT TRUE
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS block_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    process_name TEXT,
                    process_id INTEGER,
                    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    action_taken TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database init failed: {e}")
    
    def block_process(self, process_name: str, reason: str = None, 
                     action: str = 'block') -> bool:
        """Block a process from execution"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            reason = reason or 'Manual blocking'
            
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_processes 
                (process_name, block_reason, action, active)
                VALUES (?, ?, ?, 1)
            ''', (process_name, reason, action))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Blocked process: {process_name} ({reason})")
            return True
        except Exception as e:
            logger.error(f"Process blocking failed: {e}")
            return False
    
    def unblock_process(self, process_name: str) -> bool:
        """Unblock a previously blocked process"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                'UPDATE blocked_processes SET active = 0 WHERE process_name = ?',
                (process_name,)
            )
            
            if cursor.rowcount == 0:
                logger.warning(f"Process not found in block list: {process_name}")
                conn.close()
                return False
            
            conn.commit()
            conn.close()
            
            logger.info(f"Unblocked process: {process_name}")
            return True
        except Exception as e:
            logger.error(f"Process unblocking failed: {e}")
            return False
    
    def kill_process(self, process_name: str) -> Tuple[bool, str]:
        """Forcefully terminate a running process"""
        try:
            result = subprocess.run(
                ['taskkill', '/IM', process_name, '/F'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                logger.info(f"Killed process: {process_name}")
                return True, "Process terminated"
            else:
                msg = result.stderr or "Process not found"
                logger.warning(f"Failed to kill {process_name}: {msg}")
                return False, msg
        except Exception as e:
            logger.error(f"Process kill failed: {e}")
            return False, str(e)
    
    def is_blocked(self, process_name: str) -> bool:
        """Check if a process is blocked"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT active FROM blocked_processes WHERE process_name = ?',
                (process_name,)
            )
            
            row = cursor.fetchone()
            conn.close()
            
            return row and row[0]
        except Exception:
            return False
    
    def list_blocked_processes(self) -> List[Dict]:
        """List all blocked processes"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT process_name, block_reason, action, created_at 
                FROM blocked_processes WHERE active = 1
                ORDER BY created_at DESC
            ''')
            
            columns = ['process_name', 'block_reason', 'action', 'created_at']
            processes = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return processes
        except Exception as e:
            logger.error(f"Listing failed: {e}")
            return []
    
    def log_block_event(self, process_name: str, process_id: int = None, 
                       action: str = 'blocked') -> bool:
        """Log a block event"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO block_events (process_name, process_id, action_taken)
                VALUES (?, ?, ?)
            ''', (process_name, process_id, action))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Event logging failed: {e}")
            return False
    
    def get_block_statistics(self) -> Dict:
        """Get blocking statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM blocked_processes WHERE active = 1')
            total_blocked = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT COUNT(*) FROM block_events 
                WHERE attempted_at > datetime('now', '-24 hours')
            ''')
            blocked_24h = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_blocked_processes': total_blocked,
                'block_events_24h': blocked_24h
            }
        except Exception as e:
            logger.error(f"Statistics failed: {e}")
            return {}
    
    def print_blocked_processes(self, processes: List[Dict]):
        """Print blocked processes in table format"""
        if not processes:
            print("No blocked processes.")
            return
        
        print("\n" + "="*100)
        print(f"{'PROCESS':<30} {'REASON':<40} {'ACTION':<10} {'CREATED':<20}")
        print("="*100)
        
        for proc in processes:
            created = proc['created_at'].split(' ')[0] if proc['created_at'] else 'N/A'
            reason = proc['block_reason'][:38] if proc['block_reason'] else 'N/A'
            print(f"{proc['process_name']:<30} {reason:<40} {proc['action']:<10} {created:<20}")
        
        print("="*100 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Blocking Protection")
    parser.add_argument('--process', metavar='EXE', help='Process name to manage')
    parser.add_argument('--action', choices=['block', 'unblock', 'kill'], 
                       help='Action to perform')
    parser.add_argument('--reason', help='Reason for blocking')
    parser.add_argument('--list', action='store_true', help='List blocked processes')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--db', default='admin.db', help='Database path')
    
    args = parser.parse_args()
    
    blocker = ProcessBlocker(args.db)
    
    if args.list:
        processes = blocker.list_blocked_processes()
        blocker.print_blocked_processes(processes)
    
    elif args.stats:
        stats = blocker.get_block_statistics()
        print("\nBlocking Statistics:")
        print("="*60)
        for key, value in stats.items():
            print(f"{key}: {value}")
        print("="*60 + "\n")
    
    elif args.process and args.action:
        if args.action == 'block':
            if blocker.block_process(args.process, args.reason):
                print(f"Blocked: {args.process}")
                blocker.log_block_event(args.process, action='blocked')
            else:
                print(f"Failed to block: {args.process}")
                return 1
        
        elif args.action == 'unblock':
            if blocker.unblock_process(args.process):
                print(f"Unblocked: {args.process}")
                blocker.log_block_event(args.process, action='unblocked')
            else:
                print(f"Failed to unblock: {args.process}")
                return 1
        
        elif args.action == 'kill':
            success, msg = blocker.kill_process(args.process)
            if success:
                print(f"Killed: {args.process}")
                blocker.log_block_event(args.process, action='killed')
            else:
                print(f"Failed to kill: {msg}")
                return 1
    
    else:
        parser.print_help()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
