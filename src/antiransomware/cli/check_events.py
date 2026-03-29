#!/usr/bin/env python3
"""
Check Security Events
Monitor and analyze security events, threats, and protection status
"""

import os
import sys
import json
import logging
import argparse
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from antiransomware.core.engine import ProtectionEngine

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_events.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class SecurityEventAnalyzer:
    """Analyze security events and system status"""
    
    def __init__(self, db_path: str = "protection_db.sqlite"):
        self.db_path = Path(db_path)
        self.engine = ProtectionEngine(str(self.db_path))
        self.init_database()
    
    def init_database(self):
        """Initialize security events database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Security events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    file_path TEXT,
                    process_id INTEGER,
                    process_name TEXT,
                    user_id TEXT,
                    action TEXT,
                    threat_score REAL,
                    details TEXT
                )
            ''')
            
            # Threat intelligence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_hash TEXT UNIQUE NOT NULL,
                    threat_name TEXT,
                    severity TEXT,
                    description TEXT,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # System status table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    component TEXT UNIQUE NOT NULL,
                    status TEXT DEFAULT 'unknown',
                    last_check DATETIME DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Security events database initialized")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
    
    def get_events(self, limit: int = 50, since: str = None, 
                   severity_filter: str = None) -> List[Dict]:
        """Get security events with filtering"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = "SELECT * FROM security_events WHERE 1=1"
            params = []
            
            if since:
                # Parse time string like "1h", "30m", "1d"
                if since.endswith('h'):
                    hours = int(since[:-1])
                    since_dt = datetime.now() - timedelta(hours=hours)
                elif since.endswith('m'):
                    minutes = int(since[:-1])
                    since_dt = datetime.now() - timedelta(minutes=minutes)
                elif since.endswith('d'):
                    days = int(since[:-1])
                    since_dt = datetime.now() - timedelta(days=days)
                else:
                    since_dt = datetime.fromisoformat(since)
                
                query += " AND timestamp >= ?"
                params.append(since_dt.isoformat())
            
            if severity_filter:
                query += " AND severity = ?"
                params.append(severity_filter.lower())
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            columns = [desc[0] for desc in cursor.description]
            events = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return events
        except Exception as e:
            logger.error(f"Failed to get events: {e}")
            return []
    
    def log_security_event(self, event_type: str, severity: str = 'medium',
                          file_path: str = None, process_id: int = None,
                          process_name: str = None, user_id: str = None,
                          action: str = None, threat_score: float = 0,
                          details: str = None) -> bool:
        """Log a security event"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO security_events
                (event_type, severity, file_path, process_id, process_name, 
                 user_id, action, threat_score, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (event_type, severity, file_path, process_id, process_name,
                  user_id, action, threat_score, details))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Security event logged: {event_type} ({severity})")
            return True
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
            return False
    
    def get_threat_status(self) -> Dict:
        """Get overall threat status"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Critical threats in last hour
            cursor.execute('''
                SELECT COUNT(*) FROM security_events
                WHERE severity = 'critical'
                AND timestamp > datetime('now', '-1 hour')
            ''')
            critical_count = cursor.fetchone()[0]
            
            # High severity threats today
            cursor.execute('''
                SELECT COUNT(*) FROM security_events
                WHERE severity = 'high'
                AND DATE(timestamp) = DATE('now')
            ''')
            high_count = cursor.fetchone()[0]
            
            # Average threat score
            cursor.execute('''
                SELECT AVG(threat_score) FROM security_events
                WHERE DATE(timestamp) = DATE('now')
            ''')
            avg_threat = cursor.fetchone()[0] or 0
            
            # Total events today
            cursor.execute('''
                SELECT COUNT(*) FROM security_events
                WHERE DATE(timestamp) = DATE('now')
            ''')
            total_today = cursor.fetchone()[0]
            
            conn.close()
            
            # Determine overall status
            if critical_count > 0:
                status = "CRITICAL"
            elif high_count > 2:
                status = "HIGH ALERT"
            elif avg_threat > 70:
                status = "ELEVATED"
            else:
                status = "NORMAL"
            
            return {
                'status': status,
                'critical_threats': critical_count,
                'high_threats': high_count,
                'avg_threat_score': round(avg_threat, 2),
                'total_events_today': total_today
            }
        except Exception as e:
            logger.error(f"Failed to get threat status: {e}")
            return {'status': 'UNKNOWN', 'error': str(e)}
    
    def get_protection_status(self) -> Dict:
        """Get protection component status"""
        try:
            component_state = self.engine.get_component_status()
            status_rows = [
                {
                    'component': component,
                    'status': 'operational' if enabled else 'disabled',
                    'details': '',
                    'last_check': datetime.now().isoformat(),
                }
                for component, enabled in component_state.items()
            ]
            if not status_rows:
                return {'status': 'unknown', 'components': []}
            
            return {
                'status': 'operational' if all(s['status'] == 'operational' for s in status_rows) else 'degraded',
                'components': status_rows
            }
        except Exception as e:
            logger.error(f"Failed to get protection status: {e}")
            return {'status': 'unknown', 'error': str(e)}
    
    def print_security_status(self):
        """Print detailed security and protection status"""
        threat_status = self.get_threat_status()
        prot_status = self.get_protection_status()
        
        print("\n" + "="*80)
        print("SECURITY & PROTECTION STATUS")
        print("="*80)
        
        print(f"\nThreat Status: {threat_status['status']}")
        print(f"  Critical Threats (last 1h): {threat_status['critical_threats']}")
        print(f"  High Severity Threats (today): {threat_status['high_threats']}")
        print(f"  Average Threat Score: {threat_status['avg_threat_score']}")
        print(f"  Total Events (today): {threat_status['total_events_today']}")
        
        print(f"\nProtection Status: {prot_status['status']}")
        if 'components' in prot_status and prot_status['components']:
            for comp in prot_status['components']:
                status_icon = "✓" if comp['status'] == 'operational' else "✗"
                print(f"  {status_icon} {comp['component']:.<30} {comp['status']:.<15} [{comp['last_check']}]")
        
        print("="*80 + "\n")
    
    def print_recent_events(self, limit: int = 20, since: str = None):
        """Print recent security events"""
        events = self.get_events(limit=limit, since=since)
        
        if not events:
            print("No security events found.")
            return
        
        print("\n" + "="*120)
        print(f"{'TIMESTAMP':<20} {'TYPE':<15} {'SEVERITY':<10} {'ACTION':<15} {'PROCESS':<30} {'THREAT SCORE':<12}")
        print("="*120)
        
        for event in events:
            ts = event['timestamp'].split('.')[0] if event['timestamp'] else 'N/A'
            proc = event['process_name'] or f"[{event['process_id']}]" if event['process_id'] else 'N/A'
            print(f"{ts:<20} {event['event_type']:<15} {event['severity']:<10} {event['action']:<15} {proc:<30} {event['threat_score']:<12.1f}")
        
        print("="*120 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="Check Security Events"
    )
    parser.add_argument('--status', action='store_true', help='Show protection status')
    parser.add_argument('--events', action='store_true', help='Show recent events')
    parser.add_argument('--since', metavar='TIME', help='Events since time (e.g., 1h, 30m, 1d)')
    parser.add_argument('--severity', metavar='LEVEL', help='Filter by severity (critical/high/medium/low)')
    parser.add_argument('--limit', type=int, default=20, help='Limit number of events')
    parser.add_argument('--log-event', action='store_true', help='Log a test event')
    parser.add_argument('--db', default='protection_db.sqlite', help='Database file path')
    
    args = parser.parse_args()
    
    analyzer = SecurityEventAnalyzer(args.db)
    
    if args.status:
        analyzer.print_security_status()
    
    elif args.events:
        analyzer.print_recent_events(limit=args.limit, since=args.since)
    
    elif args.log_event:
        logger.info("Logging test security event...")
        if analyzer.log_security_event(
            event_type="TEST_SECURITY_EVENT",
            severity="medium",
            file_path="C:\\test_file.txt",
            process_id=1234,
            process_name="test_process.exe",
            action="blocked",
            threat_score=45.5,
            details="Test security event for validation"
        ):
            logger.info("✓ Test event logged")
        else:
            logger.error("✗ Failed to log test event")
            sys.exit(1)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
