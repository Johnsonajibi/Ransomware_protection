#!/usr/bin/env python3
"""
Anti-Ransomware Admin Dashboard
gRPC server, SIEM integration, fleet management, and web interface
"""

import os
import sys
import json
import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import grpc
from concurrent import futures
import sqlite3
import threading
import yaml
import psutil

# Web framework
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import requests

# SIEM integration
try:
    import syslog
    SYSLOG_AVAILABLE = True
except ImportError:
    SYSLOG_AVAILABLE = False
from elasticsearch import Elasticsearch

# Import our modules
from policy_engine import PolicyEngine, Policy, PathRule, Quota, ProcessRule, TimeWindow
from ar_token import TokenVerifier, ARToken

# gRPC proto (optional; fallback stubs if not generated)
try:
    import admin_pb2
    import admin_pb2_grpc
    ADMIN_PROTO_AVAILABLE = True
except ImportError:
    ADMIN_PROTO_AVAILABLE = False

    class _ProtoObj:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    class admin_pb2:  # type: ignore
        DashboardStatsResponse = _ProtoObj
        Event = _ProtoObj
        GetEventsResponse = _ProtoObj
        UpdatePolicyResponse = _ProtoObj

    class admin_pb2_grpc:  # type: ignore
        class AdminServiceServicer:
            pass

        @staticmethod
        def add_AdminServiceServicer_to_server(*_args, **_kwargs):
            logging.warning("admin_pb2 not found; skipping gRPC servicer registration")

class User(UserMixin):
    def __init__(self, username: str, role: str = "admin"):
        self.id = username
        self.username = username
        self.role = role


class DatabaseManager:
    """SQLite database for storing events, tokens, and admin data"""

    def __init__(self, db_path: str = "admin.db"):
        self.db_path = db_path
        self.connection = None
        self.init_database()

    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'admin',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                file_path TEXT,
                process_id INTEGER,
                process_name TEXT,
                user_id TEXT,
                result TEXT,
                reason TEXT,
                token_id TEXT,
                host_id TEXT
            )
        ''')

        # Tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_id TEXT UNIQUE NOT NULL,
                file_path TEXT,
                process_id INTEGER,
                user_id TEXT,
                expiry DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                revoked BOOLEAN DEFAULT FALSE,
                host_id TEXT
            )
        ''')

        # Dongles table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dongles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_number TEXT UNIQUE NOT NULL,
                public_key TEXT,
                registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME,
                active BOOLEAN DEFAULT TRUE,
                user_id TEXT,
                host_id TEXT
            )
        ''')

        # Hosts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id TEXT UNIQUE NOT NULL,
                hostname TEXT,
                os_type TEXT,
                os_version TEXT,
                agent_version TEXT,
                last_checkin DATETIME,
                policy_version TEXT,
                status TEXT DEFAULT 'active'
            )
        ''')

        conn.commit()
        conn.close()

    def has_users(self) -> bool:
        """Return True if at least one user exists"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users')
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Fetch a user record by username"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password_hash, role FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return {
            'id': row[0],
            'username': row[1],
            'password_hash': row[2],
            'role': row[3],
        }

    def create_user(self, username: str, password: str, role: str = 'admin') -> None:
        """Create a new user with hashed password"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        password_hash = generate_password_hash(password)
        cursor.execute(
            'INSERT OR REPLACE INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            (username, password_hash, role)
        )
        conn.commit()
        conn.close()
    
    def log_event(self, event_type: str, file_path: str = None, process_id: int = None,
                  process_name: str = None, user_id: str = None, result: str = None,
                  reason: str = None, token_id: str = None, host_id: str = None):
        """Log an event to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO events (event_type, file_path, process_id, process_name, 
                               user_id, result, reason, token_id, host_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (event_type, file_path, process_id, process_name, user_id, result, reason, token_id, host_id))
        
        conn.commit()
        conn.close()
    
    def get_events(self, limit: int = 100, offset: int = 0, filter_type: str = None) -> List[Dict]:
        """Get events from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM events"
        params = []
        
        if filter_type:
            query += " WHERE event_type = ?"
            params.append(filter_type)
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        events = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        return events
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get dashboard statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total events today
        cursor.execute("SELECT COUNT(*) FROM events WHERE DATE(timestamp) = DATE('now')")
        stats['events_today'] = cursor.fetchone()[0]
        
        # Denied access attempts today
        cursor.execute("SELECT COUNT(*) FROM events WHERE result = 'denied' AND DATE(timestamp) = DATE('now')")
        stats['denied_today'] = cursor.fetchone()[0]
        
        # Active tokens
        cursor.execute("SELECT COUNT(*) FROM tokens WHERE expiry > datetime('now') AND revoked = FALSE")
        stats['active_tokens'] = cursor.fetchone()[0]
        
        # Active dongles
        cursor.execute("SELECT COUNT(*) FROM dongles WHERE active = TRUE")
        stats['active_dongles'] = cursor.fetchone()[0]
        
        # Active hosts
        cursor.execute("SELECT COUNT(*) FROM hosts WHERE status = 'active'")
        stats['active_hosts'] = cursor.fetchone()[0]
        
        conn.close()
        return stats

class SIEMIntegration:
    """SIEM integration for logging and alerting"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.elasticsearch_client = None
        self.setup_integrations()
    
    def setup_integrations(self):
        """Set up SIEM integrations"""
        # Elasticsearch
        if self.config.get('elasticsearch', {}).get('enabled', False):
            try:
                self.elasticsearch_client = Elasticsearch(
                    [self.config['elasticsearch']['url']],
                    http_auth=(
                        self.config['elasticsearch'].get('username'),
                        self.config['elasticsearch'].get('password')
                    )
                )
            except Exception as e:
                logging.error(f"Failed to connect to Elasticsearch: {e}")
        
        # Syslog
        if self.config.get('syslog', {}).get('enabled', False):
            if SYSLOG_AVAILABLE:
                syslog.openlog("anti-ransomware", syslog.LOG_PID, syslog.LOG_LOCAL0)
            else:
                logging.warning("Syslog enabled in config but not available on this platform")
    
    def send_event(self, event: Dict[str, Any]):
        """Send event to configured SIEM systems"""
        # Send to Elasticsearch
        if self.elasticsearch_client:
            try:
                self.elasticsearch_client.index(
                    index=f"anti-ransomware-{datetime.now().strftime('%Y-%m')}",
                    body=event
                )
            except Exception as e:
                logging.error(f"Failed to send event to Elasticsearch: {e}")
        
        # Send to syslog
        if self.config.get('syslog', {}).get('enabled', False) and SYSLOG_AVAILABLE:
            syslog_msg = f"Anti-Ransomware: {event.get('event_type', 'unknown')} - {event.get('result', 'unknown')}"
            syslog.syslog(syslog.LOG_INFO, syslog_msg)
        
        # Send webhook
        if self.config.get('webhook', {}).get('enabled', False):
            try:
                requests.post(
                    self.config['webhook']['url'],
                    json=event,
                    headers=self.config['webhook'].get('headers', {}),
                    timeout=10
                )
            except Exception as e:
                logging.error(f"Failed to send webhook: {e}")

class AdminService(admin_pb2_grpc.AdminServiceServicer):
    """gRPC admin service"""
    
    def __init__(self, db_manager: DatabaseManager, policy_engine: PolicyEngine, 
                 siem: SIEMIntegration):
        self.db = db_manager
        self.policy = policy_engine
        self.siem = siem
    
    def GetDashboardStats(self, request, context):
        """Get dashboard statistics"""
        try:
            stats = self.db.get_statistics()
            return admin_pb2.DashboardStatsResponse(
                events_today=stats['events_today'],
                denied_today=stats['denied_today'],
                active_tokens=stats['active_tokens'],
                active_dongles=stats['active_dongles'],
                active_hosts=stats['active_hosts']
            )
        except Exception as e:
            context.set_details(str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            return admin_pb2.DashboardStatsResponse()
    
    def GetEvents(self, request, context):
        """Get events with pagination"""
        try:
            events = self.db.get_events(
                limit=request.limit or 100,
                offset=request.offset or 0,
                filter_type=request.filter_type if request.filter_type else None
            )
            
            event_protos = []
            for event in events:
                event_proto = admin_pb2.Event(
                    id=event['id'],
                    timestamp=event['timestamp'],
                    event_type=event['event_type'],
                    file_path=event['file_path'] or '',
                    process_id=event['process_id'] or 0,
                    process_name=event['process_name'] or '',
                    user_id=event['user_id'] or '',
                    result=event['result'] or '',
                    reason=event['reason'] or '',
                    token_id=event['token_id'] or '',
                    host_id=event['host_id'] or ''
                )
                event_protos.append(event_proto)
            
            return admin_pb2.GetEventsResponse(events=event_protos)
            
        except Exception as e:
            context.set_details(str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            return admin_pb2.GetEventsResponse()
    
    def UpdatePolicy(self, request, context):
        """Update policy configuration"""
        try:
            # Accept YAML or JSON payloads from gRPC request
            policy_dict: Optional[Dict[str, Any]] = None
            if hasattr(request, 'policy_yaml') and request.policy_yaml:
                policy_dict = yaml.safe_load(request.policy_yaml)
            elif hasattr(request, 'policy_json') and request.policy_json:
                policy_dict = json.loads(request.policy_json)
            elif hasattr(request, 'policy') and request.policy:
                # If proto embeds structured policy
                policy_dict = json.loads(request.policy)
            else:
                raise ValueError("No policy data provided")

            # Parse and persist policy
            new_policy = self.policy._parse_policy(policy_dict)
            self.policy.policy = new_policy
            self.policy.save_policy()

            return admin_pb2.UpdatePolicyResponse(success=True, version=new_policy.version)
        except Exception as e:
            context.set_details(str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            return admin_pb2.UpdatePolicyResponse(success=False, error=str(e))

# Flask web application
def create_web_app(db_manager: DatabaseManager, policy_engine: PolicyEngine,
                   siem: SIEMIntegration, secret_key: str, cookie_secure: bool) -> Flask:
    """Create Flask web application"""
    
    app = Flask(__name__)
    app.secret_key = secret_key
    app.config.update(
        SESSION_COOKIE_SECURE=cookie_secure,
        REMEMBER_COOKIE_SECURE=cookie_secure,
        SESSION_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_HTTPONLY=True,
        SESSION_PROTECTION="strong",
    )
    
    # CSRF protection
    csrf = CSRFProtect()
    csrf.init_app(app)
    
    # Login manager
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    
    @login_manager.user_loader
    def load_user(username):
        user_record = db_manager.get_user(username)
        if not user_record:
            return None
        return User(user_record['username'], role=user_record.get('role', 'admin'))
    
    @app.route('/')
    @login_required
    def dashboard():
        """Main dashboard"""
        stats = db_manager.get_statistics()
        
        # Check PQC token status
        token_status = {'connected': False, 'serial': None, 'public_key': None, 'error': None}
        try:
            from pqcdualusb import PQCUSBAdapter
            adapter = PQCUSBAdapter()
            devices = adapter.detect()
            if devices:
                token_status['connected'] = True
                token_status['serial'] = devices[0].get('serial', 'Unknown')
                token_status['public_key'] = devices[0].get('public_key', 'Unknown')[:32] + '...'
        except Exception as e:
            token_status['error'] = str(e)
        
        recent_events = db_manager.get_events(limit=10)
        return render_template('dashboard.html', stats=stats, events=recent_events, token_status=token_status)
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Login page"""
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            user_record = db_manager.get_user(username)
            if not user_record or not check_password_hash(user_record['password_hash'], password):
                return render_template('login.html', error='Invalid credentials')

            user = User(user_record['username'], role=user_record.get('role', 'admin'))
            login_user(user)
            return redirect(url_for('dashboard'))
        
        return render_template('login.html')
    
    @app.route('/logout')
    @login_required
    def logout():
        """Logout"""
        logout_user()
        return redirect(url_for('login'))
    
    @app.route('/api/events')
    @login_required
    @csrf.exempt
    def api_events():
        """API endpoint for events"""
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        filter_type = request.args.get('type')
        
        events = db_manager.get_events(limit, offset, filter_type)
        return jsonify(events)
    
    @app.route('/api/stats')
    @login_required
    def api_stats():
        """API endpoint for statistics"""
        return jsonify(db_manager.get_statistics())
    
    @app.route('/api/policy', methods=['GET', 'POST'])
    @login_required
    def api_policy():
        """API endpoint for policy management"""
        if request.method == 'GET':
            return jsonify(policy_engine.get_policy_summary())
        
        elif request.method == 'POST':
            # Update policy
            policy_data = request.get_json(silent=True)
            if not policy_data:
                return jsonify({'success': False, 'error': 'No policy payload supplied'}), 400

            try:
                new_policy = policy_engine._parse_policy(policy_data)
                policy_engine.policy = new_policy
                policy_engine.save_policy()
                return jsonify({'success': True, 'version': new_policy.version})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/policy')
    @login_required
    def policy_page():
        """Policy management page"""
        summary = policy_engine.get_policy_summary()
        return render_template('policy.html', policy=summary)
    
    @app.route('/events')
    @login_required
    def events_page():
        """Events page"""
        return render_template('events.html')
    
    @app.route('/dongles')
    @login_required
    def dongles_page():
        """Dongles management page"""
        dongles = []
        try:
            # Enumerate removable devices using psutil; enhanced on Windows with drive type check
            partitions = psutil.disk_partitions(all=False)
            for p in partitions:
                is_removable = False
                if os.name == 'nt':
                    try:
                        import win32file
                        drive_type = win32file.GetDriveType(p.device)
                        is_removable = drive_type == win32file.DRIVE_REMOVABLE
                    except Exception:
                        is_removable = 'removable' in p.opts.lower()
                else:
                    is_removable = 'rw' in p.opts and ('nosuid' in p.opts or 'nodev' in p.opts)
                
                if is_removable:
                    dongles.append({
                        'device': p.device,
                        'mountpoint': p.mountpoint,
                        'fstype': p.fstype,
                        'opts': p.opts
                    })
        except Exception as e:
            logging.error(f"Failed to enumerate dongles: {e}")
        
        return render_template('dongles.html', dongles=dongles)

    @app.route('/paths')
    @login_required
    def paths_page():
        """Protected paths management page"""
        paths = []
        for rule in policy_engine.policy.rules:
            paths.append({
                'pattern': rule.path_pattern,
                'recursive': rule.recursive,
                'quota': f"{rule.quota.files_per_min} files/min, {rule.quota.bytes_per_min} bytes/min"
            })
        return render_template('paths.html', paths=paths)

    @app.route('/drivers')
    @login_required
    def drivers_page():
        """Kernel drivers and agents status page"""
        drivers_status = {
            'windows': {'available': False, 'loaded': False, 'service': None},
            'linux': {'available': False, 'running': False, 'service': None},
            'macos': {'available': False, 'running': False, 'service': None}
        }
        
        if os.name == 'nt':
            # Check Windows minifilter driver
            drivers_status['windows']['available'] = True
            try:
                import subprocess
                # Check if driver is loaded via fltmc
                result = subprocess.run(['fltmc', 'filters'], capture_output=True, text=True)
                drivers_status['windows']['loaded'] = 'RealAntiRansomware' in result.stdout
                
                # Check service status
                result = subprocess.run(['sc', 'query', 'RealAntiRansomware'], capture_output=True, text=True)
                if 'RUNNING' in result.stdout:
                    drivers_status['windows']['service'] = 'running'
                elif 'STOPPED' in result.stdout:
                    drivers_status['windows']['service'] = 'stopped'
            except Exception as e:
                logging.error(f"Failed to query Windows driver: {e}")
        
        elif os.uname().sysname == 'Linux':
            # Check Linux netlink broker service
            drivers_status['linux']['available'] = True
            try:
                import subprocess
                result = subprocess.run(['systemctl', 'is-active', 'linux_broker.service'], 
                                       capture_output=True, text=True)
                drivers_status['linux']['running'] = result.stdout.strip() == 'active'
                drivers_status['linux']['service'] = result.stdout.strip()
            except Exception as e:
                logging.error(f"Failed to query Linux broker: {e}")
        
        elif os.uname().sysname == 'Darwin':
            # Check macOS EndpointSecurity agent
            drivers_status['macos']['available'] = True
            try:
                import subprocess
                result = subprocess.run(['launchctl', 'list'], capture_output=True, text=True)
                drivers_status['macos']['running'] = 'com.real.antiransomware' in result.stdout
                drivers_status['macos']['service'] = 'loaded' if drivers_status['macos']['running'] else 'unloaded'
            except Exception as e:
                logging.error(f"Failed to query macOS agent: {e}")
        
        return render_template('drivers.html', drivers=drivers_status)

    @app.route('/api/paths', methods=['GET', 'POST', 'DELETE'])
    @login_required
    @csrf.exempt
    def api_paths():
        """API endpoint for protected paths management"""
        if request.method == 'GET':
            paths = []
            for rule in policy_engine.policy.rules:
                paths.append({
                    'pattern': rule.path_pattern,
                    'recursive': rule.recursive,
                    'quota_files': rule.quota.files_per_min,
                    'quota_bytes': rule.quota.bytes_per_min
                })
            return jsonify(paths)

        elif request.method == 'POST':
            # Add new protected path
            data = request.get_json()
            if not data or not data.get('pattern'):
                return jsonify({'success': False, 'error': 'Missing pattern'}), 400

            from policy_engine import PathRule, Quota
            new_rule = PathRule(
                path_pattern=data['pattern'],
                quota=Quota(
                    files_per_min=data.get('quota_files', 10),
                    bytes_per_min=data.get('quota_bytes', 1048576)
                ),
                process_rules=[],
                time_windows=[],
                recursive=data.get('recursive', True)
            )
            policy_engine.policy.rules.append(new_rule)
            policy_engine.save_policy()
            return jsonify({'success': True, 'pattern': new_rule.path_pattern})

        elif request.method == 'DELETE':
            # Remove protected path
            data = request.get_json()
            if not data or not data.get('pattern'):
                return jsonify({'success': False, 'error': 'Missing pattern'}), 400

            pattern = data['pattern']
            policy_engine.policy.rules = [r for r in policy_engine.policy.rules if r.path_pattern != pattern]
            policy_engine.save_policy()
            return jsonify({'success': True})
    
    return app

class AdminDashboard:
    """Main admin dashboard service"""
    
    def __init__(self, config_file: str = "admin_config.json"):
        self.config = self.load_config(config_file)
        self.db = DatabaseManager(self.config.get('database', {}).get('path', 'admin.db'))
        self.policy = PolicyEngine(self.config.get('policy', {}).get('file', 'policy.yaml'))
        self.siem = SIEMIntegration(self.config.get('siem', {}))

        # Secret key must be provided
        self.secret_key = self._resolve_secret(
            self.config.get('web', {}).get('secret_key'),
            self.config.get('web', {}).get('secret_key_env', 'ADMIN_SECRET_KEY'),
            'flask secret key'
        )

        # Bootstrap initial admin user if none exists
        self.bootstrap_initial_user()

        # Cookie security defaults to True when TLS is enabled/required
        tls_required = self.config.get('web', {}).get('tls', {}).get('require', False)
        self.cookie_secure = self.config.get('web', {}).get('cookie_secure', tls_required)
        
        # gRPC server
        self.grpc_server = None
        self.web_app = create_web_app(
            self.db,
            self.policy,
            self.siem,
            self.secret_key,
            self.cookie_secure,
        )
    
    def load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Create default config
            default_config = {
                'database': {'path': 'admin.db'},
                'policy': {'file': 'policy.yaml'},
                'auth': {
                    'username_env': 'ADMIN_USERNAME',
                    'password_env': 'ADMIN_PASSWORD'
                },
                'grpc': {
                    'port': 50052,
                    'tls': {
                        'cert': '',
                        'key': '',
                        'require': False
                    }
                },
                'web': {
                    'port': 8080,
                    'host': '127.0.0.1',
                    'secret_key_env': 'ADMIN_SECRET_KEY',
                    'cookie_secure': False,
                    'tls': {
                        'cert': '',
                        'key': '',
                        'require': False
                    }
                },
                'siem': {
                    'elasticsearch': {'enabled': False, 'url': 'http://localhost:9200'},
                    'syslog': {'enabled': True},
                    'webhook': {'enabled': False, 'url': ''}
                }
            }
            
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            return default_config

    def _get_config_or_env(self, value: Optional[str], env_key: Optional[str]) -> Optional[str]:
        """Fetch from env if set, else return provided value."""
        env_val = os.environ.get(env_key) if env_key else None
        return env_val or value

    def _resolve_secret(self, value: Optional[str], env_key: Optional[str], label: str, allow_empty: bool = False) -> str:
        """Resolve secret values from env first, then config; fail closed if missing unless allow_empty."""
        resolved = self._get_config_or_env(value, env_key)
        if not resolved and not allow_empty:
            raise ValueError(f"Missing required {label}; set {env_key} or provide in config")
        return resolved or ""

    def bootstrap_initial_user(self):
        """Create the first admin user from env/config if none exist."""
        if self.db.has_users():
            return

        auth_cfg = self.config.get('auth', {})
        username = self._get_config_or_env(auth_cfg.get('username'), auth_cfg.get('username_env', 'ADMIN_USERNAME'))
        password = self._get_config_or_env(auth_cfg.get('password'), auth_cfg.get('password_env', 'ADMIN_PASSWORD'))

        if not username or not password:
            raise ValueError("No users exist. Set ADMIN_USERNAME/ADMIN_PASSWORD or populate auth.username/password in admin_config.json to bootstrap the first admin user.")

        self.db.create_user(username, password, role='admin')
        logging.info("Bootstrapped initial admin user")
    
    def start_grpc_server(self):
        """Start gRPC server"""
        if not ADMIN_PROTO_AVAILABLE:
            logging.warning("Admin proto not available; gRPC server not started")
            return

        self.grpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        admin_pb2_grpc.add_AdminServiceServicer_to_server(
            AdminService(self.db, self.policy, self.siem),
            self.grpc_server
        )
        
        port = self.config.get('grpc', {}).get('port', 50052)
        listen_addr = f'[::]:{port}'
        tls_cfg = self.config.get('grpc', {}).get('tls', {})
        cert_path = tls_cfg.get('cert')
        key_path = tls_cfg.get('key')
        require_tls = tls_cfg.get('require', False)

        if cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path):
            with open(key_path, 'rb') as kf, open(cert_path, 'rb') as cf:
                creds = grpc.ssl_server_credentials(((kf.read(), cf.read()),))
            self.grpc_server.add_secure_port(listen_addr, creds)
            logging.info(f"Admin gRPC server started with TLS on {listen_addr}")
        else:
            if require_tls:
                raise RuntimeError("gRPC TLS required but cert/key not provided")
            self.grpc_server.add_insecure_port(listen_addr)
            logging.warning("Admin gRPC server started WITHOUT TLS")

        self.grpc_server.start()
    
    def start_web_server(self):
        """Start web server"""
        host = self.config.get('web', {}).get('host', '127.0.0.1')
        port = self.config.get('web', {}).get('port', 8080)
        tls_cfg = self.config.get('web', {}).get('tls', {})
        cert_path = tls_cfg.get('cert')
        key_path = tls_cfg.get('key')
        require_tls = tls_cfg.get('require', False)
        ssl_context = None

        if cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path):
            ssl_context = (cert_path, key_path)
            logging.info("Admin web server TLS enabled")
        elif require_tls:
            raise RuntimeError("Web TLS required but cert/key not provided")
        
        logging.info(f"Admin web server starting on {host}:{port}")
        self.web_app.run(host=host, port=port, debug=False, ssl_context=ssl_context)
    
    def start(self):
        """Start admin dashboard"""
        logging.info("Starting Anti-Ransomware Admin Dashboard")
        
        # Start gRPC server in background
        grpc_thread = threading.Thread(target=self.start_grpc_server)
        grpc_thread.daemon = True
        grpc_thread.start()
        
        # Start web server (blocking)
        self.start_web_server()
    
    def stop(self):
        """Stop admin dashboard"""
        if self.grpc_server:
            self.grpc_server.stop(0)

def setup_logging():
    """Set up logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('admin.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )


def create_wsgi_app():
    """Factory for WSGI servers (waitress, gunicorn, etc.)."""
    setup_logging()
    dashboard = AdminDashboard()
    # Note: gRPC remains disabled when protos are missing; web app is returned for WSGI hosting.
    return dashboard.web_app

if __name__ == "__main__":
    setup_logging()
    
    dashboard = AdminDashboard()
    
    try:
        dashboard.start()
    except KeyboardInterrupt:
        logging.info("Shutting down admin dashboard...")
        dashboard.stop()
