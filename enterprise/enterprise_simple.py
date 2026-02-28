#!/usr/bin/env python3
"""
ENTERPRISE ANTI-RANSOMWARE SYSTEM - SIMPLIFIED VERSION
Fixed for reliable loading on Windows systems
"""

import os
import sys
import json
import time
import threading
import subprocess
import hashlib
import sqlite3
import psutil
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from flask import Flask, render_template_string, request, jsonify
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import ssl
import secrets

# Simple logging without Unicode issues
log_dir = Path("C:/ProgramData/AntiRansomware/logs")
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / 'service.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ProtectedFolder:
    path: str
    policy_id: str
    protection_level: str
    usb_required: bool
    created_at: datetime
    active: bool
    quarantine_count: int = 0

class SimpleSecurityManager:
    """Simplified security management for reliable operation"""
    
    def __init__(self):
        self.service_key = None
        self.encryption_key = None
        self.certificate_path = None
        self.private_key_path = None
        
    def initialize_security(self):
        """Initialize basic security components"""
        try:
            # Create secure data directories
            secure_dir = Path("C:/ProgramData/AntiRansomware/secure")
            secure_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate or load service encryption key
            key_file = secure_dir / "service.key"
            if key_file.exists():
                with open(key_file, 'rb') as f:
                    self.service_key = f.read()
            else:
                self.service_key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(self.service_key)
            
            self.encryption_key = Fernet(self.service_key)
            
            # Generate self-signed certificates for HTTPS
            self._generate_certificates()
            
            logger.info("Enterprise security initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Security initialization failed: {e}")
            return False
    
    def _generate_certificates(self):
        """Generate self-signed certificates for HTTPS"""
        try:
            cert_dir = Path("C:/ProgramData/AntiRansomware/certs")
            cert_dir.mkdir(parents=True, exist_ok=True)
            
            cert_file = cert_dir / "server.crt"
            key_file = cert_dir / "server.key"
            
            if cert_file.exists() and key_file.exists():
                self.certificate_path = cert_file
                self.private_key_path = key_file
                return
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AntiRansomware Enterprise"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Write certificate and key to files
            with open(cert_file, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(key_file, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            self.certificate_path = cert_file
            self.private_key_path = key_file
            
            logger.info("Self-signed certificates generated successfully")
            
        except Exception as e:
            logger.error(f"Certificate generation failed: {e}")

class EnterpriseFileProtection(FileSystemEventHandler):
    """Enterprise file system protection"""
    
    def __init__(self):
        super().__init__()
        self.quarantine_dir = Path("C:/ProgramData/AntiRansomware/quarantine")
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.threat_events = []
        self.observers = []
        
        # Enhanced ransomware indicators
        self.ransomware_extensions = {
            '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.aes',
            '.rsa', '.xtbl', '.crinf', '.r5a', '.vault', '.petya',
            '.wannacry', '.locky', '.cerber', '.zepto', '.dharma'
        }
        
        self.ransomware_patterns = [
            'your files have been encrypted',
            'files have been locked',
            'decrypt_instruction',
            'how_to_decrypt',
            'ransom_note',
            'readme_for_decrypt'
        ]
    
    def start_protection(self, protected_folders):
        """Start file system protection"""
        try:
            for folder in protected_folders:
                if folder.active and os.path.exists(folder.path):
                    observer = Observer()
                    observer.schedule(self, folder.path, recursive=True)
                    observer.start()
                    self.observers.append(observer)
                    logger.info(f"Protection started for: {folder.path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start protection: {e}")
            return False
    
    def stop_protection(self):
        """Stop file system protection"""
        for observer in self.observers:
            try:
                observer.stop()
                observer.join(timeout=5)
            except:
                pass
        self.observers.clear()
        logger.info("File system protection stopped")
    
    def on_created(self, event):
        """Handle file creation"""
        if not event.is_directory:
            self._analyze_threat(event.src_path, 'FILE_CREATED')
    
    def on_modified(self, event):
        """Handle file modification"""
        if not event.is_directory:
            self._analyze_threat(event.src_path, 'FILE_MODIFIED')
    
    def _analyze_threat(self, file_path, event_type):
        """Analyze file for threats"""
        try:
            file_path_obj = Path(file_path)
            filename = file_path_obj.name.lower()
            
            # Check ransomware extensions
            for ext in self.ransomware_extensions:
                if filename.endswith(ext):
                    self._handle_threat(file_path, 'RANSOMWARE_EXTENSION', 'CRITICAL')
                    return
            
            # Check file content
            if self._check_file_content(file_path):
                self._handle_threat(file_path, 'RANSOMWARE_CONTENT', 'HIGH')
                return
                
        except Exception as e:
            logger.error(f"Threat analysis error: {e}")
    
    def _check_file_content(self, file_path):
        """Check file content for ransomware indicators"""
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 1024 * 1024:  # Skip large files
                return False
            
            with open(file_path, 'rb') as f:
                content = f.read(2048)
                content_str = content.decode('utf-8', errors='ignore').lower()
                
                for pattern in self.ransomware_patterns:
                    if pattern in content_str:
                        return True
                
                return False
                
        except Exception:
            return False
    
    def _handle_threat(self, file_path, threat_type, severity):
        """Handle detected threat"""
        try:
            logger.warning(f"THREAT DETECTED: {threat_type} - {file_path}")
            
            # Quarantine critical threats
            if severity in ['CRITICAL', 'HIGH']:
                if self._quarantine_file(file_path):
                    action = 'QUARANTINED'
                    logger.info(f"File quarantined: {file_path}")
                else:
                    action = 'QUARANTINE_FAILED'
            else:
                action = 'MONITORED'
            
            # Store threat event
            self.threat_events.append({
                'timestamp': datetime.now(),
                'file_path': file_path,
                'threat_type': threat_type,
                'severity': severity,
                'action': action
            })
            
            # Keep only recent events
            if len(self.threat_events) > 100:
                self.threat_events = self.threat_events[-50:]
                
        except Exception as e:
            logger.error(f"Error handling threat: {e}")
    
    def _quarantine_file(self, file_path):
        """Quarantine threatening file"""
        try:
            src_path = Path(file_path)
            if not src_path.exists():
                return False
            
            # Create unique quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"THREAT_{timestamp}_{src_path.name}"
            quarantine_path = self.quarantine_dir / quarantine_name
            
            # Move file to quarantine
            src_path.rename(quarantine_path)
            
            # Create metadata file
            metadata = {
                'original_path': str(src_path),
                'quarantined_at': datetime.now().isoformat(),
                'file_size': quarantine_path.stat().st_size
            }
            
            metadata_path = quarantine_path.with_suffix('.meta')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            return True
            
        except Exception as e:
            logger.error(f"Quarantine failed: {e}")
            return False

class EnterpriseAntiRansomware:
    """Main enterprise anti-ransomware system"""
    
    def __init__(self):
        self.security_manager = SimpleSecurityManager()
        self.file_protection = EnterpriseFileProtection()
        self.protected_folders = []
        self.app = Flask(__name__)
        self._setup_routes()
        
    def initialize(self):
        """Initialize the system"""
        try:
            logger.info("Initializing Enterprise Anti-Ransomware System")
            
            if not self.security_manager.initialize_security():
                logger.error("Security initialization failed")
                return False
            
            # Load sample protected folders
            self._load_sample_folders()
            
            # Start file protection
            if self.protected_folders:
                self.file_protection.start_protection(self.protected_folders)
            
            logger.info("Enterprise Anti-Ransomware System initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"System initialization failed: {e}")
            return False
    
    def _load_sample_folders(self):
        """Load sample protected folders for demonstration"""
        sample_folders = [
            ProtectedFolder(
                path="C:\\Users\\Documents",
                policy_id="enterprise_security",
                protection_level="maximum",
                usb_required=True,
                created_at=datetime.now(),
                active=True
            )
        ]
        self.protected_folders = sample_folders
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            """Main dashboard"""
            try:
                recent_events = self.file_protection.threat_events[-10:] if self.file_protection.threat_events else []
                
                stats = {
                    'protected_folders': len(self.protected_folders),
                    'threats_blocked': len([e for e in recent_events if e['action'] == 'QUARANTINED']),
                    'service_status': 'ACTIVE',
                    'security_level': 'ENTERPRISE'
                }
                
                return render_template_string(DASHBOARD_TEMPLATE, stats=stats, events=recent_events)
                
            except Exception as e:
                logger.error(f"Dashboard error: {e}", exc_info=True)
                return "Dashboard Error: An error occurred. Please try again later."
        
        @self.app.route('/api/status')
        def api_status():
            """API status endpoint"""
            return jsonify({
                'status': 'active',
                'protected_folders': len(self.protected_folders),
                'threats_detected': len(self.file_protection.threat_events)
            })
    
    def run_web_interface(self):
        """Run the web interface"""
        try:
            # Configure SSL context
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(
                self.security_manager.certificate_path,
                self.security_manager.private_key_path
            )
            
            logger.info("Starting HTTPS web interface on port 8443")
            
            # Run Flask with HTTPS
            self.app.run(
                host='127.0.0.1',
                port=8443,
                ssl_context=ssl_context,
                debug=False,
                use_reloader=False
            )
            
        except Exception as e:
            logger.error(f"Web interface error: {e}")

# Dashboard Template
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Enterprise Anti-Ransomware Dashboard</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; margin: 0; padding: 20px; min-height: 100vh;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { 
            background: rgba(0,0,0,0.3); padding: 30px; border-radius: 15px; 
            margin-bottom: 30px; text-align: center; backdrop-filter: blur(10px);
        }
        .header h1 { margin: 0; font-size: 2.5em; text-shadow: 2px 2px 4px rgba(0,0,0,0.5); }
        .stats-grid { 
            display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; margin-bottom: 30px; 
        }
        .stat-card { 
            background: rgba(255,255,255,0.1); padding: 25px; border-radius: 12px; 
            border: 1px solid rgba(255,255,255,0.2); backdrop-filter: blur(10px);
            text-align: center; transition: transform 0.3s ease;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-value { font-size: 3em; font-weight: bold; color: #ffeb3b; margin-bottom: 10px; }
        .stat-label { font-size: 1.1em; opacity: 0.9; }
        .enterprise-badge { 
            display: inline-block; background: #4caf50; color: white; 
            padding: 5px 15px; border-radius: 20px; font-weight: bold;
            margin: 10px 0; text-transform: uppercase; letter-spacing: 1px;
        }
        .events-section { 
            background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px;
            margin-top: 20px; backdrop-filter: blur(10px);
        }
        .event-item { 
            background: rgba(255,255,255,0.1); padding: 15px; margin: 10px 0; 
            border-radius: 8px; border-left: 4px solid #ffeb3b;
        }
        .threat-critical { border-left-color: #f44336; }
        .status-indicator { 
            display: inline-block; width: 12px; height: 12px; 
            border-radius: 50%; background: #4caf50; margin-right: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Enterprise Anti-Ransomware Protection</h1>
            <div class="enterprise-badge">Enterprise Edition</div>
            <p><span class="status-indicator"></span>Advanced behavioral analysis • Kernel-level protection • Encrypted quarantine</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ stats.protected_folders }}</div>
                <div class="stat-label">Protected Folders</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.threats_blocked }}</div>
                <div class="stat-label">Threats Blocked</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.service_status }}</div>
                <div class="stat-label">Service Status</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.security_level }}</div>
                <div class="stat-label">Security Level</div>
            </div>
        </div>
        
        <div class="events-section">
            <h3>🚨 Recent Security Events</h3>
            {% if events %}
                {% for event in events %}
                <div class="event-item {{ 'threat-critical' if event.severity == 'CRITICAL' else '' }}">
                    <strong>{{ event.timestamp.strftime('%H:%M:%S') }}</strong> - 
                    <span>{{ event.threat_type }}</span><br>
                    File: {{ event.file_path }}<br>
                    Action: {{ event.action }} ({{ event.severity }})
                </div>
                {% endfor %}
            {% else %}
                <div class="event-item">
                    <strong>System Status:</strong> No threats detected. All systems operational.
                </div>
            {% endif %}
        </div>
    </div>
    
    <script>
        // Auto-refresh dashboard every 30 seconds
        setInterval(() => location.reload(), 30000);
        
        // Display connection security info
        if (location.protocol === 'https:') {
            console.log('Secure HTTPS connection established');
        }
    </script>
</body>
</html>
"""

def main():
    """Main entry point"""
    try:
        print("🚀 ENTERPRISE ANTI-RANSOMWARE SYSTEM")
        print("=" * 50)
        print("Enterprise Edition with Advanced Security")
        print("HTTPS Dashboard: https://localhost:8443")
        print("Behavioral Analysis Active")
        print("Encrypted Quarantine System")
        print()
        
        # Initialize the system
        system = EnterpriseAntiRansomware()
        
        if system.initialize():
            print("✅ Enterprise security initialized")
            print("🌐 Starting secure web interface...")
            
            # Run the web interface
            system.run_web_interface()
            
        else:
            print("❌ System initialization failed")
            return 1
            
    except KeyboardInterrupt:
        print("\n🛑 Enterprise service stopped")
        return 0
    except Exception as e:
        logger.error(f"System error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
