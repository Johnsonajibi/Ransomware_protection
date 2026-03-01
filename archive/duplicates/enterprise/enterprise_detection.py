"""
ENTERPRISE-GRADE DETECTION FEATURES
- File entropy analysis (detect encrypted files)
- Canary file monitoring (honeypot detection)
- VirusTotal integration (threat intelligence)
- Email/Slack alerting
"""

import os
import math
import hashlib
import json
import logging
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import threading
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_enterprise_config(config_path: str = "enterprise_config.json") -> Dict:
    """Load enterprise detection configuration from disk."""
    try:
        # Resolve config path relative to this script if not found directly
        if config_path == "enterprise_config.json" and not os.path.exists(config_path):
            script_dir = os.path.dirname(os.path.abspath(__file__))
            potential_path = os.path.join(script_dir, config_path)
            if os.path.exists(potential_path):
                config_path = potential_path
                
        with open(config_path, 'r', encoding='utf-8') as cfg:
            return json.load(cfg)
    except FileNotFoundError:
        logger.warning(f"Enterprise config not found: {config_path}")
    except Exception as exc:
        logger.error(f"Failed to load enterprise config {config_path}: {exc}")
    return {}


class EntropyAnalyzer:
    """
    Detect ransomware by analyzing file entropy.
    Encrypted files have high entropy (7.5-8.0), normal files are lower (4.0-6.5)
    """
    
    RANSOMWARE_ENTROPY_THRESHOLD = 7.5
    SUSPICIOUS_ENTROPY_THRESHOLD = 7.0
    
    def __init__(self):
        self.entropy_cache = {}
        logger.info("✅ Entropy analyzer initialized")
    
    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        Returns value 0-8, where 8 is maximum entropy (random/encrypted)
        """
        if not data:
            return 0.0
        
        # Count byte frequencies
        counter = Counter(data)
        length = len(data)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in counter.values():
            p_x = count / length
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        
        return entropy
    
    def analyze_file(self, file_path: str, sample_size: int = 8192) -> Dict:
        """
        Analyze file entropy and determine if it's suspicious.
        Only reads first sample_size bytes for performance.
        
        Returns:
            {
                'entropy': float,
                'is_suspicious': bool,
                'is_likely_ransomware': bool,
                'risk_level': str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
            }
        """
        try:
            if not os.path.exists(file_path):
                return {'entropy': 0, 'is_suspicious': False, 'is_likely_ransomware': False, 'risk_level': 'NONE'}
            
            # Read sample of file
            with open(file_path, 'rb') as f:
                data = f.read(sample_size)
            
            if len(data) < 100:  # Too small to analyze
                return {'entropy': 0, 'is_suspicious': False, 'is_likely_ransomware': False, 'risk_level': 'LOW'}
            
            entropy = self.calculate_entropy(data)
            
            # Determine risk level
            if entropy >= self.RANSOMWARE_ENTROPY_THRESHOLD:
                risk_level = 'CRITICAL'
                is_likely_ransomware = True
                is_suspicious = True
            elif entropy >= self.SUSPICIOUS_ENTROPY_THRESHOLD:
                risk_level = 'HIGH'
                is_likely_ransomware = False
                is_suspicious = True
            elif entropy >= 6.5:
                risk_level = 'MEDIUM'
                is_likely_ransomware = False
                is_suspicious = False
            else:
                risk_level = 'LOW'
                is_likely_ransomware = False
                is_suspicious = False
            
            return {
                'entropy': round(entropy, 2),
                'is_suspicious': is_suspicious,
                'is_likely_ransomware': is_likely_ransomware,
                'risk_level': risk_level,
                'file_size': len(data),
                'analyzed_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing entropy for {file_path}: {e}")
            return {'entropy': 0, 'is_suspicious': False, 'is_likely_ransomware': False, 'risk_level': 'UNKNOWN'}
    
    def batch_analyze_directory(self, directory: str, extensions: List[str] = None) -> List[Dict]:
        """
        Analyze all files in a directory for suspicious entropy.
        
        Args:
            directory: Path to scan
            extensions: Only analyze these extensions (e.g., ['.doc', '.pdf'])
        
        Returns:
            List of suspicious files with entropy details
        """
        suspicious_files = []
        
        try:
            for root, dirs, files in os.walk(directory):
                for filename in files:
                    # Filter by extension if specified
                    if extensions:
                        if not any(filename.lower().endswith(ext) for ext in extensions):
                            continue
                    
                    file_path = os.path.join(root, filename)
                    result = self.analyze_file(file_path)
                    
                    if result['is_suspicious']:
                        result['file_path'] = file_path
                        result['file_name'] = filename
                        suspicious_files.append(result)
        
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
        
        return suspicious_files


class CanaryFileMonitor:
    """
    Create and monitor "canary" (honeypot) files.
    Any access to these files triggers immediate alert - likely ransomware.
    """
    
    def __init__(self, canary_directory: str = None):
        self.canary_directory = canary_directory or os.path.join(os.environ.get('TEMP', 'C:\\Temp'), '__CANARY__')
        self.canary_files = []
        self.access_log = []
        self.monitoring = False
        self.monitor_thread = None
        self._last_alert_at = {}  # (type,path) -> unix timestamp
        self.alert_cooldown_seconds = 300
        logger.info("✅ Canary file monitor initialized")
    
    def create_canary_files(self) -> List[str]:
        """
        Create bait files that ransomware will target.
        These files look like valuable data.
        """
        os.makedirs(self.canary_directory, exist_ok=True)
        
        # Clear existing canary list (fresh start)
        self.canary_files = []
        
        canary_templates = [
            ("passwords.txt", "# Password Database\nDO NOT MODIFY - CANARY FILE"),
            ("bitcoin_wallet.dat", "BITCOIN WALLET - CANARY FILE"),
            ("credit_cards.xlsx", "Credit Card Database - CANARY FILE"),
            ("private_keys.pem", "-----BEGIN PRIVATE KEY-----\nCANARY FILE\n-----END PRIVATE KEY-----"),
            ("bank_accounts.csv", "Account,Balance,Bank\nCANARY,0,TRAP"),
            ("ssn_list.txt", "SSN Database - CANARY FILE"),
            ("customer_database.db", "SQLite format - CANARY FILE"),
            ("backup_codes.txt", "2FA Backup Codes - CANARY FILE")
        ]
        
        created_files = []
        
        for filename, content in canary_templates:
            file_path = os.path.join(self.canary_directory, filename)
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                # Store original hash
                file_hash = hashlib.sha256(content.encode()).hexdigest()
                self.canary_files.append({
                    'path': file_path,
                    'name': filename,
                    'original_hash': file_hash,
                    'original_size': len(content.encode('utf-8')),
                    'created_at': datetime.now().isoformat()
                })
                created_files.append(file_path)
                
                # Make file hidden (optional) - skip for now to avoid permission issues
                # try:
                #     import ctypes
                #     ctypes.windll.kernel32.SetFileAttributesW(file_path, 0x02)  # Hidden
                # except:
                #     pass
                    
            except Exception as e:
                logger.error(f"Failed to create canary file {filename}: {e}")
        
        logger.info(f"✅ Created {len(created_files)} canary files in {self.canary_directory}")
        return created_files
    
    def check_canaries(self) -> List[Dict]:
        """
        Check if any canary files have been accessed, modified, or deleted.
        
        Returns:
            List of alerts for compromised canary files
        """
        alerts = []
        
        for canary in self.canary_files:
            file_path = canary['path']
            
            # Check if file exists
            if not os.path.exists(file_path):
                alerts.append({
                    'type': 'CANARY_DELETED',
                    'severity': 'CRITICAL',
                    'file': canary['name'],
                    'path': file_path,
                    'message': f"🚨 RANSOMWARE DETECTED: Canary file '{canary['name']}' was DELETED!",
                    'timestamp': datetime.now().isoformat()
                })
                continue
            
            # Check if file was modified
            try:
                with open(file_path, 'rb') as f:
                    current_content = f.read()
                
                current_hash = hashlib.sha256(current_content).hexdigest()
                
                if current_hash != canary['original_hash']:
                    # Get file size change
                    original_size = int(canary.get('original_size', 0))
                    current_size = len(current_content)
                    
                    # Check if encrypted (high entropy)
                    entropy_analyzer = EntropyAnalyzer()
                    entropy_result = entropy_analyzer.analyze_file(file_path)
                    
                    alerts.append({
                        'type': 'CANARY_MODIFIED',
                        'severity': 'CRITICAL' if entropy_result['is_likely_ransomware'] else 'HIGH',
                        'file': canary['name'],
                        'path': file_path,
                        'message': f"🚨 RANSOMWARE DETECTED: Canary file '{canary['name']}' was MODIFIED!",
                        'entropy': entropy_result['entropy'],
                        'likely_encrypted': entropy_result['is_likely_ransomware'],
                        'size_change': current_size - original_size,
                        'timestamp': datetime.now().isoformat()
                    })

                    # Prevent alert spam: treat first compromise as terminal and don't re-alert every poll
                    canary['original_hash'] = current_hash
                    canary['original_size'] = current_size
                    canary['compromised_at'] = datetime.now().isoformat()
                    
            except Exception as e:
                logger.error(f"Error checking canary file {file_path}: {e}")
        
        return alerts
    
    def start_monitoring(self, check_interval: int = 5):
        """
        Start continuous monitoring of canary files.
        
        Args:
            check_interval: Seconds between checks
        """
        if self.monitoring:
            logger.warning("Canary monitoring already running")
            return
        
        self.monitoring = True
        
        def monitor_loop():
            logger.info(f"🔍 Canary monitoring started (checking every {check_interval}s)")
            while self.monitoring:
                alerts = self.check_canaries()
                if alerts:
                    for alert in alerts:
                        key = (alert.get('type'), alert.get('path'))
                        now = time.time()
                        last = self._last_alert_at.get(key, 0)
                        if now - last >= self.alert_cooldown_seconds:
                            self._last_alert_at[key] = now
                            logger.critical(alert['message'])
                            self.access_log.append(alert)
                            # Trigger alert handlers here
                            self._trigger_alert(alert)
                
                time.sleep(check_interval)
        
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop canary file monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logger.info("🛑 Canary monitoring stopped")
    
    def _trigger_alert(self, alert: Dict):
        """Override this method to implement custom alerting (email, Slack, etc.)"""
        pass  # Implement in subclass or connect to alert system
    
    def get_alert_history(self) -> List[Dict]:
        """Get all canary file alerts"""
        return self.access_log.copy()


def deploy_canaries(locations: List[str], check_interval: int = 5) -> List[CanaryFileMonitor]:
    """Create and start canary monitors across multiple locations."""
    monitors: List[CanaryFileMonitor] = []
    seen = set()
    for location in locations or []:
        if not location:
            continue
        resolved = os.path.expandvars(location)
        resolved = str(os.path.abspath(resolved))
        if resolved in seen:
            continue
        seen.add(resolved)
        monitor = CanaryFileMonitor(canary_directory=resolved)
        monitor.create_canary_files()
        monitor.start_monitoring(check_interval=check_interval)
        monitors.append(monitor)
    return monitors


class ThreatIntelligence:
    """Integration with threat intelligence feeds (VirusTotal, etc.)."""
    
    def __init__(
        self,
        virustotal_api_key: str = None,
        rate_limit_per_minute: int = 4,
        backoff_seconds: int = 60,
        enabled: bool = True,
    ):
        self.vt_api_key = virustotal_api_key
        self.rate_limit_per_minute = max(1, rate_limit_per_minute or 4)
        self.backoff_seconds = max(0, backoff_seconds or 0)
        self.cache = {}
        self._request_timestamps: List[float] = []
        self.enabled = enabled and bool(virustotal_api_key)
        logger.info("✅ Threat intelligence module initialized")
    
    def check_file_hash(self, file_path: str) -> Optional[Dict]:
        """
        Check file hash against VirusTotal database.
        Requires VirusTotal API key.
        
        Returns:
            {
                'malicious': bool,
                'detections': int,
                'total_scanners': int,
                'threat_names': List[str]
            }
        """
        if not self.enabled:
            logger.warning("VirusTotal disabled or API key not configured")
            return None
        
        try:
            self._enforce_rate_limit()
            request_attempts = 0

            # Calculate file hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Check cache
            if file_hash in self.cache:
                return self.cache[file_hash]
            
            # Query VirusTotal API
            import requests
            
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.vt_api_key}

            while request_attempts < 2:
                response = requests.get(url, headers=headers, timeout=10)
                request_attempts += 1

                if response.status_code == 200:
                    self._request_timestamps.append(time.time())
                    data = response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    
                    result = {
                        'malicious': stats.get('malicious', 0) > 0,
                        'detections': stats.get('malicious', 0),
                        'total_scanners': sum(stats.values()),
                        'threat_names': [],
                        'checked_at': datetime.now().isoformat()
                    }
                    
                    # Get threat names
                    results = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
                    for scanner, details in results.items():
                        if details.get('category') == 'malicious':
                            result['threat_names'].append(details.get('result', 'Unknown'))
                    
                    self.cache[file_hash] = result
                    return result
                
                if response.status_code == 404:
                    return {
                        'malicious': False,
                        'detections': 0,
                        'total_scanners': 0,
                        'threat_names': [],
                        'note': 'File not found in VirusTotal database'
                    }

                if response.status_code == 429 and self.backoff_seconds:
                    logger.warning("VirusTotal rate limit hit; backing off")
                    time.sleep(self.backoff_seconds)
                    continue

                logger.error(f"VirusTotal API error: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error checking VirusTotal: {e}")
            return None

    def _enforce_rate_limit(self):
        """Simple per-minute rate limiter with sleep-based backoff."""
        if self.rate_limit_per_minute <= 0:
            return
        now = time.time()
        one_minute_ago = now - 60
        self._request_timestamps = [t for t in self._request_timestamps if t >= one_minute_ago]
        if len(self._request_timestamps) >= self.rate_limit_per_minute:
            if self.backoff_seconds:
                logger.warning("VirusTotal quota reached; backing off")
                time.sleep(self.backoff_seconds)
            self._request_timestamps = [t for t in self._request_timestamps if t >= one_minute_ago]


class EnterpriseAlerting:
    """
    Enterprise alert system - Email, Slack, Teams, SMS
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.alert_history = []
        self.alert_levels = self.config.get('alert_levels', {})
        logger.info("✅ Enterprise alerting system initialized")
    
    def send_email_alert(self, subject: str, body: str, to_addresses: List[str] = None):
        """
        Send email alert to security team.
        
        Requires config:
            {
                'smtp_server': 'smtp.company.com',
                'smtp_port': 587,
                'smtp_user': 'alerts@company.com',
                'smtp_password': 'password',
                'from_address': 'antiransomware@company.com',
                'to_addresses': ['security@company.com']
            }
        """
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            smtp_config = self.config.get('email', {})
            
            if not smtp_config.get('enabled'):
                logger.info("Email alerting disabled")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['Subject'] = f"🚨 RANSOMWARE ALERT: {subject}"
            msg['From'] = smtp_config.get('from_address', 'antiransomware@localhost')
            msg['To'] = ', '.join(to_addresses or smtp_config.get('to_addresses', []))
            
            # Add body
            html_body = f"""
            <html>
            <body>
                <h2 style="color: red;">🚨 Anti-Ransomware Alert</h2>
                <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <hr>
                <pre>{body}</pre>
                <hr>
                <p><em>This is an automated alert from your Anti-Ransomware Protection System</em></p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html_body, 'html'))
            
            # Send email
            with smtplib.SMTP(smtp_config['smtp_server'], smtp_config.get('smtp_port', 587)) as server:
                server.starttls()
                if smtp_config.get('smtp_user') and smtp_config.get('smtp_password'):
                    server.login(smtp_config['smtp_user'], smtp_config['smtp_password'])
                server.send_message(msg)
            
            logger.info(f"✅ Email alert sent: {subject}")
            self.alert_history.append({
                'type': 'email',
                'subject': subject,
                'timestamp': datetime.now().isoformat()
            })
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False
    
    def send_slack_alert(self, message: str, channel: str = None):
        """
        Send alert to Slack channel.
        
        Requires config:
            {
                'slack_webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
            }
        """
        try:
            import requests
            
            slack_config = self.config.get('slack', {})
            webhook_url = slack_config.get('webhook_url')
            
            if not slack_config.get('enabled'):
                logger.info("Slack alerting disabled")
                return False
            
            if not webhook_url:
                logger.warning("Slack webhook not configured")
                return False
            
            payload = {
                "text": f"🚨 *RANSOMWARE ALERT*",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🚨 Anti-Ransomware Alert"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": message
                        }
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                            }
                        ]
                    }
                ]
            }
            
            if channel:
                payload['channel'] = channel
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                logger.info("✅ Slack alert sent")
                self.alert_history.append({
                    'type': 'slack',
                    'message': message,
                    'timestamp': datetime.now().isoformat()
                })
                return True
            else:
                logger.error(f"Slack alert failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False
    
    def send_teams_alert(self, message: str):
        """
        Send alert to Microsoft Teams.
        
        Requires config:
            {
                'teams_webhook_url': 'https://outlook.office.com/webhook/YOUR/WEBHOOK/URL'
            }
        """
        try:
            import requests
            
            teams_config = self.config.get('teams', {})
            webhook_url = teams_config.get('webhook_url')
            
            if not teams_config.get('enabled'):
                logger.info("Teams alerting disabled")
                return False
            
            if not webhook_url:
                logger.warning("Teams webhook not configured")
                return False
            
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "FF0000",
                "summary": "Ransomware Alert",
                "sections": [{
                    "activityTitle": "🚨 Anti-Ransomware Alert",
                    "activitySubtitle": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "text": message,
                    "markdown": True
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                logger.info("✅ Teams alert sent")
                self.alert_history.append({
                    'type': 'teams',
                    'message': message,
                    'timestamp': datetime.now().isoformat()
                })
                return True
            else:
                logger.error(f"Teams alert failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send Teams alert: {e}")
            return False
    
    def alert(self, severity: str, title: str, details: str):
        """
        Send alert through all configured channels.
        
        Args:
            severity: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
            title: Brief alert title
            details: Full alert details
        """
        severity_allowed = self.alert_levels.get(severity, True)
        if not severity_allowed:
            logger.info(f"Skipping alert {severity}: filtered by config")
            return False

        message = f"*Severity:* {severity}\n*Alert:* {title}\n\n{details}"
        
        # Send to all configured channels
        if self.config.get('email'):
            self.send_email_alert(title, details)
        
        if self.config.get('slack'):
            self.send_slack_alert(message)
        
        if self.config.get('teams'):
            self.send_teams_alert(message)
        
        logger.info(f"Alert sent - {severity}: {title}")
        return True


# Example usage and testing
if __name__ == "__main__":
    print("🔬 Testing Enterprise Detection Features\n")
    
    # Test 1: Entropy Analysis
    print("=" * 60)
    print("TEST 1: File Entropy Analysis")
    print("=" * 60)
    
    entropy_analyzer = EntropyAnalyzer()
    
    # Create test files
    test_dir = "test_entropy"
    os.makedirs(test_dir, exist_ok=True)
    
    # Normal text file (low entropy)
    with open(f"{test_dir}/normal.txt", 'w') as f:
        f.write("This is a normal text file with regular content. " * 100)
    
    # Encrypted-like file (high entropy)
    with open(f"{test_dir}/encrypted.bin", 'wb') as f:
        import random
        f.write(bytes([random.randint(0, 255) for _ in range(8192)]))
    
    print("\nAnalyzing normal.txt:")
    result = entropy_analyzer.analyze_file(f"{test_dir}/normal.txt")
    print(json.dumps(result, indent=2))
    
    print("\nAnalyzing encrypted.bin (simulated ransomware):")
    result = entropy_analyzer.analyze_file(f"{test_dir}/encrypted.bin")
    print(json.dumps(result, indent=2))
    
    # Test 2: Canary Files
    print("\n" + "=" * 60)
    print("TEST 2: Canary File Monitoring")
    print("=" * 60)
    
    canary_monitor = CanaryFileMonitor()
    created = canary_monitor.create_canary_files()
    print(f"\n✅ Created {len(created)} canary files:")
    for cf in created:
        print(f"   📄 {cf}")
    
    print("\nInitial check (should be clean):")
    alerts = canary_monitor.check_canaries()
    print(f"   Alerts: {len(alerts)}")
    
    # Simulate ransomware attack
    print("\nSimulating ransomware attack...")
    if created:
        with open(created[0], 'wb') as f:
            import random
            f.write(bytes([random.randint(0, 255) for _ in range(1000)]))  # Encrypt first canary
        print(f"   Modified: {created[0]}")
    
    print("\nChecking canaries after 'attack':")
    alerts = canary_monitor.check_canaries()
    if alerts:
        print(f"   🚨 ALERTS TRIGGERED: {len(alerts)}")
        for alert in alerts:
            print(f"\n   {alert['message']}")
            print(f"      Severity: {alert['severity']}")
            print(f"      Entropy: {alert.get('entropy', 'N/A')}")
    
    # Test 3: Alerting
    print("\n" + "=" * 60)
    print("TEST 3: Enterprise Alerting System")
    print("=" * 60)
    
    alerting = EnterpriseAlerting()
    print("\n✅ Alerting system ready (configure webhooks for full functionality)")
    print("   - Email alerts: Not configured")
    print("   - Slack alerts: Not configured")
    print("   - Teams alerts: Not configured")
    
    print("\n💡 To enable alerts, add to config:")
    print("""
    config = {
        'email': {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'smtp_user': 'your-email@gmail.com',
            'smtp_password': 'your-app-password',
            'from_address': 'alerts@yourcompany.com',
            'to_addresses': ['security@yourcompany.com']
        },
        'slack': {
            'webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
        },
        'teams': {
            'webhook_url': 'https://outlook.office.com/webhook/YOUR/WEBHOOK/URL'
        }
    }
    """)
    
    print("\n" + "=" * 60)
    print("✅ All tests completed!")
    print("=" * 60)
