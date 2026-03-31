#!/usr/bin/env python3
"""
Email Alerting System
====================
SMTP-based security alert notifications

Features:
- Multi-provider support (Gmail, Office 365, custom SMTP)
- Event-based email templates
- Rate limiting to prevent alert fatigue
- Attachment support for forensic logs
- TLS/SSL security
- Configurable recipients

Author: Johnson Ajibi
Date: December 28, 2025
"""

import os
import re as _re
import smtplib
import threading
import time
import json
import sys
import tempfile
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

try:
    from security_event_logger import SecurityEventLogger
    HAS_LOGGER = True
except ImportError:
    HAS_LOGGER = False


def _console_print(*args, sep: str = " ", end: str = "\n"):
    """Print without crashing on Windows consoles that can't encode Unicode."""

    text = sep.join(str(arg) for arg in args) + end
    stream = sys.stdout
    encoding = getattr(stream, "encoding", None) or "utf-8"

    try:
        stream.write(text)
    except UnicodeEncodeError:
        safe_text = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
        stream.write(safe_text)


class EmailAlertingSystem:
    """
    Email notification system for security events
    
    Supports:
    - Gmail with app passwords
    - Office 365 with modern auth
    - Custom SMTP servers
    - TLS/SSL encryption
    - Rate limiting
    - Event templating
    """
    
    # SMTP provider configurations
    SMTP_PROVIDERS = {
        'gmail': {
            'server': 'smtp.gmail.com',
            'port': 587,
            'use_tls': True,
            'auth_required': True
        },
        'office365': {
            'server': 'smtp.office365.com',
            'port': 587,
            'use_tls': True,
            'auth_required': True
        },
        'outlook': {
            'server': 'smtp-mail.outlook.com',
            'port': 587,
            'use_tls': True,
            'auth_required': True
        },
        # Note: 'custom' is intentionally NOT in this dict so the send logic
        # falls through to reading smtp_server/smtp_port directly from config.
    }

    @staticmethod
    def _resolve_config_path(config_file: Optional[Path], filename: str) -> Path:
        if config_file is not None:
            return Path(config_file)

        candidates = [
            Path.home() / "AppData" / "Local" / "AntiRansomware" / filename,
            Path.cwd() / "config" / filename,
            Path(tempfile.gettempdir()) / "AntiRansomware" / filename,
        ]

        for candidate in candidates:
            try:
                candidate.parent.mkdir(parents=True, exist_ok=True)
                return candidate
            except (PermissionError, FileExistsError, OSError):
                continue

        return Path(tempfile.gettempdir()) / filename
    
    def __init__(self, config_file: Optional[Path] = None):
        """Initialize email alerting system"""

        self.config_file = self._resolve_config_path(config_file, "email_config.json")
        
        # Load configuration
        self.config = self._load_config()
        
        # Rate limiting state
        self.rate_limit_file = self.config_file.parent / "email_rate_limit.json"
        self.alert_history = self._load_alert_history()
        
        # Event logger
        self.logger = SecurityEventLogger() if HAS_LOGGER else None

        # Background greylisting retry queue
        self._retry_queue: list = []
        self._retry_lock = threading.Lock()
        self._retry_thread: threading.Thread | None = None
    
    def _load_config(self) -> Dict:
        """Load email configuration"""
        
        default_config = {
            'enabled': False,
            'provider': 'gmail',
            'smtp_server': '',
            'smtp_port': 587,
            'use_tls': True,
            'username': '',
            'password': '',  # App password or auth token
            'from_email': '',
            'recipients': [],  # List of recipient emails
            'cc_recipients': [],
            'bcc_recipients': [],
            'rate_limit': {
                'enabled': True,
                'max_emails_per_hour': 10,
                'max_emails_per_day': 50,
                'cooldown_seconds': 300  # 5 minutes between similar alerts
            },
            'alert_levels': {
                'CRITICAL': True,
                'HIGH': True,
                'MEDIUM': True,
                'LOW': False,
                'INFO': False
            },
            'attach_logs': True,
            'include_system_info': True
        }
        
        try:
            config_exists = self.config_file.exists()
        except (PermissionError, OSError):
            self.config_file = self._resolve_config_path(Path.cwd() / "config" / "email_config.json", "email_config.json")
            config_exists = False

        if config_exists:
            try:
                with self.config_file.open('r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except PermissionError:
                import tempfile as _tf
                self.config_file = Path(_tf.gettempdir()) / 'AntiRansomware' / 'email_config.json'
                self.config_file.parent.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                _console_print(f"⚠️ Config load failed: {e}")
        else:
            # Save default config
            try:
                with self.config_file.open('w') as f:
                    json.dump(default_config, f, indent=2)
                _console_print(f"✓ Default config saved to {self.config_file}")
            except PermissionError:
                import tempfile as _tf
                self.config_file = Path(_tf.gettempdir()) / 'AntiRansomware' / 'email_config.json'
                self.config_file.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with self.config_file.open('w') as _f:
                        import json as _j; _j.dump(default_config, _f, indent=2)
                except Exception:
                    pass
            except Exception as e:
                _console_print(f"⚠️ Config save failed: {e}")
        
        return default_config
    
    def _load_alert_history(self) -> Dict:
        """Load alert history for rate limiting"""
        
        if self.rate_limit_file.exists():
            try:
                with self.rate_limit_file.open('r') as f:
                    return json.load(f)
            except:
                pass
        
        return {
            'alerts': [],
            'last_cleanup': time.time()
        }
    
    def _save_alert_history(self):
        """Save alert history"""
        
        try:
            with self.rate_limit_file.open('w') as f:
                json.dump(self.alert_history, f)
        except Exception as e:
            _console_print(f"⚠️ Failed to save alert history: {e}")
    
    def _check_rate_limit(self, alert_type: str, severity: str) -> bool:
        """
        Check if alert should be sent based on rate limits
        
        Args:
            alert_type: Type of alert
            severity: Alert severity level
        
        Returns:
            True if alert can be sent
        """
        
        if not self.config['rate_limit']['enabled']:
            return True
        
        now = time.time()
        rate_config = self.config['rate_limit']
        
        # Clean old alerts (older than 24 hours)
        cutoff_24h = now - 86400
        self.alert_history['alerts'] = [
            a for a in self.alert_history['alerts']
            if a['timestamp'] > cutoff_24h
        ]
        
        # Count recent alerts
        cutoff_1h = now - 3600
        alerts_last_hour = sum(
            1 for a in self.alert_history['alerts']
            if a['timestamp'] > cutoff_1h
        )
        
        alerts_last_day = len(self.alert_history['alerts'])
        
        # Check hourly limit
        if alerts_last_hour >= rate_config['max_emails_per_hour']:
            _console_print(f"⚠️ Rate limit: {alerts_last_hour} emails in last hour")
            return False
        
        # Check daily limit
        if alerts_last_day >= rate_config['max_emails_per_day']:
            _console_print(f"⚠️ Rate limit: {alerts_last_day} emails in last 24h")
            return False
        
        # Check cooldown for similar alerts
        cooldown = rate_config['cooldown_seconds']
        for alert in reversed(self.alert_history['alerts']):
            if alert['type'] == alert_type:
                time_since = now - alert['timestamp']
                if time_since < cooldown:
                    remaining = int(cooldown - time_since)
                    _console_print(f"⚠️ Cooldown: {remaining}s remaining for {alert_type}")
                    return False
                break
        
        return True
    
    def _record_alert(self, alert_type: str, severity: str):
        """Record alert in history"""
        
        self.alert_history['alerts'].append({
            'type': alert_type,
            'severity': severity,
            'timestamp': time.time()
        })
        
        self._save_alert_history()
    
    def _create_email_template(self, alert_type: str, severity: str, details: Dict) -> str:
        """
        Create HTML email template
        
        Args:
            alert_type: Type of security alert
            severity: Severity level
            details: Alert details dictionary
        
        Returns:
            HTML email body
        """
        
        severity_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#17a2b8',
            'INFO': '#6c757d'
        }
        
        color = severity_colors.get(severity, '#6c757d')
        
        # System info
        import socket
        hostname = socket.gethostname()
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: {color}; color: white; padding: 20px; border-radius: 5px; }}
        .content {{ padding: 20px; background-color: #f8f9fa; margin-top: 20px; border-radius: 5px; }}
        .detail-row {{ margin: 10px 0; }}
        .label {{ font-weight: bold; color: #495057; }}
        .value {{ color: #212529; }}
        .footer {{ margin-top: 20px; padding: 10px; border-top: 1px solid #dee2e6; font-size: 12px; color: #6c757d; }}
    </style>
</head>
<body>
    <div class="header">
        <h2>🚨 Security Alert: {alert_type}</h2>
        <p>Severity: <strong>{severity}</strong></p>
    </div>
    
    <div class="content">
        <div class="detail-row">
            <span class="label">Timestamp:</span>
            <span class="value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
        </div>
        <div class="detail-row">
            <span class="label">Host:</span>
            <span class="value">{hostname}</span>
        </div>
"""
        
        # Add details
        for key, value in details.items():
            if isinstance(value, (list, dict)):
                value = json.dumps(value, indent=2)
            
            html += f"""
        <div class="detail-row">
            <span class="label">{key.replace('_', ' ').title()}:</span>
            <span class="value">{value}</span>
        </div>
"""
        
        html += """
    </div>
    
    <div class="footer">
        <p>This is an automated security alert from AntiRansomware Protection System</p>
        <p>If you did not expect this alert, please verify your system immediately</p>
    </div>
</body>
</html>
"""
        
        return html

    def _connect_smtp(self):
        """Open an authenticated SMTP connection using current config."""
        import socket as _sock
        smtp_server = self.config['smtp_server']
        smtp_port = int(self.config['smtp_port'])
        use_tls = self.config.get('use_tls', True)
        try:
            _probe = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            _probe.connect((smtp_server, smtp_port))
            ehlo_name = f'[{_probe.getsockname()[0]}]'
            _probe.close()
        except Exception:
            ehlo_name = '[127.0.0.1]'
        if smtp_port == 465:
            conn = smtplib.SMTP_SSL(smtp_server, smtp_port)
            conn.ehlo(ehlo_name)
        elif use_tls:
            conn = smtplib.SMTP(smtp_server, smtp_port)
            conn.ehlo(ehlo_name)
            conn.starttls()
            conn.ehlo(ehlo_name)
        else:
            conn = smtplib.SMTP(smtp_server, smtp_port)
            conn.ehlo(ehlo_name)
        if self.config.get('username') and self.config.get('password'):
            conn.login(self.config['username'], self.config['password'])
        return conn

    def _enqueue_for_retry(self, msg, from_addr, to_addrs, alert_type, severity):
        """Queue a greylisted message for automatic retry in 15 minutes.

        Stores the message with a *clean* subject (no spam-challenge codes)
        so that retries can negotiate fresh per-session codes.
        """
        import email as _email_mod
        parsed = _email_mod.message_from_string(msg.as_string())
        subj = str(parsed.get('Subject', ''))
        # Strip any appended spam codes from the subject
        clean_subj = _re.sub(r'(?:\s+[A-Za-z0-9]{6,20})+\s*$', '', subj)
        if clean_subj != subj:
            del parsed['Subject']
            parsed['Subject'] = clean_subj
        entry = {
            'msg_str': parsed.as_string(),
            'from_addr': from_addr,
            'to_addrs': to_addrs,
            'alert_type': alert_type,
            'severity': severity,
            'retry_after': time.time() + 15 * 60,
            'attempts': 0,
        }
        with self._retry_lock:
            self._retry_queue.append(entry)
        _console_print("   Queued for retry in 15 min (greylisting).")
        self._start_retry_worker()

    @staticmethod
    def _full_smtp_error(err):
        """Extract a complete error string from an SMTP exception."""
        s = str(err)
        if hasattr(err, 'recipients') and err.recipients:
            for _a, (_c, _m) in err.recipients.items():
                s += ' ' + (_m.decode('utf-8', errors='replace')
                            if isinstance(_m, bytes) else str(_m))
        elif hasattr(err, 'smtp_error'):
            _se = err.smtp_error
            s += ' ' + (_se.decode('utf-8', errors='replace')
                        if isinstance(_se, bytes) else str(_se))
        return s

    def _retry_worker(self):
        """Background daemon: retries greylisted messages every 60 s.

        Each retry performs the full spam-challenge negotiation:
        send -> if 554, extract per-session code -> resend with code ->
        if greylisted (451), re-queue for another 15 min.
        """
        MAX_ATTEMPTS = 3
        while True:
            time.sleep(60)
            with self._retry_lock:
                due = [e for e in self._retry_queue
                       if time.time() >= e['retry_after']]
            for entry in due:
                entry['attempts'] += 1
                attempt = entry['attempts']
                _console_print(f"   Retry #{attempt} for queued alert...")
                try:
                    conn = self._connect_smtp()
                    conn.sendmail(entry['from_addr'], entry['to_addrs'],
                                  entry['msg_str'])
                    conn.quit()
                    self._record_alert(entry['alert_type'], entry['severity'])
                    _console_print(
                        f"✓ Queued alert delivered (attempt {attempt})")
                    with self._retry_lock:
                        if entry in self._retry_queue:
                            self._retry_queue.remove(entry)
                    continue
                except Exception as err:
                    pass  # fall through to challenge handling below

                # --- Handle the error from the initial send attempt ---
                err_str = self._full_smtp_error(err)
                err_lower = err_str.lower()
                smtp_code = getattr(err, 'smtp_code', 0)

                # Extract any per-session challenge code
                m = _re.search(
                    r'(?:resend(?:\s+it)?\s+with\s+(?:the\s+)?code\s+)'
                    r'([A-Za-z0-9]{6,20})',
                    err_str, _re.IGNORECASE)
                code = m.group(1) if m else None
                if code == 'NOTSPAMTAG':
                    code = None

                is_spam_554 = (
                    smtp_code == 554 or
                    'unsolicited' in err_lower or
                    '5.7.1' in err_str
                ) and code
                is_grey = (
                    'greylisting' in err_lower or
                    '4.7.1' in err_str or
                    smtp_code in (450, 451)
                )

                if is_spam_554:
                    # Server gave a new per-session code — retry with it
                    import email as _email_mod
                    parsed = _email_mod.message_from_string(entry['msg_str'])
                    subj = str(parsed.get('Subject', ''))
                    del parsed['Subject']
                    parsed['Subject'] = f"{subj} {code}"
                    _console_print(f"   New spam code '{code}' — "
                                   f"retrying immediately...")
                    try:
                        import time as _time
                        _time.sleep(3)
                        conn2 = self._connect_smtp()
                        conn2.sendmail(entry['from_addr'],
                                       entry['to_addrs'],
                                       parsed.as_string())
                        conn2.quit()
                        self._record_alert(entry['alert_type'],
                                           entry['severity'])
                        _console_print(
                            f"✓ Queued alert delivered (attempt {attempt},"
                            f" code {code})")
                        with self._retry_lock:
                            if entry in self._retry_queue:
                                self._retry_queue.remove(entry)
                        continue
                    except Exception as err2:
                        err2_str = self._full_smtp_error(err2)
                        if 'greylisting' in err2_str.lower() or \
                           '4.7.1' in err2_str or \
                           getattr(err2, 'smtp_code', 0) in (450, 451):
                            is_grey = True
                            _console_print(
                                "   Spam code accepted — greylisted again.")
                        else:
                            _console_print(
                                f"   Retry with code failed: {err2}")

                if is_grey and attempt < MAX_ATTEMPTS:
                    entry['retry_after'] = time.time() + 15 * 60
                    _console_print(
                        f"   Still greylisted — retry "
                        f"#{attempt + 1} in 15 min.")
                else:
                    reason = "greylisting" if is_grey else str(err)
                    _console_print(
                        f"   Queued alert failed permanently after "
                        f"{attempt} attempts: {reason}")
                    with self._retry_lock:
                        if entry in self._retry_queue:
                            self._retry_queue.remove(entry)

    def _start_retry_worker(self):
        """Start the retry worker thread if it is not already running."""
        with self._retry_lock:
            if self._retry_thread is None or not self._retry_thread.is_alive():
                self._retry_thread = threading.Thread(
                    target=self._retry_worker,
                    daemon=True,
                    name='email-retry',
                )
                self._retry_thread.start()

    def send_alert(self, alert_type: str, severity: str, details: Dict, 
                   attach_logs: Optional[bool] = None) -> bool:
        """
        Send security alert email
        
        Args:
            alert_type: Type of alert (e.g., RANSOMWARE_DETECTED)
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            details: Dictionary of alert details
            attach_logs: Whether to attach log files
        
        Returns:
            True if email sent successfully
        """
        
        # Check if alerting is enabled
        if not self.config['enabled']:
            _console_print("⚠️ Email alerting is disabled")
            return False
        
        # Check if severity level should be alerted
        if not self.config['alert_levels'].get(severity, False):
            _console_print(f"⚠️ {severity} alerts are disabled")
            return False
        
        # Check rate limits
        if not self._check_rate_limit(alert_type, severity):
            return False
        
        # Create email message
        msg = MIMEMultipart()
        msg['From'] = self.config['from_email']
        msg['To'] = ', '.join(self.config['recipients'])
        
        if self.config['cc_recipients']:
            msg['Cc'] = ', '.join(self.config['cc_recipients'])
        
        msg['Subject'] = f"[{severity}] {alert_type} - AntiRansomware Alert"
        
        # Create HTML body
        html_body = self._create_email_template(alert_type, severity, details)
        msg.attach(MIMEText(html_body, 'html'))
        
        # Attach logs if requested
        if attach_logs is None:
            attach_logs = self.config['attach_logs']
        
        if attach_logs and self.logger:
            try:
                log_file = self.logger.event_log
                if log_file.exists():
                    with log_file.open('rb') as f:
                        attachment = MIMEApplication(f.read(), Name=log_file.name)
                        attachment['Content-Disposition'] = f'attachment; filename="{log_file.name}"'
                        msg.attach(attachment)
                    _console_print(f"   ✓ Attached log file: {log_file.name}")
            except Exception as e:
                _console_print(f"   ⚠️ Failed to attach logs: {e}")
        
        # Send email
        try:
            # Get SMTP configuration
            if self.config['provider'] in self.SMTP_PROVIDERS:
                provider_config = self.SMTP_PROVIDERS[self.config['provider']]
                smtp_server = provider_config['server']
                smtp_port = provider_config['port']
                use_tls = provider_config['use_tls']
            else:
                smtp_server = self.config['smtp_server']
                smtp_port = self.config['smtp_port']
                use_tls = self.config['use_tls']
            
            # Connect to SMTP server
            _console_print(f"   Connecting to {smtp_server}:{smtp_port}...")

            # RFC 5321 §4.1.3: clients without a matching PTR record must use
            # address-literal format "[IP]" so the server can't reject it as
            # "Forged HELO" or "LOCALDOMAIN".  We probe which local interface
            # would be used to reach the SMTP server, then wrap it in brackets.
            import socket as _sock
            try:
                _probe = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
                _probe.connect((smtp_server, smtp_port))
                ehlo_name = f'[{_probe.getsockname()[0]}]'
                _probe.close()
            except Exception:
                ehlo_name = f'[127.0.0.1]'

            # Port 465 uses implicit SSL (SMTP_SSL); all others use STARTTLS or plain
            if smtp_port == 465:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port)
                server.ehlo(ehlo_name)
            elif use_tls:
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.ehlo(ehlo_name)
                server.starttls()
                server.ehlo(ehlo_name)   # re-EHLO after STARTTLS
            else:
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.ehlo(ehlo_name)
            
            # Login if required
            if self.config['username'] and self.config['password']:
                server.login(self.config['username'], self.config['password'])
            
            # Send email
            all_recipients = (
                self.config['recipients'] + 
                self.config['cc_recipients'] + 
                self.config['bcc_recipients']
            )
            
            try:
                server.send_message(msg, to_addrs=all_recipients)
                server.quit()
                self._record_alert(alert_type, severity)
                _console_print(f"✓ Alert email sent to {len(all_recipients)} recipients")
                self._last_send_error = ''
                return True
            except (smtplib.SMTPRecipientsRefused,
                    smtplib.SMTPDataError,
                    smtplib.SMTPSenderRefused) as e:
                # Parse server challenge code from error message.
                # Many spam filters respond with "resend with code XYZ appended to subject"

                # Build a plain-text version of the error — SMTPRecipientsRefused
                # stores per-recipient tuples of (code, bytes_msg), so we must decode.
                err_str = str(e)
                if hasattr(e, 'recipients') and e.recipients:
                    for _addr, (_code, _msg) in e.recipients.items():
                        if isinstance(_msg, bytes):
                            err_str += ' ' + _msg.decode('utf-8', errors='replace')
                        else:
                            err_str += ' ' + str(_msg)
                elif hasattr(e, 'smtp_error'):
                    _se = e.smtp_error
                    err_str += ' ' + (_se.decode('utf-8', errors='replace')
                                      if isinstance(_se, bytes) else str(_se))

                challenge = None
                m = _re.search(
                    r'(?:resend(?:\s+it)?\s+with\s+(?:the\s+)?code\s+)([A-Za-z0-9]{6,20})',
                    err_str, _re.IGNORECASE
                )
                if m:
                    challenge = m.group(1)

                smtp_code = getattr(e, 'smtp_code', None) or (
                    list(e.recipients.values())[0][0]
                    if hasattr(e, 'recipients') and e.recipients else 0
                )

                err_lower = err_str.lower()
                is_greylisting = smtp_code in (450, 451) and 'greylisting' in err_lower
                is_spam_challenge = (
                    is_greylisting or
                    challenge is not None or
                    (smtp_code == 554 and (
                        '4.7.1' in err_str or '5.7.1' in err_str or
                        'greylisting' in err_lower or 'unsolicited' in err_lower or
                        'localdomain' in err_lower or 'resend' in err_lower or
                        'spam' in err_lower
                    )) or
                    '4.7.1' in err_str or '5.7.1' in err_str or
                    'greylisting' in err_lower or 'unsolicited' in err_lower or
                    'localdomain' in err_lower
                )

                if is_spam_challenge:
                    try:
                        server.quit()
                    except Exception:
                        pass

                    tag = challenge or 'NOTSPAMTAG'
                    _console_print(f"   Spam challenge detected (code={smtp_code}) — "
                                   f"server said: {err_str[:300]!r}")

                    # If this is pure greylisting (451) with only the
                    # generic NOTSPAMTAG placeholder (not a real per-
                    # session code), don't retry — the server will
                    # accept the message once the greylist period
                    # expires (typically 5-15 minutes).
                    if is_greylisting and tag == 'NOTSPAMTAG':
                        _console_print("   Greylisting detected — email will be delivered "
                                       "automatically in 5-15 minutes.")
                        self._enqueue_for_retry(
                            msg, self.config['from_email'], all_recipients,
                            alert_type, severity)
                        self._last_send_error = f"SPAM_CHALLENGE:{tag}:greylisting"
                        return False

                    _console_print(f"   Retrying with tag '{tag}'...")
                    import time as _time
                    _time.sleep(5)

                    # Patch subject with the server-requested tag
                    orig_subject = str(msg['Subject'])
                    del msg['Subject']
                    msg['Subject'] = f"{orig_subject} {tag}"
                    _console_print(f"   Connecting to {smtp_server}:{smtp_port}...")
                    _console_print(f"   Subject: {msg['Subject']}")

                    def _smtp_connect():
                        if smtp_port == 465:
                            s = smtplib.SMTP_SSL(smtp_server, smtp_port)
                            s.ehlo(ehlo_name)
                        elif use_tls:
                            s = smtplib.SMTP(smtp_server, smtp_port)
                            s.ehlo(ehlo_name)
                            s.starttls()
                            s.ehlo(ehlo_name)
                        else:
                            s = smtplib.SMTP(smtp_server, smtp_port)
                            s.ehlo(ehlo_name)
                        if self.config['username'] and self.config['password']:
                            s.login(self.config['username'], self.config['password'])
                        return s

                    try:
                        server2 = _smtp_connect()
                        # Use sendmail() with flattened message to ensure
                        # the Subject header (with tag) is sent verbatim
                        # in the DATA payload — some greylisting filters
                        # only inspect the raw DATA stream.
                        from_addr = self.config['from_email']
                        raw_msg = msg.as_string()
                        server2.sendmail(from_addr, all_recipients, raw_msg)
                        server2.quit()
                        self._record_alert(alert_type, severity)
                        _console_print("✓ Alert email sent (after spam-filter retry)")
                        self._last_send_error = ''
                        return True
                    except Exception as retry_err:
                        retry_err_str = str(retry_err)
                        retry_smtp_code = getattr(retry_err, 'smtp_code', 0)
                        if hasattr(retry_err, 'recipients') and retry_err.recipients:
                            for _a, (_c, _m) in retry_err.recipients.items():
                                retry_err_str += ' ' + (
                                    _m.decode('utf-8', errors='replace')
                                    if isinstance(_m, bytes) else str(_m))
                        elif hasattr(retry_err, 'smtp_error'):
                            _se2 = retry_err.smtp_error
                            retry_err_str += ' ' + (
                                _se2.decode('utf-8', errors='replace')
                                if isinstance(_se2, bytes) else str(_se2))

                        retry_err_lower = retry_err_str.lower()

                        # If the retry with the per-session code now gets
                        # greylisted (554→451), the code was accepted —
                        # treat as Config OK (greylisting will auto-clear).
                        retry_is_greylisting = (
                            retry_smtp_code in (450, 451) and
                            'greylisting' in retry_err_lower
                        ) or (
                            'greylisting' in retry_err_lower and
                            '4.7.1' in retry_err_str
                        )
                        if retry_is_greylisting:
                            _console_print("   Spam code accepted — server is now greylisting.")
                            _console_print("   Email will be delivered automatically "
                                           "in 5-15 minutes.")
                            self._enqueue_for_retry(
                                msg, self.config['from_email'], all_recipients,
                                alert_type, severity)
                            self._last_send_error = (
                                f"SPAM_CHALLENGE:{tag}:greylisting {retry_err}")
                            return False

                        # Check if server gave a new/different challenge code
                        _console_print(f"   Retry failed (code={retry_smtp_code}) — "
                                       f"server said: {retry_err_str[:300]!r}")

                        m2 = _re.search(
                            r'(?:resend(?:\s+it)?\s+with\s+(?:the\s+)?code\s+)([A-Za-z0-9]{6,20})',
                            retry_err_str, _re.IGNORECASE)
                        real_code = m2.group(1) if m2 else None
                        # Ignore NOTSPAMTAG — it's a generic greylisting
                        # placeholder, not a real per-session bypass code.
                        if real_code == 'NOTSPAMTAG':
                            real_code = None

                        if real_code and real_code != tag:
                            _console_print(f"   Server gave new code '{real_code}' — final attempt...")
                            _time.sleep(5)
                            # Append the new code (keep the old one too —
                            # server may require both codes in the subject).
                            cur_subj = str(msg['Subject'])
                            del msg['Subject']
                            msg['Subject'] = f"{cur_subj} {real_code}"
                            _console_print(f"   Subject: {msg['Subject']}")
                            try:
                                server3 = _smtp_connect()
                                from_addr = self.config['from_email']
                                raw_msg = msg.as_string()
                                server3.sendmail(from_addr, all_recipients, raw_msg)
                                server3.quit()
                                self._record_alert(alert_type, severity)
                                _console_print("✓ Alert email sent (challenge code accepted)")
                                self._last_send_error = ''
                                return True
                            except Exception as final_err:
                                self._last_send_error = f"SPAM_CHALLENGE:{real_code}:{final_err}"
                                return False

                        # Greylisting with no new code — server will accept
                        # the message once the greylist period expires.
                        if is_greylisting:
                            self._last_send_error = f"SPAM_CHALLENGE:{tag}:{retry_err}"
                            return False

                        self._last_send_error = f"SPAM_CHALLENGE:{tag}:{retry_err}"
                        return False
                raise

        except smtplib.SMTPException as e:
            err = str(e)
            _console_print(f"❌ SMTP error: {err}")
            self._last_send_error = err
            return False
        except Exception as e:
            _console_print(f"❌ Failed to send email: {e}")
            self._last_send_error = str(e)
            return False


def main():
    """Main entry point"""
    
    import argparse
    
    parser = argparse.ArgumentParser(description='Email Alerting System')
    parser.add_argument('--configure', action='store_true', help='Configure email settings')
    parser.add_argument('--test', action='store_true', help='Send test email')
    parser.add_argument('--status', action='store_true', help='Show configuration status')
    
    args = parser.parse_args()
    
    alerter = EmailAlertingSystem()
    
    if args.status:
        _console_print("\n" + "="*60)
        _console_print("Email Alerting System Status")
        _console_print("="*60)
        _console_print(f"Enabled: {alerter.config['enabled']}")
        _console_print(f"Provider: {alerter.config['provider']}")
        _console_print(f"From: {alerter.config['from_email']}")
        _console_print(f"Recipients: {', '.join(alerter.config['recipients']) if alerter.config['recipients'] else 'None'}")
        _console_print(f"Rate Limit: {alerter.config['rate_limit']['max_emails_per_hour']}/hour, {alerter.config['rate_limit']['max_emails_per_day']}/day")
        _console_print("\nAlert Levels:")
        for level, enabled in alerter.config['alert_levels'].items():
            status = "✓" if enabled else "✗"
            _console_print(f"  {status} {level}")
        _console_print("="*60 + "\n")
    
    elif args.configure:
        _console_print("\n" + "="*60)
        _console_print("Email Configuration Wizard")
        _console_print("="*60)
        
        _console_print("\nSelect email provider:")
        for i, provider in enumerate(EmailAlertingSystem.SMTP_PROVIDERS.keys(), 1):
            _console_print(f"  {i}. {provider}")
        
        provider_choice = input("\nProvider (1-4): ").strip()
        providers = list(EmailAlertingSystem.SMTP_PROVIDERS.keys())
        provider = providers[int(provider_choice) - 1] if provider_choice.isdigit() and 1 <= int(provider_choice) <= len(providers) else 'gmail'
        
        from_email = input("From email address: ").strip()
        username = input("SMTP username (usually same as from email): ").strip() or from_email
        password = input("SMTP password (use app password for Gmail): ").strip()
        
        recipients = []
        _console_print("\nEnter recipient email addresses (one per line, empty line to finish):")
        while True:
            recipient = input("  Recipient: ").strip()
            if not recipient:
                break
            recipients.append(recipient)
        
        # Update config
        alerter.config.update({
            'enabled': True,
            'provider': provider,
            'from_email': from_email,
            'username': username,
            'password': password,
            'recipients': recipients
        })
        
        # Save config
        try:
            with alerter.config_file.open('w') as f:
                json.dump(alerter.config, f, indent=2)
            _console_print("\n✓ Configuration saved")
        except Exception as e:
            _console_print(f"\n❌ Failed to save configuration: {e}")
    
    elif args.test:
        _console_print("\nSending test email...")
        
        success = alerter.send_alert(
            alert_type='TEST_ALERT',
            severity='INFO',
            details={
                'message': 'This is a test email from AntiRansomware',
                'test_timestamp': datetime.now().isoformat(),
                'status': 'Email system operational'
            },
            attach_logs=False
        )
        
        if success:
            _console_print("✓ Test email sent successfully")
        else:
            _console_print("❌ Test email failed")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
