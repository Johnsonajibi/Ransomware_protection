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
import smtplib
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

            # Use the SMTP server's own domain as the EHLO name.
            # Using the from_email domain (e.g. gmail.com) against a corporate
            # SMTP server triggers spam/relay rejections. The server domain is
            # always the right value for an internal sender.
            ehlo_name = smtp_server

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
                import re as _re

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

                is_spam_challenge = (
                    challenge is not None or
                    smtp_code in (450, 451, 554) or
                    '4.7.1' in err_str or '5.7.1' in err_str or
                    'greylisting' in err_str.lower() or
                    'unsolicited' in err_str.lower() or
                    'localdomain' in err_str.lower()
                )

                if is_spam_challenge:
                    try:
                        server.quit()
                    except Exception:
                        pass

                    tag = challenge or 'NOTSPAMTAG'
                    _console_print(f"   Spam challenge detected (code={smtp_code}) — "
                                   f"retrying with tag '{tag}'...")
                    import time as _time
                    _time.sleep(2)

                    # Patch subject with the server-requested tag
                    orig_subject = str(msg['Subject'])
                    del msg['Subject']
                    msg['Subject'] = f"{orig_subject} {tag}"

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
                        server2.send_message(msg, to_addrs=all_recipients)
                        server2.quit()
                        self._record_alert(alert_type, severity)
                        _console_print("✓ Alert email sent (after spam-filter retry)")
                        self._last_send_error = ''
                        return True
                    except Exception as retry_err:
                        # Retry failed — check if server returned a NEW challenge code
                        retry_err_str = str(retry_err)
                        if hasattr(retry_err, 'recipients') and retry_err.recipients:
                            for _a, (_c, _m) in retry_err.recipients.items():
                                if isinstance(_m, bytes):
                                    retry_err_str += ' ' + _m.decode('utf-8', errors='replace')
                                else:
                                    retry_err_str += ' ' + str(_m)
                        elif hasattr(retry_err, 'smtp_error'):
                            _se2 = retry_err.smtp_error
                            retry_err_str += ' ' + (_se2.decode('utf-8', errors='replace')
                                                    if isinstance(_se2, bytes) else str(_se2))

                        m2 = _re.search(
                            r'(?:resend(?:\s+it)?\s+with\s+(?:the\s+)?code\s+)([A-Za-z0-9]{6,20})',
                            retry_err_str, _re.IGNORECASE
                        )
                        real_code = m2.group(1) if m2 else None

                        if real_code and real_code != tag:
                            _console_print(f"   Server provided real code '{real_code}' — final attempt...")
                            _time.sleep(2)
                            # Replace tag in subject with the real code
                            cur_subj = str(msg['Subject'])
                            del msg['Subject']
                            msg['Subject'] = cur_subj.replace(tag, real_code)
                            try:
                                server3 = _smtp_connect()
                                server3.send_message(msg, to_addrs=all_recipients)
                                server3.quit()
                                self._record_alert(alert_type, severity)
                                _console_print("✓ Alert email sent (challenge code accepted)")
                                self._last_send_error = ''
                                return True
                            except Exception as final_err:
                                self._last_send_error = f"SMTP error after challenge: {final_err}"
                                return False
                        else:
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
