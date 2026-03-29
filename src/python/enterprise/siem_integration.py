#!/usr/bin/env python3
"""
SIEM Integration Module
======================
Forward security events to SIEM systems

Supports:
- Syslog (RFC 5424) over TLS/TCP/UDP
- CEF (Common Event Format)
- Splunk, ELK, QRadar, Azure Sentinel
- Event enrichment with context
- Reliable delivery with retries

Author: Johnson Ajibi
Date: December 28, 2025
"""

import os
import json
import socket
import ssl
import time
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import logging
import logging.handlers

try:
    from security_event_logger import SecurityEventLogger
    HAS_LOGGER = True
except ImportError:
    HAS_LOGGER = False


class SIEMIntegration:
    """
    Forward security events to SIEM platforms
    
    Features:
    - Syslog RFC 5424 format
    - CEF (Common Event Format)
    - Multiple transport protocols (TLS, TCP, UDP)
    - Event enrichment
    - Retry logic
    - Platform-specific optimizations
    """
    
    # SIEM platform configurations
    SIEM_PLATFORMS = {
        'splunk': {
            'format': 'json',
            'protocol': 'tcp',
            'default_port': 514,
            'index_field': 'index',
            'sourcetype': 'antiransomware:security'
        },
        'elk': {
            'format': 'json',
            'protocol': 'tcp',
            'default_port': 5044,
            'index_pattern': 'antiransomware-%Y.%m.%d'
        },
        'qradar': {
            'format': 'cef',
            'protocol': 'udp',
            'default_port': 514,
            'device_vendor': 'AntiRansomware',
            'device_product': 'SecuritySuite',
            'device_version': '1.0'
        },
        'sentinel': {
            'format': 'json',
            'protocol': 'https',
            'workspace_id': '',
            'shared_key': ''
        },
        'generic_syslog': {
            'format': 'rfc5424',
            'protocol': 'udp',
            'default_port': 514
        }
    }
    
    # CEF severity mapping
    CEF_SEVERITY = {
        'CRITICAL': 10,
        'HIGH': 8,
        'MEDIUM': 5,
        'LOW': 3,
        'INFO': 1
    }
    
    def __init__(self, config_file: Optional[Path] = None):
        """Initialize SIEM integration"""
        
        if config_file is None:
            config_file = Path.home() / "AppData" / "Local" / "AntiRansomware" / "siem_config.json"
        
        self.config_file = Path(config_file)
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self.config = self._load_config()
        
        # Event logger
        self.logger = SecurityEventLogger() if HAS_LOGGER else None
        
        # Syslog handler
        self.syslog_handler = None
        if self.config['enabled']:
            self._setup_syslog()
        
        # Event counter
        self.events_sent = 0
        self.events_failed = 0
    
    def _load_config(self) -> Dict:
        """Load SIEM configuration"""
        
        default_config = {
            'enabled': False,
            'platform': 'generic_syslog',
            'siem_server': '',
            'siem_port': 514,
            'protocol': 'udp',  # udp, tcp, tls
            'use_tls': False,
            'tls_ca_cert': '',
            'tls_client_cert': '',
            'tls_client_key': '',
            'format': 'rfc5424',  # rfc5424, cef, json
            'facility': logging.handlers.SysLogHandler.LOG_USER,
            'hostname': socket.gethostname(),
            'app_name': 'AntiRansomware',
            'enrichment': {
                'add_hostname': True,
                'add_username': True,
                'add_pid': True,
                'add_system_info': True,
                'add_geo_location': False
            },
            'retry': {
                'enabled': True,
                'max_retries': 3,
                'retry_delay': 5
            },
            'severity_filter': ['CRITICAL', 'HIGH', 'MEDIUM']
        }
        
        if self.config_file.exists():
            try:
                with self.config_file.open('r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except PermissionError:
                import tempfile as _tf
                self.config_file = Path(_tf.gettempdir()) / 'AntiRansomware' / 'siem_config.json'
                self.config_file.parent.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                print(f"⚠️ Config load failed: {e}")
        else:
            # Save default config
            try:
                with self.config_file.open('w') as f:
                    json.dump(default_config, f, indent=2)
                print(f"✓ Default config saved to {self.config_file}")
            except PermissionError:
                import tempfile as _tf
                self.config_file = Path(_tf.gettempdir()) / 'AntiRansomware' / 'siem_config.json'
                self.config_file.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with self.config_file.open('w') as _f:
                        import json as _j; _j.dump(default_config, _f, indent=2)
                except Exception:
                    pass
            except Exception as e:
                print(f"⚠️ Config save failed: {e}")
        
        return default_config
    
    def _setup_syslog(self):
        """Setup syslog handler based on configuration"""
        
        try:
            server = self.config['siem_server']
            port = self.config['siem_port']
            
            if not server:
                print("⚠️ SIEM server not configured")
                return
            
            # Create syslog handler
            if self.config['protocol'] == 'udp':
                self.syslog_handler = logging.handlers.SysLogHandler(
                    address=(server, port),
                    facility=self.config['facility'],
                    socktype=socket.SOCK_DGRAM
                )
            elif self.config['protocol'] in ['tcp', 'tls']:
                # TCP/TLS requires custom socket
                self.syslog_handler = None  # Will use custom send method
            
            print(f"✓ Syslog configured: {server}:{port} ({self.config['protocol']})")
            
        except Exception as e:
            print(f"⚠️ Syslog setup failed: {e}")
    
    def _enrich_event(self, event: Dict) -> Dict:
        """
        Add contextual information to event
        
        Args:
            event: Original event dict
        
        Returns:
            Enriched event dict
        """
        
        enriched = event.copy()
        enrichment_config = self.config['enrichment']
        
        if enrichment_config['add_hostname']:
            enriched['hostname'] = self.config['hostname']
        
        if enrichment_config['add_username']:
            try:
                enriched['username'] = os.getlogin()
            except:
                enriched['username'] = 'UNKNOWN'
        
        if enrichment_config['add_pid']:
            enriched['process_id'] = os.getpid()
        
        if enrichment_config['add_system_info']:
            import platform
            enriched['os'] = platform.system()
            enriched['os_version'] = platform.version()
            enriched['architecture'] = platform.machine()
        
        return enriched
    
    def _format_rfc5424(self, event: Dict) -> str:
        """
        Format event as RFC 5424 syslog message
        
        Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        
        Args:
            event: Event dictionary
        
        Returns:
            RFC 5424 formatted string
        """
        
        # Calculate priority (facility * 8 + severity)
        severity_map = {'CRITICAL': 2, 'HIGH': 3, 'MEDIUM': 4, 'LOW': 5, 'INFO': 6}
        severity_code = severity_map.get(event.get('severity', 'INFO'), 6)
        priority = self.config['facility'] * 8 + severity_code
        
        # Timestamp in ISO 8601
        timestamp = datetime.fromtimestamp(event.get('timestamp', time.time())).isoformat()
        
        # Hostname
        hostname = self.config['hostname']
        
        # App name
        app_name = self.config['app_name']
        
        # Process ID
        procid = str(event.get('process_id', os.getpid()))
        
        # Message ID (event type)
        msgid = event.get('event_type', 'SECURITY_EVENT')
        
        # Structured data
        structured_data = '-'  # NIL value for now
        
        # Message (JSON encoded details)
        message = json.dumps(event.get('details', {}))
        
        syslog_msg = (
            f"<{priority}>1 {timestamp} {hostname} {app_name} "
            f"{procid} {msgid} {structured_data} {message}"
        )
        
        return syslog_msg
    
    def _format_cef(self, event: Dict) -> str:
        """
        Format event as CEF (Common Event Format)
        
        Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        
        Args:
            event: Event dictionary
        
        Returns:
            CEF formatted string
        """
        
        platform_config = self.SIEM_PLATFORMS.get(self.config['platform'], {})
        
        device_vendor = platform_config.get('device_vendor', 'AntiRansomware')
        device_product = platform_config.get('device_product', 'SecuritySuite')
        device_version = platform_config.get('device_version', '1.0')
        
        signature_id = event.get('event_type', 'SECURITY_EVENT')
        name = event.get('event_type', 'Security Event').replace('_', ' ')
        severity = self.CEF_SEVERITY.get(event.get('severity', 'INFO'), 1)
        
        # Extension fields
        extensions = []
        
        # Standard CEF fields
        extensions.append(f"rt={int(event.get('timestamp', time.time()) * 1000)}")
        
        if 'file_path' in event:
            extensions.append(f"fname={event['file_path']}")
        
        if 'process_name' in event:
            extensions.append(f"sprocess={event['process_name']}")
        
        if 'process_id' in event:
            extensions.append(f"spid={event['process_id']}")
        
        if 'user_account' in event:
            extensions.append(f"suser={event['user_account']}")
        
        # Add details as custom fields
        details = event.get('details', {})
        for key, value in details.items():
            safe_key = key.replace('_', '')
            safe_value = str(value).replace('=', '\\=').replace('|', '\\|')
            extensions.append(f"cs1={safe_value} cs1Label={key}")
        
        extension_str = ' '.join(extensions)
        
        cef_msg = (
            f"CEF:0|{device_vendor}|{device_product}|{device_version}|"
            f"{signature_id}|{name}|{severity}|{extension_str}"
        )
        
        return cef_msg
    
    def _format_json(self, event: Dict) -> str:
        """
        Format event as JSON
        
        Args:
            event: Event dictionary
        
        Returns:
            JSON formatted string
        """
        
        # Add platform-specific fields
        if self.config['platform'] == 'splunk':
            event['sourcetype'] = self.SIEM_PLATFORMS['splunk']['sourcetype']
        elif self.config['platform'] == 'elk':
            index_pattern = self.SIEM_PLATFORMS['elk']['index_pattern']
            event['@timestamp'] = datetime.now().isoformat()
            event['_index'] = datetime.now().strftime(index_pattern)
        
        return json.dumps(event)
    
    def _send_tcp(self, message: str, use_tls: bool = False) -> bool:
        """
        Send message via TCP/TLS
        
        Args:
            message: Formatted message
            use_tls: Whether to use TLS
        
        Returns:
            True if sent successfully
        """
        
        try:
            server = self.config['siem_server']
            port = self.config['siem_port']
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            if use_tls:
                # SAFE: Secure default context with strict TLS 1.2+ enforcement
                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True
                
                # Load CA cert if provided
                if self.config['tls_ca_cert']:
                    context.load_verify_locations(self.config['tls_ca_cert'])
                
                # Load client cert if provided
                if self.config['tls_client_cert'] and self.config['tls_client_key']:
                    context.load_cert_chain(
                        self.config['tls_client_cert'],
                        self.config['tls_client_key']
                    )
                
                # Wrap socket with TLS
                sock = context.wrap_socket(sock, server_hostname=server)
            
            # Connect and send
            sock.connect((server, port))
            sock.sendall(message.encode('utf-8') + b'\n')
            sock.close()
            
            return True
            
        except ssl.SSLError as e:
            logging.error(f"TLS handshake failed: {e}", exc_info=True)
            return False
        except Exception as e:
            logging.error(f"TCP send failed: {e}", exc_info=True)
            return False
    
    def _send_udp(self, message: str) -> bool:
        """
        Send message via UDP
        
        Args:
            message: Formatted message
        
        Returns:
            True if sent successfully
        """
        
        try:
            server = self.config['siem_server']
            port = self.config['siem_port']
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message.encode('utf-8'), (server, port))
            sock.close()
            
            return True
            
        except Exception as e:
            print(f"⚠️ UDP send failed: {e}")
            return False
    
    def send_event(self, event: Dict, retry: bool = True) -> bool:
        """
        Send security event to SIEM
        
        Args:
            event: Event dictionary
            retry: Whether to retry on failure
        
        Returns:
            True if sent successfully
        """
        
        if not self.config['enabled']:
            return False
        
        # Check severity filter
        severity = event.get('severity', 'INFO')
        if severity not in self.config['severity_filter']:
            return False
        
        # Enrich event
        enriched_event = self._enrich_event(event)
        
        # Format event
        format_type = self.config['format']
        
        if format_type == 'rfc5424':
            message = self._format_rfc5424(enriched_event)
        elif format_type == 'cef':
            message = self._format_cef(enriched_event)
        elif format_type == 'json':
            message = self._format_json(enriched_event)
        else:
            print(f"⚠️ Unknown format: {format_type}")
            return False
        
        # Send based on protocol
        protocol = self.config['protocol']
        max_retries = self.config['retry']['max_retries'] if retry else 1
        
        for attempt in range(max_retries):
            success = False
            
            if protocol == 'udp':
                success = self._send_udp(message)
            elif protocol == 'tcp':
                success = self._send_tcp(message, use_tls=False)
            elif protocol == 'tls':
                success = self._send_tcp(message, use_tls=True)
            
            if success:
                self.events_sent += 1
                return True
            
            # Retry with delay
            if attempt < max_retries - 1:
                time.sleep(self.config['retry']['retry_delay'])
        
        self.events_failed += 1
        return False
    
    def forward_logged_events(self, start_time: Optional[float] = None, limit: int = 100):
        """
        Forward events from security event logger to SIEM
        
        Args:
            start_time: Only forward events after this timestamp
            limit: Maximum number of events to forward
        """
        
        if not self.logger or not HAS_LOGGER:
            print("⚠️ Security event logger not available")
            return
        
        print(f"\nForwarding events to SIEM ({self.config['platform']})...")
        
        # Get events
        events = self.logger.get_events(start_time=start_time, limit=limit)
        
        forwarded = 0
        failed = 0
        
        for signed_event in events:
            event = signed_event['event']
            
            if self.send_event(event):
                forwarded += 1
            else:
                failed += 1
        
        print(f"✓ Forwarded {forwarded} events")
        if failed > 0:
            print(f"⚠️ Failed to forward {failed} events")


def main():
    """Main entry point"""
    
    import argparse
    
    parser = argparse.ArgumentParser(description='SIEM Integration')
    parser.add_argument('--configure', action='store_true', help='Configure SIEM settings')
    parser.add_argument('--test', action='store_true', help='Send test event')
    parser.add_argument('--forward', action='store_true', help='Forward logged events to SIEM')
    parser.add_argument('--status', action='store_true', help='Show configuration status')
    parser.add_argument('--limit', type=int, default=100, help='Limit for event forwarding')
    
    args = parser.parse_args()
    
    siem = SIEMIntegration()
    
    if args.status:
        print("\n" + "="*60)
        print("SIEM Integration Status")
        print("="*60)
        print(f"Enabled: {siem.config['enabled']}")
        print(f"Platform: {siem.config['platform']}")
        print(f"Server: {siem.config['siem_server']}:{siem.config['siem_port']}")
        print(f"Protocol: {siem.config['protocol']}")
        print(f"Format: {siem.config['format']}")
        print(f"Severity Filter: {', '.join(siem.config['severity_filter'])}")
        print(f"\nStatistics:")
        print(f"  Events Sent: {siem.events_sent}")
        print(f"  Events Failed: {siem.events_failed}")
        print("="*60 + "\n")
    
    elif args.configure:
        print("\n" + "="*60)
        print("SIEM Configuration Wizard")
        print("="*60)
        
        print("\nSelect SIEM platform:")
        platforms = list(SIEMIntegration.SIEM_PLATFORMS.keys())
        for i, platform in enumerate(platforms, 1):
            print(f"  {i}. {platform}")
        
        platform_choice = input("\nPlatform (1-5): ").strip()
        platform = platforms[int(platform_choice) - 1] if platform_choice.isdigit() and 1 <= int(platform_choice) <= len(platforms) else 'generic_syslog'
        
        server = input("SIEM server address: ").strip()
        port_str = input(f"SIEM port ({SIEMIntegration.SIEM_PLATFORMS[platform]['default_port']}): ").strip()
        port = int(port_str) if port_str else SIEMIntegration.SIEM_PLATFORMS[platform]['default_port']
        
        # Update config
        platform_config = SIEMIntegration.SIEM_PLATFORMS[platform]
        siem.config.update({
            'enabled': True,
            'platform': platform,
            'siem_server': server,
            'siem_port': port,
            'protocol': platform_config['protocol'],
            'format': platform_config['format']
        })
        
        # Save config
        try:
            with siem.config_file.open('w') as f:
                json.dump(siem.config, f, indent=2)
            print("\n✓ Configuration saved")
        except Exception as e:
            print(f"\n❌ Failed to save configuration: {e}")
    
    elif args.test:
        print("\nSending test event to SIEM...")
        
        test_event = {
            'timestamp': time.time(),
            'event_type': 'TEST_EVENT',
            'severity': 'INFO',
            'details': {
                'message': 'This is a test event from AntiRansomware SIEM integration',
                'test_timestamp': datetime.now().isoformat()
            }
        }
        
        success = siem.send_event(test_event)
        
        if success:
            print("✓ Test event sent successfully")
        else:
            print("❌ Test event failed")
    
    elif args.forward:
        siem.forward_logged_events(limit=args.limit)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
