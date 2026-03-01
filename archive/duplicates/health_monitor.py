#!/usr/bin/env python3
"""
Anti-Ransomware Health Check and Monitoring System
Production-grade health monitoring with alerting
"""

import os
import sys
import time
import json
import psutil
import socket
import threading
import requests
import smtplib
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography import x509
from cryptography.hazmat.backends import default_backend

@dataclass
class HealthCheckResult:
    """Health check result"""
    name: str
    status: str  # OK, WARNING, CRITICAL, UNKNOWN
    message: str
    timestamp: float
    duration_ms: float
    details: Dict[str, Any] = None
    
    def to_dict(self):
        return asdict(self)

@dataclass  
class Alert:
    """Alert configuration"""
    name: str
    level: str  # WARNING, CRITICAL
    condition: str
    threshold: float
    window: int  # seconds
    cooldown: int  # seconds
    enabled: bool = True
    last_triggered: float = 0

class HealthMonitor:
    """Production health monitoring system"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.checks: Dict[str, Callable] = {}
        self.results: List[HealthCheckResult] = []
        self.alerts: List[Alert] = []
        self.running = False
        self.monitor_thread = None
        self.alert_thread = None
        self.lock = threading.RLock()
        
        # Initialize built-in checks
        self._register_builtin_checks()
        
        # Load alerts from config
        self._load_alerts()
        
        # Notification handlers
        self.notification_handlers = {
            'email': self._send_email_alert,
            'webhook': self._send_webhook_alert,
            'syslog': self._send_syslog_alert,
            'file': self._write_file_alert
        }
    
    def _register_builtin_checks(self):
        """Register built-in health checks"""
        self.register_check("memory_usage", self._check_memory_usage)
        self.register_check("cpu_usage", self._check_cpu_usage)  
        self.register_check("disk_space", self._check_disk_space)
        self.register_check("file_handles", self._check_file_handles)
        self.register_check("network_connectivity", self._check_network_connectivity)
        self.register_check("service_ports", self._check_service_ports)
        self.register_check("kernel_driver", self._check_kernel_driver)
        self.register_check("usb_dongles", self._check_usb_dongles)
        self.register_check("policy_files", self._check_policy_files)
        self.register_check("certificate_expiry", self._check_certificate_expiry)
        self.register_check("log_rotation", self._check_log_rotation)
        self.register_check("database_health", self._check_database_health)
    
    def _load_alerts(self):
        """Load alert configurations"""
        alert_configs = self.config.get("monitoring", {}).get("alerts", [])
        
        for alert_config in alert_configs:
            alert = Alert(
                name=alert_config["name"],
                level=alert_config["level"],
                condition=alert_config["condition"],
                threshold=alert_config["threshold"],
                window=alert_config.get("window", 300),
                cooldown=alert_config.get("cooldown", 900),
                enabled=alert_config.get("enabled", True)
            )
            self.alerts.append(alert)
    
    def register_check(self, name: str, check_func: Callable):
        """Register a health check function"""
        self.checks[name] = check_func
    
    def start_monitoring(self, interval: int = 30):
        """Start continuous health monitoring"""
        if self.running:
            return
        
        self.running = True
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        
        # Start alert processing thread
        self.alert_thread = threading.Thread(
            target=self._alert_processing_loop,
            daemon=True
        )
        self.alert_thread.start()
    
    def stop_monitoring(self):
        """Stop health monitoring"""
        self.running = False
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        if self.alert_thread and self.alert_thread.is_alive():
            self.alert_thread.join(timeout=5)
    
    def _monitoring_loop(self, interval: int):
        """Main monitoring loop"""
        while self.running:
            try:
                self.run_all_checks()
                time.sleep(interval)
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(interval)
    
    def _alert_processing_loop(self):
        """Alert processing loop"""
        while self.running:
            try:
                self._process_alerts()
                time.sleep(10)  # Check alerts every 10 seconds
            except Exception as e:
                print(f"Error in alert processing: {e}")
                time.sleep(10)
    
    def run_all_checks(self) -> List[HealthCheckResult]:
        """Run all registered health checks"""
        current_results = []
        
        for check_name, check_func in self.checks.items():
            try:
                start_time = time.time()
                result = check_func()
                duration_ms = (time.time() - start_time) * 1000
                
                if isinstance(result, HealthCheckResult):
                    result.duration_ms = duration_ms
                    current_results.append(result)
                else:
                    # Legacy return format
                    status, message, details = result
                    current_results.append(HealthCheckResult(
                        name=check_name,
                        status=status,
                        message=message,
                        timestamp=time.time(),
                        duration_ms=duration_ms,
                        details=details
                    ))
            except Exception as e:
                current_results.append(HealthCheckResult(
                    name=check_name,
                    status="UNKNOWN",
                    message=f"Check failed: {str(e)}",
                    timestamp=time.time(),
                    duration_ms=0,
                    details={"error": str(e)}
                ))
        
        with self.lock:
            self.results = current_results
            
        return current_results
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get current health status"""
        with self.lock:
            results = self.results.copy()
        
        status_counts = {"OK": 0, "WARNING": 0, "CRITICAL": 0, "UNKNOWN": 0}
        
        for result in results:
            status_counts[result.status] += 1
        
        # Determine overall status
        overall_status = "OK"
        if status_counts["CRITICAL"] > 0:
            overall_status = "CRITICAL"
        elif status_counts["WARNING"] > 0:
            overall_status = "WARNING"
        elif status_counts["UNKNOWN"] > 0:
            overall_status = "UNKNOWN"
        
        return {
            "overall_status": overall_status,
            "timestamp": time.time(),
            "status_counts": status_counts,
            "checks": [result.to_dict() for result in results]
        }
    
    def _process_alerts(self):
        """Process alerts based on current health status"""
        current_status = self.get_health_status()
        current_time = time.time()
        
        for alert in self.alerts:
            if not alert.enabled:
                continue
            
            # Check cooldown
            if current_time - alert.last_triggered < alert.cooldown:
                continue
            
            # Evaluate alert condition
            if self._evaluate_alert_condition(alert, current_status):
                self._trigger_alert(alert, current_status)
                alert.last_triggered = current_time
    
    def _evaluate_alert_condition(self, alert: Alert, status: Dict[str, Any]) -> bool:
        """Evaluate if alert condition is met"""
        try:
            # Simple condition evaluation
            if alert.condition == "overall_status":
                return status["overall_status"] == alert.level
            elif alert.condition == "critical_count":
                return status["status_counts"]["CRITICAL"] >= alert.threshold
            elif alert.condition == "warning_count":
                return status["status_counts"]["WARNING"] >= alert.threshold
            elif alert.condition.startswith("check:"):
                check_name = alert.condition[6:]
                for check in status["checks"]:
                    if check["name"] == check_name:
                        return check["status"] == alert.level
            
            return False
        except Exception:
            return False
    
    def _trigger_alert(self, alert: Alert, status: Dict[str, Any]):
        """Trigger an alert"""
        alert_message = {
            "alert": alert.name,
            "level": alert.level,
            "condition": alert.condition,
            "threshold": alert.threshold,
            "timestamp": time.time(),
            "status": status
        }
        
        # Send notifications
        notification_config = self.config.get("monitoring", {}).get("notifications", {})
        
        for handler_type, config in notification_config.items():
            if config.get("enabled", False):
                try:
                    handler = self.notification_handlers.get(handler_type)
                    if handler:
                        handler(alert_message, config)
                except Exception as e:
                    print(f"Failed to send {handler_type} notification: {e}")
    
    def _send_email_alert(self, alert_message: Dict[str, Any], config: Dict[str, Any]):
        """Send email alert"""
        msg = MIMEMultipart()
        msg['From'] = config["from"]
        msg['To'] = ", ".join(config["to"])
        msg['Subject'] = f"[{alert_message['level']}] Anti-Ransomware Alert: {alert_message['alert']}"
        
        body = f"""
Anti-Ransomware Health Alert

Alert: {alert_message['alert']}
Level: {alert_message['level']}
Condition: {alert_message['condition']}
Timestamp: {datetime.fromtimestamp(alert_message['timestamp']).isoformat()}

System Status:
- Overall Status: {alert_message['status']['overall_status']}
- OK: {alert_message['status']['status_counts']['OK']}
- Warning: {alert_message['status']['status_counts']['WARNING']}
- Critical: {alert_message['status']['status_counts']['CRITICAL']}
- Unknown: {alert_message['status']['status_counts']['UNKNOWN']}

Failed Checks:
"""
        
        for check in alert_message['status']['checks']:
            if check['status'] != 'OK':
                body += f"- {check['name']}: {check['status']} - {check['message']}\n"
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(config["smtp_server"], config.get("smtp_port", 587))
        if config.get("use_tls", True):
            server.starttls()
        if config.get("username") and config.get("password"):
            server.login(config["username"], config["password"])
        
        server.send_message(msg)
        server.quit()
    
    def _send_webhook_alert(self, alert_message: Dict[str, Any], config: Dict[str, Any]):
        """Send webhook alert"""
        payload = {
            "alert": alert_message,
            "timestamp": alert_message["timestamp"],
            "service": "anti-ransomware"
        }
        
        headers = {"Content-Type": "application/json"}
        if config.get("auth_header"):
            headers[config["auth_header"]] = config["auth_token"]
        
        response = requests.post(
            config["url"],
            json=payload,
            headers=headers,
            timeout=config.get("timeout", 30)
        )
        response.raise_for_status()
    
    def _send_syslog_alert(self, alert_message: Dict[str, Any], config: Dict[str, Any]):
        """Send syslog alert"""
        import syslog
        
        priority = syslog.LOG_CRIT if alert_message["level"] == "CRITICAL" else syslog.LOG_WARNING
        message = f"Anti-Ransomware Alert: {alert_message['alert']} - {alert_message['condition']}"
        
        syslog.openlog("antiransomware", syslog.LOG_PID, syslog.LOG_DAEMON)
        syslog.syslog(priority, message)
        syslog.closelog()
    
    def _write_file_alert(self, alert_message: Dict[str, Any], config: Dict[str, Any]):
        """Write alert to file"""
        alert_file = Path(config["path"])
        alert_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(alert_file, "a") as f:
            f.write(f"{datetime.now().isoformat()} - {json.dumps(alert_message)}\n")
    
    # Built-in health checks
    
    def _check_memory_usage(self) -> HealthCheckResult:
        """Check memory usage"""
        process = psutil.Process()
        memory_info = process.memory_info()
        memory_mb = memory_info.rss / 1024 / 1024
        
        max_memory_mb = self.config.get("performance", {}).get("max_memory_usage", 100 * 1024 * 1024) / 1024 / 1024
        
        usage_percent = (memory_mb / max_memory_mb) * 100
        
        if usage_percent > 90:
            status = "CRITICAL"
            message = f"Memory usage critical: {memory_mb:.1f}MB ({usage_percent:.1f}% of limit)"
        elif usage_percent > 75:
            status = "WARNING"
            message = f"Memory usage high: {memory_mb:.1f}MB ({usage_percent:.1f}% of limit)"
        else:
            status = "OK"
            message = f"Memory usage normal: {memory_mb:.1f}MB ({usage_percent:.1f}% of limit)"
        
        return HealthCheckResult(
            name="memory_usage",
            status=status,
            message=message,
            timestamp=time.time(),
            duration_ms=0,
            details={
                "memory_mb": memory_mb,
                "limit_mb": max_memory_mb,
                "usage_percent": usage_percent
            }
        )
    
    def _check_cpu_usage(self) -> HealthCheckResult:
        """Check CPU usage"""
        process = psutil.Process()
        cpu_percent = process.cpu_percent(interval=1)
        
        if cpu_percent > 90:
            status = "CRITICAL"
            message = f"CPU usage critical: {cpu_percent}%"
        elif cpu_percent > 75:
            status = "WARNING"
            message = f"CPU usage high: {cpu_percent}%"
        else:
            status = "OK"
            message = f"CPU usage normal: {cpu_percent}%"
        
        return HealthCheckResult(
            name="cpu_usage",
            status=status,
            message=message,
            timestamp=time.time(),
            duration_ms=0,
            details={"cpu_percent": cpu_percent}
        )
    
    def _check_disk_space(self) -> HealthCheckResult:
        """Check disk space"""
        disk_usage = psutil.disk_usage('/')
        usage_percent = disk_usage.percent
        
        if usage_percent > 95:
            status = "CRITICAL"
            message = f"Disk space critical: {usage_percent}% used"
        elif usage_percent > 85:
            status = "WARNING"
            message = f"Disk space high: {usage_percent}% used"
        else:
            status = "OK"
            message = f"Disk space normal: {usage_percent}% used"
        
        return HealthCheckResult(
            name="disk_space",
            status=status,
            message=message,
            timestamp=time.time(),
            duration_ms=0,
            details={
                "total_gb": disk_usage.total / 1024**3,
                "used_gb": disk_usage.used / 1024**3,
                "free_gb": disk_usage.free / 1024**3,
                "usage_percent": usage_percent
            }
        )
    
    def _check_file_handles(self) -> HealthCheckResult:
        """Check open file handles"""
        process = psutil.Process()
        open_files = len(process.open_files())
        
        # Get system limit
        import resource
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        
        usage_percent = (open_files / soft_limit) * 100 if soft_limit > 0 else 0
        
        if usage_percent > 90:
            status = "CRITICAL"
            message = f"File handles critical: {open_files}/{soft_limit} ({usage_percent:.1f}%)"
        elif usage_percent > 75:
            status = "WARNING"
            message = f"File handles high: {open_files}/{soft_limit} ({usage_percent:.1f}%)"
        else:
            status = "OK"
            message = f"File handles normal: {open_files}/{soft_limit} ({usage_percent:.1f}%)"
        
        return HealthCheckResult(
            name="file_handles",
            status=status,
            message=message,
            timestamp=time.time(),
            duration_ms=0,
            details={
                "open_files": open_files,
                "soft_limit": soft_limit,
                "hard_limit": hard_limit,
                "usage_percent": usage_percent
            }
        )
    
    def _check_network_connectivity(self) -> HealthCheckResult:
        """Check network connectivity"""
        try:
            # Try to connect to a reliable server
            socket.create_connection(("8.8.8.8", 53), timeout=5)
            status = "OK"
            message = "Network connectivity normal"
            details = {"connectivity": True}
        except Exception as e:
            status = "CRITICAL"
            message = f"Network connectivity failed: {str(e)}"
            details = {"connectivity": False, "error": str(e)}
        
        return HealthCheckResult(
            name="network_connectivity",
            status=status,
            message=message,
            timestamp=time.time(),
            duration_ms=0,
            details=details
        )
    
    def _check_service_ports(self) -> HealthCheckResult:
        """Check service ports are listening"""
        required_ports = [
            self.config.get("network", {}).get("grpc", {}).get("port", 50051),
            self.config.get("network", {}).get("web", {}).get("port", 8080)
        ]
        
        listening_ports = [conn.laddr.port for conn in psutil.net_connections(kind='inet') 
                          if conn.status == 'LISTEN']
        
        missing_ports = [port for port in required_ports if port not in listening_ports]
        
        if missing_ports:
            status = "CRITICAL"
            message = f"Service ports not listening: {missing_ports}"
            details = {"missing_ports": missing_ports, "listening_ports": listening_ports}
        else:
            status = "OK"
            message = "All service ports listening"
            details = {"required_ports": required_ports, "listening_ports": listening_ports}
        
        return HealthCheckResult(
            name="service_ports",
            status=status,
            message=message,
            timestamp=time.time(),
            duration_ms=0,
            details=details
        )
    
    def _check_kernel_driver(self) -> HealthCheckResult:
        """Check kernel driver status"""
        service_name = self.config.get("kernel", {}).get("service_name", "AntiRansomwareDriver")
        status = "UNKNOWN"
        message = "Driver status unknown"
        details = {"service_name": service_name}

        try:
            if sys.platform == 'win32':
                svc = psutil.win_service_get(service_name)
                info = svc.as_dict()
                running = info.get('status') == 'running'
                status = "OK" if running else "CRITICAL"
                message = "Kernel driver loaded" if running else "Kernel driver not running"
                details.update({"status": info.get('status'), "binpath": info.get('binpath')})
            else:
                # On Unix-like systems, check /proc/modules for driver name
                driver_name = self.config.get("kernel", {}).get("module_name", "anti_ransomware")
                running = False
                try:
                    with open('/proc/modules', 'r') as f:
                        running = any(driver_name in line for line in f.readlines())
                except FileNotFoundError:
                    running = False
                status = "OK" if running else "CRITICAL"
                message = "Kernel module loaded" if running else "Kernel module not loaded"
                details.update({"module_name": driver_name, "loaded": running})
        except Exception as e:
            status = "WARNING"
            message = f"Kernel driver check failed: {e}"
            details["error"] = str(e)
        
        return HealthCheckResult(
            name="kernel_driver",
            status=status,
            message=message,
            timestamp=time.time(),
            duration_ms=0,
            details=details
        )
    
    def _check_usb_dongles(self) -> HealthCheckResult:
        """Check USB dongles availability"""
        status = "CRITICAL"
        message = "No USB dongles detected"
        details = {"dongles_detected": 0, "devices": []}

        try:
            partitions = psutil.disk_partitions(all=False)
            for p in partitions:
                is_removable = False
                if sys.platform == 'win32':
                    try:
                        import win32file
                        is_removable = win32file.GetDriveType(p.device) == win32file.DRIVE_REMOVABLE
                    except Exception:
                        is_removable = 'removable' in p.opts.lower()
                else:
                    is_removable = p.fstype in ['vfat', 'exfat'] or 'nosuid' in p.opts
                if is_removable:
                    details['devices'].append({
                        'device': p.device,
                        'mountpoint': p.mountpoint,
                        'fstype': p.fstype,
                        'opts': p.opts
                    })
            count = len(details['devices'])
            details['dongles_detected'] = count
            if count > 0:
                status = "OK"
                message = f"{count} USB dongle(s) detected"
            else:
                message = "No USB dongles detected"
        except Exception as e:
            status = "WARNING"
            message = f"USB dongle check failed: {e}"
            details['error'] = str(e)
        
        return HealthCheckResult(
            name="usb_dongles",
            status=status,
            message=message,
            timestamp=time.time(),
            duration_ms=0,
            details=details
        )
    
    def _check_policy_files(self) -> HealthCheckResult:
        """Check policy files exist and are valid"""
        policy_file = Path(self.config.get("policy", {}).get("file", "policies/default.yaml"))
        
        if not policy_file.exists():
            status = "CRITICAL"
            message = f"Policy file missing: {policy_file}"
            details = {"policy_file_exists": False, "path": str(policy_file)}
        else:
            # Check if file is readable and not empty
            try:
                stat = policy_file.stat()
                if stat.st_size == 0:
                    status = "WARNING"
                    message = f"Policy file empty: {policy_file}"
                    details = {"policy_file_exists": True, "size": 0, "path": str(policy_file)}
                else:
                    status = "OK"
                    message = f"Policy file valid: {policy_file}"
                    details = {"policy_file_exists": True, "size": stat.st_size, "path": str(policy_file)}
            except Exception as e:
                status = "WARNING"
                message = f"Policy file check failed: {e}"
                details = {"policy_file_exists": True, "error": str(e), "path": str(policy_file)}
        
        return HealthCheckResult(
            name="policy_files",
            status=status,
            message=message,
            timestamp=time.time(),
            duration_ms=0,
            details=details
        )
    
    def _check_certificate_expiry(self) -> HealthCheckResult:
        """Check certificate expiry"""
        cert_dir = Path("certs/")
        
        if not cert_dir.exists():
            status = "WARNING"
            message = "Certificate directory not found"
            details = {"cert_dir_exists": False}
        else:
            status = "OK"
            message = "Certificates valid"
            details = {"certificates_checked": 0, "expiring_soon": []}
            for cert_path in cert_dir.glob('*.pem'):
                try:
                    with open(cert_path, 'rb') as f:
                        data = f.read()
                    cert = x509.load_pem_x509_certificate(data, default_backend())
                    days_left = (cert.not_valid_after - datetime.utcnow()).days
                    details["certificates_checked"] += 1
                    if days_left <= 30:
                        details["expiring_soon"].append({"file": cert_path.name, "days_left": days_left})
                        status = "WARNING"
                        message = "Some certificates expiring soon"
                except Exception as e:
                    details.setdefault("errors", []).append({"file": cert_path.name, "error": str(e)})
                    status = "WARNING"
                    message = "Certificate parsing issues detected"
        
        return HealthCheckResult(
            name="certificate_expiry",
            status=status,
            message=message,
            timestamp=time.time(),
            duration_ms=0,
            details=details
        )
    
    def _check_log_rotation(self) -> HealthCheckResult:
        """Check log rotation and cleanup"""
        log_dir = Path("logs/")
        
        if not log_dir.exists():
            status = "WARNING"
            message = "Log directory not found"
            details = {"log_dir_exists": False}
        else:
            # Check log file sizes
            log_files = list(log_dir.glob("*.log"))
            large_files = [f for f in log_files if f.stat().st_size > 100 * 1024 * 1024]  # 100MB
            
            if large_files:
                status = "WARNING"
                message = f"Large log files detected: {[f.name for f in large_files]}"
                details = {"large_log_files": [f.name for f in large_files]}
            else:
                status = "OK"
                message = "Log rotation working normally"
                details = {"log_files_count": len(log_files)}
        
        return HealthCheckResult(
            name="log_rotation",
            status=status,
            message=message,
            timestamp=time.time(),
            duration_ms=0,
            details=details
        )
    
    def _check_database_health(self) -> HealthCheckResult:
        """Check database health"""
        db_path = Path(self.config.get("database", {}).get("path", "data/antiransomware.db"))
        
        if not db_path.exists():
            status = "WARNING"
            message = f"Database file not found: {db_path}"
            details = {"database_exists": False, "path": str(db_path)}
        else:
            try:
                import sqlite3
                conn = sqlite3.connect(str(db_path))
                cursor = conn.cursor()
                cursor.execute("PRAGMA integrity_check")
                result = cursor.fetchone()
                conn.close()
                
                if result[0] == "ok":
                    status = "OK"
                    message = "Database integrity check passed"
                    details = {"integrity_check": "ok", "path": str(db_path)}
                else:
                    status = "CRITICAL"
                    message = f"Database integrity check failed: {result[0]}"
                    details = {"integrity_check": result[0], "path": str(db_path)}
            except Exception as e:
                status = "CRITICAL"
                message = f"Database check failed: {e}"
                details = {"error": str(e), "path": str(db_path)}
        
        return HealthCheckResult(
            name="database_health",
            status=status,
            message=message,
            timestamp=time.time(),
            duration_ms=0,
            details=details
        )

def create_health_monitor(config: Dict[str, Any]) -> HealthMonitor:
    """Create and configure health monitor"""
    return HealthMonitor(config)
