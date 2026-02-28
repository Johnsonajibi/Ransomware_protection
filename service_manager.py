#!/usr/bin/env python3
"""
Anti-Ransomware Production Service Manager
Windows Service / Linux Systemd / macOS LaunchDaemon integration
"""

import os
import sys
import signal
import time
import threading
import subprocess
import json
from pathlib import Path
from typing import Optional, Dict, Any
import psutil
import platform

# Import our modules
from config_manager import ConfigManager, init_config
from production_logger import ProductionLogger, init_logger

class ServiceManager:
    """Cross-platform service management"""
    
    def __init__(self, service_name: str = "antiransomware"):
        self.service_name = service_name
        self.platform = platform.system().lower()
        self.config: Optional[ConfigManager] = None
        self.logger: Optional[ProductionLogger] = None
        self.running = False
        self.shutdown_event = threading.Event()
        self.health_check_thread = None
        self.metrics_thread = None
    
    def initialize(self, config_path: str = None):
        """Initialize service with configuration and logging"""
        try:
            # Initialize configuration
            self.config = init_config(config_path or "config.yaml")
            
            # Initialize logger
            log_config = self.config.get("logging", {})
            self.logger = init_logger(self.service_name, log_config)
            
            self.logger.system_event("initialize", f"Service initializing on {self.platform}")
            
            # Setup signal handlers
            self._setup_signal_handlers()
            
            # Create necessary directories
            self._create_directories()
            
            # Validate configuration
            self._validate_environment()
            
            self.logger.system_event("initialize", "Service initialization complete")
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.system_event("initialize", f"Failed to initialize: {e}", level="ERROR")
            else:
                print(f"Failed to initialize service: {e}")
            return False
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            signal_name = signal.Signals(signum).name
            self.logger.system_event("signal", f"Received signal {signal_name}")
            self.shutdown()
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        if hasattr(signal, 'SIGHUP'):
            def reload_handler(signum, frame):
                self.logger.system_event("signal", "Received SIGHUP, reloading configuration")
                self.config.load_config()
            signal.signal(signal.SIGHUP, reload_handler)
    
    def _create_directories(self):
        """Create necessary directories with proper permissions"""
        directories = [
            self.config.get("logging.handlers.file.path", "logs/antiransomware.log"),
            self.config.get("database.path", "data/antiransomware.db"),
            self.config.get("database.backup.path", "backups/"),
            "certs/",
            "policies/",
            "keys/",
            "dongles/",
            "tmp/"
        ]
        
        for dir_path in directories:
            path = Path(dir_path)
            if path.suffix:  # It's a file, get parent directory
                path = path.parent
            
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)
                # Set secure permissions (owner read/write/execute only)
                os.chmod(path, 0o700)
                self.logger.system_event("directory", f"Created directory: {path}")
    
    def _validate_environment(self):
        """Validate environment and dependencies"""
        # Check required files
        required_files = [
            self.config.get("policy.file", "policies/default.yaml"),
            self.config.get("policy.admin_key_path", "keys/admin.pub")
        ]
        
        for file_path in required_files:
            if not Path(file_path).exists():
                self.logger.system_event("validation", f"Warning: Required file missing: {file_path}", level="WARNING")
        
        # Check network ports
        grpc_port = self.config.get("network.grpc.port", 50051)
        web_port = self.config.get("network.web.port", 8080)
        
        if self._is_port_in_use(grpc_port):
            raise RuntimeError(f"GRPC port {grpc_port} is already in use")
        
        if self._is_port_in_use(web_port):
            raise RuntimeError(f"Web port {web_port} is already in use")
        
        # Check memory limits
        max_memory = self.config.get("performance.max_memory_usage", 104857600)  # 100MB
        available_memory = psutil.virtual_memory().available
        
        if max_memory > available_memory * 0.8:
            self.logger.system_event("validation", 
                f"Warning: Max memory setting ({max_memory}) is high compared to available memory ({available_memory})",
                level="WARNING")
    
    def _is_port_in_use(self, port: int) -> bool:
        """Check if a port is in use"""
        for conn in psutil.net_connections():
            if conn.laddr.port == port:
                return True
        return False
    
    def start(self):
        """Start the service"""
        if self.running:
            self.logger.system_event("start", "Service already running")
            return True
        
        try:
            self.running = True
            self.shutdown_event.clear()
            
            self.logger.system_event("start", "Starting service")
            
            # Start health check thread
            self.health_check_thread = threading.Thread(target=self._health_check_loop, daemon=True)
            self.health_check_thread.start()
            
            # Start metrics collection thread
            self.metrics_thread = threading.Thread(target=self._metrics_loop, daemon=True)
            self.metrics_thread.start()
            
            # Platform-specific service registration
            if self.platform == "windows":
                self._register_windows_service()
            elif self.platform == "linux":
                self._register_systemd_service()
            elif self.platform == "darwin":
                self._register_launchd_service()
            
            self.logger.system_event("start", "Service started successfully")
            return True
            
        except Exception as e:
            self.logger.system_event("start", f"Failed to start service: {e}", level="ERROR")
            self.running = False
            return False
    
    def stop(self):
        """Stop the service"""
        if not self.running:
            return True
        
        self.logger.system_event("stop", "Stopping service")
        
        try:
            # Signal shutdown
            self.shutdown()
            
            # Wait for threads to finish
            if self.health_check_thread and self.health_check_thread.is_alive():
                self.health_check_thread.join(timeout=5)
            
            if self.metrics_thread and self.metrics_thread.is_alive():
                self.metrics_thread.join(timeout=5)
            
            self.logger.system_event("stop", "Service stopped successfully")
            return True
            
        except Exception as e:
            self.logger.system_event("stop", f"Error stopping service: {e}", level="ERROR")
            return False
    
    def shutdown(self):
        """Graceful shutdown"""
        self.running = False
        self.shutdown_event.set()
    
    def run(self):
        """Main service run loop"""
        self.logger.system_event("run", "Service main loop starting")
        
        try:
            # Main service loop
            while self.running and not self.shutdown_event.is_set():
                # Service-specific work would go here
                time.sleep(1)
                
        except Exception as e:
            self.logger.system_event("run", f"Error in main loop: {e}", level="ERROR")
        finally:
            self.logger.system_event("run", "Service main loop ended")
    
    def _health_check_loop(self):
        """Health check monitoring loop"""
        check_interval = self.config.get("monitoring.health_check.interval", 30)
        
        while self.running and not self.shutdown_event.wait(check_interval):
            try:
                self._perform_health_check()
            except Exception as e:
                self.logger.system_event("health_check", f"Health check failed: {e}", level="ERROR")
    
    def _perform_health_check(self):
        """Perform health check"""
        # Check memory usage
        process = psutil.Process()
        memory_info = process.memory_info()
        max_memory = self.config.get("performance.max_memory_usage", 104857600)
        
        if memory_info.rss > max_memory:
            self.logger.system_event("health_check", 
                f"Memory usage ({memory_info.rss}) exceeds limit ({max_memory})",
                level="WARNING")
        
        # Check disk usage
        disk_usage = psutil.disk_usage('/')
        if disk_usage.percent > 95:
            self.logger.system_event("health_check", 
                f"Disk usage critical: {disk_usage.percent}%",
                level="CRITICAL")
        
        # Check CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > 90:
            self.logger.system_event("health_check", 
                f"High CPU usage: {cpu_percent}%",
                level="WARNING")
    
    def _metrics_loop(self):
        """Metrics collection loop"""
        collection_interval = self.config.get("monitoring.metrics.interval", 60)
        
        while self.running and not self.shutdown_event.wait(collection_interval):
            try:
                self._collect_metrics()
            except Exception as e:
                self.logger.system_event("metrics", f"Metrics collection failed: {e}", level="ERROR")
    
    def _collect_metrics(self):
        """Collect system and security metrics"""
        # Get security metrics from logger
        security_metrics = self.logger.get_metrics()
        
        # Get system metrics
        process = psutil.Process()
        system_metrics = {
            'memory_usage_bytes': process.memory_info().rss,
            'cpu_percent': process.cpu_percent(),
            'open_files': len(process.open_files()),
            'threads': process.num_threads(),
            'uptime_seconds': time.time() - process.create_time()
        }
        
        # Combine metrics
        all_metrics = {
            'timestamp': time.time(),
            'security': security_metrics,
            'system': system_metrics
        }
        
        # Log metrics
        self.logger.system_event("metrics", json.dumps(all_metrics))
    
    def _register_windows_service(self):
        """Register Windows service"""
        if self.platform != "windows":
            return
        
        try:
            service_definition = {
                'DisplayName': 'Anti-Ransomware Protection Service',
                'Description': 'Kernel-enforced anti-ransomware protection with hardware root of trust',
                'StartType': 'Automatic',
                'ServiceType': 'OwnProcess',
                'ErrorControl': 'Normal',
                'BinaryPathName': f'"{sys.executable}" "{__file__}" --service'
            }
            
            # Use sc command to create service
            cmd = [
                'sc', 'create', self.service_name,
                'binPath=', service_definition['BinaryPathName'],
                'DisplayName=', service_definition['DisplayName'],
                'start=', 'auto'
            ]
            
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.system_event("service", "Windows service registered")
            
        except subprocess.CalledProcessError as e:
            self.logger.system_event("service", f"Failed to register Windows service: {e}", level="ERROR")
    
    def _register_systemd_service(self):
        """Register systemd service"""
        if self.platform != "linux":
            return
        
        service_file_content = f"""[Unit]
Description=Anti-Ransomware Protection Service
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {__file__} --service
Restart=always
RestartSec=10
User=root
WorkingDirectory={os.getcwd()}
Environment=PYTHONPATH={os.environ.get('PYTHONPATH', '')}

[Install]
WantedBy=multi-user.target
"""
        
        try:
            service_path = f"/etc/systemd/system/{self.service_name}.service"
            with open(service_path, 'w') as f:
                f.write(service_file_content)
            
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            subprocess.run(['systemctl', 'enable', self.service_name], check=True)
            
            self.logger.system_event("service", "Systemd service registered")
            
        except Exception as e:
            self.logger.system_event("service", f"Failed to register systemd service: {e}", level="ERROR")
    
    def _register_launchd_service(self):
        """Register macOS LaunchDaemon"""
        if self.platform != "darwin":
            return
        
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.{self.service_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{__file__}</string>
        <string>--service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>{os.getcwd()}</string>
</dict>
</plist>
"""
        
        try:
            plist_path = f"/Library/LaunchDaemons/com.{self.service_name}.plist"
            with open(plist_path, 'w') as f:
                f.write(plist_content)
            
            subprocess.run(['launchctl', 'load', plist_path], check=True)
            
            self.logger.system_event("service", "LaunchDaemon registered")
            
        except Exception as e:
            self.logger.system_event("service", f"Failed to register LaunchDaemon: {e}", level="ERROR")
    
    def status(self) -> Dict[str, Any]:
        """Get service status"""
        try:
            process = psutil.Process()
            return {
                'running': self.running,
                'pid': process.pid,
                'memory_mb': process.memory_info().rss / 1024 / 1024,
                'cpu_percent': process.cpu_percent(),
                'uptime_seconds': time.time() - process.create_time(),
                'threads': process.num_threads(),
                'open_files': len(process.open_files())
            }
        except Exception as e:
            return {'running': False, 'error': str(e)}

def main():
    """Main entry point"""
    service = ServiceManager("antiransomware")
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "--service":
            # Running as service
            if not service.initialize():
                sys.exit(1)
            
            if not service.start():
                sys.exit(1)
            
            try:
                service.run()
            except KeyboardInterrupt:
                pass
            finally:
                service.stop()
                
        elif command == "--install":
            # Install service
            if not service.initialize():
                sys.exit(1)
            
            platform_name = platform.system().lower()
            if platform_name == "windows":
                service._register_windows_service()
            elif platform_name == "linux":
                service._register_systemd_service()
            elif platform_name == "darwin":
                service._register_launchd_service()
            
            print(f"Service installed for {platform_name}")
            
        elif command == "--status":
            # Show status
            if not service.initialize():
                sys.exit(1)
            
            status = service.status()
            print(json.dumps(status, indent=2))
            
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)
    else:
        # Interactive mode
        if not service.initialize():
            sys.exit(1)
        
        print("Anti-Ransomware Service Manager")
        print("Starting service in interactive mode...")
        print("Press Ctrl+C to stop")
        
        if not service.start():
            sys.exit(1)
        
        try:
            service.run()
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            service.stop()

if __name__ == "__main__":
    main()
