#!/usr/bin/env python3
"""
Anti-Ransomware Production Configuration Management
Centralized configuration with validation, encryption, and hot-reload
"""

import os
import json
import yaml
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from cryptography.fernet import Fernet
import threading
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class ConfigValidationError(Exception):
    """Configuration validation error"""
    pass

class ConfigManager:
    """Production-grade configuration management"""
    
    def __init__(self, config_path: str = "config.yaml", encrypted: bool = True):
        self.config_path = Path(config_path)
        self.encrypted = encrypted
        self.config: Dict[str, Any] = {}
        self.watchers: Dict[str, callable] = {}
        self.lock = threading.RLock()
        self.observer = Observer()
        self.encryption_key = self._get_or_create_key()
        
        self.load_config()
        self._setup_file_watcher()
    
    def _get_or_create_key(self) -> bytes:
        """Get or create encryption key"""
        key_file = Path("config.key")
        
        if key_file.exists():
            with open(key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            # Store key securely (in production, use HSM/key vault)
            with open(key_file, "wb") as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Restrict permissions
            return key
    
    def load_config(self):
        """Load and validate configuration"""
        try:
            with self.lock:
                if not self.config_path.exists():
                    self._create_default_config()
                
                with open(self.config_path, "rb") as f:
                    data = f.read()
                
                # Decrypt if encrypted
                if self.encrypted:
                    fernet = Fernet(self.encryption_key)
                    data = fernet.decrypt(data)
                
                # Parse YAML/JSON
                config_str = data.decode('utf-8')
                if self.config_path.suffix.lower() in ['.yaml', '.yml']:
                    self.config = yaml.safe_load(config_str)
                else:
                    self.config = json.loads(config_str)
                
                self._validate_config()
                logging.info(f"Configuration loaded from {self.config_path}")
                
        except Exception as e:
            logging.error(f"Failed to load configuration: {e}")
            self._create_default_config()
    
    def save_config(self):
        """Save configuration with encryption"""
        try:
            with self.lock:
                # Serialize config
                if self.config_path.suffix.lower() in ['.yaml', '.yml']:
                    config_str = yaml.dump(self.config, default_flow_style=False, indent=2)
                else:
                    config_str = json.dumps(self.config, indent=2)
                
                data = config_str.encode('utf-8')
                
                # Encrypt if needed
                if self.encrypted:
                    fernet = Fernet(self.encryption_key)
                    data = fernet.encrypt(data)
                
                # Atomic write
                temp_path = self.config_path.with_suffix('.tmp')
                with open(temp_path, "wb") as f:
                    f.write(data)
                
                temp_path.replace(self.config_path)
                os.chmod(self.config_path, 0o600)
                
                logging.info(f"Configuration saved to {self.config_path}")
                
        except Exception as e:
            logging.error(f"Failed to save configuration: {e}")
            raise
    
    def _create_default_config(self):
        """Create default production configuration"""
        self.config = {
            "version": "1.0.0",
            "environment": "production",
            
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                "handlers": {
                    "file": {
                        "enabled": True,
                        "path": "logs/antiransomware.log",
                        "max_size": 10485760,  # 10MB
                        "backup_count": 10,
                        "rotate_on_startup": True
                    },
                    "syslog": {
                        "enabled": True,
                        "facility": "local0",
                        "address": "/dev/log"
                    },
                    "console": {
                        "enabled": False
                    }
                }
            },
            
            "security": {
                "require_dongle": True,
                "require_pin": True,
                "max_failed_attempts": 3,
                "lockout_duration": 300,
                "token_lifetime": 300,
                "encryption": {
                    "algorithm": "ed25519",
                    "pqc_enabled": True,
                    "hybrid_mode": True
                },
                "audit": {
                    "enabled": True,
                    "log_level": "full",
                    "retention_days": 90,
                    "tamper_detection": True
                }
            },
            
            "performance": {
                "max_concurrent_tokens": 10000,
                "token_cache_size": 1000,
                "cleanup_interval": 60,
                "max_memory_usage": 104857600,  # 100MB
                "gc_threshold": 85
            },
            
            "network": {
                "grpc": {
                    "enabled": True,
                    "bind_address": "127.0.0.1",
                    "port": 50051,
                    "tls_enabled": True,
                    "cert_path": "certs/server.crt",
                    "key_path": "certs/server.key",
                    "client_ca_path": "certs/ca.crt",
                    "max_connections": 100,
                    "keepalive_timeout": 30
                },
                "web": {
                    "enabled": True,
                    "bind_address": "127.0.0.1",
                    "port": 8080,
                    "tls_enabled": True,
                    "cert_path": "certs/web.crt",
                    "key_path": "certs/web.key",
                    "session_timeout": 3600,
                    "csrf_protection": True
                }
            },
            
            "database": {
                "type": "sqlite",
                "path": "data/antiransomware.db",
                "connection_pool": 5,
                "timeout": 30,
                "backup": {
                    "enabled": True,
                    "interval": 3600,
                    "retention": 7,
                    "path": "backups/"
                }
            },
            
            "monitoring": {
                "metrics": {
                    "enabled": True,
                    "port": 9090,
                    "path": "/metrics"
                },
                "health_check": {
                    "enabled": True,
                    "port": 8081,
                    "path": "/health"
                },
                "alerts": {
                    "enabled": True,
                    "webhook_url": "",
                    "email_smtp": "",
                    "thresholds": {
                        "denied_requests_per_minute": 10,
                        "failed_authentications_per_hour": 5,
                        "memory_usage_percent": 90,
                        "disk_usage_percent": 95
                    }
                }
            },
            
            "siem": {
                "elasticsearch": {
                    "enabled": False,
                    "urls": ["http://localhost:9200"],
                    "index_prefix": "antiransomware",
                    "username": "",
                    "password": "",
                    "verify_certs": True,
                    "timeout": 30
                },
                "splunk": {
                    "enabled": False,
                    "host": "localhost",
                    "port": 8088,
                    "token": "",
                    "index": "antiransomware",
                    "verify_ssl": True
                },
                "syslog": {
                    "enabled": True,
                    "server": "localhost",
                    "port": 514,
                    "facility": "local0",
                    "protocol": "udp"
                },
                "webhook": {
                    "enabled": False,
                    "url": "",
                    "headers": {},
                    "timeout": 10,
                    "retry_attempts": 3
                }
            },
            
            "policy": {
                "file": "policies/default.yaml",
                "reload_interval": 300,
                "signature_verification": True,
                "admin_key_path": "keys/admin.pub",
                "default_deny": True,
                "emergency_bypass": {
                    "enabled": True,
                    "duration": 3600,
                    "require_reason": True,
                    "audit_trail": True
                }
            },
            
            "hardware": {
                "dongles": {
                    "detection_interval": 5,
                    "supported_types": ["yubikey", "nitrokey", "safenet"],
                    "whitelist_file": "dongles/whitelist.json",
                    "revocation_check": True,
                    "revocation_url": ""
                },
                "tpm": {
                    "enabled": True,
                    "pcr_banks": [0, 1, 2, 3, 4, 5, 6, 7],
                    "attestation": True
                }
            }
        }
        
        self.save_config()
    
    def _validate_config(self):
        """Validate configuration structure and values"""
        required_sections = [
            "version", "environment", "logging", "security", 
            "performance", "network", "database", "policy"
        ]
        
        for section in required_sections:
            if section not in self.config:
                raise ConfigValidationError(f"Missing required section: {section}")
        
        # Validate specific values
        if self.config["security"]["token_lifetime"] < 60:
            raise ConfigValidationError("Token lifetime must be at least 60 seconds")
        
        if self.config["performance"]["max_concurrent_tokens"] < 1:
            raise ConfigValidationError("Max concurrent tokens must be positive")
        
        # Validate file paths exist
        policy_file = Path(self.config["policy"]["file"])
        if not policy_file.parent.exists():
            policy_file.parent.mkdir(parents=True, exist_ok=True)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        with self.lock:
            keys = key.split('.')
            value = self.config
            
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            
            return value
    
    def set(self, key: str, value: Any, save: bool = True):
        """Set configuration value using dot notation"""
        with self.lock:
            keys = key.split('.')
            config = self.config
            
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            
            config[keys[-1]] = value
            
            if save:
                self.save_config()
    
    def watch(self, key: str, callback: callable):
        """Watch for configuration changes"""
        self.watchers[key] = callback
    
    def _setup_file_watcher(self):
        """Set up file system watcher for hot-reload"""
        if not self.config_path.exists():
            return
        
        class ConfigFileHandler(FileSystemEventHandler):
            def __init__(self, config_manager):
                self.config_manager = config_manager
            
            def on_modified(self, event):
                if event.src_path == str(self.config_manager.config_path):
                    logging.info("Configuration file changed, reloading...")
                    try:
                        old_config = dict(self.config_manager.config)
                        self.config_manager.load_config()
                        self._notify_watchers(old_config, self.config_manager.config)
                    except Exception as e:
                        logging.error(f"Failed to reload configuration: {e}")
            
            def _notify_watchers(self, old_config, new_config):
                for key, callback in self.config_manager.watchers.items():
                    old_value = self._get_nested_value(old_config, key)
                    new_value = self._get_nested_value(new_config, key)
                    if old_value != new_value:
                        try:
                            callback(key, old_value, new_value)
                        except Exception as e:
                            logging.error(f"Error in config watcher callback: {e}")
            
            def _get_nested_value(self, config, key):
                keys = key.split('.')
                value = config
                for k in keys:
                    if isinstance(value, dict) and k in value:
                        value = value[k]
                    else:
                        return None
                return value
        
        self.observer.schedule(
            ConfigFileHandler(self),
            str(self.config_path.parent),
            recursive=False
        )
        self.observer.start()
        logging.info("Configuration file watcher started")
    
    def stop(self):
        """Stop configuration manager"""
        if self.observer:
            self.observer.stop()
            self.observer.join()

# Global configuration instance
config = None

def init_config(config_path: str = "config.yaml", encrypted: bool = True) -> ConfigManager:
    """Initialize global configuration"""
    global config
    config = ConfigManager(config_path, encrypted)
    return config

def get_config() -> ConfigManager:
    """Get global configuration instance"""
    global config
    if config is None:
        config = init_config()
    return config

if __name__ == "__main__":
    # Example usage
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize configuration
    cfg = init_config("test_config.yaml")
    
    # Get values
    print(f"Token lifetime: {cfg.get('security.token_lifetime')}")
    print(f"GRPC port: {cfg.get('network.grpc.port')}")
    
    # Set values
    cfg.set("security.token_lifetime", 600)
    
    # Watch for changes
    def on_token_lifetime_change(key, old_value, new_value):
        print(f"Token lifetime changed from {old_value} to {new_value}")
    
    cfg.watch("security.token_lifetime", on_token_lifetime_change)
    
    print("Configuration manager running. Press Ctrl+C to exit.")
    try:
        time.sleep(60)
    except KeyboardInterrupt:
        cfg.stop()
        print("Configuration manager stopped.")
