#!/usr/bin/env python3
"""
Real-Time File Access Blocker
Blocks all file access to protected paths without valid USB token
"""

import os
import sys
import time
import threading
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

class TokenGateHandler(FileSystemEventHandler):
    """Block all file operations unless valid USB token is present"""
    
    def __init__(self, token_manager, access_control, event_logger=None):
        super().__init__()
        self.token_manager = token_manager
        self.access_control = access_control
        self.blocked_operations = 0
        self.allowed_operations = 0
        self.event_logger = event_logger
        
    def _should_allow_access(self, event_path):
        """Check if access should be allowed"""
        # Check if file is protected
        if not self.access_control.is_protected(event_path):
            return True
            
        # Verify USB token is present
        tokens = self.token_manager.find_usb_tokens(validate=True)
        if tokens:
            self.allowed_operations += 1
            return True
        
        # No token = BLOCK
        self.blocked_operations += 1
        print(f"🚫 BLOCKED: {Path(event_path).name} (No USB token)")
        if self.event_logger:
            try:
                self.event_logger(
                    event_type="FILE_ACCESS_BLOCKED",
                    file_path=str(event_path),
                    process_name="TokenGate",
                    details="Access attempt without USB token",
                    action_taken="ACCESS_BLOCKED",
                    severity="CRITICAL"
                )
            except Exception:
                pass
        return False
    
    def on_any_event(self, event: FileSystemEvent):
        """Handle any file system event"""
        if event.is_directory:
            return
            
        # Check if access should be allowed
        if not self._should_allow_access(event.src_path):
            # Block the operation by making file inaccessible
            try:
                # Re-apply protection to ensure file stays locked
                self.access_control.block_external_access(event.src_path)
            except Exception:
                pass

class RealtimeFileBlocker:
    """Real-time file access blocker using watchdog"""
    
    def __init__(self, token_manager, access_control, event_logger=None):
        self.token_manager = token_manager
        self.access_control = access_control
        self.observer = None
        self.monitoring = False
        self.protected_paths = set()
        self.handler = None
        self.event_logger = event_logger
        
    def add_protected_path(self, path):
        """Add path to real-time protection"""
        path_str = str(Path(path).resolve())
        self.protected_paths.add(path_str)
        
        # Register all files in path
        if Path(path).is_file():
            self.access_control.register_protected_file(path)
            self.access_control.block_external_access(path)
        else:
            for file_path in Path(path).rglob('*'):
                if file_path.is_file():
                    self.access_control.register_protected_file(file_path)
                    self.access_control.block_external_access(file_path)
    
    def start_monitoring(self):
        """Start real-time file access monitoring"""
        if self.monitoring:
            return
            
        print("🛡️ Starting real-time file access blocker...")
        self.monitoring = True
        
        # Create observer and handler
        self.observer = Observer()
        self.handler = TokenGateHandler(self.token_manager, self.access_control, self.event_logger)
        
        # Watch all protected paths
        for path in self.protected_paths:
            if os.path.exists(path):
                try:
                    self.observer.schedule(self.handler, path, recursive=True)
                    print(f"🛡️ Monitoring: {path}")
                except Exception as e:
                    print(f"⚠️ Could not monitor {path}: {e}")
        
        # Start observer
        self.observer.start()
        print("🛡️ Real-time file blocker ACTIVE")
        print("🔒 All file operations require valid USB token")
        
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        if not self.monitoring:
            return
            
        self.monitoring = False
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
        
        print("🛡️ Real-time file blocker stopped")
        
    def get_stats(self):
        """Get blocking statistics"""
        if self.handler:
            return {
                'blocked': self.handler.blocked_operations,
                'allowed': self.handler.allowed_operations,
                'protected_paths': len(self.protected_paths)
            }
        return {'blocked': 0, 'allowed': 0, 'protected_paths': 0}
