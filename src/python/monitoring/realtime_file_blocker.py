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
    
    def __init__(self, token_manager, access_control, protected_paths, event_logger=None):
        super().__init__()
        self.token_manager = token_manager
        self.access_control = access_control
        self.protected_paths = protected_paths
        self.blocked_operations = 0
        self.allowed_operations = 0
        self.event_logger = event_logger
        
    def _should_allow_access(self, event_path):
        """Check if access should be allowed"""
        # Check if the file is under a protected directory
        abs_path = os.path.abspath(event_path)
        in_protected = any(
            abs_path.startswith(p + os.sep) or abs_path == p
            for p in self.protected_paths
        )
        if not in_protected:
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
        """Add path to real-time protection.
        ACL enforcement (icacls DENY) is handled by FourLayerProtection before this is called.
        This only registers the path for watchdog event monitoring.
        """
        path_str = str(os.path.abspath(path))
        self.protected_paths.add(path_str)
    
    def start_monitoring(self):
        """Start real-time file access monitoring"""
        if self.monitoring:
            return
            
        print("🛡️ Starting real-time file access blocker...")
        self.monitoring = True
        
        # Create observer and handler
        self.observer = Observer()
        self.handler = TokenGateHandler(self.token_manager, self.access_control, self.protected_paths, self.event_logger)
        
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
            try:
                self.observer.stop()
            except Exception:
                pass
            try:
                self.observer.join(timeout=5)
            except RuntimeError:
                pass  # thread was never started
            self.observer = None

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
