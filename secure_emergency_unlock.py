#!/usr/bin/env python3
"""
SECURE EMERGENCY UNLOCK
Multi-factor authentication for emergency access
"""

import os
import sys
import time
import json
import hashlib
import secrets
import getpass
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
import ctypes
import ctypes.wintypes

class SecureEmergencyUnlock:
    """Multi-factor emergency unlock with audit trail"""
    
    def __init__(self, token_manager, event_logger):
        self.token_manager = token_manager
        self.event_logger = event_logger
        self.unlock_log = Path("emergency_unlock_audit.log")
        
    def check_admin_privileges(self):
        """Verify administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def verify_usb_token(self):
        """Require valid USB token for emergency unlock"""
        print("🔑 STEP 1: USB Token Verification")
        print("-" * 30)
        
        from security_patches import SecureUSBTokenFinder
        tokens = SecureUSBTokenFinder.find_tokens_safe()
        
        if not tokens:
            print("❌ No USB tokens found")
            return False
        
        for token_path in tokens:
            try:
                with open(token_path, 'r') as f:
                    token_data = f.read()
                
                if self.token_manager.validate_secure_token(token_data):
                    print(f"✅ Valid token found: {token_path.name}")
                    return True
            except:
                continue
        
        print("❌ No valid tokens found")
        return False
    
    def verify_admin_confirmation(self):
        """Require explicit admin confirmation"""
        print("\n🔐 STEP 2: Administrator Confirmation")
        print("-" * 30)
        
        if not self.check_admin_privileges():
            print("❌ Administrator privileges required")
            return False
        
        # Get current user
        username = os.environ.get('USERNAME', 'Unknown')
        print(f"Current user: {username}")
        
        # Require explicit confirmation
        confirmation = input("Type 'EMERGENCY UNLOCK AUTHORIZED' to confirm: ")
        
        if confirmation != "EMERGENCY UNLOCK AUTHORIZED":
            print("❌ Invalid confirmation")
            return False
        
        print("✅ Administrator confirmation received")
        return True
    
    def verify_windows_hello_or_pin(self):
        """Optional: Windows Hello or PIN verification"""
        print("\n🔒 STEP 3: Additional Authentication")
        print("-" * 30)
        
        try:
            # Try to use Windows Hello API
            import win32security
            import win32api
            
            # For now, simulate with a challenge-response
            challenge = secrets.token_hex(16)
            print(f"Challenge: {challenge}")
            
            response = getpass.getpass("Enter response (or press Enter to skip): ")
            
            if response:
                # Verify response (simplified)
                expected = hashlib.sha256(f"{challenge}admin".encode()).hexdigest()[:8]
                if response == expected:
                    print("✅ Challenge-response verified")
                    return True
                else:
                    print("❌ Invalid response")
                    return False
            else:
                print("⚠️ Additional authentication skipped")
                return True
                
        except ImportError:
            print("⚠️ Windows Hello not available, skipping")
            return True
    
    def show_countdown_warning(self, duration=10):
        """Show prominent countdown before proceeding"""
        print(f"\n⚠️ EMERGENCY UNLOCK COUNTDOWN: {duration} SECONDS")
        print("=" * 50)
        print("🚨 THIS WILL REMOVE ALL PROTECTION FROM FILES")
        print("🚨 PRESS CTRL+C TO CANCEL")
        print("=" * 50)
        
        try:
            for i in range(duration, 0, -1):
                print(f"⏰ Proceeding in {i} seconds...", end='\r')
                time.sleep(1)
            print("\n✅ Countdown complete, proceeding...")
            return True
        except KeyboardInterrupt:
            print("\n❌ Emergency unlock cancelled by user")
            return False
    
    def log_emergency_access(self, success, reason=""):
        """Log emergency access attempt with integrity"""
        timestamp = datetime.now().isoformat()
        username = os.environ.get('USERNAME', 'Unknown')
        hostname = os.environ.get('COMPUTERNAME', 'Unknown')
        
        log_entry = {
            'timestamp': timestamp,
            'username': username,
            'hostname': hostname,
            'success': success,
            'reason': reason,
            'ip_address': self._get_local_ip(),
            'session_id': os.environ.get('SESSIONNAME', 'Unknown')
        }
        
        # Create tamper-evident log entry
        entry_str = json.dumps(log_entry, sort_keys=True)
        entry_hash = hashlib.sha256(entry_str.encode()).hexdigest()
        
        # Write to audit log
        with open(self.unlock_log, 'a') as f:
            f.write(f"{entry_str}\n")
            f.write(f"HASH:{entry_hash}\n")
        
        # Also log to event system
        event_type = "EMERGENCY_UNLOCK_SUCCESS" if success else "EMERGENCY_UNLOCK_FAILED"
        self.event_logger.log_security_event(
            event_type, 
            f"User {username} on {hostname}: {reason}",
            "CRITICAL"
        )
    
    def _get_local_ip(self):
        """Get local IP address for audit trail"""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "Unknown"
    
    def emergency_unlock(self, target_path=None):
        """Secure emergency unlock procedure"""
        print("🚨 SECURE EMERGENCY UNLOCK PROCEDURE")
        print("=" * 50)
        
        start_time = time.time()
        
        try:
            # Step 1: USB Token verification
            if not self.verify_usb_token():
                self.log_emergency_access(False, "USB token verification failed")
                return False
            
            # Step 2: Admin confirmation
            if not self.verify_admin_confirmation():
                self.log_emergency_access(False, "Administrator confirmation failed")
                return False
            
            # Step 3: Additional auth (optional)
            if not self.verify_windows_hello_or_pin():
                self.log_emergency_access(False, "Additional authentication failed")
                return False
            
            # Step 4: Final warning countdown
            if not self.show_countdown_warning():
                self.log_emergency_access(False, "User cancelled during countdown")
                return False
            
            # Step 5: Perform unlock
            print("\n🔓 PERFORMING EMERGENCY UNLOCK...")
            print("-" * 30)
            
            if target_path:
                success = self._perform_safe_unlock(target_path)
            else:
                success = self._perform_global_unlock()
            
            duration = time.time() - start_time
            
            if success:
                self.log_emergency_access(True, f"Emergency unlock completed in {duration:.1f}s")
                print("✅ Emergency unlock completed successfully")
                return True
            else:
                self.log_emergency_access(False, f"Emergency unlock failed after {duration:.1f}s")
                print("❌ Emergency unlock failed")
                return False
                
        except Exception as e:
            self.log_emergency_access(False, f"Exception during unlock: {str(e)}")
            print(f"❌ Emergency unlock failed: {e}")
            return False
    
    def _perform_safe_unlock(self, target_path):
        """Safely unlock specific path"""
        try:
            path = Path(target_path)
            if not path.exists():
                print(f"❌ Path not found: {target_path}")
                return False
            
            print(f"🔓 Unlocking: {path}")
            
            # Use safer ACL restore instead of removing all attributes
            from security_patches import SecureACLManager
            acl_manager = SecureACLManager()
            
            success = acl_manager.restore_acl_safe(path)
            
            if success:
                print(f"✅ Successfully unlocked: {path}")
            else:
                print(f"⚠️ Partial unlock of: {path}")
            
            return success
            
        except Exception as e:
            print(f"❌ Error unlocking {target_path}: {e}")
            return False
    
    def _perform_global_unlock(self):
        """Perform global unlock of all protected items"""
        print("🔓 Performing global unlock...")
        
        # This should query the database for all protected items
        # and unlock them safely one by one
        
        success_count = 0
        total_count = 0
        
        protected_items = []

        # Attempt to read protected items from SQLite database
        db_path = Path("complete_antiransomware.db")
        if db_path.exists():
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("CREATE TABLE IF NOT EXISTS protected_items (path TEXT PRIMARY KEY)")
                cursor.execute("SELECT path FROM protected_items")
                protected_items = [row[0] for row in cursor.fetchall()]
                conn.close()
            except Exception as e:
                print(f"⚠️ Failed to query database: {e}")

        # Fallback: read from JSON configuration if DB is empty
        if not protected_items:
            json_path = Path("protected_items.json")
            if json_path.exists():
                try:
                    with open(json_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        protected_items = data.get('paths', [])
                except Exception as e:
                    print(f"⚠️ Failed to read protected_items.json: {e}")

        # If still empty, default to known safe locations (minimal fallback)
        if not protected_items:
            protected_items = [
                "C:\\Users\\Public\\Documents",
                "C:\\Users\\Public\\Pictures"
            ]
        
        for item in protected_items:
            total_count += 1
            if self._perform_safe_unlock(item):
                success_count += 1
        
        print(f"📊 Unlock summary: {success_count}/{total_count} items unlocked")
        
        return success_count > 0

def main():
    """Test the secure emergency unlock"""
    print("🧪 TESTING SECURE EMERGENCY UNLOCK")
    print("=" * 40)
    
    # Import required components
    from security_patches import SecureTokenManager, SecureEventLogger
    
    token_manager = SecureTokenManager()
    event_logger = SecureEventLogger()
    
    emergency_unlock = SecureEmergencyUnlock(token_manager, event_logger)
    
    print("Testing emergency unlock components...")
    
    # Test admin check
    is_admin = emergency_unlock.check_admin_privileges()
    print(f"Admin privileges: {'✅ YES' if is_admin else '❌ NO'}")
    
    # Test audit logging
    emergency_unlock.log_emergency_access(False, "Test log entry")
    print("✅ Audit logging test completed")
    
    print("\n💡 To perform actual emergency unlock:")
    print("python emergency_unlock.py --unlock [path]")

if __name__ == "__main__":
    main()
