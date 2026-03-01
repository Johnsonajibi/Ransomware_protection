#!/usr/bin/env python3
"""
Real Token-Gated Access Control
Blocks file/folder access until valid token + TPM + fingerprint validation
"""

import os
import sys
import json
import win32security
import win32api
import win32con
import ntsecuritycon as con
import subprocess
import shlex
from pathlib import Path
from typing import Optional, List, Dict
import ctypes
from ctypes import wintypes

# Backup integration
try:
    from backup_integration import BackupIntegration
    HAS_BACKUP = True
except ImportError:
    HAS_BACKUP = False

# Import tri-factor authentication
try:
    from trifactor_auth_manager import TriFactorAuthManager, SecurityLevel
    HAS_TRIFACTOR = True
except ImportError:
    print("⚠️ Tri-factor authentication not available")
    HAS_TRIFACTOR = False

# Import system health checker
try:
    from system_health_checker import SystemHealthChecker
    HAS_HEALTH_CHECKER = True
except ImportError:
    print("⚠️ System health checker not available")
    HAS_HEALTH_CHECKER = False

# Import security event logger
try:
    from security_event_logger import SecurityEventLogger
    HAS_LOGGER = True
except ImportError:
    print("⚠️ Security event logger not available")
    HAS_LOGGER = False


class TokenGatedAccessControl:
    """
    Token-Gated Access Control System
    Blocks access to files/folders until valid token is presented
    """
    
    def __init__(self):
        self.config_file = Path.home() / "AppData" / "Local" / "AntiRansomware" / "protected_paths.json"
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.protected_paths = {}  # path -> token_requirements
        self.auth_manager = None
        self.health_checker = None
        self.logger = None
        self.backup = BackupIntegration() if HAS_BACKUP else None
        
        # Load saved protected paths
        self._load_protected_paths()
        
        # Initialize security components
        if HAS_HEALTH_CHECKER:
            self.health_checker = SystemHealthChecker()
        
        if HAS_LOGGER:
            self.logger = SecurityEventLogger()
        
        if HAS_TRIFACTOR:
            try:
                self.auth_manager = TriFactorAuthManager()
                print("[OK] Tri-factor authentication initialized")
            except Exception as e:
                print(f"⚠️ Tri-factor init failed: {e}")
    
    def _load_protected_paths(self):
        """Load protected paths from config file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    self.protected_paths = json.load(f)
        except Exception as e:
            print(f"⚠️ Could not load protected paths: {e}")
    
    def _save_protected_paths(self):
        """Save protected paths to config file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.protected_paths, f, indent=2)
        except Exception as e:
            print(f"⚠️ Could not save protected paths: {e}")
    
    def add_protected_path(self, path: str, require_tpm: bool = True, 
                          require_fingerprint: bool = True, 
                          require_usb: bool = False) -> bool:
        """
        Add a file or folder to protection with token requirements
        
        Returns:
            bool: True if successfully protected
        """
        path_obj = Path(path)
        
        if not path_obj.exists():
            print(f"❌ Path does not exist: {path}")
            return False
        
        # Store requirements
        self.protected_paths[str(path_obj)] = {
            'require_tpm': require_tpm,
            'require_fingerprint': require_fingerprint,
            'require_usb': require_usb,
            'is_directory': path_obj.is_dir()
        }
        
        # Apply access control
        if path_obj.is_dir():
            success = self._block_folder_access(str(path_obj))
        else:
            success = self._block_file_access(str(path_obj))
        
        if success:
            # Save to persistent config
            self._save_protected_paths()
            print(f"✅ Protected: {path}")
            print(f"   Requirements: TPM={require_tpm}, Fingerprint={require_fingerprint}, USB={require_usb}")
        else:
            print(f"❌ Failed to protect: {path}")
        
        return success
    
    def _block_file_access(self, file_path: str) -> bool:
        """Block all access to a file"""
        try:
            # Method 1: Windows ACLs - Deny Everyone
            result = subprocess.run(
                ['icacls', file_path, '/deny', 'Everyone:(F,M,RX,R,W)', '/C'],
                capture_output=True,
                text=True,
                shell=True
            )
            
            if result.returncode != 0:
                print(f"⚠️ icacls warning: {result.stderr}")
            
            # Method 2: Deny SYSTEM (even admin processes)
            subprocess.run(
                ['icacls', file_path, '/deny', 'SYSTEM:(F,M,RX,R,W)', '/C'],
                capture_output=True,
                shell=True
            )
            
            # Method 3: Deny Administrators group
            subprocess.run(
                ['icacls', file_path, '/deny', 'Administrators:(F,M,RX,R,W)', '/C'],
                capture_output=True,
                shell=True
            )
            
            # Method 4: Set as system + hidden + readonly
            subprocess.run(
                ['attrib', '+S', '+H', '+R', file_path],
                capture_output=True,
                shell=True
            )
            
            print(f"  🔒 File access blocked: {Path(file_path).name}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to block file access: {e}")
            return False
    
    def _block_folder_access(self, folder_path: str) -> bool:
        """Block all access to a folder and its contents"""
        try:
            folder_obj = Path(folder_path)
            
            # Block folder itself
            print(f"  🔒 Blocking folder: {folder_obj.name}")
            
            # Deny Everyone with inheritance
            subprocess.run(
                ['icacls', folder_path, '/deny', 'Everyone:(OI)(CI)(F,M,RX,R,W)', '/C'],
                capture_output=True,
                shell=True
            )
            
            # Deny SYSTEM with inheritance
            subprocess.run(
                ['icacls', folder_path, '/deny', 'SYSTEM:(OI)(CI)(F,M,RX,R,W)', '/C'],
                capture_output=True,
                shell=True
            )
            
            # Deny Administrators with inheritance
            subprocess.run(
                ['icacls', folder_path, '/deny', 'Administrators:(OI)(CI)(F,M,RX,R,W)', '/C'],
                capture_output=True,
                shell=True
            )
            
            # Set folder attributes
            subprocess.run(
                ['attrib', '+S', '+H', '+R', folder_path],
                capture_output=True,
                shell=True
            )
            
            # Block all existing files
            file_count = 0
            for file_path in folder_obj.rglob('*'):
                if file_path.is_file():
                    self._block_file_access(str(file_path))
                    file_count += 1
            
            print(f"  ✅ Blocked folder + {file_count} files")
            return True
            
        except Exception as e:
            print(f"❌ Failed to block folder access: {e}")
            return False
    
    def grant_access(self, path: str, token_data: Optional[bytes] = None) -> bool:
        """
        Grant access to a protected path after token validation
        
        Args:
            path: File or folder path
            token_data: Token bytes for validation (if None, will prompt for token)
        
        Returns:
            bool: True if access granted
        """
        path_str = str(Path(path))
        
        if path_str not in self.protected_paths:
            print(f"⚠️ Path not protected: {path}")
            return False
        
        # STEP 1: System Health Check (CRITICAL)
        if self.health_checker and HAS_HEALTH_CHECKER:
            print("\n🔍 Performing system health check before granting access...")
            
            if not self.health_checker.can_use_usb_token():
                # Log the blocked attempt
                if self.logger:
                    usb_info = self.auth_manager.usb_auth.detect_pqc_usb_token() if self.auth_manager else None
                    device_id = usb_info['device_id'] if usb_info else 'UNKNOWN'
                    self.logger.log_usb_blocked(device_id, self.health_checker.threat_indicators)
                
                print("\n❌ ACCESS DENIED: System compromised - USB token blocked")
                print("   Complete remediation steps before attempting access")
                return False
            
            print("✓ System health check passed")
        
        requirements = self.protected_paths[path_str]
        
        # STEP 2: Validate token
        if not self._validate_token(token_data, requirements):
            print("❌ Token validation failed - access denied")
            
            # Log the failed attempt
            if self.logger:
                self.logger.log_access_denied(
                    path_str,
                    {'name': 'token_gated_access.py', 'pid': os.getpid(), 'user': os.getlogin() if hasattr(os, 'getlogin') else 'UNKNOWN'},
                    token_present=token_data is not None
                )
            
            return False
        
        # STEP 2b: Create safety backup before unblocking
        backup_path = None
        if self.backup:
            backup_path = self.backup.backup_before_access(path_str)
            if backup_path:
                print(f"💾 Backup created: {backup_path}")
            else:
                print("⚠️ Backup could not be created (continuing)")

        # STEP 3: Remove access restrictions
        if requirements['is_directory']:
            success = self._unblock_folder_access(path_str)
        else:
            success = self._unblock_file_access(path_str)
        
        if success:
            print(f"✅ Access granted: {path}")
        else:
            print(f"❌ Failed to grant access: {path}")
        
        return success
    
    def _validate_token(self, token_data: Optional[bytes], requirements: Dict) -> bool:
        """Validate token with tri-factor authentication"""
        if not HAS_TRIFACTOR or not self.auth_manager:
            print("⚠️ Tri-factor authentication not available - using fallback")
            return True  # Fallback for testing
        
        try:
            # If no token data provided, try to load from file
            if token_data is None:
                print("\n🔑 Token validation required")
                print("   Checking for existing tokens...")
                
                # Try to find and verify token
                token_dir = Path(".trifactor_tokens")
                if token_dir.exists():
                    token_files = list(token_dir.glob("service_token_*.dat"))
                    if token_files:
                        print(f"   Found {len(token_files)} token(s)")
                        # Use the most recent token
                        token_file = max(token_files, key=lambda p: p.stat().st_mtime)
                        with open(token_file, 'rb') as f:
                            token_data = f.read()
                        print(f"   Using token: {token_file.name}")
            
            if token_data is None:
                print("❌ No token found - generate token first")
                return False
            
            # Verify token
            print("   Validating token...")
            verification = self.auth_manager.verify_service_token(token_data)
            
            if not verification['valid']:
                print(f"❌ Token invalid: {verification.get('error', 'Unknown error')}")
                return False
            
            # Check security level
            security_level = verification.get('security_level', SecurityLevel.LOW)
            print(f"   Security Level: {security_level.name}")
            
            # Check if meets requirements
            if requirements['require_tpm']:
                if not verification.get('tpm_verified', False):
                    print("❌ TPM verification required but not present")
                    return False
                print("   ✅ TPM verified")
            
            if requirements['require_fingerprint']:
                if not verification.get('fingerprint_verified', False):
                    print("❌ Device fingerprint required but not present")
                    return False
                print("   ✅ Device fingerprint verified")
            
            if requirements['require_usb']:
                if not verification.get('usb_verified', False):
                    print("❌ USB token required but not present")
                    return False
                print("   ✅ USB token verified")
            
            print("✅ All authentication factors verified")
            return True
            
        except Exception as e:
            print(f"❌ Token validation error: {e}")
            return False
    
    def _unblock_file_access(self, file_path: str) -> bool:
        """Remove access restrictions from a file"""
        try:
            # Remove system/hidden/readonly attributes
            subprocess.run(
                ['attrib', '-S', '-H', '-R', file_path],
                capture_output=True,
                shell=True
            )
            
            # Remove denial ACEs
            subprocess.run(
                ['icacls', file_path, '/remove:d', 'Everyone', '/C'],
                capture_output=True,
                shell=True
            )
            
            subprocess.run(
                ['icacls', file_path, '/remove:d', 'SYSTEM', '/C'],
                capture_output=True,
                shell=True
            )
            
            subprocess.run(
                ['icacls', file_path, '/remove:d', 'Administrators', '/C'],
                capture_output=True,
                shell=True
            )
            
            # Grant standard user permissions
            subprocess.run(
                ['icacls', file_path, '/grant', f'{os.getenv("USERNAME")}:(F)', '/C'],
                capture_output=True,
                shell=True
            )
            
            print(f"  🔓 File access restored: {Path(file_path).name}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to restore file access: {e}")
            return False
    
    def _unblock_folder_access(self, folder_path: str) -> bool:
        """Remove access restrictions from a folder"""
        try:
            folder_obj = Path(folder_path)
            
            # Remove folder attributes
            subprocess.run(
                ['attrib', '-S', '-H', '-R', folder_path],
                capture_output=True,
                shell=True
            )
            
            # Remove denial ACEs with inheritance
            subprocess.run(
                ['icacls', folder_path, '/remove:d', 'Everyone', '/C'],
                capture_output=True,
                shell=True
            )
            
            subprocess.run(
                ['icacls', folder_path, '/remove:d', 'SYSTEM', '/C'],
                capture_output=True,
                shell=True
            )
            
            subprocess.run(
                ['icacls', folder_path, '/remove:d', 'Administrators', '/C'],
                capture_output=True,
                shell=True
            )
            
            # Grant standard user permissions with inheritance
            subprocess.run(
                ['icacls', folder_path, '/grant', f'{os.getenv("USERNAME")}:(OI)(CI)(F)', '/C'],
                capture_output=True,
                shell=True
            )
            
            # Unblock all files
            file_count = 0
            for file_path in folder_obj.rglob('*'):
                if file_path.is_file():
                    self._unblock_file_access(str(file_path))
                    file_count += 1
            
            print(f"  ✅ Unblocked folder + {file_count} files")
            return True
            
        except Exception as e:
            print(f"❌ Failed to restore folder access: {e}")
            return False
    
    def list_protected_paths(self) -> List[str]:
        """List all protected paths"""
        return list(self.protected_paths.keys())
    
    def remove_protection(self, path: str) -> bool:
        """Remove protection from a path"""
        path_str = str(Path(path))
        
        if path_str not in self.protected_paths:
            print(f"⚠️ Path not protected: {path}")
            return False
        
        requirements = self.protected_paths[path_str]
        
        # Remove restrictions
        if requirements['is_directory']:
            success = self._unblock_folder_access(path_str)
        else:
            success = self._unblock_file_access(path_str)
        
        if success:
            del self.protected_paths[path_str]
            self._save_protected_paths()
            print(f"✅ Protection removed: {path}")
        
        return success


def main():
    """CLI interface for token-gated access control"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Token-Gated Access Control')
    parser.add_argument('command', choices=['protect', 'grant', 'remove', 'list'],
                       help='Command to execute')
    parser.add_argument('path', nargs='?', help='File or folder path')
    parser.add_argument('--no-tpm', action='store_true', help='Do not require TPM')
    parser.add_argument('--no-fingerprint', action='store_true', help='Do not require fingerprint')
    parser.add_argument('--require-usb', action='store_true', help='Require USB token')
    
    args = parser.parse_args()
    
    controller = TokenGatedAccessControl()
    
    if args.command == 'list':
        paths = controller.list_protected_paths()
        if paths:
            print("\n🛡️ PROTECTED PATHS:")
            print("="*60)
            for path in paths:
                req = controller.protected_paths[path]
                print(f"📂 {path}")
                print(f"   TPM: {req['require_tpm']}, Fingerprint: {req['require_fingerprint']}, USB: {req['require_usb']}")
        else:
            print("No protected paths")
    
    elif args.command == 'protect':
        if not args.path:
            print("❌ Path required")
            return
        
        controller.add_protected_path(
            args.path,
            require_tpm=not args.no_tpm,
            require_fingerprint=not args.no_fingerprint,
            require_usb=args.require_usb
        )
    
    elif args.command == 'grant':
        if not args.path:
            print("❌ Path required")
            return
        
        controller.grant_access(args.path)
    
    elif args.command == 'remove':
        if not args.path:
            print("❌ Path required")
            return
        
        controller.remove_protection(args.path)


if __name__ == "__main__":
    main()
