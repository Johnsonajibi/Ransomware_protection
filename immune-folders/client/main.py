"""
Immune Folders - Main Client Application
Secure folder protection using VeraCrypt containers with USB token authentication
"""

import os
import sys
import json
import time
import argparse
import threading
import signal
from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import our modules
from infra.tmp_ksp import SecureKeyProvider
from client.usb_token import USBTokenManager, TokenValidationResult, TokenInfo
from client.veracrypt import VeraCryptManager, MountResult, ContainerInfo
from util.log import TamperEvidentLogger, AuditHelper, AuditEventType, AuditLevel

@dataclass
class ImmuneFolderConfig:
    """Configuration for an immune folder"""
    folder_id: str
    folder_name: str
    container_id: str
    container_size_mb: int
    mount_point: str
    auto_lock_timeout: int
    permissions: List[str]

class ImmuneFoldersClient:
    """Main Immune Folders client application"""
    
    def __init__(self, config_path: str = None):
        self.config_path = Path(config_path or 
                              os.path.join(os.getenv('PROGRAMDATA', 'C:\\ProgramData'),
                                         'ImmuneFolders', 'config.json'))
        
        # Initialize components
        self.key_provider = SecureKeyProvider()
        self.token_manager = USBTokenManager()
        self.veracrypt_manager = VeraCryptManager()
        self.audit_logger = TamperEvidentLogger()
        self.audit_helper = AuditHelper(self.audit_logger)
        
        # Application state
        self.immune_folders: Dict[str, ImmuneFolderConfig] = {}
        self.mounted_folders: Dict[str, ContainerInfo] = {}
        self.current_token: Optional[TokenInfo] = None
        self.running = False
        
        # Auto-lock timer
        self.auto_lock_timer = None
        self.auto_lock_timeout = 1800  # 30 minutes default
        
        # Load configuration
        self._load_configuration()
        
        # Register for token events
        self.token_manager.register_token_callback(self._on_token_event)
        
        print("Immune Folders client initialized")
    
    def _load_configuration(self):
        """Load application configuration"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config_data = json.load(f)
                
                # Load immune folder configurations
                for folder_data in config_data.get("immune_folders", []):
                    folder_config = ImmuneFolderConfig(
                        folder_id=folder_data["folder_id"],
                        folder_name=folder_data["folder_name"],
                        container_id=folder_data["container_id"],
                        container_size_mb=folder_data["container_size_mb"],
                        mount_point=folder_data.get("mount_point", ""),
                        auto_lock_timeout=folder_data.get("auto_lock_timeout", 1800),
                        permissions=folder_data.get("permissions", ["read", "write"])
                    )
                    self.immune_folders[folder_config.folder_id] = folder_config
                
                # Load global settings
                self.auto_lock_timeout = config_data.get("auto_lock_timeout", 1800)
                
                print(f"Loaded configuration for {len(self.immune_folders)} immune folders")
            
        except Exception as e:
            print(f"Configuration loading error: {e}")
    
    def _save_configuration(self):
        """Save application configuration"""
        try:
            config_data = {
                "version": 1,
                "auto_lock_timeout": self.auto_lock_timeout,
                "immune_folders": []
            }
            
            for folder_config in self.immune_folders.values():
                config_data["immune_folders"].append({
                    "folder_id": folder_config.folder_id,
                    "folder_name": folder_config.folder_name,
                    "container_id": folder_config.container_id,
                    "container_size_mb": folder_config.container_size_mb,
                    "mount_point": folder_config.mount_point,
                    "auto_lock_timeout": folder_config.auto_lock_timeout,
                    "permissions": folder_config.permissions
                })
            
            # Ensure config directory exists
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            print("Configuration saved")
            
        except Exception as e:
            print(f"Configuration saving error: {e}")
    
    def _on_token_event(self, result: TokenValidationResult):
        """Handle USB token insertion/removal events"""
        if result.is_valid:
            print(f"Valid token detected: {result.token_info.token_id}")
            self.current_token = result.token_info
            
            # Log authentication success
            self.audit_helper.log_authentication(True, result.token_info.token_id)
            
            # Auto-mount accessible folders
            self._auto_mount_folders(result.folders_accessible)
            
            # Start auto-lock timer
            self._start_auto_lock_timer()
            
        else:
            if result.error_message == "Token removed":
                print("Token removed - locking all folders")
                self.current_token = None
                self._lock_all_folders()
            else:
                print(f"Token validation failed: {result.error_message}")
                # Log authentication failure
                self.audit_helper.log_authentication(False, None, result.error_message)
    
    def _auto_mount_folders(self, accessible_folders: List[str]):
        """Automatically mount folders accessible by the current token"""
        try:
            for folder_id in accessible_folders:
                if folder_id in self.immune_folders:
                    folder_config = self.immune_folders[folder_id]
                    
                    # Derive container password from token and folder
                    container_password = self._derive_container_password(folder_id)
                    
                    # Mount container
                    mount_result = self.veracrypt_manager.mount_container(
                        folder_config.container_id, 
                        container_password,
                        folder_config.mount_point if folder_config.mount_point else None
                    )
                    
                    if mount_result.result == MountResult.SUCCESS:
                        print(f"✓ Mounted {folder_config.folder_name} at {mount_result.mount_point}")
                        self.mounted_folders[folder_id] = mount_result.container_info
                        
                        # Log successful mount
                        self.audit_helper.log_container_operation(
                            "mount", folder_config.container_id, True,
                            {"folder_name": folder_config.folder_name, 
                             "mount_point": mount_result.mount_point}
                        )
                        
                        # Update mount point in config
                        folder_config.mount_point = mount_result.mount_point
                        
                    else:
                        print(f"✗ Failed to mount {folder_config.folder_name}: {mount_result.error_message}")
                        
                        # Log failed mount
                        self.audit_helper.log_container_operation(
                            "mount", folder_config.container_id, False,
                            {"folder_name": folder_config.folder_name,
                             "error": mount_result.error_message}
                        )
            
            # Save updated configuration
            self._save_configuration()
            
        except Exception as e:
            print(f"Auto-mount error: {e}")
    
    def _derive_container_password(self, folder_id: str) -> str:
        """Derive container password from folder master key"""
        try:
            # Retrieve folder master key
            folder_master_key = self.key_provider.retrieve_folder_master_key(folder_id)
            if not folder_master_key:
                raise ValueError(f"No master key found for folder: {folder_id}")
            
            # Get container ID
            folder_config = self.immune_folders.get(folder_id)
            if not folder_config:
                raise ValueError(f"No configuration found for folder: {folder_id}")
            
            # Derive container-specific key
            container_key = self.key_provider.derive_container_key(
                folder_master_key, folder_config.container_id
            )
            
            # Convert to password format (base64)
            import base64
            return base64.b64encode(container_key).decode('ascii')
            
        except Exception as e:
            print(f"Password derivation error: {e}")
            raise
    
    def _start_auto_lock_timer(self):
        """Start the auto-lock timer"""
        self._cancel_auto_lock_timer()
        
        self.auto_lock_timer = threading.Timer(
            self.auto_lock_timeout, 
            self._auto_lock_callback
        )
        self.auto_lock_timer.daemon = True
        self.auto_lock_timer.start()
        
        print(f"Auto-lock timer started ({self.auto_lock_timeout} seconds)")
    
    def _cancel_auto_lock_timer(self):
        """Cancel the auto-lock timer"""
        if self.auto_lock_timer:
            self.auto_lock_timer.cancel()
            self.auto_lock_timer = None
    
    def _auto_lock_callback(self):
        """Auto-lock callback when timer expires"""
        print("Auto-lock timeout reached - locking all folders")
        self._lock_all_folders()
        
        # Log auto-lock event
        self.audit_logger.log_event(
            AuditEventType.EMERGENCY_LOCK_ACTIVATED,
            {"reason": "auto_lock_timeout", "timeout_seconds": self.auto_lock_timeout},
            AuditLevel.INFO
        )
    
    def _lock_all_folders(self):
        """Lock (unmount) all currently mounted folders"""
        try:
            folders_to_unmount = list(self.mounted_folders.keys())
            
            for folder_id in folders_to_unmount:
                folder_config = self.immune_folders.get(folder_id)
                if folder_config:
                    success = self.veracrypt_manager.unmount_container(
                        folder_config.container_id, force=True
                    )
                    
                    if success:
                        print(f"✓ Locked {folder_config.folder_name}")
                        
                        # Log successful unmount
                        self.audit_helper.log_container_operation(
                            "unmount", folder_config.container_id, True,
                            {"folder_name": folder_config.folder_name}
                        )
                        
                    else:
                        print(f"✗ Failed to lock {folder_config.folder_name}")
                        
                        # Log failed unmount
                        self.audit_helper.log_container_operation(
                            "unmount", folder_config.container_id, False,
                            {"folder_name": folder_config.folder_name}
                        )
            
            # Clear mounted folders
            self.mounted_folders.clear()
            
            # Cancel auto-lock timer
            self._cancel_auto_lock_timer()
            
        except Exception as e:
            print(f"Lock all folders error: {e}")
    
    def create_immune_folder(self, folder_name: str, size_mb: int, 
                           permissions: List[str] = None) -> Optional[str]:
        """Create a new immune folder"""
        try:
            if not permissions:
                permissions = ["read", "write"]
            
            # Generate unique folder ID
            import uuid
            folder_id = str(uuid.uuid4())
            
            print(f"Creating immune folder: {folder_name} ({size_mb} MB)")
            
            # Generate folder master key
            folder_master_key = self.key_provider.generate_folder_master_key(folder_id)
            
            # Create VeraCrypt container
            container_password = self._derive_container_password(folder_id)
            container_id = self.veracrypt_manager.create_container(
                folder_id, size_mb, container_password
            )
            
            if not container_id:
                print("Failed to create VeraCrypt container")
                return None
            
            # Create folder configuration
            folder_config = ImmuneFolderConfig(
                folder_id=folder_id,
                folder_name=folder_name,
                container_id=container_id,
                container_size_mb=size_mb,
                mount_point="",
                auto_lock_timeout=self.auto_lock_timeout,
                permissions=permissions
            )
            
            # Add to configuration
            self.immune_folders[folder_id] = folder_config
            self._save_configuration()
            
            # Log folder creation
            self.audit_helper.log_container_operation(
                "create", container_id, True,
                {"folder_name": folder_name, "folder_id": folder_id, "size_mb": size_mb}
            )
            
            print(f"✓ Immune folder created: {folder_name} (ID: {folder_id})")
            return folder_id
            
        except Exception as e:
            print(f"Immune folder creation error: {e}")
            return None
    
    def delete_immune_folder(self, folder_id: str, secure_delete: bool = True) -> bool:
        """Delete an immune folder and its container"""
        try:
            folder_config = self.immune_folders.get(folder_id) 
            if not folder_config:
                print(f"Folder not found: {folder_id}")
                return False
            
            print(f"Deleting immune folder: {folder_config.folder_name}")
            
            # Unmount if mounted
            if folder_id in self.mounted_folders:
                self.veracrypt_manager.unmount_container(folder_config.container_id, force=True)
                del self.mounted_folders[folder_id]
            
            # Delete VeraCrypt container
            if not self.veracrypt_manager.delete_container(folder_config.container_id, secure_delete):
                print("Warning: Failed to delete VeraCrypt container")
            
            # Remove from configuration
            del self.immune_folders[folder_id]
            self._save_configuration()
            
            # Log folder deletion
            self.audit_helper.log_container_operation(
                "delete", folder_config.container_id, True,
                {"folder_name": folder_config.folder_name, "folder_id": folder_id}
            )
            
            print(f"✓ Immune folder deleted: {folder_config.folder_name}")
            return True
            
        except Exception as e:
            print(f"Immune folder deletion error: {e}")
            return False
    
    def create_usb_token(self, drive_path: str, folder_permissions: Dict[str, List[str]]) -> Optional[str]:
        """Create a USB token with specified folder permissions"""
        try:
            print(f"Creating USB token on drive: {drive_path}")
            
            token_id = self.token_manager.create_token(
                drive_path, folder_permissions, "ImmuneFolders"
            )
            
            if token_id:
                print(f"✓ USB token created: {token_id}")
                
                # Log token creation
                self.audit_logger.log_event(
                    AuditEventType.TOKEN_INSERTED,
                    {"token_id": token_id, "drive_path": drive_path, 
                     "folder_permissions": folder_permissions},
                    AuditLevel.SECURITY
                )
                
                return token_id
            else:
                print("✗ USB token creation failed")
                return None
                
        except Exception as e:
            print(f"USB token creation error: {e}")
            return None
    
    def list_immune_folders(self) -> Dict[str, ImmuneFolderConfig]:
        """List all immune folders"""
        return self.immune_folders.copy()
    
    def get_status(self) -> Dict[str, Any]:
        """Get current system status"""
        return {
            "current_token": self.current_token.token_id if self.current_token else None,
            "immune_folders_count": len(self.immune_folders),
            "mounted_folders_count": len(self.mounted_folders),
            "mounted_folders": list(self.mounted_folders.keys()),
            "auto_lock_timeout": self.auto_lock_timeout,
            "auto_lock_active": self.auto_lock_timer is not None
        }
    
    def emergency_lock(self):
        """Emergency lock - immediately lock all folders"""
        print("🚨 EMERGENCY LOCK ACTIVATED")
        
        # Log emergency lock
        self.audit_logger.log_event(
            AuditEventType.EMERGENCY_LOCK_ACTIVATED,
            {"reason": "manual_emergency_lock"},
            AuditLevel.CRITICAL
        )
        
        # Lock all folders
        self._lock_all_folders()
        
        print("All immune folders have been locked")
    
    def run_service(self):
        """Run as a background service"""
        print("Starting Immune Folders service...")
        
        # Log service start
        self.audit_logger.log_event(
            AuditEventType.SERVICE_STARTED,
            {"version": "1.0", "pid": os.getpid()},
            AuditLevel.INFO
        )
        
        self.running = True
        
        # Set up signal handlers for graceful shutdown
        def signal_handler(signum, frame):
            print(f"\nReceived signal {signum}, shutting down...")
            self.shutdown()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            # Main service loop
            while self.running:
                time.sleep(1)
                
                # Periodic health checks could go here
                # For now, just sleep and wait for token events
                
        except KeyboardInterrupt:
            print("\nService interrupted")
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Shutdown the service gracefully"""
        print("Shutting down Immune Folders...")
        
        self.running = False
        
        # Lock all folders
        self._lock_all_folders()
        
        # Cancel timers
        self._cancel_auto_lock_timer()
        
        # Cleanup components
        self.token_manager.cleanup()
        self.veracrypt_manager.cleanup()
        self.audit_logger.cleanup()
        
        # Log service stop
        self.audit_logger.log_event(
            AuditEventType.SERVICE_STOPPED,
            {"reason": "normal_shutdown"},
            AuditLevel.INFO
        )
        
        print("Immune Folders shutdown complete")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Immune Folders - Secure folder protection")
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Service command
    service_parser = subparsers.add_parser('service', help='Run as background service')
    
    # Create folder command
    create_parser = subparsers.add_parser('create-folder', help='Create immune folder')
    create_parser.add_argument('name', help='Folder name')
    create_parser.add_argument('--size', type=int, default=100, help='Size in MB (default: 100)')
    create_parser.add_argument('--permissions', nargs='+', default=['read', 'write'], 
                              help='Permissions (default: read write)')
    
    # Delete folder command
    delete_parser = subparsers.add_parser('delete-folder', help='Delete immune folder')
    delete_parser.add_argument('folder_id', help='Folder ID to delete')
    delete_parser.add_argument('--secure', action='store_true', 
                              help='Use secure deletion (multiple overwrites)')
    
    # Create token command
    token_parser = subparsers.add_parser('create-token', help='Create USB token')
    token_parser.add_argument('drive', help='USB drive path (e.g., E:\\)')
    token_parser.add_argument('--folders', nargs='+', required=True, 
                             help='Folder IDs to grant access to')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List immune folders and status')
    
    # Lock command
    lock_parser = subparsers.add_parser('lock', help='Emergency lock all folders')
    
    # Recovery commands
    recovery_parser = subparsers.add_parser('recovery', help='Recovery operations')
    recovery_subparsers = recovery_parser.add_subparsers(dest='recovery_command')
    
    export_recovery = recovery_subparsers.add_parser('export', help='Export recovery data')
    export_recovery.add_argument('folder_id', help='Folder ID')
    export_recovery.add_argument('passphrase', help='Recovery passphrase')
    export_recovery.add_argument('output_file', help='Output file path')
    
    import_recovery = recovery_subparsers.add_parser('import', help='Import recovery data')
    import_recovery.add_argument('recovery_file', help='Recovery file path')
    import_recovery.add_argument('passphrase', help='Recovery passphrase')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        # Initialize client
        client = ImmuneFoldersClient()
        
        if args.command == 'service':
            client.run_service()
            
        elif args.command == 'create-folder':
            folder_id = client.create_immune_folder(args.name, args.size, args.permissions)
            if folder_id:
                print(f"Folder created with ID: {folder_id}")
            else:
                print("Folder creation failed")
                sys.exit(1)
                
        elif args.command == 'delete-folder':
            if client.delete_immune_folder(args.folder_id, args.secure):
                print("Folder deleted successfully")
            else:
                print("Folder deletion failed")
                sys.exit(1)
                
        elif args.command == 'create-token':
            # Build folder permissions dictionary
            folder_permissions = {}
            for folder_id in args.folders:
                if folder_id in client.immune_folders:
                    folder_permissions[folder_id] = ["read", "write"]
                else:
                    print(f"Warning: Folder ID not found: {folder_id}")
            
            if folder_permissions:
                token_id = client.create_usb_token(args.drive, folder_permissions)
                if token_id:
                    print(f"Token created with ID: {token_id}")
                else:
                    print("Token creation failed")
                    sys.exit(1)
            else:
                print("No valid folder IDs provided")
                sys.exit(1)
                
        elif args.command == 'list':
            folders = client.list_immune_folders()
            status = client.get_status()
            
            print(f"\nImmune Folders Status:")
            print(f"Current Token: {status['current_token'] or 'None'}")
            print(f"Total Folders: {status['immune_folders_count']}")
            print(f"Mounted Folders: {status['mounted_folders_count']}")
            print(f"Auto-lock Timeout: {status['auto_lock_timeout']} seconds")
            
            if folders:
                print(f"\nConfigured Folders:")
                for folder_id, config in folders.items():
                    mounted = "✓" if folder_id in status['mounted_folders'] else "✗"
                    print(f"  {mounted} {config.folder_name}")
                    print(f"    ID: {folder_id}")
                    print(f"    Size: {config.container_size_mb} MB")
                    print(f"    Mount Point: {config.mount_point or 'Not mounted'}")
                    print(f"    Permissions: {', '.join(config.permissions)}")
                    print()
            else:
                print("No immune folders configured")
                
        elif args.command == 'lock':
            client.emergency_lock()
            
        elif args.command == 'recovery':
            if args.recovery_command == 'export':
                recovery_data = client.key_provider.export_recovery_data(
                    args.folder_id, args.passphrase
                )
                if recovery_data:
                    with open(args.output_file, 'wb') as f:
                        f.write(recovery_data)
                    print(f"Recovery data exported to: {args.output_file}")
                else:
                    print("Recovery export failed")
                    sys.exit(1)
                    
            elif args.recovery_command == 'import':
                with open(args.recovery_file, 'rb') as f:
                    recovery_data = f.read()
                
                folder_id = client.key_provider.import_recovery_data(
                    recovery_data, args.passphrase
                )
                if folder_id:
                    print(f"Recovery successful for folder: {folder_id}")
                else:
                    print("Recovery import failed")
                    sys.exit(1)
            else:
                recovery_parser.print_help()
        
    except KeyboardInterrupt:
        print("\nOperation cancelled")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
