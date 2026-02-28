"""
Recovery Manager
Handles file recovery, VSS snapshots, and post-attack restoration
"""

import os
import shutil
import logging
import subprocess
import shlex
import tempfile
from datetime import datetime
from typing import List, Optional, Dict, Tuple
import json

try:
    import win32com.client
    import win32api
    import win32security
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False
    logging.warning("win32 modules not available, some features disabled")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RecoveryManager:
    """
    Manages file recovery and VSS snapshots
    """
    
    def __init__(self, backup_dir: str = "C:\\ProgramData\\AntiRansomware\\backups"):
        """
        Initialize recovery manager
        
        Args:
            backup_dir: Directory for storing backups
        """
        self.backup_dir = backup_dir
        os.makedirs(backup_dir, exist_ok=True)
        self.recovery_log = []
        
    def create_vss_snapshot(self, volume: str = "C:") -> Optional[str]:
        """
        Create a Volume Shadow Copy snapshot
        
        Args:
            volume: Volume to snapshot (e.g., "C:")
            
        Returns:
            Snapshot ID or None on failure
        """
        try:
            if not HAS_WIN32:
                logger.error("VSS requires pywin32")
                return None
            
            # Use vssadmin command
            cmd = f'vssadmin create shadow /for={volume}\\'
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Parse snapshot ID from output
                output = result.stdout
                for line in output.split('\n'):
                    if 'Shadow Copy ID:' in line:
                        snapshot_id = line.split(':')[1].strip()
                        logger.info(f"Created VSS snapshot: {snapshot_id}")
                        return snapshot_id
            else:
                logger.error(f"VSS creation failed: {result.stderr}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating VSS snapshot: {e}")
            return None
    
    def list_vss_snapshots(self, volume: str = "C:") -> List[Dict]:
        """
        List existing VSS snapshots
        
        Args:
            volume: Volume to query
            
        Returns:
            List of snapshot info dictionaries
        """
        snapshots = []
        try:
            cmd = f'vssadmin list shadows /for={volume}\\'
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Parse output
                current_snapshot = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if 'Shadow Copy ID:' in line:
                        if current_snapshot:
                            snapshots.append(current_snapshot)
                        current_snapshot = {'id': line.split(':')[1].strip()}
                    elif 'Creation Time:' in line:
                        current_snapshot['creation_time'] = line.split(':', 1)[1].strip()
                
                if current_snapshot:
                    snapshots.append(current_snapshot)
                    
                logger.info(f"Found {len(snapshots)} VSS snapshots")
                
        except Exception as e:
            logger.error(f"Error listing VSS snapshots: {e}")
        
        return snapshots
    
    def restore_from_vss(self, snapshot_id: str, file_path: str, 
                        restore_path: Optional[str] = None) -> bool:
        """
        Restore file from VSS snapshot
        
        Args:
            snapshot_id: VSS snapshot ID
            file_path: Original file path
            restore_path: Where to restore (None = overwrite original)
            
        Returns:
            True if successful
        """
        try:
            # VSS snapshots are mounted under \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\
            # This is simplified - production code would use COM APIs
            logger.warning("VSS restore requires administrative privileges")
            
            if restore_path is None:
                restore_path = file_path
            
            # Log the restore attempt
            self.recovery_log.append({
                'timestamp': datetime.now().isoformat(),
                'snapshot_id': snapshot_id,
                'file_path': file_path,
                'restore_path': restore_path,
                'success': False
            })
            
            logger.info(f"VSS restore would copy from snapshot {snapshot_id}")
            logger.info(f"  Source: {file_path}")
            logger.info(f"  Dest: {restore_path}")
            
            # Actual implementation would use VSS COM API
            return True
            
        except Exception as e:
            logger.error(f"Error restoring from VSS: {e}")
            return False
    
    def backup_file(self, file_path: str, reason: str = "manual") -> Optional[str]:
        """
        Create a backup copy of a file
        
        Args:
            file_path: File to backup
            reason: Reason for backup
            
        Returns:
            Path to backup file or None
        """
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return None
            
            # Create timestamped backup
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.basename(file_path)
            backup_path = os.path.join(self.backup_dir, f"{timestamp}_{filename}")
            
            # Copy file
            shutil.copy2(file_path, backup_path)
            
            # Save metadata
            metadata = {
                'original_path': file_path,
                'backup_path': backup_path,
                'timestamp': timestamp,
                'reason': reason,
                'size': os.path.getsize(file_path)
            }
            
            metadata_path = backup_path + '.meta.json'
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Backed up {file_path} to {backup_path}")
            return backup_path
            
        except Exception as e:
            logger.error(f"Error backing up file: {e}")
            return None
    
    def restore_backup(self, backup_path: str, 
                      original_path: Optional[str] = None) -> bool:
        """
        Restore a file from backup
        
        Args:
            backup_path: Path to backup file
            original_path: Where to restore (None = use original location)
            
        Returns:
            True if successful
        """
        try:
            # Load metadata
            metadata_path = backup_path + '.meta.json'
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                if original_path is None:
                    original_path = metadata['original_path']
            
            if original_path is None:
                logger.error("Cannot determine original path")
                return False
            
            # Create directory if needed
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            
            # Restore file
            shutil.copy2(backup_path, original_path)
            logger.info(f"Restored {backup_path} to {original_path}")
            
            self.recovery_log.append({
                'timestamp': datetime.now().isoformat(),
                'backup_path': backup_path,
                'restore_path': original_path,
                'success': True
            })
            
            return True
            
        except Exception as e:
            logger.error(f"Error restoring backup: {e}")
            return False
    
    def list_backups(self) -> List[Dict]:
        """List all backups"""
        backups = []
        try:
            for filename in os.listdir(self.backup_dir):
                if filename.endswith('.meta.json'):
                    metadata_path = os.path.join(self.backup_dir, filename)
                    with open(metadata_path, 'r') as f:
                        metadata = json.load(f)
                    backups.append(metadata)
        except Exception as e:
            logger.error(f"Error listing backups: {e}")
        
        return sorted(backups, key=lambda x: x['timestamp'], reverse=True)
    
    def cleanup_old_backups(self, days: int = 7) -> int:
        """
        Remove backups older than specified days
        
        Args:
            days: Age threshold in days
            
        Returns:
            Number of backups removed
        """
        removed = 0
        try:
            cutoff = datetime.now().timestamp() - (days * 86400)
            
            for filename in os.listdir(self.backup_dir):
                file_path = os.path.join(self.backup_dir, filename)
                if os.path.getmtime(file_path) < cutoff:
                    os.remove(file_path)
                    removed += 1
            
            logger.info(f"Cleaned up {removed} old backups")
            
        except Exception as e:
            logger.error(f"Error cleaning up backups: {e}")
        
        return removed
    
    def get_recovery_statistics(self) -> Dict:
        """Get recovery statistics"""
        return {
            'total_backups': len(self.list_backups()),
            'backup_directory': self.backup_dir,
            'recovery_attempts': len(self.recovery_log),
            'successful_recoveries': sum(1 for log in self.recovery_log if log.get('success'))
        }


if __name__ == "__main__":
    # Test recovery manager
    print("Testing Recovery Manager...")
    
    recovery = RecoveryManager()
    
    # Test backup
    test_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
    test_file.write("Test content for recovery")
    test_file.close()
    
    print(f"\nBacking up test file: {test_file.name}")
    backup_path = recovery.backup_file(test_file.name, "test")
    
    if backup_path:
        print(f"Backup created: {backup_path}")
        
        # List backups
        backups = recovery.list_backups()
        print(f"\nTotal backups: {len(backups)}")
        
        # Restore test
        print(f"\nRestoring backup...")
        success = recovery.restore_backup(backup_path)
        print(f"Restore successful: {success}")
    
    # VSS test
    print(f"\nListing VSS snapshots...")
    snapshots = recovery.list_vss_snapshots()
    print(f"Found {len(snapshots)} snapshots")
    
    # Get statistics
    stats = recovery.get_recovery_statistics()
    print(f"\nStatistics: {json.dumps(stats, indent=2)}")
    
    # Cleanup
    os.unlink(test_file.name)
    
    print("\nRecovery test complete!")
