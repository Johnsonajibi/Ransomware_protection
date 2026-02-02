"""
Real Anti-Ransomware Quarantine Manager
Manage quarantined files and restoration

Features:
- Move suspicious files to quarantine
- Maintain quarantine database
- Restore files from quarantine
- Automatic cleanup of old quarantined files
"""

import os
import shutil
import sqlite3
import hashlib
import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from pathlib import Path
import json

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class QuarantineManager:
    """Manage quarantined files"""
    
    def __init__(self, quarantine_dir: Optional[str] = None,
                 db_path: Optional[str] = None):
        """
        Initialize quarantine manager
        
        Args:
            quarantine_dir: Directory to store quarantined files
            db_path: Path to quarantine database
        """
        # Set default paths
        if quarantine_dir is None:
            quarantine_dir = os.path.join(
                os.getenv('PROGRAMDATA', 'C:\\ProgramData'),
                'AntiRansomware',
                'quarantine'
            )
        
        if db_path is None:
            db_path = os.path.join(quarantine_dir, 'quarantine.db')
        
        self.quarantine_dir = quarantine_dir
        self.db_path = db_path
        
        # Create directories
        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        logger.info(f"Quarantine Manager initialized: {self.quarantine_dir}")
    
    def _init_database(self):
        """Initialize quarantine database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantined_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_size INTEGER,
                quarantine_date TEXT NOT NULL,
                threat_score INTEGER,
                threat_details TEXT,
                process_id INTEGER,
                process_name TEXT,
                restored INTEGER DEFAULT 0,
                restore_date TEXT,
                notes TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_original_path 
            ON quarantined_files(original_path)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_quarantine_date 
            ON quarantined_files(quarantine_date)
        ''')
        
        conn.commit()
        conn.close()
    
    def _calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {filepath}: {e}")
            return ""
    
    def quarantine_file(self, filepath: str, threat_score: int = 0,
                       threat_details: Optional[Dict] = None,
                       process_id: int = 0, process_name: str = "") -> bool:
        """
        Move file to quarantine
        
        Args:
            filepath: Path to file to quarantine
            threat_score: Threat score from detection engine
            threat_details: Additional threat details
            process_id: PID of process that modified file
            process_name: Name of process that modified file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not os.path.exists(filepath):
                logger.error(f"File not found: {filepath}")
                return False
            
            # Calculate hash
            file_hash = self._calculate_file_hash(filepath)
            file_size = os.path.getsize(filepath)
            
            # Generate unique quarantine filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.basename(filepath)
            quarantine_filename = f"{timestamp}_{file_hash[:16]}_{filename}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            # Move file to quarantine
            shutil.move(filepath, quarantine_path)
            
            # Record in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO quarantined_files 
                (original_path, quarantine_path, file_hash, file_size,
                 quarantine_date, threat_score, threat_details,
                 process_id, process_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                filepath,
                quarantine_path,
                file_hash,
                file_size,
                datetime.now().isoformat(),
                threat_score,
                json.dumps(threat_details) if threat_details else None,
                process_id,
                process_name
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"File quarantined: {filepath} -> {quarantine_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error quarantining file {filepath}: {e}")
            return False
    
    def restore_file(self, quarantine_id: int, force: bool = False) -> bool:
        """
        Restore file from quarantine
        
        Args:
            quarantine_id: Database ID of quarantined file
            force: Force restore even if original path exists
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get file info
            cursor.execute('''
                SELECT original_path, quarantine_path, restored
                FROM quarantined_files
                WHERE id = ?
            ''', (quarantine_id,))
            
            row = cursor.fetchone()
            if not row:
                logger.error(f"Quarantined file not found: ID {quarantine_id}")
                conn.close()
                return False
            
            original_path, quarantine_path, restored = row
            
            if restored:
                logger.warning(f"File already restored: ID {quarantine_id}")
                conn.close()
                return False
            
            if not os.path.exists(quarantine_path):
                logger.error(f"Quarantined file not found: {quarantine_path}")
                conn.close()
                return False
            
            # Check if original location exists
            if os.path.exists(original_path) and not force:
                logger.error(
                    f"Original file exists, use force=True to overwrite: "
                    f"{original_path}"
                )
                conn.close()
                return False
            
            # Create original directory if needed
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            
            # Restore file
            shutil.move(quarantine_path, original_path)
            
            # Update database
            cursor.execute('''
                UPDATE quarantined_files
                SET restored = 1, restore_date = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), quarantine_id))
            
            conn.commit()
            conn.close()
            
            logger.info(f"File restored: {original_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error restoring file {quarantine_id}: {e}")
            return False
    
    def list_quarantined_files(self, include_restored: bool = False,
                               limit: int = 100) -> List[Dict]:
        """
        List quarantined files
        
        Args:
            include_restored: Include already restored files
            limit: Maximum number of results
            
        Returns:
            List of quarantined file information
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = '''
                SELECT id, original_path, quarantine_path, file_hash,
                       file_size, quarantine_date, threat_score,
                       process_name, restored, restore_date
                FROM quarantined_files
            '''
            
            if not include_restored:
                query += ' WHERE restored = 0'
            
            query += ' ORDER BY quarantine_date DESC LIMIT ?'
            
            cursor.execute(query, (limit,))
            
            files = []
            for row in cursor.fetchall():
                files.append({
                    'id': row[0],
                    'original_path': row[1],
                    'quarantine_path': row[2],
                    'file_hash': row[3],
                    'file_size': row[4],
                    'quarantine_date': row[5],
                    'threat_score': row[6],
                    'process_name': row[7],
                    'restored': bool(row[8]),
                    'restore_date': row[9]
                })
            
            conn.close()
            return files
        
        except Exception as e:
            logger.error(f"Error listing quarantined files: {e}")
            return []
    
    def delete_quarantined_file(self, quarantine_id: int) -> bool:
        """
        Permanently delete quarantined file
        
        Args:
            quarantine_id: Database ID of quarantined file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get file path
            cursor.execute('''
                SELECT quarantine_path, restored
                FROM quarantined_files
                WHERE id = ?
            ''', (quarantine_id,))
            
            row = cursor.fetchone()
            if not row:
                logger.error(f"Quarantined file not found: ID {quarantine_id}")
                conn.close()
                return False
            
            quarantine_path, restored = row
            
            # Delete physical file if exists and not restored
            if not restored and os.path.exists(quarantine_path):
                os.remove(quarantine_path)
            
            # Delete from database
            cursor.execute('DELETE FROM quarantined_files WHERE id = ?', 
                          (quarantine_id,))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Quarantined file deleted: ID {quarantine_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error deleting quarantined file {quarantine_id}: {e}")
            return False
    
    def cleanup_old_files(self, days: int = 30) -> int:
        """
        Delete quarantined files older than specified days
        
        Args:
            days: Delete files older than this many days
            
        Returns:
            Number of files deleted
        """
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get old files
            cursor.execute('''
                SELECT id, quarantine_path
                FROM quarantined_files
                WHERE quarantine_date < ? AND restored = 0
            ''', (cutoff_date,))
            
            old_files = cursor.fetchall()
            deleted_count = 0
            
            for file_id, quarantine_path in old_files:
                # Delete physical file
                if os.path.exists(quarantine_path):
                    try:
                        os.remove(quarantine_path)
                        deleted_count += 1
                    except Exception as e:
                        logger.error(f"Error deleting file {quarantine_path}: {e}")
                
                # Delete from database
                cursor.execute('DELETE FROM quarantined_files WHERE id = ?', 
                              (file_id,))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Cleaned up {deleted_count} old quarantined files")
            return deleted_count
        
        except Exception as e:
            logger.error(f"Error cleaning up old files: {e}")
            return 0
    
    def get_statistics(self) -> Dict:
        """Get quarantine statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total quarantined
            cursor.execute('SELECT COUNT(*) FROM quarantined_files WHERE restored = 0')
            total_quarantined = cursor.fetchone()[0]
            
            # Total restored
            cursor.execute('SELECT COUNT(*) FROM quarantined_files WHERE restored = 1')
            total_restored = cursor.fetchone()[0]
            
            # Total size
            cursor.execute('SELECT SUM(file_size) FROM quarantined_files WHERE restored = 0')
            total_size = cursor.fetchone()[0] or 0
            
            conn.close()
            
            return {
                'total_quarantined': total_quarantined,
                'total_restored': total_restored,
                'total_size_bytes': total_size,
                'total_size_mb': round(total_size / (1024 * 1024), 2)
            }
        
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}


if __name__ == "__main__":
    print("=" * 60)
    print("Real Anti-Ransomware Quarantine Manager")
    print("=" * 60)
    
    manager = QuarantineManager()
    
    # Show statistics
    stats = manager.get_statistics()
    print("\n[*] Quarantine Statistics:")
    for key, value in stats.items():
        print(f"    {key}: {value}")
    
    # List quarantined files
    files = manager.list_quarantined_files(limit=10)
    print(f"\n[*] Quarantined Files (showing {len(files)}):")
    
    if files:
        for file in files:
            print(f"\n  ID: {file['id']}")
            print(f"    Original: {file['original_path']}")
            print(f"    Date: {file['quarantine_date']}")
            print(f"    Score: {file['threat_score']}")
            print(f"    Process: {file['process_name']}")
    else:
        print("    No files in quarantine")
    
    print("\n✅ Quarantine manager test complete")
