"""
VeraCrypt Integration for Immune Folders
Handles encrypted container creation, mounting, and management
"""

import os
import sys
import json
import time
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass
from enum import Enum

@dataclass
class ContainerInfo:
    """Information about a VeraCrypt container"""
    container_id: str
    container_path: str
    mount_point: str
    size_mb: int
    is_mounted: bool
    mount_time: Optional[int]
    last_access: Optional[int]
    folder_id: str
    encryption_algorithm: str
    hash_algorithm: str

class MountResult(Enum):
    """Result codes for mount operations"""
    SUCCESS = "success"
    CONTAINER_NOT_FOUND = "container_not_found"
    ALREADY_MOUNTED = "already_mounted"
    INVALID_PASSWORD = "invalid_password"
    VERACRYPT_ERROR = "veracrypt_error"
    MOUNT_POINT_BUSY = "mount_point_busy"
    PERMISSION_DENIED = "permission_denied"

@dataclass
class MountResponse:
    """Response from mount operation"""
    result: MountResult
    mount_point: Optional[str]
    error_message: str
    container_info: Optional[ContainerInfo]

class VeraCryptManager:
    """Main VeraCrypt integration class"""
    
    def __init__(self, container_base_path: str = None, veracrypt_path: str = None):
        # Default paths
        self.container_base_path = Path(container_base_path or 
                                      os.path.join(os.getenv('PROGRAMDATA', 'C:\\ProgramData'),
                                                 'ImmuneFolders', 'containers'))
        
        self.veracrypt_path = Path(veracrypt_path or 
                                 r"C:\Program Files\VeraCrypt\VeraCrypt.exe")
        
        # Create container directory
        self.container_base_path.mkdir(parents=True, exist_ok=True)
        
        # Mount tracking
        self.mounted_containers: Dict[str, ContainerInfo] = {}
        self.mount_lock = threading.Lock()
        
        # Verify VeraCrypt installation
        if not self._verify_veracrypt_installation():
            raise RuntimeError("VeraCrypt not found or not properly installed")
        
        print(f"VeraCrypt Manager initialized")
        print(f"Container path: {self.container_base_path}")
        print(f"VeraCrypt executable: {self.veracrypt_path}")
    
    def _verify_veracrypt_installation(self) -> bool:
        """Verify VeraCrypt is installed and accessible"""
        try:
            if not self.veracrypt_path.exists():
                print(f"VeraCrypt executable not found: {self.veracrypt_path}")
                return False
            
            # Test VeraCrypt version
            result = subprocess.run([
                str(self.veracrypt_path), '/help'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print("VeraCrypt installation verified")
                return True
            else:
                print(f"VeraCrypt test failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"VeraCrypt verification error: {e}")
            return False
    
    def create_container(self, folder_id: str, size_mb: int, 
                        password: str, container_id: str = None) -> Optional[str]:
        """Create a new VeraCrypt container"""
        try:
            if not container_id:
                import uuid
                container_id = str(uuid.uuid4())
            
            container_filename = f"immune_{folder_id}_{container_id}.vc"
            container_path = self.container_base_path / container_filename
            
            # Check if container already exists
            if container_path.exists():
                print(f"Container already exists: {container_path}")
                return None
            
            print(f"Creating container: {container_path} ({size_mb} MB)")
            
            # Create VeraCrypt container using command line
            cmd = [
                str(self.veracrypt_path),
                '/create', str(container_path),
                '/size', f"{size_mb}M",
                '/password', password,
                '/encryption', 'AES',
                '/hash', 'SHA-512',
                '/filesystem', 'NTFS',
                '/format', 'Quick',
                '/silent'
            ]
            
            # Execute container creation
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                print(f"Container creation failed: {result.stderr}")
                return None
            
            # Verify container was created
            if not container_path.exists():
                print("Container file not found after creation")
                return None
            
            # Create container metadata
            container_info = ContainerInfo(
                container_id=container_id,
                container_path=str(container_path),
                mount_point="",
                size_mb=size_mb,
                is_mounted=False,
                mount_time=None,
                last_access=None,
                folder_id=folder_id,
                encryption_algorithm="AES",
                hash_algorithm="SHA-512"
            )
            
            # Save metadata
            self._save_container_metadata(container_id, container_info)
            
            print(f"Container created successfully: {container_id}")
            return container_id
            
        except subprocess.TimeoutExpired:
            print("Container creation timed out")
            return None
        except Exception as e:
            print(f"Container creation error: {e}")
            return None
    
    def mount_container(self, container_id: str, password: str, 
                       mount_point: str = None) -> MountResponse:
        """Mount a VeraCrypt container"""
        with self.mount_lock:
            try:
                # Load container metadata
                container_info = self._load_container_metadata(container_id)
                if not container_info:
                    return MountResponse(
                        result=MountResult.CONTAINER_NOT_FOUND,
                        mount_point=None,
                        error_message=f"Container not found: {container_id}",
                        container_info=None
                    )
                
                # Check if already mounted
                if container_info.is_mounted:
                    return MountResponse(
                        result=MountResult.ALREADY_MOUNTED,
                        mount_point=container_info.mount_point,
                        error_message="Container is already mounted",
                        container_info=container_info
                    )
                
                # Verify container file exists
                container_path = Path(container_info.container_path)
                if not container_path.exists():
                    return MountResponse(
                        result=MountResult.CONTAINER_NOT_FOUND,
                        mount_point=None,
                        error_message=f"Container file not found: {container_path}",
                        container_info=None
                    )
                
                # Find available drive letter or use specified mount point
                if not mount_point:
                    mount_point = self._find_available_drive_letter()
                    if not mount_point:
                        return MountResponse(
                            result=MountResult.MOUNT_POINT_BUSY,
                            mount_point=None,
                            error_message="No available drive letters",
                            container_info=None
                        )
                
                print(f"Mounting container {container_id} to {mount_point}")
                
                # Mount using VeraCrypt command line
                cmd = [
                    str(self.veracrypt_path),
                    '/volume', str(container_path),
                    '/letter', mount_point.rstrip(':'),
                    '/password', password,
                    '/auto',
                    '/silent'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode != 0:
                    error_msg = result.stderr.strip() or "Unknown VeraCrypt error"
                    
                    # Detect specific error types
                    if "incorrect password" in error_msg.lower():
                        mount_result = MountResult.INVALID_PASSWORD
                    elif "access denied" in error_msg.lower():
                        mount_result = MountResult.PERMISSION_DENIED
                    else:
                        mount_result = MountResult.VERACRYPT_ERROR
                    
                    return MountResponse(
                        result=mount_result,
                        mount_point=None,
                        error_message=error_msg,
                        container_info=None
                    )
                
                # Verify mount was successful
                time.sleep(2)  # Give Windows time to recognize the drive
                mount_path = Path(f"{mount_point}\\")
                if not mount_path.exists():
                    return MountResponse(
                        result=MountResult.VERACRYPT_ERROR,
                        mount_point=None,
                        error_message="Mount verification failed",
                        container_info=None
                    )
                
                # Update container info
                container_info.is_mounted = True
                container_info.mount_point = mount_point
                container_info.mount_time = int(time.time())
                container_info.last_access = int(time.time())
                
                # Save updated metadata
                self._save_container_metadata(container_id, container_info)
                
                # Add to mounted containers tracking
                self.mounted_containers[container_id] = container_info
                
                print(f"Container mounted successfully: {mount_point}")
                
                return MountResponse(
                    result=MountResult.SUCCESS,
                    mount_point=mount_point,
                    error_message="",
                    container_info=container_info
                )
                
            except subprocess.TimeoutExpired:
                return MountResponse(
                    result=MountResult.VERACRYPT_ERROR,
                    mount_point=None,
                    error_message="Mount operation timed out",
                    container_info=None
                )
            except Exception as e:
                return MountResponse(
                    result=MountResult.VERACRYPT_ERROR,
                    mount_point=None,
                    error_message=f"Mount error: {str(e)}",
                    container_info=None
                )
    
    def unmount_container(self, container_id: str, force: bool = False) -> bool:
        """Unmount a VeraCrypt container"""
        with self.mount_lock:
            try:
                # Get container info
                container_info = self.mounted_containers.get(container_id)
                if not container_info:
                    # Try loading from metadata
                    container_info = self._load_container_metadata(container_id)
                    if not container_info or not container_info.is_mounted:
                        print(f"Container not mounted: {container_id}")
                        return True  # Already unmounted
                
                mount_point = container_info.mount_point
                print(f"Unmounting container {container_id} from {mount_point}")
                
                # Unmount using VeraCrypt
                cmd = [
                    str(self.veracrypt_path),
                    '/dismount', mount_point.rstrip(':'),
                    '/silent'
                ]
                
                if force:
                    cmd.append('/force')
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode != 0:
                    error_msg = result.stderr.strip()
                    print(f"Unmount failed: {error_msg}")
                    
                    if not force:
                        # Try force unmount
                        print("Attempting force unmount...")
                        return self.unmount_container(container_id, force=True)
                    
                    return False
                
                # Update container info
                container_info.is_mounted = False
                container_info.mount_point = ""
                container_info.mount_time = None
                
                # Save updated metadata
                self._save_container_metadata(container_id, container_info)
                
                # Remove from mounted containers tracking
                if container_id in self.mounted_containers:
                    del self.mounted_containers[container_id]
                
                print(f"Container unmounted successfully: {container_id}")
                return True
                
            except subprocess.TimeoutExpired:
                print("Unmount operation timed out")
                return False
            except Exception as e:
                print(f"Unmount error: {e}")
                return False
    
    def unmount_all_containers(self) -> bool:
        """Unmount all mounted containers"""
        success = True
        
        # Get list of mounted containers
        mounted_list = list(self.mounted_containers.keys())
        
        for container_id in mounted_list:
            if not self.unmount_container(container_id):
                success = False
        
        return success
    
    def list_containers(self) -> List[ContainerInfo]:
        """List all containers"""
        containers = []
        
        try:
            # Load all container metadata files
            for metadata_file in self.container_base_path.glob("container_*.meta"):
                try:
                    with open(metadata_file, 'r') as f:
                        data = json.load(f)
                    
                    container_info = ContainerInfo(
                        container_id=data["container_id"],
                        container_path=data["container_path"],
                        mount_point=data.get("mount_point", ""),
                        size_mb=data["size_mb"],
                        is_mounted=data.get("is_mounted", False),
                        mount_time=data.get("mount_time"),
                        last_access=data.get("last_access"),
                        folder_id=data["folder_id"],
                        encryption_algorithm=data.get("encryption_algorithm", "AES"),
                        hash_algorithm=data.get("hash_algorithm", "SHA-512")
                    )
                    
                    containers.append(container_info)
                    
                except Exception as e:
                    print(f"Error loading container metadata {metadata_file}: {e}")
        
        except Exception as e:
            print(f"Error listing containers: {e}")
        
        return containers
    
    def get_container_info(self, container_id: str) -> Optional[ContainerInfo]:
        """Get information about a specific container"""
        return self._load_container_metadata(container_id)
    
    def delete_container(self, container_id: str, secure_delete: bool = True) -> bool:
        """Delete a VeraCrypt container"""
        try:
            # Load container metadata
            container_info = self._load_container_metadata(container_id)
            if not container_info:
                print(f"Container not found: {container_id}")
                return False
            
            # Unmount if mounted
            if container_info.is_mounted:
                if not self.unmount_container(container_id, force=True):
                    print("Failed to unmount container before deletion")
                    return False
            
            container_path = Path(container_info.container_path)
            
            if container_path.exists():
                if secure_delete:
                    # Use secure deletion (multiple overwrites)
                    print(f"Securely deleting container: {container_path}")
                    self._secure_delete_file(container_path)
                else:
                    # Simple deletion
                    container_path.unlink()
                    print(f"Container deleted: {container_path}")
            
            # Remove metadata
            metadata_file = self.container_base_path / f"container_{container_id}.meta"
            if metadata_file.exists():
                metadata_file.unlink()
            
            # Remove from tracking
            if container_id in self.mounted_containers:
                del self.mounted_containers[container_id]
            
            print(f"Container completely removed: {container_id}")
            return True
            
        except Exception as e:
            print(f"Container deletion error: {e}")
            return False
    
    def resize_container(self, container_id: str, new_size_mb: int, password: str) -> bool:
        """Resize a VeraCrypt container"""
        try:
            container_info = self._load_container_metadata(container_id)
            if not container_info:
                print(f"Container not found: {container_id}")
                return False
            
            # Container must be unmounted for resizing
            if container_info.is_mounted:
                print("Container must be unmounted for resizing")
                return False
            
            container_path = Path(container_info.container_path)
            
            print(f"Resizing container {container_id} to {new_size_mb} MB")
            
            # Use VeraCrypt's resize feature
            cmd = [
                str(self.veracrypt_path),
                '/resize', str(container_path),
                '/size', f"{new_size_mb}M",
                '/password', password,
                '/silent'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                print(f"Container resize failed: {result.stderr}")
                return False
            
            # Update metadata
            container_info.size_mb = new_size_mb
            self._save_container_metadata(container_id, container_info)
            
            print(f"Container resized successfully: {container_id}")
            return True
            
        except subprocess.TimeoutExpired:
            print("Container resize timed out")
            return False
        except Exception as e:
            print(f"Container resize error: {e}")
            return False
    
    def change_container_password(self, container_id: str, old_password: str, 
                                new_password: str) -> bool:
        """Change container password"""
        try:
            container_info = self._load_container_metadata(container_id)
            if not container_info:
                print(f"Container not found: {container_id}")
                return False
            
            # Container must be unmounted for password change
            if container_info.is_mounted:
                print("Container must be unmounted for password change")
                return False
            
            container_path = Path(container_info.container_path)
            
            print(f"Changing password for container {container_id}")
            
            # Use VeraCrypt's password change feature
            cmd = [
                str(self.veracrypt_path),
                '/chpwd', str(container_path),
                '/oldpassword', old_password,
                '/newpassword', new_password,
                '/silent'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode != 0:
                print(f"Password change failed: {result.stderr}")
                return False
            
            print(f"Container password changed successfully: {container_id}")
            return True
            
        except subprocess.TimeoutExpired:
            print("Password change timed out")
            return False
        except Exception as e:
            print(f"Password change error: {e}")
            return False
    
    def _find_available_drive_letter(self) -> Optional[str]:
        """Find an available drive letter for mounting"""
        import string
        
        # Get currently used drive letters
        used_letters = set()
        for drive in Path.cwd().root.replace('\\', '').split():
            used_letters.add(drive.upper())
        
        # Check mounted containers
        for container in self.mounted_containers.values():
            if container.mount_point:
                used_letters.add(container.mount_point.rstrip(':').upper())
        
        # Find first available letter (starting from X and going backwards)
        for letter in reversed(string.ascii_uppercase):
            if letter not in used_letters and letter not in ['A', 'B', 'C']:
                return f"{letter}:"
        
        return None
    
    def _save_container_metadata(self, container_id: str, container_info: ContainerInfo):
        """Save container metadata to file"""
        try:
            metadata = {
                "container_id": container_info.container_id,
                "container_path": container_info.container_path,
                "mount_point": container_info.mount_point,
                "size_mb": container_info.size_mb,
                "is_mounted": container_info.is_mounted,
                "mount_time": container_info.mount_time,
                "last_access": container_info.last_access,
                "folder_id": container_info.folder_id,
                "encryption_algorithm": container_info.encryption_algorithm,
                "hash_algorithm": container_info.hash_algorithm,
                "metadata_version": 1
            }
            
            metadata_file = self.container_base_path / f"container_{container_id}.meta"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
                
        except Exception as e:
            print(f"Error saving container metadata: {e}")
    
    def _load_container_metadata(self, container_id: str) -> Optional[ContainerInfo]:
        """Load container metadata from file"""
        try:
            metadata_file = self.container_base_path / f"container_{container_id}.meta"
            if not metadata_file.exists():
                return None
            
            with open(metadata_file, 'r') as f:
                data = json.load(f)
            
            return ContainerInfo(
                container_id=data["container_id"],
                container_path=data["container_path"],
                mount_point=data.get("mount_point", ""),
                size_mb=data["size_mb"],
                is_mounted=data.get("is_mounted", False),
                mount_time=data.get("mount_time"),
                last_access=data.get("last_access"),
                folder_id=data["folder_id"],
                encryption_algorithm=data.get("encryption_algorithm", "AES"),
                hash_algorithm=data.get("hash_algorithm", "SHA-512")
            )
            
        except Exception as e:
            print(f"Error loading container metadata: {e}")
            return None
    
    def _secure_delete_file(self, file_path: Path):
        """Securely delete a file with multiple overwrites"""
        try:
            if not file_path.exists():
                return
            
            file_size = file_path.stat().st_size
            
            print(f"Performing secure deletion of {file_path} ({file_size} bytes)")
            
            # Perform multiple overwrite passes
            with open(file_path, 'r+b') as f:
                # Pass 1: All zeros
                f.seek(0)
                f.write(b'\x00' * file_size)
                f.flush()
                os.fsync(f.fileno())
                
                # Pass 2: All ones
                f.seek(0)
                f.write(b'\xFF' * file_size)
                f.flush()
                os.fsync(f.fileno())
                
                # Pass 3: Random data
                import secrets
                f.seek(0)
                chunk_size = 64 * 1024  # 64KB chunks
                remaining = file_size
                while remaining > 0:
                    chunk = min(chunk_size, remaining)
                    f.write(secrets.token_bytes(chunk))
                    remaining -= chunk
                f.flush()
                os.fsync(f.fileno())
            
            # Finally delete the file
            file_path.unlink()
            print(f"Secure deletion completed: {file_path}")
            
        except Exception as e:
            print(f"Secure deletion error: {e}")
            # Fall back to normal deletion
            try:
                file_path.unlink()
            except:
                pass
    
    def get_mount_status(self) -> Dict[str, ContainerInfo]:
        """Get status of all mounted containers"""
        return self.mounted_containers.copy()
    
    def cleanup(self):
        """Cleanup and unmount all containers"""
        print("Cleaning up VeraCrypt manager...")
        self.unmount_all_containers()
        print("VeraCrypt manager cleanup complete")

# Utility functions
class VeraCryptUtils:
    """Utility functions for VeraCrypt operations"""
    
    @staticmethod
    def estimate_container_size(folder_path: str, padding_factor: float = 1.5) -> int:
        """Estimate required container size for a folder"""
        try:
            total_size = 0
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        total_size += os.path.getsize(file_path)
                    except (OSError, IOError):
                        pass  # Skip inaccessible files
            
            # Convert to MB and add padding
            size_mb = int((total_size / (1024 * 1024)) * padding_factor)
            
            # Minimum size of 10MB
            return max(size_mb, 10)
            
        except Exception as e:
            print(f"Size estimation error: {e}")
            return 100  # Default 100MB
    
    @staticmethod
    def check_veracrypt_version() -> Optional[str]:
        """Get VeraCrypt version information"""
        try:
            veracrypt_path = r"C:\Program Files\VeraCrypt\VeraCrypt.exe"
            result = subprocess.run([veracrypt_path, '/help'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Extract version from help output
                for line in result.stdout.split('\n'):
                    if 'VeraCrypt' in line and 'version' in line.lower():
                        return line.strip()
                return "VeraCrypt (version unknown)"
            
        except Exception as e:
            print(f"Version check error: {e}")
        
        return None
    
    @staticmethod
    def is_veracrypt_installed() -> bool:
        """Check if VeraCrypt is installed"""
        veracrypt_path = Path(r"C:\Program Files\VeraCrypt\VeraCrypt.exe")
        return veracrypt_path.exists()

# Test and example usage
if __name__ == "__main__":
    # Test VeraCrypt manager
    if not VeraCryptUtils.is_veracrypt_installed():
        print("VeraCrypt is not installed. Please install VeraCrypt first.")
        sys.exit(1)
    
    version = VeraCryptUtils.check_veracrypt_version()
    if version:
        print(f"Found: {version}")
    
    try:
        # Initialize manager
        vc_manager = VeraCryptManager()
        
        # Test container creation
        folder_id = "test_folder"
        container_size = 50  # 50MB
        password = "test_password_123"
        
        print(f"Creating test container...")
        container_id = vc_manager.create_container(folder_id, container_size, password)
        
        if container_id:
            print(f"✓ Container created: {container_id}")
            
            # Test mounting
            print("Testing container mount...")
            mount_result = vc_manager.mount_container(container_id, password)
            
            if mount_result.result == MountResult.SUCCESS:
                print(f"✓ Container mounted: {mount_result.mount_point}")
                
                # Wait a moment
                time.sleep(3)
                
                # Test unmounting
                print("Testing container unmount...")
                if vc_manager.unmount_container(container_id):
                    print("✓ Container unmounted successfully")
                else:
                    print("✗ Container unmount failed")
                
            else:
                print(f"✗ Container mount failed: {mount_result.error_message}")
            
            # Clean up test container
            print("Cleaning up test container...")
            if vc_manager.delete_container(container_id):
                print("✓ Test container deleted")
            else:
                print("✗ Test container deletion failed")
        
        else:
            print("✗ Container creation failed")
    
    except Exception as e:
        print(f"Test error: {e}")
    
    finally:
        try:
            vc_manager.cleanup()
        except:
            pass
