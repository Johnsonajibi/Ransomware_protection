"""
Threat Intelligence Manager
Manages signature databases, IOC feeds, and threat intelligence updates
"""

import json
import os
import logging
import hashlib
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import threading

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatIntelligence:
    """
    Manages threat intelligence including signatures, IOCs, and updates
    """
    
    def __init__(self, signatures_dir: str = "signatures"):
        """
        Initialize threat intelligence manager
        
        Args:
            signatures_dir: Directory containing signature files
        """
        self.signatures_dir = signatures_dir
        self.patterns = {}
        self.rules = {}
        self.last_update = None
        self.lock = threading.Lock()
        
        # Default signature files
        self.pattern_file = os.path.join(signatures_dir, "ransomware_patterns.json")
        self.rules_file = os.path.join(signatures_dir, "behavioral_rules.json")
        
        # IOC storage
        self.known_hashes: Set[str] = set()
        self.known_ips: Set[str] = set()
        self.known_domains: Set[str] = set()
        
        # Load signatures
        self.load_signatures()
        
    def load_signatures(self) -> bool:
        """Load signature files from disk"""
        try:
            with self.lock:
                # Load ransomware patterns
                if os.path.exists(self.pattern_file):
                    with open(self.pattern_file, 'r') as f:
                        self.patterns = json.load(f)
                    logger.info(f"Loaded patterns: {len(self.patterns.get('extensions', []))} extensions, "
                               f"{len(self.patterns.get('processes', []))} processes")
                else:
                    logger.warning(f"Pattern file not found: {self.pattern_file}")
                    self.patterns = self._get_default_patterns()
                
                # Load behavioral rules
                if os.path.exists(self.rules_file):
                    with open(self.rules_file, 'r') as f:
                        self.rules = json.load(f)
                    logger.info(f"Loaded {len(self.rules.get('file_patterns', []))} file patterns")
                else:
                    logger.warning(f"Rules file not found: {self.rules_file}")
                    self.rules = self._get_default_rules()
                
                self.last_update = datetime.now()
                return True
                
        except Exception as e:
            logger.error(f"Error loading signatures: {e}")
            return False
    
    def save_signatures(self) -> bool:
        """Save current signatures to disk"""
        try:
            with self.lock:
                os.makedirs(self.signatures_dir, exist_ok=True)
                
                with open(self.pattern_file, 'w') as f:
                    json.dump(self.patterns, f, indent=2)
                
                with open(self.rules_file, 'w') as f:
                    json.dump(self.rules, f, indent=2)
                
                logger.info("Signatures saved successfully")
                return True
                
        except Exception as e:
            logger.error(f"Error saving signatures: {e}")
            return False
    
    def is_known_ransomware_extension(self, extension: str) -> bool:
        """Check if extension matches known ransomware"""
        extensions = self.patterns.get('extensions', [])
        return extension.lower() in [ext.lower() for ext in extensions]
    
    def is_known_ransomware_process(self, process_name: str) -> bool:
        """Check if process name matches known ransomware"""
        processes = self.patterns.get('processes', [])
        return process_name.lower() in [proc.lower() for proc in processes]
    
    def is_suspicious_url(self, url: str) -> bool:
        """Check if URL is suspicious"""
        suspicious_urls = self.patterns.get('suspicious_urls', [])
        url_lower = url.lower()
        return any(sus_url in url_lower for sus_url in suspicious_urls)
    
    def get_score_for_behavior(self, behavior_type: str) -> int:
        """Get score for a specific behavior type"""
        scores = self.rules.get('behavior_scores', {})
        return scores.get(behavior_type, 0)
    
    def add_hash_ioc(self, file_hash: str, source: str = "manual"):
        """Add a file hash IOC"""
        with self.lock:
            self.known_hashes.add(file_hash.lower())
            logger.info(f"Added hash IOC: {file_hash[:16]}... (source: {source})")
    
    def add_ip_ioc(self, ip_address: str, source: str = "manual"):
        """Add an IP address IOC"""
        with self.lock:
            self.known_ips.add(ip_address)
            logger.info(f"Added IP IOC: {ip_address} (source: {source})")
    
    def add_domain_ioc(self, domain: str, source: str = "manual"):
        """Add a domain IOC"""
        with self.lock:
            self.known_domains.add(domain.lower())
            logger.info(f"Added domain IOC: {domain} (source: {source})")
    
    def check_file_hash(self, file_path: str) -> Optional[str]:
        """Check if file hash matches known malware"""
        try:
            file_hash = self._calculate_file_hash(file_path)
            if file_hash.lower() in self.known_hashes:
                logger.warning(f"File hash match: {file_path}")
                return file_hash
            return None
        except Exception as e:
            logger.error(f"Error checking file hash: {e}")
            return None
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def update_from_url(self, url: str, timeout: int = 30) -> bool:
        """
        Update signatures from remote URL
        
        Args:
            url: URL to download signatures from
            timeout: Request timeout in seconds
            
        Returns:
            True if update successful
        """
        try:
            logger.info(f"Updating signatures from {url}")
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            
            new_signatures = response.json()
            
            with self.lock:
                # Merge new signatures
                if 'extensions' in new_signatures:
                    current_ext = set(self.patterns.get('extensions', []))
                    new_ext = set(new_signatures['extensions'])
                    self.patterns['extensions'] = list(current_ext | new_ext)
                
                if 'processes' in new_signatures:
                    current_proc = set(self.patterns.get('processes', []))
                    new_proc = set(new_signatures['processes'])
                    self.patterns['processes'] = list(current_proc | new_proc)
                
                # Update other fields
                for key in ['registry_keys', 'suspicious_urls', 'file_signatures']:
                    if key in new_signatures:
                        self.patterns[key] = new_signatures[key]
                
                self.last_update = datetime.now()
            
            # Save updated signatures
            self.save_signatures()
            logger.info("Signatures updated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error updating signatures: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get threat intelligence statistics"""
        with self.lock:
            return {
                'extensions': len(self.patterns.get('extensions', [])),
                'processes': len(self.patterns.get('processes', [])),
                'registry_keys': len(self.patterns.get('registry_keys', [])),
                'hash_iocs': len(self.known_hashes),
                'ip_iocs': len(self.known_ips),
                'domain_iocs': len(self.known_domains),
                'last_update': self.last_update.isoformat() if self.last_update else None
            }
    
    def _get_default_patterns(self) -> Dict:
        """Get default patterns if file doesn't exist"""
        return {
            "extensions": [".encrypted", ".locked", ".crypto"],
            "processes": ["encrypt.exe", "locker.exe"],
            "registry_keys": [],
            "suspicious_urls": [".onion"],
            "file_signatures": {}
        }
    
    def _get_default_rules(self) -> Dict:
        """Get default rules if file doesn't exist"""
        return {
            "behavior_scores": {
                "rapid_file_modification": 30,
                "extension_change": 40,
                "high_entropy": 35
            },
            "file_patterns": []
        }


if __name__ == "__main__":
    # Test threat intelligence
    print("Testing Threat Intelligence Manager...")
    
    ti = ThreatIntelligence()
    
    # Test extension check
    print(f"\n.encrypted is known: {ti.is_known_ransomware_extension('.encrypted')}")
    print(f".txt is known: {ti.is_known_ransomware_extension('.txt')}")
    
    # Test process check
    print(f"\nwannacry.exe is known: {ti.is_known_ransomware_process('wannacry.exe')}")
    print(f"notepad.exe is known: {ti.is_known_ransomware_process('notepad.exe')}")
    
    # Test IOC management
    ti.add_hash_ioc("abc123def456", "test")
    ti.add_ip_ioc("192.168.1.100", "test")
    ti.add_domain_ioc("malicious.com", "test")
    
    # Get statistics
    stats = ti.get_statistics()
    print(f"\nStatistics: {json.dumps(stats, indent=2)}")
    
    print("\nThreat Intelligence test complete!")
