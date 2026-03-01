"""
Real Anti-Ransomware Detection Engine
Behavioral analysis and pattern matching for ransomware detection

Features:
- Multi-layer detection (signatures, behavioral, heuristics)
- Scoring system for threat assessment
- Real-time pattern analysis
- Machine learning integration ready
"""

import os
import time
import hashlib
import logging
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import json
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass


def safe_import(module_name: str):
    """Safely import a module from whitelist"""
    import importlib
    
    # Whitelist of allowed modules
    ALLOWED_MODULES = {
        'cryptography', 'sqlite3', 'tkinter', 'psutil', 'pywin32',
        'requests', 'numpy', 'pandas', 'pytest', 'sys', 'os', 're',
        'json', 'datetime', 'pathlib', 'logging', 'subprocess'
    }
    
    if module_name not in ALLOWED_MODULES:
        raise ValueError(f"Module {module_name} not in security whitelist")
    
    try:
        return importlib.import_module(module_name)
    except ImportError as e:
        raise ImportError(f"Failed to import {module_name}: {e}")

class FileEvent:
    """Represents a file system event"""
    timestamp: datetime
    path: str
    event_type: str  # 'modified', 'created', 'deleted', 'renamed'
    process_id: int
    process_name: str
    old_path: Optional[str] = None
    file_size: int = 0
    entropy: float = 0.0


@dataclass
class ThreatScore:
    """Threat scoring details"""
    total_score: int = 0
    signature_match: bool = False
    rapid_modification: int = 0
    extension_change: int = 0
    delete_on_close: int = 0
    suspicious_origin: int = 0
    network_activity: int = 0
    registry_persistence: int = 0
    high_entropy: int = 0
    details: List[str] = field(default_factory=list)
    
    def get_risk_level(self) -> str:
        """Get risk level based on total score"""
        if self.total_score >= 91:
            return "CRITICAL"
        elif self.total_score >= 61:
            return "HIGH"
        elif self.total_score >= 31:
            return "MEDIUM"
        else:
            return "LOW"


class BehavioralAnalysisEngine:
    """Core behavioral analysis engine for ransomware detection"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Tracking data structures
        self.file_events: List[FileEvent] = []
        self.process_file_access: Dict[int, List[FileEvent]] = defaultdict(list)
        self.extension_changes: Dict[int, int] = defaultdict(int)
        self.rapid_modifications: Dict[int, int] = defaultdict(int)
        
        # Signature database
        self.ransomware_extensions = self._load_ransomware_extensions()
        self.ransomware_processes = self._load_ransomware_processes()
        self.suspicious_patterns = self._load_suspicious_patterns()
        
        # Thresholds from config
        self.rapid_write_threshold = self.config.get('rapid_write_threshold', 50)
        self.time_window_seconds = self.config.get('time_window_seconds', 30)
        self.score_threshold_high = self.config.get('score_threshold_high', 61)
        self.score_threshold_critical = self.config.get('score_threshold_critical', 91)
        
        logger.info("Behavioral Analysis Engine initialized")
    
    def _load_config(self) -> Dict:
        """Load configuration from YAML or use defaults"""
        default_config = {
            'rapid_write_threshold': 50,
            'time_window_seconds': 30,
            'score_threshold_high': 61,
            'score_threshold_critical': 91,
            'extension_change_score': 40,
            'rapid_modification_score': 30,
            'delete_on_close_score': 25,
            'suspicious_origin_score': 15,
            'network_activity_score': 20,
            'registry_persistence_score': 10,
            'high_entropy_score': 35
        }
        
        try:
            import yaml
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    if loaded_config and 'detection' in loaded_config:
                        default_config.update(loaded_config['detection'])
        except Exception as e:
            logger.warning(f"Could not load config, using defaults: {e}")
        
        return default_config
    
    def _load_ransomware_extensions(self) -> Set[str]:
        """Load known ransomware file extensions"""
        default_extensions = {
            '.encrypted', '.locked', '.crypto', '.wannacry', '.locky',
            '.cerber', '.cryptolocker', '.cryptowall', '.teslacrypt',
            '.zepto', '.osiris', '.dharma', '.sage', '.good', '.better',
            '.darkness', '.onion', '.zzzzz', '.micro', '.LeChiffre',
            '.keybtc@inbox_com', '.0x0', '.bleep', '.1999', '.vault',
            '.HA3', '.toxcrypt', '.hydracrypt', '.ezz', '.ecc', '.exx',
            '.xyz', '.zzz', '.aaa', '.abc', '.ccc', '.vvv', '.xxx',
            '.ttt', '.micro', '.encoded', '.kraken', '.supercrypt',
            '.ctbl', '.ctb2', '.crinf', '.r5a', '.XRNT', '.XTBL',
            '.crypt', '.R16M01D05', '.pzdc', '.good', '.LOL!', '.OMG!',
            '.RDM', '.RRK', '.encryptedRSA', '.crjoker', '.EnCiPhErEd',
            '.LeChiffre', '.keybtc@inbox_com', '.0x0', '.bleep',
            '.1999', '.vault', '.HA3', '.toxcrypt', '.hydracrypt'
        }
        
        try:
            patterns_file = os.path.join(
                os.path.dirname(__file__),
                'signatures',
                'ransomware_patterns.json'
            )
            if os.path.exists(patterns_file):
                with open(patterns_file, 'r') as f:
                    data = json.load(f)
                    if 'extensions' in data:
                        default_extensions.update(data['extensions'])
        except Exception as e:
            logger.warning(f"Could not load extension patterns: {e}")
        
        return default_extensions
    
    def _load_ransomware_processes(self) -> Set[str]:
        """Load known ransomware process names"""
        default_processes = {
            'encrypt.exe', 'locker.exe', 'cryptolocker.exe',
            'wannacry.exe', 'wcry.exe', 'wanna.exe',
            'locky.exe', 'cerber.exe', 'cryptowall.exe',
            'teslacrypt.exe', 'petya.exe', 'mischa.exe',
            'goldeneye.exe', 'jigsaw.exe', 'samsam.exe',
            'ryuk.exe', 'sodinokibi.exe', 'revil.exe',
            'darkside.exe', 'conti.exe', 'lockbit.exe',
            'blackmatter.exe', 'hive.exe'
        }
        
        try:
            patterns_file = os.path.join(
                os.path.dirname(__file__),
                'signatures',
                'ransomware_patterns.json'
            )
            if os.path.exists(patterns_file):
                with open(patterns_file, 'r') as f:
                    data = json.load(f)
                    if 'processes' in data:
                        default_processes.update(data['processes'])
        except Exception as e:
            logger.warning(f"Could not load process patterns: {e}")
        
        return {p.lower() for p in default_processes}
    
    def _load_suspicious_patterns(self) -> List[Dict]:
        """Load suspicious file/behavior patterns"""
        default_patterns = [
            {'pattern': r'readme.*\.txt$', 'type': 'ransom_note', 'score': 50},
            {'pattern': r'how.*decrypt', 'type': 'ransom_note', 'score': 50},
            {'pattern': r'your.*files.*encrypted', 'type': 'ransom_note', 'score': 50},
            {'pattern': r'decrypt.*instruction', 'type': 'ransom_note', 'score': 50},
        ]
        
        try:
            patterns_file = os.path.join(
                os.path.dirname(__file__),
                'signatures',
                'behavioral_rules.json'
            )
            if os.path.exists(patterns_file):
                with open(patterns_file, 'r') as f:
                    data = json.load(f)
                    if 'file_patterns' in data:
                        default_patterns.extend(data['file_patterns'])
        except Exception as e:
            logger.warning(f"Could not load behavioral patterns: {e}")
        
        return default_patterns
    
    def calculate_file_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of file (0-8, higher = more random/encrypted)"""
        try:
            if not os.path.exists(file_path):
                return 0.0
            
            # Read sample of file (first 64KB)
            with open(file_path, 'rb') as f:
                data = f.read(65536)
            
            if len(data) == 0:
                return 0.0
            
            # Calculate byte frequency
            byte_counts = defaultdict(int)
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate Shannon entropy
            entropy = 0.0
            data_len = len(data)
            for count in byte_counts.values():
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * (probability and (
                        safe_import('math').log2(probability)
                    ))
            
            return entropy
        except Exception as e:
            logger.error(f"Error calculating entropy for {file_path}: {e}")
            return 0.0
    
    def analyze_file_event(self, event: FileEvent) -> ThreatScore:
        """Analyze a single file event and return threat score"""
        score = ThreatScore()
        
        # Add event to tracking
        self.file_events.append(event)
        self.process_file_access[event.process_id].append(event)
        
        # Layer 1: Signature matching
        file_ext = os.path.splitext(event.path)[1].lower()
        if file_ext in self.ransomware_extensions:
            score.signature_match = True
            score.total_score += 100
            score.details.append(f"Known ransomware extension: {file_ext}")
            return score  # Immediate block
        
        if event.process_name.lower() in self.ransomware_processes:
            score.signature_match = True
            score.total_score += 100
            score.details.append(f"Known ransomware process: {event.process_name}")
            return score  # Immediate block
        
        # Check suspicious file patterns
        for pattern_dict in self.suspicious_patterns:
            if re.search(pattern_dict['pattern'], event.path, re.IGNORECASE):
                score.total_score += pattern_dict.get('score', 30)
                score.details.append(
                    f"Suspicious pattern: {pattern_dict['pattern']} "
                    f"({pattern_dict['type']})"
                )
        
        # Layer 2: Behavioral analysis
        
        # [1] Rapid file modification
        recent_events = self._get_recent_events(event.process_id)
        if len(recent_events) >= self.rapid_write_threshold:
            rapid_score = self.config.get('rapid_modification_score', 30)
            score.rapid_modification = rapid_score
            score.total_score += rapid_score
            score.details.append(
                f"Rapid modifications: {len(recent_events)} files in "
                f"{self.time_window_seconds}s"
            )
        
        # [2] Extension changes (renamed file)
        if event.event_type == 'renamed' and event.old_path:
            old_ext = os.path.splitext(event.old_path)[1].lower()
            new_ext = os.path.splitext(event.path)[1].lower()
            
            if old_ext != new_ext:
                self.extension_changes[event.process_id] += 1
                ext_score = self.config.get('extension_change_score', 40)
                score.extension_change = ext_score
                score.total_score += ext_score
                score.details.append(
                    f"Extension change: {old_ext} → {new_ext}"
                )
        
        # [3] High entropy (encrypted data)
        if event.entropy > 7.5:  # High entropy threshold
            entropy_score = self.config.get('high_entropy_score', 35)
            score.high_entropy = entropy_score
            score.total_score += entropy_score
            score.details.append(f"High entropy: {event.entropy:.2f} (likely encrypted)")
        
        # [4] Multiple different file types accessed
        if self._check_diverse_file_access(event.process_id):
            score.total_score += 20
            score.details.append("Accessing diverse file types")
        
        return score
    
    def _get_recent_events(self, process_id: int) -> List[FileEvent]:
        """Get recent file events for a process within time window"""
        cutoff_time = datetime.now() - timedelta(seconds=self.time_window_seconds)
        return [
            e for e in self.process_file_access[process_id]
            if e.timestamp >= cutoff_time
        ]
    
    def _check_diverse_file_access(self, process_id: int) -> bool:
        """Check if process is accessing many different file types"""
        recent_events = self._get_recent_events(process_id)
        if len(recent_events) < 10:
            return False
        
        extensions = set()
        for event in recent_events:
            ext = os.path.splitext(event.path)[1].lower()
            if ext:
                extensions.add(ext)
        
        # Accessing 5+ different file types is suspicious
        return len(extensions) >= 5
    
    def get_process_threat_level(self, process_id: int) -> Tuple[str, int]:
        """Get overall threat level for a process"""
        events = self.process_file_access.get(process_id, [])
        if not events:
            return "NONE", 0
        
        # Calculate aggregate score
        total_score = 0
        for event in events[-50:]:  # Last 50 events
            score = self.analyze_file_event(event)
            total_score = max(total_score, score.total_score)
        
        if total_score >= self.score_threshold_critical:
            return "CRITICAL", total_score
        elif total_score >= self.score_threshold_high:
            return "HIGH", total_score
        elif total_score >= 31:
            return "MEDIUM", total_score
        else:
            return "LOW", total_score
    
    def cleanup_old_events(self, max_age_minutes: int = 60):
        """Remove old events from memory"""
        cutoff_time = datetime.now() - timedelta(minutes=max_age_minutes)
        
        # Clean main event list
        self.file_events = [
            e for e in self.file_events
            if e.timestamp >= cutoff_time
        ]
        
        # Clean per-process tracking
        for pid in list(self.process_file_access.keys()):
            self.process_file_access[pid] = [
                e for e in self.process_file_access[pid]
                if e.timestamp >= cutoff_time
            ]
            if not self.process_file_access[pid]:
                del self.process_file_access[pid]
        
        logger.debug(f"Cleaned events older than {max_age_minutes} minutes")
    
    def get_statistics(self) -> Dict:
        """Get detection engine statistics"""
        return {
            'total_events': len(self.file_events),
            'monitored_processes': len(self.process_file_access),
            'extension_changes': sum(self.extension_changes.values()),
            'known_ransomware_extensions': len(self.ransomware_extensions),
            'known_ransomware_processes': len(self.ransomware_processes),
            'suspicious_patterns': len(self.suspicious_patterns)
        }


class SignatureDetector:
    """Signature-based detection for known threats"""
    
    def __init__(self):
        self.signatures_path = os.path.join(
            os.path.dirname(__file__),
            'signatures',
            'ransomware_patterns.json'
        )
        self.signatures = self._load_signatures()
    
    def _load_signatures(self) -> Dict:
        """Load signature database"""
        default_sigs = {
            'extensions': ['.encrypted', '.locked', '.crypto'],
            'processes': ['encrypt.exe', 'locker.exe'],
            'registry_keys': [
                r'HKLM\Software\Ransom',
                r'HKCU\Software\CryptoLocker'
            ],
            'bitcoin_addresses': [],
            'tor_nodes': []
        }
        
        try:
            if os.path.exists(self.signatures_path):
                with open(self.signatures_path, 'r') as f:
                    loaded = json.load(f)
                    default_sigs.update(loaded)
        except Exception as e:
            logger.warning(f"Could not load signatures: {e}")
        
        return default_sigs
    
    def check_signature(self, indicator: str, indicator_type: str) -> bool:
        """Check if indicator matches known signature"""
        indicator = indicator.lower()
        
        if indicator_type == 'extension':
            return indicator in self.signatures.get('extensions', [])
        elif indicator_type == 'process':
            return indicator in self.signatures.get('processes', [])
        elif indicator_type == 'registry':
            for pattern in self.signatures.get('registry_keys', []):
                if re.search(pattern, indicator, re.IGNORECASE):
                    return True
        
        return False


if __name__ == "__main__":
    # Test the detection engine
    print("=" * 60)
    print("Real Anti-Ransomware Detection Engine Test")
    print("=" * 60)
    
    engine = BehavioralAnalysisEngine()
    
    # Simulate some file events
    test_events = [
        FileEvent(
            timestamp=datetime.now(),
            path="C:\\Users\\test\\document.docx.encrypted",
            event_type="renamed",
            process_id=1234,
            process_name="suspicious.exe",
            old_path="C:\\Users\\test\\document.docx",
            entropy=7.8
        ),
        FileEvent(
            timestamp=datetime.now(),
            path="C:\\Users\\test\\photo.jpg.locked",
            event_type="renamed",
            process_id=1234,
            process_name="suspicious.exe",
            old_path="C:\\Users\\test\\photo.jpg",
            entropy=7.9
        ),
    ]
    
    print("\n[*] Analyzing test file events...")
    for event in test_events:
        score = engine.analyze_file_event(event)
        print(f"\n File: {event.path}")
        print(f"  Risk Level: {score.get_risk_level()}")
        print(f"  Total Score: {score.total_score}")
        print(f"  Signature Match: {score.signature_match}")
        print(f"  Details:")
        for detail in score.details:
            print(f"    - {detail}")
    
    # Get statistics
    stats = engine.get_statistics()
    print(f"\n[*] Detection Engine Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n✅ Detection engine test complete")
