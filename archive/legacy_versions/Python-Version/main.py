"""
Real Anti-Ransomware - Main Orchestrator
Coordinates all protection components
"""

import os
import sys
import time
import signal
import logging
import argparse
from typing import Optional

try:
    from emergency_kill_switch import EmergencyKillSwitch
    HAS_KILL_SWITCH = True
except ImportError:
    HAS_KILL_SWITCH = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# Import our modules
from detection_engine import BehavioralAnalysisEngine
from file_monitor import FileMonitor
from process_monitor import ProcessMonitor
from quarantine_manager import QuarantineManager
from threat_intelligence import ThreatIntelligence
from recovery import RecoveryManager
from forensics import ForensicsManager
from integrity_monitor import IntegrityMonitor
from honeypot_monitor import HoneypotMonitor

try:
    from email_alerting import EmailAlertingSystem
    HAS_EMAIL = True
except ImportError:
    HAS_EMAIL = False

try:
    from siem_integration import SIEMIntegration
    HAS_SIEM = True
except ImportError:
    HAS_SIEM = False

# Advanced features
try:
    from ml_detector import MLRansomwareDetector
    HAS_ML = True
except ImportError:
    HAS_ML = False
    logger.warning("ML detector not available")

try:
    from tpm_integration import TPMManager, TPMKeyManager
    HAS_TPM = True
except ImportError:
    HAS_TPM = False
    logger.warning("TPM integration not available")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AntiRansomwareManager:
    """
    Main orchestrator for Anti-Ransomware protection
    """
    
    def __init__(self, config_path: str = "config.yaml"):
        """
        Initialize the Anti-Ransomware manager
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        self.running = False
        
        # Components
        self.threat_intel: Optional[ThreatIntelligence] = None
        self.detection_engine: Optional[BehavioralAnalysisEngine] = None
        self.quarantine_manager: Optional[QuarantineManager] = None
        self.file_monitor: Optional[FileMonitor] = None
        self.process_monitor: Optional[ProcessMonitor] = None
        self.recovery_manager: Optional[RecoveryManager] = None
        self.forensics: Optional[ForensicsManager] = None
        self.integrity_monitor: Optional[IntegrityMonitor] = None
        self.kill_switch: Optional['EmergencyKillSwitch'] = None
        self.honeypot_monitor: Optional[HoneypotMonitor] = None
        self.email_alerter: Optional['EmailAlertingSystem'] = None
        self.siem: Optional['SIEMIntegration'] = None
        
        # Advanced features
        self.ml_detector: Optional['MLRansomwareDetector'] = None
        self.tpm_manager: Optional['TPMManager'] = None
        self.tpm_key_manager: Optional['TPMKeyManager'] = None
        
        # Statistics
        self.stats = {
            'threats_detected': 0,
            'files_quarantined': 0,
            'processes_blocked': 0,
            'start_time': None
        }
    
    def _load_config(self) -> dict:
        """Load configuration from file"""
        try:
            if HAS_YAML and os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f)
                logger.info(f"Loaded configuration from {self.config_path}")
                return config
            else:
                logger.warning("Using default configuration")
                return self._get_default_config()
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> dict:
        """Get default configuration"""
        return {
            'detection': {
                'rapid_write_threshold': 50,
                'time_window_seconds': 30,
                'score_threshold_high': 61,
                'score_threshold_critical': 91
            },
            'quarantine': {
                'directory': 'C:\\ProgramData\\AntiRansomware\\quarantine',
                'auto_quarantine_threshold': 80
            },
            'integrity_monitor': {
                'enable': False,
                'paths': []
            },
            'honeypots': {
                'enable': False,
                'directories': []
            },
            'kill_switch': {
                'enable': False,
                'score_threshold': 95
            },
            'email_alerts': {
                'enable': False
            },
            'siem': {
                'enable': False
            },
            'logging': {
                'level': 'INFO',
                'file': 'C:\\ProgramData\\AntiRansomware\\logs\\antiransomware.log'
            }
        }
    
    def initialize(self) -> bool:
        """Initialize all components"""
        try:
            logger.info("Initializing Anti-Ransomware components...")
            
            # Create required directories from config (fallback to local data paths)
            quarantine_dir_cfg = self.config.get('quarantine', {}).get('directory', './data/quarantine')
            backup_dir_cfg = self.config.get('backup', {}).get('backup_directory', './data/backups')
            forensics_dir_cfg = self.config.get('forensics', {}).get('storage_directory', './data/forensics')
            logs_dir_cfg = self.config.get('logging', {}).get('log_directory', './data/logs')

            for dir_path in [quarantine_dir_cfg, backup_dir_cfg, forensics_dir_cfg, logs_dir_cfg]:
                try:
                    os.makedirs(dir_path, exist_ok=True)
                except FileExistsError:
                    # If a file exists at the path, skip to avoid crashing initialization
                    logger.warning(f"Directory path already occupied by a file: {dir_path}")
                except PermissionError:
                    logger.error(f"Permission denied creating directory: {dir_path}")
            
            # Initialize threat intelligence
            self.threat_intel = ThreatIntelligence()
            logger.info("✓ Threat Intelligence initialized")
            
            # Initialize detection engine
            self.detection_engine = BehavioralAnalysisEngine()
            logger.info("✓ Detection Engine initialized")
            
            # Initialize quarantine manager
            self.quarantine_manager = QuarantineManager(quarantine_dir_cfg)
            logger.info("✓ Quarantine Manager initialized")
            
            # Initialize recovery manager
            self.recovery_manager = RecoveryManager(backup_dir=backup_dir_cfg)
            logger.info("✓ Recovery Manager initialized")
            
            # Initialize forensics
            self.forensics = ForensicsManager(forensics_dir=forensics_dir_cfg)
            logger.info("✓ Forensics Manager initialized")

            # Kill switch
            if HAS_KILL_SWITCH:
                try:
                    self.kill_switch = EmergencyKillSwitch()
                    logger.info("✓ Emergency Kill Switch ready")
                except Exception as e:
                    logger.warning(f"Kill switch init failed: {e}")

            # Initialize integrity monitor (optional)
            fim_cfg = self.config.get('integrity_monitor', {})
            if fim_cfg.get('enable'):
                self.integrity_monitor = IntegrityMonitor()
                paths = fim_cfg.get('paths') or []
                if paths:
                    self.integrity_monitor.create_baseline(paths)
                    if self.integrity_monitor.start(paths):
                        logger.info(f"✓ Integrity Monitor started for {len(paths)} path(s)")
                    else:
                        logger.warning("Integrity Monitor not started (watchdog missing)")
                else:
                    logger.warning("Integrity Monitor enabled but no paths configured")
            
            # Initialize honeypot monitor (optional)
            hp_cfg = self.config.get('honeypots', {})
            if hp_cfg.get('enable'):
                self.honeypot_monitor = HoneypotMonitor()
                dirs = hp_cfg.get('directories') or []
                if dirs:
                    self.honeypot_monitor.create_honeypots(dirs)
                    if self.honeypot_monitor.start():
                        logger.info(f"✓ Honeypot Monitor started for {len(dirs)} dir(s)")
                    else:
                        logger.warning("Honeypot Monitor not started (watchdog missing)")
                else:
                    logger.warning("Honeypot Monitor enabled but no directories configured")
            
            # Initialize ML detector if available
            if HAS_ML:
                ml_config = self.config.get('advanced', {})
                if ml_config.get('enable_ml_detection', False):
                    model_path = ml_config.get('ml_model_path', 'models/ransomware_classifier.pkl')
                    self.ml_detector = MLRansomwareDetector(model_path)
                    if self.ml_detector.model is not None:
                        logger.info("✓ ML Detector initialized")
                    else:
                        logger.warning("ML model not found, run train_ml_model.py first")
            
            # Initialize TPM if available
            if HAS_TPM:
                try:
                    self.tpm_manager = TPMManager()
                    if self.tpm_manager.is_available():
                        self.tpm_key_manager = TPMKeyManager(self.tpm_manager)
                        logger.info(f"✓ TPM Manager initialized ({self.tpm_manager.get_tpm_version()})")
                        
                        # Verify boot integrity
                        if self.tpm_key_manager.verify_boot_integrity():
                            logger.info("✓ Boot integrity verified")
                    else:
                        logger.warning("TPM not available on this system")
                except Exception as e:
                    logger.warning(f"TPM initialization failed: {e}")
            
            # Email alerting (optional)
            if HAS_EMAIL and self.config.get('email_alerts', {}).get('enable'):
                try:
                    self.email_alerter = EmailAlertingSystem()
                    logger.info("✓ Email Alerting initialized")
                except Exception as e:
                    logger.warning(f"Email alerting init failed: {e}")
            
            # SIEM integration (optional)
            if HAS_SIEM and self.config.get('siem', {}).get('enable'):
                try:
                    self.siem = SIEMIntegration()
                    logger.info("✓ SIEM Integration initialized")
                except Exception as e:
                    logger.warning(f"SIEM init failed: {e}")
            
            # Set up threat callback
            def threat_callback(threat_score):
                """Handle detected threats"""
                self.stats['threats_detected'] += 1
                
                logger.warning(f"THREAT DETECTED: {threat_score.risk_level} "
                             f"(Score: {threat_score.total_score})")
                logger.warning(f"  File: {threat_score.file_path}")
                logger.warning(f"  Process: {threat_score.process_id}")
                logger.warning(f"  Reasons: {', '.join(threat_score.reasons)}")
                
                # ML verification if available
                ml_is_malware = False
                ml_confidence = 0.0
                
                if self.ml_detector and self.ml_detector.enabled:
                    try:
                        ml_is_malware, ml_confidence = self.ml_detector.predict(
                            file_path=threat_score.file_path,
                            process_id=threat_score.process_id,
                            behavior_data=behavior_data
                        )
                        
                        if ml_is_malware:
                            logger.critical(f"ML CONFIRMED RANSOMWARE: {ml_confidence:.1%} confidence")
                            threat_score.total_score += 50  # Boost score
                    except Exception as e:
                        logger.error(f"ML detection error: {e}")
                
                # Collect forensic event
                details = f"Score: {threat_score.total_score}"
                if ml_is_malware:
                    details += f", ML: {ml_confidence:.1%}"
                
                event_id = self.forensics.record_event(
                    event_type="threat_detected",
                    severity=threat_score.risk_level.lower(),
                    process_id=threat_score.process_id,
                    file_path=threat_score.file_path,
                    details=details
                )
                
                # Send SIEM event
                if self.siem:
                    try:
                        self.siem.send_event(
                            event_type="ransomware_threat",
                            severity=threat_score.risk_level,
                            details={
                                'file': threat_score.file_path,
                                'process_id': threat_score.process_id,
                                'score': threat_score.total_score,
                                'reasons': threat_score.reasons
                            }
                        )
                    except Exception as e:
                        logger.error(f"SIEM send failed: {e}")
                
                # Send email alert
                if self.email_alerter:
                    try:
                        if threat_score.total_score >= 70:  # Send email for high scores
                            self.email_alerter.send_alert(
                                alert_type='THREAT_DETECTED',
                                severity=threat_score.risk_level,
                                details={
                                    'file': threat_score.file_path,
                                    'process_id': threat_score.process_id,
                                    'score': threat_score.total_score,
                                    'reasons': threat_score.reasons
                                },
                                attach_logs=True
                            )
                    except Exception as e:
                        logger.error(f"Email alert failed: {e}")
                
                # Auto-quarantine if critical
                auto_threshold = self.config.get('quarantine', {}).get('auto_quarantine_threshold', 80)
                if threat_score.total_score >= auto_threshold:
                    if threat_score.file_path and os.path.exists(threat_score.file_path):
                        logger.critical(f"AUTO-QUARANTINING: {threat_score.file_path}")
                        
                        # Backup first
                        self.recovery_manager.backup_file(threat_score.file_path, "pre-quarantine")
                        
                        # Quarantine
                        self.quarantine_manager.quarantine_file(
                            threat_score.file_path,
                            threat_score.total_score,
                            f"Auto-quarantine: {', '.join(threat_score.reasons)}",
                            threat_score.process_id
                        )
                        
                        self.stats['files_quarantined'] += 1
                        
                        # Collect evidence
                        self.forensics.collect_file_evidence(threat_score.file_path, event_id)

                # Kill switch trigger for extreme scenarios
                kill_cfg = self.config.get('kill_switch', {})
                kill_enabled = kill_cfg.get('enable', False)
                kill_threshold = kill_cfg.get('score_threshold', 95)
                if kill_enabled and HAS_KILL_SWITCH and self.kill_switch:
                    if threat_score.total_score >= kill_threshold:
                        try:
                            reason = f"CRITICAL_THREAT_SCORE_{threat_score.total_score}"
                            self.kill_switch.activate_lockdown(reason=reason, triggered_by='DetectionPipeline')
                            logger.critical("EMERGENCY KILL SWITCH ACTIVATED")
                        except Exception as e:
                            logger.error(f"Kill switch activation failed: {e}")
                
                # Collect process evidence
                if threat_score.process_id:
                    self.forensics.collect_process_evidence(threat_score.process_id, event_id)
            
            # Initialize file monitor
            watch_paths = self.config.get('file_monitor', {}).get('watch_paths')
            exclude_paths = self.config.get('file_monitor', {}).get('exclude_paths')
            self.file_monitor = FileMonitor(
                watch_paths=watch_paths,
                exclude_paths=exclude_paths,
                on_threat_detected=threat_callback
            )
            logger.info("✓ File Monitor initialized")
            
            # Set up process callback
            def process_callback(process_info, score):
                """Handle suspicious processes"""
                logger.warning(f"SUSPICIOUS PROCESS: {process_info.name} "
                             f"(PID: {process_info.pid}, Score: {score})")
                
                event_id = self.forensics.record_event(
                    event_type="suspicious_process",
                    severity="medium" if score < 50 else "high",
                    process_id=process_info.pid,
                    process_name=process_info.name,
                    details=f"Score: {score}"
                )
                
                # Collect evidence
                self.forensics.collect_process_evidence(process_info.pid, event_id)
                
                # Terminate if very suspicious
                if score >= 100:
                    logger.critical(f"TERMINATING MALICIOUS PROCESS: {process_info.name}")
                    self.process_monitor.terminate_process(process_info.pid)
                    self.stats['processes_blocked'] += 1
            
            # Initialize process monitor
            self.process_monitor = ProcessMonitor(on_suspicious_process=process_callback)
            logger.info("✓ Process Monitor initialized")
            
            logger.info("All components initialized successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing components: {e}")
            return False
    
    def start(self):
        """Start protection"""
        try:
            if not self.initialize():
                logger.error("Failed to initialize. Exiting.")
                return False
            
            logger.info("=" * 60)
            logger.info("REAL ANTI-RANSOMWARE PROTECTION STARTED")
            logger.info("=" * 60)
            
            self.running = True
            self.stats['start_time'] = time.time()
            
            # Start monitors
            self.file_monitor.start()
            self.process_monitor.start()
            
            logger.info("Protection is active. Press Ctrl+C to stop.")
            
            # Main loop
            try:
                while self.running:
                    time.sleep(5)
                    
                    # Periodic maintenance
                    self.quarantine_manager.cleanup_old_files(days=30)
                    self.recovery_manager.cleanup_old_backups(days=7)
                    
            except KeyboardInterrupt:
                logger.info("Shutdown requested...")
                self.stop()
            
            return True
            
        except Exception as e:
            logger.error(f"Error starting protection: {e}")
            return False
    
    def stop(self):
        """Stop protection"""
        try:
            logger.info("Stopping Anti-Ransomware protection...")
            
            self.running = False
            
            if self.file_monitor:
                self.file_monitor.stop()
            
            if self.process_monitor:
                self.process_monitor.stop()

            if self.integrity_monitor:
                self.integrity_monitor.stop()
            
            if self.honeypot_monitor:
                self.honeypot_monitor.stop()
            
            # Print statistics
            uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
            logger.info("=" * 60)
            logger.info("PROTECTION STATISTICS")
            logger.info(f"  Uptime: {uptime/3600:.2f} hours")
            logger.info(f"  Threats Detected: {self.stats['threats_detected']}")
            logger.info(f"  Files Quarantined: {self.stats['files_quarantined']}")
            logger.info(f"  Processes Blocked: {self.stats['processes_blocked']}")
            logger.info("=" * 60)
            
            logger.info("Anti-Ransomware protection stopped")
            
        except Exception as e:
            logger.error(f"Error stopping protection: {e}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Real Anti-Ransomware Protection')
    parser.add_argument('--config', default='config.yaml', help='Configuration file path')
    parser.add_argument('--dashboard', action='store_true', help='Start web dashboard')
    parser.add_argument('--port', type=int, default=8080, help='Dashboard port')
    
    args = parser.parse_args()
    
    if args.dashboard:
        # Start dashboard
        from dashboard import run_dashboard
        logger.info("Starting dashboard mode...")
        run_dashboard(port=args.port, debug=False)
    else:
        # Start protection
        manager = AntiRansomwareManager(config_path=args.config)
        
        # Handle signals
        def signal_handler(sig, frame):
            logger.info("Signal received, shutting down...")
            manager.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start
        manager.start()


if __name__ == "__main__":
    main()
