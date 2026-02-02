"""
Service Manager
Windows service wrapper for Anti-Ransomware protection
"""

import os
import sys
import time
import logging
import win32serviceutil
import win32service
import win32event
import servicemanager

# Import our modules
try:
    from detection_engine import BehavioralAnalysisEngine
    from file_monitor import FileMonitor
    from process_monitor import ProcessMonitor
    from quarantine_manager import QuarantineManager
    from threat_intelligence import ThreatIntelligence
    from recovery import RecoveryManager
    from forensics import ForensicsManager
except ImportError as e:
    logging.error(f"Failed to import modules: {e}")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='C:\\ProgramData\\AntiRansomware\\logs\\service.log'
)
logger = logging.getLogger(__name__)


class AntiRansomwareService(win32serviceutil.ServiceFramework):
    """
    Windows service for Real Anti-Ransomware
    """
    
    _svc_name_ = "RealAntiRansomware"
    _svc_display_name_ = "Real Anti-Ransomware Protection"
    _svc_description_ = "Enterprise-grade ransomware protection service"
    
    def __init__(self, args):
        """Initialize service"""
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = False
        
        # Components
        self.detection_engine = None
        self.file_monitor = None
        self.process_monitor = None
        self.quarantine_manager = None
        self.threat_intel = None
        self.recovery_manager = None
        self.forensics = None
    
    def SvcStop(self):
        """Stop the service"""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        logger.info("Service stop requested")
        self.running = False
    
    def SvcDoRun(self):
        """Run the service"""
        try:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
            logger.info("Service starting...")
            
            self.running = True
            self.main()
            
        except Exception as e:
            logger.error(f"Service error: {e}")
            servicemanager.LogErrorMsg(f"Service error: {e}")
    
    def main(self):
        """Main service loop"""
        try:
            # Initialize components
            logger.info("Initializing components...")
            
            self.threat_intel = ThreatIntelligence()
            self.detection_engine = BehavioralAnalysisEngine()
            self.quarantine_manager = QuarantineManager()
            self.recovery_manager = RecoveryManager()
            self.forensics = ForensicsManager()
            
            # Set up threat callback
            def threat_callback(threat_score):
                """Handle detected threats"""
                try:
                    logger.warning(f"Threat detected: {threat_score.risk_level} "
                                 f"(score: {threat_score.total_score})")
                    
                    # Record forensic event
                    event_id = self.forensics.record_event(
                        event_type="threat_detected",
                        severity=threat_score.risk_level.lower(),
                        process_id=threat_score.process_id,
                        file_path=threat_score.file_path,
                        details=f"Score: {threat_score.total_score}, Reasons: {threat_score.reasons}"
                    )
                    
                    # Auto-quarantine if critical
                    if threat_score.total_score >= 80:
                        if threat_score.file_path:
                            logger.critical(f"Auto-quarantining: {threat_score.file_path}")
                            self.quarantine_manager.quarantine_file(
                                threat_score.file_path,
                                threat_score.total_score,
                                f"Auto-quarantine: {threat_score.reasons}",
                                threat_score.process_id
                            )
                            
                            # Collect evidence
                            self.forensics.collect_file_evidence(
                                threat_score.file_path,
                                event_id
                            )
                    
                    # Collect process evidence
                    if threat_score.process_id:
                        self.forensics.collect_process_evidence(
                            threat_score.process_id,
                            event_id
                        )
                    
                except Exception as e:
                    logger.error(f"Error in threat callback: {e}")
            
            # Start file monitoring
            self.file_monitor = FileMonitor(
                detection_engine=self.detection_engine,
                threat_callback=threat_callback
            )
            self.file_monitor.start()
            logger.info("File monitor started")
            
            # Start process monitoring
            def process_callback(process_info, score):
                """Handle suspicious processes"""
                logger.warning(f"Suspicious process: {process_info.name} "
                             f"(PID: {process_info.pid}, Score: {score})")
                
                event_id = self.forensics.record_event(
                    event_type="suspicious_process",
                    severity="medium" if score < 50 else "high",
                    process_id=process_info.pid,
                    process_name=process_info.name,
                    details=f"Score: {score}, Path: {process_info.exe}"
                )
                
                # Collect evidence
                self.forensics.collect_process_evidence(process_info.pid, event_id)
            
            self.process_monitor = ProcessMonitor(
                suspicious_callback=process_callback
            )
            self.process_monitor.start()
            logger.info("Process monitor started")
            
            # Service main loop
            logger.info("Service is running")
            while self.running:
                # Wait for stop event (check every 5 seconds)
                if win32event.WaitForSingleObject(self.stop_event, 5000) == win32event.WAIT_OBJECT_0:
                    break
                
                # Periodic maintenance
                try:
                    # Clean old quarantined files
                    self.quarantine_manager.cleanup_old_files(days=30)
                    
                    # Clean old backups
                    self.recovery_manager.cleanup_old_backups(days=7)
                    
                except Exception as e:
                    logger.error(f"Maintenance error: {e}")
            
            # Shutdown
            logger.info("Service stopping...")
            if self.file_monitor:
                self.file_monitor.stop()
            if self.process_monitor:
                self.process_monitor.stop()
            
            logger.info("Service stopped")
            
        except Exception as e:
            logger.error(f"Main loop error: {e}")
            raise


def install_service():
    """Install the service"""
    try:
        win32serviceutil.InstallService(
            AntiRansomwareService,
            AntiRansomwareService._svc_name_,
            AntiRansomwareService._svc_display_name_,
            startType=win32service.SERVICE_AUTO_START,
            description=AntiRansomwareService._svc_description_
        )
        print(f"Service '{AntiRansomwareService._svc_display_name_}' installed successfully")
        print("Use 'net start RealAntiRansomware' to start the service")
    except Exception as e:
        print(f"Error installing service: {e}")


def remove_service():
    """Remove the service"""
    try:
        win32serviceutil.RemoveService(AntiRansomwareService._svc_name_)
        print(f"Service '{AntiRansomwareService._svc_display_name_}' removed successfully")
    except Exception as e:
        print(f"Error removing service: {e}")


if __name__ == '__main__':
    if len(sys.argv) == 1:
        # Run as service
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(AntiRansomwareService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Handle command line
        command = sys.argv[1].lower()
        
        if command == 'install':
            install_service()
        elif command == 'remove':
            remove_service()
        elif command == 'start':
            win32serviceutil.StartService(AntiRansomwareService._svc_name_)
            print("Service started")
        elif command == 'stop':
            win32serviceutil.StopService(AntiRansomwareService._svc_name_)
            print("Service stopped")
        elif command == 'restart':
            win32serviceutil.RestartService(AntiRansomwareService._svc_name_)
            print("Service restarted")
        else:
            print("Usage: service_manager.py [install|remove|start|stop|restart]")
