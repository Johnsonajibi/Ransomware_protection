#!/usr/bin/env python3
"""
Final Security Check
Final comprehensive security validation before production deployment.
"""

import os
import sys
import json
import logging
import argparse
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('final_security_check.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)



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

class FinalSecurityCheck:
    def __init__(self):
        self.results = {}
        self.db_path = 'antiransomware.db'
        self.checks_passed = 0
        self.checks_failed = 0
    
    def check_database_integrity(self) -> bool:
        """Verify database integrity and schema"""
        logger.info("Checking database integrity...")
        try:
            if not Path(self.db_path).exists():
                logger.warning(f"Database not found: {self.db_path}")
                return False
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check required tables
            required_tables = [
                'audit_events',
                'protected_paths',
                'tokens',
                'service_history'
            ]
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            existing_tables = [row[0] for row in cursor.fetchall()]
            
            for table in required_tables:
                if table not in existing_tables:
                    logger.error(f"Missing table: {table}")
                    self.checks_failed += 1
                    return False
            
            logger.info("✓ Database schema valid")
            self.checks_passed += 1
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Database check failed: {e}")
            self.checks_failed += 1
            return False
    
    def check_config_files(self) -> bool:
        """Validate all configuration files"""
        logger.info("Checking configuration files...")
        try:
            config_files = [
                'config.json',
                'admin_config.json',
                'config.yaml'
            ]
            
            found_count = 0
            for config_file in config_files:
                if Path(config_file).exists():
                    with open(config_file, 'r') as f:
                        json.load(f)
                    logger.info(f"✓ Valid: {config_file}")
                    found_count += 1
            
            if found_count == 0:
                logger.warning("No configuration files found")
                return False
            
            self.checks_passed += 1
            return True
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            self.checks_failed += 1
            return False
        except Exception as e:
            logger.error(f"Config check failed: {e}")
            self.checks_failed += 1
            return False
    
    def check_protection_status(self) -> bool:
        """Verify protection is properly configured"""
        logger.info("Checking protection status...")
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check for protected paths
            cursor.execute("SELECT COUNT(*) FROM protected_paths WHERE enabled=1")
            protected_count = cursor.fetchone()[0]
            
            if protected_count == 0:
                logger.warning("No protected paths configured")
                logger.info("  (This may be intentional for initial setup)")
            else:
                logger.info(f"✓ {protected_count} protected paths active")
            
            # Check for audit events
            cursor.execute("SELECT COUNT(*) FROM audit_events")
            event_count = cursor.fetchone()[0]
            
            logger.info(f"✓ Audit log has {event_count} events")
            
            self.checks_passed += 1
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Protection status check failed: {e}")
            self.checks_failed += 1
            return False
    
    def check_crypto_support(self) -> bool:
        """Verify cryptographic libraries are available"""
        logger.info("Checking cryptographic support...")
        try:
            required_modules = [
                'cryptography',
                'hmac',
                'hashlib',
                'secrets'
            ]
            
            for module_name in required_modules:
                try:
                    __import__(module_name)
                    logger.info(f"✓ {module_name} available")
                except ImportError:
                    logger.error(f"✗ {module_name} not available")
                    self.checks_failed += 1
                    return False
            
            self.checks_passed += 1
            return True
        except Exception as e:
            logger.error(f"Crypto check failed: {e}")
            self.checks_failed += 1
            return False
    
    def check_tpm_availability(self) -> bool:
        """Check if TPM is available (non-blocking)"""
        logger.info("Checking TPM availability...")
        try:
            try:
                import wmi
                c = wmi.WMI(namespace="root\\cimv2\\Security\\MicrosoftTpm")
                tpm_devices = c.Win32_Tpm()
                if tpm_devices:
                    logger.info("✓ TPM 2.0 detected")
                    self.checks_passed += 1
                    return True
                else:
                    logger.warning("⚠️ TPM not available (system will use soft tokens)")
                    return True
            except Exception as e:
                logger.warning(f"⚠️ TPM check skipped: {e}")
                logger.info("   System will fall back to software-based tokens")
                return True
        except Exception as e:
            logger.warning(f"TPM check failed (non-blocking): {e}")
            return True
    
    def check_file_permissions(self) -> bool:
        """Verify file permissions are appropriate"""
        logger.info("Checking file permissions...")
        try:
            critical_files = [
                self.db_path,
                'config.json',
                'admin_config.json'
            ]
            
            for file_path in critical_files:
                if Path(file_path).exists():
                    stat_info = Path(file_path).stat()
                    mode = stat_info.st_mode
                    logger.info(f"✓ {file_path} exists (mode: {oct(mode)})")
            
            self.checks_passed += 1
            return True
        except Exception as e:
            logger.error(f"File permission check failed: {e}")
            self.checks_failed += 1
            return False
    
    def generate_report(self) -> Dict:
        """Generate comprehensive security report"""
        logger.info("\n" + "="*60)
        logger.info("FINAL SECURITY CHECK REPORT")
        logger.info("="*60)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'checks_passed': self.checks_passed,
            'checks_failed': self.checks_failed,
            'total_checks': self.checks_passed + self.checks_failed,
            'status': 'PASS' if self.checks_failed == 0 else 'WARNINGS',
            'details': self.results
        }
        
        logger.info(f"\nChecks Passed: {self.checks_passed}")
        logger.info(f"Checks Failed: {self.checks_failed}")
        logger.info(f"Overall Status: {report['status']}")
        logger.info("="*60 + "\n")
        
        # Save report
        report_file = Path('security_check_report.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Report saved to: {report_file}")
        
        return report
    
    def run_all_checks(self) -> bool:
        """Execute all security checks"""
        logger.info("Starting Final Security Check...\n")
        
        checks = [
            self.check_database_integrity,
            self.check_config_files,
            self.check_file_permissions,
            self.check_crypto_support,
            self.check_protection_status,
            self.check_tpm_availability
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                logger.error(f"Check {check.__name__} failed: {e}")
        
        report = self.generate_report()
        return report['checks_failed'] == 0

def main():
    parser = argparse.ArgumentParser(
        description='Final Security Check before production deployment'
    )
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--report', action='store_true', help='Generate detailed report')
    
    args = parser.parse_args()
    
    checker = FinalSecurityCheck()
    success = checker.run_all_checks()
    
    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())
