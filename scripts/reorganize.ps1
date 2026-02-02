# File Reorganization Plan
# Industry-standard Python library structure

# Core protection logic → src/antiransomware/core/
Move-Item -Path "unified_antiransomware.py" -Destination "src/antiransomware/core/protection.py" -Force
Move-Item -Path "aggressive_protection.py" -Destination "src/antiransomware/core/aggressive_mode.py" -Force
Move-Item -Path "four_layer_protection.py" -Destination "src/antiransomware/core/four_layer.py" -Force
Move-Item -Path "policy_engine.py" -Destination "src/antiransomware/core/policy.py" -Force
Move-Item -Path "health_monitor.py" -Destination "src/antiransomware/core/health.py" -Force
Move-Item -Path "system_health_checker.py" -Destination "src/antiransomware/core/health_checker.py" -Force

# Token management → src/antiransomware/core/
Move-Item -Path "trifactor_auth_manager.py" -Destination "src/antiransomware/core/token_manager.py" -Force
Move-Item -Path "ar_token.py" -Destination "src/antiransomware/core/token_cli.py" -Force
Move-Item -Path "auth_token.py" -Destination "src/antiransomware/core/auth.py" -Force
Move-Item -Path "crypto_token.py" -Destination "src/antiransomware/core/crypto.py" -Force
Move-Item -Path "token_gated_access.py" -Destination "src/antiransomware/core/gated_access.py" -Force
Move-Item -Path "debug_token_validation.py" -Destination "src/antiransomware/core/token_debug.py" -Force

# Audit & Logging → src/antiransomware/core/
Move-Item -Path "activate_protection_logging.py" -Destination "src/antiransomware/core/logging_control.py" -Force
Move-Item -Path "view_audit_logs.py" -Destination "src/antiransomware/core/audit.py" -Force

# Detection & Analysis → src/antiransomware/core/
Move-Item -Path "enterprise_detection_advanced.py" -Destination "src/antiransomware/core/detection.py" -Force
Move-Item -Path "blocking_protection.py" -Destination "src/antiransomware/core/blocking.py" -Force
Move-Item -Path "attack_simulation.py" -Destination "src/antiransomware/core/attack_sim.py" -Force

# Integration → src/antiransomware/api/
Move-Item -Path "backup_integration.py" -Destination "src/antiransomware/api/backup.py" -Force
Move-Item -Path "siem_integration.py" -Destination "src/antiransomware/api/siem.py" -Force
Move-Item -Path "email_alerting.py" -Destination "src/antiransomware/api/email.py" -Force

# Admin & Dashboard → src/antiransomware/api/
Move-Item -Path "admin_dashboard.py" -Destination "src/antiransomware/api/dashboard.py" -Force
Move-Item -Path "admin_proof_protection.py" -Destination "src/antiransomware/api/admin_proof.py" -Force

# CLI Tools → src/antiransomware/cli/
Move-Item -Path "add_files_to_protected.py" -Destination "src/antiransomware/cli/protect_files.py" -Force
Move-Item -Path "check_security_events.py" -Destination "src/antiransomware/cli/check_events.py" -Force
Move-Item -Path "deployment_monitor.py" -Destination "src/antiransomware/cli/deploy_monitor.py" -Force
Move-Item -Path "emergency_kill_switch.py" -Destination "src/antiransomware/cli/kill_switch.py" -Force

# Service Management → src/antiransomware/utils/
Move-Item -Path "service_manager.py" -Destination "src/antiransomware/utils/service.py" -Force
Move-Item -Path "config_manager.py" -Destination "src/antiransomware/utils/config.py" -Force
Move-Item -Path "device_fingerprint_enhanced.py" -Destination "src/antiransomware/utils/fingerprint.py" -Force

# Windows-specific → src/antiransomware/utils/
Move-Item -Path "shadow_copy_protection.py" -Destination "src/antiransomware/utils/shadow_copy.py" -Force
Move-Item -Path "boot_persistence_protection.py" -Destination "src/antiransomware/utils/boot_protection.py" -Force

# Kernel Drivers → src/antiransomware/drivers/
Move-Item -Path "antiransomware_kernel.c" -Destination "src/antiransomware/drivers/kernel.c" -Force
Move-Item -Path "antiransomware_minifilter.c" -Destination "src/antiransomware/drivers/minifilter.c" -Force
Move-Item -Path "driver_common.h" -Destination "src/antiransomware/drivers/common.h" -Force
Move-Item -Path "driver_windows.c" -Destination "src/antiransomware/drivers/windows.c" -Force
Move-Item -Path "driver_linux.c" -Destination "src/antiransomware/drivers/linux.c" -Force
Move-Item -Path "driver_macos.swift" -Destination "src/antiransomware/drivers/macos.swift" -Force

# Tests → tests/
Move-Item -Path "test_*.py" -Destination "tests/unit/" -Force
Move-Item -Path "comprehensive_security_validation.py" -Destination "tests/integration/security_validation.py" -Force

# Config files → config/
Move-Item -Path "config.json" -Destination "config/config.json" -Force -ErrorAction SilentlyContinue
Move-Item -Path "config.yaml" -Destination "config/config.yaml" -Force -ErrorAction SilentlyContinue
Move-Item -Path "admin_config.json" -Destination "config/admin.json" -Force -ErrorAction SilentlyContinue

# Build & Deployment → scripts/
Move-Item -Path "build_*.py" -Destination "scripts/" -Force
Move-Item -Path "build_*.bat" -Destination "scripts/" -Force
Move-Item -Path "build_*.ps1" -Destination "scripts/" -Force
Move-Item -Path "deployment.py" -Destination "scripts/deploy.py" -Force
Move-Item -Path "cicd_pipeline.py" -Destination "scripts/cicd.py" -Force
Move-Item -Path "install_with_admin.py" -Destination "scripts/install.py" -Force

# Examples → examples/
Move-Item -Path "demo.py" -Destination "examples/demo.py" -Force -ErrorAction SilentlyContinue
Move-Item -Path "brutal_truth.py" -Destination "examples/demo_advanced.py" -Force -ErrorAction SilentlyContinue

Write-Host "File reorganization complete!" -ForegroundColor Green
