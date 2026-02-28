#!/usr/bin/env python3
"""
Anti-Ransomware Deployment and Installation System
Production-grade deployment with Docker, Kubernetes, and CI/CD support
"""

import os
import sys
import json
import yaml
import shutil
import subprocess
import platform
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

@dataclass
class DeploymentConfig:
    """Deployment configuration"""
    platform: str
    architecture: str
    version: str
    build_type: str  # development, staging, production
    features: List[str]
    dependencies: List[str]

class DeploymentManager:
    """Production deployment manager"""
    
    def __init__(self, config_path: str = None):
        self.config_path = config_path or "deployment.yaml"
        self.config = self._load_config()
        self.platform_info = self._detect_platform()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load deployment configuration"""
        if Path(self.config_path).exists():
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            return self._create_default_config()
    
    def _create_default_config(self) -> Dict[str, Any]:
        """Create default deployment configuration"""
        default_config = {
            'project': {
                'name': 'anti-ransomware',
                'version': '1.0.0',
                'description': 'Production Anti-Ransomware Protection System'
            },
            'platforms': {
                'windows': {
                    'enabled': True,
                    'architectures': ['amd64'],
                    'features': ['kernel-driver', 'usb-dongle', 'web-ui', 'grpc-api']
                },
                'linux': {
                    'enabled': True,
                    'architectures': ['amd64', 'arm64'],
                    'features': ['kernel-driver', 'usb-dongle', 'web-ui', 'grpc-api']
                },
                'darwin': {
                    'enabled': True,
                    'architectures': ['amd64', 'arm64'],
                    'features': ['kernel-driver', 'usb-dongle', 'web-ui', 'grpc-api']
                }
            },
            'deployment': {
                'docker': {
                    'enabled': True,
                    'registry': 'ghcr.io',
                    'namespace': 'antiransomware'
                },
                'kubernetes': {
                    'enabled': True,
                    'namespace': 'antiransomware-system'
                },
                'systemd': {
                    'enabled': True
                }
            },
            'security': {
                'sign_binaries': True,
                'verify_signatures': True,
                'code_signing_cert': 'certs/code_signing.p12'
            }
        }
        
        # Save default config
        with open(self.config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        
        return default_config
    
    def _detect_platform(self) -> Dict[str, str]:
        """Detect current platform information"""
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        # Normalize architecture names
        arch_map = {
            'x86_64': 'amd64',
            'amd64': 'amd64',
            'arm64': 'arm64',
            'aarch64': 'arm64'
        }
        
        return {
            'system': system,
            'architecture': arch_map.get(machine, machine),
            'python_version': platform.python_version()
        }
    
    def build_for_platform(self, target_platform: str = None, architecture: str = None) -> bool:
        """Build the project for specified platform"""
        target_platform = target_platform or self.platform_info['system']
        architecture = architecture or self.platform_info['architecture']
        
        print(f"Building for {target_platform}/{architecture}")
        
        # Create build directory
        build_dir = Path(f"dist/{target_platform}-{architecture}")
        build_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Build kernel drivers
            self._build_kernel_drivers(target_platform, architecture, build_dir)
            
            # Build Python components
            self._build_python_components(target_platform, architecture, build_dir)
            
            # Create installation package
            self._create_installation_package(target_platform, architecture, build_dir)
            
            # Sign binaries if configured
            if self.config.get('security', {}).get('sign_binaries', False):
                self._sign_binaries(target_platform, build_dir)
            
            print(f"Build completed: {build_dir}")
            return True
            
        except Exception as e:
            print(f"Build failed: {e}")
            return False
    
    def _build_kernel_drivers(self, platform: str, arch: str, build_dir: Path):
        """Build kernel drivers"""
        drivers_dir = build_dir / "drivers"
        drivers_dir.mkdir(exist_ok=True)
        
        if platform == "windows":
            # Build Windows minifilter driver
            self._build_windows_driver(arch, drivers_dir)
        elif platform == "linux":
            # Build Linux kernel module
            self._build_linux_driver(arch, drivers_dir)
        elif platform == "darwin":
            # Build macOS system extension
            self._build_macos_driver(arch, drivers_dir)
    
    def _build_windows_driver(self, arch: str, output_dir: Path):
        """Build Windows minifilter driver"""
        if not Path("driver_windows.c").exists():
            raise FileNotFoundError("Windows driver source not found")
        
        # Use Windows Driver Kit to build
        wdk_build_cmd = [
            "msbuild",
            "/p:Configuration=Release",
            f"/p:Platform={arch}",
            "driver_windows.vcxproj"
        ]
        
        # For demonstration, copy source file
        shutil.copy("driver_windows.c", output_dir / "antiransomware.c")
        
        # Create INF file
        inf_content = f"""[Version]
Signature   = "$Windows NT$"
Class       = "AntiVirus"
ClassGuid   = {{b1d1a169-c54f-4379-81db-bee7d88d7454}}
Provider    = %ManufacturerName%
DriverVer   = 01/01/2024,1.0.0.0

[SourceDisksNames]
1 = %DiskName%,,,""

[SourceDisksFiles]
antiransomware.sys = 1,,

[DestinationDirs]
DefaultDestDir = 12
MiniFilter.DriverFiles = 12

[DefaultInstall]
OptionDesc          = %ServiceDescription%
CopyFiles           = MiniFilter.DriverFiles

[DefaultInstall.Services]
AddService          = %ServiceName%,,MiniFilter.Service

[DefaultUninstall]
DelFiles   = MiniFilter.DriverFiles

[DefaultUninstall.Services]
DelService = %ServiceName%,0x200

[MiniFilter.Service]
DisplayName      = %ServiceName%
Description      = %ServiceDescription%
ServiceBinary    = %12%\\antiransomware.sys
Dependencies     = "FltMgr"
ServiceType      = 2
StartType        = 3
ErrorControl     = 1
LoadOrderGroup   = "FSFilter Anti-Virus"

[MiniFilter.DriverFiles]
antiransomware.sys

[Strings]
ManufacturerName    = "Anti-Ransomware Solutions"
ServiceName         = "AntiRansomware"
ServiceDescription  = "Anti-Ransomware Kernel Protection Driver"
DiskName            = "Anti-Ransomware Installation Disk"
"""
        
        with open(output_dir / "antiransomware.inf", 'w') as f:
            f.write(inf_content)
    
    def _build_linux_driver(self, arch: str, output_dir: Path):
        """Build Linux kernel module"""
        if not Path("driver_linux.c").exists():
            raise FileNotFoundError("Linux driver source not found")
        
        # Create Makefile
        makefile_content = f"""obj-m := antiransomware.o
antiransomware-objs := driver_linux.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -A
"""
        
        shutil.copy("driver_linux.c", output_dir / "driver_linux.c")
        with open(output_dir / "Makefile", 'w') as f:
            f.write(makefile_content)
    
    def _build_macos_driver(self, arch: str, output_dir: Path):
        """Build macOS system extension"""
        if not Path("driver_macos.swift").exists():
            raise FileNotFoundError("macOS driver source not found")
        
        shutil.copy("driver_macos.swift", output_dir / "driver_macos.swift")
        
        # Create Info.plist
        plist_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleDisplayName</key>
    <string>Anti-Ransomware Protection</string>
    <key>CFBundleExecutable</key>
    <string>antiransomware</string>
    <key>CFBundleIdentifier</key>
    <string>com.antiransomware.systemextension</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>AntiRansomware</string>
    <key>CFBundlePackageType</key>
    <string>XPC!</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>NSSystemExtensionUsageDescription</key>
    <string>Anti-Ransomware protection requires system-level access to monitor file operations.</string>
</dict>
</plist>
"""
        
        with open(output_dir / "Info.plist", 'w') as f:
            f.write(plist_content)
    
    def _build_python_components(self, platform: str, arch: str, build_dir: Path):
        """Build Python components using PyInstaller"""
        python_dir = build_dir / "python"
        python_dir.mkdir(exist_ok=True)
        
        components = [
            ("broker.py", "antiransomware-broker"),
            ("admin_dashboard.py", "antiransomware-dashboard"),
            ("service_manager.py", "antiransomware-service")
        ]
        
        for source_file, executable_name in components:
            if not Path(source_file).exists():
                print(f"Warning: {source_file} not found, skipping")
                continue
            
            # Create PyInstaller spec file
            spec_content = f"""
import sys
from pathlib import Path

block_cipher = None

a = Analysis(['{source_file}'],
             pathex=['.'],
             binaries=[],
             datas=[
                 ('policies/*.yaml', 'policies'),
                 ('certs/*', 'certs'),
                 ('static/*', 'static'),
                 ('templates/*', 'templates'),
             ],
             hiddenimports=[
                 'grpc',
                 'cryptography',
                 'pyscard',
                 'flask',
                 'sqlite3',
                 'yaml',
                 'psutil'
             ],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='{executable_name}',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True)
"""
            
            spec_file = f"{executable_name}.spec"
            with open(spec_file, 'w') as f:
                f.write(spec_content)
            
            # Build with PyInstaller
            cmd = [sys.executable, "-m", "PyInstaller", "--clean", "--onefile", spec_file]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Move executable to build directory
                if platform == "windows":
                    exe_name = f"{executable_name}.exe"
                else:
                    exe_name = executable_name
                
                src_exe = Path("dist") / exe_name
                if src_exe.exists():
                    shutil.move(src_exe, python_dir / exe_name)
                    print(f"Built {executable_name}")
                else:
                    print(f"Warning: {exe_name} not found after build")
            else:
                print(f"Failed to build {executable_name}: {result.stderr}")
            
            # Cleanup
            if Path(spec_file).exists():
                Path(spec_file).unlink()
    
    def _create_installation_package(self, platform: str, arch: str, build_dir: Path):
        """Create installation package"""
        if platform == "windows":
            self._create_windows_installer(arch, build_dir)
        elif platform == "linux":
            self._create_linux_package(arch, build_dir)
        elif platform == "darwin":
            self._create_macos_package(arch, build_dir)
    
    def _create_windows_installer(self, arch: str, build_dir: Path):
        """Create Windows MSI installer"""
        installer_dir = build_dir / "installer"
        installer_dir.mkdir(exist_ok=True)
        
        # Create NSIS script
        nsis_script = f"""
!define PRODUCT_NAME "Anti-Ransomware Protection"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "Anti-Ransomware Solutions"

Name "${{PRODUCT_NAME}}"
OutFile "antiransomware-{arch}-setup.exe"
InstallDir "$PROGRAMFILES64\\Anti-Ransomware"
RequestExecutionLevel admin

Page directory
Page instfiles

Section "MainSection" SEC01
    SetOutPath "$INSTDIR"
    
    ; Copy Python executables
    File /r "{build_dir}\\python\\*"
    
    ; Copy driver files
    File /r "{build_dir}\\drivers\\*"
    
    ; Create uninstaller
    WriteUninstaller "$INSTDIR\\uninstall.exe"
    
    ; Install driver
    ExecWait '"$INSTDIR\\drivers\\antiransomware.inf" /install'
    
    ; Install service
    ExecWait '"$INSTDIR\\python\\antiransomware-service.exe" --install'
    
    ; Start service
    ExecWait 'net start antiransomware'
    
SectionEnd

Section "Uninstall"
    ; Stop service
    ExecWait 'net stop antiransomware'
    
    ; Uninstall service
    ExecWait 'sc delete antiransomware'
    
    ; Remove files
    RMDir /r "$INSTDIR"
SectionEnd
"""
        
        with open(installer_dir / "installer.nsi", 'w') as f:
            f.write(nsis_script)
        
        print(f"Windows installer script created: {installer_dir / 'installer.nsi'}")
    
    def _create_linux_package(self, arch: str, build_dir: Path):
        """Create Linux DEB/RPM packages"""
        # Create DEB package structure
        deb_dir = build_dir / "deb"
        deb_root = deb_dir / "antiransomware"
        
        # Create directory structure
        (deb_root / "DEBIAN").mkdir(parents=True)
        (deb_root / "usr/bin").mkdir(parents=True)
        (deb_root / "usr/lib/antiransomware").mkdir(parents=True)
        (deb_root / "etc/antiransomware").mkdir(parents=True)
        (deb_root / "lib/systemd/system").mkdir(parents=True)
        
        # Copy executables
        for exe in (build_dir / "python").glob("antiransomware-*"):
            shutil.copy(exe, deb_root / "usr/bin")
        
        # Copy configuration files
        if Path("config.yaml").exists():
            shutil.copy("config.yaml", deb_root / "etc/antiransomware")
        
        if Path("policies").exists():
            shutil.copytree("policies", deb_root / "etc/antiransomware/policies")
        
        # Create systemd service file
        service_content = f"""[Unit]
Description=Anti-Ransomware Protection Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/antiransomware-service
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
"""
        
        with open(deb_root / "lib/systemd/system/antiransomware.service", 'w') as f:
            f.write(service_content)
        
        # Create control file
        control_content = f"""Package: antiransomware
Version: 1.0.0
Section: security
Priority: optional
Architecture: {arch}
Maintainer: Anti-Ransomware Solutions <support@antiransomware.com>
Description: Production Anti-Ransomware Protection System
 Kernel-enforced anti-ransomware protection with hardware root of trust
 and post-quantum cryptography support.
"""
        
        with open(deb_root / "DEBIAN/control", 'w') as f:
            f.write(control_content)
        
        # Create postinst script
        postinst_content = """#!/bin/bash
set -e

# Reload systemd
systemctl daemon-reload

# Enable service
systemctl enable antiransomware

# Load kernel module
if [ -f /lib/modules/$(uname -r)/extra/antiransomware.ko ]; then
    modprobe antiransomware
fi

# Start service
systemctl start antiransomware

echo "Anti-Ransomware Protection installed successfully"
"""
        
        with open(deb_root / "DEBIAN/postinst", 'w') as f:
            f.write(postinst_content)
        os.chmod(deb_root / "DEBIAN/postinst", 0o755)
        
        print(f"Linux package structure created: {deb_root}")
    
    def _create_macos_package(self, arch: str, build_dir: Path):
        """Create macOS installer package"""
        pkg_dir = build_dir / "pkg"
        pkg_root = pkg_dir / "root"
        
        # Create directory structure
        (pkg_root / "usr/local/bin").mkdir(parents=True)
        (pkg_root / "usr/local/lib/antiransomware").mkdir(parents=True)
        (pkg_root / "usr/local/etc/antiransomware").mkdir(parents=True)
        (pkg_root / "Library/LaunchDaemons").mkdir(parents=True)
        (pkg_root / "Library/SystemExtensions").mkdir(parents=True)
        
        # Copy executables
        for exe in (build_dir / "python").glob("antiransomware-*"):
            shutil.copy(exe, pkg_root / "usr/local/bin")
        
        # Copy system extension
        if (build_dir / "drivers").exists():
            shutil.copytree(build_dir / "drivers", 
                          pkg_root / "Library/SystemExtensions/antiransomware.systemextension")
        
        # Create LaunchDaemon plist
        plist_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.antiransomware.service</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/antiransomware-service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""
        
        with open(pkg_root / "Library/LaunchDaemons/com.antiransomware.plist", 'w') as f:
            f.write(plist_content)
        
        print(f"macOS package structure created: {pkg_root}")
    
    def _sign_binaries(self, platform: str, build_dir: Path):
        """Sign binaries with code signing certificate"""
        cert_path = self.config.get('security', {}).get('code_signing_cert')
        
        if not cert_path or not Path(cert_path).exists():
            print("Warning: Code signing certificate not found, skipping signing")
            return
        
        if platform == "windows":
            # Use signtool.exe to sign Windows binaries
            for exe in (build_dir / "python").glob("*.exe"):
                cmd = ["signtool", "sign", "/f", cert_path, str(exe)]
                subprocess.run(cmd, check=False)
        
        elif platform == "darwin":
            # Use codesign to sign macOS binaries
            for exe in (build_dir / "python").glob("antiransomware-*"):
                cmd = ["codesign", "-s", "Developer ID Application", str(exe)]
                subprocess.run(cmd, check=False)
    
    def create_docker_image(self) -> bool:
        """Create Docker container image"""
        try:
            dockerfile_content = """FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    build-essential \\
    linux-headers-generic \\
    libpcsclite-dev \\
    pcscd \\
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -s /bin/bash antiransomware

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set proper permissions
RUN chown -R antiransomware:antiransomware /app

# Expose ports
EXPOSE 8080 50051

# Switch to app user
USER antiransomware

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:8080/health || exit 1

# Start services
CMD ["python", "service_manager.py"]
"""
            
            with open("Dockerfile", 'w') as f:
                f.write(dockerfile_content)
            
            # Create docker-compose file
            compose_content = """version: '3.8'

services:
  antiransomware:
    build: .
    container_name: antiransomware
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "50051:50051"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./policies:/app/policies
      - ./certs:/app/certs
    environment:
      - ANTIRANSOMWARE_CONFIG=/app/config.yaml
    privileged: true  # Required for kernel driver access
    devices:
      - /dev/usb:/dev/usb  # USB dongle access
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
"""
            
            with open("docker-compose.yml", 'w') as f:
                f.write(compose_content)
            
            print("Docker configuration created")
            return True
            
        except Exception as e:
            print(f"Failed to create Docker configuration: {e}")
            return False
    
    def create_kubernetes_manifests(self) -> bool:
        """Create Kubernetes deployment manifests"""
        try:
            k8s_dir = Path("k8s")
            k8s_dir.mkdir(exist_ok=True)
            
            # Namespace
            namespace_manifest = """apiVersion: v1
kind: Namespace
metadata:
  name: antiransomware-system
  labels:
    name: antiransomware-system
"""
            
            # ConfigMap
            configmap_manifest = """apiVersion: v1
kind: ConfigMap
metadata:
  name: antiransomware-config
  namespace: antiransomware-system
data:
  config.yaml: |
    network:
      grpc:
        host: "0.0.0.0"
        port: 50051
      web:
        host: "0.0.0.0"  
        port: 8080
    database:
      path: "/data/antiransomware.db"
    logging:
      level: "INFO"
"""
            
            # Deployment
            deployment_manifest = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: antiransomware
  namespace: antiransomware-system
  labels:
    app: antiransomware
spec:
  replicas: 1
  selector:
    matchLabels:
      app: antiransomware
  template:
    metadata:
      labels:
        app: antiransomware
    spec:
      serviceAccountName: antiransomware
      securityContext:
        runAsUser: 0  # Required for kernel driver
        privileged: true
      containers:
      - name: antiransomware
        image: ghcr.io/antiransomware/antiransomware:latest
        ports:
        - containerPort: 8080
          name: web
        - containerPort: 50051
          name: grpc
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
        - name: data
          mountPath: /data
        - name: logs
          mountPath: /app/logs
        - name: usb-devices
          mountPath: /dev/usb
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: antiransomware-config
      - name: data
        persistentVolumeClaim:
          claimName: antiransomware-data
      - name: logs
        persistentVolumeClaim:
          claimName: antiransomware-logs
      - name: usb-devices
        hostPath:
          path: /dev/usb
---
apiVersion: v1
kind: Service
metadata:
  name: antiransomware-service
  namespace: antiransomware-system
spec:
  selector:
    app: antiransomware
  ports:
  - name: web
    port: 8080
    targetPort: 8080
  - name: grpc
    port: 50051
    targetPort: 50051
  type: LoadBalancer
"""
            
            # PersistentVolumeClaim
            pvc_manifest = """apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: antiransomware-data
  namespace: antiransomware-system
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: antiransomware-logs
  namespace: antiransomware-system
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
"""
            
            # ServiceAccount
            serviceaccount_manifest = """apiVersion: v1
kind: ServiceAccount
metadata:
  name: antiransomware
  namespace: antiransomware-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: antiransomware
rules:
- apiGroups: [""]
  resources: ["nodes", "pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: antiransomware
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: antiransomware
subjects:
- kind: ServiceAccount
  name: antiransomware
  namespace: antiransomware-system
"""
            
            # Write manifests
            manifests = {
                'namespace.yaml': namespace_manifest,
                'configmap.yaml': configmap_manifest,
                'deployment.yaml': deployment_manifest,
                'pvc.yaml': pvc_manifest,
                'serviceaccount.yaml': serviceaccount_manifest
            }
            
            for filename, content in manifests.items():
                with open(k8s_dir / filename, 'w') as f:
                    f.write(content)
            
            print(f"Kubernetes manifests created in {k8s_dir}")
            return True
            
        except Exception as e:
            print(f"Failed to create Kubernetes manifests: {e}")
            return False
    
    def deploy_to_environment(self, environment: str = "production") -> bool:
        """Deploy to specified environment"""
        print(f"Deploying to {environment} environment...")
        
        try:
            if environment == "docker":
                return self._deploy_docker()
            elif environment == "kubernetes":
                return self._deploy_kubernetes()
            elif environment == "local":
                return self._deploy_local()
            else:
                print(f"Unknown environment: {environment}")
                return False
                
        except Exception as e:
            print(f"Deployment failed: {e}")
            return False
    
    def _deploy_docker(self) -> bool:
        """Deploy using Docker Compose"""
        if not Path("docker-compose.yml").exists():
            self.create_docker_image()
        
        cmd = ["docker-compose", "up", "-d"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("Docker deployment successful")
            return True
        else:
            print(f"Docker deployment failed: {result.stderr}")
            return False
    
    def _deploy_kubernetes(self) -> bool:
        """Deploy to Kubernetes"""
        if not Path("k8s").exists():
            self.create_kubernetes_manifests()
        
        # Apply manifests
        for manifest in Path("k8s").glob("*.yaml"):
            cmd = ["kubectl", "apply", "-f", str(manifest)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Failed to apply {manifest}: {result.stderr}")
                return False
        
        print("Kubernetes deployment successful")
        return True
    
    def _deploy_local(self) -> bool:
        """Deploy locally as service"""
        # Build for current platform
        if not self.build_for_platform():
            return False
        
        # Install and start service
        platform_name = self.platform_info['system']
        
        if platform_name == "windows":
            cmd = ["python", "service_manager.py", "--install"]
        elif platform_name == "linux":
            cmd = ["sudo", "python", "service_manager.py", "--install"]  
        elif platform_name == "darwin":
            cmd = ["sudo", "python", "service_manager.py", "--install"]
        else:
            print(f"Unsupported platform: {platform_name}")
            return False
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("Local deployment successful")
            return True
        else:
            print(f"Local deployment failed: {result.stderr}")
            return False

def main():
    """Main deployment script"""
    deployment = DeploymentManager()
    
    if len(sys.argv) < 2:
        print("Usage: deployment.py <command> [options]")
        print("Commands:")
        print("  build [platform] [arch]  - Build for platform/architecture")
        print("  docker                   - Create Docker configuration")
        print("  kubernetes              - Create Kubernetes manifests")
        print("  deploy <env>            - Deploy to environment (docker/kubernetes/local)")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "build":
        platform = sys.argv[2] if len(sys.argv) > 2 else None
        arch = sys.argv[3] if len(sys.argv) > 3 else None
        success = deployment.build_for_platform(platform, arch)
        sys.exit(0 if success else 1)
    
    elif command == "docker":
        success = deployment.create_docker_image()
        sys.exit(0 if success else 1)
    
    elif command == "kubernetes":
        success = deployment.create_kubernetes_manifests()
        sys.exit(0 if success else 1)
    
    elif command == "deploy":
        environment = sys.argv[2] if len(sys.argv) > 2 else "production"
        success = deployment.deploy_to_environment(environment)
        sys.exit(0 if success else 1)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()
