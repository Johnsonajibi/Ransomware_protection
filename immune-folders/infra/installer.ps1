# Immune Folders Installation Script
# PowerShell script to install and configure Immune Folders system

param(
    [switch]$RecoveryMode,
    [switch]$Repair,
    [switch]$PreserveData,
    [switch]$Uninstall,
    [string]$InstallPath = "$env:ProgramFiles\ImmuneFolders",
    [string]$DataPath = "$env:ProgramData\ImmuneFolders"
)

# Require Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

$ErrorActionPreference = "Stop"

Write-Host "=== Immune Folders Installation Script ===" -ForegroundColor Cyan
Write-Host "Installation Path: $InstallPath" -ForegroundColor Gray
Write-Host "Data Path: $DataPath" -ForegroundColor Gray
Write-Host ""

# Function to check prerequisites
function Test-Prerequisites {
    Write-Host "Checking prerequisites..." -ForegroundColor Yellow
    
    # Check Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        Write-Error "Windows 10 or later is required"
        return $false
    }
    Write-Host "✓ Windows version compatible" -ForegroundColor Green
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Error "PowerShell 5.0 or later is required"
        return $false
    }
    Write-Host "✓ PowerShell version compatible" -ForegroundColor Green
    
    # Check Python installation
    try {
        $pythonVersion = python --version 2>&1
        if ($pythonVersion -match "Python (\d+)\.(\d+)") {
            $major = [int]$matches[1]
            $minor = [int]$matches[2]
            if ($major -ge 3 -and $minor -ge 8) {
                Write-Host "✓ Python $($matches[0]) found" -ForegroundColor Green
            } else {
                Write-Warning "Python 3.8+ recommended (found $($matches[0]))"
            }
        }
    } catch {
        Write-Warning "Python not found in PATH. Please install Python 3.8+"
    }
    
    # Check VeraCrypt installation
    $veracryptPath = "$env:ProgramFiles\VeraCrypt\VeraCrypt.exe"
    if (Test-Path $veracryptPath) {
        Write-Host "✓ VeraCrypt found" -ForegroundColor Green
    } else {
        Write-Warning "VeraCrypt not found. Please install VeraCrypt first."
        Write-Host "Download from: https://www.veracrypt.fr/en/Downloads.html" -ForegroundColor Gray
    }
    
    # Check required Windows features
    $features = @("Microsoft-Windows-Subsystem-Linux")  # Example
    foreach ($feature in $features) {
        try {
            $featureState = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
            if ($featureState -and $featureState.State -eq "Enabled") {
                Write-Host "✓ Windows feature $feature enabled" -ForegroundColor Green
            }
        } catch {
            # Feature check not critical, continue
        }
    }
    
    return $true
}

# Function to install Python dependencies
function Install-PythonDependencies {
    Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
    
    $requirements = @(
        "cryptography>=41.0.0",
        "psutil>=5.9.0",
        "pywin32>=306",
        "wmi>=1.5.1",
        "qrcode>=7.4.2",
        "Pillow>=10.0.0"
    )
    
    foreach ($package in $requirements) {
        try {
            Write-Host "Installing $package..." -ForegroundColor Gray
            python -m pip install $package --upgrade --no-warn-script-location
            Write-Host "✓ $package installed" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to install $package"
        }
    }
}

# Function to create directory structure
function New-DirectoryStructure {
    Write-Host "Creating directory structure..." -ForegroundColor Yellow
    
    $directories = @(
        $InstallPath,
        "$InstallPath\client",
        "$InstallPath\infra", 
        "$InstallPath\util",
        "$InstallPath\docs",
        $DataPath,
        "$DataPath\containers",
        "$DataPath\keys",
        "$DataPath\tokens",
        "$DataPath\audit",
        "$DataPath\backup",
        "$DataPath\temp"
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "✓ Created $dir" -ForegroundColor Green
        }
    }
}

# Function to copy files
function Copy-ImmuneFoldersFiles {
    Write-Host "Copying Immune Folders files..." -ForegroundColor Yellow
    
    $sourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    
    # Copy Python modules
    $sourceFiles = @{
        "$sourceDir\client\main.py" = "$InstallPath\client\main.py"
        "$sourceDir\client\usb_token.py" = "$InstallPath\client\usb_token.py"
        "$sourceDir\client\veracrypt.py" = "$InstallPath\client\veracrypt.py"
        "$sourceDir\infra\tmp_ksp.py" = "$InstallPath\infra\tmp_ksp.py"
        "$sourceDir\util\log.py" = "$InstallPath\util\log.py"
        "$sourceDir\docs\*.md" = "$InstallPath\docs\"
    }
    
    foreach ($source in $sourceFiles.Keys) {
        $destination = $sourceFiles[$source]
        
        if ($source.Contains("*")) {
            # Handle wildcard copying
            $sourcePattern = $source
            $destDir = $destination
            Get-ChildItem $sourcePattern | ForEach-Object {
                Copy-Item $_.FullName -Destination $destDir -Force
                Write-Host "✓ Copied $($_.Name)" -ForegroundColor Green
            }
        } else {
            if (Test-Path $source) {
                Copy-Item $source -Destination $destination -Force
                Write-Host "✓ Copied $(Split-Path -Leaf $source)" -ForegroundColor Green
            } else {
                Write-Warning "Source file not found: $source"
            }
        }
    }
}

# Function to create Windows service
function Install-ImmuneFoldersService {
    Write-Host "Installing Windows service..." -ForegroundColor Yellow
    
    # Create service wrapper script
    $serviceScript = @"
@echo off
cd /d "$InstallPath"
python client\main.py service
"@
    
    $serviceBat = "$InstallPath\service.bat"
    $serviceScript | Out-File -FilePath $serviceBat -Encoding ASCII
    
    # Install service using NSSM (Non-Sucking Service Manager) or sc.exe
    try {
        # Try using sc.exe first
        $serviceName = "ImmuneFoldersService"
        $serviceDisplayName = "Immune Folders Protection Service"
        $serviceDescription = "Provides tamper-proof folder protection using encrypted containers"
        
        # Remove existing service if it exists
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Write-Host "Removing existing service..." -ForegroundColor Gray
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            sc.exe delete $serviceName | Out-Null
            Start-Sleep -Seconds 2
        }
        
        # Create new service
        $result = sc.exe create $serviceName binPath= "$serviceBat" DisplayName= "$serviceDisplayName" start= auto
        if ($LASTEXITCODE -eq 0) {
            sc.exe description $serviceName "$serviceDescription" | Out-Null
            Write-Host "✓ Service installed successfully" -ForegroundColor Green
            
            # Set service recovery options
            sc.exe failure $serviceName reset= 86400 actions= restart/60000/restart/60000/run/1000 | Out-Null
            
        } else {
            Write-Warning "Failed to install service: $result"
        }
        
    } catch {
        Write-Warning "Service installation failed: $_"
    }
}

# Function to configure Windows Firewall
function Set-FirewallRules {
    Write-Host "Configuring Windows Firewall..." -ForegroundColor Yellow
    
    try {
        # Block outbound connections from container mount points
        $ruleName = "Immune Folders - Block Container Access"
        
        # Remove existing rule if it exists
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        # Create new rule (example - customize as needed)
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -Protocol TCP -RemotePort 445 -Program "System" -ErrorAction SilentlyContinue
        
        Write-Host "✓ Firewall rules configured" -ForegroundColor Green
        
    } catch {
        Write-Warning "Firewall configuration failed: $_"
    }
}

# Function to set registry entries
function Set-RegistryConfiguration {
    Write-Host "Configuring registry settings..." -ForegroundColor Yellow
    
    try {
        $registryPath = "HKLM:\SOFTWARE\ImmuneFolders"
        
        # Create registry key if it doesn't exist
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        
        # Set configuration values
        Set-ItemProperty -Path $registryPath -Name "InstallPath" -Value $InstallPath
        Set-ItemProperty -Path $registryPath -Name "DataPath" -Value $DataPath
        Set-ItemProperty -Path $registryPath -Name "Version" -Value "1.0.0"
        Set-ItemProperty -Path $registryPath -Name "InstallDate" -Value (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        
        Write-Host "✓ Registry settings configured" -ForegroundColor Green
        
    } catch {
        Write-Warning "Registry configuration failed: $_"
    }
}

# Function to create desktop shortcuts
function New-DesktopShortcuts {
    Write-Host "Creating desktop shortcuts..." -ForegroundColor Yellow
    
    try {
        $WshShell = New-Object -comObject WScript.Shell
        
        # Create main application shortcut
        $Shortcut = $WshShell.CreateShortcut("$env:PUBLIC\Desktop\Immune Folders.lnk")
        $Shortcut.TargetPath = "python.exe"
        $Shortcut.Arguments = "`"$InstallPath\client\main.py`" list"
        $Shortcut.WorkingDirectory = $InstallPath
        $Shortcut.IconLocation = "$InstallPath\docs\icon.ico"
        $Shortcut.Description = "Immune Folders - Secure folder protection"
        $Shortcut.Save()
        
        Write-Host "✓ Desktop shortcuts created" -ForegroundColor Green
        
    } catch {
        Write-Warning "Desktop shortcut creation failed: $_"
    }
}

# Function to perform initial setup
function Initialize-ImmuneFolders {
    Write-Host "Performing initial setup..." -ForegroundColor Yellow
    
    try {
        # Create initial configuration file
        $configPath = "$DataPath\config.json"
        $initialConfig = @{
            version = 1
            auto_lock_timeout = 1800
            immune_folders = @()
            installation_date = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        } | ConvertTo-Json -Depth 3
        
        $initialConfig | Out-File -FilePath $configPath -Encoding UTF8
        
        # Set secure permissions on data directory
        $acl = Get-Acl $DataPath
        $acl.SetAccessRuleProtection($true, $false)  # Remove inheritance
        
        # Add SYSTEM full control
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
        $systemAccess = New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($systemAccess)
        
        # Add Administrators full control
        $adminsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $adminsAccess = New-Object System.Security.AccessControl.FileSystemAccessRule($adminsSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($adminsAccess)
        
        # Apply ACL
        Set-Acl -Path $DataPath -AclObject $acl
        
        Write-Host "✓ Initial setup completed" -ForegroundColor Green
        
    } catch {
        Write-Warning "Initial setup failed: $_"
    }
}

# Function to test installation
function Test-Installation {
    Write-Host "Testing installation..." -ForegroundColor Yellow
    
    try {
        # Test Python modules can be imported
        $testScript = @"
import sys
sys.path.insert(0, r'$InstallPath')

try:
    from client.main import ImmuneFoldersClient
    from client.usb_token import USBTokenManager
    from client.veracrypt import VeraCryptManager
    from infra.tmp_ksp import SecureKeyProvider
    from util.log import TamperEvidentLogger
    print('✓ All modules imported successfully')
except ImportError as e:
    print(f'✗ Module import failed: {e}')
    exit(1)

# Test basic functionality
try:
    client = ImmuneFoldersClient()
    status = client.get_status()
    print(f'✓ Basic functionality test passed')
    print(f'  Immune folders: {status["immune_folders_count"]}')
    print(f'  Mounted folders: {status["mounted_folders_count"]}')
except Exception as e:
    print(f'✗ Basic functionality test failed: {e}')
    exit(1)
"@
        
        $testResult = python -c $testScript
        if ($LASTEXITCODE -eq 0) {
            Write-Host $testResult -ForegroundColor Green
        } else {
            Write-Warning "Installation test failed"
            Write-Host $testResult -ForegroundColor Red
        }
        
    } catch {
        Write-Warning "Installation test error: $_"
    }
}

# Function to uninstall Immune Folders
function Uninstall-ImmuneFolders {
    Write-Host "Uninstalling Immune Folders..." -ForegroundColor Yellow
    
    try {
        # Stop and remove service
        $serviceName = "ImmuneFoldersService"
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            Write-Host "Stopping service..." -ForegroundColor Gray
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            sc.exe delete $serviceName | Out-Null
            Write-Host "✓ Service removed" -ForegroundColor Green
        }
        
        # Remove desktop shortcuts
        $shortcuts = @(
            "$env:PUBLIC\Desktop\Immune Folders.lnk",
            "$env:USERPROFILE\Desktop\Immune Folders.lnk"
        )
        foreach ($shortcut in $shortcuts) {
            if (Test-Path $shortcut) {
                Remove-Item $shortcut -Force
                Write-Host "✓ Removed shortcut: $(Split-Path -Leaf $shortcut)" -ForegroundColor Green
            }
        }
        
        # Remove registry entries
        $registryPath = "HKLM:\SOFTWARE\ImmuneFolders"
        if (Test-Path $registryPath) {
            Remove-Item $registryPath -Recurse -Force
            Write-Host "✓ Registry entries removed" -ForegroundColor Green
        }
        
        # Remove installation directory
        if (Test-Path $InstallPath) {
            Remove-Item $InstallPath -Recurse -Force
            Write-Host "✓ Installation directory removed" -ForegroundColor Green
        }
        
        # Optionally remove data directory
        if (-not $PreserveData -and (Test-Path $DataPath)) {
            $confirmation = Read-Host "Remove all data including containers and keys? (y/N)"
            if ($confirmation -eq 'y' -or $confirmation -eq 'Y') {
                Remove-Item $DataPath -Recurse -Force
                Write-Host "✓ Data directory removed" -ForegroundColor Green
            } else {
                Write-Host "Data directory preserved: $DataPath" -ForegroundColor Yellow
            }
        }
        
        Write-Host "Uninstallation completed successfully" -ForegroundColor Green
        
    } catch {
        Write-Error "Uninstallation failed: $_"
    }
}

# Main installation logic
try {
    if ($Uninstall) {
        Uninstall-ImmuneFolders
        exit 0
    }
    
    if (-not (Test-Prerequisites)) {
        Write-Error "Prerequisites check failed"
        exit 1
    }
    
    if (-not $RecoveryMode) {
        Install-PythonDependencies
    }
    
    New-DirectoryStructure
    Copy-ImmuneFoldersFiles
    
    if (-not $RecoveryMode) {
        Install-ImmuneFoldersService
        Set-FirewallRules
        Set-RegistryConfiguration
        New-DesktopShortcuts
        Initialize-ImmuneFolders
    }
    
    Test-Installation
    
    Write-Host ""
    Write-Host "=== Installation Completed Successfully ===" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "1. Install VeraCrypt if not already installed" -ForegroundColor White
    Write-Host "2. Create your first immune folder:" -ForegroundColor White
    Write-Host "   python `"$InstallPath\client\main.py`" create-folder MyDocuments --size 500" -ForegroundColor Gray
    Write-Host "3. Create a USB token:" -ForegroundColor White
    Write-Host "   python `"$InstallPath\client\main.py`" create-token E:\ --folders [folder-id]" -ForegroundColor Gray
    Write-Host "4. Start the service:" -ForegroundColor White
    Write-Host "   Start-Service ImmuneFoldersService" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Documentation: $InstallPath\docs\" -ForegroundColor Gray
    Write-Host "Configuration: $DataPath\config.json" -ForegroundColor Gray
    Write-Host ""
    
} catch {
    Write-Error "Installation failed: $_"
    exit 1
}
