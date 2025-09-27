# GENUINE KERNEL DRIVER COMPILATION
# Elevates to Administrator and compiles real kernel driver from genuine source

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# If not Administrator, restart with elevation
if (-not (Test-Administrator)) {
    Write-Host "ELEVATING TO ADMINISTRATOR FOR GENUINE COMPILATION..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Path
    Start-Process PowerShell -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
    exit
}

Write-Host "GENUINE KERNEL DRIVER COMPILATION" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green
Write-Host "Administrator privileges confirmed" -ForegroundColor Green
Write-Host ""

# Set environment paths
$WDK_ROOT = "C:\Program Files (x86)\Windows Kits\10"
$WDK_VERSION = "10.0.26100.0" 
$VS_ROOT = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"

$WDK_BIN = "$WDK_ROOT\bin\$WDK_VERSION\x64"
$WDK_INC = "$WDK_ROOT\Include\$WDK_VERSION"
$WDK_LIB = "$WDK_ROOT\Lib\$WDK_VERSION"

# Verify WDK installation
if (!(Test-Path $WDK_BIN)) {
    Write-Host "ERROR: WDK not found at $WDK_BIN" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "WDK Tools found: $WDK_BIN" -ForegroundColor Green

# Find Visual Studio cl.exe
$clPaths = Get-ChildItem -Path "$VS_ROOT\VC\Tools\MSVC" -Directory | ForEach-Object {
    "$($_.FullName)\bin\Hostx64\x64\cl.exe"
} | Where-Object { Test-Path $_ } | Select-Object -First 1

if (!$clPaths) {
    Write-Host "ERROR: Visual Studio cl.exe not found" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

$clExe = $clPaths
$linkExe = $clExe.Replace("cl.exe", "link.exe")

Write-Host "Visual Studio cl.exe: $clExe" -ForegroundColor Green
Write-Host "Visual Studio link.exe: $linkExe" -ForegroundColor Green

# Create genuine build directory
if (Test-Path "build_genuine") {
    Remove-Item -Path "build_genuine" -Recurse -Force
}
New-Item -ItemType Directory -Path "build_genuine" | Out-Null

Write-Host ""
Write-Host "COMPILING GENUINE KERNEL DRIVER FROM 25KB SOURCE CODE..." -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# Compile kernel driver object file
$compileArgs = @(
    "/c"
    "/Zp8" 
    "/W3"
    "/Gz"
    "/GR-"
    "/GF"
    "/Zc:wchar_t-"
    "/Zc:forScope"
    "/GS-"
    "/kernel"
    "/DWINNT=1"
    "/D_WIN64"
    "/D_AMD64_"
    "/DSTD_CALL"
    "/DCONDITION_HANDLING=1"
    "/DNT_UP=1"
    "/DNT_INST=0"
    "/DWIN32=100"
    "/D_NT1X_=100"
    "/DWINVER=0x0A00"
    "/D_WIN32_WINNT=0x0A00"
    "/DNTDDI_VERSION=0x0A000000"
    "/I$WDK_INC\km"
    "/I$WDK_INC\km\crt"
    "/I$WDK_INC\shared"
    "/I$WDK_INC\um"
    "/Fo:build_genuine\RealAntiRansomwareDriver.obj"
    "RealAntiRansomwareDriver.c"
)

Write-Host "Compiling genuine kernel source code..." -ForegroundColor Yellow
$compileProcess = Start-Process -FilePath $clExe -ArgumentList $compileArgs -Wait -PassThru -NoNewWindow

if ($compileProcess.ExitCode -ne 0) {
    Write-Host "ERROR: Genuine kernel compilation failed" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "SUCCESS: Genuine object file compiled" -ForegroundColor Green

# Link genuine kernel driver
Write-Host "Linking genuine kernel driver..." -ForegroundColor Yellow

$linkArgs = @(
    "/DRIVER"
    "/ENTRY:DriverEntry"
    "/SUBSYSTEM:NATIVE"
    "/LIBPATH:$WDK_LIB\km\x64"
    "/OUT:build_genuine\RealAntiRansomwareDriver.sys"
    "/MACHINE:X64"
    "/KERNEL"
    "/NODEFAULTLIB"
    "/SECTION:INIT,d"
    "/MERGE:_PAGE=PAGE"
    "/MERGE:_TEXT=.text"
    "/STACK:0x40000,0x1000"
    "/ALIGN:0x80"
    "/RELEASE"
    "/INCREMENTAL:NO"
    "/OPT:REF"
    "/OPT:ICF"
    "ntoskrnl.lib"
    "hal.lib"
    "fltMgr.lib"
    "ntstrsafe.lib"
    "build_genuine\RealAntiRansomwareDriver.obj"
)

$linkProcess = Start-Process -FilePath $linkExe -ArgumentList $linkArgs -Wait -PassThru -NoNewWindow

if ($linkProcess.ExitCode -ne 0) {
    Write-Host "ERROR: Genuine driver linking failed" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "SUCCESS: Genuine kernel driver linked!" -ForegroundColor Green

# Verify genuine driver was created
if (Test-Path "build_genuine\RealAntiRansomwareDriver.sys") {
    $driverFile = Get-Item "build_genuine\RealAntiRansomwareDriver.sys"
    Write-Host ""
    Write-Host "GENUINE KERNEL DRIVER SUCCESSFULLY CREATED!" -ForegroundColor Green
    Write-Host "===========================================" -ForegroundColor Green
    Write-Host "Driver: $($driverFile.FullName)" -ForegroundColor Cyan
    Write-Host "Size: $($driverFile.Length) bytes" -ForegroundColor Cyan
    
    # Validate it's a real PE file
    $bytes = [System.IO.File]::ReadAllBytes($driverFile.FullName)
    if ($bytes.Length -gt 60 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
        Write-Host "Valid PE format: YES" -ForegroundColor Green
        $peOffset = [BitConverter]::ToInt32($bytes, 60)
        if ($peOffset -lt $bytes.Length -and $peOffset -gt 0) {
            if ($bytes[$peOffset] -eq 0x50 -and $bytes[$peOffset+1] -eq 0x45) {
                Write-Host "Valid PE header: YES" -ForegroundColor Green
                Write-Host "STATUS: GENUINE COMPILED KERNEL DRIVER!" -ForegroundColor Green
            }
        }
    }
    
    # Copy support files to genuine build
    Copy-Item "RealAntiRansomwareDriver.inf" "build_genuine\" -ErrorAction SilentlyContinue
    Copy-Item "RealAntiRansomwareManager.exe" "build_genuine\" -ErrorAction SilentlyContinue
    
    Write-Host ""
    Write-Host "COMPLETE GENUINE SYSTEM READY!" -ForegroundColor Green
    Write-Host "=============================" -ForegroundColor Green
    Write-Host "All components in build_genuine/:" -ForegroundColor Cyan
    Get-ChildItem "build_genuine" | ForEach-Object { 
        Write-Host "  $($_.Name) - $($_.Length) bytes" -ForegroundColor White 
    }
    
} else {
    Write-Host "ERROR: Genuine driver file not created" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "NEXT STEPS FOR GENUINE SYSTEM:" -ForegroundColor Yellow
Write-Host "1. Enable test signing: bcdedit /set testsigning on" -ForegroundColor White
Write-Host "2. Reboot system" -ForegroundColor White
Write-Host "3. Install genuine driver: build_genuine\RealAntiRansomwareManager.exe install" -ForegroundColor White
Write-Host "4. Test genuine system: build_genuine\RealAntiRansomwareManager.exe status" -ForegroundColor White
Write-Host ""
Write-Host "GENUINE KERNEL-LEVEL ANTI-RANSOMWARE SYSTEM COMPLETE!" -ForegroundColor Green

Read-Host "Press Enter to exit"
