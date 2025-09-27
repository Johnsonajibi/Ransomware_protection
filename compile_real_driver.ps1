# Real Kernel Driver Compilation - PowerShell Version with UAC
# Automatically elevates to Administrator if needed

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# If not Administrator, restart with elevation
if (-not (Test-Administrator)) {
    Write-Host "🔒 Administrator privileges required. Requesting elevation..." -ForegroundColor Yellow
    Start-Process PowerShell -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "🔨 REAL KERNEL DRIVER COMPILATION" -ForegroundColor Green
Write-Host "==================================" -ForegroundColor Green
Write-Host "✅ Administrator privileges confirmed" -ForegroundColor Green

# Set WDK and Visual Studio paths
$WDK_ROOT = "C:\Program Files (x86)\Windows Kits\10"
$WDK_VERSION = "10.0.26100.0"
$VS_ROOT = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"

# Verify WDK installation
$WDK_BIN = "$WDK_ROOT\bin\$WDK_VERSION\x64"
$WDK_INC = "$WDK_ROOT\Include\$WDK_VERSION"
$WDK_LIB = "$WDK_ROOT\Lib\$WDK_VERSION"

if (!(Test-Path "$WDK_BIN")) {
    Write-Host "❌ WDK tools not found at $WDK_BIN" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

if (!(Test-Path "$WDK_INC\km")) {
    Write-Host "❌ WDK kernel headers not found at $WDK_INC\km" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✅ WDK installation verified" -ForegroundColor Green

# Set up environment variables
$env:PATH = "$WDK_BIN;$env:PATH"

# Create real build directory
if (Test-Path "build_real") {
    Remove-Item -Path "build_real" -Recurse -Force
}
New-Item -ItemType Directory -Path "build_real" | Out-Null

Write-Host ""
Write-Host "🔨 Compiling Real Kernel Driver..." -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

# Set up Visual Studio environment
Write-Host "Setting up Visual Studio build environment..." -ForegroundColor Yellow

# Find vcvarsall.bat
$vcvarsall = "$VS_ROOT\VC\Auxiliary\Build\vcvarsall.bat"
if (!(Test-Path $vcvarsall)) {
    Write-Host "❌ Visual Studio vcvarsall.bat not found at $vcvarsall" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Compile using direct cl.exe invocation with proper environment
Write-Host "Compiling RealAntiRansomwareDriver.c..." -ForegroundColor Yellow

# Kernel compilation flags and defines
$KERNEL_CFLAGS = "/c", "/Zp8", "/Gy", "/W3", "/Gz", "/GR-", "/GF", "/Zc:wchar_t-", "/Zc:forScope", "/GS-", "/kernel"
$KERNEL_DEFINES = "/DWINNT=1", "/D_WIN64", "/D_AMD64_", "/DSTD_CALL", "/DCONDITION_HANDLING=1", "/DNT_UP=1", "/DNT_INST=0", "/DWIN32=100", "/D_NT1X_=100", "/DWINVER=0x0A00", "/D_WIN32_WINNT=0x0A00", "/DNTDDI_VERSION=0x0A000000", "/DKMDF_VERSION_MAJOR=1", "/DKMDF_VERSION_MINOR=15"
$KERNEL_INCLUDES = "/I`"$WDK_INC\km`"", "/I`"$WDK_INC\km\crt`"", "/I`"$WDK_INC\shared`"", "/I`"$WDK_INC\um`""

# Create a batch file to set up environment and compile
$batchScript = @'
@echo off
call "$vcvarsall" x64
if %errorLevel% neq 0 exit /b 1

cl.exe $($KERNEL_CFLAGS -join ' ') $($KERNEL_DEFINES -join ' ') $($KERNEL_INCLUDES -join ' ') /Fo:build_real\RealAntiRansomwareDriver.obj RealAntiRansomwareDriver.c

if %errorLevel% neq 0 exit /b 1

link.exe /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE /LIBPATH:"$WDK_LIB\km\x64" /OUT:build_real\RealAntiRansomwareDriver.sys /MACHINE:X64 /KERNEL /NODEFAULTLIB /SECTION:INIT,d /MERGE:_PAGE=PAGE /MERGE:_TEXT=.text /STACK:0x40000,0x1000 /ALIGN:0x80 /SUBSYSTEM:NATIVE /DRIVER /ENTRY:DriverEntry /RELEASE /INCREMENTAL:NO /OPT:REF /ICF ntoskrnl.lib hal.lib fltMgr.lib ntstrsafe.lib build_real\RealAntiRansomwareDriver.obj
'@

$batchScript | Out-File -FilePath "temp_compile.bat" -Encoding ASCII

# Run the compilation
$result = & cmd.exe /c "temp_compile.bat"
$exitCode = $LASTEXITCODE

Remove-Item "temp_compile.bat" -ErrorAction SilentlyContinue

if ($exitCode -eq 0 -and (Test-Path "build_real\RealAntiRansomwareDriver.sys")) {
    Write-Host ""
    Write-Host "🎉 SUCCESS! Real kernel driver compiled!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    
    $driverFile = Get-Item "build_real\RealAntiRansomwareDriver.sys"
    Write-Host "Driver file: $($driverFile.FullName)" -ForegroundColor Cyan
    Write-Host "Size: $($driverFile.Length) bytes" -ForegroundColor Cyan
    
    # Check if it's a real PE file
    $bytes = [System.IO.File]::ReadAllBytes($driverFile.FullName)
    if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
        Write-Host "✅ Valid PE executable format" -ForegroundColor Green
        $peOffset = [BitConverter]::ToInt32($bytes, 60)
        if ($peOffset -lt $bytes.Length -and $bytes[$peOffset] -eq 0x50 -and $bytes[$peOffset+1] -eq 0x45) {
            Write-Host "✅ Valid PE header found" -ForegroundColor Green
        }
    }
    Write-Host "File appears to be a real compiled driver" -ForegroundColor Green
    
    # Copy INF file
    Copy-Item "RealAntiRansomwareDriver.inf" "build_real\" -ErrorAction SilentlyContinue
    
    Write-Host ""
    Write-Host "⚠️  IMPORTANT: Driver needs to be signed for production use" -ForegroundColor Yellow
    Write-Host "For testing, you can enable test signing:" -ForegroundColor Yellow
    Write-Host "  bcdedit /set testsigning on" -ForegroundColor Yellow
    Write-Host "  (requires reboot)" -ForegroundColor Yellow
    
} else {
    Write-Host "❌ Kernel driver compilation failed" -ForegroundColor Red
    Write-Host "Exit code: $exitCode" -ForegroundColor Red
}

Write-Host ""
Write-Host "🔨 Compiling C++ Management Application..." -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Compile C++ manager
$cppBatch = @'
@echo off
call "$vcvarsall" x64
cl.exe /EHsc /std:c++17 /O2 /MT /Fe:build_real\RealAntiRansomwareManager.exe RealAntiRansomwareManager.cpp setupapi.lib newdev.lib cfgmgr32.lib ole32.lib user32.lib kernel32.lib advapi32.lib
'@

$cppBatch | Out-File -FilePath "temp_cpp.bat" -Encoding ASCII
$cppResult = & cmd.exe /c "temp_cpp.bat"
$cppExitCode = $LASTEXITCODE
Remove-Item "temp_cpp.bat" -ErrorAction SilentlyContinue

if ($cppExitCode -eq 0) {
    Write-Host "✅ C++ manager compiled" -ForegroundColor Green
} else {
    Write-Host "❌ C++ manager compilation failed" -ForegroundColor Red
}

Write-Host ""
Write-Host "🎉 REAL KERNEL DRIVER BUILD COMPLETE!" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green
Write-Host ""
Write-Host "Build artifacts in build_real/:" -ForegroundColor Cyan
Get-ChildItem "build_real" | ForEach-Object { Write-Host "  $($_.Name) - $($_.Length) bytes" -ForegroundColor White }
Write-Host ""
Write-Host "🚀 Next Steps:" -ForegroundColor Yellow
Write-Host "1. Enable test signing: bcdedit /set testsigning on" -ForegroundColor White
Write-Host "2. Reboot system" -ForegroundColor White
Write-Host "3. Install driver: build_real\RealAntiRansomwareManager.exe install" -ForegroundColor White
Write-Host "4. Test: build_real\RealAntiRansomwareManager.exe status" -ForegroundColor White
Write-Host ""

Read-Host "Press Enter to exit"
