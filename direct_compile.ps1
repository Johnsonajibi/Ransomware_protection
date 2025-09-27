# Simple Direct Compilation Approach
# Uses cl.exe and link.exe directly with proper WDK paths

# Check if running as Administrator
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "🔒 Administrator privileges required. Requesting elevation..." -ForegroundColor Yellow
    Start-Process PowerShell -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "🔨 DIRECT KERNEL DRIVER COMPILATION" -ForegroundColor Green
Write-Host "===================================" -ForegroundColor Green

# Set paths
$WDK_ROOT = "C:\Program Files (x86)\Windows Kits\10"
$WDK_VERSION = "10.0.26100.0"
$VS_ROOT = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"

$WDK_BIN = "$WDK_ROOT\bin\$WDK_VERSION\x64"
$WDK_INC = "$WDK_ROOT\Include\$WDK_VERSION"
$WDK_LIB = "$WDK_ROOT\Lib\$WDK_VERSION"

# Check paths
if (!(Test-Path $WDK_BIN)) {
    Write-Host "❌ WDK not found: $WDK_BIN" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit
}

Write-Host "✅ Found WDK at: $WDK_BIN" -ForegroundColor Green

# Create build directory
if (Test-Path "build_real") { Remove-Item -Path "build_real" -Recurse -Force }
New-Item -ItemType Directory -Path "build_real" | Out-Null

# Set environment
$env:PATH = "$WDK_BIN;$env:PATH"

# Try to find Visual Studio cl.exe
$clPaths = @(
    "$VS_ROOT\VC\Tools\MSVC\14.39.33519\bin\Hostx64\x64\cl.exe",
    "$VS_ROOT\VC\Tools\MSVC\14.38.33130\bin\Hostx64\x64\cl.exe",
    "$VS_ROOT\VC\Tools\MSVC\14.37.32822\bin\Hostx64\x64\cl.exe"
)

$clExe = $null
foreach ($path in $clPaths) {
    if (Test-Path $path) {
        $clExe = $path
        break
    }
}

if (-not $clExe) {
    Write-Host "❌ Visual Studio cl.exe not found" -ForegroundColor Red
    Write-Host "Searching for cl.exe..." -ForegroundColor Yellow
    $found = Get-ChildItem -Path "$VS_ROOT" -Name "cl.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        $clExe = "$VS_ROOT\$found"
        Write-Host "Found cl.exe at: $clExe" -ForegroundColor Green
    } else {
        Read-Host "Press Enter to exit"
        exit
    }
} else {
    Write-Host "✅ Found Visual Studio cl.exe: $clExe" -ForegroundColor Green
}

# Find link.exe in the same directory as cl.exe
$linkExe = $clExe.Replace("cl.exe", "link.exe")
if (!(Test-Path $linkExe)) {
    Write-Host "❌ link.exe not found at: $linkExe" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit
}

Write-Host "✅ Found link.exe: $linkExe" -ForegroundColor Green

Write-Host ""
Write-Host "🔨 Compiling kernel driver..." -ForegroundColor Cyan

# Compile object file
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
    "/Fo:build_real\RealAntiRansomwareDriver.obj"
    "RealAntiRansomwareDriver.c"
)

Write-Host "Running: $clExe with compilation flags..." -ForegroundColor Yellow
$compileResult = & $clExe @compileArgs
$compileExitCode = $LASTEXITCODE

if ($compileExitCode -ne 0) {
    Write-Host "❌ Compilation failed with exit code: $compileExitCode" -ForegroundColor Red
    Write-Host "Compile output:" -ForegroundColor Yellow
    Write-Host $compileResult -ForegroundColor Gray
    Read-Host "Press Enter to exit"
    exit
}

Write-Host "✅ Object file compiled successfully" -ForegroundColor Green

# Link the driver
Write-Host "🔗 Linking kernel driver..." -ForegroundColor Cyan

$linkArgs = @(
    "/DRIVER"
    "/ENTRY:DriverEntry"
    "/SUBSYSTEM:NATIVE"
    "/LIBPATH:$WDK_LIB\km\x64"
    "/OUT:build_real\RealAntiRansomwareDriver.sys"
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
    "build_real\RealAntiRansomwareDriver.obj"
)

Write-Host "Running: $linkExe with linking flags..." -ForegroundColor Yellow
$linkResult = & $linkExe @linkArgs
$linkExitCode = $LASTEXITCODE

if ($linkExitCode -ne 0) {
    Write-Host "❌ Linking failed with exit code: $linkExitCode" -ForegroundColor Red
    Write-Host "Link output:" -ForegroundColor Yellow
    Write-Host $linkResult -ForegroundColor Gray
} else {
    Write-Host "✅ Driver linked successfully!" -ForegroundColor Green
}

# Check result
if (Test-Path "build_real\RealAntiRansomwareDriver.sys") {
    $driverFile = Get-Item "build_real\RealAntiRansomwareDriver.sys"
    Write-Host ""
    Write-Host "🎉 SUCCESS! Real kernel driver created!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Driver: $($driverFile.FullName)" -ForegroundColor Cyan
    Write-Host "Size: $($driverFile.Length) bytes" -ForegroundColor Cyan
    
    # Basic PE validation
    $bytes = [System.IO.File]::ReadAllBytes($driverFile.FullName)
    if ($bytes.Length -gt 60 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
        Write-Host "✅ Valid PE format detected" -ForegroundColor Green
        $peOffset = [BitConverter]::ToInt32($bytes, 60)
        if ($peOffset -lt $bytes.Length -and $peOffset -gt 0 -and 
            $bytes[$peOffset] -eq 0x50 -and $bytes[$peOffset+1] -eq 0x45) {
            Write-Host "✅ Valid PE header found" -ForegroundColor Green
            Write-Host "✅ This appears to be a real compiled kernel driver!" -ForegroundColor Green
        }
    }
    
    # Copy support files
    Copy-Item "RealAntiRansomwareDriver.inf" "build_real\" -ErrorAction SilentlyContinue
    
} else {
    Write-Host "❌ Driver file not created" -ForegroundColor Red
}

Write-Host ""
Write-Host "🔨 Compiling C++ Manager..." -ForegroundColor Cyan

# Compile manager application
$cppArgs = @(
    "/EHsc"
    "/std:c++17"
    "/O2"
    "/MT"
    "/Fe:build_real\RealAntiRansomwareManager.exe"
    "RealAntiRansomwareManager.cpp"
    "setupapi.lib"
    "newdev.lib"  
    "cfgmgr32.lib"
    "ole32.lib"
    "user32.lib"
    "kernel32.lib"
    "advapi32.lib"
)

$cppResult = & $clExe @cppArgs
$cppExitCode = $LASTEXITCODE

if ($cppExitCode -eq 0) {
    Write-Host "✅ C++ manager compiled" -ForegroundColor Green
} else {
    Write-Host "❌ C++ manager compilation failed" -ForegroundColor Red
}

Write-Host ""
Write-Host "🎉 BUILD COMPLETE!" -ForegroundColor Green
Write-Host "=================" -ForegroundColor Green

if (Test-Path "build_real") {
    Write-Host "Build artifacts:" -ForegroundColor Cyan
    Get-ChildItem "build_real" | ForEach-Object { 
        Write-Host "  $($_.Name) - $($_.Length) bytes" -ForegroundColor White 
    }
}

Write-Host ""
Write-Host "🚀 Next Steps:" -ForegroundColor Yellow
Write-Host "1. Enable test signing: bcdedit /set testsigning on" -ForegroundColor White
Write-Host "2. Reboot" -ForegroundColor White  
Write-Host "3. Install: build_real\RealAntiRansomwareManager.exe install" -ForegroundColor White
Write-Host "4. Test: build_real\RealAntiRansomwareManager.exe status" -ForegroundColor White

Read-Host "Press Enter to exit"
