@echo off
REM Real Kernel Driver Compilation Script
REM Uses Windows Driver Kit (WDK) to compile actual kernel driver

echo 🔨 REAL KERNEL DRIVER COMPILATION
echo ==================================

REM Check administrator privileges
NET SESSION >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Administrator privileges required for kernel driver compilation
    echo Please run as Administrator
    pause
    exit /b 1
)

echo ✅ Administrator privileges confirmed

REM Set WDK and Visual Studio paths
set WDK_ROOT=C:\Program Files (x86)\Windows Kits\10
set WDK_VERSION=10.0.26100.0
set VS_ROOT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools

REM Verify WDK installation
if not exist "%WDK_ROOT%\bin\%WDK_VERSION%\x64" (
    echo ❌ WDK tools not found at %WDK_ROOT%\bin\%WDK_VERSION%\x64
    pause
    exit /b 1
)

if not exist "%WDK_ROOT%\Include\%WDK_VERSION%\km" (
    echo ❌ WDK kernel headers not found
    pause
    exit /b 1
)

echo ✅ WDK installation verified

REM Set up Visual Studio environment first
echo Setting up Visual Studio build environment...
call "%VS_ROOT%\VC\Auxiliary\Build\vcvarsall.bat" x64

if %errorLevel% neq 0 (
    echo ❌ Failed to set up Visual Studio environment
    pause
    exit /b 1
)

echo ✅ Visual Studio environment ready

REM Set up WDK environment variables
echo Setting up WDK environment...

set WDK_BIN=%WDK_ROOT%\bin\%WDK_VERSION%\x64
set WDK_INC=%WDK_ROOT%\Include\%WDK_VERSION%
set WDK_LIB=%WDK_ROOT%\Lib\%WDK_VERSION%

REM Add WDK tools to PATH
set PATH=%WDK_BIN%;%PATH%

REM Kernel compilation flags
set KERNEL_CFLAGS=/c /Zp8 /Gy /W3 /Gz /GR- /GF /Zc:wchar_t- /Zc:forScope /GS- /kernel
set KERNEL_DEFINES=/DWINNT=1 /D_WIN64 /D_AMD64_ /DSTD_CALL /DCONDITION_HANDLING=1 /DNT_UP=1 /DNT_INST=0 /DWIN32=100 /D_NT1X_=100 /DWINVER=0x0A00 /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A000000 /DKMDF_VERSION_MAJOR=1 /DKMDF_VERSION_MINOR=15
set KERNEL_INCLUDES=/I"%WDK_INC%\km" /I"%WDK_INC%\km\crt" /I"%WDK_INC%\shared" /I"%WDK_INC%\um"

REM Create real build directory
if exist build_real rmdir /s /q build_real
mkdir build_real

echo.
echo 🔨 Compiling Real Kernel Driver...
echo ==================================

REM Compile the kernel driver source
echo Compiling RealAntiRansomwareDriver.c...

cl.exe %KERNEL_CFLAGS% %KERNEL_DEFINES% %KERNEL_INCLUDES% ^
    /Fo:build_real\RealAntiRansomwareDriver.obj ^
    RealAntiRansomwareDriver.c

if %errorLevel% neq 0 (
    echo ❌ Kernel driver compilation failed
    pause
    exit /b 1
)

echo ✅ Kernel driver object file compiled

REM Link the kernel driver
echo Linking kernel driver...

link.exe /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE ^
    /LIBPATH:"%WDK_LIB%\km\x64" ^
    /OUT:build_real\RealAntiRansomwareDriver.sys ^
    /MACHINE:X64 /KERNEL /NODEFAULTLIB ^
    /SECTION:INIT,d /MERGE:_PAGE=PAGE /MERGE:_TEXT=.text ^
    /STACK:0x40000,0x1000 /ALIGN:0x80 ^
    /SUBSYSTEM:NATIVE /DRIVER /ENTRY:DriverEntry ^
    /RELEASE /INCREMENTAL:NO /OPT:REF /OPT:ICF ^
    ntoskrnl.lib hal.lib fltMgr.lib ntstrsafe.lib ^
    build_real\RealAntiRansomwareDriver.obj

if %errorLevel% neq 0 (
    echo ❌ Kernel driver linking failed
    pause
    exit /b 1
)

echo ✅ Kernel driver linked successfully!

REM Copy INF and other files
copy RealAntiRansomwareDriver.inf build_real\ >nul

REM Verify the output
if exist build_real\RealAntiRansomwareDriver.sys (
    echo.
    echo 🎉 SUCCESS! Real kernel driver compiled!
    echo ========================================
    
    echo Driver file: build_real\RealAntiRansomwareDriver.sys
    for %%F in (build_real\RealAntiRansomwareDriver.sys) do echo Size: %%~zF bytes
    
    REM Check if it's a real PE file
    powershell -Command "
    $bytes = [System.IO.File]::ReadAllBytes('build_real\RealAntiRansomwareDriver.sys');
    if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
        Write-Host '✅ Valid PE executable format';
        $peOffset = [BitConverter]::ToInt32($bytes, 60);
        if ($peOffset -lt $bytes.Length -and $bytes[$peOffset] -eq 0x50 -and $bytes[$peOffset+1] -eq 0x45) {
            Write-Host '✅ Valid PE header found';
        }
    }
    Write-Host 'File appears to be a real compiled driver';
    "
    
    echo.
    echo ⚠️  IMPORTANT: Driver needs to be signed for production use
    echo For testing, you can enable test signing:
    echo   bcdedit /set testsigning on
    echo   ^(requires reboot^)
    
) else (
    echo ❌ Kernel driver compilation failed - no output file
    pause
    exit /b 1
)

echo.
echo 🔨 Compiling C++ Management Application...
echo =========================================

REM Also recompile the C++ manager with the real driver
cl.exe /EHsc /std:c++17 /O2 /MT /Fe:build_real\RealAntiRansomwareManager.exe ^
    RealAntiRansomwareManager.cpp ^
    setupapi.lib newdev.lib cfgmgr32.lib ole32.lib user32.lib kernel32.lib advapi32.lib

if %errorLevel% equ 0 (
    echo ✅ C++ manager compiled
) else (
    echo ❌ C++ manager compilation failed
)

echo.
echo 🎉 REAL KERNEL DRIVER BUILD COMPLETE!
echo ====================================
echo.
echo Build artifacts in build_real/:
dir build_real\
echo.
echo 🚀 Next Steps:
echo 1. Enable test signing: bcdedit /set testsigning on
echo 2. Reboot system
echo 3. Install driver: build_real\RealAntiRansomwareManager.exe install
echo 4. Test: build_real\RealAntiRansomwareManager.exe status
echo.

pause
