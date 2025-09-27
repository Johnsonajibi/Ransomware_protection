@echo off
REM Setup build environment for kernel driver compilation
echo 🔧 Setting up Visual Studio and WDK build environment...

REM Check if running as administrator
NET SESSION >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Administrator privileges required for kernel driver development
    echo Please run as Administrator
    pause
    exit /b 1
)

echo ✅ Administrator privileges confirmed

REM Set up Visual Studio environment
echo Setting up Visual Studio 2022 environment...
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

if %errorLevel% neq 0 (
    echo ❌ Failed to set up Visual Studio environment
    pause
    exit /b 1
)

echo ✅ Visual Studio environment ready

REM Check if compiler is available
where cl >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Visual Studio C++ compiler not found
    pause
    exit /b 1
)

echo ✅ C++ compiler available

REM Set up WDK environment
echo Setting up Windows Driver Kit environment...

set WDK_ROOT=C:\Program Files (x86)\Windows Kits\10
if not exist "%WDK_ROOT%" (
    echo ❌ Windows Driver Kit not found at %WDK_ROOT%
    pause
    exit /b 1
)

REM Find latest WDK version
for /f "delims=" %%i in ('dir "%WDK_ROOT%\bin" /b /ad /on') do set WDK_VERSION=%%i

echo Using WDK version: %WDK_VERSION%

REM Set WDK paths
set WDK_BIN=%WDK_ROOT%\bin\%WDK_VERSION%\x64
set WDK_INC=%WDK_ROOT%\Include\%WDK_VERSION%
set WDK_LIB=%WDK_ROOT%\Lib\%WDK_VERSION%

if not exist "%WDK_BIN%" (
    echo ❌ WDK binaries not found at %WDK_BIN%
    pause
    exit /b 1
)

echo ✅ Windows Driver Kit ready

REM Update PATH to include WDK tools
set PATH=%WDK_BIN%;%PATH%

echo.
echo 🎯 Build Environment Summary:
echo Visual Studio: 2022 Community
echo WDK Version: %WDK_VERSION%
echo Architecture: x64
echo.

REM Create build directory
if not exist build mkdir build

echo 🔨 Building kernel driver...
echo =============================

REM Compile the kernel driver using proper WDK build
cl.exe /c /Fo:build\ ^
    /I"%WDK_INC%\km" ^
    /I"%WDK_INC%\km\crt" ^
    /I"%WDK_INC%\shared" ^
    /I"%WDK_INC%\um" ^
    /DWINNT=1 /D_WIN64 /D_AMD64_ /DSTD_CALL /DCONDITION_HANDLING=1 ^
    /DNT_UP=1 /DNT_INST=0 /DWIN32=100 /D_NT1X_=100 /DWINVER=0x0A00 ^
    /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A000000 ^
    /DKMDF_VERSION_MAJOR=1 /DKMDF_VERSION_MINOR=15 ^
    /kernel /Zp8 /Gy /W3 /Gz /hotpatch /EHs-c- /GR- /GF ^
    /Zc:wchar_t- /Zc:forScope /GS /fp:precise /Fa /FC ^
    RealAntiRansomwareDriver.c

if %errorLevel% neq 0 (
    echo ❌ Kernel driver compilation failed
    pause
    exit /b 1
)

echo ✅ Kernel driver object compiled

REM Link the driver
link.exe /OUT:build\RealAntiRansomwareDriver.sys ^
    /LIBPATH:"%WDK_LIB%\km\x64" ^
    /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE ^
    /STACK:0x40000,0x1000 /ALIGN:0x80 /SECTION:INIT,D ^
    /MERGE:_PAGE=PAGE /MERGE:_TEXT=.text /FULLBUILD ^
    /RELEASE /NODEFAULTLIB /INCREMENTAL:NO /OPT:REF /OPT:ICF ^
    ntoskrnl.lib hal.lib fltMgr.lib ntstrsafe.lib ^
    build\RealAntiRansomwareDriver.obj

if %errorLevel% neq 0 (
    echo ❌ Kernel driver linking failed
    pause
    exit /b 1
)

echo ✅ Kernel driver linked successfully!

REM Check the output
if exist build\RealAntiRansomwareDriver.sys (
    echo.
    echo 🎉 SUCCESS! Kernel driver compiled:
    dir build\RealAntiRansomwareDriver.sys
    echo.
    echo File size: 
    powershell -Command "(Get-Item 'build\RealAntiRansomwareDriver.sys').Length" 2>nul
    echo.
    echo ⚠️  Note: Driver needs to be signed for production use
    echo ⚠️  For testing, enable test signing mode: bcdedit /set testsigning on
) else (
    echo ❌ Driver compilation failed - no output file created
    pause
    exit /b 1
)

echo.
echo 🔨 Building C++ Management Application...
echo ========================================

REM Compile the C++ manager
cl.exe /EHsc /std:c++17 /O2 /Fe:build\RealAntiRansomwareManager.exe ^
    RealAntiRansomwareManager.cpp ^
    setupapi.lib newdev.lib cfgmgr32.lib ole32.lib user32.lib

if %errorLevel% neq 0 (
    echo ❌ C++ manager compilation failed
    pause
    exit /b 1
)

echo ✅ C++ manager compiled successfully!

REM Copy INF file
copy RealAntiRansomwareDriver.inf build\ >nul

echo.
echo 🎉 BUILD COMPLETE!
echo ================
echo ✅ Kernel Driver: build\RealAntiRansomwareDriver.sys
echo ✅ Manager App: build\RealAntiRansomwareManager.exe  
echo ✅ INF File: build\RealAntiRansomwareDriver.inf
echo.
echo 🚀 Next Steps:
echo 1. Enable test signing: bcdedit /set testsigning on
echo 2. Reboot system
echo 3. Install driver: build\RealAntiRansomwareManager.exe install
echo 4. Check status: build\RealAntiRansomwareManager.exe status
echo.

pause
