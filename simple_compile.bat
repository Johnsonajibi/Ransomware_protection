@echo off
REM Simple Direct Kernel Driver Compilation
REM No fancy Unicode characters - just basic compilation

echo REAL KERNEL DRIVER COMPILATION
echo ===============================

REM Check admin
NET SESSION >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Administrator privileges required
    echo Please run as Administrator
    pause
    exit /b 1
)

echo OK: Administrator privileges confirmed

REM Set paths
set "WDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "WDK_VERSION=10.0.26100.0"
set "VS_ROOT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"

set "WDK_BIN=%WDK_ROOT%\bin\%WDK_VERSION%\x64"
set "WDK_INC=%WDK_ROOT%\Include\%WDK_VERSION%"
set "WDK_LIB=%WDK_ROOT%\Lib\%WDK_VERSION%"

REM Check WDK
if not exist "%WDK_BIN%" (
    echo ERROR: WDK not found at %WDK_BIN%
    pause
    exit /b 1
)

echo OK: WDK found at %WDK_BIN%

REM Find Visual Studio tools
set "CL_EXE="
for /d %%i in ("%VS_ROOT%\VC\Tools\MSVC\*") do (
    if exist "%%i\bin\Hostx64\x64\cl.exe" (
        set "CL_EXE=%%i\bin\Hostx64\x64\cl.exe"
        set "LINK_EXE=%%i\bin\Hostx64\x64\link.exe"
        goto found_vs
    )
)

:found_vs
if "%CL_EXE%"=="" (
    echo ERROR: Visual Studio cl.exe not found
    pause
    exit /b 1
)

echo OK: Found Visual Studio tools
echo   cl.exe: %CL_EXE%
echo   link.exe: %LINK_EXE%

REM Create build directory
if exist build_real rmdir /s /q build_real
mkdir build_real

echo.
echo COMPILING KERNEL DRIVER...
echo ==========================

REM Compile to object file
"%CL_EXE%" /c /Zp8 /W3 /Gz /GR- /GF /Zc:wchar_t- /Zc:forScope /GS- /kernel ^
    /DWINNT=1 /D_WIN64 /D_AMD64_ /DSTD_CALL /DCONDITION_HANDLING=1 ^
    /DNT_UP=1 /DNT_INST=0 /DWIN32=100 /D_NT1X_=100 /DWINVER=0x0A00 ^
    /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A000000 ^
    /I"%WDK_INC%\km" /I"%WDK_INC%\km\crt" /I"%WDK_INC%\shared" /I"%WDK_INC%\um" ^
    /Fo:build_real\RealAntiRansomwareDriver.obj ^
    RealAntiRansomwareDriver.c

if %errorLevel% neq 0 (
    echo ERROR: Compilation failed
    pause
    exit /b 1
)

echo OK: Object file compiled

echo.
echo LINKING KERNEL DRIVER...
echo ========================

REM Link the driver
"%LINK_EXE%" /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE ^
    /LIBPATH:"%WDK_LIB%\km\x64" ^
    /OUT:build_real\RealAntiRansomwareDriver.sys ^
    /MACHINE:X64 /KERNEL /NODEFAULTLIB ^
    /SECTION:INIT,d /MERGE:_PAGE=PAGE /MERGE:_TEXT=.text ^
    /STACK:0x40000,0x1000 /ALIGN:0x80 ^
    /RELEASE /INCREMENTAL:NO /OPT:REF /OPT:ICF ^
    ntoskrnl.lib hal.lib fltMgr.lib ntstrsafe.lib ^
    build_real\RealAntiRansomwareDriver.obj

if %errorLevel% neq 0 (
    echo ERROR: Linking failed
    pause
    exit /b 1
)

echo OK: Driver linked successfully

REM Check result
if exist build_real\RealAntiRansomwareDriver.sys (
    echo.
    echo SUCCESS! Real kernel driver created!
    echo ====================================
    
    for %%F in (build_real\RealAntiRansomwareDriver.sys) do (
        echo Driver: %%~fF
        echo Size: %%~zF bytes
    )
    
    REM Copy support files
    copy RealAntiRansomwareDriver.inf build_real\ >nul 2>&1
    
    echo.
    echo COMPILING C++ MANAGER...
    echo ========================
    
    REM Compile C++ manager
    "%CL_EXE%" /EHsc /std:c++17 /O2 /MT /Fe:build_real\RealAntiRansomwareManager.exe ^
        RealAntiRansomwareManager.cpp ^
        setupapi.lib newdev.lib cfgmgr32.lib ole32.lib user32.lib kernel32.lib advapi32.lib
    
    if %errorLevel% equ 0 (
        echo OK: C++ manager compiled
    ) else (
        echo ERROR: C++ manager compilation failed
    )
    
    echo.
    echo BUILD COMPLETE!
    echo ===============
    echo.
    echo Build artifacts in build_real/:
    dir build_real\
    echo.
    echo NEXT STEPS:
    echo 1. Enable test signing: bcdedit /set testsigning on
    echo 2. Reboot system
    echo 3. Install driver: build_real\RealAntiRansomwareManager.exe install
    echo 4. Test: build_real\RealAntiRansomwareManager.exe status
    echo.
    
) else (
    echo ERROR: Driver file not created
    pause
    exit /b 1
)

pause
