@echo off
setlocal
:: ===================================================================
:: FINAL, BULLETPROOF ANTI-RANSOMWARE BUILD SCRIPT
:: This version is designed to be robust against path parsing errors.
:: ===================================================================

echo.
echo ============================================================
echo   ANTI-RANSOMWARE - FINAL BUILD (ROBUST)
echo ============================================================
echo.

:: --- Step 1: Admin Check ---
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges.
    goto :fail
)

:: --- Step 2: Find vswhere.exe ---
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [ERROR] vswhere.exe not found. Visual Studio Installer is missing.
    goto :fail
)

:: --- Step 3: Find Visual Studio C++ Tools ---
echo [INFO] Searching for Visual Studio C++ tools...
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VS_INSTALL_PATH=%%i"
)

if not defined VS_INSTALL_PATH (
    echo [ERROR] No Visual Studio installation with C++ tools was found.
    echo Please run the 'Visual Studio Installer' and add the 'Desktop development with C++' workload.
    goto :fail
)
echo [INFO] Found Visual Studio at: %VS_INSTALL_PATH%

:: --- Step 4: Setup Build Environment ---
set "VCVARS_BAT=%VS_INSTALL_PATH%\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VCVARS_BAT%" (
    echo [WARNING] vcvarsall.bat not found at expected location.
    echo [INFO] Trying alternative path...
    set "VCVARS_BAT=%VS_INSTALL_PATH%\Common7\Tools\VsDevCmd.bat"
)
if not exist "%VCVARS_BAT%" (
    echo [ERROR] Cannot find build environment script.
    echo Please verify Visual Studio C++ tools are installed.
    goto :fail
)
echo [INFO] Initializing build environment from: %VCVARS_BAT%
call "%VCVARS_BAT%" -arch=x64 -host_arch=x64

:: --- Step 5: Verify Environment and Paths ---
set "BUILD_DIR=%~dp0build_production"
set "WDK_PATH=C:\Program Files (x86)\Windows Kits\10"

where cl.exe >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] cl.exe (C++ Compiler) is not in the path. The C++ workload is likely missing.
    goto :fail
)
if not exist "%WDK_PATH%" (
    echo [ERROR] Windows Driver Kit (WDK) not found at "%WDK_PATH%".
    goto :fail
)
echo [INFO] Build environment successfully configured.

:: --- Step 6: Build the Driver ---
echo [INFO] Creating build directory...
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [INFO] Compiling driver source...
cl.exe /c /nologo /W4 /O2 /D "_AMD64_" /D "NDEBUG" /kernel /I "%WDK_PATH%\Include\10.0.22621.0\km" /I "%WDK_PATH%\Include\10.0.22621.0\shared" "%~dp0real_kernel_driver.c" /Fo"%BUILD_DIR%\real_kernel_driver.obj"
if %errorLevel% neq 0 (
    echo [ERROR] Compilation failed.
    goto :fail
)

echo [INFO] Linking driver...
link.exe /nologo /DRIVER /SUBSYSTEM:NATIVE /MACHINE:X64 /ENTRY:DriverEntry /OUT:"%BUILD_DIR%\AntiRansomwareKernel.sys" /LIBPATH:"%WDK_PATH%\Lib\10.0.22621.0\km\x64" ntoskrnl.lib hal.lib fltmgr.lib wdmsec.lib "%BUILD_DIR%\real_kernel_driver.obj"
if %errorLevel% neq 0 (
    echo [ERROR] Linking failed.
    goto :fail
)

:: --- Success ---
echo.
echo ============================================================
echo   BUILD COMPLETED SUCCESSFULLY!
echo ============================================================
echo.
echo Driver created at: %BUILD_DIR%\AntiRansomwareKernel.sys
echo.
goto :end

:fail
echo.
echo ============================================================
echo   BUILD FAILED
echo ============================================================
echo.

:end
pause