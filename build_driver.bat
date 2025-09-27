@echo off
REM Anti-Ransomware Kernel Driver Build Script
REM Requires Windows Driver Kit (WDK) and Visual Studio Build Tools

echo ==============================================
echo ANTI-RANSOMWARE KERNEL DRIVER BUILD
echo ==============================================

REM Check for WDK installation
if not exist "C:\Program Files (x86)\Windows Kits\10\bin" (
    echo ERROR: Windows Driver Kit (WDK) not found!
    echo Please install WDK from: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    pause
    exit /b 1
)

REM Set WDK environment
call "C:\Program Files (x86)\Windows Kits\10\bin\SetupVSEnv.cmd"

REM Create build directory
if not exist "build" mkdir build
cd build

echo Building Anti-Ransomware Kernel Driver...

REM Build the driver using MSBuild
msbuild ..\AntiRansomwareDriver.vcxproj /p:Configuration=Release /p:Platform=x64

if %ERRORLEVEL% neq 0 (
    echo BUILD FAILED!
    pause
    exit /b 1
)

echo ==============================================
echo BUILD SUCCESSFUL!
echo Driver file: build\x64\Release\AntiRansomwareDriver.sys
echo ==============================================

echo NEXT STEPS:
echo 1. Sign the driver with a valid certificate
echo 2. Install using the service installer
echo 3. Enable test signing for development: bcdedit /set testsigning on

pause
