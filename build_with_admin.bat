@echo off
REM Launcher script that ensures administrator privileges
echo 🚀 Kernel Driver Build Launcher
echo ==============================

REM Check if already running as administrator
NET SESSION >nul 2>&1
if %errorLevel% equ 0 (
    echo ✅ Already running as Administrator
    call build_kernel.bat
    exit /b %errorLevel%
)

echo ⚠️  Administrator privileges required for kernel driver compilation
echo Requesting elevation...

REM Request administrator elevation
powershell -Command "Start-Process -FilePath '%~dp0build_kernel.bat' -Verb RunAs -Wait"

if %errorLevel% equ 0 (
    echo ✅ Build completed with elevation
) else (
    echo ❌ Build failed or was cancelled
    pause
)

exit /b %errorLevel%
