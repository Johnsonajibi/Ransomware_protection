@echo off
setlocal EnableDelayedExpansion

REM ============================================================
REM   KERNEL DRIVER MANAGEMENT UTILITY
REM   Manage the Anti-Ransomware kernel driver
REM ============================================================

echo.
echo ============================================================
echo    KERNEL DRIVER MANAGER
echo ============================================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if !errorlevel! neq 0 (
    echo ERROR: Administrator privileges required!
    pause
    exit /b 1
)

:menu
cls
echo.
echo ============================================================
echo    ANTI-RANSOMWARE KERNEL DRIVER MANAGEMENT
echo ============================================================
echo.

REM Check driver status
sc query AntiRansomwareKernel >nul 2>&1
set SERVICE_EXISTS=!errorlevel!

if !SERVICE_EXISTS! equ 0 (
    for /f "tokens=3" %%A in ('sc query AntiRansomwareKernel ^| findstr "STATE"') do set DRIVER_STATE=%%A
    
    echo Current Status:
    if "!DRIVER_STATE!"=="RUNNING" (
        echo   [ACTIVE] Kernel driver is running
    ) else if "!DRIVER_STATE!"=="STOPPED" (
        echo   [STOPPED] Kernel driver is installed but not running
    ) else (
        echo   [!DRIVER_STATE!] Driver in !DRIVER_STATE! state
    )
) else (
    echo Current Status:
    echo   [NOT INSTALLED] Kernel driver service not found
)

echo.
echo ============================================================
echo.
echo Available Operations:
echo.
echo   [1] Start Driver
echo   [2] Stop Driver
echo   [3] Restart Driver
echo   [4] View Driver Statistics
echo   [5] Check Driver Logs
echo   [6] Uninstall Driver
echo   [7] Reinstall Driver
echo   [8] Test Driver Communication
echo   [9] Enable Debug Mode
echo   [0] Exit
echo.
echo ============================================================
echo.

set /p choice="Select operation: "

if "!choice!"=="1" goto :start_driver
if "!choice!"=="2" goto :stop_driver
if "!choice!"=="3" goto :restart_driver
if "!choice!"=="4" goto :view_stats
if "!choice!"=="5" goto :check_logs
if "!choice!"=="6" goto :uninstall
if "!choice!"=="7" goto :reinstall
if "!choice!"=="8" goto :test_comm
if "!choice!"=="9" goto :debug_mode
if "!choice!"=="0" goto :exit

echo Invalid choice!
timeout /t 2 >nul
goto :menu

:start_driver
echo.
echo Starting kernel driver...
sc start AntiRansomwareKernel
if !errorlevel! equ 0 (
    echo [OK] Driver started successfully
    timeout /t 2 >nul
    
    REM Verify it's actually running
    sc query AntiRansomwareKernel | findstr "RUNNING" >nul 2>&1
    if !errorlevel! equ 0 (
        echo [OK] Driver confirmed running
    )
) else (
    echo [ERROR] Failed to start driver
    echo.
    echo Checking for errors...
    powershell -Command "Get-EventLog -LogName System -Newest 10 -ErrorAction SilentlyContinue | Where-Object { $_.Source -like '*AntiRansomware*' -or ($_.Source -eq 'Service Control Manager' -and $_.Message -like '*AntiRansomware*') } | Format-List TimeGenerated, EntryType, Message"
)
pause
goto :menu

:stop_driver
echo.
echo Stopping kernel driver...
sc stop AntiRansomwareKernel
if !errorlevel! equ 0 (
    echo [OK] Driver stopped successfully
    
    REM Wait for it to fully stop
    timeout /t 2 /nobreak >nul
    
    sc query AntiRansomwareKernel | findstr "STOPPED" >nul 2>&1
    if !errorlevel! equ 0 (
        echo [OK] Driver confirmed stopped
    )
) else (
    echo [ERROR] Failed to stop driver
)
pause
goto :menu

:restart_driver
echo.
echo Restarting kernel driver...
sc stop AntiRansomwareKernel >nul 2>&1
timeout /t 2 /nobreak >nul
sc start AntiRansomwareKernel
if !errorlevel! equ 0 (
    echo [OK] Driver restarted successfully
) else (
    echo [ERROR] Failed to restart driver
)
pause
goto :menu

:view_stats
echo.
echo ============================================================
echo   DRIVER STATISTICS
echo ============================================================
echo.

sc query AntiRansomwareKernel
echo.

REM Get driver file information
set "BUILD_DIR=%~dp0build"
if exist "!BUILD_DIR!\AntiRansomwareKernel.sys" (
    echo Driver File: !BUILD_DIR!\AntiRansomwareKernel.sys
    dir "!BUILD_DIR!\AntiRansomwareKernel.sys" | findstr "AntiRansomwareKernel.sys"
    echo.
    
    REM Check signature
    set "SIGNTOOL="
    for /f "delims=" %%D in ('dir /s /b "C:\Program Files (x86)\Windows Kits\10\signtool.exe" 2^>nul ^| findstr /v "arm"') do (
        set "SIGNTOOL=%%D"
        goto :signtool_found_stats
    )
    :signtool_found_stats
    if not "!SIGNTOOL!"=="" (
        echo Signature Status:
        "!SIGNTOOL!" verify /v "!BUILD_DIR!\AntiRansomwareKernel.sys" 2>&1 | findstr /C:"Successfully verified" /C:"SignTool Error"
    )
)

echo.
echo System Information:
bcdedit | findstr /C:"testsigning"
echo.

pause
goto :menu

:check_logs
echo.
echo ============================================================
echo   RECENT DRIVER EVENTS
echo ============================================================
echo.

echo Checking Windows Event Log for driver activity...
echo.

powershell -Command "Get-EventLog -LogName System -Newest 20 -ErrorAction SilentlyContinue | Where-Object { $_.Source -like '*AntiRansomware*' -or $_.Source -eq 'Microsoft-Windows-FilterManager' -or ($_.Source -eq 'Service Control Manager' -and $_.Message -like '*AntiRansomware*') } | Select-Object -First 10 | Format-Table TimeGenerated, EntryType, Source, Message -AutoSize -Wrap"

echo.
pause
goto :menu

:uninstall
echo.
echo WARNING: This will completely remove the kernel driver!
echo.
choice /C YN /M "Are you sure you want to uninstall"
if !errorlevel! neq 1 goto :menu

echo.
echo Stopping driver...
sc stop AntiRansomwareKernel >nul 2>&1
timeout /t 2 /nobreak >nul

echo Removing service...
sc delete AntiRansomwareKernel
if !errorlevel! equ 0 (
    echo [OK] Driver service removed successfully
) else (
    echo [ERROR] Failed to remove service
)

echo.
pause
goto :menu

:reinstall
echo.
echo Reinstalling kernel driver...
echo.

REM Stop and remove existing
sc stop AntiRansomwareKernel >nul 2>&1
timeout /t 1 /nobreak >nul
sc delete AntiRansomwareKernel >nul 2>&1
timeout /t 1 /nobreak >nul

REM Reinstall
set "BUILD_DIR=%~dp0build"
set "DRIVER_FILE=!BUILD_DIR!\AntiRansomwareKernel.sys"

if not exist "!DRIVER_FILE!" (
    echo ERROR: Driver file not found at !DRIVER_FILE!
    echo Please build the driver first using build_complete.bat
    pause
    goto :menu
)

echo Creating service...
sc create AntiRansomwareKernel binPath= "!DRIVER_FILE!" type= filesys start= demand
if !errorlevel! neq 0 (
    echo [ERROR] Failed to create service
    pause
    goto :menu
)

echo Starting driver...
sc start AntiRansomwareKernel
if !errorlevel! equ 0 (
    echo [OK] Driver reinstalled and started successfully
) else (
    echo [!] Driver service created but failed to start
    echo Check logs for details
)

pause
goto :menu

:test_comm
echo.
echo ============================================================
echo   TESTING DRIVER COMMUNICATION
echo ============================================================
echo.

REM Check if driver is running
sc query AntiRansomwareKernel | findstr "RUNNING" >nul 2>&1
if !errorlevel! neq 0 (
    echo ERROR: Driver is not running
    echo Please start the driver first
    pause
    goto :menu
)

echo Driver Status: RUNNING
echo.
echo Testing communication channel...
echo (This requires the AntiRansomware.exe client)
echo.

set "BUILD_DIR=%~dp0build"
if exist "!BUILD_DIR!\AntiRansomware.exe" (
    echo Launching client for communication test...
    start "" "!BUILD_DIR!\AntiRansomware.exe"
) else (
    echo Client application not found.
    echo Build the client using build_complete.bat
)

pause
goto :menu

:debug_mode
echo.
echo ============================================================
echo   DEBUG MODE CONFIGURATION
echo ============================================================
echo.

echo Current Settings:
bcdedit | findstr /C:"testsigning" /C:"debug"
echo.

echo Debug Options:
echo   [1] Enable kernel debugging
echo   [2] Disable kernel debugging
echo   [3] Enable Driver Verifier
echo   [4] Disable Driver Verifier
echo   [0] Back to main menu
echo.

set /p debug_choice="Select option: "

if "!debug_choice!"=="1" (
    echo Enabling kernel debug mode...
    bcdedit /debug on
    bcdedit /dbgsettings serial debugport:1 baudrate:115200
    echo [OK] Debug mode enabled (restart required)
) else if "!debug_choice!"=="2" (
    echo Disabling kernel debug mode...
    bcdedit /debug off
    echo [OK] Debug mode disabled (restart required)
) else if "!debug_choice!"=="3" (
    echo Enabling Driver Verifier for AntiRansomwareKernel.sys...
    verifier /standard /driver AntiRansomwareKernel.sys
    echo [OK] Driver Verifier enabled (restart required)
) else if "!debug_choice!"=="4" (
    echo Disabling Driver Verifier...
    verifier /reset
    echo [OK] Driver Verifier disabled (restart required)
)

pause
goto :menu

:exit
echo.
echo Exiting...
exit /b 0
