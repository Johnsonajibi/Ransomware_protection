@echo off
REM Quick Kernel Protection Status Check

echo.
echo ========================================
echo  KERNEL PROTECTION STATUS
echo ========================================
echo.

REM Check administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Not running as Administrator
    echo     Some checks may be incomplete
) else (
    echo [OK] Running as Administrator
)

echo.
echo Test Signing Status:
bcdedit | findstr /C:"testsigning" | findstr /C:"Yes" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Test signing: ENABLED
) else (
    echo [X] Test signing: DISABLED
    echo     Run: bcdedit /set testsigning on
)

echo.
echo Driver Service Status:
sc query AntiRansomwareKernel >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Service: INSTALLED
    sc query AntiRansomwareKernel | findstr "STATE"
    sc query AntiRansomwareKernel | findstr "RUNNING" >nul 2>&1
    if !errorlevel! equ 0 (
        echo [OK] Status: KERNEL PROTECTION ACTIVE
    ) else (
        echo [!] Status: Service installed but not running
        echo     Run: sc start AntiRansomwareKernel
    )
) else (
    echo [X] Service: NOT INSTALLED
    echo     Run: deploy_kernel_protection.bat
)

echo.
echo Build Files:
if exist "%~dp0build\AntiRansomwareKernel.sys" (
    echo [OK] Driver: %~dp0build\AntiRansomwareKernel.sys
) else (
    echo [X] Driver not built
)

if exist "%~dp0build\AntiRansomware.exe" (
    echo [OK] Client: %~dp0build\AntiRansomware.exe
) else (
    echo [X] Client not built
)

echo.
echo ========================================
echo.

pause
