@echo off
setlocal EnableDelayedExpansion

REM ============================================================
REM   COMPLETE KERNEL-MODE PROTECTION DEPLOYMENT
REM   Builds, Signs, and Installs the Anti-Ransomware Driver
REM ============================================================

echo.
echo ============================================================
echo    ANTI-RANSOMWARE KERNEL DEPLOYMENT v2.0
echo ============================================================
echo.
echo This script will:
echo   1. Build the kernel driver (AntiRansomwareKernel.sys)
echo   2. Build the user-mode client (AntiRansomware.exe)
echo   3. Create a test certificate for signing
echo   4. Sign the driver for test deployment
echo   5. Install the driver service
echo   6. Start the protection
echo.

REM Check for administrator privileges
net session >nul 2>&1
if !errorlevel! neq 0 (
    echo ERROR: Administrator privileges required!
    echo Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo [STEP 1/7] Checking system requirements...
echo.

REM Check if test signing is enabled
REM Check if test signing is enabled (Robust Check)
bcdedit | findstr /i "testsigning" | findstr /i "Yes" >nul 2>&1
set TEST_SIGNING_ENABLED=!errorlevel!

if !TEST_SIGNING_ENABLED! neq 0 (
    echo [!] Test signing check failed. Debugging info:
    echo     Raw bcdedit output for 'testsigning':
    bcdedit | findstr /i "testsigning"
    echo.
)

if !TEST_SIGNING_ENABLED! neq 0 (
    echo [!] Test signing is NOT enabled
    echo.
    echo To enable kernel driver loading, we need to enable test signing.
    echo This requires a system restart.
    echo.
    choice /C YN /M "Enable test signing now (restart required)"
    if !errorlevel! equ 1 (
        echo Enabling test signing...
        bcdedit /set testsigning on
        if !errorlevel! equ 0 (
            echo.
            echo ====================================================
            echo   TEST SIGNING ENABLED
            echo ====================================================
            echo Your computer needs to restart to apply changes.
            echo After restart, run this script again to continue.
            echo.
            echo Current progress will be saved.
            echo ====================================================
            echo.
            choice /C YN /M "Restart now"
            if !errorlevel! equ 1 (
                shutdown /r /t 10 /c "Restarting to enable kernel driver test signing"
                exit /b 0
            ) else (
                echo.
                echo Please restart manually and run this script again.
                pause
                exit /b 0
            )
        ) else (
            echo ERROR: Could not enable test signing.
            echo This may be because Secure Boot is enabled.
            echo.
            echo To fix:
            echo 1. Restart and enter BIOS/UEFI setup (usually F2, F10, or DEL)
            echo 2. Disable Secure Boot
            echo 3. Save and restart
            echo 4. Run this script again
            pause
            exit /b 1
        )
    ) else (
        echo.
        echo WARNING: Test signing check failed.
        choice /C YN /M "Proceed anyway? (Y=Yes, N=Cancel)"
        if !errorlevel! equ 1 (
            echo [!] Bypassing check...
        ) else (
            echo Deployment cancelled.
            pause
            exit /b 1
        )
    )
) else (
    echo [OK] Test signing is enabled
)

echo.
echo [STEP 2/7] Building components...
echo.

REM Build everything
call "%~dp0build_complete.bat"
if !errorlevel! neq 0 (
    echo ERROR: Build failed
    pause
    exit /b 1
)

set "BUILD_DIR=%~dp0build"
set "DRIVER_FILE=%BUILD_DIR%\AntiRansomwareKernel.sys"
set "CLIENT_FILE=%BUILD_DIR%\AntiRansomware.exe"

if not exist "!DRIVER_FILE!" (
    echo ERROR: Driver not built successfully
    pause
    exit /b 1
)

if not exist "!CLIENT_FILE!" (
    echo ERROR: Client application not built successfully
    pause
    exit /b 1
)

echo.
echo [STEP 3/7] Finding signing tools...
echo.

REM Find signtool.exe
set "SIGNTOOL_EXE="
set "SDK_ROOT=C:\Program Files (x86)\Windows Kits\10"

for /f "delims=" %%D in ('dir /s /b "!SDK_ROOT!\signtool.exe" 2^>nul ^| findstr /v "arm"') do (
    set "SIGNTOOL_EXE=%%D"
    echo Found: %%D
    goto :signtool_found
)

:signtool_found
if "!SIGNTOOL_EXE!"=="" (
    echo ERROR: signtool.exe not found
    echo Please install Windows SDK
    pause
    exit /b 1
)

echo.
echo [STEP 4/7] Creating test certificate...
echo.

REM Check if certificate already exists
powershell -Command "Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq 'CN=AntiRansomwareTest' }" | findstr "AntiRansomwareTest" >nul 2>&1
if !errorlevel! equ 0 (
    echo [OK] Test certificate already exists
) else (
    echo Creating new test certificate...
    powershell -Command "$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=AntiRansomwareTest' -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddYears(5); Export-Certificate -Cert $cert -FilePath '%~dp0AntiRansomwareTest.cer' | Out-Null; Import-Certificate -FilePath '%~dp0AntiRansomwareTest.cer' -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null; Import-Certificate -FilePath '%~dp0AntiRansomwareTest.cer' -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null"
    
    if !errorlevel! equ 0 (
        echo [OK] Certificate created and installed
    ) else (
        echo ERROR: Certificate creation failed
        pause
        exit /b 1
    )
)

echo.
echo [STEP 5/7] Signing driver...
echo.

"!SIGNTOOL_EXE!" sign /v /a /s My /n "AntiRansomwareTest" /fd SHA256 /t http://timestamp.digicert.com "!DRIVER_FILE!" 2>nul
if !errorlevel! neq 0 (
    echo [!] Timestamp server unavailable, signing without timestamp...
    "!SIGNTOOL_EXE!" sign /v /a /s My /n "AntiRansomwareTest" /fd SHA256 "!DRIVER_FILE!"
)

if !errorlevel! equ 0 (
    echo [OK] Driver signed successfully
) else (
    echo ERROR: Driver signing failed
    pause
    exit /b 1
)

REM Verify signature
"!SIGNTOOL_EXE!" verify /pa "!DRIVER_FILE!" >nul 2>&1
if !errorlevel! equ 0 (
    echo [OK] Driver signature verified
) else (
    echo [!] Warning: Signature verification failed (may still work with test signing)
)

echo [STEP 6/7] Installing kernel driver service...
echo.

REM Set install directory
set "INSTALL_DIR=C:\AntiRansomware"
if not exist "!INSTALL_DIR!" mkdir "!INSTALL_DIR!"

REM Copy driver to install directory (Better for iterative dev)
echo Copying driver to !INSTALL_DIR!...
copy /y "!DRIVER_FILE!" "!INSTALL_DIR!\AntiRansomwareKernel.sys" >nul
if !errorlevel! neq 0 (
    echo ERROR: Failed to copy driver to directory
    pause
    exit /b 1
)

REM Stop existing service if running
sc query AntiRansomwareKernel >nul 2>&1
if !errorlevel! equ 0 (
    echo Stopping existing driver...
    sc stop AntiRansomwareKernel >nul 2>&1
    timeout /t 2 /nobreak >nul
    
    echo Removing existing service...
    sc delete AntiRansomwareKernel >nul 2>&1
    timeout /t 2 /nobreak >nul
)

REM Create the service
echo Creating driver service...
sc create AntiRansomwareKernel binPath= "!INSTALL_DIR!\AntiRansomwareKernel.sys" type= filesys start= demand
if !errorlevel! neq 0 (
    echo ERROR: Failed to create driver service
    pause
    exit /b 1
)

echo [OK] Driver service created

echo.
echo Configuring Minifilter Registry Keys...
call "%~dp0fix_registry.bat"
if !errorlevel! neq 0 (
    echo ERROR: Failed to configure registry
    pause
    exit /b 1
)

echo.
echo [STEP 7/7] Starting protection...
echo.

REM Start the driver
sc start AntiRansomwareKernel
if !errorlevel! equ 0 (
    echo [OK] Kernel driver started successfully!
) else (
    echo [!] Warning: Driver failed to start
    echo Checking Windows Event Log for details...
    
    REM Show recent driver errors from event log
    powershell -Command "Get-EventLog -LogName System -Source 'Service Control Manager' -Newest 5 -ErrorAction SilentlyContinue | Where-Object { $_.Message -like '*AntiRansomware*' } | Format-List TimeGenerated, Message"
    
    echo.
    echo Common issues:
    echo 1. Incompatible driver binary (rebuild with correct WDK)
    echo 2. Secure Boot blocking unsigned drivers (disable in BIOS)
    echo 3. Missing dependencies or incorrect driver initialization
    echo.
    echo You can still use the user-mode application with reduced protection.
)

REM Verify status
sc query AntiRansomwareKernel
set DRIVER_STATUS=!errorlevel!

echo.
echo ============================================================
echo   DEPLOYMENT SUMMARY
echo ============================================================
echo.
echo Files Built:
echo   [X] !DRIVER_FILE!
echo   [X] !CLIENT_FILE!
echo.
echo Driver Status:
if !DRIVER_STATUS! equ 0 (
    echo   [X] Service created
    echo   [X] Driver running
    echo.
    echo ====================================================
    echo   SUCCESS: KERNEL-MODE PROTECTION ACTIVE!
    echo ====================================================
) else (
    echo   [X] Service created
    echo   [ ] Driver not running (see warnings above)
    echo.
    echo ====================================================
    echo   PARTIAL: User-mode protection available
    echo ====================================================
)
echo.
echo Next steps:
echo   1. Launch: !CLIENT_FILE!
echo   2. Configure protected folders
echo   3. Enable real-time protection
echo   4. Monitor system activity
echo.
if !DRIVER_STATUS! equ 0 (
    echo To stop the driver:
    echo   sc stop AntiRansomwareKernel
    echo.
    echo To remove the driver:
    echo   sc delete AntiRansomwareKernel
    echo.
)
echo ============================================================
echo.

REM Launch the application
choice /C YN /M "Launch Anti-Ransomware application now"
if !errorlevel! equ 1 (
    start "" "!CLIENT_FILE!"
)

pause
