@echo off
setlocal EnableDelayedExpansion

REM ============================================================
REM   AUTOMATED KERNEL DEPLOYMENT (NON-INTERACTIVE)
REM ============================================================

echo.
echo ============================================================
echo    ANTI-RANSOMWARE KERNEL DEPLOYMENT (AUTO)
echo ============================================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if !errorlevel! neq 0 (
    echo ERROR: Administrator privileges required!
    exit /b 1
)

echo [STEP 1/7] Checking system requirements...
echo.

REM Check/Enable Test Signing
bcdedit | findstr /i "testsigning" | findstr /i "Yes" >nul 2>&1
if !errorlevel! neq 0 (
    echo [!] Test signing not active. Attempting to enable...
    bcdedit /set testsigning on
    if !errorlevel! neq 0 (
        echo [!] Failed to enable test signing. Secure Boot might be on.
        echo [!] Proceeding with build, but driver loading requires manual fix.
    ) else (
        echo [!] Test signing enabled. RESTART REQUIRED after this script.
    )
) else (
    echo [OK] Test signing is enabled.
)

echo.
echo [STEP 2/7] Building components...
echo.

REM Build everything
call "%~dp0build_complete.bat"
if !errorlevel! neq 0 (
    echo ERROR: Build failed
    exit /b 1
)

set "BUILD_DIR=%~dp0build"
set "DRIVER_FILE=%BUILD_DIR%\AntiRansomwareKernel.sys"
set "CLIENT_FILE=%BUILD_DIR%\AntiRansomware.exe"

if not exist "!DRIVER_FILE!" (
    echo ERROR: Driver not built successfully
    exit /b 1
)

echo.
echo [STEP 3/7] Finding signing tools...
echo.

set "SIGNTOOL_EXE="
set "SDK_ROOT=C:\Program Files (x86)\Windows Kits\10"

for /f "delims=" %%D in ('dir /s /b "!SDK_ROOT!\signtool.exe" 2^>nul ^| findstr /v "arm"') do (
    set "SIGNTOOL_EXE=%%D"
    goto :signtool_found
)

:signtool_found
if "!SIGNTOOL_EXE!"=="" (
    echo ERROR: signtool.exe not found
    exit /b 1
)
echo Found: !SIGNTOOL_EXE!

echo.
echo [STEP 4/7] Creating test certificate...
echo.

powershell -Command "Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq 'CN=AntiRansomwareTest' }" | findstr "AntiRansomwareTest" >nul 2>&1
if !errorlevel! equ 0 (
    echo [OK] Test certificate already exists
) else (
    echo Creating new test certificate...
    powershell -Command "$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=AntiRansomwareTest' -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddYears(5); Export-Certificate -Cert $cert -FilePath '%~dp0AntiRansomwareTest.cer' | Out-Null; Import-Certificate -FilePath '%~dp0AntiRansomwareTest.cer' -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null; Import-Certificate -FilePath '%~dp0AntiRansomwareTest.cer' -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null"
)

echo.
echo [STEP 5/7] Signing driver...
echo.

"!SIGNTOOL_EXE!" sign /v /a /s My /n "AntiRansomwareTest" /fd SHA256 /t http://timestamp.digicert.com "!DRIVER_FILE!" 2>nul
if !errorlevel! neq 0 (
    echo [!] Timestamp failed, trying without...
    "!SIGNTOOL_EXE!" sign /v /a /s My /n "AntiRansomwareTest" /fd SHA256 "!DRIVER_FILE!"
)

if !errorlevel! neq 0 (
    echo ERROR: Driver signing failed
    exit /b 1
)

echo.
echo [STEP 6/7] Installing kernel driver service...
echo.

echo Copying driver to System32\drivers...
copy /y "!DRIVER_FILE!" "%SystemRoot%\System32\drivers\AntiRansomwareKernel.sys" >nul

sc query AntiRansomwareKernel >nul 2>&1
if !errorlevel! equ 0 (
    echo Stopping existing driver...
    sc stop AntiRansomwareKernel >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete AntiRansomwareKernel >nul 2>&1
)

echo Creating driver service...
sc create AntiRansomwareKernel binPath= "\SystemRoot\System32\drivers\AntiRansomwareKernel.sys" type= filesys start= demand
if !errorlevel! neq 0 (
    echo ERROR: Failed to create driver service
    exit /b 1
)

echo.
echo Configuring Minifilter Registry Keys...
call "%~dp0fix_registry.bat"
if !errorlevel! neq 0 (
    echo ERROR: Failed to configure registry
    exit /b 1
)

echo.
echo [STEP 7/7] Starting protection...
echo.

sc start AntiRansomwareKernel
if !errorlevel! equ 0 (
    echo [OK] Kernel driver started successfully!
) else (
    echo [!] Warning: Driver failed to start.
    echo     Possible reasons: Test Signing not standard, Secure Boot on, or Reboot pending.
)

echo.
echo DEPLOYMENT FINISHED.
exit /b 0
