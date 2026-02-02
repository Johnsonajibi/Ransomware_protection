@echo off
setlocal EnableDelayedExpansion

echo ========================================================
echo   KERNEL DRIVER SIGNING TOOL (TEST MODE)
echo ========================================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if !errorlevel! neq 0 (
    echo ERROR: This script requires administrator privileges.
    pause
    exit /b 1
)

set "BUILD_DIR=%~dp0build"
set "DRIVER_FILE=!BUILD_DIR!\AntiRansomwareKernel.sys"

if not exist "!DRIVER_FILE!" (
    echo ERROR: Driver file not found at !DRIVER_FILE!
    echo Please run build_complete.bat first.
    pause
    exit /b 1
)

echo [1/3] Enabling Test Signing mode...
bcdedit /set testsigning on
if !errorlevel! equ 0 (
    echo SUCCESS: Test signing enabled. (Note: A restart may be required).
) else (
    echo [!] WARNING: Could not enable Test Signing.
    echo This is likely because SECURE BOOT is enabled in your BIOS.
    echo.
    echo To fix this:
    echo 1. Restart your computer and enter BIOS/UEFI.
    echo 2. Find "Secure Boot" and set it to "Disabled".
    echo 3. Save and Exit, then run this script again.
)

echo.
echo [2/3] Searching for SignTool.exe...
set "SIGNTOOL_EXE="
set "SDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
for /f "delims=" %%D in ('dir /s /b "!SDK_ROOT!\signtool.exe" 2^>nul') do (
    set "SIGNTOOL_EXE=%%D"
)

if "!SIGNTOOL_EXE!"=="" (
    echo ERROR: signtool.exe not found in Windows SDK.
    pause
    exit /b 1
)
echo Found: !SIGNTOOL_EXE!

echo.
echo [3/3] Creating Test Certificate and Signing Driver...
REM Create a local test certificate and sign the driver
powershell -Command "$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=AntiRansomwareTest' -CertStoreLocation 'Cert:\CurrentUser\My'; Export-Certificate -Cert $cert -FilePath 'AntiRansomwareTest.cer'; Import-Certificate -FilePath 'AntiRansomwareTest.cer' -CertStoreLocation 'Cert:\LocalMachine\Root'"

if !errorlevel! equ 0 (
    "!SIGNTOOL_EXE!" sign /v /a /s My /n "AntiRansomwareTest" /t http://timestamp.digicert.com "!DRIVER_FILE!"
    if !errorlevel! equ 0 (
        echo.
        echo ========================================================
        echo   SUCCESS: Driver signed and ready to load!
        echo ========================================================
        echo.
        echo Next steps:
        echo 1. RESTART your computer (mandatory for testsigning).
        echo 2. Run: sc create AntiRansomwareKernel binPath= "%DRIVER_FILE%" type= kernel
        echo 3. Run: sc start AntiRansomwareKernel
    ) else (
        echo ERROR: Signing failed.
    )
) else (
    echo ERROR: Certificate creation failed.
)

pause
