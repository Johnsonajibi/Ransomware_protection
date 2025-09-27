@echo off
REM Quick folder access script for USB token holders
REM This script requires your USB tokens to be present in drive E:

echo 🔐 USB Token Folder Access Utility
echo ==================================

REM Check for USB tokens
if not exist "E:\protection_token_*.key" (
    echo ❌ No USB tokens found on drive E:
    echo    Please ensure your USB drive is connected
    pause
    exit /b 1
)

echo ✅ USB tokens detected on drive E:
dir "E:\protection_token_*.key" /B

echo.
echo 🔍 Showing all folders (including protected):
attrib "c:\Users\ajibi\Music\Anti-Ransomeware\*" /D

echo.
echo 🔓 Making TestFolder visible (requires USB token):
attrib -H -S "c:\Users\ajibi\Music\Anti-Ransomeware\TestFolder"

echo.
echo 📂 Attempting to show TestFolder contents:
dir "c:\Users\ajibi\Music\Anti-Ransomeware\TestFolder"

echo.
echo ⚠️  Note: Folder will remain protected. Only visibility is restored.
echo    Use the GUI or true_prevention.py for full unlock operations.

pause
