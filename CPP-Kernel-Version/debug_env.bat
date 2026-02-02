@echo off
echo ====================================
echo   BUILD ENVIRONMENT DEBUG
echo ====================================
echo.
echo Current Directory: %CD%
echo.
echo Checking for cl.exe...
where cl.exe
if %errorlevel% neq 0 (
    echo [!] cl.exe NOT found in PATH
) else (
    echo [OK] cl.exe found
)
echo.
echo Checking for vcvarsall.bat...
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    echo [OK] Community vcvarsall.bat found
) else (
    echo [!] Community vcvarsall.bat NOT found
)
echo.
pause
