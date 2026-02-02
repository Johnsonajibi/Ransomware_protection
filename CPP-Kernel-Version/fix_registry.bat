@echo off
set "SERVICE_PATH=HKLM\System\CurrentControlSet\Services\AntiRansomwareKernel"

echo Creating Instances key...
reg add "%SERVICE_PATH%\Instances" /f
if %errorlevel% neq 0 exit /b 1

echo Setting DefaultInstance...
reg add "%SERVICE_PATH%\Instances" /v "DefaultInstance" /t REG_SZ /d "AntiRansomware Instance" /f
if %errorlevel% neq 0 exit /b 1

echo Creating Instance key...
reg add "%SERVICE_PATH%\Instances\AntiRansomware Instance" /f
if %errorlevel% neq 0 exit /b 1

echo Setting Altitude...
reg add "%SERVICE_PATH%\Instances\AntiRansomware Instance" /v "Altitude" /t REG_SZ /d "365000" /f
if %errorlevel% neq 0 exit /b 1

echo Setting Flags...
reg add "%SERVICE_PATH%\Instances\AntiRansomware Instance" /v "Flags" /t REG_DWORD /d 0 /f
if %errorlevel% neq 0 exit /b 1

echo Registry keys created successfully.
exit /b 0
