@echo off
setlocal EnableDelayedExpansion

REM ========================================================
REM   ADVANCED ANTI-RANSOMWARE BUILD SYSTEM (ROBUST)
REM ========================================================

echo.
echo ========================================================
echo   ADVANCED ANTI-RANSOMWARE BUILD SYSTEM
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
set "SRC_DIR=%~dp0src"
if not exist "!BUILD_DIR!" mkdir "!BUILD_DIR!"

echo [1/4] Detecting Visual Studio...
set "VS_ROOT="
set "VS_COMMUNITY=C:\Program Files\Microsoft Visual Studio\2022\Community"
set "VS_BUILDTOOLS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"

if exist "!VS_COMMUNITY!\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VS_ROOT=!VS_COMMUNITY!"
    echo Found: Visual Studio 2022 Community
) else if exist "!VS_BUILDTOOLS!\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VS_ROOT=!VS_BUILDTOOLS!"
    echo Found: Visual Studio 2022 Build Tools
) else (
    echo ERROR: Visual Studio 2022 not found.
    pause
    exit /b 1
)

echo [2/4] Detecting Windows SDK...
set "SDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "SDK_VERSION="

REM Find the latest SDK version by looking at Include folders
if exist "!SDK_ROOT!\Include" (
    for /f "delims=" %%D in ('dir /b /ad "!SDK_ROOT!\Include\10.*" 2^>nul') do (
        if exist "!SDK_ROOT!\Include\%%D\um\windows.h" (
            set "SDK_VERSION=%%D"
        )
    )
)

if not "!SDK_VERSION!"=="" (
    echo Found: Windows SDK !SDK_VERSION!
) else (
    echo ERROR: Windows SDK not found.
    pause
    exit /b 1
)

echo [3/4] Building user application...

REM Attempt standard environment setup first
where cl.exe >nul 2>&1
if !errorlevel! neq 0 (
    echo Setting up environment via vcvarsall.bat...
    call "!VS_ROOT!\VC\Auxiliary\Build\vcvarsall.bat" x64
)

REM Verify and manual fallback
where cl.exe >nul 2>&1
if !errorlevel! neq 0 (
    echo [!] Standard environment setup failed. Applying manual fallback...
    
    REM Find MSVC Tools Version
    set "MSVC_ROOT=!VS_ROOT!\VC\Tools\MSVC"
    for /f "delims=" %%D in ('dir /b /ad "!MSVC_ROOT!" 2^>nul') do (
        set "MSVC_VERSION=%%D"
    )
    
    set "CL_DIR=!MSVC_ROOT!\!MSVC_VERSION!\bin\Hostx64\x64"
    if exist "!CL_DIR!\cl.exe" (
        echo [OK] Using compiler at: !CL_DIR!
        set "PATH=!PATH!;!CL_DIR!"
        
        REM Manually set core environment variables
        set "INCLUDE=!MSVC_ROOT!\!MSVC_VERSION!\include;!SDK_ROOT!\Include\!SDK_VERSION!\ucrt;!SDK_ROOT!\Include\!SDK_VERSION!\um;!SDK_ROOT!\Include\!SDK_VERSION!\shared;!SDK_ROOT!\Include\!SDK_VERSION!\winrt"
        set "LIB=!MSVC_ROOT!\!MSVC_VERSION!\lib\x64;!SDK_ROOT!\Lib\!SDK_VERSION!\ucrt\x64;!SDK_ROOT!\Lib\!SDK_VERSION!\um\x64"
    ) else (
        echo ERROR: cl.exe could not be located.
        pause
        exit /b 1
    )
)

echo Compiling user application...

REM Kill existing instance if running to prevent LNK1104 error
taskkill /F /IM AntiRansomware.exe >nul 2>&1
timeout /t 1 /nobreak >nul

cl.exe /EHsc /std:c++17 /DUNICODE /D_UNICODE ^
    "!SRC_DIR!\antiransomware_client.cpp" ^
    /link user32.lib gdi32.lib shell32.lib kernel32.lib fltlib.lib advapi32.lib ^
    /out:"!BUILD_DIR!\AntiRansomware.exe"

if !errorlevel! neq 0 (
    echo.
    echo ERROR: Compilation failed.
    echo Please check if "Desktop development with C++" is installed in Visual Studio.
    pause
    exit /b 1
)

echo SUCCESS: AntiRansomware.exe created in !BUILD_DIR!

REM Brief kernel build check
if exist "!SDK_ROOT!\Include\!SDK_VERSION!\um\windows.h" (
    echo [4/4] Building kernel driver...
    
    REM Find MSBuild
    set "MSBUILD_EXE="
    set "MSBUILD_BASE=!VS_ROOT!\MSBuild\Current\Bin\amd64\MSBuild.exe"
    if exist "!MSBUILD_BASE!" (
        set "MSBUILD_EXE=!MSBUILD_BASE!"
    ) else (
        for /f "delims=" %%D in ('dir /s /b "!VS_ROOT!\MSBuild.exe" 2^>nul') do (
            set "MSBUILD_EXE=%%D"
        )
    )
    
    if not "!MSBUILD_EXE!"=="" (
        echo Using MSBuild at: !MSBUILD_EXE!
        pushd "!SRC_DIR!"
        "!MSBUILD_EXE!" AntiRansomwareKernel.vcxproj /p:Configuration=Release /p:Platform=x64
        popd
        
        if exist "!SRC_DIR!\x64\Release\AntiRansomwareKernel.sys" (
            copy "!SRC_DIR!\x64\Release\AntiRansomwareKernel.sys" "!BUILD_DIR!\"
            echo SUCCESS: AntiRansomwareKernel.sys created via MSBuild.
            goto :driver_built
        )
    )
    
    echo [!] MSBuild failed or not available. Attempting manual cl.exe build for driver...
    
    set "KM_INC=!SDK_ROOT!\Include\!SDK_VERSION!\km"
    set "SHARED_INC=!SDK_ROOT!\Include\!SDK_VERSION!\shared"
    set "KM_LIB=!SDK_ROOT!\Lib\!SDK_VERSION!\km\x64"
    
    if exist "!KM_INC!\ntddk.h" (
        echo [OK] Kernel mode headers found. Compiling manually...
        cl.exe /nologo /kernel /GS- /Z7 /Zp8 /W3 /std:c++17 /D_AMD64_ /D_WIN64 ^
            /I"!KM_INC!" /I"!SHARED_INC!" /I"!MSVC_ROOT!\!MSVC_VERSION!\include" ^
            "!SRC_DIR!\antiransomware_kernel.c" /c /Fo"!SRC_DIR!\antiransomware_kernel.obj"
        
        if !errorlevel! equ 0 (
            echo Linking kernel driver...
            link.exe /nologo /driver /entry:DriverEntry /subsystem:native /nodefaultlib ^
                /libpath:"!KM_LIB!" /libpath:"!MSVC_ROOT!\!MSVC_VERSION!\lib\x64" ^
                "!SRC_DIR!\antiransomware_kernel.obj" ntoskrnl.lib fltMgr.lib ^
                /out:"!BUILD_DIR!\AntiRansomwareKernel.sys"
            
            if !errorlevel! equ 0 (
                echo SUCCESS: AntiRansomwareKernel.sys created manually.
            ) else (
                echo ERROR: Kernel linking failed.
            )
        ) else (
            echo ERROR: Kernel compilation failed.
        )
    ) else (
        echo ERROR: Kernel mode headers not found in !KM_INC!. Skipping driver build.
    )
)
:driver_built

echo.
echo ========================================================
echo   BUILD COMPLETE
echo ========================================================
echo Created: !BUILD_DIR!\AntiRansomware.exe
if exist "!BUILD_DIR!\AntiRansomwareKernel.sys" echo Created: !BUILD_DIR!\AntiRansomwareKernel.sys
echo.
pause
