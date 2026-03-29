# Build, sign, deploy and restart the kernel minifilter driver
# Run this script as Administrator.

$ErrorActionPreference = "Stop"

$msbuild  = "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
$proj     = "$PSScriptRoot\src\AntiRansomwareKernel.vcxproj"
$buildDir = "$PSScriptRoot\build"
$log      = "C:\Users\ajibi\AppData\Local\Temp\build_driver.txt"

# Both service registrations that may exist
$svcPrimary   = "AntiRansomwareKernel"            # service name used by new builds
$svcLegacy    = "AntiRansomwareFilter"             # service name installed from old .inf

# Deploy targets — cover both possible locations
$destPrimary  = "C:\AntiRansomware\AntiRansomwareKernel.sys"
$destLegacy   = "C:\Windows\System32\drivers\AntiRansomwareFilter.sys"

"=== Build started $(Get-Date) ===" | Tee-Object $log

# ── 1. Compile ────────────────────────────────────────────────────────────────
"--- MSBuild ---" | Tee-Object $log -Append
& $msbuild $proj /p:Configuration=Release /p:Platform=x64 `
           /p:OutDir="$buildDir\\" /v:minimal 2>&1 | Tee-Object $log -Append
if ($LASTEXITCODE -ne 0) {
    "BUILD FAILED (exit $LASTEXITCODE)" | Tee-Object $log -Append
    Write-Error "Build failed — check $log"
    exit 1
}
"Build succeeded." | Tee-Object $log -Append

$builtSys = "$buildDir\AntiRansomwareKernel.sys"
if (-not (Test-Path $builtSys)) {
    Write-Error "Built .sys not found at $builtSys"
    exit 1
}

# ── 2. Kill the GUI app so it releases the device handle ──────────────────────
"--- Kill app process ---" | Tee-Object $log -Append
Get-Process -Name "python*" -ErrorAction SilentlyContinue |
    Where-Object { $_.MainWindowTitle -like "*Anti-Ransomware*" -or
                   $_.CommandLine -like "*desktop_app*" } |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# ── 3. Stop both driver services (ignore errors if already stopped) ────────────
"--- Stop drivers ---" | Tee-Object $log -Append
sc.exe stop $svcPrimary 2>&1 | Tee-Object $log -Append
Start-Sleep -Seconds 1
sc.exe stop $svcLegacy  2>&1 | Tee-Object $log -Append
Start-Sleep -Seconds 2

# ── 4. Deploy to primary location ─────────────────────────────────────────────
"--- Deploy to $destPrimary ---" | Tee-Object $log -Append
if (-not (Test-Path (Split-Path $destPrimary))) {
    New-Item -ItemType Directory -Path (Split-Path $destPrimary) | Out-Null
}
Copy-Item -Force $builtSys $destPrimary
"Deployed OK -> $destPrimary" | Tee-Object $log -Append

# ── 5. Deploy to legacy location (overwrite the old AntiRansomwareFilter.sys) ─
"--- Deploy to $destLegacy ---" | Tee-Object $log -Append
try {
    Copy-Item -Force $builtSys $destLegacy
    "Deployed OK -> $destLegacy" | Tee-Object $log -Append
} catch {
    "Warning: could not deploy to $destLegacy : $_" | Tee-Object $log -Append
}

# ── 6. Sign with test certificate (if present) ────────────────────────────────
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
if (Test-Path $signtool) {
    "--- Signing ---" | Tee-Object $log -Append
    $cert = Get-ChildItem Cert:\CurrentUser\My |
            Where-Object { $_.Subject -like "*AntiRansomware*" } |
            Select-Object -First 1
    if ($cert) {
        & $signtool sign /v /fd sha256 /s My /n "AntiRansomwareTest" `
            /t http://timestamp.digicert.com $destPrimary 2>&1 | Tee-Object $log -Append
        try {
            & $signtool sign /v /fd sha256 /s My /n "AntiRansomwareTest" `
                /t http://timestamp.digicert.com $destLegacy 2>&1 | Tee-Object $log -Append
        } catch {}
    } else {
        "No AntiRansomwareTest cert — skipping sign" | Tee-Object $log -Append
    }
}

# ── 7. Start both services ────────────────────────────────────────────────────
"--- Start drivers ---" | Tee-Object $log -Append
sc.exe start $svcLegacy  2>&1 | Tee-Object $log -Append
Start-Sleep -Seconds 2
sc.exe query $svcLegacy  2>&1 | Tee-Object $log -Append

sc.exe start $svcPrimary 2>&1 | Tee-Object $log -Append
Start-Sleep -Seconds 2
sc.exe query $svcPrimary 2>&1 | Tee-Object $log -Append

"--- Active filters ---" | Tee-Object $log -Append
fltmc.exe 2>&1 | Tee-Object $log -Append

"=== Done $(Get-Date) ===" | Tee-Object $log -Append
Write-Host "Log: $log"
