# Download Python Dependencies for Offline Installer
# This script downloads all required Python packages as wheel files

param(
    [string]$VendorDir = "vendor"
)

Write-Host "======================================"
Write-Host "Dependency Downloader for Offline Installer"
Write-Host "======================================`n"

# Create vendor directory
if (Test-Path $VendorDir) {
    Write-Host "[INFO] Cleaning existing vendor directory..."
    Remove-Item -Path $VendorDir -Recurse -Force
}

New-Item -ItemType Directory -Path $VendorDir -Force | Out-Null
Write-Host "[OK] Created vendor directory: $VendorDir`n"

# Check if requirements.txt exists
if (-not (Test-Path "requirements.txt")) {
    Write-Host "[ERROR] requirements.txt not found!"
    exit 1
}

Write-Host "[1/2] Downloading dependencies..."
Write-Host "This will download all packages from requirements.txt as wheel files.`n"

# Download all dependencies including their dependencies
python -m pip download -r requirements.txt -d $VendorDir --prefer-binary

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[ERROR] Failed to download dependencies!"
    exit 1
}

# Get file count and total size
$files = Get-ChildItem -Path $VendorDir -File
$totalSize = ($files | Measure-Object -Property Length -Sum).Sum
$totalSizeMB = [math]::Round($totalSize / 1MB, 2)

Write-Host "`n[2/2] Download complete!"
Write-Host "Files downloaded: $($files.Count)"
Write-Host "Total size: $totalSizeMB MB"
Write-Host "Location: $(Resolve-Path $VendorDir)`n"

Write-Host "[OK] Dependencies ready for offline installer"
Write-Host "`nYou can now build the offline installer with:"
Write-Host "  .\build_installer.ps1 -Type offline`n"
