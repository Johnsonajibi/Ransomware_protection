# PowerShell script to remove all emojis from Python and PowerShell files

$files = @('desktop_app.py', 'brutal_truth.py', 'boot_persistence_protection.py', 'Build-Driver-Direct.ps1')

Write-Host "====== EMOJI REMOVAL UTILITY ======"
Write-Host "Cleaning emojis from source files..."
Write-Host ""

foreach ($file in $files) {
    if (Test-Path $file) {
        Write-Host "Processing: $file"
        
        # Read file as bytes
        $bytes = [System.IO.File]::ReadAllBytes($file)
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        
        # Remove all non-ASCII characters
        $cleaned = $text -replace '[^\x00-\x7F]', ''
        
        # Write back
        [System.IO.File]::WriteAllText($file, $cleaned, [System.Text.Encoding]::UTF8)
        
        Write-Host "   Cleaned successfully" -ForegroundColor Green
    } else {
        Write-Host "   File not found" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "====== CLEANUP COMPLETE ======"
Write-Host "All emojis have been removed from source files."
