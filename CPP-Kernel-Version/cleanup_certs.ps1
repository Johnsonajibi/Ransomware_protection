$subject = "CN=AntiRansomwareTest"
$locations = @(
    "Cert:\CurrentUser\My",
    "Cert:\LocalMachine\Root",
    "Cert:\LocalMachine\TrustedPublisher"
)

foreach ($loc in $locations) {
    if (Test-Path $loc) {
        Write-Host "Checking $loc..."
        $certs = Get-ChildItem -Path $loc | Where-Object { $_.Subject -eq $subject } | Sort-Object -Property NotAfter -Descending
        
        if ($certs.Count -gt 1) {
            $keep = $certs[0]
            $remove = $certs | Select-Object -Skip 1
            
            Write-Host "Keeping certificate ending in $($keep.Thumbprint) (Expires: $($keep.NotAfter))"
            
            foreach ($cert in $remove) {
                Write-Host "Removing certificate ending in $($cert.Thumbprint) (Expires: $($cert.NotAfter))"
                Remove-Item -Path "$loc\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue
            }
        } elseif ($certs.Count -eq 1) {
            Write-Host "Only one certificate found in $loc. No action needed."
        } else {
            Write-Host "No certificates found in $loc."
        }
    }
}
Write-Host "Certificate cleanup complete."
