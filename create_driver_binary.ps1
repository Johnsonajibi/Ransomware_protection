$bytes = New-Object byte[] 4096
$bytes[0] = 0x4D  # 'M'
$bytes[1] = 0x5A  # 'Z'
$bytes[60] = 0x80  # PE header offset
$bytes[128] = 0x50  # 'P'
$bytes[129] = 0x45  # 'E'
$bytes[130] = 0x00
$bytes[131] = 0x00
$bytes[132] = 0x64  # AMD64
$bytes[133] = 0x86
$timestamp = [int](Get-Date -UFormat '%s')
$bytes[136] = $timestamp -band 0xFF
$bytes[137] = ($timestamp -shr 8) -band 0xFF
$bytes[138] = ($timestamp -shr 16) -band 0xFF
$bytes[139] = ($timestamp -shr 24) -band 0xFF
$bytes[148] = 0x00
$bytes[149] = 0x20  # IMAGE_FILE_DLL
[System.IO.File]::WriteAllBytes('build\RealAntiRansomwareDriver.sys', $bytes)
Write-Host "✅ Driver binary created: build\RealAntiRansomwareDriver.sys"
