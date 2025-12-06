$files = @(
    "Rules\S1\1.5\1.5.1\audit.sh",
    "Rules\S1\1.5\1.5.1\remediation.sh"
)

foreach ($file in $files) {
    $fullPath = Join-Path $PSScriptRoot $file
    if (Test-Path $fullPath) {
        $content = [System.IO.File]::ReadAllText($fullPath)
        $content = $content -replace [char]0xFEFF, ''
        $content = $content -replace "`r`n", "`n"
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $content, $utf8NoBom)
        Write-Host "Converted: $file"
    } else {
        Write-Host "File not found: $file"
    }
}
Write-Host "Done!"
