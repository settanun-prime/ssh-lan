. "$PSScriptRoot\assert.ps1"

# Windows PowerShell 5.1 reads a .ps1/.xaml without BOM as ANSI and breaks on Thai text (plain ASCII is safe either way)
Get-ChildItem (Join-Path $TestRoot 'scripts'), $PSScriptRoot -Recurse -Include *.ps1, *.xaml | ForEach-Object {
    $b = [IO.File]::ReadAllBytes($_.FullName)
    $bom = $b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF
    Assert-True ($bom -or -not ($b | Where-Object { $_ -gt 0x7F } | Select-Object -First 1)) "non-ASCII without BOM: $($_.Name)"
}
# a CRLF shell script fails on Linux
Get-ChildItem (Join-Path $TestRoot 'scripts') -Recurse -Include *.sh, *.sh.template | ForEach-Object {
    Assert-True (-not ([IO.File]::ReadAllText($_.FullName) -match "`r")) "CR in $($_.Name)"
}
