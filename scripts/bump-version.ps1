# one step per release: write the new version everywhere it is shown, then rebuild SSH LAN.exe so the exe
# on disk always carries the same number as the code. Usage: scripts\bump-version.ps1 0.6.3
param([Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$old = (Get-Content -LiteralPath (Join-Path $root 'VERSION') -TotalCount 1).Trim()
if ($old -eq $Version) { throw "already $Version" }

function Set-Text([string]$Rel, [string]$Pattern, [string]$Replace) {
    $path = Join-Path $root $Rel
    $raw = [IO.File]::ReadAllBytes($path)
    $bom = $raw.Length -ge 3 -and $raw[0] -eq 0xEF -and $raw[1] -eq 0xBB -and $raw[2] -eq 0xBF
    $text = [Text.Encoding]::UTF8.GetString($raw, $(if ($bom) { 3 } else { 0 }), $raw.Length - $(if ($bom) { 3 } else { 0 }))
    $new = [regex]::Replace($text, $Pattern, $Replace)
    if ($new -eq $text) { throw "version not found in $Rel" }
    [IO.File]::WriteAllText($path, $new, (New-Object Text.UTF8Encoding $bom))
}

Set-Text 'VERSION' ([regex]::Escape($old)) $Version
Set-Text 'scripts\app.manifest' ('version="' + [regex]::Escape($old) + '\.0"') ('version="' + $Version + '.0"')
Set-Text 'README.md' ('Current version: \*\*' + [regex]::Escape($old) + '\*\*') ('Current version: **' + $Version + '**')
Set-Text 'docs\SSH-LAN-TH.md' ('ตอนนี้ \*\*' + [regex]::Escape($old) + '\*\*') ('ตอนนี้ **' + $Version + '**')
& (Join-Path $PSScriptRoot 'build-launcher.ps1')
$exe = Get-Item -LiteralPath (Join-Path $root 'SSH LAN.exe')
if ($exe.VersionInfo.FileVersion -ne "$Version.0") { throw "SSH LAN.exe is $($exe.VersionInfo.FileVersion), expected $Version.0" }
Write-Host " [✓] $old -> $Version · SSH LAN.exe $($exe.VersionInfo.FileVersion) $($exe.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))"
