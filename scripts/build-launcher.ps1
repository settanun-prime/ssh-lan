$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$root = Split-Path -Parent $PSScriptRoot
$png = Join-Path $root 'assets\ssh-lan-logo.png'
if (-not (Test-Path -LiteralPath $png)) { throw "Missing logo: $png" }
$source = [Drawing.Image]::FromFile($png)
$images = @()
try {
    foreach ($size in @(16, 24, 32, 48, 64, 128, 256)) {
        $bitmap = New-Object Drawing.Bitmap($source, $size, $size)
        $stream = New-Object IO.MemoryStream
        try {
            $bitmap.Save($stream, [Drawing.Imaging.ImageFormat]::Png)
            $images += , [pscustomobject]@{ Size = $size; Bytes = $stream.ToArray() }
        } finally {
            $bitmap.Dispose()
            $stream.Dispose()
        }
    }
} finally { $source.Dispose() }

$iconPath = Join-Path $root 'assets\ssh-lan.ico'
$stream = [IO.File]::Create($iconPath)
$writer = New-Object IO.BinaryWriter($stream)
try {
    $writer.Write([uint16]0)
    $writer.Write([uint16]1)
    $writer.Write([uint16]$images.Count)
    $offset = 6 + 16 * $images.Count
    foreach ($item in $images) {
        $dimension = if ($item.Size -eq 256) { 0 } else { $item.Size }
        $writer.Write([byte]$dimension)
        $writer.Write([byte]$dimension)
        $writer.Write([uint16]0)
        $writer.Write([uint16]1)
        $writer.Write([uint16]32)
        $writer.Write([uint32]$item.Bytes.Length)
        $writer.Write([uint32]$offset)
        $offset += $item.Bytes.Length
    }
    foreach ($item in $images) { $writer.Write([byte[]]$item.Bytes) }
} finally {
    $writer.Dispose()
    $stream.Dispose()
}

$compiler = Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'
$manifestPath = Join-Path $PSScriptRoot 'app.manifest'
$outExe = Join-Path $root 'SSH LAN.exe'

# the version lives in one place: VERSION
$version = (Get-Content -LiteralPath (Join-Path $root 'VERSION') -TotalCount 1).Trim()
$versionCs = Join-Path ([IO.Path]::GetTempPath()) 'ssh-lan-version.cs'
Set-Content -LiteralPath $versionCs -Encoding ASCII -Value @(
    "[assembly: System.Reflection.AssemblyVersion(`"$version.0`")]",
    "[assembly: System.Reflection.AssemblyFileVersion(`"$version.0`")]",
    "[assembly: System.Reflection.AssemblyInformationalVersion(`"$version`")]"
)
& $compiler /nologo /target:winexe /platform:anycpu /optimize+ /reference:System.Windows.Forms.dll `
    ("/win32icon:$iconPath") ("/win32manifest:$manifestPath") ("/out:$outExe") (Join-Path $PSScriptRoot 'launcher.cs') $versionCs
if ($LASTEXITCODE -ne 0) { throw 'SSH LAN launcher compilation failed.' }
Remove-Item -LiteralPath $versionCs -Force
Write-Host "Built: $outExe (v$version)" -ForegroundColor Green
