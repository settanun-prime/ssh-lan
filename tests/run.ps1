# runs each tests\*.tests.ps1 in its own Windows PowerShell 5.1, the runtime the app ships on
param([string]$Filter = '*')
$failed = 0
foreach ($t in Get-ChildItem -LiteralPath $PSScriptRoot -Filter "$Filter.tests.ps1") {
    $out = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $t.FullName 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { "PASS $($t.Name)" } else { $failed++; "FAIL $($t.Name)"; $out.Trim() }
}
"$failed failed"
exit [int]($failed -gt 0)
