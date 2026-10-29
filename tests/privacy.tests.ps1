. "$PSScriptRoot\assert.ps1"
# the repository is public: no address, MAC, key or machine name from a real network may be committed.
# Two checks: patterns that are never placeholders, and the real values of the machine running the tests

$files = @(git -C $TestRoot ls-files | Where-Object { $_ -and $_ -notmatch '\.(png|ico|exe|zip)$' })
$text = @{}
foreach ($f in $files) { $p = Join-Path $TestRoot $f; if (Test-Path -LiteralPath $p) { $text[$f] = [IO.File]::ReadAllText($p) } }
Assert-True ($text.Count -gt 20) 'tracked files read'

function Find-InRepo([string]$Pattern, [scriptblock]$Allowed) {
    foreach ($f in $text.Keys) {
        foreach ($m in [regex]::Matches($text[$f], $Pattern)) { if (-not (& $Allowed $m.Value)) { "$f ($($m.Value.Length) chars)" } }
    }
}

# tailnet addresses: placeholders live in 100.64.0.x and fd7a:115c:a1e0::<short>
$bad = @(Find-InRepo '(?<![\d.])100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}(?!\d)' { param($v) $v -like '100.64.0.*' })
Assert-True (-not $bad) "real-looking tailnet IPv4 in: $($bad -join '; ')"
$bad = @(Find-InRepo '(?i)fd7a:115c:a1e0:[0-9a-f:]*[0-9a-f]' { param($v) $v -match '(?i)^fd7a:115c:a1e0::[0-9a-f]{1,3}$' })
Assert-True (-not $bad) "real-looking tailnet IPv6 in: $($bad -join '; ')"
# MACs: a burned-in (universally administered) address is real hardware; test MACs set the local bit (02-, 06-, 0A-, ...)
$bad = @(Find-InRepo '(?i)\b[0-9a-f]{2}([-:][0-9a-f]{2}){5}\b' {
    param($v)
    $first = [Convert]::ToInt32($v.Substring(0, 2), 16)
    ($first -band 2) -or $v -match '(?i)^(00[-:]){5}00$|^(ff[-:]){5}ff$|^01[-:]00[-:]5e'
})
Assert-True (-not $bad) "hardware MAC address in: $($bad -join '; ')"
$bad = @(Find-InRepo 'BEGIN (OPENSSH|RSA|EC|DSA) PRIVATE KEY' { $false })
Assert-True (-not $bad) "private key in: $($bad -join '; ')"

# this machine's real identifiers (skipped where a value does not exist, e.g. on a build server)
$real = New-Object System.Collections.Generic.List[string]
foreach ($ip in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress) { if ($ip -notmatch '^(127\.|169\.254\.)' -and $ip -ne '192.168.1.1') { $real.Add($ip) } }
foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue)) { if ($a.MacAddress) { $real.Add($a.MacAddress) } }
. (Join-Path $TestRoot 'scripts\ssh-lan-common.ps1')
$dev = Join-Path (Get-SshLanDataDirectory) 'devices.json'
if (Test-Path -LiteralPath $dev) {
    try { $raw = Get-Content -LiteralPath $dev -Raw -Encoding UTF8 | ConvertFrom-Json; foreach ($d in @($raw)) { if ($d.Mac) { $real.Add([string]$d.Mac) }; if ($d.Name -and "$($d.Name)".Length -ge 4) { $real.Add([string]$d.Name) } } } catch { }
}
$cfg = Join-Path $env:USERPROFILE '.ssh\config'
if (Test-Path -LiteralPath $cfg) {
    foreach ($m in Select-String -LiteralPath $cfg -Pattern '^\s*(Host|HostName)\s+(\S+)') { $v = $m.Matches[0].Groups[2].Value; if ($v -ne '*' -and $v.Length -ge 4) { $real.Add($v) } }
}
foreach ($f in Get-ChildItem "$env:USERPROFILE\.ssh\*.pub" -ErrorAction SilentlyContinue) { $k = ((Get-Content -LiteralPath $f.FullName -TotalCount 1) -split ' ')[1]; if ($k) { $real.Add($k.Substring(0, [Math]::Min(40, $k.Length))) } }
if ($env:USERNAME -and $env:USERNAME.Length -ge 4) { $real.Add($env:USERNAME) }
$email = git config user.email
if ($email) { $real.Add($email) }
$hits = foreach ($v in $real | Select-Object -Unique) {
    $rx = '(?<![\w.-])' + [regex]::Escape($v) + '(?![\w-]|\.\d)'
    foreach ($f in $text.Keys) { if ([regex]::IsMatch($text[$f], $rx, 'IgnoreCase')) { "$f (a value $($v.Length) chars long from this machine)" } }
}
Assert-True (-not @($hits)) "this machine's real data in: $(@($hits) -join '; ')"
