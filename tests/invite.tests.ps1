. "$PSScriptRoot\assert.ps1"
. (Join-Path $TestRoot 'scripts\ssh-lan-common.ps1')
. (Join-Path $TestRoot 'scripts\ssh-lan\ssh-lan.ps1')

$t = New-SshLanInviteToken
Assert-True ($t -match '^[0-9a-f]{32}$') 'token format'
Assert-True ($t -ne (New-SshLanInviteToken)) 'token random'

$pub = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4bQZ8Yl0p8bS2s0l3l7tqJvR0b3hY0gL9vJ1h3v2kT test'
Assert-True ((Get-SshLanConfirmCode $pub) -match '^[0-9A-F]{6}$') 'confirm code format'
Assert-Equal (Get-SshLanConfirmCode $pub) (Get-SshLanConfirmCode ($pub -replace ' test$', ' other')) 'comment ignored'

$now = [datetime]'2026-10-28T10:00'
$exp = $now.AddMinutes(15)
Assert-Equal (Resolve-SshLanInviteRequest "/t/$t/join.cmd" $t $exp $now).Status 'ok' 'valid'
Assert-Equal (Resolve-SshLanInviteRequest "/t/$t/join.cmd" $t $exp $now).File 'join.cmd' 'file'
Assert-Equal (Resolve-SshLanInviteRequest "/t/bad/join.cmd" $t $exp $now).Status 'notfound' 'bad token'
Assert-Equal (Resolve-SshLanInviteRequest "/t/$t/../../etc" $t $exp $now).Status 'notfound' 'traversal'
Assert-Equal (Resolve-SshLanInviteRequest "/t/$t/other.exe" $t $exp $now).Status 'notfound' 'unlisted file'
Assert-Equal (Resolve-SshLanInviteRequest "/t/$t/join.cmd" $t $exp $exp.AddSeconds(1)).Status 'expired' 'expired'

# --- hello -> pair + harden (fake profile so ~/.ssh is never the real one) ---
$realProfile = $env:USERPROFILE
$env:USERPROFILE = Join-Path $env:TEMP "sshlan-profile-$(Get-Random)"
New-Item -ItemType Directory -Force (Join-Path $env:USERPROFILE '.ssh') | Out-Null
try {
    $ok = @{ hostname = 'OFF-PC-07'; user = 'alice'; ips = @('192.168.1.57'); pubkey = $pub; os = 'Windows'; chassis = '3'; remote = '192.168.1.57' }
    $calls = [Collections.ArrayList]@()
    $yes = { param($t) [void]$calls.Add("test $t"); $true }
    $no = { param($t) [void]$calls.Add("test $t"); $false }
    $harden = { param($alias, $os, $user) [void]$calls.Add("harden $alias $os $user"); $true }
    $auth = { param($key) [void]$calls.Add("auth $key") }
    $approve = { param($h, $code) [void]$calls.Add("approve $code"); $true }
    foreach ($bad in @(@{ hostname = 'x;calc' }, @{ user = 'a b' }, @{ remote = '8.8.8.8' }, @{ pubkey = 'ssh-ed25519 AAAA; rm -rf /' }, @{ hostname = '' })) {
        $h = $ok.Clone()
        foreach ($k in $bad.Keys) { $h[$k] = $bad[$k] }
        $calls.Clear()
        Assert-Throws { Complete-SshLanJoin $h $yes $harden $auth $approve } "reject $($bad.Keys)"
        Assert-Equal $calls.Count 0 "nothing ran for bad $($bad.Keys)"
    }
    Assert-True (-not (Test-Path (Join-Path $env:USERPROFILE '.ssh\config'))) 'no config written for bad hellos'

    $calls.Clear()
    $r = Complete-SshLanJoin $ok $no $harden $auth $approve
    Assert-True (-not $r.Hardened) 'not hardened when the key does not open the door'
    Assert-True (-not ($calls -match '^harden')) 'harden never called without key proof'

    $calls.Clear()
    # default: paired with the key, password login stays as it was
    $r = Complete-SshLanJoin $ok $yes $harden $auth $approve
    Assert-True (-not $r.Hardened) 'passwords kept by default'
    Assert-True (-not ($calls -match '^harden')) 'no harden unless asked'
    Assert-True ($calls -contains "auth $pub") 'paired by default'
    $calls.Clear()
    $r = Complete-SshLanJoin $ok $yes $harden $auth $approve -KeyOnly
    Assert-True $r.Hardened 'key-only when asked, after key proof'
    Assert-Equal $r.Alias 'off-pc-07' 'alias from hostname'
    Assert-True ($calls -contains "auth $pub") 'child key allowed here'
    Assert-True ($calls -contains 'harden off-pc-07 Windows alice') 'harden through alias'
    $cfg = Get-Content (Join-Path $env:USERPROFILE '.ssh\config') -Raw
    Assert-True ($cfg -match '(?m)^Host off-pc-07\r?\n\s+HostName 192\.168\.1\.57\r?\n\s+User alice') "host entry: $cfg"
    $tsHello = $ok.Clone(); $tsHello.hostname = 'TS-PC'; $tsHello.remote = '100.64.0.102'
    Assert-True (Complete-SshLanJoin $tsHello $yes $harden $auth $approve -KeyOnly).Hardened 'tailscale address accepted'
    # nothing is trusted until a person approves this machine, shown with the code of ITS key
    $calls.Clear()
    $deny = { param($h, $code) [void]$calls.Add("approve $code"); $false }
    $r = Complete-SshLanJoin $ok $yes $harden $auth $deny
    Assert-True (-not $r.Hardened) 'denied = not hardened'
    Assert-True ($calls -contains "approve $(Get-SshLanConfirmCode $pub)") 'approval sees the joining key code'
    Assert-True (-not ($calls -match '^(auth|harden)')) 'denied = nothing trusted'
    # an alias that already points at another address is never re-pointed
    $cfgPath = Join-Path $env:USERPROFILE '.ssh\config'
    $cfgBefore = Get-Content $cfgPath -Raw
    $other = $ok.Clone(); $other.remote = '192.168.1.99'
    $calls.Clear()
    Assert-Throws { Complete-SshLanJoin $other $yes $harden $auth $approve } 'alias taken by another address'
    Assert-Equal (Get-Content $cfgPath -Raw) $cfgBefore 'config untouched'
    Assert-Equal $calls.Count 0 'nothing ran for a taken alias'
    # remote harden: Windows only touches the password settings (AllowUsers can lock out a domain user)
    $win = Get-SshLanHardenCommand 'Windows'
    $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(($win -split ' ')[-1]))
    Assert-True ($decoded -match "PasswordAuthentication='no'") 'windows harden turns passwords off'
    Assert-True ($decoded -notmatch 'AllowUsers|AuthenticationMethods') 'windows harden sets no AllowUsers'
    $lin = Get-SshLanHardenCommand 'Linux'
    Assert-True ($lin -match 'sshd -t') 'linux harden checks the config before reload'
    Assert-True ($lin -match 'rm -f /etc/ssh/sshd_config.d/10-ssh-lan.conf') 'linux harden removes a bad file'
    Assert-True ($lin -match 'sshd -T' -and $lin -match 'passwordauthentication no') 'linux harden proves passwords are off'
    # USB-joined machine: read its hello.json over SSH (fake runner); the address comes from us, not from the file
    $json = (@{ hostname = 'LINE-PC-1'; user = 'bob'; pubkey = $pub; os = 'Windows'; remote = '8.8.8.8' } | ConvertTo-Json)
    $seen = [Collections.ArrayList]@()
    $runner = { param($t, $cmd) [void]$seen.Add("$t|$cmd"); $json }
    $rh = Get-SshLanRemoteHello 'bob@192.168.20.41' '192.168.20.41' 'Windows' $runner
    Assert-Equal $rh.remote '192.168.20.41' 'remote is the scanned address'
    Assert-Equal $rh.hostname 'LINE-PC-1' 'hostname from file'
    Assert-True ($seen[0] -match 'hello\.json') 'reads hello.json'
    Assert-True ((Get-SshLanRemoteHello 'bob@192.168.20.41' '192.168.20.41' 'Linux / macOS' $runner) -ne $null) 'linux path'
    Assert-True ($seen[1] -match '\.config/ssh-lan/hello\.json') 'linux reads ~/.config/ssh-lan/hello.json'
    Assert-Equal (Get-SshLanRemoteHello 'bob@192.168.20.41' '192.168.20.41' 'Windows' { param($t, $c) $null }) $null 'no file = null'
} finally { $env:USERPROFILE = $realProfile }

# --- join package (link and USB) ---
$out = Join-Path $env:TEMP 'sshlan-pkg-test'
Remove-Item $out, "$out-usb" -Recurse -Force -ErrorAction SilentlyContinue
$p = New-SshLanJoinPackage $out 'http://192.168.1.10:8765/t/0123456789abcdef0123456789abcdef/'
foreach ($f in 'ssh-lan.zip', 'join.cmd', 'join.sh', 'inviter.pub', 'inviter.json') { Assert-True (Test-Path "$out\$f") "missing $f" }
Assert-Equal $p.ZipHash (Get-FileHash "$out\ssh-lan.zip" -Algorithm SHA256).Hash 'zip hash'
Assert-Equal $p.ConfirmCode (Get-SshLanConfirmCode (Get-Content "$out\inviter.pub" -TotalCount 1)) 'code matches inviter.pub'
$cmd = [IO.File]::ReadAllText("$out\join.cmd")
Assert-True ($cmd.Contains($p.ZipHash) -and $cmd.Contains($p.ConfirmCode)) 'cmd has hash + code'
Assert-True ($cmd -notmatch '[^\x00-\x7F]') 'cmd ascii only'
Assert-True ($cmd -match "`r`n" -and $cmd -notmatch "[^`r]`n") 'cmd crlf'
Assert-True ([IO.File]::ReadAllText("$out\join.sh") -notmatch "`r") 'sh lf'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zr = [IO.Compression.ZipFile]::OpenRead("$out\ssh-lan.zip")
try { $names = @($zr.Entries | ForEach-Object { $_.FullName }) } finally { $zr.Dispose() }
Assert-True ($names -contains 'scripts/ssh-lan/invite.ps1') 'zip has scripts'
Assert-True (-not ($names -match '^(\.git|\.superpowers|tests)/')) 'zip has no .git, .superpowers, tests'
$usb = New-SshLanJoinPackage "$out-usb" ''
Assert-True ([IO.File]::ReadAllText("$out-usb\join.cmd") -match '%~dp0') 'usb mode reads own folder'
# a changed package must not be installed: join.cmd checks the hash before extracting (join.ps1 lives inside the zip)
Add-Content "$out-usb\ssh-lan.zip" 'tampered'
$env:SSHLAN_DRYRUN = '1'
# started from PowerShell 7 (Windows Terminal), the 5.1 child inherits 7's module path and loses Get-FileHash
$modulePath = $env:PSModulePath
if (Get-Command pwsh -ErrorAction SilentlyContinue) {
    $env:PSModulePath = (Join-Path (& pwsh -NoProfile -Command '$PSHOME') 'Modules') + ";$env:PSModulePath"
}
# 5.1 turns a native command's stderr into terminating errors under Stop
$ErrorActionPreference = 'Continue'
$said = cmd /c "`"$out-usb\join.cmd`"" 2>&1 | Out-String
$code = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
Assert-True ($code -ne 0) 'tampered zip rejected'
Assert-True ($said -match 'hash mismatch') "rejected for the hash, not something else: $said"
Assert-True (-not (Test-Path "$env:TEMP\sshlan-join\scripts")) 'tampered zip not extracted'

# the genuine package runs all the way through join.ps1 (dry run touches nothing)
$env:SSH_LAN_DATA_DIR = Join-Path $env:TEMP "sshlan-pkg-data-$(Get-Random)"
$good = New-SshLanJoinPackage "$out-good" ''
$ErrorActionPreference = 'Continue'
$said = cmd /c "`"$out-good\join.cmd`"" 2>&1 | Out-String
$code = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
Assert-Equal $code 0 "genuine package dry run: $said"
Assert-True ((Get-Content (Join-Path $env:SSH_LAN_DATA_DIR 'join.log')) -match ' hello ok') 'join.ps1 ran to the end'
Remove-Item Env:SSHLAN_DRYRUN, Env:SSH_LAN_DATA_DIR
$env:PSModulePath = $modulePath

# --- CLI: USB package needs no admin ---
$cliDir = Join-Path $env:TEMP "sshlan-cli-usb-$(Get-Random)"
$ErrorActionPreference = 'Continue'
$env:SSH_LAN_UI = ''   # inherited by the child; set, it would skip the CLI entry
$said = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File (Join-Path $TestRoot 'scripts\ssh-lan\ssh-lan.ps1') -Action invite -Usb $cliDir 2>&1 | Out-String
$env:SSH_LAN_UI = '1'
$ErrorActionPreference = 'Stop'
Assert-True (Test-Path (Join-Path $cliDir 'join.cmd')) "cli usb package: $said"
Assert-True ($said -match '[0-9A-F]{6}') 'cli prints the confirm code'

# --- invite server (test port, no firewall: tests do not run elevated) ---
$s = Start-SshLanInviteServer -Port 18765 -Minutes 1 -NoFirewall
$base = "http://127.0.0.1:18765/t/$($s.Token)/"
try {
    Assert-True ($s.Url -match "^http://[0-9.]+:18765/t/$($s.Token)/$") "url $($s.Url)"
    Assert-Equal (Get-StatusCode "${base}inviter.pub") 200 'serves inviter.pub'
    Assert-Equal (Get-StatusCode "${base}join.cmd") 200 'serves join.cmd'
    Assert-Equal (Get-StatusCode "http://127.0.0.1:18765/t/$(New-SshLanInviteToken)/join.cmd") 404 'wrong token'
    $jobs = 1..2 | ForEach-Object {
        Start-Job { param($u, $n) Invoke-RestMethod -Method Post -Uri "${u}hello" -ContentType 'application/json' -Body (@{ hostname = "pc$n" } | ConvertTo-Json) } -ArgumentList $base, $_
    }
    $jobs | Wait-Job -Timeout 20 | Out-Null
    Assert-Equal $s.Hellos.Count 2 'two concurrent hellos'
    $first = $null
    [void]$s.Hellos.TryPeek([ref]$first)
    Assert-Equal $first.remote '127.0.0.1' 'hello carries sender address'
    Assert-Equal (Get-StatusCode "${base}hello" 'POST' ('x' * 9000)) 413 'oversized body'
    Assert-Equal (Get-StatusCode "${base}hello" 'POST' 'not json') 400 'bad json'
    Assert-Equal (Get-StatusCode "${base}inviter.pub" 'POST' '') 404 'wrong method'
    $slow = New-Object Net.Sockets.TcpClient('127.0.0.1', 18765)
    Start-Sleep -Seconds 6
    Assert-Equal (Get-StatusCode "${base}inviter.pub") 200 'alive after a client that sent nothing'
    $slow.Close()
    # a client that trickles one byte a second is dropped after 5 s in total, not 5 s per byte
    $trickle = Start-Job { $c = New-Object Net.Sockets.TcpClient('127.0.0.1', 18765); $s = $c.GetStream(); 1..12 | ForEach-Object { $s.WriteByte(71); Start-Sleep -Seconds 1 }; $c.Close() }
    Start-Sleep -Seconds 7
    $t0 = Get-Date
    Assert-Equal (Get-StatusCode "${base}inviter.pub") 200 'alive while a client trickles'
    Assert-True (((Get-Date) - $t0).TotalSeconds -lt 3) 'answered without waiting for the trickler'
    $trickle | Stop-Job -PassThru | Remove-Job
    $busy = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any, 18766)
    $busy.Start()
    try { Assert-Throws { Start-SshLanInviteServer -Port 18766 -NoFirewall } 'port in use' } finally { $busy.Stop() }
} finally { & $s.Stop }
Assert-Equal (Get-StatusCode "${base}inviter.pub") -1 'stopped'
Assert-True (-not (Test-Path $s.Dir)) 'package folder removed'

# at expiry the server stops by itself
$e = Start-SshLanInviteServer -Port 18767 -Minutes 1 -NoFirewall
try {
    $e.State.Expires = Get-Date
    $t0 = Get-Date
    while (-not $e.State.Done -and ((Get-Date) - $t0).TotalSeconds -lt 3) { Start-Sleep -Milliseconds 50 }
    Assert-True $e.State.Done 'stopped at expiry'
    Assert-Equal (Get-StatusCode "http://127.0.0.1:18767/t/$($e.Token)/inviter.pub") -1 'port closed after expiry'
} finally { & $e.Stop }
