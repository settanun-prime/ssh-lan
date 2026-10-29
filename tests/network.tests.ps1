. "$PSScriptRoot\assert.ps1"
. (Join-Path $TestRoot 'scripts\ssh-lan-common.ps1')
. (Join-Path $TestRoot 'scripts\ssh-lan\ssh-lan.ps1')

# this PC's address mode, read-only: the window shows whether the fixed IP really stuck
$ip = Get-SshLanPrimaryLanIp
$mode = Get-SshLanIpMode $ip
Assert-True ($mode -in 'static', 'dhcp') "mode for this PC: $mode"
$expect = if ("$((Get-NetIPAddress -AddressFamily IPv4 -IPAddress $ip).PrefixOrigin)" -eq 'Manual') { 'static' } else { 'dhcp' }
Assert-Equal $mode $expect 'mode follows the adapter'
Assert-Equal (Get-SshLanIpMode '203.0.113.9') $null 'an address this PC does not have = unknown'

# refused and timed out mean different things to a person fixing it
$listen = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
$listen.Start()
$port = $listen.LocalEndpoint.Port
try { Assert-Equal (Get-SshLanPortState '127.0.0.1' $port 1500) 'open' 'open port' } finally { $listen.Stop() }
Assert-Equal (Get-SshLanPortState '127.0.0.1' $port 3000) 'refused' 'closed port answers with a reset'
Assert-Equal (Get-SshLanPortState '10.255.255.1' 22 800) 'timeout' 'nothing answers'

# diagnose: a refusal points at that machine's sshd/firewall and names this PC's address (it may only trust an old one)
$closed = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
$closed.Start(); $cp = $closed.LocalEndpoint.Port; $closed.Stop()
$said = Test-SshLanReach '127.0.0.1' 'nobody' '' -Port $cp 6>&1 | Out-String
Assert-True ($said -match 'ปฏิเสธ') "refusal named: $said"
Assert-True ($said.Contains((Get-SshLanPrimaryLanIp))) 'names this PC current IP'

# --- fixed IP with a temporary extra address (machines that still dial the old one keep working) ---
$cur = '192.168.1.120'; $pre = 24; $gw = '192.168.1.1'
Assert-Equal (Resolve-SshLanLanIp '50' $cur $pre $gw) '192.168.1.50' 'last number only'
Assert-Equal (Resolve-SshLanLanIp '192.168.1.121' $cur $pre $gw) '192.168.1.121' 'full address'
Assert-Throws { Resolve-SshLanLanIp '1' $cur $pre $gw } 'router address refused'
Assert-Throws { Resolve-SshLanLanIp '0' $cur $pre $gw } 'network address refused'
Assert-Throws { Resolve-SshLanLanIp '255' $cur $pre $gw } 'broadcast refused'
Assert-Throws { Resolve-SshLanLanIp '10.0.0.5' $cur $pre $gw } 'other subnet refused'
Assert-Throws { Resolve-SshLanLanIp '300' $cur $pre $gw } 'not an address'
$plan = Get-SshLanIpPlan '50' @('121', '', '50', '192.168.1.121') $cur $pre $gw
Assert-Equal $plan.Primary '192.168.1.50' 'primary'
Assert-Equal (@($plan.Extras) -join ',') '192.168.1.121' 'extras: deduped, blanks and the primary dropped'
Assert-Equal @((Get-SshLanIpPlan '50' @() $cur $pre $gw).Extras).Count 0 'no extras'

# with two addresses on one card, "this PC" is the primary, never the temporary one
$cands = @(
    [pscustomobject]@{ IPAddress = '192.168.1.121'; InterfaceAlias = 'Ethernet'; SkipAsSource = $true },
    [pscustomobject]@{ IPAddress = '192.168.1.50'; InterfaceAlias = 'Ethernet'; SkipAsSource = $false },
    [pscustomobject]@{ IPAddress = '172.20.16.1'; InterfaceAlias = 'vEthernet (WSL)'; SkipAsSource = $false })
Assert-Equal (Select-SshLanPrimaryIp $cands) '192.168.1.50' 'primary beats the temporary extra'
Assert-Equal (Select-SshLanPrimaryIp @($cands[0], $cands[2])) '192.168.1.121' 'an extra still beats a virtual adapter when it is all the LAN card has'
Assert-Equal (Select-SshLanPrimaryIp @()) $null 'nothing'
Assert-True (@(Get-SshLanExtraIps).Count -ge 0) 'extras readable without admin'

# set-lan-ip.ps1 takes the extras and adds them so they only answer
$tokens = $null; $errs = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $TestRoot 'scripts\ssh-lan\set-lan-ip.ps1'), [ref]$tokens, [ref]$errs)
Assert-True (-not $errs) 'set-lan-ip.ps1 parses'
$params = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
foreach ($p in 'Ip', 'Extra', 'Dhcp', 'RemoveExtra') { Assert-True ($params -contains $p) "set-lan-ip.ps1 -$p" }
Assert-True ($ast.Extent.Text -match 'SkipAsSource \$true') 'extras added with SkipAsSource'

# --- "allow from" list: machines that really logged in, not this PC probing itself ---
$log = @(
    'sshd: Connection reset by 192.168.1.120 port 61204',
    'sshd: Invalid user nobody from 127.0.0.1 port 49556',
    'sshd: Accepted publickey for user from 192.168.1.60 port 21165 ssh2: ED25519 SHA256:x',
    'sshd: Failed password for user from 192.168.1.61 port 5000 ssh2',
    'sshd: Accepted publickey for user from 192.168.1.120 port 1 ssh2',
    'sshd: Accepted publickey for user from 192.168.1.60 port 18137 ssh2')
Assert-Equal ((Get-SshLanLoginSources $log @('192.168.1.120', '192.168.1.121')) -join ',') '192.168.1.60,192.168.1.61' 'logins and failed logins, self and loopback dropped'
Assert-Equal @(Get-SshLanLoginSources @() @()).Count 0 'empty log'

# --- an ssh-config name belongs to a machine, not an address (DHCP hands addresses to other devices) ---
$paired = @{
    '10.9.8.20' = [pscustomobject]@{ Alias = 'box-a'; User = 'u'; HostName = '10.9.8.20'; Port = 22 }
    '10.9.8.30' = [pscustomobject]@{ Alias = 'phone-b'; User = 'u'; HostName = '10.9.8.30'; Port = 8021 }
}
$macA = '02-00-00-00-00-0A'; $macX = '02-00-00-00-00-0F'
Assert-Equal (Resolve-SshLanPair '10.9.8.20' @(22) $macA @() $paired).Pair.Alias 'box-a' 'never bound: the address answering SSH earns the name'
Assert-Equal (Resolve-SshLanPair '10.9.8.20' @(80) $macX @() $paired) $null 'never bound, no SSH there: another device took the address, no name'
Assert-Equal (Resolve-SshLanPair '10.9.8.30' @(8021) $macA @() $paired).Pair.Alias 'phone-b' 'the alias own port counts'
$known = @([pscustomobject]@{ Ip = '10.9.8.20'; Mac = $macA; PairAlias = 'box-a'; LastSeen = (Get-Date).ToString('o') })
Assert-Equal (Resolve-SshLanPair '10.9.8.20' @(22) $macX $known $paired) $null 'bound to another MAC: SSH open is not enough'
$moved = Resolve-SshLanPair '10.9.8.25' @() $macA $known $paired
Assert-Equal $moved.Pair.Alias 'box-a' 'same MAC at a new address keeps its name'
Assert-True $moved.Moved 'and says it moved'
Assert-True (-not (Resolve-SshLanPair '10.9.8.20' @() $macA $known $paired).Moved) 'same address: not moved'
Assert-Equal (Resolve-SshLanPair '10.9.8.99' @(22) $macX $known $paired) $null 'nothing paired there'

# ghosts: a machine that has not answered for a day leaves the list (still remembered for Wake-on-LAN)
$now = Get-Date '2026-10-29T09:00:00'
Assert-True (Test-SshLanRecentlySeen '2026-10-29T01:00:00.0000000' $now) 'seen 8 h ago: listed as offline'
Assert-True (-not (Test-SshLanRecentlySeen '2026-10-27T09:00:00.0000000' $now)) 'two days ago: gone'
Assert-True (-not (Test-SshLanRecentlySeen '' $now)) 'never stamped (older data): gone'
Assert-True (-not (Test-SshLanRecentlySeen 'junk' $now)) 'unreadable stamp: gone'

# IP clash: a fixed IP inside the router's DHCP pool gets handed to another device while its owner sleeps
$clashKnown = @(
    [pscustomobject]@{ Ip = '192.0.2.50'; Mac = '02-00-00-00-00-0B'; Name = 'tv'; LastSeen = '2026-10-29T08:00:00.0000000' }
    [pscustomobject]@{ Ip = '192.0.2.51'; Mac = '02-00-00-00-00-0C'; Name = ''; LastSeen = '2026-10-29T08:00:00.0000000' }
    [pscustomobject]@{ Ip = '192.0.2.52'; Mac = '02-00-00-00-00-0D'; Name = ''; LastSeen = '2026-10-20T08:00:00.0000000' })
$clash = Get-SshLanIpClash '192.0.2.50' '02-00-00-00-00-0A' $clashKnown $now
Assert-Equal $clash.Mac '02-00-00-00-00-0B' 'another MAC on this IP within a day: clash names it'
Assert-Equal (Get-SshLanIpClash '192.0.2.50' '02-00-00-00-00-0B' $clashKnown $now) $null 'same machine again: no clash'
Assert-Equal (Get-SshLanIpClash '192.0.2.52' '02-00-00-00-00-0A' $clashKnown $now) $null 'the other one left days ago: a normal DHCP reuse'
Assert-Equal (Get-SshLanIpClash '192.0.2.50' '' $clashKnown $now) $null 'no MAC seen now: nothing to compare'
Assert-True ((Get-SshLanIpClashText $clash) -match 'DHCP') 'the warning says how to fix it'

# a moved machine: its ssh config entry follows the new address, the rest of the file is untouched
$cfgFile = Join-Path $env:TEMP "sshlan-cfg-$PID"
[IO.File]::WriteAllText($cfgFile, "Host box-a`r`n  HostName 10.9.8.20`r`n  User u`r`n`r`nHost other`r`n  HostName 10.9.8.20`r`n")
try {
    Set-SshLanHostName 'box-a' '10.9.8.25' $cfgFile
    $after = [IO.File]::ReadAllText($cfgFile)
    Assert-True ($after -match '(?m)^Host box-a\r?\n\s+HostName 10\.9\.8\.25') "box-a moved: $after"
    Assert-True ($after -match '(?m)^Host other\r?\n\s+HostName 10\.9\.8\.20') 'other host untouched'
} finally { Remove-Item -LiteralPath $cfgFile, "$cfgFile.*" -ErrorAction SilentlyContinue }
$old = @([pscustomobject]@{ Ip = '10.9.8.20'; Mac = $macA; PairAlias = 'box-a'; LastSeen = '2026-01-01T00:00:00.0000000' })
Assert-Equal (Resolve-SshLanPair '10.9.8.20' @(22) $macX $old $paired).Pair.Alias 'box-a' 'old binding silent for a day: a replacement answering SSH takes the name'

# open SSH / pair on a machine with no SSH server: say so instead of a window that hangs or a silent failure
$listen = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0); $listen.Start(); $lp = $listen.LocalEndpoint.Port
try { Assert-Equal (Get-SshLanNoSshReason '127.0.0.1' $lp) '' 'SSH listening: nothing to say' } finally { $listen.Stop() }
$why = Get-SshLanNoSshReason '127.0.0.1' $lp
Assert-True ($why -match 'ปฏิเสธ' -and $why -match 'SSH server') "refused explained: $why"
Assert-True ((Get-SshLanNoSshReason '10.255.255.1' 22) -match 'ไม่มีอะไรตอบ') 'silence explained'
