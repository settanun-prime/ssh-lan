. "$PSScriptRoot\assert.ps1"
. (Join-Path $TestRoot 'scripts\ssh-lan-common.ps1')
. (Join-Path $TestRoot 'scripts\ssh-lan\ssh-lan.ps1')

# test-only devices: N scan rows on 192.168.1.x (spec: simulated data lives in tests/ only)
function New-TestDevices([int]$N, [string]$Net = '192.168.1') {
    @(for ($i = 0; $i -lt $N; $i++) {
        $o = $i + 2
        [pscustomobject]@{ Online = $true; Name = "PC-$o"; NameFrom = 'DNS'; Ip = "$Net.$o"; Mac = ('02-00-00-{0:X2}-{1:X2}-{2:X2}' -f ([int]($Net.Split('.')[-1]) % 256), [int]($o / 256), ($o % 256)); Os = ''
                           Ports = @(); Services = ''; Alias = ''; User = ''; Note = ''; Evidence = 'ตอบ: ping' }
    })
}

# --- kind from evidence, one row of the spec's table each ---
$d = { param($p) [pscustomobject]@{ Name = 'x'; Ports = $p; Mac = ''; Note = '' } }
Assert-Equal (Get-SshLanDeviceKind ([pscustomobject]@{ Note = 'เราเตอร์'; Ports = @(80) }) $null $null '').kind 'router' 'gateway'
Assert-Equal (Get-SshLanDeviceKind (& $d @()) @{ Chassis = '3' } $null '').kind 'desktop' 'chassis desktop'
Assert-Equal (Get-SshLanDeviceKind (& $d @()) @{ Chassis = '10' } $null '').kind 'laptop' 'chassis notebook'
Assert-Equal (Get-SshLanDeviceKind (& $d @()) @{ Chassis = '23' } $null '').kind 'server' 'chassis rack server'
Assert-Equal (Get-SshLanDeviceKind (& $d @()) @{ Chassis = '2'; Server = $true; Os = 'Ubuntu' } $null '').kind 'server' 'multi-user.target'
Assert-Equal (Get-SshLanDeviceKind (& $d @(9100)) $null $null '').kind 'printer' 'printer port'
Assert-Equal (Get-SshLanDeviceKind (& $d @(554)) $null $null '').kind 'camera' 'RTSP'
Assert-Equal (Get-SshLanDeviceKind (& $d @(8009)) $null $null '').kind 'tv' 'cast'
Assert-Equal (Get-SshLanDeviceKind (& $d @(5000, 445)) $null $null '').kind 'nas' 'NAS'
Assert-Equal (Get-SshLanDeviceKind (& $d @(5000)) $null $null '').kind 'unknown' '5000 alone is not a NAS'
Assert-Equal (Get-SshLanDeviceKind (& $d @(502)) $null $null '').kind 'plc' 'Modbus'
Assert-Equal (Get-SshLanDeviceKind ([pscustomobject]@{ Name = 'HMI-LINE2'; Ports = @() }) $null $null '').kind 'hmi' 'HMI name'
Assert-Equal (Get-SshLanDeviceKind (& $d @()) $null @{ os = 'android' } '').kind 'phone' 'tailscale android'
Assert-Equal (Get-SshLanDeviceKind ([pscustomobject]@{ Name = ''; Ports = @(); Mac = '02-00-5E-00-00-0F' }) $null $null '').kind 'phone' 'random MAC, no ports'
Assert-Equal (Get-SshLanDeviceKind (& $d @()) $null $null '').kind 'unknown' 'no evidence'
Assert-Equal (Get-SshLanDeviceKind (& $d @(9100)) $null $null 'camera').kind 'camera' 'the user wins'
Assert-True (Get-SshLanDeviceKind (& $d @(9100)) $null $null '').evidence 'kind says why'
Assert-Equal (Get-SshLanDeviceKind ([pscustomobject]@{ Name = ''; Alias = 'MY-ANDROID'; Ports = @(); Mac = '' }) $null $null '').kind 'phone' 'name says android'
Assert-Equal (Get-SshLanDeviceKind (& $d @()) $null @{ os = 'linux'; name = 'box' } '').kind 'computer' 'tailscale linux = a computer'
Assert-Equal (Get-SshLanDeviceKind ([pscustomobject]@{ Name = 'x'; Os = 'Windows'; Ports = @(445); Mac = '' }) $null $null '').kind 'computer' 'Windows from the scan'
Assert-Equal (Get-SshLanDeviceKind ([pscustomobject]@{ Name = 'x'; Os = ''; Ports = @(); Mac = '' }) $null @{ os = 'linux'; name = 'homeserver' } '').kind 'server' 'tailscale name says server'
Assert-Equal (Get-SshLanDeviceKind (& $d @(9100)) $null @{ os = 'linux'; name = 'phone-like' } '').kind 'printer' 'ports beat names and OS'

# --- real data only: N in = N nodes out, no duplicates ---
foreach ($n in 0, 1, 4, 13, 50) {
    $m = Get-SshLanTopologyModel (New-TestDevices $n) $null @() @{}
    Assert-Equal @($m.Nodes).Count $n "nodes for $n devices"
    Assert-Equal @($m.Nodes | Select-Object -ExpandProperty Key -Unique).Count $n "unique keys for $n"
    $lay = Get-SshLanTopologyLayout $m
    Assert-Equal @($lay.Places).Count $n "placed $n"
    Assert-Equal $lay.View $(if ($n -le 12) { 'link' } else { 'group' }) "default view for $n"
}
# a stale offline row for a machine that is back online is not counted twice
$devs = New-TestDevices 3
$devs += [pscustomobject]@{ Online = $false; Name = 'PC-2'; Ip = '192.168.1.99'; Mac = $devs[0].Mac; Ports = @(); Note = 'ออฟไลน์' }
$m = Get-SshLanTopologyModel $devs $null @() @{}
Assert-Equal @($m.Nodes).Count 3 'offline twin dropped'
Assert-Equal @($m.Nodes | Where-Object { $_.Mac -eq $devs[0].Mac })[0].Online $true 'live row kept'
$m = Get-SshLanTopologyModel @([pscustomobject]@{ Online = $false; Name = 'OFF'; Ip = '192.168.1.80'; Mac = ''; Ports = @(); Note = 'ออฟไลน์' }) $null @() @{}
Assert-Equal $m.Nodes[0].Online $false 'offline device stays, marked offline'

# --- audit and Tailscale feed the nodes ---
$devs = @(New-TestDevices 2)
$devs[0].Note = 'เครื่องนี้'
$audit = [pscustomobject]@{ Time = '2026-10-29T01:00:00'; Machines = @([pscustomobject]@{ Ip = $devs[0].Ip; Color = 'red'; Os = 'Windows'; Chassis = '10'; Media = 'wifi'; Red = 2; Amber = 1 })
                            Findings = @([pscustomobject]@{ Ip = $devs[0].Ip; Port = 23; Color = 'red'; Reason = 'telnet' }) }
$peers = @(@{ name = 'me-ts'; os = 'windows'; online = $true; ips = @('100.64.0.5'); self = $true },
           @{ name = 'PC-3'; os = 'linux'; online = $true; ips = @('100.64.0.6'); self = $false },
           @{ name = 'phone'; os = 'android'; online = $false; ips = @('100.64.0.7'); self = $false })
$m = Get-SshLanTopologyModel $devs $audit $peers @{}
$me = $m.Nodes[0]
Assert-Equal $me.Kind 'laptop' 'kind from audited chassis'
Assert-Equal $me.Link 'wifi' 'link from audited media'
Assert-Equal $me.Color 'red' 'audit colour'
Assert-Equal @($me.Findings).Count 1 'findings attached'
Assert-Equal @($me.TsIps)[0] '100.64.0.5' 'this PC merged with its own Tailscale entry'
Assert-Equal @($m.Nodes[1].TsIps)[0] '100.64.0.6' 'peer merged by name'
Assert-Equal @($m.Tailscale).Count 1 'only the phone is Tailscale-only'
Assert-Equal $m.Tailscale[0].Kind 'phone' 'Tailscale-only phone'
Assert-Equal $m.Nodes[1].Color 'gray' 'not audited = gray'
Assert-Equal @($me.Names | Where-Object { $_.from -eq 'Tailscale' }).Count 1 'other names kept with their source'
# an audited member is matched to its tailnet entry by the hostname it reported
$audit.Machines += [pscustomobject]@{ Ip = $devs[1].Ip; Color = 'green'; Hostname = 'BOXHOST' }
$m = Get-SshLanTopologyModel $devs $audit @($peers + @{ name = 'BOXHOST'; os = 'linux'; online = $true; ips = @('100.64.0.9'); self = $false }) @{}
Assert-Equal @($m.Nodes[1].TsIps)[0] '100.64.0.6' 'name match still first'
$devs2 = @(New-TestDevices 2 '192.168.7')
$audit2 = [pscustomobject]@{ Machines = @([pscustomobject]@{ Ip = $devs2[1].Ip; Color = 'green'; Hostname = 'BOXHOST' }); Findings = @() }
$m = Get-SshLanTopologyModel $devs2 $audit2 @(@{ name = 'BOXHOST'; os = 'linux'; online = $true; ips = @('100.64.0.9'); self = $false }) @{}
Assert-Equal @($m.Nodes[1].TsIps)[0] '100.64.0.9' 'matched by reported hostname'
Assert-Equal @($m.Tailscale).Count 0 'so it is not listed outside the LAN'
# a peer is tied to the LAN device by the address it announces to the tailnet, whatever its name
$devs3 = @(New-TestDevices 2 '192.168.9')
$m = Get-SshLanTopologyModel $devs3 $null @(@{ name = 'someotherhost'; os = 'linux'; online = $false; ips = @('100.64.0.30'); self = $false; lanIps = @($devs3[1].Ip); lastSeen = (Get-Date).AddHours(-10) }) @{}
Assert-Equal @($m.Nodes[1].TsIps)[0] '100.64.0.30' 'matched by LAN endpoint'
Assert-Equal $m.Nodes[1].Kind 'computer' 'and its OS gives the kind'
# the box shows the name the machine gives itself; the ssh-config alias is only this PC's nickname for it
$devs4 = @(New-TestDevices 2 '192.168.11')
$devs4[1].Name = 'my-alias'; $devs4[1].NameFrom = '~/.ssh/config'; $devs4[1].Alias = 'my-alias'
$tsPeer = @{ name = 'realhost'; os = 'linux'; online = $true; ips = @('100.64.0.9'); self = $false; lanIps = @($devs4[1].Ip) }
$m4 = Get-SshLanTopologyModel $devs4 $null @($tsPeer) @{}
Assert-Equal $m4.Nodes[1].Label 'realhost' 'Tailscale hostname beats the ssh alias'
Assert-Equal (@($m4.Nodes[1].Names | Where-Object { $_.from -eq '~/.ssh/config' })[0].name) 'my-alias' 'alias kept as a second name'
Assert-Equal $m4.Nodes[1].Alias 'my-alias' 'SSH still uses the alias'
$audit4 = [pscustomobject]@{ Machines = @([pscustomobject]@{ Ip = $devs4[1].Ip; Color = 'green'; Hostname = 'REALHOST-AUDIT' }); Findings = @() }
Assert-Equal (Get-SshLanTopologyModel $devs4 $audit4 @($tsPeer) @{}).Nodes[1].Label 'REALHOST-AUDIT' 'the hostname the machine reported itself comes first'
$bare = (Get-SshLanTopologyModel $devs4 $null @() @{}).Nodes[1]
Assert-Equal $bare.Label $devs4[1].Ip 'no real hostname known: the IP, never the alias'
Assert-Equal $bare.Name '' 'and no name claimed'
Assert-Equal $bare.Alias 'my-alias' 'the alias still opens SSH'
Assert-Equal $m4.Nodes[0].Label $devs4[0].Name 'a DNS name stays first'
Assert-True ($m.Nodes[1].TsSeen -is [datetime]) 'last seen carried'
Assert-Equal @($m.Nodes[0].Findings).Count 0 'no audit findings = none, not one empty'
# this PC before any audit: its own chassis and media
$devs2[0].Note = 'เครื่องนี้'
$m = Get-SshLanTopologyModel $devs2 $null @() @{} @{ Os = 'Windows'; Chassis = '9'; Media = 'wired' }
Assert-Equal $m.Nodes[0].Kind 'laptop' 'local chassis'
Assert-Equal $m.Nodes[0].Link 'wired' 'local media'
Assert-Equal $m.Nodes[0].Color 'gray' 'still not audited'
$lk = Get-SshLanLocalKindFacts
Assert-True ($lk.ContainsKey('Chassis') -and $lk.Os -eq 'Windows') 'local kind facts read'

# --- layout: fixed, inside the frame, no overlaps ---
$m = Get-SshLanTopologyModel (New-TestDevices 50) $null @() @{}
$a = Get-SshLanTopologyLayout $m 'group' 'subnet' 1000
$b = Get-SshLanTopologyLayout $m 'group' 'subnet' 1000
Assert-Equal (($a.Places | ForEach-Object { "$($_.X),$($_.Y)" }) -join ';') (($b.Places | ForEach-Object { "$($_.X),$($_.Y)" }) -join ';') 'same data, same picture'
Assert-True (-not @($a.Places | Where-Object { $_.X -lt 0 -or $_.X + $_.W -gt 1000 })) '50 tiles inside the width'
$seen = @{}
foreach ($p in $a.Places) { $k = "$($p.X),$($p.Y)"; Assert-True (-not $seen.ContainsKey($k)) "no two tiles at $k"; $seen[$k] = $true }
$two = @(New-TestDevices 4) + @(New-TestDevices 3 '10.0.5')
$g = Get-SshLanTopologyLayout (Get-SshLanTopologyModel $two $null @() @{}) 'group' 'subnet' 1100
Assert-Equal @($g.Groups).Count 2 'one group per subnet'
Assert-Equal $g.Groups[0].Y $g.Groups[1].Y 'small groups share a row'
$k = Get-SshLanTopologyLayout (Get-SshLanTopologyModel $two $null @() @{}) 'group' 'kind' 1100
Assert-Equal @($k.Groups).Count 1 'group by kind'
$devs = @(New-TestDevices 5)
$devs[0].Note = 'เราเตอร์'
$devs[1].Alias = 'pc3'
$l = Get-SshLanTopologyLayout (Get-SshLanTopologyModel $devs $null @() @{}) 'link'
Assert-Equal @($l.Edges | Where-Object { $_.Style -ne 'internet' }).Count 4 'a line from the router to each device'
Assert-True (@($l.Edges | Where-Object { $_.Ssh }).Count -eq 1) 'paired device gets the SSH line'
Assert-Equal @($l.Places | Where-Object { $_.Key -eq $devs[0].Mac })[0].Y $l.Anchors.router.Y 'router sits on the hub'
# a narrow map puts fewer devices per row, still inside the frame and never under the spine
$nar = Get-SshLanTopologyLayout (Get-SshLanTopologyModel (New-TestDevices 11) $null @() @{}) 'link' 'subnet' 560
Assert-True (-not @($nar.Places | Where-Object { $_.X -lt 0 -or $_.X + $_.W -gt 560 })) 'narrow link view fits'
$spine = $nar.Anchors.router.X + $nar.Anchors.router.W / 2
$nrEmpty = Get-SshLanTopologyLayout ([pscustomobject]@{ Nodes = @(); Tailscale = @(); Router = $null; HasTailscale = $true }) 'link' 'subnet' 560
Assert-True (-not $nrEmpty.Anchors.tailscale) 'no Tailscale corner when every peer is on this LAN'
$offLan = [pscustomobject]@{ Key = 'ts-phone'; Label = 'phone'; Ip = '100.64.0.2'; TsIps = @('100.64.0.2'); Online = $true; InLan = $false; Kind = 'phone'; Os = 'android'; Color = 'gray' }
$nr = Get-SshLanTopologyLayout ([pscustomobject]@{ Nodes = @(); Tailscale = @($offLan); Router = $null; HasTailscale = $true }) 'link' 'subnet' 560
Assert-True ($nr.Anchors.tailscale.X -ge $nr.Anchors.router.X + $nr.Anchors.router.W) 'Tailscale box never covers the router'
# LAN nodes with TsIps get a corner badge in the UI, not hub spokes (ruling B)
$lanTs = @(New-TestDevices 3)
$lanTs[0].Note = 'เราเตอร์'
$peers = @(@{ name = 'on-lan'; os = 'linux'; online = $true; ips = @('100.64.0.3'); self = $false; lanIps = @($lanTs[1].Ip); lastSeen = $null })
$mTs = Get-SshLanTopologyModel $lanTs $null $peers @{}
$lTs = Get-SshLanTopologyLayout $mTs 'link'
Assert-equal @($lTs.Edges | Where-Object { $_.Style -eq 'tailscale' }).Count 0 'no Tailscale hub edges into the LAN'
Assert-True (@($mTs.Nodes | Where-Object { @($_.TsIps).Count }).Count -ge 1) 'model still carries TsIps for the badge'
$lastRow = (@($nar.Places | ForEach-Object { $_.Y }) | Sort-Object)[-1]
Assert-True (-not @($nar.Places | Where-Object { $_.Y -gt $nar.Anchors.router.Y -and $_.X -lt $spine -and $_.X + $_.W -gt $spine -and $_.Y -lt $lastRow })) 'spine passes between devices'

# --- SSH with this PC: a line of its own that says which way it goes ---
$ev = @(
    [pscustomobject]@{ TimeCreated = [datetime]'2026-10-29T07:51:00'; Message = 'sshd: Accepted publickey for u from 192.0.2.40 port 21165 ssh2: ED25519 SHA256:x' }
    [pscustomobject]@{ TimeCreated = [datetime]'2026-10-28T07:00:00'; Message = 'sshd: Accepted password for u from 192.0.2.40 port 2 ssh2' }
    [pscustomobject]@{ TimeCreated = [datetime]'2026-10-29T09:14:00'; Message = 'sshd: banner exchange: Connection from 192.0.2.9 port 1: Connection aborted' })
$logins = ConvertFrom-SshLanSshdLog $ev
Assert-Equal @($logins.Keys).Count 1 'only accepted logins count'
Assert-Equal $logins['192.0.2.40'] ([datetime]'2026-10-29T07:51:00') 'latest login kept'
$devs = @(New-TestDevices 5)
$devs[0].Note = 'เราเตอร์'; $devs[1].Note = 'เครื่องนี้'
$devs[2].Alias = 'pc4'; $devs[3].Alias = 'pc5'
$ssh = @{ In = @{ $devs[2].Ip = [datetime]'2026-10-29T07:00:00'; $devs[4].Ip = [datetime]'2026-10-28T07:00:00' }; LiveOut = @($devs[2].Ip); LiveIn = @() }
$m = Get-SshLanTopologyModel $devs $null @() @{} $null $ssh
$l = Get-SshLanTopologyLayout $m 'link'
$se = @($l.Edges | Where-Object { $_.Style -eq 'ssh' })
Assert-equal $se.Count 3 'one SSH line per machine that talks SSH with this PC'
$e2 = @($se | Where-Object { ($_.From -eq $devs[1].Mac -and $_.To -eq $devs[2].Mac) -or ($_.From -eq $devs[2].Mac -and $_.To -eq $devs[1].Mac) })[0]
Assert-True $e2 'SSH line between this PC and the paired+login machine'
Assert-equal $e2.Dir 'both' 'paired here and logged in here: both ways'
Assert-True $e2.Live 'an open session makes it live'
Assert-equal @($se | Where-Object { ($_.From -eq $devs[1].Mac -and $_.To -eq $devs[3].Mac) -or ($_.From -eq $devs[3].Mac -and $_.To -eq $devs[1].Mac) })[0].Dir 'out' 'paired only: this PC to it'
$e4 = @($se | Where-Object { ($_.From -eq $devs[1].Mac -and $_.To -eq $devs[4].Mac) -or ($_.From -eq $devs[4].Mac -and $_.To -eq $devs[1].Mac) })[0]
Assert-equal $e4.From $devs[4].Mac 'login-only: line drawn from the guest'
Assert-equal $e4.To $devs[1].Mac 'login-only: arrow into this PC'
Assert-equal $e4.Dir 'out' 'one-way hop toward the host'
Assert-True (-not $e4.Live) 'no session now: not live'
Assert-True (-not @($l.Edges | Where-Object { $_.Ssh -and $_.Style -ne 'ssh' })) 'with this PC on the map the router cable stays a plain cable'
Assert-True (-not @($se | ForEach-Object { $_.Points } | Where-Object { $_[1] -gt $l.Height })) 'SSH lines stay inside the map'
# every edge says what measures it: a key, whether both ends are up, and (for SSH with this PC) the address on the other end
$devs[3].Online = $false
$m = Get-SshLanTopologyModel $devs $null @() @{} $null $ssh
$l = Get-SshLanTopologyLayout $m 'link'
$keys = @($l.Edges | ForEach-Object { [string]$_.FlowKey })
Assert-True (-not @($keys | Where-Object { -not $_ })) 'every edge has a FlowKey'
Assert-Equal @($keys | Select-Object -Unique).Count $keys.Count 'FlowKeys are unique'
Assert-True (@($l.Edges | Where-Object { $_.FlowKey -eq 'internet' }).Count -eq 1) 'the internet line'
Assert-True (@($l.Edges | Where-Object { $_.FlowKey -eq 'nic' -and $_.To -eq $devs[1].Mac }).Count -eq 1) 'the cable to this PC is the nic line'
Assert-True (@($l.Edges | Where-Object { $_.FlowKey -eq "lan:$($devs[2].Mac)" }).Count -eq 1) 'other cables are lan lines'
Assert-Equal @($l.Edges | Where-Object { $_.FlowKey -eq "lan:$($devs[3].Mac)" })[0].Online $false 'an offline device: its cable is not online'
Assert-Equal @($l.Edges | Where-Object { $_.FlowKey -eq "lan:$($devs[2].Mac)" })[0].Online $true 'an online device: its cable is'
$sx = @($l.Edges | Where-Object { $_.Style -eq 'ssh' })
$toOff = @($sx | Where-Object { $_.From -eq $devs[3].Mac -or $_.To -eq $devs[3].Mac })[0]
Assert-Equal $toOff.Online $false 'ssh line to an offline machine is not online'
$toOn = @($sx | Where-Object { $_.From -eq $devs[2].Mac -or $_.To -eq $devs[2].Mac })[0]
Assert-Equal $toOn.Online $true 'ssh line between online machines is'
Assert-Equal $toOn.PeerIp $devs[2].Ip 'ssh line with this PC carries the other end address'
Assert-True ($toOn.FlowKey -like 'ssh:*>*') 'ssh flow key names both ends'

# peer SSH (.40 -> .200) comes from the audited host's sshd log, not a manual mark
$peerDevs = @(New-TestDevices 4)
$peerDevs[0].Note = 'เราเตอร์'; $peerDevs[1].Note = 'เครื่องนี้'
$peerAudit = [pscustomobject]@{ Machines = @([pscustomobject]@{ Ip = $peerDevs[3].Ip; Color = 'green'; SshIn = @($peerDevs[2].Ip); SshOut = @(); SshLiveIn = @(); SshLiveOut = @() }); Findings = @() }
$pm = Get-SshLanTopologyModel $peerDevs $peerAudit @() @{} $null @{ In = @{}; LiveIn = @(); LiveOut = @() }
$pl = Get-SshLanTopologyLayout $pm 'link'
$peerEdge = @($pl.Edges | Where-Object { $_.Style -eq 'ssh' -and (($_.From -eq $peerDevs[2].Mac -and $_.To -eq $peerDevs[3].Mac) -or ($_.From -eq $peerDevs[3].Mac -and $_.To -eq $peerDevs[2].Mac)) })[0]
Assert-True $peerEdge 'audit SshIn draws SSH between two other machines'
Assert-equal $peerEdge.From $peerDevs[2].Mac 'guest (.40) is the from end'
Assert-equal $peerEdge.To $peerDevs[3].Mac 'host (.200) is the to end'

# --- the user's kind is kept in devices.json and survives a model rebuild ---
$old = $env:SSH_LAN_DATA_DIR
$env:SSH_LAN_DATA_DIR = Join-Path $env:TEMP ('ssh-lan-test-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $env:SSH_LAN_DATA_DIR | Out-Null
    Set-SshLanDeviceKind '02-00-00-01-00-02' 'nas'
    Set-SshLanDeviceKind '02-00-00-01-00-02' 'printer'
    $kinds = Get-SshLanDeviceKinds
    Assert-Equal $kinds['02-00-00-01-00-02'] 'printer' 'kind saved, last one wins'
    Assert-Equal (Get-SshLanTopologyModel (New-TestDevices 1) $null @() $kinds).Nodes[0].Kind 'printer' 'saved kind used'
    Assert-Throws { Set-SshLanDeviceKind 'x' 'toaster' } 'unknown kind refused'
    # a device seen before and silent now stays on the map as offline, with its saved kind (192.0.2.0/24 never answers)
    ConvertTo-Json -InputObject @([pscustomobject]@{ Ip = '192.0.2.10'; Mac = '02-AA-00-00-00-10'; Name = 'OLD'; Os = ''; Kind = 'nas'; LastSeen = (Get-Date).ToString('o') }, [pscustomobject]@{ Ip = '192.0.2.11'; Mac = ''; Name = 'X'; Os = '' }) |
        Set-Content -LiteralPath (Join-Path $env:SSH_LAN_DATA_DIR 'devices.json') -Encoding UTF8
    $rows = @(Find-SshLanLanDevices '192.0.2.10')
    $off = @($rows | Where-Object { $_.Ip -eq '192.0.2.10' })[0]
    Assert-True ($off -and -not $off.Online) "known device listed offline: $(@($rows).Count) rows"
    Assert-Equal (Get-SshLanTopologyModel $rows $null @() (Get-SshLanDeviceKinds)).Nodes[0].Kind 'nas' 'offline node keeps its kind'
    Assert-Equal (Get-SshLanDeviceKinds)['02-AA-00-00-00-10'] 'nas' 'rescan kept the kind in devices.json'
    # Tailscale often has empty Addrs: an explicit TsPeer link merges the boxes (not a typed Name)
    Set-SshLanTsPeer '02-00-00-00-00-40' 'peer-box'
    Assert-equal (Get-SshLanTsLinks)['02-00-00-00-00-40'] 'peer-box' 'Set-SshLanTsPeer writes TsPeer'
    $lanOnly = @([pscustomobject]@{ Online = $true; Name = ''; NameFrom = ''; Ip = '192.168.1.40'; Mac = '02-00-00-00-00-40'; Ports = @(); Note = '' })
    $mName = Get-SshLanTopologyModel $lanOnly $null @(@{ name = 'peer-box'; os = 'windows'; online = $true; ips = @('100.64.0.77'); self = $false; lanIps = @() }) @{} $null $null (Get-SshLanTsLinks)
    Assert-equal @($mName.Nodes[0].TsIps)[0] '100.64.0.77' 'peer merged by TsPeer when Addrs empty'
    Assert-equal $mName.Nodes[0].TsPeer 'peer-box' 'node keeps TsPeer'
    Assert-equal @($mName.Tailscale).Count 0 'no duplicate Tailscale-only box'
    # hostname from the machine wins the label when it disagrees with the Tailscale name
    $auditHn = [pscustomobject]@{ Machines = @([pscustomobject]@{ Ip = '192.168.1.40'; Hostname = 'real-box'; Color = 'green' }); Findings = @() }
    $mHn = Get-SshLanTopologyModel $lanOnly $auditHn @(@{ name = 'peer-box'; os = 'windows'; online = $true; ips = @('100.64.0.77'); self = $false; lanIps = @() }) @{} $null $null (Get-SshLanTsLinks)
    Assert-equal $mHn.Nodes[0].Label 'real-box' 'hostname beats Tailscale name on the label'
    Assert-equal @($mHn.Nodes[0].TsIps)[0] '100.64.0.77' 'TsPeer link still merges when hostname differs'
    Set-SshLanTsPeer '02-00-00-00-00-40' ''
    Assert-True (-not (Get-SshLanTsLinks)['02-00-00-00-00-40']) 'blank TsPeer clears the link'
} finally {
    Remove-Item -LiteralPath $env:SSH_LAN_DATA_DIR -Recurse -Force -ErrorAction SilentlyContinue
    $env:SSH_LAN_DATA_DIR = $old
}

# --- a machine the newest audit could not reach keeps what an earlier round read from it ---
$old = $env:SSH_LAN_DATA_DIR
$env:SSH_LAN_DATA_DIR = Join-Path $env:TEMP ('ssh-lan-test-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $env:SSH_LAN_DATA_DIR | Out-Null
    $a1 = @{ Time = '2026-10-28T10:00:00'; Machines = @(@{ Ip = '192.168.1.60'; Color = 'green'; Hostname = 'BOXHOST'; Chassis = '10'; Os = 'Ubuntu' }); Findings = @() }
    $a2 = @{ Time = '2026-10-29T10:00:00'; Machines = @(@{ Ip = '192.168.1.60'; Color = 'gray'; Error = 'ssh: connect timed out' }, @{ Ip = '192.168.1.61'; Color = 'green'; Hostname = 'OTHER' }); Findings = @() }
    $a1 | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $env:SSH_LAN_DATA_DIR 'audit-20261028-1000.json') -Encoding UTF8
    (Get-Item (Join-Path $env:SSH_LAN_DATA_DIR 'audit-20261028-1000.json')).LastWriteTime = (Get-Date).AddHours(-24)
    $a2 | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $env:SSH_LAN_DATA_DIR 'audit-20261029-1000.json') -Encoding UTF8
    $la = Get-SshLanLatestAudit
    $m60 = @($la.Machines | Where-Object { $_.Ip -eq '192.168.1.60' })[0]
    Assert-Equal $m60.Hostname 'BOXHOST' 'hostname from the last round that reached it'
    Assert-Equal $m60.Color 'gray' 'colour stays the newest'
    Assert-Equal $m60.FactsFrom '2026-10-28T10:00:00' 'says which round'
    $mm = Get-SshLanTopologyModel @([pscustomobject]@{ Online = $true; Name = ''; Ip = '192.168.1.60'; Mac = ''; Ports = @(); Note = '' }) $la @(@{ name = 'BOXHOST'; os = 'linux'; online = $false; ips = @('100.64.0.40'); self = $false }) @{}
    Assert-Equal $mm.Nodes[0].Kind 'laptop' 'kind from the remembered chassis'
    Assert-Equal @($mm.Tailscale).Count 0 'and the tailnet entry joins it: no duplicate box'
} finally {
    Remove-Item -LiteralPath $env:SSH_LAN_DATA_DIR -Recurse -Force -ErrorAction SilentlyContinue
    $env:SSH_LAN_DATA_DIR = $old
}
Assert-Equal (Get-SshLanDeviceKind ([pscustomobject]@{ Name = ''; Ports = @(); Mac = ''; Ttl = 127 }) $null $null '').kind 'computer' 'TTL 128 range = Windows'
Assert-Equal (Get-SshLanDeviceKind ([pscustomobject]@{ Name = ''; Ports = @(); Mac = ''; Ttl = 64 }) $null $null '').kind 'unknown' 'TTL 64 alone proves nothing'

# --- an open temp window is a property of that node; an expired or undone one is not, and it never becomes a Tailscale spoke ---
$old = $env:SSH_LAN_DATA_DIR
$env:SSH_LAN_DATA_DIR = Join-Path $env:TEMP ('ssh-lan-test-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $env:SSH_LAN_DATA_DIR | Out-Null
    $devs = @(New-TestDevices 2)
    $devs[0].Note = 'เราเตอร์'
    $mac = $devs[1].Mac
    $ip = $devs[1].Ip
    $now = Get-Date
    $row = {
        param($Id, [int]$Port, $Expires, [string]$Undone, $When)
        [pscustomobject]@{
            id = $Id; time = $When.ToString('o'); machine = 'PC-3'; ip = $ip; mac = $mac; os = 'Windows'
            action = 'temp-open'; port = $Port; rules = @("sshlan-temp-$Port"); before = @{}; expires = $Expires.ToString('o'); undoneAt = $Undone
        }
    }
    $changes = @(
        (& $row 'live' 443 $now.AddHours(2) '' $now),
        (& $row 'dead' 80 $now.AddHours(-1) '' $now.AddHours(-2)),
        (& $row 'undo' 444 $now.AddHours(3) $now.ToString('o') $now.AddMinutes(-5))
    )
    ConvertTo-Json -InputObject $changes -Depth 5 | Set-Content -LiteralPath (Join-Path $env:SSH_LAN_DATA_DIR 'changes.json') -Encoding UTF8
    $facts = [pscustomobject]@{ firewallOn = $false; member = $true; os = 'Windows' }
    $audit = [pscustomobject]@{
        Time = '2026-10-29T01:00:00'
        Machines = @([pscustomobject]@{ Ip = $ip; Color = 'green'; Os = 'Windows'; Facts = $facts })
        Findings = @()
    }
    $peers = @(
        @{ name = 'PC-3'; os = 'windows'; online = $true; ips = @('100.64.0.6'); self = $false; lanIps = @($ip) },
        @{ name = 'phone'; os = 'android'; online = $true; ips = @('100.64.0.7'); self = $false }
    )
    $m = Get-SshLanTopologyModel $devs $audit $peers @{}
    $node = @($m.Nodes | Where-Object { $_.Mac -eq $mac })[0]
    Assert-Equal $node.TempOpen.Count 1 'node lists open temp windows'
    Assert-Equal ($node.TempOpen[0].Port) 443 'node lists open temp windows'
    Assert-Equal @($node.TempOpen | Where-Object { [int]$_.Port -eq 80 -or [int]$_.Port -eq 444 }).Count 0 'node lists open temp windows'
    Assert-Equal (Get-SshLanBag $node.Facts 'firewallOn') $false 'node keeps the audit facts'
    $lay = Get-SshLanTopologyLayout $m 'link'
    Assert-True ($null -ne $lay.Anchors.tailscale) 'temp-open shows on the node (no hub tailscale edge)'
    Assert-Equal @($lay.Edges | Where-Object { $_.Style -eq 'tailscale' -or $_.From -eq 'tailscale' }).Count 0 'temp-open shows on the node (no hub tailscale edge)'
    Assert-Equal ($node.TempOpen[0].Port) 443 'temp-open shows on the node (no hub tailscale edge)'
    Assert-True (@($node.TsIps).Count -ge 1) 'temp-open shows on the node (no hub tailscale edge)'
} finally {
    Remove-Item -LiteralPath $env:SSH_LAN_DATA_DIR -Recurse -Force -ErrorAction SilentlyContinue
    $env:SSH_LAN_DATA_DIR = $old
}
