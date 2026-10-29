. "$PSScriptRoot\assert.ps1"
. (Join-Path $TestRoot 'scripts\ssh-lan-common.ps1')
. (Join-Path $TestRoot 'scripts\ssh-lan\ssh-lan.ps1')

# --- rate from two counter reads: bytes per second, or nothing when the two reads cannot be compared ---
Assert-Equal (Get-SshLanRate 1000 3500 2.5) 1000 'rate from two counters'
Assert-Equal (Get-SshLanRate 5000 100 2.5) $null 'counter reset gives no rate'
Assert-Equal (Get-SshLanRate 0 9999 11) $null 'gap over 10 s gives no rate'
Assert-Equal (Get-SshLanRate $null 10 2.5) $null 'missing counter gives no rate'
Assert-Equal (Get-SshLanRate 10 $null 2.5) $null 'missing second counter gives no rate'
Assert-Equal (Get-SshLanRate 10 20 0) $null 'no time passed gives no rate'

# --- dots: none under 512 B/s, 1..3 by level, slower when quieter (log scale, 1.2 s .. 4 s) ---
Assert-Equal (ConvertTo-SshLanDotSpec 511).Dots 0 'below 512 B/s no dots'
$s = ConvertTo-SshLanDotSpec 1000
Assert-Equal $s.Dots 1 '1 KB/s is single'
Assert-Equal $s.Ms 4000 '1 KB/s is slow'
$s = ConvertTo-SshLanDotSpec 1000000
Assert-Equal $s.Dots 3 '1 MB/s is triple'
Assert-True ($s.Ms -ge 1190 -and $s.Ms -le 1210) "1 MB/s is fast (got $($s.Ms))"
Assert-Equal (ConvertTo-SshLanDotSpec 100000).Dots 2 '100 KB/s is double'
Assert-True ((ConvertTo-SshLanDotSpec 600).Ms -le 4000) 'ms never above 4000'
Assert-True ((ConvertTo-SshLanDotSpec 1e9).Ms -ge 1200) 'ms never below 1200'

# --- flow state of one edge ---
$t0 = Get-Date '2026-10-29T10:00:00'
function New-Sample($Seconds, $Rx, $Tx, [string[]]$Live = @(), [string]$Nic = 'eth0') { @{ Time = $t0.AddSeconds($Seconds); NicRx = $Rx; NicTx = $Tx; NicId = $Nic; SshLive = $Live } }
# the state as seen a second after the newest sample (a sample older than 10 s is not a measurement any more)
function FS($e, $p, $c) { Get-SshLanFlowState $e $p $c ($c.Time.AddSeconds(1)) }
$nic = @{ FlowKey = 'nic'; Online = $true; PeerIp = '' }
$prev = New-Sample 0 1000 1000
$st = FS $nic $null (New-Sample 2 21000 1000)
Assert-Equal $st.State 'unknown' 'first sample is measuring'
Assert-True ($st.Why -match 'กำลังวัด') 'and says so'
$st = FS $nic $prev (New-Sample 2 21000 1000)
Assert-Equal $st.State 'flow' 'nic flow'
Assert-Equal $st.RxBps 10000 'nic rx rate'
Assert-Equal $st.TxBps 0 'nic tx rate'
Assert-Equal (FS $nic $prev (New-Sample 2 1100 1000)).State 'idle' 'nic idle under the threshold'
Assert-Equal (FS $nic $prev (New-Sample 2 $null $null)).State 'unknown' 'adapter gone gives unknown'
Assert-Equal (FS $nic $prev (New-Sample 2 10 10)).State 'unknown' 'counter reset gives unknown'
$lan = FS @{ FlowKey = 'lan:02-00-00-00-00-01'; Online = $true; PeerIp = '' } $prev (New-Sample 2 5 5)
Assert-Equal $lan.State 'unknown' 'a lan cable cannot be measured'
Assert-True ($lan.Why -match 'SNMP') 'and says why'
$net = FS @{ FlowKey = 'internet'; Online = $true; PeerIp = '' } $prev (New-Sample 2 5 5)
Assert-Equal $net.State 'unknown' 'the internet line cannot be measured'
Assert-True ($net.Why -match 'UPnP') 'and says why'
# the internet line: a real ping says up or down; still no dots, it is not a traffic count
$inet = @{ FlowKey = 'internet'; Online = $true; PeerIp = '' }
$up = New-Sample 2 5 5; $up.Net = @{ Up = $true; Ms = 14; Target = '192.0.2.53' }
$st = FS $inet $prev $up
Assert-Equal $st.Net 'up' 'a ping answer marks the internet up'
Assert-Equal $st.State 'unknown' 'up is still not a traffic count (no dots)'
Assert-True ($st.Why -match '14 ms' -and $st.Why -match 'UPnP') 'says the ping time and why there are no dots'
$down = New-Sample 2 5 5; $down.Net = @{ Up = $false; Ms = $null; Target = '192.0.2.53' }
$st = FS $inet $prev $down
Assert-Equal $st.Net 'down' 'no ping answer marks the internet down'
Assert-True ($st.Why -match 'ไม่ได้') 'and says it cannot get out'
Assert-Equal (Get-SshLanFlowState $inet $prev $up $up.Time.AddSeconds(30)).Net $null 'an old ping is not up or down'
Assert-True ((Get-SshLanFlowSig (FS $inet $prev $up)) -ne (Get-SshLanFlowSig (FS $inet $prev $down))) 'up to down redraws the line'
Assert-Equal (FS @{ FlowKey = 'lan:x'; Online = $false; PeerIp = '' } $prev (New-Sample 2 5 5)).State 'offline' 'offline cable'
$sshOff = @{ FlowKey = 'ssh:a>b'; Online = $false; PeerIp = '10.0.0.5' }
Assert-Equal (FS $sshOff $prev (New-Sample 2 5 5 '10.0.0.5')).State 'offline' 'offline beats live ssh'
$ssh = @{ FlowKey = 'ssh:a>b'; Online = $true; PeerIp = '10.0.0.5' }
$st = FS $ssh $prev (New-Sample 2 5 5 '10.0.0.5')
Assert-Equal $st.State 'flow' 'ssh live from sockets'
Assert-True $st.Fixed 'ssh dots run at a fixed speed'
Assert-Equal (FS $ssh $prev (New-Sample 2 5 5 '10.0.0.9')).State 'idle' 'ssh without a session is idle'
Assert-True ((FS $ssh $prev (New-Sample 2 5 5 '10.0.0.9')).Why -match 'ไม่เห็น session') 'and does not claim there is none anywhere (it may run over another address)'
Assert-Equal (FS @{ FlowKey = 'ssh:a>b'; Online = $true; PeerIp = '' } $prev (New-Sample 2 5 5)).State 'unknown' 'ssh between two other machines is unknown'

# --- counters: Tailscale per-peer bytes, sockets that mean "an SSH session is open", the NIC ---
$json = '{"Self":{"HostName":"me","RxBytes":1,"TxBytes":2},"Peer":{"nodekey:a":{"HostName":"localhost","DNSName":"box.example.ts.net.","RxBytes":2000,"TxBytes":500,"Online":true},"nodekey:b":{"HostName":"phone","DNSName":"phone.example.ts.net.","RxBytes":0,"TxBytes":0,"Online":false}}}'
$ts = ConvertFrom-SshLanTailscaleCounters $json
Assert-Equal @($ts.Keys).Count 2 'two peers, this PC left out'
Assert-Equal $ts['box'].Rx 2000 'a peer named localhost is read by its DNS name'
Assert-Equal $ts['box'].Tx 500 'tx kept'
Assert-Equal $ts['phone'].Online $false 'online flag kept'
Assert-True (-not $ts.ContainsKey('me')) 'self excluded'
Assert-Equal @((ConvertFrom-SshLanTailscaleCounters 'not json').Keys).Count 0 'bad json gives empty'
Assert-Equal @((ConvertFrom-SshLanTailscaleCounters '').Keys).Count 0 'empty text gives empty'
$r = Get-SshLanTsRate @{ box = @{ Rx = 1000; Tx = 100 } } @{ box = @{ Rx = 11000; Tx = 100 } } 'box' 2
Assert-Equal $r.Rx 5000 'ts rx rate'
Assert-Equal $r.Tx 0 'ts tx rate'
Assert-Equal (Get-SshLanTsRate @{} @{ box = @{ Rx = 1; Tx = 1 } } 'box' 2) $null 'peer missing in the first read'
$conns = @(
    [pscustomobject]@{ LocalAddress = '10.0.0.2'; LocalPort = 51000; RemoteAddress = '10.0.0.5'; RemotePort = 22 }
    [pscustomobject]@{ LocalAddress = '10.0.0.2'; LocalPort = 22; RemoteAddress = '10.0.0.6'; RemotePort = 40000 }
    [pscustomobject]@{ LocalAddress = '10.0.0.2'; LocalPort = 51001; RemoteAddress = '10.0.0.7'; RemotePort = 8021 }
    [pscustomobject]@{ LocalAddress = '10.0.0.2'; LocalPort = 51002; RemoteAddress = '10.0.0.2'; RemotePort = 22 }
    [pscustomobject]@{ LocalAddress = '127.0.0.1'; LocalPort = 51003; RemoteAddress = '127.0.0.1'; RemotePort = 22 }
    [pscustomobject]@{ LocalAddress = '10.0.0.2'; LocalPort = 51004; RemoteAddress = '10.0.0.8'; RemotePort = 443 })
$live = @(Get-SshLanLivePeers $conns @(22, 8021) @('10.0.0.2'))
Assert-Equal ($live -join ',') '10.0.0.5,10.0.0.6,10.0.0.7' 'out, in and a paired port count; self, loopback and other ports do not'
Assert-Equal @(Get-SshLanLivePeers @() @(22) @()).Count 0 'no connections'
Assert-Equal (Get-SshLanNicCounters '192.0.2.250') $null 'no adapter holds that address'
Assert-True ($null -ne (Get-SshLanNicCounters '127.0.0.1')) 'loopback counters are readable'
$real = Read-SshLanTrafficSample (Get-SshLanPrimaryLanIp)
Assert-True ($real.NicRx -is [ValueType]) 'real sample: rx counter is a number'
Assert-True (((Get-Date) - $real.Time).TotalSeconds -lt 5) 'real sample: stamped now'
$none = Read-SshLanTrafficSample '127.0.0.1' ''
Assert-Equal @($none.Ts.Keys).Count 0 'no tailscale.exe gives no peers'
# --- the signature of a state: a redraw is needed only when what the dots look like changes ---
$a = @{ State = 'flow'; RxBps = 20000; TxBps = 0; Fixed = $false }
$b = @{ State = 'flow'; RxBps = 21000; TxBps = 0; Fixed = $false }
$c = @{ State = 'flow'; RxBps = 2000000; TxBps = 0; Fixed = $false }
Assert-Equal (Get-SshLanFlowSig $a) (Get-SshLanFlowSig $b) 'a small change in rate keeps the dots as they are'
Assert-True ((Get-SshLanFlowSig $a) -ne (Get-SshLanFlowSig $c)) 'a big change restarts them'
Assert-True ((Get-SshLanFlowSig $a) -ne (Get-SshLanFlowSig @{ State = 'idle'; RxBps = 0; TxBps = 0; Fixed = $false })) 'flow to idle is a change'
# --- review fixes: an adapter swap is not a rate, and an old sample is not a measurement ---
$wifi = New-Sample 0 1000000000 1000 @() 'wifi'
$eth = New-Sample 2 50000000000 1000 @() 'eth'
$st = FS $nic $wifi $eth
Assert-Equal $st.State 'unknown' 'a different adapter between two reads gives no rate (not 24 GB/s)'
Assert-True ($st.Why -match 'การ์ดเน็ต') 'and says the adapter changed'
Assert-Equal (FS $nic (New-Sample 0 1000 1000 @() 'eth') (New-Sample 2 21000 1000 @() 'eth')).State 'flow' 'the same adapter twice is a rate'
$cur = New-Sample 2 21000 1000
Assert-Equal (Get-SshLanFlowState $nic $prev $cur $cur.Time.AddSeconds(30)).State 'unknown' 'a sample 30 s old is not a measurement'
Assert-True ((Get-SshLanFlowState $nic $prev $cur $cur.Time.AddSeconds(30)).Why -match 'เก่า') 'and says why'
Assert-Equal (Get-SshLanFlowState $ssh $prev (New-Sample 2 5 5 '10.0.0.5') $cur.Time.AddSeconds(30)).State 'unknown' 'a live ssh socket list 30 s old is not either'
Assert-Equal (Get-SshLanFlowState $nic $prev $cur $cur.Time.AddSeconds(5)).State 'flow' 'five seconds old is still fine'
Assert-True ((Get-SshLanNicCounters '127.0.0.1').Id) 'the adapter id comes with the counters'
Assert-True ($real.NicId) 'a real sample names its adapter'
Assert-True ($real.Net -and $real.Net.Up -is [bool]) 'a real sample says whether the internet answered'
Assert-Equal (Get-SshLanInternetReach @('192.0.2.1') 200).Up $false 'an address nobody answers is down'