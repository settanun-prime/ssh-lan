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
function New-Sample($Seconds, $Rx, $Tx, [string[]]$Live = @()) { @{ Time = $t0.AddSeconds($Seconds); NicRx = $Rx; NicTx = $Tx; SshLive = $Live } }
$nic = @{ FlowKey = 'nic'; Online = $true; PeerIp = '' }
$prev = New-Sample 0 1000 1000
$st = Get-SshLanFlowState $nic $null (New-Sample 2 21000 1000)
Assert-Equal $st.State 'unknown' 'first sample is measuring'
Assert-True ($st.Why -match 'กำลังวัด') 'and says so'
$st = Get-SshLanFlowState $nic $prev (New-Sample 2 21000 1000)
Assert-Equal $st.State 'flow' 'nic flow'
Assert-Equal $st.RxBps 10000 'nic rx rate'
Assert-Equal $st.TxBps 0 'nic tx rate'
Assert-Equal (Get-SshLanFlowState $nic $prev (New-Sample 2 1100 1000)).State 'idle' 'nic idle under the threshold'
Assert-Equal (Get-SshLanFlowState $nic $prev (New-Sample 2 $null $null)).State 'unknown' 'adapter gone gives unknown'
Assert-Equal (Get-SshLanFlowState $nic $prev (New-Sample 2 10 10)).State 'unknown' 'counter reset gives unknown'
$lan = Get-SshLanFlowState @{ FlowKey = 'lan:02-00-00-00-00-01'; Online = $true; PeerIp = '' } $prev (New-Sample 2 5 5)
Assert-Equal $lan.State 'unknown' 'a lan cable cannot be measured'
Assert-True ($lan.Why -match 'SNMP') 'and says why'
$net = Get-SshLanFlowState @{ FlowKey = 'internet'; Online = $true; PeerIp = '' } $prev (New-Sample 2 5 5)
Assert-Equal $net.State 'unknown' 'the internet line cannot be measured'
Assert-True ($net.Why -match 'UPnP') 'and says why'
Assert-Equal (Get-SshLanFlowState @{ FlowKey = 'lan:x'; Online = $false; PeerIp = '' } $prev (New-Sample 2 5 5)).State 'offline' 'offline cable'
$sshOff = @{ FlowKey = 'ssh:a>b'; Online = $false; PeerIp = '10.0.0.5' }
Assert-Equal (Get-SshLanFlowState $sshOff $prev (New-Sample 2 5 5 '10.0.0.5')).State 'offline' 'offline beats live ssh'
$ssh = @{ FlowKey = 'ssh:a>b'; Online = $true; PeerIp = '10.0.0.5' }
$st = Get-SshLanFlowState $ssh $prev (New-Sample 2 5 5 '10.0.0.5')
Assert-Equal $st.State 'flow' 'ssh live from sockets'
Assert-True $st.Fixed 'ssh dots run at a fixed speed'
Assert-Equal (Get-SshLanFlowState $ssh $prev (New-Sample 2 5 5 '10.0.0.9')).State 'idle' 'ssh without a session is idle'
Assert-Equal (Get-SshLanFlowState @{ FlowKey = 'ssh:a>b'; Online = $true; PeerIp = '' } $prev (New-Sample 2 5 5)).State 'unknown' 'ssh between two other machines is unknown'
