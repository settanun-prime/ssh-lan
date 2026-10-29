# --- live traffic on the map: what a moving dot is allowed to mean ---
# A dot runs only where a byte counter really went up between two reads. A line nothing can measure stays still and says why.
# Pure functions here (tested with made-up numbers); the readers that touch the system are further down.

$script:SshLanFlowMinBps = 512

# bytes per second between two counter reads, or $null when the two cannot be compared:
# a missing read, a counter that went back (reset, adapter replaced), or reads too far apart (sleep, hidden window)
function Get-SshLanRate($Prev, $Now, [double]$Seconds) {
    if ($null -eq $Prev -or $null -eq $Now -or $Seconds -le 0 -or $Seconds -gt 10) { return $null }
    if ([double]$Now -lt [double]$Prev) { return $null }
    return ([double]$Now - [double]$Prev) / $Seconds
}

# how many dots and how long one trip takes: 1 KB/s = 4 s, 1 MB/s = 1.2 s on a log scale
function ConvertTo-SshLanDotSpec([double]$Bps) {
    if ($Bps -lt $script:SshLanFlowMinBps) { return @{ Dots = 0; Ms = 0 } }
    $dots = if ($Bps -lt 10000) { 1 } elseif ($Bps -lt 1000000) { 2 } else { 3 }
    $ms = 4000 - 933.33 * ([Math]::Log10($Bps) - 3)
    return @{ Dots = $dots; Ms = [int][Math]::Round([Math]::Min(4000, [Math]::Max(1200, $ms))) }
}

# $Edge = @{ FlowKey; Online; PeerIp }, $Prev / $Cur = @{ Time; NicRx; NicTx; SshLive }
# State: flow (a counter went up), idle (measured, nothing moving), unknown (nothing can measure it), offline (an end is down)
function Get-SshLanFlowState($Edge, $Prev, $Cur) {
    $r = { param($state, $why, $rx, $tx, $fixed) @{ State = $state; RxBps = $rx; TxBps = $tx; Fixed = [bool]$fixed; Why = $why } }
    $key = [string]$Edge.FlowKey
    if ($Edge.Online -eq $false) { return & $r 'offline' 'ออฟไลน์' $null $null $false }
    if ($key -eq 'internet') { return & $r 'unknown' 'วัดไม่ได้: router ไม่ตอบ UPnP' $null $null $false }
    if ($key -like 'lan:*') { return & $r 'unknown' 'วัดไม่ได้: ไม่มี SNMP' $null $null $false }
    if ($key -like 'ssh:*') {
        if (-not [string]$Edge.PeerIp) { return & $r 'unknown' 'วัดสดไม่ได้: ใช้หลักฐานจาก audit' $null $null $false }
        if (-not $Cur) { return & $r 'unknown' 'กำลังวัด' $null $null $false }
        if (@($Cur.SshLive) -contains [string]$Edge.PeerIp) { return & $r 'flow' 'มี session เปิดอยู่' $null $null $true }
        return & $r 'idle' 'ไม่มี session เปิดอยู่' $null $null $false
    }
    if (-not $Prev -or -not $Cur) { return & $r 'unknown' 'กำลังวัด' $null $null $false }
    $secs = ([datetime]$Cur.Time - [datetime]$Prev.Time).TotalSeconds
    $rx = Get-SshLanRate $Prev.NicRx $Cur.NicRx $secs
    $tx = Get-SshLanRate $Prev.NicTx $Cur.NicTx $secs
    if ($null -eq $rx -and $null -eq $tx) { return & $r 'unknown' 'ตัวนับรีเซ็ตหรือห่างเกินไป รอรอบหน้า' $null $null $false }
    $top = [Math]::Max([double]$rx, [double]$tx)
    if ($top -ge $script:SshLanFlowMinBps) { return & $r 'flow' '' $rx $tx $false }
    return & $r 'idle' 'ไม่มีข้อมูลวิ่ง' $rx $tx $false
}
