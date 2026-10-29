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


# --- readers: each one returns $null or empty when it cannot read, never throws ---

# rx / tx byte counters of the adapter that holds $Ip (no admin needed), or $null
function Get-SshLanNicCounters([string]$Ip) {
    try {
        foreach ($n in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if (-not @($n.GetIPProperties().UnicastAddresses | Where-Object { $_.Address.ToString() -eq $Ip }).Count) { continue }
            $s = $n.GetIPv4Statistics()
            return @{ Rx = [uint64]$s.BytesReceived; Tx = [uint64]$s.BytesSent }
        }
    } catch { }
    return $null
}

# `tailscale status --json` -> name -> @{ Rx; Tx; Online } for every peer but this PC; the name follows Get-SshLanTailscalePeers
function ConvertFrom-SshLanTailscaleCounters([string]$Json) {
    $out = @{}
    if (-not $Json -or -not $Json.Trim()) { return $out }
    try { $st = $Json | ConvertFrom-Json } catch { return $out }
    if (-not $st -or -not $st.Peer) { return $out }
    foreach ($p in $st.Peer.PSObject.Properties.Value) {
        $name = if ($p.HostName -and $p.HostName -ne 'localhost') { [string]$p.HostName } else { [string](([string]$p.DNSName) -split '\.')[0] }
        if ($name) { $out[$name] = @{ Rx = $p.RxBytes; Tx = $p.TxBytes; Online = [bool]$p.Online } }
    }
    return $out
}

function Get-SshLanTsRate([hashtable]$Prev, [hashtable]$Cur, [string]$Name, [double]$Seconds) {
    if (-not $Prev -or -not $Cur -or -not $Prev.ContainsKey($Name) -or -not $Cur.ContainsKey($Name)) { return $null }
    $rx = Get-SshLanRate $Prev[$Name].Rx $Cur[$Name].Rx $Seconds
    $tx = Get-SshLanRate $Prev[$Name].Tx $Cur[$Name].Tx $Seconds
    if ($null -eq $rx -and $null -eq $tx) { return $null }
    return @{ Rx = $rx; Tx = $tx }
}

# addresses on the other end of an established connection on one of the SSH ports (either end), this PC and loopback left out
function Get-SshLanLivePeers([object[]]$Connections, [int[]]$Ports, [string[]]$SelfIps) {
    $self = @{}; foreach ($a in $SelfIps) { if ($a) { $self[[string]$a] = $true } }
    $peers = New-Object System.Collections.Generic.List[string]
    foreach ($c in $Connections) {
        $ip = [string]$c.RemoteAddress
        if (-not $ip -or $self.ContainsKey($ip) -or $ip -eq '::1' -or $ip -match '^127\.') { continue }
        if (($Ports -contains [int]$c.LocalPort) -or ($Ports -contains [int]$c.RemotePort)) { if (-not $peers.Contains($ip)) { $peers.Add($ip) } }
    }
    return $peers.ToArray()
}

# one sample: NIC counters, SSH sessions open now, Tailscale peer counters. Slow readers (netstat, tailscale.exe) belong in a runspace
function Read-SshLanTrafficSample([string]$LanIp, [string]$TailscaleExe = (Get-SshLanTailscaleExe)) {
    $nic = Get-SshLanNicCounters $LanIp
    $ports = @(22)
    try { $ports += @((Get-SshLanPairedHosts).Values | ForEach-Object { [int]$_.Port }) } catch { }
    $selfIps = @(); try { $selfIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.IPAddress }) } catch { }
    $conns = @(); try { $conns = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue) } catch { }
    $ts = @{}
    if ($TailscaleExe) { try { $ts = ConvertFrom-SshLanTailscaleCounters ((& $TailscaleExe status --json 2>$null) | Out-String) } catch { } }
    return @{
        Time = Get-Date; NicRx = $(if ($nic) { $nic.Rx } else { $null }); NicTx = $(if ($nic) { $nic.Tx } else { $null })
        SshLive = @(Get-SshLanLivePeers $conns ($ports | Select-Object -Unique) $selfIps); Ts = $ts
    }
}