# --- network map: one node per real device (scan + latest audit + Tailscale), its kind from evidence, and a fixed layout ---
# real data only: nothing here invents a device. N devices in = N nodes out (plus Tailscale peers not on this LAN)

$script:SshLanKinds = [ordered]@{
    router = 'เราเตอร์'; desktop = 'เดสก์ท็อป'; laptop = 'โน้ตบุ๊ก'; server = 'เซิร์ฟเวอร์'; printer = 'เครื่องพิมพ์'; camera = 'กล้อง'
    tv = 'ทีวี/สื่อ'; nas = 'NAS'; plc = 'PLC'; hmi = 'HMI'; phone = 'มือถือ'; computer = 'คอมพิวเตอร์'; unknown = 'ไม่ทราบชนิด'
}
# what a device calls itself is evidence too, though weaker than what it reports: checked after ports and chassis
$script:SshLanNameKind = @(
    @{ rx = '(?i)android|iphone|ipad|galaxy|pixel|redmi|xiaomi|oppo|vivo|huawei'; kind = 'phone' }
    @{ rx = '(?i)chromecast|bravia|tv\b|smart-?tv|roku|firetv|apple-?tv'; kind = 'tv' }
    @{ rx = '(?i)printer|epson|canon|brother|laserjet|officejet|deskjet|\bhp[-_ ]?\w*print'; kind = 'printer' }
    @{ rx = '(?i)synology|diskstation|qnap|\bnas\b'; kind = 'nas' }
    @{ rx = '(?i)\bcam(era)?\b|ipcam|hikvision|dahua'; kind = 'camera' }
    @{ rx = '(?i)server|\bsrv\b'; kind = 'server' }
    @{ rx = '(?i)laptop|notebook|\bnb-|thinkpad|macbook|zenbook|vivobook|ideapad'; kind = 'laptop' }
)
# SMBIOS chassis types (Win32_SystemEnclosure.ChassisTypes, /sys/class/dmi/id/chassis_type)
$script:SshLanChassisKind = @{
    3 = 'desktop'; 4 = 'desktop'; 5 = 'desktop'; 6 = 'desktop'; 7 = 'desktop'; 13 = 'desktop'; 15 = 'desktop'; 16 = 'desktop'; 24 = 'desktop'; 35 = 'desktop'; 36 = 'desktop'
    8 = 'laptop'; 9 = 'laptop'; 10 = 'laptop'; 11 = 'laptop'; 12 = 'laptop'; 14 = 'laptop'; 18 = 'laptop'; 21 = 'laptop'; 30 = 'laptop'; 31 = 'laptop'; 32 = 'laptop'
    17 = 'server'; 23 = 'server'; 25 = 'server'; 28 = 'server'
}

# every machine in the tailnet, this PC included: @{ name; os; online; ips; self; exitNode }
function Get-SshLanTailscalePeers {
    $ts = Get-SshLanTailscaleExe
    if (-not $ts) { return @() }
    $ErrorActionPreference = 'Continue'
    try { $st = (& $ts status --json 2>$null | Out-String) | ConvertFrom-Json } catch { return @() }
    if (-not $st) { return @() }
    $all = @(if ($st.Self) { , @($st.Self, $true) }) + @(if ($st.Peer) { foreach ($p in $st.Peer.PSObject.Properties.Value) { , @($p, $false) } })
    return @(foreach ($pair in $all) {
        $p = $pair[0]
        $name = if ($p.HostName -and $p.HostName -ne 'localhost') { [string]$p.HostName } else { [string](([string]$p.DNSName) -split '\.')[0] }
        # Addrs = the endpoints the node announced: its LAN address ties the tailnet entry to the device the scan saw
        $lan = @($p.Addrs | ForEach-Object { ([string]$_) -replace ':\d+$', '' } | Where-Object { Test-SshLanPrivateIp $_ } | Select-Object -Unique)
        $seen = if ($p.LastSeen -and "$($p.LastSeen)" -notmatch '^0001') { [datetime]$p.LastSeen } else { $null }
        @{ name = $name; os = ([string]$p.OS).ToLower(); online = [bool]$p.Online; ips = @($p.TailscaleIPs | Where-Object { $_ -match '^\d+\.' }); self = $pair[1]
           exitNode = [bool]$p.ExitNodeOption; lanIps = $lan; lastSeen = $seen }
    })
}

# this PC's own kind evidence, read on the spot (no admin, about a second)
function Get-SshLanLocalKindFacts {
    $ip = Get-SshLanPrimaryLanIp
    $a = if ($ip) { Get-NetIPAddress -AddressFamily IPv4 -IPAddress $ip -ErrorAction SilentlyContinue | Select-Object -First 1 } else { $null }
    $nic = if ($a) { Get-NetAdapter -InterfaceIndex $a.InterfaceIndex -ErrorAction SilentlyContinue } else { $null }
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    return @{
        Os = 'Windows'; Chassis = [string]@((Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue).ChassisTypes)[0]
        Media = $(switch -Regex ("$($nic.PhysicalMediaType)") { '802\.3' { 'wired' } '802\.11' { 'wifi' } default { $null } })
        Server = $(if ($os) { [int]$os.ProductType -ne 1 } else { $null })
    }
}

# the newest audit-*.json, parsed, or $null
# the newest audit-*.json, parsed, or $null. A machine the newest round could not reach keeps the facts
# (hostname, chassis, link, OS) of the last round that did reach it, marked with that round's time
function Get-SshLanLatestAudit([int]$LookBack = 30) {
    $dir = Get-SshLanDataDirectory
    $files = @(Get-ChildItem -LiteralPath $dir -Filter 'audit-*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First $LookBack)
    if (-not $files) { return $null }
    try { $latest = Get-Content -LiteralPath $files[0].FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
    $need = @($latest.Machines | Where-Object { $_.Error -or -not $_.Hostname })
    foreach ($f in $files | Select-Object -Skip 1) {
        if (-not $need) { break }
        try { $old = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
        foreach ($m in @($need)) {
            $hit = @($old.Machines | Where-Object { $_.Ip -eq $m.Ip -and -not $_.Error -and $_.Hostname })[0]
            if (-not $hit) { continue }
            foreach ($k in 'Hostname', 'Chassis', 'Media', 'Os', 'Server') { if ($null -eq $m.$k -or "$($m.$k)" -eq '') { $m | Add-Member -NotePropertyName $k -NotePropertyValue $hit.$k -Force } }
            foreach ($k in 'SshOut', 'SshIn', 'SshLiveIn', 'SshLiveOut') {
                if (@($m.$k).Count) { continue }
                if (@($hit.$k).Count) { $m | Add-Member -NotePropertyName $k -NotePropertyValue @($hit.$k) -Force }
            }
            $m | Add-Member -NotePropertyName FactsFrom -NotePropertyValue ([string]$old.Time) -Force
            $need = @($need | Where-Object { $_ -ne $m })
        }
    }
    return $latest
}

# kinds the user set by hand, keyed by MAC (or IP when there is no MAC); kept in devices.json
function Get-SshLanDeviceKinds {
    $map = @{}
    $path = Get-SshLanKnownDevicesPath
    if (-not (Test-Path -LiteralPath $path)) { return $map }
    try { $items = ConvertFrom-SshLanJsonList (Get-Content -LiteralPath $path -Raw -Encoding UTF8) } catch { return $map }
    foreach ($k in @($items)) { if ($k.Kind) { $map[$(if ($k.Mac) { [string]$k.Mac } else { [string]$k.Ip })] = [string]$k.Kind } }
    return $map
}

function Set-SshLanDeviceKind([string]$Key, [string]$Kind) {
    if ($Kind -and -not $script:SshLanKinds.Contains($Kind)) { throw "ชนิดเครื่องไม่ถูกต้อง: $Kind" }
    $path = Get-SshLanKnownDevicesPath
    $items = @()
    if (Test-Path -LiteralPath $path) { try { $items = ConvertFrom-SshLanJsonList (Get-Content -LiteralPath $path -Raw -Encoding UTF8) } catch { } }
    $hit = @($items | Where-Object { $_.Mac -eq $Key -or (-not $_.Mac -and $_.Ip -eq $Key) })[0]
    if ($hit) {
        $hit | Add-Member -NotePropertyName Kind -NotePropertyValue $Kind -Force
    } else {
        # an entry with only a MAC never shows up as an offline row (those need an IP)
        $isMac = $Key -match '^[0-9A-F]{2}(-[0-9A-F]{2}){5}$'
        $items += [pscustomobject]@{ Ip = $(if ($isMac) { '' } else { $Key }); Mac = $(if ($isMac) { $Key } else { '' }); Name = ''; Os = ''; Kind = $Kind }
    }
    ConvertTo-Json -InputObject @($items) -Depth 3 | Set-Content -LiteralPath $path -Encoding UTF8
}

# explicit Tailscale link by peer hostname (not a typed display name). Key = MAC or IP
function Get-SshLanTsLinks {
    $map = @{}
    $path = Get-SshLanKnownDevicesPath
    if (-not (Test-Path -LiteralPath $path)) { return $map }
    try { $items = ConvertFrom-SshLanJsonList (Get-Content -LiteralPath $path -Raw -Encoding UTF8) } catch { return $map }
    foreach ($k in @($items)) {
        if (-not $k.TsPeer) { continue }
        $map[$(if ($k.Mac) { [string]$k.Mac } else { [string]$k.Ip })] = [string]$k.TsPeer
    }
    return $map
}

function Set-SshLanTsPeer([string]$Key, [string]$Peer) {
    $path = Get-SshLanKnownDevicesPath
    $items = @()
    if (Test-Path -LiteralPath $path) { try { $items = ConvertFrom-SshLanJsonList (Get-Content -LiteralPath $path -Raw -Encoding UTF8) } catch { } }
    $hit = @($items | Where-Object { $_.Mac -eq $Key -or (-not $_.Mac -and $_.Ip -eq $Key) })[0]
    if ($hit) {
        $hit | Add-Member -NotePropertyName TsPeer -NotePropertyValue $Peer -Force
    } else {
        $isMac = $Key -match '^[0-9A-F]{2}(-[0-9A-F]{2}){5}$'
        $items += [pscustomobject]@{ Ip = $(if ($isMac) { '' } else { $Key }); Mac = $(if ($isMac) { $Key } else { '' }); Name = ''; Os = ''; Kind = ''; TsPeer = $Peer }
    }
    ConvertTo-Json -InputObject @($items) -Depth 3 | Set-Content -LiteralPath $path -Encoding UTF8
}

# @{ kind; evidence } following the spec's table, first proof wins; a kind the user set wins over everything
function Get-SshLanDeviceKind($Device, $Facts, $Peer, [string]$UserKind) {
    if ($UserKind -and $script:SshLanKinds.Contains($UserKind)) { return @{ kind = $UserKind; evidence = 'ผู้ใช้ตั้งเอง' } }
    if ("$($Device.Note)" -eq 'เราเตอร์') { return @{ kind = 'router'; evidence = 'IP = default gateway' } }
    $ch = 0
    if ($Facts -and [int]::TryParse([string]$Facts.Chassis, [ref]$ch) -and $script:SshLanChassisKind.ContainsKey($ch)) {
        return @{ kind = $script:SshLanChassisKind[$ch]; evidence = "chassis type $ch (รายงานจากตัวเครื่อง)" }
    }
    if ($Facts -and $Facts.Server -eq $true) {
        return @{ kind = 'server'; evidence = $(if ("$($Facts.Os)" -match 'Windows') { 'Windows Server' } else { 'systemctl get-default = multi-user.target' }) }
    }
    $p = @($Device.Ports | Where-Object { $_ } | ForEach-Object { [int]$_ })
    $has = { param([int[]]$Want) @($Want | Where-Object { $p -contains $_ }) }
    if (& $has 631, 9100, 515) { return @{ kind = 'printer'; evidence = "พอร์ต $((& $has 631, 9100, 515) -join ', ')" } }
    if (& $has 554) { return @{ kind = 'camera'; evidence = 'พอร์ต 554 (RTSP)' } }
    if (& $has 8008, 8009, 7000) { return @{ kind = 'tv'; evidence = "พอร์ต $((& $has 8008, 8009, 7000) -join ', ')" } }
    if ((& $has 5000, 5001) -and $p -contains 445) { return @{ kind = 'nas'; evidence = "พอร์ต $((& $has 5000, 5001) -join ', ') + 445" } }
    if (& $has 502, 102, 44818) { return @{ kind = 'plc'; evidence = "พอร์ต $((& $has 502, 102, 44818) -join ', ')" } }
    if ("$($Device.Name)" -match '^HMI') { return @{ kind = 'hmi'; evidence = 'ชื่อขึ้นต้น HMI' } }
    if ($Peer -and $Peer.os -in 'android', 'ios') { return @{ kind = 'phone'; evidence = "Tailscale: OS = $($Peer.os)" } }
    $names = @($Device.Name, $Device.Alias, $(if ($Peer) { $Peer.name })) | Where-Object { $_ }
    foreach ($h in $script:SshLanNameKind) {
        $hit = @($names | Where-Object { "$_" -match $h.rx })[0]
        if ($hit) { return @{ kind = $h.kind; evidence = "ชื่อเครื่อง $hit" } }
    }
    if ($Peer -and $Peer.os -in 'windows', 'linux', 'macos') { return @{ kind = 'computer'; evidence = "Tailscale: OS = $($Peer.os)" } }
    $os = if ($Facts -and $Facts.Os) { [string]$Facts.Os } else { [string]$Device.Os }
    if ($os -match '(?i)windows|ubuntu|debian|fedora|linux|macos') { return @{ kind = 'computer'; evidence = "ระบบ $os (แบนเนอร์ SSH / พอร์ต)" } }
    # Windows answers ping with TTL 128 (less a few hops); phones, Linux and most gadgets start at 64
    $ttl = [int]$Device.Ttl
    if ($ttl -gt 64 -and $ttl -le 128 -and -not (Test-SshLanRandomMac ([string]$Device.Mac))) { return @{ kind = 'computer'; evidence = "ping TTL $ttl (Windows)" } }
    if ((Test-SshLanRandomMac ([string]$Device.Mac)) -and -not $p) { return @{ kind = 'phone'; evidence = 'MAC สุ่ม และไม่มีพอร์ตเปิด' } }
    return @{ kind = 'unknown'; evidence = 'ไม่มีหลักฐาน' }
}

# sshd's own log (OpenSSH/Operational): who logged in to this PC, IP -> latest login
function ConvertFrom-SshLanSshdLog([object[]]$Events) {
    $in = @{}
    foreach ($e in $Events) {
        if ("$($e.Message)" -notmatch 'Accepted \S+ for \S+ from (\d+\.\d+\.\d+\.\d+) ') { continue }
        $ip = $Matches[1]
        if (-not $in.ContainsKey($ip) -or $e.TimeCreated -gt $in[$ip]) { $in[$ip] = $e.TimeCreated }
    }
    return $in
}

# SSH between this PC and the others: logins here in the last $Days, sessions open now in each direction
# shortcut: logins are matched by IP, so a DHCP move inside the window can credit the wrong machine; match key fingerprints if that bites
function Get-SshLanSshTraffic([int]$Days = 30) {
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'OpenSSH/Operational'; StartTime = (Get-Date).AddDays(-$Days) } -ErrorAction SilentlyContinue)
    $ports = @(@(22) + @((Get-SshLanPairedHosts).Values | ForEach-Object { [int]$_.Port }) | Select-Object -Unique)
    $tcp = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)
    # never count this PC talking to itself (sshd on .100 + client to .100 showed up as "live" and hid real peers)
    $self = @{}
    foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.IPAddress })) {
        if ($a -and $a -notmatch '^127\.') { $self[$a] = $true }
    }
    $peer = { param($ip) $ip -and -not $self.ContainsKey([string]$ip) -and [string]$ip -ne '::1' -and [string]$ip -notmatch '^127\.' }
    return @{
        In = (ConvertFrom-SshLanSshdLog $ev)
        LiveIn = @($tcp | Where-Object { $ports -contains $_.LocalPort -and (& $peer $_.RemoteAddress) } | ForEach-Object { [string]$_.RemoteAddress } | Select-Object -Unique)
        LiveOut = @($tcp | Where-Object { $ports -contains $_.RemotePort -and (& $peer $_.RemoteAddress) } | ForEach-Object { [string]$_.RemoteAddress } | Select-Object -Unique)
    }
}

function Get-SshLanTempOpenIndex {
    $by = @{}
    $now = Get-Date
    foreach ($c in @(Get-SshLanChanges)) {
        if ((Get-SshLanText $c 'action') -ne 'temp-open') { continue }
        if (Get-SshLanText $c 'undoneAt') { continue }
        $mac = Get-SshLanText $c 'mac'
        if (-not $mac) { continue }
        $exp = ConvertTo-SshLanChangeTime (Get-SshLanText $c 'expires')
        if ($exp -eq [datetime]::MinValue -or $exp -le $now) { continue }
        $key = $mac.ToUpperInvariant()
        if (-not $by.ContainsKey($key)) { $by[$key] = New-Object System.Collections.Generic.List[object] }
        [void]$by[$key].Add(@{ Port = [int](Get-SshLanText $c 'port'); Expires = $exp; ChangeId = (Get-SshLanText $c 'id') })
    }
    return $by
}

function Get-SshLanNodeFacts($Machine) {
    if (-not $Machine) { return $null }
    $facts = Get-SshLanBag $Machine 'Facts'
    if ($null -eq $facts) { $facts = Get-SshLanBag $Machine 'facts' }
    return $facts
}

function Get-SshLanNodeTempList([string]$Mac, $Index) {
    $list = New-Object System.Collections.Generic.List[object]
    $key = if ($Mac) { $Mac.ToUpperInvariant() } else { '' }
    if ($key -and $Index -and $Index.ContainsKey($key)) {
        foreach ($row in $Index[$key]) { if ($null -ne $row) { [void]$list.Add($row) } }
    }
    return ,$list
}

# scan rows + latest audit + Tailscale -> nodes. Key = MAC, or IP when the MAC is unknown
# $Local = this PC's own chassis / media / server, read on the spot, used until an audit reports them
# $Ssh = Get-SshLanSshTraffic: @{ In = @{ ip = last login }; LiveIn = @(ip); LiveOut = @(ip) }
function Get-SshLanTopologyModel([object[]]$Devices, $Audit, [object[]]$Peers, [hashtable]$Kinds, $Local, $Ssh, [hashtable]$TsLinks) {
    if (-not $Kinds) { $Kinds = @{} }
    if (-not $TsLinks) { $TsLinks = @{} }
    $sshIn = if ($Ssh -and $Ssh.In) { $Ssh.In } else { @{} }
    $live = @(@($Ssh.LiveIn) + @($Ssh.LiveOut) | Where-Object { $_ })
    $machines = @{}
    foreach ($m in @($Audit.Machines)) { if ($m.Ip) { $machines[[string]$m.Ip] = $m } }
    $findings = @{}
    foreach ($f in @($Audit.Findings)) { if ($f.Ip) { $findings[[string]$f.Ip] = @($findings[[string]$f.Ip]) + $f | Where-Object { $_ } } }
    $peers = @($Peers | Where-Object { $_ })
    $used = @{}
    $tempBy = Get-SshLanTempOpenIndex
    $byKey = [ordered]@{}
    foreach ($d in @($Devices | Where-Object { $_ -and $_.Ip })) {
        $key = if ($d.Mac) { [string]$d.Mac } else { [string]$d.Ip }
        # the same machine twice (a stale offline row next to the live one): keep the live one
        if ($byKey.Contains($key) -and ($byKey[$key].Online -or -not $d.Online)) { continue }
        $self = "$($d.Note)" -eq 'เครื่องนี้'
        $m = $machines[[string]$d.Ip]
        # hostname the machine reported (SSH/audit) wins over DNS and over a Tailscale name when they differ
        $hn = if ($m) { [string]$m.Hostname } else { '' }
        $tsLink = [string]$TsLinks[$key]
        $peer = @($peers | Where-Object {
            ($self -and $_.self) -or
            (@($_.lanIps) -contains [string]$d.Ip) -or
            ($tsLink -and $_.name -eq $tsLink) -or
            ($_.name -and ($_.name -eq "$($d.Name)" -or $_.name -eq "$($d.Alias)" -or ($hn -and $_.name -eq $hn)))
        })[0]
        if ($peer) { $used[$peer.name] = $true }
        $kf = if ($m) { $m } elseif ($self -and $Local) { [pscustomobject]$Local } else { $null }
        $k = Get-SshLanDeviceKind $d $kf $peer $Kinds[$key]
        # hostname from the machine first, then DNS/NetBIOS, then Tailscale; ssh alias last and never the box label alone
        $names = New-Object System.Collections.Generic.List[object]
        $add = { param($n, $from) if ($n -and -not @($names | Where-Object { $_.name -eq $n }).Count) { $names.Add(@{ name = [string]$n; from = $from }) } }
        & $add $hn 'ชื่อที่เครื่องรายงาน (audit)'
        if ($d.Name -and $d.NameFrom -ne '~/.ssh/config') { & $add $d.Name $(if ($d.NameFrom) { [string]$d.NameFrom } else { 'สแกน' }) }
        if ($peer) { & $add $peer.name 'Tailscale' }
        & $add $d.Alias '~/.ssh/config'
        if ($d.NameFrom -eq '~/.ssh/config') { & $add $d.Name '~/.ssh/config' }
        $os = ''; $osFrom = ''
        if ($kf -and $kf.Os) { $os = [string]$kf.Os; $osFrom = 'สมาชิก (อ่านจากตัวเครื่อง)' }
        elseif ($d.Os) { $os = [string]$d.Os; $osFrom = 'แบนเนอร์ SSH / พอร์ต' }
        elseif ($peer) { $os = $peer.os; $osFrom = 'Tailscale' }
        $byKey[$key] = [pscustomobject]@{
            Key = $key; Ip = [string]$d.Ip; Mac = [string]$d.Mac; RandomMac = (Test-SshLanRandomMac ([string]$d.Mac))
            Name = [string]@($names | Where-Object { $_.from -ne '~/.ssh/config' })[0].name; Label = ''
            Names = $names.ToArray(); Kind = $k.kind; KindEvidence = $k.evidence; Os = $os; OsFrom = $osFrom
            Online = [bool]($d.Online -ne $false); InLan = $true; IsRouter = ($k.kind -eq 'router' -and "$($d.Note)" -eq 'เราเตอร์'); IsSelf = $self
            Ports = @($d.Ports | Where-Object { $_ }); Services = [string]$d.Services; Evidence = [string]$d.Evidence; Note = [string]$d.Note; Clash = [string]$d.Clash
            Alias = [string]$d.Alias; User = [string]$d.User; Paired = [bool]$d.Alias
            SshOut = (-not $self -and [bool]$d.Alias); SshIn = (-not $self -and ($sshIn.ContainsKey([string]$d.Ip) -or @($Ssh.LiveIn) -contains [string]$d.Ip))
            SshInAt = $sshIn[[string]$d.Ip]; SshLive = (-not $self -and $live -contains [string]$d.Ip)
            Link = $(if ($kf -and $kf.Media -in 'wired', 'wifi') { [string]$kf.Media } else { 'unknown' })
            Chassis = $(if ($kf) { $kf.Chassis } else { $null })
            Color = $(if ($m) { [string]$m.Color } else { 'gray' }); Audited = [bool]$m
            FactsFrom = $(if ($m -and $m.FactsFrom) { [string]$m.FactsFrom } else { '' }); Red = $(if ($m) { [int]$m.Red } else { 0 }); Amber = $(if ($m) { [int]$m.Amber } else { 0 }); AuditError = $(if ($m) { [string]$m.Error } else { '' })
            Findings = @($findings[[string]$d.Ip] | Where-Object { $_ }); TsIps = $(if ($peer) { @($peer.ips) } else { @() }); TsOnline = $(if ($peer) { $peer.online } else { $false }); TsSeen = $(if ($peer) { $peer.lastSeen } else { $null })
            TsPeer = $tsLink; Facts = (Get-SshLanNodeFacts $m); TempOpen = (Get-SshLanNodeTempList ([string]$d.Mac) $tempBy)
            # SSH graph from the last audit that reached this box (config HostName + sshd Accepted + live sockets)
            SshPeersOut = $(if ($m) { @($m.SshOut | ForEach-Object { [string]$_ } | Where-Object { $_ }) } else { @() })
            SshPeersIn = $(if ($m) { @($m.SshIn | ForEach-Object { [string]$_ } | Where-Object { $_ }) } else { @() })
            SshPeersLive = $(if ($m) { @(@($m.SshLiveIn) + @($m.SshLiveOut) | ForEach-Object { [string]$_ } | Where-Object { $_ } | Select-Object -Unique) } else { @() })
        }
    }
    $nodes = @($byKey.Values | Sort-Object { ConvertTo-SshLanUInt32 $_.Ip })
    $tsOnly = @(foreach ($p in $peers | Where-Object { -not $used.ContainsKey($_.name) -and -not $_.self } | Sort-Object name) {
        $k = Get-SshLanDeviceKind ([pscustomobject]@{ Name = $p.name; Ports = @(); Mac = '' }) $null $p $Kinds["ts:$($p.name)"]
        [pscustomobject]@{
            Key = "ts:$($p.name)"; Ip = [string]@($p.ips)[0]; Mac = ''; RandomMac = $false; Name = $p.name; Label = $p.name
            Names = @(@{ name = $p.name; from = 'Tailscale' }); Kind = $k.kind; KindEvidence = $k.evidence; Os = $p.os; OsFrom = 'Tailscale'
            Online = $p.online; InLan = $false; IsRouter = $false; IsSelf = $false; Ports = @(); Services = ''; Evidence = 'อยู่ใน tailnet ไม่ได้อยู่ในวง LAN นี้'
            Note = ''; Alias = ''; User = ''; Paired = $false; Link = 'tailscale'; Chassis = $null; Color = 'gray'; Audited = $false
            Red = 0; Amber = 0; AuditError = ''; Findings = @(); TsIps = @($p.ips); TsOnline = $p.online; TsSeen = $p.lastSeen
            TsPeer = ''; Facts = $null; TempOpen = (Get-SshLanNodeTempList '' $null)
            SshPeersOut = @(); SshPeersIn = @(); SshPeersLive = @()
        }
    })
    foreach ($n in $nodes + $tsOnly) { $n.Label = if ($n.Name) { $n.Name } else { $n.Ip } }
    return [pscustomobject]@{
        Nodes = $nodes; Tailscale = $tsOnly; Router = @($nodes | Where-Object { $_.IsRouter })[0]
        AuditTime = $(if ($Audit) { [string]$Audit.Time } else { '' }); HasTailscale = [bool]$peers
    }
}

# name prefix for grouping: letters before the first digit or separator ("PC-07" -> "PC")
function Get-SshLanNamePrefix([string]$Name) {
    if ($Name -match '^([A-Za-z]+)') { return $Matches[1].ToUpper() }
    if ($Name) { return $Name }
    return 'ไม่มีชื่อ'
}

# fixed positions from the data (sorted by IP): the same input always draws the same picture
# View: 'link' (router in the middle, lines to each device) or 'group' (80x66 tiles in labelled groups)
function Get-SshLanTopologyLayout($Model, [string]$View = '', [string]$GroupBy = 'subnet', [int]$Width = 1100) {
    $lan = @($Model.Nodes)
    # link view carries SSH motion; keep it when any SSH evidence exists even if the LAN is crowded with phones
    if (-not $View) {
        $sshN = @($lan | Where-Object { $_.SshOut -or $_.SshIn -or @($_.SshPeersOut).Count -or @($_.SshPeersIn).Count }).Count
        $View = if ($lan.Count -le 12 -or $sshN) { 'link' } else { 'group' }
    }
    $place = New-Object System.Collections.Generic.List[object]
    $edges = New-Object System.Collections.Generic.List[object]
    $groups = New-Object System.Collections.Generic.List[object]
    $anchors = @{}
    if ($View -eq 'link') {
        $nw = 104; $nh = 92
        $anchors.internet = @{ X = 40; Y = 24; W = 120; H = 56 }
        $hub = @{ X = [int]($Width / 2 - $nw / 2); Y = 120; W = $nw; H = $nh }
        $anchors.router = $hub
        # corner box only for peers not on this LAN (ruling B: no Tailscale hub spokes into the LAN)
        $ts = @($Model.Tailscale)
        if ($ts.Count) {
            $th = 56 + 30 * [Math]::Max(1, $ts.Count)
            # beside the router, never over it, however narrow the window
            $tsW = [int][Math]::Max(150, [Math]::Min(240, $Width / 2 - $nw / 2 - 40))
            $anchors.tailscale = @{ X = $Width - $tsW - 20; Y = 24; W = $tsW; H = $th }
            foreach ($i in 0..($ts.Count - 1)) {
                $place.Add(@{ Key = $ts[$i].Key; X = $Width - $tsW - 8; Y = 64 + 30 * $i; W = $tsW - 24; H = 26; Small = $true })
            }
        }
        $router = $Model.Router
        if ($router) { $place.Add(@{ Key = $router.Key; X = $hub.X; Y = $hub.Y; W = $nw; H = $nh }) }
        # FlowKey / Online / PeerIp: what measures the line (traffic.ps1), whether both ends are up, the address across a line that touches this PC
        $edges.Add(@{ From = 'internet'; To = $(if ($router) { $router.Key } else { 'router' }); Style = 'internet'
                      FlowKey = 'internet'; Online = $true; PeerIp = ''
                      X1 = $anchors.internet.X + 120; Y1 = $anchors.internet.Y + 28; X2 = $hub.X; Y2 = $hub.Y + $nh / 2
                      Points = @(@(($anchors.internet.X + 120), ($anchors.internet.Y + 28)), @($hub.X, ($hub.Y + $nh / 2))) })
        $rest = @($lan | Where-Object { -not $_.IsRouter })
        # with this PC on the map, SSH gets a line of its own and the router cables stay cables
        $hasSelf = [bool]@($rest | Where-Object { $_.IsSelf }).Count
        $top = [Math]::Max(300, $(if ($anchors.tailscale) { $anchors.tailscale.Y + $anchors.tailscale.H + 70 } else { 0 }))
        # lines run like cabling: down a spine under the router, along a bus above each row, then a drop to each device.
        # Full rows hold an even number, so the spine at the centre always passes between two devices
        $per = [Math]::Max(2, [Math]::Min(6, [Math]::Floor($Width / 124)))
        if ($per % 2 -and $rest.Count -gt $per) { $per-- }
        $cx = $hub.X + $nw / 2; $hubBottom = $hub.Y + $nh
        $trunk = New-Object System.Collections.Generic.List[object]
        $rowsN = [Math]::Ceiling($rest.Count / $per)
        for ($r = 0; $r -lt $rowsN; $r++) {
            $inRow = [Math]::Min($per, $rest.Count - $r * $per)
            $step = $Width / ($inRow + 1)
            $y = [int]($top + $r * ($nh + 80)); $bus = $y - 34
            $xs = @(for ($c = 0; $c -lt $inRow; $c++) { [int]($step * ($c + 1)) })
            $trunk.Add(@(@(([Math]::Min($cx, $xs[0])), $bus), @(([Math]::Max($cx, $xs[-1])), $bus)))
            for ($c = 0; $c -lt $inRow; $c++) {
                $n = $rest[$r * $per + $c]
                $ncx = $xs[$c]
                $place.Add(@{ Key = $n.Key; X = $ncx - $nw / 2; Y = $y; W = $nw; H = $nh })
                $edges.Add(@{ From = $(if ($router) { $router.Key } else { 'router' }); To = $n.Key; Style = $n.Link; Ssh = $n.Paired -and $n.Online -and -not $hasSelf
                              Online = [bool]$n.Online; PeerIp = ''; FlowKey = $(if ($n.IsSelf) { 'nic' } else { "lan:$($n.Key)" })
                              X1 = $ncx; Y1 = $bus; X2 = $ncx; Y2 = $y
                              Points = @(@($cx, $hubBottom), @($cx, $bus), @($ncx, $bus), @($ncx, $y)) })
            }
        }
        # SSH edges from evidence on any home-office box: this PC's pair/login, plus each audited member's config + sshd log.
        # shortcut: a line between rows can cross a device in the row between; route around it if maps grow past two rows
        $at = @{}; foreach ($p in $place) { $at[[string]$p.Key] = $p }
        $byIp = @{}; foreach ($n in $rest) { if ($n.Ip) { $byIp[[string]$n.Ip] = $n } }
        $nodeBy = @{}; foreach ($n in $rest) { $nodeBy[[string]$n.Key] = $n }
        $me = @($rest | Where-Object { $_.IsSelf })[0]
        # directed hops FromKey -> ToKey; later collapsed to one drawn edge with Dir
        $hop = @{}
        $mark = {
            param($FromKey, $ToKey, [bool]$Live)
            if (-not $FromKey -or -not $ToKey -or $FromKey -eq $ToKey) { return }
            $k = "$FromKey>$ToKey"
            if ($hop.ContainsKey($k)) { if ($Live) { $hop[$k] = $true }; return }
            $hop[$k] = $Live
        }
        if ($me) {
            foreach ($n in @($rest | Where-Object { $_.SshOut -or $_.SshIn })) {
                if ($n.SshOut) { & $mark $me.Key $n.Key ([bool]$n.SshLive) }
                if ($n.SshIn) { & $mark $n.Key $me.Key ([bool]$n.SshLive) }
            }
        }
        foreach ($n in $rest) {
            foreach ($ip in @($n.SshPeersOut)) {
                $t = $byIp[[string]$ip]; if (-not $t) { continue }
                & $mark $n.Key $t.Key (@($n.SshPeersLive) -contains [string]$ip)
            }
            foreach ($ip in @($n.SshPeersIn)) {
                $t = $byIp[[string]$ip]; if (-not $t) { continue }
                & $mark $t.Key $n.Key (@($n.SshPeersLive) -contains [string]$ip)
            }
        }
        $pairs = @{}
        foreach ($k in @($hop.Keys)) {
            $parts = $k -split '>', 2
            $pair = if ($parts[0] -lt $parts[1]) { "$($parts[0])|$($parts[1])" } else { "$($parts[1])|$($parts[0])" }
            $pairs[$pair] = $true
        }
        $i = 0
        foreach ($pair in @($pairs.Keys)) {
            $ab = $pair -split '\|', 2
            $a = $ab[0]; $b = $ab[1]
            $fwd = $hop.ContainsKey("$a>$b"); $back = $hop.ContainsKey("$b>$a")
            # Points always follow an outbound hop so Dir out/both puts the arrow on the right end
            if ($fwd -and $back) { $from = $a; $to = $b; $dir = 'both' }
            elseif ($fwd) { $from = $a; $to = $b; $dir = 'out' }
            else { $from = $b; $to = $a; $dir = 'out' }
            $live = [bool]($hop["$a>$b"] -or $hop["$b>$a"])
            $s = $at[$from]; $t = $at[$to]
            if (-not $s -or -not $t) { continue }
            $nf = $nodeBy[$from]; $nt = $nodeBy[$to]
            $peerIp = if ($me -and $from -eq $me.Key) { [string]$nt.Ip } elseif ($me -and $to -eq $me.Key) { [string]$nf.Ip } else { '' }
            $lane = [Math]::Max($s.Y, $t.Y) + $nh + 10 + 6 * ($i % 5)
            $sx = $s.X + 20 + 16 * ($i % 5); $tx = $t.X + $nw / 2
            $edges.Add(@{ From = $from; To = $to; Style = 'ssh'; Ssh = $false; Live = $live; Dir = $dir
                          FlowKey = "ssh:$from>$to"; Online = [bool]($nf.Online -and $nt.Online); PeerIp = $peerIp
                          X1 = $sx; Y1 = $s.Y + $nh; X2 = $tx; Y2 = $t.Y + $nh
                          Points = @(@($sx, ($s.Y + $nh)), @($sx, $lane), @($tx, $lane), @($tx, ($t.Y + $nh))) })
            $i++
        }
        if ($rowsN) { $trunk.Insert(0, @(@($cx, $hubBottom), @($cx, ($top + ($rowsN - 1) * ($nh + 80) - 34)))) }
        $anchors.trunk = $trunk.ToArray()
        $height = $top + [Math]::Max(1, $rowsN) * ($nh + 80) + 10
    } else {
        $tw = 80; $th = 66; $gap = 10; $pad = 14; $head = 30
        $keyOf = switch ($GroupBy) {
            'kind' { { param($n) $script:SshLanKinds[$n.Kind] } }
            'prefix' { { param($n) Get-SshLanNamePrefix $n.Name } }
            default { { param($n) if ($n.Ip -match '^(\d+\.\d+\.\d+)\.') { "$($Matches[1]).0/24" } else { 'ไม่ทราบวง' } } }
        }
        $bag = @{}
        foreach ($n in $lan) { $g = [string](& $keyOf $n); if (-not $bag.ContainsKey($g)) { $bag[$g] = @() }; $bag[$g] += , $n }
        if (@($Model.Tailscale).Count) { $bag['Tailscale'] = @($Model.Tailscale) }
        $maxCols = [Math]::Max(1, [Math]::Floor(($Width - 2 * $pad - 20) / ($tw + $gap)))
        $x = 20; $y = 20; $rowH = 0
        foreach ($g in @($bag.Keys | Sort-Object { if ($_ -eq 'Tailscale') { 'zzz' } else { $_ } })) {
            $items = $bag[[string]$g]
            $cols = [Math]::Min($maxCols, $items.Count)
            $rows = [Math]::Ceiling($items.Count / $cols)
            $gw = $cols * ($tw + $gap) - $gap + 2 * $pad; $gh = $head + $rows * ($th + $gap) - $gap + $pad
            # small groups share a row while they fit
            if ($x -gt 20 -and $x + $gw -gt $Width - 20) { $x = 20; $y += $rowH + 20; $rowH = 0 }
            $groups.Add(@{ Label = "$g · $($items.Count)"; X = $x; Y = $y; W = $gw; H = $gh })
            for ($i = 0; $i -lt $items.Count; $i++) {
                $place.Add(@{ Key = $items[$i].Key; X = $x + $pad + ($i % $cols) * ($tw + $gap); Y = $y + $head + [Math]::Floor($i / $cols) * ($th + $gap); W = $tw; H = $th; Tile = $true })
            }
            $x += $gw + 20; $rowH = [Math]::Max($rowH, $gh)
        }
        $height = $y + $rowH + 20
    }
    return [pscustomobject]@{ View = $View; GroupBy = $GroupBy; Width = $Width; Height = [int]$height; Places = $place.ToArray(); Edges = $edges.ToArray(); Groups = $groups.ToArray(); Anchors = $anchors }
}
