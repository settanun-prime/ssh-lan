# --- audit: turn facts about a machine into coloured findings. Pure: no network, no system calls ---
# colours: red = fix now, amber = check it is meant to be open, green = fine, gray = could not tell

$script:SshLanAuditPorts = @{
    21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 80 = 'HTTP'; 102 = 'Siemens S7'; 443 = 'HTTPS'; 445 = 'SMB (แชร์ไฟล์)'
    502 = 'Modbus'; 515 = 'LPD (พิมพ์)'; 554 = 'RTSP (กล้อง)'; 631 = 'IPP (พิมพ์)'; 1883 = 'MQTT'; 3389 = 'Remote Desktop'
    4840 = 'OPC UA'; 5000 = 'UPnP/NAS'; 5900 = 'VNC'; 8008 = 'Chromecast'; 8080 = 'HTTP-8080'; 9100 = 'พิมพ์ (RAW)'
    44818 = 'EtherNet/IP'; 47808 = 'BACnet'
}
$script:SshLanIndustrialPorts = @(502, 102, 44818, 4840, 47808)
$script:SshLanAuditRank = @{ red = 4; amber = 3; gray = 2; green = 1 }

function Test-SshLanIpInCidr([string]$Ip, [string]$Cidr) {
    $net, $prefix = $Cidr.Split('/')
    $mask = [uint32](([uint64]4294967295 -shl (32 - [int]$prefix)) -band [uint64]4294967295)
    return ((ConvertTo-SshLanUInt32 $Ip) -band $mask) -eq ((ConvertTo-SshLanUInt32 $net) -band $mask)
}

function New-SshLanFinding($Facts, [int]$Port, [string]$Color, [string]$Reason, [string]$Evidence, [string]$Fix, [string]$Process = '', [string]$OpenTo = '', [string]$Rule = '', [string]$Via = '') {
    $openText = @{ any = 'ทุกที่'; lan = 'วง LAN'; tailscale = 'Tailscale'; blocked = 'ไฟร์วอลล์บล็อก'; local = 'เครื่องนี้เท่านั้น' }[$OpenTo]
    $osRaw = [string]$Facts.os
    $os = if ($osRaw -match 'Windows') { 'Windows' } elseif ($osRaw) { 'Linux' } else { '' }
    return [pscustomobject]@{
        Machine = [string]$Facts.machine; Ip = [string]$Facts.ip; Port = $Port
        Service = $(if ($Port) { [string]$script:SshLanAuditPorts[$Port] } else { '' })
        Process = $(if ($Process) { $Process } else { 'ไม่ทราบ' }); OpenTo = $(if ($openText) { $openText } else { $OpenTo })
        Color = $Color; Reason = $Reason; Evidence = $Evidence; Fix = $Fix
        Exposure = [string]$OpenTo; Rule = [string]$Rule; Os = $os; Via = [string]$Via
    }
}

function Get-SshLanAuditFindings([object]$Facts, [hashtable]$Context) {
    $out = New-Object System.Collections.Generic.List[object]
    if ($Facts.error) {
        $out.Add((New-SshLanFinding $Facts 0 'gray' "ตรวจเครื่องนี้ไม่ได้: $($Facts.error)" "ตรวจผ่าน SSH ไม่สำเร็จ" 'เปิดเครื่อง หรือกด "ตรวจว่าทำไมเข้าไม่ได้" แล้วตรวจใหม่'))
        return $out.ToArray()
    }
    if ($Facts.isRouter -and $Context.upnp -eq $true -and -not @($Context.internetPorts).Count) {
        $out.Add((New-SshLanFinding $Facts 0 'amber' 'เราเตอร์เปิด UPnP: โปรแกรมในบ้านเปิดพอร์ตออกอินเทอร์เน็ตเองได้' 'เราเตอร์ตอบ UPnP IGD' 'ปิด UPnP ในหน้าตั้งค่าเราเตอร์ ถ้าไม่ได้ใช้'))
    }
    if ($Facts.member -and $Facts.firewallOn -eq $false) {
        $fwEv = if ([string]$Facts.os -match 'Windows') { 'Get-NetFirewallProfile: Enabled = False' } else { 'ufw: Status inactive' }
        $out.Add((New-SshLanFinding $Facts 0 'red' 'ไฟร์วอลล์ปิดอยู่: ทุกพอร์ตที่เปิดเข้าถึงได้จากเครือข่าย' $fwEv 'กด "เปิดไฟร์วอลล์"'))
    }
    foreach ($m in @($Context.internetPorts) | Where-Object { $_ -and $_.target -eq $Facts.ip }) {
        $viaKey = [string]$m.via
        $via = if ($viaKey -eq 'upnp') { 'เราเตอร์ forward ผ่าน UPnP' } else { 'ทดสอบจากนอกบ้านแล้วเข้าได้' }
        $out.Add((New-SshLanFinding $Facts ([int]$m.port) 'red' 'เข้าจากอินเทอร์เน็ตได้' "$via พอร์ต $($m.port)" 'ลบ port forward ที่เราเตอร์ แล้วเข้าจากข้างนอกผ่าน Tailscale แทน' '' 'any' '' $viaKey))
    }
    $done = @{}
    foreach ($f in $out) { if ($f.Port) { $done[$f.Port] = $true } }

    if ($Facts.member) {
        foreach ($l in @($Facts.listeners)) {
            $p = [int]$l.port
            if (-not $l -or $done.ContainsKey($p)) { continue }
            $done[$p] = $true
            $ruleName = [string]$l.rule
            $ev = "โปรเซส $($l.process) ฟังที่ $($l.address):$p" + $(if ($ruleName) { " · กฎ $ruleName" } else { '' })
            $x = [string]$l.exposure
            $f = { param($c, $why, $fix, $evidence) $out.Add((New-SshLanFinding $Facts $p $c $why $(if ($evidence) { $evidence } else { $ev }) $fix $l.process $x $ruleName)) }
            if ($x -eq 'local') { & $f 'green' 'ฟังเฉพาะในเครื่องนี้ เครื่องอื่นเข้าไม่ได้' '-'; continue }
            if ($x -eq 'blocked') { & $f 'green' 'ไฟร์วอลล์บล็อกอยู่' '-'; continue }
            if ($x -eq 'tailscale' -and $p -notin $script:SshLanIndustrialPorts) { & $f 'green' 'เปิดเฉพาะ Tailscale' '-'; continue }
            if ($p -in 21, 23) { & $f 'red' "$($script:SshLanAuditPorts[$p]) ส่งรหัสผ่านแบบไม่เข้ารหัส" "ปิดบริการ $($script:SshLanAuditPorts[$p]) ใช้ SSH/SFTP แทน"; continue }
            if ($p -eq 445 -and $Facts.smb1) { & $f 'red' 'เปิด SMBv1 ซึ่งมีช่องโหว่ร้ายแรง (เช่น WannaCry)' 'ปิด SMB 1.0 ใน Windows Features'; continue }
            if ($p -eq 22 -and $Facts.sshdPassword -eq $true) { & $f 'red' 'SSH ยังรับล็อกอินด้วยรหัสผ่าน (เดารหัสได้)' 'จับคู่ด้วยกุญแจ แล้วติ๊ก "ใช้กุญแจอย่างเดียว"' ($ev + ' · sshd: passwordauthentication yes'); continue }
            if ($p -eq 3389 -and $Facts.rdp -and $Facts.rdp.nla -eq $false) { & $f 'red' 'Remote Desktop ไม่บังคับ NLA' 'เปิด "Require Network Level Authentication"'; continue }
            if ($x -eq 'any' -and $Facts.profile -eq 'Public') { & $f 'red' 'เปิดรับจากทุกที่บนเครือข่ายแบบ Public' 'จำกัดกฎให้ LocalSubnet หรือเปลี่ยนเครือข่ายเป็น Private'; continue }
            if ($p -in $script:SshLanIndustrialPorts -and $x -in 'any', 'tailscale') { & $f 'red' 'พอร์ตเครื่องจักรเข้าถึงได้จากนอกวงของมัน' 'จำกัดให้เฉพาะวงสายการผลิต'; continue }
            if ($x -eq 'any' -and -not $Facts.profile) { & $f 'amber' 'เปิดให้ทุกเครื่องที่ต่อถึงเครื่องนี้ (ไม่มีไฟร์วอลล์กั้น)' 'กด "เปิดไฟร์วอลล์" แล้วจำกัดพอร์ตนี้'; continue }
            if ($p -in 3389, 5900, 445) { & $f 'amber' "$($script:SshLanAuditPorts[$p]) เปิดให้ทั้งวง ใช้อยู่จริงไหม" 'ปิดถ้าไม่ได้ใช้'; continue }
            if (-not $script:SshLanAuditPorts.ContainsKey($p)) { & $f 'amber' "โปรแกรม $($l.process) เปิดพอร์ต $p ให้เครือข่าย" 'ตรวจว่าโปรแกรมนี้ควรรับการเชื่อมต่อจากเครื่องอื่นไหม'; continue }
            & $f 'green' "เปิดเฉพาะ$(@{ lan = 'วง LAN'; tailscale = 'Tailscale'; any = 'เครือข่าย Private' }[$x])" '-'
        }
        return $out.ToArray()
    }

    # not a member: only what the scan saw from outside, no process, no rules
    $own = @($Context.subnets | Where-Object { $_ -and (Test-SshLanIpInCidr $Facts.ip $_) }).Count -gt 0
    foreach ($p in @($Facts.scannedPorts) | ForEach-Object { [int]$_ }) {
        if ($done.ContainsKey($p)) { continue }
        $done[$p] = $true
        $ev = "สแกนจากเครื่องนี้พบพอร์ต $p เปิด"
        $name = [string]$script:SshLanAuditPorts[$p]
        if ($p -in 21, 23) { $c, $why, $fix = 'red', "$name ส่งรหัสผ่านแบบไม่เข้ารหัส", "ปิด $name ในหน้าตั้งค่าอุปกรณ์" }
        elseif ($p -in $script:SshLanIndustrialPorts -and -not $own) { $c, $why, $fix = 'red', "$name เข้าถึงได้จากวงอื่น", 'แยกวงเครื่องจักร หรือกั้นด้วยไฟร์วอลล์/VLAN' }
        elseif ($p -in 80, 443, 8080) { $c, $why, $fix = 'amber', 'หน้าเว็บตั้งค่าอุปกรณ์ (อาจยังใช้รหัสผ่านเริ่มต้น)', 'เปลี่ยนรหัสผ่านผู้ดูแลของอุปกรณ์' }
        elseif ($p -in 3389, 5900, 445) { $c, $why, $fix = 'amber', "$name เปิดอยู่", 'ปิดถ้าไม่ได้ใช้' }
        else { $c, $why, $fix = 'gray', "$(if ($name) { $name } else { "พอร์ต $p" }) เปิดอยู่ ไม่ทราบรายละเอียด", 'ลง SSH LAN บนเครื่องนั้นเพื่อดูรายละเอียด' }
        $out.Add((New-SshLanFinding $Facts $p $c $why $ev $fix))
    }
    return $out.ToArray()
}

function Get-SshLanAuditSummary([object[]]$Findings) {
    $s = @{ Red = 0; Amber = 0; Green = 0; Gray = 0; Color = 'green' }
    foreach ($f in @($Findings)) {
        if (-not $f) { continue }
        $k = (Get-Culture).TextInfo.ToTitleCase([string]$f.Color)
        $s[$k]++
        if ($script:SshLanAuditRank[[string]$f.Color] -gt $script:SshLanAuditRank[$s.Color]) { $s.Color = [string]$f.Color }
    }
    return $s
}
