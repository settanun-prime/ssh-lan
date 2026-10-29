# --- audit round: facts from every device, coloured findings, saved and compared with the last round ---
# read-only on every machine. Collectors are swappable so the round can be tested without a network

function Get-SshLanAuditDefaultCollectors {
    return @{
        Local = { Get-SshLanWindowsFacts }
        Member = { param($d) Get-SshLanMemberFacts $d }
        Router = { Get-SshLanRouterFacts }
        Internet = { param($router) Get-SshLanInternetExposure $router.wanIp (Get-SshLanPublicIp) @($router.mappings) @() }
    }
}

# this PC's own networks: an industrial port seen from one of them is in its own range
function Get-SshLanOwnSubnets {
    return @(Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred -ErrorAction SilentlyContinue |
        Where-Object { Test-SshLanPrivateIp $_.IPAddress } | ForEach-Object { ConvertTo-SshLanCidr $_.IPAddress $_.PrefixLength } | Select-Object -Unique)
}

function Invoke-SshLanAudit([object[]]$Devices, [hashtable]$Collectors, [string[]]$Subnets) {
    $col = Get-SshLanAuditDefaultCollectors
    if ($Collectors) { foreach ($k in @($Collectors.Keys)) { $col[$k] = $Collectors[$k] } }
    if ($null -eq $Subnets) { $Subnets = Get-SshLanOwnSubnets }
    $time = Get-Date
    $Devices = @($Devices | Where-Object { $_ })

    $router = try { & $col.Router } catch { @{ upnp = $null; evidence = "ถามเราเตอร์ไม่ได้: $($_.Exception.Message)" } }
    $inet = try { & $col.Internet $router } catch { @{ cgnat = $null; internetPorts = @(); evidence = @("ตรวจอินเทอร์เน็ตไม่ได้: $($_.Exception.Message)") } }
    $ctx = @{ subnets = @($Subnets); internetPorts = @($inet.internetPorts); upnp = $router.upnp; cgnat = $inet.cgnat }

    $facts = @{}
    $isLocal = { param($d) "$($d.Note)" -eq 'เครื่องนี้' }
    $members = @($Devices | Where-Object { $_.Alias -and -not (& $isLocal $_) -and $_.Online -ne $false })
    if ($members) {
        foreach ($r in Invoke-SshLanFleet $members $col.Member) {
            $d = $r.Target
            $facts[$d.Ip] = if ($r.Status -eq 'ok' -and $r.Result) { ConvertTo-SshLanHashtable $r.Result }
                            else { @{ machine = [string]$d.Name; ip = [string]$d.Ip; member = $true; error = $(if ($r.Error) { $r.Error } else { 'ไม่มีคำตอบ' }) } }
        }
    }
    foreach ($d in $Devices) {
        if ($facts.ContainsKey($d.Ip)) { continue }
        if (& $isLocal $d) {
            $facts[$d.Ip] = try { ConvertTo-SshLanHashtable (& $col.Local) } catch { @{ member = $true; error = $_.Exception.Message } }
        } elseif ($d.Online -eq $false) {
            $facts[$d.Ip] = @{ member = [bool]$d.Alias; error = 'ออฟไลน์ในรอบสแกนนี้' }
        } else {
            $facts[$d.Ip] = @{ member = $false; os = [string]$d.Os; scannedPorts = @($d.Ports | Where-Object { $_ }); isRouter = ("$($d.Note)" -eq 'เราเตอร์') }
        }
    }
    # findings are keyed by the address the scan saw, whatever the machine reported about itself
    foreach ($d in $Devices) {
        $f = $facts[$d.Ip]
        $f.ip = [string]$d.Ip
        if (-not $f.machine) { $f.machine = [string]$d.Name }
        if ("$($d.Note)" -eq 'เราเตอร์') { $f.isRouter = $true }
    }

    $findings = New-Object System.Collections.Generic.List[object]
    $byMachine = [ordered]@{}
    foreach ($d in $Devices | Sort-Object { ConvertTo-SshLanUInt32 $_.Ip }) {
        $mine = @(Get-SshLanAuditFindings $facts[$d.Ip] $ctx | Sort-Object { -$script:SshLanAuditRank[$_.Color] }, Port)
        foreach ($x in $mine) { $findings.Add($x) }
        $sum = Get-SshLanAuditSummary $mine
        $byMachine[[string]$d.Ip] = [pscustomobject]@{ Ip = [string]$d.Ip; Name = [string]$facts[$d.Ip].machine; Color = $sum.Color; Findings = $mine; Facts = $facts[$d.Ip] }
    }
    $all = $findings.ToArray()

    $dir = Initialize-SshLanDataDirectory
    $prev = Get-ChildItem -LiteralPath $dir -Filter 'audit-*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
    $new = @($all)
    if ($prev) {
        try {
            $old = @{}
            foreach ($o in @((Get-Content -LiteralPath $prev.FullName -Raw -Encoding UTF8 | ConvertFrom-Json).Findings)) { $old["$($o.Machine)|$($o.Ip)|$($o.Port)"] = $true }
            $new = @($all | Where-Object { -not $old.ContainsKey("$($_.Machine)|$($_.Ip)|$($_.Port)") })
        } catch { }
    }
    # invariant culture: a Thai Windows would otherwise write the Buddhist year (2569)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $path = Join-Path $dir ('audit-' + $time.ToString('yyyyMMdd-HHmm', $inv) + '.json')
    if (Test-Path -LiteralPath $path) { $path = Join-Path $dir ('audit-' + $time.ToString('yyyyMMdd-HHmm-ss', $inv) + '.json') }
    $summary = Get-SshLanAuditSummary $all
    $internet = @{ upnp = $router.upnp; cgnat = $inet.cgnat; wanIp = $router.wanIp; internetPorts = @($inet.internetPorts)
                   evidence = @(@($router.evidence) + @($inet.evidence) | Where-Object { $_ }) }
    ConvertTo-Json -Depth 8 -InputObject ([ordered]@{ Time = $time.ToString('s', $inv); Summary = $summary; Internet = $internet; Findings = $all
        Machines = @($byMachine.Values | ForEach-Object { $f = $_.Facts
            @{ Ip = $_.Ip; Name = $_.Name; Hostname = [string]$f.hostname; Color = $_.Color; Member = [bool]$f.member; Os = $f.os; Chassis = $f.chassis; Media = $f.media; Server = $f.server
               SshOut = @($f.sshOut | Where-Object { $_ }); SshIn = @($f.sshIn | Where-Object { $_ })
               SshLiveIn = @($f.sshLiveIn | Where-Object { $_ }); SshLiveOut = @($f.sshLiveOut | Where-Object { $_ })
               Error = $f.error; Red = @($_.Findings | Where-Object { $_.Color -eq 'red' }).Count; Amber = @($_.Findings | Where-Object { $_.Color -eq 'amber' }).Count } }) }) |
        Set-Content -LiteralPath $path -Encoding UTF8

    return @{ Time = $time; Findings = $all; Summary = $summary; ByMachine = $byMachine; NewSinceLast = $new; Internet = $internet; Path = $path }
}

# CLI: scan, audit, print a summary line and one row per finding (worst first)
function Show-SshLanAudit([string]$Range) {
    Write-Host ' กำลังสแกนวง LAN และตรวจแต่ละเครื่อง (อ่านอย่างเดียว ไม่เปลี่ยนอะไร)...'
    $a = Invoke-SshLanAudit @(Find-SshLanLanDevices $Range)
    $s = $a.Summary
    $th = @{ red = 'แดง'; amber = 'เหลือง'; green = 'เขียว'; gray = 'เทา' }
    $fg = @{ red = 'Red'; amber = 'Yellow'; green = 'Green'; gray = 'DarkGray' }
    Write-Host "สรุป: แดง $($s.Red) เหลือง $($s.Amber) เขียว $($s.Green) เทา $($s.Gray)" -ForegroundColor $fg[$s.Color]
    $i = $a.Internet
    $yn = { param($v, $yes, $no) if ($v -eq $true) { $yes } elseif ($v -eq $false) { $no } else { 'ไม่ทราบ' } }
    Write-Host ("อินเทอร์เน็ต: CGNAT {0} · UPnP {1} · พอร์ตที่เข้าจากนอกบ้านได้ {2}" -f (& $yn $i.cgnat 'ใช่' 'ไม่ใช่'), (& $yn $i.upnp 'เปิด' 'ปิด'), @($i.internetPorts).Count)
    foreach ($e in @($i.evidence)) { Write-Host "    $e" -ForegroundColor DarkGray }
    $new = @{}
    foreach ($n in @($a.NewSinceLast)) { $new["$($n.Ip)|$($n.Port)"] = $true }
    foreach ($f in @($a.Findings) | Sort-Object { -$script:SshLanAuditRank[$_.Color] }, { ConvertTo-SshLanUInt32 $_.Ip }, Port) {
        $port = if ($f.Port) { $f.Port } else { '-' }
        $tag = if ($new.ContainsKey("$($f.Ip)|$($f.Port)")) { ' [ใหม่]' } else { '' }
        Write-Host ('[{0}] {1,-15} {2,-14} {3,-6} {4,-16} {5,-14} {6}{7}' -f $th[$f.Color], $f.Ip, $f.Machine, $port, $f.Service, $f.OpenTo, $f.Reason, $tag) -ForegroundColor $fg[$f.Color]
        Write-Host "      หลักฐาน: $($f.Evidence) · โปรเซส: $($f.Process)" -ForegroundColor DarkGray
        if ($f.Fix -and $f.Fix -ne '-') { Write-Host "      วิธีแก้: $($f.Fix)" -ForegroundColor DarkGray }
    }
    Write-Host " [✓] บันทึกผลที่ $($a.Path)"
}
