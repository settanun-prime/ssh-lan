# --- push inventory hub: peers POST real NIC reports; scan overlays MAC/hostname ---
# Skip: Intune, MDM, SNMP switches, ONVIF cameras. Agents push out; this PC does not pull WMI.

$script:SshLanInventoryPort = 8766
$script:SshLanInventoryHub = $null

function Get-SshLanInventoryPath { Join-Path (Initialize-SshLanDataDirectory) 'inventory.json' }

function Get-SshLanInventoryToken {
    $cfg = Get-SshLanSettings
    if ("$($cfg.inventoryToken)" -match '^[0-9a-f]{32}$') { return [string]$cfg.inventoryToken }
    $token = New-SshLanInviteToken
    $path = Get-SshLanConfigPath
    $obj = if (Test-Path -LiteralPath $path) {
        Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    } else { [pscustomobject]@{} }
    Add-Member -InputObject $obj -NotePropertyName inventoryToken -NotePropertyValue $token -Force
    ($obj | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $path -Encoding UTF8
    return $token
}

function Test-SshLanInventoryBindIp([string]$Ip) {
    if (-not $Ip) { return $false }
    if ($Ip -eq '0.0.0.0' -or $Ip -eq '127.0.0.1') { return $false }
    if (Test-SshLanPrivateIp $Ip) { return $true }
    return [bool]($Ip -match '^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.')
}

function Get-SshLanInventoryBindAddresses {
    return @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { Test-SshLanInventoryBindIp $_.IPAddress } |
        ForEach-Object { [string]$_.IPAddress } | Select-Object -Unique)
}

function Resolve-SshLanInventoryRequest([string]$Method, [string]$Path, [string]$AuthHeader, [string]$Token) {
    $notFound = [pscustomobject]@{ Status = 'notfound' }
    if ($Method -ne 'POST') { return $notFound }
    if ($Path -ne '/inventory' -and $Path -ne '/inventory/') { return $notFound }
    if ($AuthHeader -notmatch '^[Bb]earer\s+(\S+)$') { return $notFound }
    if (-not [string]::Equals($Matches[1], $Token, [StringComparison]::Ordinal)) { return $notFound }
    return [pscustomobject]@{ Status = 'ok' }
}

function Test-SshLanInventoryReport($Raw) {
    if ($null -eq $Raw) { return $null }
    $id = [string]$Raw.deviceId
    if ($id -notmatch '^[0-9A-F]{2}(-[0-9A-F]{2}){5}$') { return $null }
    $hn = [string]$Raw.hostname
    if ($hn -notmatch '^[A-Za-z0-9]([A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') { return $null }
    $adapters = @($Raw.adapters)
    $okMac = $false
    foreach ($a in $adapters) {
        $mac = [string]$a.mac
        $media = [string]$a.media
        if ($media -notin 'wired', 'wifi') { continue }
        if ($mac -eq $id) { $okMac = $true; break }
    }
    if (-not $okMac) { return $null }
    return @{
        v = 1
        deviceId = $id
        hostname = $hn
        os = $(if ([string]$Raw.os) { [string]$Raw.os } else { 'Windows' })
        reportedAt = [string]$Raw.reportedAt
        source = 'agent'
        adapters = @(foreach ($a in $adapters) {
            @{
                name = [string]$a.name
                mac = [string]$a.mac
                media = [string]$a.media
                ips = @($a.ips | ForEach-Object { [string]$_ })
            }
        })
    }
}

function Read-SshLanInventoryStore {
    $path = Get-SshLanInventoryPath
    if (-not (Test-Path -LiteralPath $path)) { return @{} }
    try {
        $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        $h = @{}
        foreach ($p in @($raw.PSObject.Properties)) { $h[$p.Name] = $p.Value }
        return $h
    } catch { return @{} }
}

function Write-SshLanInventoryStore([hashtable]$Store) {
    $path = Get-SshLanInventoryPath
    $tmp = "$path.tmp"
    $obj = [ordered]@{}
    foreach ($k in @($Store.Keys | Sort-Object)) { $obj[$k] = $Store[$k] }
    ($obj | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $path -Force
}

function Merge-SshLanInventoryReport($Report, [datetime]$Now = (Get-Date)) {
    $parsed = Test-SshLanInventoryReport $Report
    if (-not $parsed) { throw 'bad inventory report' }
    $id = $parsed.deviceId
    $store = Read-SshLanInventoryStore
    $prev = $store[$id]
    if ($prev) {
        $old = [datetime]::MinValue
        [void][datetime]::TryParse([string]$prev.lastSeen, [ref]$old)
        if ($old -gt $Now) { return $prev }
    }
    $rec = [pscustomobject]@{
        v = 1
        deviceId = $id
        hostname = $parsed.hostname
        os = $parsed.os
        reportedAt = $parsed.reportedAt
        source = 'agent'
        adapters = $parsed.adapters
        lastSeen = $Now.ToString('o')
    }
    $store[$id] = $rec
    Write-SshLanInventoryStore $store
    return $rec
}

function Apply-SshLanInventoryToDevices([object[]]$Rows, [hashtable]$Store = $null, [datetime]$Now = (Get-Date)) {
    if ($null -eq $Store) { $Store = Read-SshLanInventoryStore }
    if (-not $Store.Count) { return @($Rows) }
    foreach ($r in @($Rows)) {
        if ("$($r.Note)" -eq 'เครื่องนี้') { continue }
        $ip = [string]$r.Ip
        $arp = [string]$r.Mac
        $byIp = $null
        $byMac = $null
        foreach ($rec in $Store.Values) {
            if (-not (Test-SshLanRecentlySeen ([string]$rec.lastSeen) $Now)) { continue }
            foreach ($a in @($rec.adapters)) {
                if ($a.media -notin 'wired', 'wifi') { continue }
                if ($ip -and (@($a.ips) -contains $ip)) {
                    $byIp = @{ Rec = $rec; Mac = [string]$a.mac }
                }
                if ($arp -and [string]$a.mac -eq $arp) {
                    $byMac = $rec
                }
            }
        }
        if ($byIp) {
            $r.Mac = $byIp.Mac
            if ($byIp.Rec.hostname) { $r.Name = [string]$byIp.Rec.hostname; $r.NameFrom = 'agent' }
            if ($byIp.Rec.os) { $r.Os = [string]$byIp.Rec.os }
            $bit = 'inventory agent'
            if ("$($r.Evidence)" -notmatch [regex]::Escape($bit)) {
                $r.Evidence = if ($r.Evidence) { "$($r.Evidence) | $bit" } else { $bit }
            }
            continue
        }
        if ($byMac -and $byMac.hostname) {
            $r.Name = [string]$byMac.hostname
            $r.NameFrom = 'agent'
            if ($byMac.os) { $r.Os = [string]$byMac.os }
        }
    }
    return @($Rows)
}

function Get-SshLanInventoryHubUrls([string[]]$BindIps, [int]$Port = 8766) {
    return @($BindIps | ForEach-Object { "http://${_}:$Port/inventory" })
}

# one request at a time per accepted socket; 5 s budget; body <= 16 KB
$script:SshLanInventoryLoop = {
    param($State, $HubPath, $AgentPath)
    . $HubPath
    if (Test-Path -LiteralPath $AgentPath) { . $AgentPath }
    function Send-Inv([Net.Sockets.NetworkStream]$S, [int]$Code, [string]$Body) {
        $reason = @{ 200 = 'OK'; 400 = 'Bad Request'; 404 = 'Not Found'; 413 = 'Payload Too Large' }[$Code]
        $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
        $head = "HTTP/1.1 $Code $reason`r`nContent-Type: text/plain; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
        $h = [Text.Encoding]::ASCII.GetBytes($head)
        $S.Write($h, 0, $h.Length)
        $S.Write($bytes, 0, $bytes.Length)
    }
    $utf8 = [Text.Encoding]::UTF8
    try {
        while (-not $State.Stop) {
            $client = $null
            foreach ($l in @($State.Listeners)) {
                if ($l.Pending()) { $client = $l.AcceptTcpClient(); break }
            }
            if (-not $client) { Start-Sleep -Milliseconds 50; continue }
            try {
                $client.SendTimeout = 5000
                $st = $client.GetStream()
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $budget = { $left = 5000 - $sw.ElapsedMilliseconds; if ($left -le 0) { throw 'too slow' }; $st.ReadTimeout = [int]$left }
                $buf = New-Object byte[] 20480
                $n = 0
                $end = -1
                while ($n -lt 8192) {
                    & $budget
                    $r = $st.Read($buf, $n, 8192 - $n)
                    if ($r -le 0) { break }
                    $n += $r
                    $end = [Text.Encoding]::ASCII.GetString($buf, 0, $n).IndexOf("`r`n`r`n")
                    if ($end -ge 0) { break }
                }
                if ($end -lt 0) { continue }
                $head = [Text.Encoding]::ASCII.GetString($buf, 0, $end)
                if ($head -notmatch '^(GET|POST) (\S+) HTTP/1\.[01]') { Send-Inv $st 404 'not found'; continue }
                $method = $Matches[1]
                $path = $Matches[2] -replace '\?.*$', ''
                $auth = ''
                if ($head -match '(?im)^Authorization:\s*(.+?)\r?$') { $auth = $Matches[1].Trim() }
                $req = Resolve-SshLanInventoryRequest $method $path $auth $State.Token
                if ($req.Status -ne 'ok') { Send-Inv $st 404 'not found'; continue }
                $len = if ($head -match '(?im)^Content-Length:\s*(\d+)') { [int64]$Matches[1] } else { 0 }
                if ($len -gt 16384) {
                    $left = [math]::Min($len, 65536) - ($n - ($end + 4))
                    $sink = New-Object byte[] 4096
                    while ($left -gt 0) { & $budget; $r = $st.Read($sink, 0, [int][math]::Min(4096, $left)); if ($r -le 0) { break }; $left -= $r }
                    Send-Inv $st 413 'too large'; continue
                }
                $got = $n - ($end + 4)
                while ($got -lt $len) {
                    & $budget
                    $r = $st.Read($buf, $n, [int]($len - $got))
                    if ($r -le 0) { break }
                    $n += $r
                    $got += $r
                }
                try { $raw = $utf8.GetString($buf, $end + 4, [int]$got) | ConvertFrom-Json } catch { $raw = $null }
                $parsed = Test-SshLanInventoryReport $raw
                if (-not $parsed) { Send-Inv $st 400 'bad json'; continue }
                [void](Merge-SshLanInventoryReport $parsed)
                Send-Inv $st 200 'ok'
            } catch {
            } finally { $client.Close() }
        }
    } finally {
        foreach ($l in @($State.Listeners)) { try { $l.Stop() } catch { } }
        $State.Done = $true
    }
}

function Start-SshLanInventoryHub {
    if ($script:SshLanInventoryHub) { return $script:SshLanInventoryHub }
    $binds = @(Get-SshLanInventoryBindAddresses)
    if (-not $binds.Count) { return $null }
    $token = Get-SshLanInventoryToken
    $port = 8766
    $listeners = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($ip in $binds) {
            $l = New-Object Net.Sockets.TcpListener ([Net.IPAddress]::Parse($ip), $port)
            $l.Start()
            $listeners.Add($l)
        }
    } catch {
        foreach ($l in $listeners) { try { $l.Stop() } catch { } }
        throw
    }
    try {
        Get-NetFirewallRule -Name sshlan-inventory -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -Name sshlan-inventory -DisplayName 'SSH LAN inventory' -Protocol TCP -LocalPort $port `
            -Action Allow -RemoteAddress LocalSubnet, '100.64.0.0/10' -Profile Any -ErrorAction Stop | Out-Null
    } catch {
        # non-admin: bind still limits who can connect if the OS allows the listen
    }
    # copy agent script into data dir for fleet install (runspace has no package root)
    $agentSrc = Join-Path $PSScriptRoot 'inventory-agent.ps1'
    $agentDst = Join-Path (Initialize-SshLanDataDirectory) 'inventory-agent.ps1'
    if (Test-Path -LiteralPath $agentSrc) { Copy-Item -LiteralPath $agentSrc -Destination $agentDst -Force }
    $state = [hashtable]::Synchronized(@{
        Listeners = $listeners.ToArray(); Token = $token; Stop = $false; Done = $false
    })
    $ps = [powershell]::Create()
    [void]$ps.AddScript($script:SshLanInventoryLoop).AddArgument($state).AddArgument((Join-Path $PSScriptRoot 'inventory.ps1')).AddArgument($agentDst)
    $handle = $ps.BeginInvoke()
    $script:SshLanInventoryHub = [pscustomobject]@{
        Token = $token; Port = $port; Urls = @(Get-SshLanInventoryHubUrls $binds $port)
        State = $state; Ps = $ps; Handle = $handle
    }
    return $script:SshLanInventoryHub
}

function Stop-SshLanInventoryHub {
    $hub = $script:SshLanInventoryHub
    if (-not $hub) { return }
    try { $hub.State.Stop = $true } catch { }
    $deadline = (Get-Date).AddSeconds(3)
    while (-not $hub.State.Done -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 50 }
    foreach ($l in @($hub.State.Listeners)) { try { $l.Stop() } catch { } }
    try { $hub.Ps.Dispose() } catch { }
    Get-NetFirewallRule -Name sshlan-inventory -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $script:SshLanInventoryHub = $null
}

function Write-SshLanInventoryAgentConfig([string]$Path, [string[]]$Hubs, [string]$Token) {
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    (@{ hubs = @($Hubs); token = $Token } | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Install-SshLanInventoryAgent([string]$Alias, [string]$Token = '', [string[]]$Urls = @()) {
    if ($Alias -notmatch '^[A-Za-z0-9._-]+$') { throw "alias ไม่ถูกต้อง: $Alias" }
    if (-not $Token) { $Token = Get-SshLanInventoryToken }
    if (-not @($Urls).Count) { $Urls = @(Get-SshLanInventoryHubUrls (Get-SshLanInventoryBindAddresses)) }
    if (-not @($Urls).Count) { throw 'ไม่มี hub URL (LAN/Tailscale)' }
    $agentFile = Join-Path (Get-SshLanDataDirectory) 'inventory-agent.ps1'
    if (-not (Test-Path -LiteralPath $agentFile)) {
        $src = Join-Path $PSScriptRoot 'inventory-agent.ps1'
        if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $agentFile -Force }
    }
    if (-not (Test-Path -LiteralPath $agentFile)) { throw 'ไม่มี inventory-agent.ps1 ใน data dir' }
    $agentText = Get-Content -LiteralPath $agentFile -Raw -Encoding UTF8
    $commonHint = 'Ssh-Lan-Prime-Studio'
    $b64Agent = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($agentText))
    $cfgJson = (@{ hubs = @($Urls); token = $Token } | ConvertTo-Json -Compress)
    $b64Cfg = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($cfgJson))
    $remote = @"
`$ErrorActionPreference='Stop'
`$dir=Join-Path `$env:LOCALAPPDATA '$commonHint'
New-Item -ItemType Directory -Force -Path `$dir | Out-Null
[IO.File]::WriteAllBytes((Join-Path `$dir 'inventory-agent.ps1'), [Convert]::FromBase64String('$b64Agent'))
[IO.File]::WriteAllBytes((Join-Path `$dir 'inventory-agent.json'), [Convert]::FromBase64String('$b64Cfg'))
`$push=Join-Path `$dir 'push-inventory.ps1'
Set-Content -LiteralPath `$push -Encoding UTF8 -Value @'
. (Join-Path `$env:LOCALAPPDATA '$commonHint\inventory-agent.ps1')
try { Send-SshLanAgentReport | Out-Null } catch {}
'@
`$exe=Join-Path `$env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
`$arg="-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ``"`$push``""
Unregister-ScheduledTask -TaskName 'SSH LAN inventory push' -Confirm:`$false -ErrorAction SilentlyContinue
`$a=New-ScheduledTaskAction -Execute `$exe -Argument `$arg
`$t1=New-ScheduledTaskTrigger -AtLogOn
`$t2=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration ([TimeSpan]::MaxValue)
Register-ScheduledTask -TaskName 'SSH LAN inventory push' -Action `$a -Trigger @(`$t1,`$t2) -Force | Out-Null
& `$exe -NoProfile -ExecutionPolicy Bypass -File `$push
'installed'
"@
    $out = Invoke-SshLanSshCapture @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=12', $Alias, $remote) '' 60
    if ("$out" -notmatch 'installed') { throw "install on $Alias failed: $out" }
    return $Alias
}

function Install-SshLanInventoryAgents {
    $map = Get-SshLanPairedHosts
    $targets = @($map.Values)
    if (-not $targets.Count) { return @() }
    $agentSrc = Join-Path $PSScriptRoot 'inventory-agent.ps1'
    $agentDst = Join-Path (Get-SshLanDataDirectory) 'inventory-agent.ps1'
    if (Test-Path -LiteralPath $agentSrc) { Copy-Item -LiteralPath $agentSrc -Destination $agentDst -Force }
    # fleet reparses the scriptblock: Install re-reads token + hub URLs itself (no closed-over locals)
    return @(Invoke-SshLanFleet $targets {
        param($t)
        try {
            $alias = [string]$t.Alias
            Install-SshLanInventoryAgent $alias
            [pscustomobject]@{ Alias = $alias; Ok = $true; Detail = 'installed' }
        } catch {
            [pscustomobject]@{ Alias = [string]$t.Alias; Ok = $false; Detail = $_.Exception.Message }
        }
    } -Throttle 4 -TimeoutSec 90 | ForEach-Object { $_.Result })
}
