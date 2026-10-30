# --- inventory agent (peer): collect real NIC report; POST only when Send-SshLanAgentReport runs ---
# Skip: Intune, MDM, SNMP, ONVIF. This file is the only collector.

$script:SshLanVirtualNic = 'vEthernet|WSL|Hyper-V|VirtualBox|VMware|Tailscale|Bluetooth|WireGuard|WinTUN'

function Format-SshLanMacBytes([string]$Hex) {
    $Hex = ("$Hex" -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($Hex.Length -ne 12) { return '' }
    return ($Hex -replace '..(?!$)', '$&-')
}

function Test-SshLanVirtualNicName([string]$Name, [string]$Desc) {
    return [bool](("$Name $Desc") -match $script:SshLanVirtualNic)
}

function Get-SshLanRealAdapters {
    $out = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($n in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            $type = "$($n.NetworkInterfaceType)"
            if ($type -notin 'Ethernet', 'Wireless80211') { continue }
            if (Test-SshLanVirtualNicName $n.Name $n.Description) { continue }
            $mac = Format-SshLanMacBytes ($n.GetPhysicalAddress().ToString())
            if (-not $mac -or $mac -eq '00-00-00-00-00-00') { continue }
            $ips = @($n.GetIPProperties().UnicastAddresses |
                Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } |
                ForEach-Object { $_.Address.ToString() })
            $media = if ($type -eq 'Wireless80211') { 'wifi' } else { 'wired' }
            $out.Add(@{
                name = [string]$n.Name
                mac = $mac
                media = $media
                ips = @($ips)
            })
        }
    } catch { }
    return @($out)
}

function Get-SshLanAgentDeviceId([object[]]$Adapters) {
    $cands = @($Adapters | Where-Object { $_.media -in 'wired', 'wifi' -and $_.mac })
    $wired = @($cands | Where-Object { $_.media -eq 'wired' } | Sort-Object { $_.mac })
    if ($wired.Count) { return [string]$wired[0].mac }
    $wifi = @($cands | Where-Object { $_.media -eq 'wifi' } | Sort-Object { $_.mac })
    if ($wifi.Count) { return [string]$wifi[0].mac }
    return ''
}

function New-SshLanAgentReport {
    $adapters = @(Get-SshLanRealAdapters)
    $id = Get-SshLanAgentDeviceId $adapters
    if (-not $id) { throw 'no physical NIC MAC for deviceId' }
    return @{
        v = 1
        deviceId = $id
        hostname = $env:COMPUTERNAME
        os = 'Windows'
        reportedAt = (Get-Date).ToString('o')
        source = 'agent'
        adapters = $adapters
    }
}

function Get-SshLanAgentDataDir {
    $d = Join-Path $env:LOCALAPPDATA 'Ssh-Lan-Prime-Studio'
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
    return $d
}

function Get-SshLanAgentConfigPath {
    Join-Path (Get-SshLanAgentDataDir) 'inventory-agent.json'
}

function Send-SshLanAgentReport {
    $cfgPath = Get-SshLanAgentConfigPath
    if (-not (Test-Path -LiteralPath $cfgPath)) { throw "ไม่มี $cfgPath" }
    $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $token = [string]$cfg.token
    $hubs = @($cfg.hubs | ForEach-Object { [string]$_ } | Where-Object { $_ })
    if (-not $token -or -not $hubs.Count) { throw 'inventory-agent.json ต้องมี token และ hubs' }
    $body = (New-SshLanAgentReport | ConvertTo-Json -Depth 6 -Compress)
    if ([Text.Encoding]::UTF8.GetByteCount($body) -gt 16384) { throw 'report too large' }
    $last = $null
    foreach ($url in $hubs) {
        try {
            $resp = Invoke-WebRequest -Uri $url -Method POST -Body $body -ContentType 'application/json; charset=utf-8' `
                -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 5 -UseBasicParsing
            if ([int]$resp.StatusCode -eq 200) { return $true }
            $last = "HTTP $($resp.StatusCode)"
        } catch {
            $last = $_.Exception.Message
        }
    }
    throw "push failed: $last"
}
