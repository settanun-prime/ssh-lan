# --- router and internet: what the router forwards in (UPnP IGD) and whether the outside can reach in ---
# Anything the router does not answer stays $null. Delete and add go through the two mapping functions below.

$script:SshLanSsdpGroup = '239.255.255.250'

# SSDP M-SEARCH for an Internet Gateway Device; returns the URL of its description XML or $null
function Find-SshLanIgd([int]$TimeoutMs = 2000) {
    $msg = "M-SEARCH * HTTP/1.1`r`nHOST: $($script:SshLanSsdpGroup):1900`r`nMAN: `"ssdp:discover`"`r`nMX: 1`r`nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1`r`n`r`n"
    $bytes = [Text.Encoding]::ASCII.GetBytes($msg)
    $u = New-Object Net.Sockets.UdpClient
    try {
        [void]$u.Send($bytes, $bytes.Length, $script:SshLanSsdpGroup, 1900)
        $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
        while ($true) {
            $left = [int]($deadline - (Get-Date)).TotalMilliseconds
            if ($left -le 0) { break }
            $u.Client.ReceiveTimeout = [Math]::Max(50, $left)
            $from = New-Object Net.IPEndPoint ([Net.IPAddress]::Any), 0
            try { $data = $u.Receive([ref]$from) } catch { break }
            $text = [Text.Encoding]::ASCII.GetString($data)
            if ($text -match '(?im)^LOCATION:\s*(\S+)') { return $Matches[1] }
        }
        return $null
    } catch { return $null } finally { $u.Close() }
}

# the WAN connection service in a description XML: @{ url; service } or $null
function Get-SshLanIgdControl([string]$DescXml, [string]$BaseUrl) {
    try { $x = [xml]$DescXml } catch { return $null }
    $base = if ($x.root.URLBase) { [string]$x.root.URLBase } else { $BaseUrl }
    $services = @($x.GetElementsByTagName('service'))
    foreach ($want in 'WANIPConnection:2', 'WANIPConnection:1', 'WANPPPConnection:1') {
        $s = $services | Where-Object { "$($_.serviceType)".Trim() -eq "urn:schemas-upnp-org:service:$want" } | Select-Object -First 1
        if ($s -and $s.controlURL) {
            try { $url = [string](New-Object Uri ([Uri]$base), ([string]$s.controlURL).Trim()) } catch { return $null }
            return @{ url = $url; service = "urn:schemas-upnp-org:service:$want" }
        }
    }
    return $null
}

# Invoke-WebRequest hands back bytes, not text, when a router omits a text Content-Type
function ConvertFrom-SshLanWebContent($Response) {
    if ($Response.Content -is [byte[]]) { return [Text.Encoding]::UTF8.GetString($Response.Content) }
    return [string]$Response.Content
}

# a SOAP caller bound to one control URL: & $soap 'Action' @{ Arg = 'v' } -> hashtable of the response fields; throws on a fault
function New-SshLanIgdSoap([hashtable]$Control, [int]$TimeoutSec = 5) {
    $url = $Control.url; $service = $Control.service
    return {
        param([string]$Action, [hashtable]$Arguments)
        $inner = (@($Arguments.Keys) | ForEach-Object { "<$_>$([Security.SecurityElement]::Escape([string]$Arguments[$_]))</$_>" }) -join ''
        $body = "<?xml version=`"1.0`"?><s:Envelope xmlns:s=`"http://schemas.xmlsoap.org/soap/envelope/`" s:encodingStyle=`"http://schemas.xmlsoap.org/soap/encoding/`">" +
                "<s:Body><u:$Action xmlns:u=`"$service`">$inner</u:$Action></s:Body></s:Envelope>"
        $resp = Invoke-WebRequest $url -Method Post -UseBasicParsing -TimeoutSec $TimeoutSec -Body $body -ContentType 'text/xml; charset="utf-8"' -Headers @{ SOAPAction = "`"$service#$Action`"" }
        $x = [xml](ConvertFrom-SshLanWebContent $resp)
        $node = @($x.GetElementsByTagName('*') | Where-Object { $_.LocalName -eq "${Action}Response" })[0]
        if (-not $node) { throw "SOAP $Action ไม่มีคำตอบ" }
        $h = @{}
        foreach ($c in $node.ChildNodes) { $h[$c.LocalName] = $c.InnerText }
        return $h
    }.GetNewClosure()
}

# an empty answer is success; a fault is $false so the caller records nothing
function Remove-SshLanIgdMapping([scriptblock]$Soap, [int]$External, [string]$Protocol) {
    if (-not $Soap) { return $false }
    try {
        & $Soap 'DeletePortMapping' @{ NewRemoteHost = ''; NewExternalPort = $External; NewProtocol = $Protocol }
        return $true
    } catch { return $false }
}

# the stored mapping (external, internalClient, internalPort, protocol, description) goes back as AddPortMapping
function Add-SshLanIgdMapping([scriptblock]$Soap, $Mapping) {
    if (-not $Soap -or $null -eq $Mapping) { return $false }
    $external = 0
    $internal = 0
    $ext = $Mapping.external
    $inn = $Mapping.internalPort
    if ("$ext" -match '^\d+$') { $external = [int]$ext }
    if ("$inn" -match '^\d+$') { $internal = [int]$inn }
    $protocol = [string]$Mapping.protocol
    $client = [string]$Mapping.internalClient
    if ($external -lt 1 -or $internal -lt 1 -or -not $protocol -or -not $client) { return $false }
    try {
        & $Soap 'AddPortMapping' @{
            NewRemoteHost = ''
            NewExternalPort = $external
            NewProtocol = $protocol
            NewInternalPort = $internal
            NewInternalClient = $client
            NewEnabled = 1
            NewPortMappingDescription = [string]$Mapping.description
            NewLeaseDuration = 0
        }
        return $true
    } catch { return $false }
}

function Get-SshLanIgdExternalIp([scriptblock]$Soap) {
    try { $ip = [string](& $Soap 'GetExternalIPAddress' @{}).NewExternalIPAddress } catch { return $null }
    if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') { return $ip }
    return $null
}

# $Entry = { param($i) ... } gives mapping $i as @{ external; internalClient; internalPort; protocol; description } and throws past the last one
function Get-SshLanIgdMappings([scriptblock]$Entry, [int]$Max = 64) {
    $out = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $Max; $i++) {
        try { $m = & $Entry $i } catch { break }
        if (-not $m) { break }
        $out.Add($m)
    }
    return , $out.ToArray()
}

# private, CGNAT (100.64/10) or link-local: not reachable from the internet as is
function Test-SshLanNonPublicIp([string]$Ip) {
    return [bool]($Ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|169\.254\.)')
}

# CGNAT and the ports reachable from the internet, from what the router and the outside probe said
function Get-SshLanInternetExposure([string]$WanIp, [string]$PublicIp, [object[]]$Mappings, [object[]]$Probe) {
    $ev = New-Object System.Collections.Generic.List[string]
    $cgnat = $null
    if ($WanIp -and (Test-SshLanNonPublicIp $WanIp)) { $cgnat = $true; $ev.Add("WAN ของเราเตอร์เป็น IP ภายใน ($WanIp): อยู่หลัง CGNAT ของผู้ให้บริการ") }
    elseif ($WanIp -and $PublicIp) {
        $cgnat = $WanIp -ne $PublicIp
        $ev.Add($(if ($cgnat) { "WAN $WanIp ไม่ตรงกับ IP ที่โลกเห็น ($PublicIp): มี NAT อีกชั้น" } else { "WAN $WanIp ตรงกับ IP ที่โลกเห็น: port forward เข้าจากอินเทอร์เน็ตได้" }))
    } else { $ev.Add('ไม่ทราบ IP ฝั่ง WAN หรือ IP ที่โลกเห็น') }
    $ports = New-Object System.Collections.Generic.List[object]
    foreach ($m in @($Mappings) | Where-Object { $_ -and "$($_.protocol)" -ne 'UDP' }) {
        if ($cgnat -eq $true) { $ev.Add("UPnP forward พอร์ต $($m.external) ไป $($m.internalClient) แต่ CGNAT กั้นไว้ก่อน"); continue }
        $ports.Add(@{ port = [int]$m.external; target = [string]$m.internalClient; internalPort = [int]$m.internalPort; via = 'upnp'; description = [string]$m.description })
    }
    foreach ($p in @($Probe) | Where-Object { $_ -and $_.open }) {
        if (@($ports | Where-Object { $_.port -eq [int]$p.port })) { continue }
        $ports.Add(@{ port = [int]$p.port; target = [string]$p.target; via = 'probe' })
    }
    return @{ cgnat = $cgnat; internetPorts = $ports.ToArray(); evidence = $ev.ToArray() }
}

function Get-SshLanTailscaleExe {
    $c = Get-Command tailscale.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    $p = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
    if (Test-Path -LiteralPath $p) { return $p }
    return $null
}

# the address the internet sees, from Tailscale's own STUN check; never asks a third-party "what is my IP" site
function Get-SshLanPublicIp {
    $ts = Get-SshLanTailscaleExe
    if (-not $ts) { return $null }
    $ErrorActionPreference = 'Continue'
    $out = (& $ts netcheck 2>$null | Out-String)
    if ($out -match 'IPv4:\s*yes,\s*(\d{1,3}(?:\.\d{1,3}){3}):\d+') { return $Matches[1] }
    return $null
}

# Android devices in the tailnet that offer to be an exit node (a phone on mobile data sees this network from outside)
function Get-SshLanExitNodeCandidates {
    $ts = Get-SshLanTailscaleExe
    if (-not $ts) { return @() }
    $ErrorActionPreference = 'Continue'
    try { $st = (& $ts status --json 2>$null | Out-String) | ConvertFrom-Json } catch { return @() }
    if (-not $st.Peer) { return @() }
    return @(foreach ($p in $st.Peer.PSObject.Properties.Value) {
        if ("$($p.OS)" -eq 'android' -and $p.ExitNodeOption -and $p.Online) { [string]($p.DNSName -split '\.')[0] }
    })
}

# reach our own public IP from outside: route through a Tailscale exit node and knock each port.
# The exit node setting is put back in finally, whatever happens
function Invoke-SshLanExitNodeProbe([string]$ExitNode, [string]$PublicIp, [int[]]$Ports, [scriptblock]$Tailscale, [scriptblock]$Knock, [int]$SettleMs = 2000) {
    if ($ExitNode -notmatch '^[A-Za-z0-9._-]+$') { throw "ชื่อ exit node ไม่ถูกต้อง: $ExitNode" }
    if (-not $Tailscale) {
        $exe = Get-SshLanTailscaleExe
        if (-not $exe) { throw 'ไม่พบ Tailscale บนเครื่องนี้' }
        $Tailscale = { & $exe @args 2>&1 | Out-Null }.GetNewClosure()
    }
    if (-not $Knock) { $Knock = { param($ip, $port) Test-SshLanPort $ip $port 3000 } }
    try {
        & $Tailscale set "--exit-node=$ExitNode"
        if ($SettleMs -gt 0) { Start-Sleep -Milliseconds $SettleMs }
        return @(foreach ($p in $Ports) { @{ port = $p; open = [bool](& $Knock $PublicIp $p) } })
    } finally {
        & $Tailscale set '--exit-node='
    }
}

# everything the router says in one go, within about 5 s: @{ upnp; wanIp; mappings; evidence }
function Get-SshLanRouterFacts([int]$BudgetSec = 5) {
    $t0 = Get-Date
    $none = { param($why) @{ upnp = $null; wanIp = $null; mappings = @(); evidence = $why } }
    $loc = Find-SshLanIgd 1500
    if (-not $loc) { return (& $none 'เราเตอร์ไม่ตอบ UPnP (ปิดอยู่ หรือไม่รองรับ)') }
    try { $desc = ConvertFrom-SshLanWebContent (Invoke-WebRequest $loc -UseBasicParsing -TimeoutSec 3) } catch { return (& $none "อ่าน $loc ไม่ได้") }
    $ctl = Get-SshLanIgdControl ([string]$desc) $loc
    if (-not $ctl) { return (& $none "$loc ไม่มีบริการ WAN") }
    $soap = New-SshLanIgdSoap $ctl 3
    $wan = Get-SshLanIgdExternalIp $soap
    $maps = Get-SshLanIgdMappings {
        param($i)
        if (((Get-Date) - $t0).TotalSeconds -gt $BudgetSec) { throw 'budget' }
        $r = & $soap 'GetGenericPortMappingEntry' @{ NewPortMappingIndex = $i }
        @{ external = [int]$r.NewExternalPort; internalClient = [string]$r.NewInternalClient; internalPort = [int]$r.NewInternalPort
           protocol = [string]$r.NewProtocol; description = [string]$r.NewPortMappingDescription }
    }
    return @{ upnp = $true; wanIp = $wan; mappings = $maps; evidence = "UPnP IGD ที่ $loc ($($ctl.service -replace '^urn:schemas-upnp-org:service:', ''))" }
}
