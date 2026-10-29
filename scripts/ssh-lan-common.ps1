function Get-SshLanDataDirectory {
    if ($env:SSH_LAN_DATA_DIR) { return [IO.Path]::GetFullPath($env:SSH_LAN_DATA_DIR) }
    return Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Ssh-Lan-Prime-Studio'
}

function Get-SshLanPackageRoot {
    # scripts\ssh-lan-common.ps1 → package root
    return (Split-Path -Parent $PSScriptRoot)
}

function Get-SshLanConfigPath {
    Join-Path (Get-SshLanDataDirectory) 'config.json'
}

function Initialize-SshLanDataDirectory {
    $dir = Get-SshLanDataDirectory
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    return $dir
}

function Get-SshLanSettings {
    $defaults = [ordered]@{
        hostAlias      = 'ssh-lan'
        identityFile   = 'id_ed25519_lan'
        serverUser     = $env:USERNAME
        serverHost     = ''
        serverIpSearch = @()
    }
    Initialize-SshLanDataDirectory | Out-Null
    $path = Get-SshLanConfigPath
    if (-not (Test-Path -LiteralPath $path)) {
        ($defaults | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $path -Encoding UTF8
        return [pscustomobject]$defaults
    }
    try {
        $saved = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($key in $defaults.Keys) {
            if ($null -eq $saved.$key) {
                Add-Member -InputObject $saved -NotePropertyName $key -NotePropertyValue $defaults[$key] -Force
            }
        }
        return $saved
    } catch {
        return [pscustomobject]$defaults
    }
}

function Get-SshLanMainScript {
    Join-Path $PSScriptRoot 'ssh-lan\ssh-lan.ps1'
}

function Start-SshLanPowerShell {
    param(
        [string[]]$ArgumentList,
        [switch]$Elevated,
        [switch]$Wait
    )
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass') + $ArgumentList
    if ($Elevated) {
        $proc = Start-Process -FilePath $exe -Verb RunAs -ArgumentList $args -PassThru -Wait:$(if ($Wait) { $true } else { $false })
        return $proc
    }
    return Start-Process -FilePath $exe -ArgumentList $args -PassThru -Wait:$(if ($Wait) { $true } else { $false })
}

function Get-SshLanVersion {
    $file = Join-Path (Get-SshLanPackageRoot) 'VERSION'
    if (Test-Path -LiteralPath $file) { return (Get-Content -LiteralPath $file -TotalCount 1).Trim() }
    return 'dev'
}

# RFC 1918 ranges: 10.x, 172.16-31.x, 192.168.x
function Test-SshLanPrivateIp([string]$Ip) {
    return [bool]($Ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)')
}

# network address of an IPv4 address and prefix length, as CIDR
function ConvertTo-SshLanCidr([string]$Ip, [int]$Prefix) {
    $b = [Net.IPAddress]::Parse($Ip).GetAddressBytes()
    [Array]::Reverse($b)
    $mask = [uint32](([uint64]4294967295 -shl (32 - $Prefix)) -band [uint64]4294967295)
    $net = [BitConverter]::GetBytes([uint32]([BitConverter]::ToUInt32($b, 0) -band $mask))
    [Array]::Reverse($net)
    return "$(([Net.IPAddress]::new($net)).IPAddressToString)/$Prefix"
}

function Get-SshLanLocalCidr {
    $ip = Get-SshLanPrimaryLanIp
    if (-not $ip) { return $null }
    $a = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $ip -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($a) { return ConvertTo-SshLanCidr $ip $a.PrefixLength }
}

# "50" or "192.168.1.50" -> a full address on this PC's LAN; refuses the router, the network and broadcast addresses, other subnets
function Resolve-SshLanLanIp([string]$Ip, [string]$Current, [int]$Prefix, [string]$Gateway) {
    $Ip = "$Ip".Trim()
    if ($Ip -match '^\d{1,3}$') { $Ip = (($Current -split '\.')[0..2] -join '.') + ".$Ip" }
    $addr = $null
    if ($Ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or -not [Net.IPAddress]::TryParse($Ip, [ref]$addr)) { throw "รูปแบบเลข IP ไม่ถูกต้อง: $Ip" }
    $toInt = { param($a) $b = ([Net.IPAddress]$a).GetAddressBytes(); [Array]::Reverse($b); [BitConverter]::ToUInt32($b, 0) }
    $all = [uint64]4294967295
    $mask = [uint32](($all -shl (32 - $Prefix)) -band $all)
    $hostMask = [uint32]($all - $mask)
    if (((& $toInt $Ip) -band $mask) -ne ((& $toInt $Current) -band $mask)) { throw "$Ip ไม่อยู่ในวง LAN เดียวกับเครื่องนี้ ($Current/$Prefix)" }
    $h = (& $toInt $Ip) -band $hostMask
    if ($h -eq 0 -or $h -eq $hostMask) { throw "$Ip เป็นเลขของวง LAN เอง (ใช้ไม่ได้)" }
    if ($Ip -eq $Gateway) { throw "$Ip เป็นเลขของเราเตอร์" }
    return $Ip
}

# the fixed address plus temporary extra addresses that only answer (machines that still dial an old address keep working)
function Get-SshLanIpPlan([string]$New, [string[]]$Extra, [string]$Current, [int]$Prefix, [string]$Gateway) {
    $primary = Resolve-SshLanLanIp $New $Current $Prefix $Gateway
    $extras = New-Object System.Collections.Generic.List[string]
    foreach ($e in @($Extra | Where-Object { "$_".Trim() })) {
        $ip = Resolve-SshLanLanIp $e $Current $Prefix $Gateway
        if ($ip -ne $primary -and -not $extras.Contains($ip)) { $extras.Add($ip) }
    }
    return @{ Primary = $primary; Extras = $extras.ToArray() }
}

# "this PC" on the LAN: never a temporary extra address (SkipAsSource) when the card has a real one, and a LAN card before virtual ones
function Select-SshLanPrimaryIp([object[]]$Candidates) {
    $c = @($Candidates | Where-Object { $_ })
    if (-not $c) { return $null }
    $virtual = 'vEthernet|WSL|Hyper-V|VirtualBox|VMware|Tailscale|Bluetooth'
    $lanCard = { param($x) "$($x.InterfaceAlias)" -match 'Ethernet|Wi-Fi|WiFi|อีเทอร์|以太' -and "$($x.InterfaceAlias)" -notmatch $virtual }
    foreach ($pick in @(
            { param($x) (& $lanCard $x) -and -not $x.SkipAsSource },
            { param($x) -not $x.SkipAsSource -and "$($x.InterfaceAlias)" -notmatch $virtual },
            { param($x) & $lanCard $x },
            { param($x) $true })) {
        $hit = @($c | Where-Object { & $pick $_ })[0]
        if ($hit) { return [string]$hit.IPAddress }
    }
}

# temporary extra addresses on this PC (added with SkipAsSource by set-lan-ip.ps1 -Extra)
function Get-SshLanExtraIps {
    return @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.SkipAsSource -and (Test-SshLanPrivateIp $_.IPAddress) } | ForEach-Object { $_.IPAddress })
}
