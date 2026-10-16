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