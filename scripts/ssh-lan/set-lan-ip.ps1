#Requires -RunAsAdministrator
# Pin this PC's LAN address to an IP you choose, or hand it back to DHCP.
#   set-lan-ip.ps1 -Ip 192.0.2.50   (full address)
#   set-lan-ip.ps1 -Ip 50             (last number only, keeps the current subnet)
#   set-lan-ip.ps1 -Dhcp              (automatic address again)
param(
    [string]$Ip,
    [switch]$Dhcp
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\ssh-lan-common.ps1')

function ConvertTo-UInt32([Net.IPAddress]$Address) {
    $b = $Address.GetAddressBytes(); [Array]::Reverse($b); [BitConverter]::ToUInt32($b, 0)
}

# the adapter that currently holds the home-LAN address
$cfg = Get-NetIPConfiguration |
    Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4DefaultGateway -and (Test-SshLanPrivateIp $_.IPv4Address.IPAddress) } |
    Select-Object -First 1
if (-not $cfg) { throw 'ไม่พบการ์ดเครือข่ายที่เชื่อมต่อ LAN ในบ้านอยู่' }

$alias = $cfg.InterfaceAlias
$current = $cfg.IPv4Address.IPAddress
$prefix = $cfg.IPv4Address.PrefixLength
$gateway = $cfg.IPv4DefaultGateway.NextHop
$dns = @($cfg.DNSServer.ServerAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
if ($dns.Count -eq 0) { $dns = @($gateway) }
Write-Host "การ์ด: $alias (ปัจจุบัน $current/$prefix, เกตเวย์ $gateway)"

if ($Dhcp) {
    Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -PrefixOrigin Manual -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false
    Get-NetRoute -InterfaceAlias $alias -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Remove-NetRoute -Confirm:$false
    Set-NetIPInterface -InterfaceAlias $alias -Dhcp Enabled
    Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses
    Restart-NetAdapter -Name $alias
    Write-Host 'คืนเป็นเลข IP อัตโนมัติ (DHCP) แล้ว — รอสักครู่ให้เราเตอร์แจกเลขใหม่'
    return
}

if (-not $Ip) { throw 'ยังไม่ได้ระบุเลข IP' }
$Ip = $Ip.Trim()
if ($Ip -match '^\d{1,3}$') { $Ip = (($current -split '\.')[0..2] -join '.') + ".$Ip" }
$addr = $null
if ($Ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or -not [Net.IPAddress]::TryParse($Ip, [ref]$addr)) { throw "รูปแบบเลข IP ไม่ถูกต้อง: $Ip" }

$all = [uint64]4294967295
$mask = [uint32](($all -shl (32 - $prefix)) -band $all)
$hostMask = [uint32]($all - $mask)
$net = (ConvertTo-UInt32 $addr) -band $mask
if ($net -ne ((ConvertTo-UInt32 ([Net.IPAddress]$current)) -band $mask)) { throw "$Ip ไม่อยู่ในวง LAN เดียวกับเครื่องนี้ ($current/$prefix)" }
$host_ = (ConvertTo-UInt32 $addr) -band $hostMask
if ($host_ -eq 0 -or $host_ -eq $hostMask) { throw "$Ip เป็นเลขของวง LAN เอง (ใช้ไม่ได้)" }
if ($Ip -eq $gateway) { throw "$Ip เป็นเลขของเราเตอร์" }

if ($Ip -eq $current -and $cfg.NetIPv4Interface.Dhcp -eq 'Disabled') { Write-Host "เครื่องนี้ใช้ $Ip แบบคงที่อยู่แล้ว"; return }

# is somebody else already using it? (ping fills the ARP table even when ICMP is blocked)
if ($Ip -ne $current) {
    $null = Test-Connection -ComputerName $Ip -Count 2 -Quiet -ErrorAction SilentlyContinue
    $mac = $cfg.NetAdapter.MacAddress
    $owner = Get-NetNeighbor -IPAddress $Ip -State Reachable, Stale, Permanent -ErrorAction SilentlyContinue |
        Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -ne $mac } | Select-Object -First 1
    if ($owner) { throw "$Ip มีเครื่องอื่นใช้อยู่แล้ว (MAC $($owner.LinkLayerAddress)) — เลือกเลขอื่น" }
}

try {
    Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false
    Get-NetRoute -InterfaceAlias $alias -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Remove-NetRoute -Confirm:$false
    Set-NetIPInterface -InterfaceAlias $alias -Dhcp Disabled
    New-NetIPAddress -InterfaceAlias $alias -IPAddress $Ip -PrefixLength $prefix -DefaultGateway $gateway | Out-Null
    Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $dns
} catch {
    # never leave the PC without an address
    Set-NetIPInterface -InterfaceAlias $alias -Dhcp Enabled -ErrorAction SilentlyContinue
    throw
}

Write-Host "ตั้งเลข IP คงที่ = $Ip/$prefix, เกตเวย์ = $gateway เรียบร้อย"
Write-Host 'เคล็ดลับ: เลือกเลขที่อยู่นอกช่วงที่เราเตอร์แจกอัตโนมัติ เพื่อไม่ให้ชนกับเครื่องอื่นในอนาคต'
