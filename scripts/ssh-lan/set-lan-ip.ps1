#Requires -RunAsAdministrator
# Pin this PC's LAN address to an IP you choose, or hand it back to DHCP.
#   set-lan-ip.ps1 -Ip 192.0.2.50   (full address)
#   set-lan-ip.ps1 -Ip 50             (last number only, keeps the current subnet)
#   set-lan-ip.ps1 -Dhcp              (automatic address again)
#   set-lan-ip.ps1 -Ip 100 -Extra 46  (fixed .100, and .46 kept answering for machines that still dial it)
#   set-lan-ip.ps1 -RemoveExtra       (drop the temporary extra addresses, the fixed one stays)
param(
    [string]$Ip,
    [string[]]$Extra = @(),
    [switch]$Dhcp,
    [switch]$RemoveExtra
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\ssh-lan-common.ps1')

# the adapter that currently holds the home-LAN address
$cfg = Get-NetIPConfiguration |
    Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4DefaultGateway -and (Test-SshLanPrivateIp $_.IPv4Address.IPAddress) } |
    Select-Object -First 1
if (-not $cfg) { throw 'ไม่พบการ์ดเครือข่ายที่เชื่อมต่อ LAN ในบ้านอยู่' }

$alias = $cfg.InterfaceAlias
# with extra addresses on the card IPv4Address is a list: the real one is the address that is not SkipAsSource
$main = @($cfg.IPv4Address | Where-Object { -not $_.SkipAsSource })[0]
if (-not $main) { $main = @($cfg.IPv4Address)[0] }
$current = $main.IPAddress
$prefix = $main.PrefixLength
$extrasNow = @($cfg.IPv4Address | Where-Object { $_.SkipAsSource } | ForEach-Object { $_.IPAddress })
$gateway = $cfg.IPv4DefaultGateway.NextHop
$dns = @($cfg.DNSServer.ServerAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
if ($dns.Count -eq 0) { $dns = @($gateway) }
Write-Host "การ์ด: $alias (ปัจจุบัน $current/$prefix, เกตเวย์ $gateway)"

if ($RemoveExtra) {
    if (-not $extrasNow) { Write-Host 'ไม่มี IP ชั่วคราวให้เอาออก'; return }
    foreach ($e in $extrasNow) { Remove-NetIPAddress -InterfaceAlias $alias -IPAddress $e -Confirm:$false }
    Write-Host "เอา IP ชั่วคราวออกแล้ว: $($extrasNow -join ', ') — เครื่องนี้ใช้ $current อย่างเดียว"
    return
}

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
$plan = Get-SshLanIpPlan $Ip $Extra $current $prefix $gateway
$Ip = $plan.Primary
$static = $cfg.NetIPv4Interface.Dhcp -eq 'Disabled'

# is somebody else already using it? (ping fills the ARP table even when ICMP is blocked)
$mac = $cfg.NetAdapter.MacAddress
foreach ($want in @($Ip) + $plan.Extras) {
    if ($want -eq $current -or $extrasNow -contains $want) { continue }
    $null = Test-Connection -ComputerName $want -Count 2 -Quiet -ErrorAction SilentlyContinue
    $owner = Get-NetNeighbor -IPAddress $want -State Reachable, Stale, Permanent -ErrorAction SilentlyContinue |
        Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -ne $mac } | Select-Object -First 1
    if ($owner) { throw "$want มีเครื่องอื่นใช้อยู่แล้ว (MAC $($owner.LinkLayerAddress)) — เลือกเลขอื่น" }
}

# same fixed address: only the extras change, the main address is never dropped
if ($Ip -eq $current -and $static) {
    foreach ($e in $extrasNow | Where-Object { $plan.Extras -notcontains $_ }) { Remove-NetIPAddress -InterfaceAlias $alias -IPAddress $e -Confirm:$false }
    foreach ($e in $plan.Extras | Where-Object { $extrasNow -notcontains $_ }) { New-NetIPAddress -InterfaceAlias $alias -IPAddress $e -PrefixLength $prefix -SkipAsSource $true | Out-Null }
    Write-Host $(if ($plan.Extras) { "เครื่องนี้ใช้ $Ip แบบคงที่ + IP ชั่วคราว $($plan.Extras -join ', ')" } else { "เครื่องนี้ใช้ $Ip แบบคงที่อยู่แล้ว" })
    return
}

try {
    Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false
    Get-NetRoute -InterfaceAlias $alias -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Remove-NetRoute -Confirm:$false
    Set-NetIPInterface -InterfaceAlias $alias -Dhcp Disabled
    New-NetIPAddress -InterfaceAlias $alias -IPAddress $Ip -PrefixLength $prefix -DefaultGateway $gateway | Out-Null
    # extras only answer: everything this PC starts goes out from the fixed address
    foreach ($e in $plan.Extras) { New-NetIPAddress -InterfaceAlias $alias -IPAddress $e -PrefixLength $prefix -SkipAsSource $true | Out-Null }
    Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $dns
} catch {
    # never leave the PC without an address
    Set-NetIPInterface -InterfaceAlias $alias -Dhcp Enabled -ErrorAction SilentlyContinue
    throw
}

Write-Host "ตั้งเลข IP คงที่ = $Ip/$prefix, เกตเวย์ = $gateway เรียบร้อย"
if ($plan.Extras) { Write-Host "IP ชั่วคราวที่ยังรับการเชื่อมต่อ: $($plan.Extras -join ', ') — กด 'เอา IP ชั่วคราวออก' เมื่อเครื่องอื่นเปลี่ยนมาใช้ $Ip แล้ว" }
Write-Host 'เคล็ดลับ: เลือกเลขที่อยู่นอกช่วงที่เราเตอร์แจกอัตโนมัติ เพื่อไม่ให้ชนกับเครื่องอื่นในอนาคต'
