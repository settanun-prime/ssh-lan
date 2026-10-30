. "$PSScriptRoot\assert.ps1"
$env:SSH_LAN_DATA_DIR = Join-Path $env:TEMP "sshlan-inv-test-$(Get-Random)"
Remove-Item $env:SSH_LAN_DATA_DIR -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $env:SSH_LAN_DATA_DIR | Out-Null
. (Join-Path $TestRoot 'scripts\ssh-lan-common.ps1')
. (Join-Path $TestRoot 'scripts\ssh-lan\ssh-lan.ps1')

$t1 = Get-SshLanInventoryToken
$t2 = Get-SshLanInventoryToken
Assert-True ($t1 -match '^[0-9a-f]{32}$') 'token format'
Assert-equal $t1 $t2 'token stable'

Assert-equal (Resolve-SshLanInventoryRequest 'POST' '/inventory' "Bearer $t1" $t1).Status 'ok' 'bearer ok'
Assert-equal (Resolve-SshLanInventoryRequest 'POST' '/inventory' 'Bearer wrong' $t1).Status 'notfound' 'bad token'
Assert-equal (Resolve-SshLanInventoryRequest 'GET' '/inventory' "Bearer $t1" $t1).Status 'notfound' 'GET'
Assert-equal (Resolve-SshLanInventoryRequest 'POST' '/other' "Bearer $t1" $t1).Status 'notfound' 'path'

Assert-True (Test-SshLanInventoryBindIp '192.168.1.10') 'lan'
Assert-True (Test-SshLanInventoryBindIp '10.1.1.1') '10'
Assert-True (Test-SshLanInventoryBindIp '172.16.0.1') '172'
Assert-True (Test-SshLanInventoryBindIp '100.64.0.1') 'tailscale'
Assert-True (-not (Test-SshLanInventoryBindIp '8.8.8.8')) 'public'
Assert-True (-not (Test-SshLanInventoryBindIp '127.0.0.1')) 'loopback'
Assert-True (-not (Test-SshLanInventoryBindIp '100.63.0.1')) 'below cgNAT'
Assert-True (-not (Test-SshLanInventoryBindIp '0.0.0.0')) 'any'

$good = @{
    v = 1; deviceId = 'AA-BB-CC-DD-EE-FF'; hostname = 'PC-07'; os = 'Windows'
    reportedAt = '2026-10-30T10:15:00+07:00'; source = 'agent'
    adapters = @(
        @{ name = 'Ethernet'; mac = 'AA-BB-CC-DD-EE-FF'; media = 'wired'; ips = @('192.168.1.50') }
        @{ name = 'Wi-Fi'; mac = '02-11-22-33-44-55'; media = 'wifi'; ips = @('192.168.1.51') }
    )
}
Assert-True (Test-SshLanInventoryReport $good) 'good report'
Assert-True (-not (Test-SshLanInventoryReport @{ deviceId = 'guid:x'; hostname = 'PC'; adapters = @() })) 'reject guid id'
Assert-True (-not (Test-SshLanInventoryReport @{ deviceId = 'host:PC'; hostname = 'PC'; adapters = @() })) 'reject host id'
Assert-True (-not (Test-SshLanInventoryReport @{
    deviceId = 'AA-BB-CC-DD-EE-FF'; hostname = 'PC 07'
    adapters = @(@{ mac = 'AA-BB-CC-DD-EE-FF'; media = 'wired'; ips = @() })
})) 'reject space hostname'
Assert-True (-not (Test-SshLanInventoryReport @{
    deviceId = 'AA-BB-CC-DD-EE-FF'; hostname = 'PC-07'
    adapters = @(@{ mac = '02-22-33-44-55-66'; media = 'wired'; ips = @() })
})) 'deviceId must match adapter'

$now = [datetime]'2026-10-30T10:15:04+07:00'
$r1 = Merge-SshLanInventoryReport $good $now
Assert-equal $r1.hostname 'PC-07' 'merge hostname'
$newer = $good.Clone(); $newer.hostname = 'PC-08'; $newer.reportedAt = '2026-10-30T11:00:00+07:00'
$r2 = Merge-SshLanInventoryReport $newer $now.AddMinutes(1)
Assert-equal $r2.hostname 'PC-08' 'newer hub time replaces'
$olderHub = Merge-SshLanInventoryReport $good ([datetime]'2026-10-30T09:00:00+07:00')
Assert-equal $olderHub.hostname 'PC-08' 'older hub lastSeen keeps stored'
$disk = Get-Content (Get-SshLanInventoryPath) -Raw | ConvertFrom-Json
Assert-True ($disk.'AA-BB-CC-DD-EE-FF') 'store keyed by MAC'
Assert-True (-not (Test-Path (Join-Path $env:SSH_LAN_DATA_DIR 'devices.json'))) 'devices.json untouched'

$rowWifi = [pscustomobject]@{
    Ip = '192.168.1.51'; Mac = 'FF-FF-FF-FF-FF-FF'; Name = 'dns-name'; NameFrom = 'DNS'
    Os = ''; Note = ''; Evidence = ''
}
[void](Apply-SshLanInventoryToDevices @($rowWifi) (Read-SshLanInventoryStore) $now.AddMinutes(2))
Assert-equal $rowWifi.Mac '02-11-22-33-44-55' 'wifi IP gets wifi MAC not ethernet'
Assert-equal $rowWifi.Name 'PC-08' 'agent hostname'
Assert-equal $rowWifi.NameFrom 'agent' 'NameFrom agent'

$rowArp = [pscustomobject]@{
    Ip = '203.0.113.9'; Mac = 'AA-BB-CC-DD-EE-FF'; Name = 'old'; NameFrom = 'DNS'; Os = ''; Note = ''; Evidence = ''
}
[void](Apply-SshLanInventoryToDevices @($rowArp) (Read-SshLanInventoryStore) $now.AddMinutes(2))
Assert-equal $rowArp.Mac 'AA-BB-CC-DD-EE-FF' 'MAC unchanged on ARP-only match'
Assert-equal $rowArp.Name 'PC-08' 'hostname from MAC match'

$rowStale = [pscustomobject]@{
    Ip = '192.168.1.51'; Mac = 'FF-FF-FF-FF-FF-FF'; Name = 'dns'; NameFrom = 'DNS'; Os = ''; Note = ''; Evidence = ''
}
$staleStore = Read-SshLanInventoryStore
$staleStore['AA-BB-CC-DD-EE-FF'].lastSeen = ([datetime]'2026-10-28T10:00:00+07:00').ToString('o')
[void](Apply-SshLanInventoryToDevices @($rowStale) $staleStore $now)
Assert-equal $rowStale.Mac 'FF-FF-FF-FF-FF-FF' 'stale report ignored'
Assert-equal $rowStale.Name 'dns' 'stale keeps DNS'

$rowSelf = [pscustomobject]@{
    Ip = '192.168.1.50'; Mac = '02-02-02-02-02-02'; Name = 'HERE'; NameFrom = 'เครื่องนี้'
    Os = 'Windows'; Note = 'เครื่องนี้'; Evidence = ''
}
[void](Apply-SshLanInventoryToDevices @($rowSelf) (Read-SshLanInventoryStore) $now.AddMinutes(2))
Assert-equal $rowSelf.Mac '02-02-02-02-02-02' 'self row untouched'
Assert-equal $rowSelf.Name 'HERE' 'self name untouched'

Remove-Item $env:SSH_LAN_DATA_DIR -Recurse -Force -ErrorAction SilentlyContinue
'inventory.tests.ps1 OK'
