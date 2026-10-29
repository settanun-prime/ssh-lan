. "$PSScriptRoot\assert.ps1"
. (Join-Path $TestRoot 'scripts\ssh-lan-common.ps1')
. (Join-Path $TestRoot 'scripts\ssh-lan\ssh-lan.ps1')

# protected.json and changes.json: a temp data dir, same as topology.tests.ps1
$old = $env:SSH_LAN_DATA_DIR
$env:SSH_LAN_DATA_DIR = Join-Path $env:TEMP ('ssh-lan-test-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $env:SSH_LAN_DATA_DIR | Out-Null

    Set-SshLanProtected '02-00-00-00-00-0A' '192.0.2.20' 'nas' $true
    $saved = @(Get-SshLanProtected)
    Assert-Equal $saved.Count 1 'protected matched by MAC even after IP change'
    Assert-Equal $saved[0].mac '02-00-00-00-00-0A' 'protected matched by MAC even after IP change'
    Assert-Equal $saved[0].ip '192.0.2.20' 'protected matched by MAC even after IP change'
    Assert-Equal $saved[0].label 'nas' 'protected matched by MAC even after IP change'
    $moved = [pscustomobject]@{ Mac = '02-00-00-00-00-0A'; Ip = '192.0.2.21' }
    Assert-True (Test-SshLanProtected $moved (Get-SshLanProtected)) 'protected matched by MAC even after IP change'
    # the old address now belongs to a different machine: MAC decides, not the leftover IP
    $tookIp = [pscustomobject]@{ Mac = '02-00-00-00-00-0B'; Ip = '192.0.2.20' }
    Assert-True (-not (Test-SshLanProtected $tookIp (Get-SshLanProtected))) 'protected matched by MAC even after IP change'
    $noMac = [pscustomobject]@{ Ip = '192.0.2.20' }
    Assert-True (Test-SshLanProtected $noMac (Get-SshLanProtected)) 'protected matched by MAC even after IP change'

    Set-SshLanProtected '02-00-00-00-00-0A' '192.0.2.21' 'nas' $false
    Assert-Equal @(Get-SshLanProtected).Count 0 'protected off removes it'

    $id = Add-SshLanChange @{
        machine = 'box'; ip = '192.0.2.20'; mac = '02-00-00-00-00-0A'; os = 'Linux'
        action = 'close'; port = 445; rules = @('sshlan-close-445'); before = @{ enabled = $true }; expires = ''
    }
    Assert-True ($id -match '^[0-9a-f]{32}$') 'change gets an id and time'
    $one = @(@(Get-SshLanChanges) | Where-Object { $_.id -eq $id })[0]
    Assert-Equal $one.id $id 'change gets an id and time'
    Assert-True ([string]$one.time) 'change gets an id and time'
    Assert-Equal $one.ip '192.0.2.20' 'change gets an id and time'
    Assert-Equal $one.undoneAt '' 'change gets an id and time'
    Assert-Equal $one.rules[0] 'sshlan-close-445' 'change gets an id and time'

    $older = Add-SshLanChange @{
        time = '2026-10-29T08:00:00'; machine = 'box'; ip = '192.0.2.20'; mac = '02-00-00-00-00-0A'; os = 'Linux'
        action = 'close'; port = 80; rules = @('a'); before = @{}; expires = ''
    }
    $newer = Add-SshLanChange @{
        time = '2026-10-29T18:00:00'; machine = 'other'; ip = '192.0.2.21'; mac = '02-00-00-00-00-0B'; os = 'Windows'
        action = 'firewall-on'; port = 0; rules = @('b', 'c'); before = @{}; expires = ''
    }
    $order = @(Get-SshLanChanges)
    $ids = @($order | ForEach-Object { $_.id })
    Assert-True (([array]::IndexOf($ids, $newer)) -lt ([array]::IndexOf($ids, $older))) 'changes newest first'
    Assert-True (([datetime]$order[0].time) -ge ([datetime]$order[1].time)) 'changes newest first'
    Assert-Equal @(Get-SshLanChanges '' 1)[0].id $order[0].id 'changes newest first'

    $onlyB = @(Get-SshLanChanges '02-00-00-00-00-0B')
    Assert-Equal $onlyB.Count 1 'filter by MAC'
    Assert-Equal $onlyB[0].id $newer 'filter by MAC'
    Assert-Equal @($onlyB[0].rules).Count 2 'filter by MAC'
    Assert-Equal $onlyB[0].rules[1] 'c' 'filter by MAC'

    # recorded while the machine was .20; lookup is the MAC, so a later address .21 does not hide it
    $byMac = @(Get-SshLanChanges '02-00-00-00-00-0A')
    Assert-True (@($byMac | Where-Object { $_.ip -eq '192.0.2.20' -and $_.id -eq $id }).Count -eq 1) 'device found by MAC'
    Assert-Equal @($byMac | Where-Object { $_.ip -eq '192.0.2.21' }).Count 0 'device found by MAC'

    Set-SshLanChangeUndone $id
    $marked = @(@(Get-SshLanChanges) | Where-Object { $_.id -eq $id })[0]
    Assert-True ([string]$marked.undoneAt) 'undo twice refused'
    Assert-Throws { Set-SshLanChangeUndone $id } 'undo twice refused'
    $again = $null
    try { Set-SshLanChangeUndone $id } catch { $again = $_.Exception.Message }
    Assert-Equal $again 'ย้อนรายการนี้ไปแล้ว' 'undo twice refused'

    # one observable line per switch row: action, on/off, button text, reason
    function Show-ControlSwitch($Switch) {
        $on = if ($Switch.Enabled) { 'on' } else { 'off' }
        return "$($Switch.Action)|$on|$($Switch.Label)|$($Switch.Why)"
    }
    function New-ControlFinding([int]$Port, [string]$Exposure = 'any', [string]$Rule = 'Allow Web', [string]$Os = 'Windows', [string]$Via = '', [string]$Process = 'app') {
        New-SshLanFinding @{ machine = 'box'; ip = '192.0.2.30'; os = $Os } $Port 'amber' 'reason' 'evidence' 'fix' $Process $Exposure $Rule $Via
    }
    $here = [pscustomobject]@{ mac = '02-00-00-00-00-0C'; ip = '192.0.2.30'; Note = 'เครื่องนี้' }
    $guest = [pscustomobject]@{ mac = '02-00-00-00-00-0F'; ip = '192.0.2.40'; Note = '' }
    $locked = [pscustomobject]@{ mac = '02-00-00-00-00-0E'; ip = '192.0.2.31'; Note = 'เครื่องนี้' }
    $lockList = @([pscustomobject]@{ mac = '02-00-00-00-00-0E'; ip = '192.0.2.31'; label = 'nas' })

    $fw = New-SshLanFinding @{ machine = 'box'; ip = '192.0.2.30'; os = 'Windows' } 0 'red' 'ไฟร์วอลล์ปิดอยู่' 'evidence' 'กด "เปิดไฟร์วอลล์"'
    Assert-Equal (Show-ControlSwitch (Get-SshLanSwitch $fw $here $true $false @())) 'firewall-on|on|เปิดไฟร์วอลล์|' 'whole-machine firewall off'
    Assert-Equal (Show-ControlSwitch (Get-SshLanSwitch (New-ControlFinding 80 'any' 'Allow Web' 'Windows' 'upnp') $here $true $true @())) 'upnp-delete|on|ลบการเปิดพอร์ตที่เราเตอร์|' 'upnp mapping'
    Assert-Equal (Show-ControlSwitch (Get-SshLanSwitch (New-ControlFinding 90 'any' '' 'Windows' 'probe') $here $true $true @())) 'none|off||ปิดที่หน้าตั้งค่าเราเตอร์: ลบ port forward พอร์ต 90' 'router probe'
    $quiet = @(foreach ($x in @('local', 'blocked', 'tailscale')) {
            Show-ControlSwitch (Get-SshLanSwitch (New-ControlFinding 443 $x) $here $true $true @())
        }) -join ';'
    Assert-Equal $quiet 'none|off||;none|off||;none|off||' 'local blocked or tailscale'
    Assert-Equal (Show-ControlSwitch (Get-SshLanSwitch (New-ControlFinding 8080) $locked $true $true $lockList)) 'close|off||ตั้งเป็น "ห้ามแอปแก้" ไว้' 'protected device'
    Assert-Equal (Show-ControlSwitch (Get-SshLanSwitch (New-ControlFinding 22) $here $true $true @())) 'close|off||ไม่ปิด SSH: ปิดแล้วแอปจะสั่งเครื่องนี้ไม่ได้อีก' 'ssh port stays open'
    Assert-Equal (Show-ControlSwitch (Get-SshLanSwitch (New-ControlFinding 8080) $guest $false $true @())) 'close|off||ยังไม่ได้เข้าวง: ตั้งค่าได้ที่หน้าเว็บของอุปกรณ์' 'not in the circle'
    Assert-Equal (Show-ControlSwitch (Get-SshLanSwitch (New-ControlFinding 8080 'any' '' 'Linux' '' 'docker-proxy') $here $true $true @())) 'close|off||Docker ข้ามไฟร์วอลล์: แก้ใน compose ให้ผูก 127.0.0.1:8080' 'docker-proxy'
    Assert-Equal (Show-ControlSwitch (Get-SshLanSwitch (New-ControlFinding 8080) $here $true $false @())) 'close|off||เปิดไฟร์วอลล์ก่อน แล้วค่อยปิดพอร์ตนี้' 'firewall off first'
    Assert-Equal (Show-ControlSwitch (Get-SshLanSwitch (New-ControlFinding 8080 'any' '') $here $true $true @())) 'close|off||หากฎที่เปิดพอร์ตนี้ไม่เจอ' 'windows rule missing'
    Assert-Equal (Show-ControlSwitch (Get-SshLanSwitch (New-ControlFinding 8080) $here $true $true @())) 'close|on|ปิดพอร์ตนี้|' 'close this port'

    $wideRules = @(
        @{ name = 'Wide'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = 'Any'; localPorts = @('Any'); remote = @('Any'); program = 'Any' }
        @{ name = 'Web'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = 'Any'; localPorts = @('8080'); remote = @('Any'); program = 'Any' }
        @{ name = 'Alt'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = 'Any'; localPorts = @('8443'); remote = @('Any'); program = 'Any' }
        @{ name = 'Discard'; enabled = $true; direction = 'Inbound'; action = 'Block'; profiles = 'Any'; localPorts = @('9'); remote = @('Any'); program = 'Any' }
        @{ name = 'Off'; enabled = $false; direction = 'Inbound'; action = 'Allow'; profiles = 'Any'; localPorts = @('9090'); remote = @('Any'); program = 'Any' }
    )
    $wide = Get-SshLanSwitch (New-ControlFinding 445 'any' 'Wide') $here $true $true @() $wideRules
    Assert-Equal "$(Show-ControlSwitch $wide)|$($wide.AlsoPorts -join ',')" 'close|on|ปิดพอร์ตนี้||8080,8443' 'wide rule warns'

    Add-SshLanChange @{
        machine = 'box'; ip = '192.0.2.30'; mac = '02-00-00-00-00-0C'; os = 'Windows'
        action = 'close'; port = 8080; rules = @('Allow Web'); before = @{}; expires = ''
    }
    Assert-Equal (Show-ControlSwitch (Get-SshLanSwitch (New-ControlFinding 8080) $here $true $true @())) 'reopen|on|เปิดคืน|' 'reopen'
    # this finding would be "เปิดไฟร์วอลล์"; protected still wins because that action is not none
    Assert-Equal (Show-ControlSwitch (Get-SshLanSwitch $fw $locked $true $false $lockList)) 'close|off||ตั้งเป็น "ห้ามแอปแก้" ไว้' 'protected beats everything'

    $winClose = Get-SshLanControlScript 'Windows' 'close' @{ Rule = 'Allow Web'; Port = 8080 }
    Assert-True ($winClose -match "Get-NetFirewallRule -DisplayName 'Allow Web'") 'windows close disables by display name, never removes'
    Assert-True ($winClose -match "Enabled -eq 'True'") 'windows close disables by display name, never removes'
    Assert-True ($winClose -match "Direction -eq 'Inbound'") 'windows close disables by display name, never removes'
    Assert-True ($winClose -match "Action -eq 'Allow'") 'windows close disables by display name, never removes'
    Assert-True ($winClose -match 'Disable-NetFirewallRule') 'windows close disables by display name, never removes'
    Assert-True ($winClose -notmatch 'Remove-NetFirewallRule') 'windows close disables by display name, never removes'
    Assert-Throws { Get-SshLanControlScript 'Windows' 'close' @{ Rule = "Allow'; Remove-NetFirewallRule" } } 'windows close disables by display name, never removes'
    Assert-Throws { Get-SshLanControlScript 'Linux' 'close' @{ Port = '8080;id' } } 'windows close disables by display name, never removes'

    $linClose = Get-SshLanControlScript 'Linux' 'close' @{ Port = 8080 }
    Assert-True ($linClose -match "ufw insert 1 deny 8080/tcp comment 'sshlan-close-8080'") 'linux close inserts deny first'
    Assert-True ($linClose -match 'exit 77') 'linux close inserts deny first'
    $prelude = @((Get-SshLanLinuxFactsScript) -split "`n")[0].TrimEnd("`r")
    Assert-True ($linClose.StartsWith($prelude)) 'linux close inserts deny first'
    Assert-True ($linClose -notmatch '### os') 'linux close inserts deny first'

    $linOn = Get-SshLanControlScript 'Linux' 'firewall-on' @{ Lan = '192.0.2.0/24'; Keep = [int[]]@(80, 443) }
    $at22 = $linOn.IndexOf('port 22')
    $atTs = $linOn.IndexOf('tailscale0')
    $atEnable = $linOn.IndexOf('--force enable')
    Assert-True ($at22 -ge 0 -and $atTs -gt $at22 -and $atEnable -gt $atTs) 'firewall-on keeps ssh first'
    Assert-True ($linOn.IndexOf('port 80') -gt $atTs -and $linOn.IndexOf('port 80') -lt $atEnable) 'firewall-on keeps ssh first'
    Assert-True ($linOn.IndexOf('port 443') -gt $atTs -and $linOn.IndexOf('port 443') -lt $atEnable) 'firewall-on keeps ssh first'
    Assert-True ($linOn -match 'sshlan-keep-ssh') 'firewall-on keeps ssh first'
    Assert-True ($linOn -match 'sshlan-keep-tailscale') 'firewall-on keeps ssh first'

    $keepFacts = @{
        listeners = @(
            @{ port = 22; process = 'sshd'; exposure = 'any' }
            @{ port = 80; process = 'nginx'; exposure = 'any' }
            @{ port = 443; process = 'nginx'; exposure = 'lan' }
            @{ port = 8080; process = 'docker-proxy'; exposure = 'any' }
            @{ port = 3306; process = 'mysqld'; exposure = 'local' }
            @{ port = 41641; process = 'tailscaled'; exposure = 'tailscale' }
            @{ port = 9; process = 'discard'; exposure = 'blocked' }
        )
    }
    $plan = Get-SshLanFirewallOnPlan $keepFacts '192.0.2.0/24'
    Assert-Equal ((@($plan.Keep) | Sort-Object) -join ',') '9,80,443' 'firewall-on keeps listening ports, not docker, not 22'
    Assert-True ($plan.Text -match '80' -and $plan.Text -match '443' -and $plan.Text -match '9') 'firewall-on keeps listening ports, not docker, not 22'
    Assert-True ($plan.Text -notmatch '8080' -and $plan.Text -notmatch '3306' -and $plan.Text -notmatch '41641') 'firewall-on keeps listening ports, not docker, not 22'
    $keepScript = Get-SshLanControlScript 'Linux' 'firewall-on' @{ Lan = '192.0.2.0/24'; Keep = [int[]]$plan.Keep }
    Assert-True ($keepScript -match 'port 80' -and $keepScript -match 'port 443' -and $keepScript -match 'port 9') 'firewall-on keeps listening ports, not docker, not 22'
    Assert-True ($keepScript -notmatch '8080' -and $keepScript -notmatch 'sshlan-keep-22') 'firewall-on keeps listening ports, not docker, not 22'

    $emptyDir = Join-Path $env:TEMP ('ssh-lan-test-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $emptyDir | Out-Null
    $savedData = $env:SSH_LAN_DATA_DIR
    $env:SSH_LAN_DATA_DIR = $emptyDir
    try {
        $miss = Invoke-SshLanSwitch $here (New-ControlFinding 8443) (Get-SshLanSwitch (New-ControlFinding 8443) $here $true $true @()) { @{ Ok = $false; Code = 255; Out = ''; Err = 'gone' } } { throw 'recheck ran' }
        Assert-Equal @(Get-SshLanChanges).Count 0 'failed run records nothing'
        Assert-True (-not $miss.Ok) 'failed run records nothing'
        Assert-Equal $miss.ChangeId '' 'failed run records nothing'
        Assert-True ($miss.Message -match 'ไม่แน่ใจ') 'failed run records nothing'

        $closed = Invoke-SshLanSwitch $here (New-ControlFinding 8443) (Get-SshLanSwitch (New-ControlFinding 8443) $here $true $true @()) { @{ Ok = $true; Code = 0; Out = "Allow Web`n"; Err = '' } } { @{ listeners = @(@{ port = 8443; exposure = 'blocked'; rule = $null; process = 'app' }) } }
        Assert-True ($closed.Message -match 'ปิดแล้ว') 'verify says closed'
        Assert-True ($closed.Ok) 'verify says closed'
        $closedRow = @(@(Get-SshLanChanges) | Where-Object { $_.id -eq $closed.ChangeId })[0]
        Assert-Equal $closedRow.action 'close' 'verify says closed'
        Assert-Equal ([string]$closedRow.rules[0]) 'Allow Web' 'verify says closed'

        $still = Invoke-SshLanSwitch $here (New-ControlFinding 8444 'any' 'Other') (Get-SshLanSwitch (New-ControlFinding 8444 'any' 'Other') $here $true $true @()) { @{ Ok = $true; Code = 0; Out = "Other`n"; Err = '' } } { @{ listeners = @(@{ port = 8444; exposure = 'any'; rule = 'Other'; process = 'app' }) } }
        Assert-True ($still.Message -match 'ยังเปิดอยู่') 'verify says still open'
        Assert-True ($still.Message -match 'Other') 'verify says still open'
        Assert-True ($still.ChangeId) 'verify says still open'
    } finally {
        Remove-Item -LiteralPath $emptyDir -Recurse -Force -ErrorAction SilentlyContinue
        $env:SSH_LAN_DATA_DIR = $savedData
    }

    $sudo = Invoke-SshLanControl $here 'Linux' 'echo hi' { @{ Code = 77; Out = ''; Err = 'sudo' } }
    Assert-True $sudo.NeedSudo 'need sudo surfaces'
    Assert-True (-not $sudo.Ok) 'need sudo surfaces'

    $at = New-Object datetime 2026, 10, 29, 15, 30, 45
    $name = Get-SshLanTempRuleName 22 $at
    Assert-Equal $name 'sshlan-temp-22-202610291530' 'temp name round-trips'
    $back = ConvertFrom-SshLanTempRuleName $name
    Assert-Equal $back.Port 22 'temp name round-trips'
    Assert-Equal $back.Expires.ToString('yyyyMMddHHmm') '202610291530' 'temp name round-trips'
    Assert-Equal (ConvertFrom-SshLanTempRuleName 'sshlan-temp-22') $null 'temp name round-trips'
    Assert-Equal (ConvertFrom-SshLanTempRuleName 'sshlan-keep-22') $null 'temp name round-trips'

    $now = New-Object datetime 2026, 10, 29, 12, 0, 0
    $gone = @(Get-SshLanExpiredTempRules @('sshlan-temp-22-202610291159', 'sshlan-temp-80-202610291200', 'sshlan-temp-443-202610291201', 'Allow Web') $now)
    Assert-Equal ($gone -join ',') 'sshlan-temp-22-202610291159,sshlan-temp-80-202610291200' 'expired found, future kept'

    Assert-Throws { Open-SshLanTemp $here 'Windows' 'ssh' 22 3 { throw 'runner' } } 'hours outside 1/2/4/8 refused'
    Assert-Throws { Open-SshLanTemp $here 'Windows' 'port' 49999 5 } 'hours outside 1/2/4/8 refused'
    Assert-Throws { Open-SshLanTemp $here 'Windows' 'ssh' 22 0 } 'hours outside 1/2/4/8 refused'

    $win = Get-SshLanTempOpenScript 'Windows' 22 $at $false
    Assert-True ($win -match '100\.64\.0\.0/10') 'windows temp allows tailnet only'
    Assert-True ($win -notmatch 'Any') 'windows temp allows tailnet only'
    Assert-True ($win -match 'LocalPort 22') 'windows temp allows tailnet only'
    Assert-True ($win -match 'New-NetFirewallRule') 'windows temp allows tailnet only'
    Assert-True ($win -match 'sshlan-temp-22-202610291530') 'windows temp allows tailnet only'
    Assert-True ($win -match "RemoteAddress 100.64.0.0/10") 'windows temp allows tailnet only'

    Assert-True ($win -match "Register-ScheduledTask -TaskName 'SSH LAN expire sshlan-temp-22-202610291530'") 'windows expiry task named by spec'
    Assert-True ($win -match '-Once') 'windows expiry task named by spec'
    Assert-True ($win -match 'StartWhenAvailable') 'windows expiry task named by spec'
    Assert-True ($win -match '-NoProfile -Command') 'windows expiry task named by spec'
    Assert-True ($win -match 'Remove-NetFirewallRule -Name') 'windows expiry task named by spec'
    Assert-True ($win -match 'Unregister-ScheduledTask') 'windows expiry task named by spec'
    Assert-True ($win -match '2026-10-29 15:30') 'windows expiry task named by spec'

    $rdp = Get-SshLanTempOpenScript 'Windows' 3389 $at $true
    Assert-True ($rdp -match 'fDenyTSConnections') 'rdp saves and restores old values'
    Assert-True ($rdp -match 'UserAuthentication') 'rdp saves and restores old values'
    Assert-True ($rdp -match 'fDenyTSConnections -Value 0') 'rdp saves and restores old values'
    Assert-True ($rdp -match 'UserAuthentication -Value 1') 'rdp saves and restores old values'
    Assert-True ($rdp -match 'fDenyTSConnections -Value \$deny') 'rdp saves and restores old values'
    Assert-True ($rdp -match 'UserAuthentication -Value \$nla') 'rdp saves and restores old values'
    Assert-True ($rdp -match 'LocalPort 3389') 'rdp saves and restores old values'
    Assert-True ($rdp -match '100\.64\.0\.0/10') 'rdp saves and restores old values'
    Assert-True ($win -notmatch 'fDenyTSConnections') 'rdp saves and restores old values'
    Assert-Throws { Get-SshLanTempOpenScript 'Linux' 3389 $at $true } 'rdp saves and restores old values'

    $lin = Get-SshLanTempOpenScript 'Linux' 22 $at $false
    Assert-True ($lin -match "ufw allow from 100.64.0.0/10 to any port 22 proto tcp comment 'sshlan-temp-22-202610291530'") 'linux temp uses systemd-run at expiry'
    Assert-True ($lin -match "systemd-run --unit=sshlan-temp-22-202610291530 --on-calendar='2026-10-29 15:30'") 'linux temp uses systemd-run at expiry'
    Assert-True ($lin -match '/usr/sbin/ufw delete allow from 100.64.0.0/10 to any port 22 proto tcp') 'linux temp uses systemd-run at expiry'
    Assert-True ($lin -match 'exit 77') 'linux temp uses systemd-run at expiry'
    $prelude = @((Get-SshLanLinuxFactsScript) -split "`n")[0].TrimEnd("`r")
    Assert-True ($lin.StartsWith($prelude)) 'linux temp uses systemd-run at expiry'

    $off = @{ mac = '02-00-00-00-00-0C'; ip = '192.0.2.30'; Name = 'box'; Note = 'เครื่องนี้'; Facts = @{ firewallOn = $false } }
    $offFlag = @{ Ran = $false }
    $beforeChanges = @(Get-SshLanChanges).Count
    $refused = Open-SshLanTemp $off 'Windows' 'ssh' 22 1 { $offFlag.Ran = $true; @{ Ok = $true; Code = 0; Out = '' } }
    Assert-True (-not $refused.Ok) 'firewall off refuses temp open'
    Assert-Equal $refused.Message 'ไฟร์วอลล์ปิดอยู่ เครื่องนี้เปิดทุกพอร์ตให้ทุกคนอยู่แล้ว กด "เปิดไฟร์วอลล์" ก่อน' 'firewall off refuses temp open'
    Assert-Equal $refused.ChangeId '' 'firewall off refuses temp open'
    Assert-True (-not $offFlag.Ran) 'firewall off refuses temp open'
    Assert-Equal @(Get-SshLanChanges).Count $beforeChanges 'firewall off refuses temp open'

    Set-SshLanProtected '02-00-00-00-00-0E' '192.0.2.31' 'nas' $true
    $lockedDev = @{ mac = '02-00-00-00-00-0E'; ip = '192.0.2.31'; Name = 'nas'; Note = 'เครื่องนี้'; Facts = @{ firewallOn = $true } }
    $lockFlag = @{ Ran = $false }
    $lockedOpen = Open-SshLanTemp $lockedDev 'Windows' 'port' 49999 2 { $lockFlag.Ran = $true; @{ Ok = $true; Code = 0; Out = '' } }
    Assert-True (-not $lockedOpen.Ok) 'protected refuses temp open'
    Assert-Equal $lockedOpen.Message 'ตั้งเป็น "ห้ามแอปแก้" ไว้' 'protected refuses temp open'
    Assert-Equal $lockedOpen.ChangeId '' 'protected refuses temp open'
    Assert-True (-not $lockFlag.Ran) 'protected refuses temp open'

    $openDev = @{ mac = '02-00-00-00-00-0D'; ip = '192.0.2.32'; Name = 'box'; Note = 'เครื่องนี้'; Os = 'Windows'; Facts = @{ firewallOn = $true; os = 'Windows'; tempRules = @('sshlan-temp-22-202001011200', 'sshlan-temp-80-209901011200') } }
    $hourCount = @(Get-SshLanChanges).Count
    foreach ($h in @(1, 2, 4, 8)) {
        $hourTry = Open-SshLanTemp $openDev 'Linux' 'port' 49999 $h { @{ Ok = $false; Code = 1; Out = '' } }
        Assert-True (-not $hourTry.Ok) 'hours outside 1/2/4/8 refused'
        Assert-Equal $hourTry.ChangeId '' 'hours outside 1/2/4/8 refused'
    }
    Assert-Equal @(Get-SshLanChanges).Count $hourCount 'hours outside 1/2/4/8 refused'

    $openFlag = @{ Script = '' }
    $opened = Open-SshLanTemp $openDev 'Windows' 'ssh' 80 1 { param($Script) $openFlag.Script = $Script; @{ Ok = $true; Code = 0; Out = '' } }
    Assert-True $opened.Ok 'temp open records a change'
    Assert-True ($opened.ChangeId) 'temp open records a change'
    Assert-True ($openFlag.Script -match 'LocalPort 22') 'temp open records a change'
    Assert-True ($openFlag.Script -match '100\.64\.0\.0/10') 'temp open records a change'
    Assert-True ($openFlag.Script -notmatch 'Any') 'temp open records a change'
    $openRow = @(@(Get-SshLanChanges) | Where-Object { $_.id -eq $opened.ChangeId })[0]
    Assert-Equal $openRow.action 'temp-open' 'temp open records a change'
    Assert-Equal ([int]$openRow.port) 22 'temp open records a change'
    Assert-True ([string]$openRow.rules[0] -match '^sshlan-temp-22-\d{12}$') 'temp open records a change'
    Assert-Equal ([string]$openRow.rules[0]).Substring(([string]$openRow.rules[0]).Length - 12) ([datetime]$openRow.expires).ToString('yyyyMMddHHmm', [Globalization.CultureInfo]::InvariantCulture) 'temp open records a change'

    $rdpOpen = Open-SshLanTemp $openDev 'Windows' 'rdp' 1 8 { @{ Ok = $true; Code = 0; Out = "SSHLAN-RDP fDenyTSConnections=1;UserAuthentication=0`n" } }
    $rdpRow = @(@(Get-SshLanChanges) | Where-Object { $_.id -eq $rdpOpen.ChangeId })[0]
    Assert-Equal ([int]$rdpRow.port) 3389 'rdp saves and restores old values'
    Assert-Equal ([int]$rdpRow.before.fDenyTSConnections) 1 'rdp saves and restores old values'
    Assert-Equal ([int]$rdpRow.before.UserAuthentication) 0 'rdp saves and restores old values'

    $closeFlag = @{ Script = '' }
    $closed = Close-SshLanTempNow $openDev $opened.ChangeId { param($Script) $closeFlag.Script = $Script; @{ Ok = $true; Code = 0; Out = '' } }
    Assert-True $closed.Ok 'close now removes the temp rule'
    Assert-Equal $closed.Message 'ปิดแล้ว' 'close now removes the temp rule'
    Assert-True ($closeFlag.Script -match 'Remove-NetFirewallRule') 'close now removes the temp rule'
    Assert-True ($closeFlag.Script -match [regex]::Escape([string]$openRow.rules[0])) 'close now removes the temp rule'
    Assert-True ($closeFlag.Script -match 'Unregister-ScheduledTask') 'close now removes the temp rule'
    $afterClose = @(@(Get-SshLanChanges) | Where-Object { $_.id -eq $opened.ChangeId })[0]
    Assert-True ([string]$afterClose.undoneAt) 'close now removes the temp rule'
    Assert-Throws { Close-SshLanTempNow $openDev $opened.ChangeId { throw 'again' } } 'close now removes the temp rule'

    $rmFlag = @{ Script = '' }
    $removed = @(Remove-SshLanExpiredTempRules $openDev $openDev.Facts { param($Script) $rmFlag.Script = $Script; @{ Ok = $true; Code = 0; Out = '' } })
    Assert-Equal ($removed -join ',') 'sshlan-temp-22-202001011200' 'expired rules are removed'
    Assert-True ($rmFlag.Script -match 'Remove-NetFirewallRule -Name ''sshlan-temp-22-202001011200''') 'expired rules are removed'
    Assert-True ($rmFlag.Script -notmatch '209901011200') 'expired rules are removed'
    $lockRm = @{ Ran = $false }
    $none = @(Remove-SshLanExpiredTempRules $lockedDev $openDev.Facts { $lockRm.Ran = $true; @{ Ok = $true } })
    Assert-Equal @($none).Count 0 'protected refuses temp open'
    Assert-True (-not $lockRm.Ran) 'protected refuses temp open'
} finally {
    Remove-Item -LiteralPath $env:SSH_LAN_DATA_DIR -Recurse -Force -ErrorAction SilentlyContinue
    $env:SSH_LAN_DATA_DIR = $old
}
