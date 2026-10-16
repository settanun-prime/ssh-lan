# SSH LAN — one script, menu TUI or CLI. Run on the Windows machine that ACCEPTS ssh (server).
#Requires -Version 5.1
param(
    [ValidateSet('', 'help', 'status', 'harden', 'add-client', 'remove', 'client', 'pair')]
    [string]$Action = '',
    [string]$LoginUser = $env:USERNAME,
    [string]$Subnet = '',
    [string]$MyPubKeyPath = '',
    [string]$MyPubKey = '',
    [string]$Target = '',
    [string]$AsUser = '',
    [string]$Alias = '',
    [switch]$Both,
    [switch]$UninstallServer
)
$ErrorActionPreference = 'Stop'
try { chcp 65001 > $null } catch {}
try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
    $OutputEncoding = [Console]::OutputEncoding
} catch {}

. (Join-Path $PSScriptRoot '..\ssh-lan-common.ps1')
$script:SshLanCfg = Get-SshLanSettings

# --- core ---
function Test-SshLanAdmin { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators') }

function Invoke-SshLanElevate {
    Write-Host 'This action needs Administrator.' -ForegroundColor Yellow
    $r = Read-Host 'Relaunch elevated? [Y/n]'
    if ($r -match '^[nN]') { throw 'Cancelled.' }
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -ArgumentList $arg
    exit 0
}

function Assert-SshLanAdmin {
    if (-not (Test-SshLanAdmin)) { Invoke-SshLanElevate }
}

function Get-SshLanAdminKeyFile {
    param([string]$User = $env:USERNAME)
    $isAdmin = [bool](Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*\$User" })
    $path = if ($isAdmin) { "$env:ProgramData\ssh\administrators_authorized_keys" } else { "C:\Users\$User\.ssh\authorized_keys" }
    return @{ Path = $path; IsAdminUser = $isAdmin }
}

function Resolve-SshLanPublicKey {
    param([string]$Path = '', [string]$Line = '', [string]$User = $env:USERNAME)
    if ($Line) {
        $Line = $Line.Trim()
    } else {
        if (-not $Path) { throw 'No public key path or line provided.' }
        if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
        $Line = (Get-Content -LiteralPath $Path | Where-Object { $_ -match '\S' } | Select-Object -First 1)
    }
    $Line = $Line.Trim().Trim([char]0xFEFF)
    if ($Line -notmatch '^(ssh-(ed25519|rsa|ecdsa)|ecdsa-sha2-)') { throw 'Invalid public key line.' }
    return $Line
}

function Add-SshLanKeyLine {
    param([string]$Path, [string]$Key)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    if ((Test-Path -LiteralPath $Path) -and (Select-String -LiteralPath $Path -SimpleMatch $Key -Quiet)) { return $false }
    Add-Content -LiteralPath $Path -Value $Key -Encoding ascii
    return $true
}

function Set-SshLanKeyAcl { param([string]$Path)
    if (Test-Path -LiteralPath $Path) { icacls $Path /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null }
}

function Set-SshLanSshdConfig {
    param([hashtable]$Settings)
    $configPath = "$env:ProgramData\ssh\sshd_config"
    if (-not (Test-Path -LiteralPath $configPath)) { throw 'OpenSSH Server not installed (no sshd_config).' }
    Copy-Item -LiteralPath $configPath -Destination "$configPath.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')" -Force
    $lines = @(Get-Content -LiteralPath $configPath)
    foreach ($key in $Settings.Keys) {
        $pattern = "^\s*#?\s*$([regex]::Escape($key))\s+"
        $repl = "$key $($Settings[$key])"
        $idx = -1
        for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match $pattern) { $idx = $i; break } }
        if ($idx -ge 0) { $lines[$idx] = $repl } else { $lines += $repl }
    }
    Set-Content -LiteralPath $configPath -Value $lines -Encoding ascii
}

function Test-SshLanSshdConfig {
    $exe = @("$env:ProgramFiles\OpenSSH\sshd.exe", "$env:SystemRoot\System32\OpenSSH\sshd.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $exe) { return }
    $out = & $exe -t 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($out | Out-String).Trim() }
}

function Restart-SshLanSshd { Test-SshLanSshdConfig; Restart-Service sshd }

function Show-SshLanFingerprint { param([string]$Pub)
    $t = Join-Path $env:TEMP 'ssh-lan-fp.pub'
    Set-Content -LiteralPath $t -Value $Pub -Encoding ascii
    & ssh-keygen -lf $t | Out-Host
    Remove-Item -LiteralPath $t -Force
}

function Read-SshLanPubKeyInteractive {
    Write-Host '  ใช้กุญแจที่มีอยู่บนเครื่องนี้ ไม่ต้องวางไฟล์' -ForegroundColor Cyan
    Show-SshLanFill -Label 'หากุญแจ'
    return Get-SshLanAutoPublicKey
}

# --- actions ---
function Get-SshLanStatus {
    Assert-SshLanAdmin
    $svc = Get-Service sshd -ErrorAction SilentlyContinue
    Write-Host "`n--- Status ---" -ForegroundColor Cyan
    Write-Host "Computer: $env:COMPUTERNAME  User: $LoginUser"
    if ($svc) { Write-Host "sshd: $($svc.Status) ($($svc.StartType))" } else { Write-Host 'sshd: not installed' }
    $rule = Get-NetFirewallRule -Name sshd-lan -ErrorAction SilentlyContinue
    if ($rule) {
        $addr = ($rule | Get-NetFirewallAddressFilter).RemoteAddress
        Write-Host "Firewall: TCP 22 from $addr"
    } else { Write-Host 'Firewall: no sshd-lan rule' }
    $listen = Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue
    Write-Host "Port 22 listen: $(if ($listen) { 'yes' } else { 'no' })"
    $info = Get-SshLanAdminKeyFile -User $LoginUser
    Write-Host "Key file: $($info.Path)"
    if (Test-Path -LiteralPath $info.Path) {
        $lines = @(Get-Content -LiteralPath $info.Path -Encoding ascii | Where-Object { $_ -match '\S' })
        Write-Host "Keys: $($lines.Count)"
        foreach ($l in $lines) { Show-SshLanFingerprint -Pub $l.Trim() }
    }
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { Test-SshLanPrivateIp $_.IPAddress }).IPAddress -join ', '
    Write-Host "LAN IP: $ip"
}

function Invoke-SshLanAddClient {
    param([string]$Path = '', [string]$Line = '')
    Assert-SshLanAdmin
    $pub = if ($Path -or $Line) { Resolve-SshLanPublicKey -Path $Path -Line $Line } else { Read-SshLanPubKeyInteractive }
    $kf = (Get-SshLanAdminKeyFile -User $LoginUser).Path
    $added = Add-SshLanKeyLine -Path $kf -Key $pub
    Set-SshLanKeyAcl -Path $kf
    Restart-SshLanSshd
    Write-Host $(if ($added) { '  เพิ่มกุญแจแล้ว' } else { '  กุญแจนี้อยู่แล้ว ไม่ต้องทำซ้ำ' }) -ForegroundColor Green
    Show-SshLanFingerprint -Pub $pub
}

function Invoke-SshLanHarden {
    param([string]$SubnetIn, [string]$Path = '', [string]$Line = '')
    if (-not $SubnetIn) { throw 'Subnet required, e.g. 192.0.2.0/24' }
    Assert-SshLanAdmin
    if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) { throw 'Install OpenSSH Server first (Windows Optional features).' }
    if (-not $Path -and -not $Line) {
        $def = "$env:USERPROFILE\.ssh\$($script:SshLanCfg.identityFile).pub"
        if (Test-Path -LiteralPath $def) { $Path = $def }
    }
    if (-not $Path -and -not $Line) {
        $pub = Read-SshLanPubKeyInteractive
    } else {
        $pub = Resolve-SshLanPublicKey -Path $Path -Line $Line
    }
    $info = Get-SshLanAdminKeyFile -User $LoginUser
    $dir = Split-Path -Parent $info.Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    Set-Content -LiteralPath $info.Path -Value $pub -Encoding ascii
    if ($info.IsAdminUser) { Set-SshLanKeyAcl -Path $info.Path }
    Get-NetFirewallRule -Name '*OpenSSH-Server*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Get-NetFirewallRule -Name sshd-lan -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -Name sshd-lan -DisplayName 'OpenSSH LAN' -Protocol TCP -LocalPort 22 -Action Allow -RemoteAddress $SubnetIn -Profile Any | Out-Null
    Set-SshLanSshdConfig -Settings @{
        PasswordAuthentication = 'no'; PubkeyAuthentication = 'yes'; KbdInteractiveAuthentication = 'no'
        AuthenticationMethods = 'publickey'; PermitEmptyPasswords = 'no'; MaxAuthTries = '3'; AllowUsers = $LoginUser
    }
    Set-Service sshd -StartupType Automatic
    if ($env:SSH_LAN_UI) {
        Write-Host "เปิดรับ SSH สำเร็จ (อนุญาตเครือข่าย: $SubnetIn)"
        Write-Host "บริการ OpenSSH Server (sshd) เริ่มทำงานและพร้อมรับการเชื่อมต่อแล้ว"
    } else {
        Write-Host "`nHarden OK. Firewall: $SubnetIn" -ForegroundColor Green
        Show-SshLanFingerprint -Pub $pub
        Write-Host 'Add more clients with menu [2] Add client key.'
    }
}

function Invoke-SshLanRemove {
    param([switch]$Uninstall)
    Assert-SshLanAdmin
    if ($Uninstall -and $PSVersionTable.PSEdition -eq 'Core') {
        & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Action remove -UninstallServer
        exit $LASTEXITCODE
    }
    Get-NetFirewallRule -Name sshd-lan -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    if (Get-Service sshd -ErrorAction SilentlyContinue) {
        Stop-Service sshd -Force -ErrorAction SilentlyContinue
        Set-Service sshd -StartupType Disabled
    }
    if ($Uninstall) { Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null }
    if ($env:SSH_LAN_UI) {
        Write-Host "ปิดการรับ SSH บนเครื่องนี้เรียบร้อย"
    } else {
        Write-Host 'Remove OK.' -ForegroundColor Green
    }
}

function Show-SshLanMotion {
    param([string]$Label, [int]$Ms = 700)
    if ($env:SSH_LAN_UI) { if ($Label) { Write-Host "  $Label" }; return }
    $spin = @('|', '/', '-', '\')
    $n = [Math]::Max(6, [int]($Ms / 70))
    for ($i = 0; $i -lt $n; $i++) {
        $dot = ('.' * (($i % 3) + 1)).PadRight(3)
        Write-Host -NoNewline ("`r  {0}  {1} {2}   " -f $spin[$i % 4], $Label, $dot) -ForegroundColor Magenta
        Start-Sleep -Milliseconds 70
    }
    Write-Host ''
}

function Show-SshLanFill {
    param([string]$Label)
    if ($env:SSH_LAN_UI) { Write-Host "  $Label"; return }
    $width = 22
    for ($i = 0; $i -le $width; $i++) {
        $bar = ('#' * $i).PadRight($width)
        $color = if ($i -lt $width) { 'Cyan' } else { 'Green' }
        Write-Host -NoNewline ("`r  [{0}] {1}   " -f $bar, $Label) -ForegroundColor $color
        Start-Sleep -Milliseconds 28
    }
    Write-Host ''
}

function Show-SshLanBoot {
    if ($env:SSH_LAN_UI) { return }
    Clear-Host
    $logo = @(
        '  .  SSH',
        '  .. SSH ใน',
        '  ... SSH ในบ้าน'
    )
    foreach ($line in $logo) {
        Write-Host $line -ForegroundColor Cyan
        Start-Sleep -Milliseconds 120
    }
    Show-SshLanFill -Label 'เตรียมเมนู'
}

function Show-SshLanSteps {
    param([string]$Title, [int]$Now, [string[]]$Labels)
    if ($env:SSH_LAN_UI) { Write-Host "  $Title ($Now/$($Labels.Count))"; return }
    Clear-Host
    Write-Host ''
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ''
    for ($i = 0; $i -lt $Labels.Count; $i++) {
        $n = $i + 1
        $on = $n -eq $Now
        $done = $n -lt $Now
        $color = if ($on) { 'Green' } elseif ($done) { 'DarkGreen' } else { 'DarkGray' }
        $mark = if ($done) { 'ok' } elseif ($on) { '>>' } else { '  ' }
        Write-Host ("  {0}  {1}  {2}" -f $mark, $n, $Labels[$i]) -ForegroundColor $color
        if ($i -lt $Labels.Count - 1) {
            Write-Host '       |' -ForegroundColor DarkGray
        }
    }
    Write-Host ''
}

function Get-SshLanIpChoices {
    $choices = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    function Add-Choice([string]$Cidr, [string]$Note) {
        if (-not $Cidr) { return }
        $norm = $Cidr -replace '/255\.255\.255\.0$', '/24' -replace '/255\.255\.255\.255$', '/32' -replace '/255\.255\.0\.0$', '/16'
        if ($norm -match '\.255(/32)?$') { return }
        if ($seen.ContainsKey($norm)) { return }
        $seen[$norm] = $true
        $choices.Add([pscustomobject]@{ Cidr = $norm; Note = $Note })
    }
    $local = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { Test-SshLanPrivateIp $_.IPAddress })
    foreach ($a in $local) {
        Add-Choice (ConvertTo-SshLanCidr $a.IPAddress $a.PrefixLength) 'ทั้งวง LAN ในบ้าน (แนะนำ)'
    }
    $rule = Get-NetFirewallRule -Name sshd-lan -ErrorAction SilentlyContinue
    if ($rule) {
        $cur = @(($rule | Get-NetFirewallAddressFilter).RemoteAddress)
        foreach ($c in $cur) { Add-Choice ([string]$c) 'ที่เปิดไว้อยู่ตอนนี้' }
    }
    Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { (Test-SshLanPrivateIp $_.IPAddress) -and $_.State -in 'Reachable', 'Stale', 'Permanent' } |
        ForEach-Object { Add-Choice "$($_.IPAddress)/32" "เครื่องในเครือข่าย" }
    try {
        Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 40 -ErrorAction SilentlyContinue |
            ForEach-Object { if ($_.Message -match 'from (\d+\.\d+\.\d+\.\d+)') { Add-Choice "$($Matches[1])/32" 'เครื่องที่เคยเชื่อมต่อ' } }
    } catch { }
    return $choices
}

function Select-SshLanSubnet {
    $choices = @(Get-SshLanIpChoices)
    Write-Host '  เลือกหมายเลขของเครื่องที่จะเข้ามา' -ForegroundColor Yellow
    Write-Host ''
    $i = 1
    foreach ($c in $choices) {
        $note = switch -Regex ($c.Note) {
            'whole LAN' { 'ทั้งวงในบ้าน' }
            'current firewall' { 'ที่เปิดไว้อยู่ตอนนี้' }
            'neighbor' { 'เจอในเครือข่าย' }
            'recent SSH' { 'เคยเข้ามาแล้ว' }
            default { $c.Note }
        }
        Write-Host ("  [{0}] " -f $i) -NoNewline -ForegroundColor Green
        Write-Host $c.Cidr -NoNewline -ForegroundColor White
        Write-Host "   $note" -ForegroundColor DarkGray
        $i++
    }
    Write-Host '  [0] ' -NoNewline -ForegroundColor Green
    Write-Host 'พิมพ์ IP เอง' -ForegroundColor White
    Write-Host ''
    $pick = Read-Host '  หมายเลข'
    if ($pick -eq '0') {
        $manual = Read-Host '  IP เช่น 192.0.2.50'
        if ($manual -match '^\d+\.\d+\.\d+\.\d+$') { return "$manual/32" }
        if ($manual -match '^\d+\.\d+\.\d+\.\d+/\d+$') { return $manual }
        throw 'รูปแบบ IP ไม่ถูก'
    }
    $n = 0
    if (-not [int]::TryParse($pick, [ref]$n) -or $n -lt 1 -or $n -gt $choices.Count) { throw 'เลือกหมายเลขในรายการ' }
    return $choices[$n - 1].Cidr
}

function Get-SshLanAutoPublicKey {
    $dir = Join-Path $env:USERPROFILE '.ssh'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $prefer = @(
        (Join-Path $dir 'id_ed25519.pub'),
        (Join-Path $dir "$($script:SshLanCfg.identityFile).pub")
    )
    $found = $prefer | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $found) {
        $found = @(Get-ChildItem -LiteralPath $dir -Filter '*.pub' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
    }
    $made = $false
    if (-not $found) {
        $priv = Join-Path $dir 'id_ed25519'
        Show-SshLanMotion -Label 'กำลังสร้างกุญแจ' -Ms 600
        $madeKey = New-SshLanKey $priv "$env:USERNAME@$env:COMPUTERNAME"
        if (-not $madeKey) { throw 'สร้างกุญแจไม่สำเร็จ' }
        $found = "$priv.pub"
        $made = $true
    }
    $line = (Resolve-SshLanPublicKey -Path $found)
    Write-Host $(if ($made) { '  สร้างกุญแจให้แล้ว' } else { '  ใช้กุญแจที่มีอยู่แล้ว' }) -ForegroundColor Green
    Write-Host "  $found" -ForegroundColor DarkGray
    Show-SshLanFingerprint -Pub $line
    return $line
}

function Start-SshLanEnable {
    $steps = @('เลือก IP ที่เข้าได้', 'เตรียมกุญแจให้', 'เปิดใช้')
    Show-SshLanSteps -Title 'เปิดใช้' -Now 1 -Labels $steps
    $sn = Select-SshLanSubnet
    Show-SshLanMotion -Label "เลือก $sn"
    Show-SshLanSteps -Title 'เปิดใช้' -Now 2 -Labels $steps
    $pub = Get-SshLanAutoPublicKey
    Show-SshLanMotion -Label 'ตรวจกุญแจ'
    Show-SshLanSteps -Title 'เปิดใช้' -Now 3 -Labels $steps
    Show-SshLanMotion -Label 'กำลังเปิดใช้' -Ms 900
    Invoke-SshLanHarden -SubnetIn $sn -Line $pub
    $ip = Get-SshLanPrimaryLanIp
    Write-Host ''
    Write-Host '  เสร็จแล้ว ไม่ต้องกดเมนู 2' -ForegroundColor Green
    if ($ip) {
        Write-Host "  IP เครื่องนี้ตอนนี้: $ip (DHCP เปลี่ยนได้ — client รันเมนู [1] จะหา IP ให้)" -ForegroundColor Cyan
    }
    Write-Host "  จากเครื่องที่จะเข้า: ssh-lan.ps1 เมนู [1] หรือ  ssh $($script:SshLanCfg.hostAlias) hostname" -ForegroundColor Yellow
    Write-Host "  ssh $($script:SshLanCfg.hostAlias) hostname" -ForegroundColor White
    Write-Host ''
}

function Start-SshLanDisable {
    $steps = @('ดูว่าจะปิดอะไร', 'ยืนยัน', 'ปิด')
    Show-SshLanSteps -Title 'ถอน' -Now 1 -Labels $steps
    Write-Host '  [1] ปิดรับเข้า ยังเก็บโปรแกรมไว้' -ForegroundColor Yellow
    Write-Host '  [2] ปิดรับเข้า และถอนโปรแกรม SSH Server' -ForegroundColor Red
    Write-Host '  [0] กลับ' -ForegroundColor DarkGray
    Write-Host ''
    $mode = Read-Host '  หมายเลข'
    if ($mode -eq '0') { return }
    if ($mode -ne '1' -and $mode -ne '2') { throw 'เลือก 1 หรือ 2' }
    Show-SshLanSteps -Title 'ถอน' -Now 2 -Labels $steps
    Write-Host '  พิมพ์ YES เพื่อยืนยัน' -ForegroundColor Yellow
    $y = Read-Host '  '
    if ($y -ne 'YES') { Write-Host '  ยกเลิก' -ForegroundColor DarkGray; return }
    Show-SshLanSteps -Title 'ถอน' -Now 3 -Labels $steps
    Show-SshLanMotion -Label 'กำลังปิด' -Ms 900
    if ($mode -eq '2') { Invoke-SshLanRemove -Uninstall } else { Invoke-SshLanRemove }
    Write-Host ''
    Write-Host '  ปิดแล้ว เครื่องนี้ไม่รับ SSH จากวง LAN' -ForegroundColor Green
    Write-Host ''
}

function Get-SshLanPrimaryLanIp {
    $cands = New-Object System.Collections.Generic.List[object]
    foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
        if ($nic.NetworkInterfaceType -eq [System.Net.NetworkInformation.NetworkInterfaceType]::Loopback) { continue }
        foreach ($addr in $nic.GetIPProperties().UnicastAddresses) {
            if ($addr.Address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
            $ip = $addr.Address.ToString()
            if ((Test-SshLanPrivateIp $ip) -and $ip -notmatch '^169\.254\.') {
                $cands.Add([pscustomobject]@{ IPAddress = $ip; InterfaceAlias = $nic.Name })
            }
        }
    }
    if ($cands.Count -eq 0) { return $null }
    $pref = $cands | Where-Object { $_.InterfaceAlias -match 'Ethernet|Wi-Fi|WiFi|อีเทอร์|以太' } | Select-Object -First 1
    if ($pref) { return $pref.IPAddress }
    return $cands[0].IPAddress
}

function Test-SshLanPort([string]$Ip, [int]$Port = 22, [int]$Ms = 500) {
    $client = New-Object System.Net.Sockets.TcpClient
    try { return ($client.ConnectAsync($Ip, $Port).Wait($Ms) -and $client.Connected) } catch { return $false } finally { $client.Close() }
}

# every address in the local /24 that answers on port 22 (shortcut: /24 only, even on a wider network)
function Find-SshLanSshHosts {
    $jobs = New-Object System.Collections.Generic.List[object]
    $own = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { Test-SshLanPrivateIp $_.IPAddress }).IPAddress
    foreach ($mine in $own) {
        $base = ($mine -split '\.')[0..2] -join '.'
        foreach ($n in 1..254) {
            $ip = "$base.$n"
            if ($own -contains $ip) { continue }
            $client = New-Object System.Net.Sockets.TcpClient
            $jobs.Add([pscustomobject]@{ Ip = $ip; Client = $client; Task = $client.ConnectAsync($ip, 22) })
        }
    }
    Start-Sleep -Milliseconds 900
    $open = @($jobs | Where-Object { $_.Task.IsCompleted -and -not $_.Task.IsFaulted -and $_.Client.Connected } | ForEach-Object { $_.Ip })
    foreach ($j in $jobs) { $j.Client.Close() }
    return $open
}

function Find-SshLanServerIp {
    $cfg = $script:SshLanCfg
    $known = New-Object System.Collections.Generic.List[string]
    if ($env:SSH_SERVER_IP) { $known.Add($env:SSH_SERVER_IP) }
    $conf = Join-Path $env:USERPROFILE '.ssh\config'
    if (Test-Path -LiteralPath $conf) {
        $q = [regex]::Escape($cfg.hostAlias)
        $block = [regex]::Match((Get-Content -LiteralPath $conf -Raw), "(?ms)^Host\s+$q\b.*?(?=^Host\s|\z)")
        $m = [regex]::Match($block.Value, '(?m)^\s*HostName\s+(\S+)')
        if ($m.Success) { $known.Add($m.Groups[1].Value) }
    }
    foreach ($ip in @($cfg.serverIpSearch)) { if ($ip) { $known.Add([string]$ip) } }
    if ($cfg.serverHost) { $known.Add([string]$cfg.serverHost) }
    foreach ($target in ($known | Select-Object -Unique)) {
        if (-not (Test-SshLanPort $target)) { continue }
        try {
            $a = [System.Net.Dns]::GetHostAddresses($target) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
            if ($a) { return $a.IPAddressToString }
        } catch { }
        return $target
    }

    # nothing known answered: look at the whole local network and keep the host our key opens
    $found = @(Find-SshLanSshHosts)
    if ($found.Count -le 1) { return ($found | Select-Object -First 1) }
    $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    $key = Join-Path $env:USERPROFILE ".ssh\$($cfg.identityFile)"
    if ((Test-Path -LiteralPath $ssh) -and (Test-Path -LiteralPath $key)) {
        foreach ($ip in $found) {
            & $ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o LogLevel=ERROR -o IdentitiesOnly=yes -i $key "$($cfg.serverUser)@$ip" exit 2>$null
            if ($LASTEXITCODE -eq 0) { return $ip }
        }
    }
    return $found[0]
}

function Test-SshLanIsServer {
    [bool](Get-Service sshd -ErrorAction SilentlyContinue)
}

function Backup-SshLanFile([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        Copy-Item -LiteralPath $Path -Destination ($Path + '.bak-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) -Force
    }
}

function Set-EditorPlatform([string]$Path) {
    $alias = $script:SshLanCfg.hostAlias
    $q = [regex]::Escape($alias)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $enc = New-Object System.Text.UTF8Encoding $true
    if (-not (Test-Path -LiteralPath $Path)) {
        $text = "{`r`n  `"remote.SSH.remotePlatform`": {`r`n    `"$alias`": `"windows`"`r`n  }`r`n}`r`n"
        [System.IO.File]::WriteAllText($Path, $text, $enc)
        return 'สร้างใหม่'
    }
    Backup-SshLanFile $Path
    $text = [System.IO.File]::ReadAllText($Path)
    $text2 = [regex]::Replace($text, "(`"$q`"\s*:\s*)`"(linux|mac|windows)`"", '${1}"windows"')
    if ($text2 -notmatch "`"$q`"\s*:\s*`"windows`"") {
        if ($text2 -match '"remote\.SSH\.remotePlatform"\s*:\s*\{') {
            $text2 = [regex]::Replace($text2, '("remote\.SSH\.remotePlatform"\s*:\s*\{)', "`$1`r`n    `"$alias`": `"windows`",", 1)
        } else {
            $idx = $text2.LastIndexOf('}')
            if ($idx -lt 0) { throw "ไฟล์ตั้งค่าไม่ใช่ JSON: $Path" }
            $head = $text2.Substring(0, $idx).TrimEnd()
            $comma = ''
            if ($head -match '[^\s\{\[]$') { $comma = ',' }
            $text2 = $head + "$comma`r`n  `"remote.SSH.remotePlatform`": { `"$alias`": `"windows`" }`r`n" + $text2.Substring($idx)
        }
    }
    [System.IO.File]::WriteAllText($Path, $text2, $enc)
    if ($text2 -eq $text) { return 'ตั้งไว้แล้ว' }
    return 'แก้แล้ว'
}

function Set-ClientSshConfig {
    $cfgData = $script:SshLanCfg
    $alias = $cfgData.hostAlias
    $q = [regex]::Escape($alias)
    $dir = Join-Path $env:USERPROFILE '.ssh'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $cfg = Join-Path $dir 'config'
    $serverIp = Find-SshLanServerIp
    if (-not $serverIp) { throw 'ไม่พบเซิร์ฟเวอร์ที่เปิดพอร์ต 22 ในวง LAN — เปิดเครื่องรับ SSH ก่อน หรือใส่ IP ใน serverIpSearch ของ config.json' }
    $block = @"
Host $alias $serverIp
  HostName $serverIp
  User $($cfgData.serverUser)
  IdentityFile ~/.ssh/$($cfgData.identityFile)
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
"@
    if (-not (Test-Path -LiteralPath $cfg)) {
        [System.IO.File]::WriteAllText($cfg, $block + "`r`n")
        return "สร้างใหม่ (HostName $serverIp)"
    }
    $text = [System.IO.File]::ReadAllText($cfg)
    if ($text -match "(?m)^Host\s+$q\b") {
        Backup-SshLanFile $cfg
        $text = [regex]::Replace($text, "(?m)^Host\s+$q[^\r\n]*", "Host $alias $serverIp")
        $text = [regex]::Replace($text, '(?m)(^\s*HostName\s+)\d+\.\d+\.\d+\.\d+', "`${1}$serverIp", 1)
        [System.IO.File]::WriteAllText($cfg, $text)
        return "อัปเดต IP → $serverIp"
    }
    Backup-SshLanFile $cfg
    [System.IO.File]::AppendAllText($cfg, "`r`n" + $block + "`r`n")
    return "เพิ่มแล้ว (HostName $serverIp)"
}

function Repair-ThisClient {
    $steps = @('ตั้งโปรแกรมให้รู้ว่าเป็น Windows', 'จัดไฟล์ SSH', 'ตรวจกุญแจ', 'ทดสอบเชื่อมต่อ')
    Show-SshLanSteps -Title 'จัดการเครื่องนี้' -Now 1 -Labels $steps
    Show-SshLanFill -Label 'VS Code / Cursor'
    foreach ($pair in @(
            @{ Name = 'VS Code'; Path = (Join-Path $env:APPDATA 'Code\User\settings.json') },
            @{ Name = 'Cursor'; Path = (Join-Path $env:APPDATA 'Cursor\User\settings.json') }
        )) {
        if ($pair.Name -eq 'Cursor' -and -not (Test-Path -LiteralPath (Split-Path $pair.Path))) { continue }
        $r = Set-EditorPlatform $pair.Path
        Write-Host "  $($pair.Name): $r" -ForegroundColor Green
    }
    Show-SshLanSteps -Title 'จัดการเครื่องนี้' -Now 2 -Labels $steps
    Show-SshLanFill -Label 'ไฟล์ SSH'
    Write-Host "  $(Set-ClientSshConfig)" -ForegroundColor Green
    Show-SshLanSteps -Title 'จัดการเครื่องนี้' -Now 3 -Labels $steps
    Show-SshLanFill -Label 'กุญแจ'
    $key = Join-Path $env:USERPROFILE ".ssh\$($script:SshLanCfg.identityFile)"
    $pub = "$key.pub"
    if ((Test-Path -LiteralPath $key) -and (Test-Path -LiteralPath $pub)) {
        ssh-keygen -lf $key | Out-Host
        ssh-keygen -lf $pub | Out-Host
    } else {
        Write-Host '  ยังไม่มีคู่กุญแจ' -ForegroundColor Yellow
        if ($env:SSH_LAN_UI) { $y = 'Y' } else { $y = Read-Host '  สร้างคู่ใหม่ให้เลยไหม [Y/n]' }
        if ($y -notmatch '^[nN]') {
            New-Item -ItemType Directory -Force -Path (Split-Path $key) | Out-Null
            Show-SshLanMotion -Label 'สร้างกุญแจ' -Ms 500
            if (-not (New-SshLanKey $key "$env:USERNAME@$env:COMPUTERNAME")) { throw 'สร้างกุญแจไม่สำเร็จ' }
            Write-Host '  นำบรรทัดนี้ไปเพิ่มบนเครื่องรับ SSH (ปุ่ม เพิ่มกุญแจเครื่องอื่น)' -ForegroundColor Yellow
            Get-Content -LiteralPath $pub | Out-Host
        }
    }
    Show-SshLanSteps -Title 'จัดการเครื่องนี้' -Now 4 -Labels $steps
    Show-SshLanFill -Label 'เชื่อมต่อ'
    $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    if (Test-Path $ssh) { & $ssh -o BatchMode=yes -o ConnectTimeout=8 $script:SshLanCfg.hostAlias hostname }
    Write-Host ''
    Write-Host "  เสร็จ ปิด VS Code แล้วเปิดใหม่ แล้วเชื่อม $($script:SshLanCfg.hostAlias)" -ForegroundColor Green
    Write-Host ''
}

# --- pairing: put this machine's key on another machine (Windows, Linux or macOS) ---
# Every machine keeps its own key pair. Only public keys travel; no private key is ever copied.

# Windows PowerShell 5.1 drops an empty argument, so the empty passphrase goes through a raw argument string
function New-SshLanKey([string]$Path, [string]$Comment) {
    $p = Start-Process -FilePath ssh-keygen -ArgumentList "-q -t ed25519 -N `"`" -f `"$Path`" -C `"$Comment`"" -NoNewWindow -Wait -PassThru
    return ($p.ExitCode -eq 0 -and (Test-Path -LiteralPath "$Path.pub"))
}

function Get-SshLanOwnKey {
    $dir = Join-Path $env:USERPROFILE '.ssh'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $key = Join-Path $dir $script:SshLanCfg.identityFile
    if (-not (Test-Path -LiteralPath "$key.pub")) {
        if (-not (New-SshLanKey $key "$env:USERNAME@$env:COMPUTERNAME-ssh-lan")) { throw 'สร้างกุญแจไม่สำเร็จ' }
    }
    return $key
}

# a public key line is data, but it ends up inside a command on another machine: only known-safe characters pass
function Test-SshLanPublicKeyLine([string]$Line) {
    return [bool]($Line -match '^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp\d{3}) [A-Za-z0-9+/=]+( [A-Za-z0-9@._-]+)?$')
}

function ConvertTo-SshLanEncodedCommand([string]$Script) {
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))
}

# ssh in a window of its own: the target's password is typed there, this program never sees it
function Invoke-SshLanSshWindow([string[]]$SshArgs) {
    $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    $quoted = ($SshArgs | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }) -join ' '
    $enc = ConvertTo-SshLanEncodedCommand "& '$ssh' $quoted; exit `$LASTEXITCODE"
    $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList '-NoProfile', '-EncodedCommand', $enc -PassThru
    # wait without freezing the window when the app is the caller (Update-Ui exists only there)
    while (-not $p.HasExited) {
        if (Get-Command Update-Ui -CommandType Function -ErrorAction SilentlyContinue) { Update-Ui }
        Start-Sleep -Milliseconds 150
    }
    $p.WaitForExit()
    return $p.ExitCode
}

# one Host block per paired machine in ~/.ssh/config, replaced when it is already there
function Add-SshLanHostEntry([string]$Alias, [string]$HostName, [string]$User, [string]$Key) {
    $cfg = Join-Path $env:USERPROFILE '.ssh\config'
    $text = if (Test-Path -LiteralPath $cfg) { [IO.File]::ReadAllText($cfg) } else { '' }
    if ($text) { Backup-SshLanFile $cfg }
    $q = [regex]::Escape($Alias)
    $text = [regex]::Replace($text, "(?ms)^Host\s+$q\s*\r?\n.*?(?=^Host\s|\z)", '')
    $block = "Host $Alias`r`n  HostName $HostName`r`n  User $User`r`n  IdentityFile ~/.ssh/$(Split-Path -Leaf $Key)`r`n  IdentitiesOnly yes`r`n  StrictHostKeyChecking accept-new`r`n"
    [IO.File]::WriteAllText($cfg, $text.TrimEnd() + $(if ($text.Trim()) { "`r`n`r`n" } else { '' }) + $block)
}

function Show-SshLanFoundHosts {
    Write-Host 'กำลังสแกนหาเครื่องที่เปิดพอร์ต 22 ในวง LAN...'
    $found = @(Find-SshLanSshHosts)
    if ($found.Count -eq 0) { Write-Host ' [!] ไม่พบเครื่องที่เปิดรับ SSH'; return }
    foreach ($ip in $found) { Write-Host "  พบ $ip" }
    Write-Host 'พิมพ์ผู้ใช้@IP ของเครื่องที่ต้องการในช่อง แล้วกดจับคู่'
}

function Invoke-SshLanPair {
    param([string]$Target, [string]$User, [string]$Alias, [switch]$Both)
    if ($Target -match '^([^@\s]+)@(.+)$') { $User = $Matches[1]; $Target = $Matches[2] }
    if ($Target -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') { throw 'ชื่อหรือ IP ของเครื่องปลายทางไม่ถูกต้อง' }
    if (-not $User) { $User = $script:SshLanCfg.serverUser }
    if ($User -notmatch '^[A-Za-z0-9._-]+$') { throw 'ชื่อผู้ใช้ของเครื่องปลายทางไม่ถูกต้อง' }
    if ($Alias -and $Alias -notmatch '^[A-Za-z0-9._-]+$') { throw 'ชื่อเรียก (alias) ใช้ได้เฉพาะ a-z 0-9 . _ -' }
    if (-not (Test-SshLanPort $Target 22 1500)) { throw "เครื่อง $Target ไม่ตอบที่พอร์ต 22 — เปิดรับ SSH บนเครื่องนั้นก่อน" }

    $key = Get-SshLanOwnKey
    $pub = (Get-Content -LiteralPath "$key.pub" -TotalCount 1).Trim()
    if (-not (Test-SshLanPublicKeyLine $pub)) { throw 'รูปแบบ public key ไม่ถูกต้อง' }

    $sys32 = Join-Path $env:SystemRoot 'System32\OpenSSH'
    $ssh = Join-Path $sys32 'ssh.exe'
    # the server's own banner tells Windows (OpenSSH_for_Windows) from Linux and macOS, which take the same commands
    $banner = (& (Join-Path $sys32 'ssh-keyscan.exe') -T 3 $Target 2>&1 | Out-String)
    $isWindows = $banner -match '(?i)for_windows'
    Write-Host ('เครื่องปลายทาง: ' + $(if ($isWindows) { 'Windows' } else { 'Linux / macOS' }))

    if ($isWindows) {
        $remote = 'powershell -NoProfile -EncodedCommand ' + (ConvertTo-SshLanEncodedCommand @"
`$ProgressPreference='SilentlyContinue'; `$k='$pub'; `$adm=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
`$f=if(`$adm){Join-Path `$env:ProgramData 'ssh\administrators_authorized_keys'}else{Join-Path `$env:USERPROFILE '.ssh\authorized_keys'}
New-Item -Force -ItemType Directory (Split-Path `$f)|Out-Null
if(-not(Test-Path `$f) -or -not(Select-String -LiteralPath `$f -SimpleMatch -Quiet `$k)){Add-Content -LiteralPath `$f -Value `$k -Encoding ascii}
if(`$adm){icacls `$f /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'|Out-Null}
"@)
    } else {
        $remote = "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; grep -qxF '$pub' ~/.ssh/authorized_keys || echo '$pub' >> ~/.ssh/authorized_keys"
    }

    Write-Host 'ใส่รหัสผ่านของเครื่องปลายทางในหน้าต่างที่เปิดขึ้น (โปรแกรมนี้ไม่เห็นรหัสผ่าน)'
    $code = Invoke-SshLanSshWindow @('-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=10', "$User@$Target", $remote)
    if ($code -ne 0) { throw "ใส่กุญแจที่เครื่องปลายทางไม่สำเร็จ (ssh ออกด้วยรหัส $code) — ตรวจชื่อผู้ใช้/รหัสผ่าน และดูว่าเครื่องนั้นยังเปิดให้ล็อกอินด้วยรหัสผ่านอยู่" }

    # prove it: the key alone must open the door now
    $common = @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'IdentitiesOnly=yes', '-i', $key, "$User@$Target")
    $name = @(& $ssh @common hostname 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'ใส่กุญแจแล้ว แต่ยังเข้าด้วยกุญแจไม่ได้ — เครื่องปลายทางอาจไม่ยอมรับ public key' }
    if (-not $Alias) { $Alias = (("$($name | Select-Object -First 1)").Trim().ToLower() -replace '[^a-z0-9-]', '-').Trim('-') }
    if (-not $Alias) { $Alias = $Target }
    Add-SshLanHostEntry $Alias $Target $User $key
    Write-Host " [✓] จับคู่สำเร็จ: เครื่องนี้เข้า $Target ได้แล้ว ลอง  ssh $Alias"

    if (-not $Both) { return }

    # the other way round: take the target's PUBLIC key (made there if it has none) and allow it here
    $leaf = Split-Path -Leaf $key
    if ($isWindows) {
        $fetch = 'powershell -NoProfile -EncodedCommand ' + (ConvertTo-SshLanEncodedCommand @"
`$ProgressPreference='SilentlyContinue'; `$k=Join-Path `$env:USERPROFILE '.ssh$leaf'
if(-not(Test-Path "`$k.pub")){New-Item -Force -ItemType Directory (Split-Path `$k)|Out-Null; Start-Process ssh-keygen -ArgumentList "-q -t ed25519 -N `"`" -f `"`$k`"" -NoNewWindow -Wait}
Get-Content "`$k.pub" -TotalCount 1
"@)
    } else {
        $fetch = "mkdir -p ~/.ssh; test -f ~/.ssh/$leaf.pub || ssh-keygen -q -t ed25519 -N '' -f ~/.ssh/$leaf; head -n1 ~/.ssh/$leaf.pub"
    }
    $theirs = ("$(& $ssh @common $fetch 2>$null | Select-Object -First 1)").Trim()
    if (-not (Test-SshLanPublicKeyLine $theirs)) { throw 'ดึง public key ของเครื่องปลายทางไม่สำเร็จ' }
    if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
        Write-Host ' [!] เครื่องนี้ยังไม่ได้ติดตั้ง OpenSSH Server จึงยังให้เครื่องนั้นเข้ามาไม่ได้ (ติดตั้งแล้วกดจับคู่อีกครั้ง)'
        return
    }
    $info = Get-SshLanAdminKeyFile -User $env:USERNAME
    if ($info.IsAdminUser -and -not (Test-SshLanAdmin)) { throw 'ต้องเปิดโปรแกรมแบบผู้ดูแลก่อน จึงจะให้เครื่องนั้นเข้ามาที่เครื่องนี้ได้' }
    [void](Add-SshLanKeyLine -Path $info.Path -Key $theirs)
    if ($info.IsAdminUser) { Set-SshLanKeyAcl -Path $info.Path }
    $me = Get-SshLanPrimaryLanIp
    Write-Host " [✓] เครื่องนั้นเข้าเครื่องนี้ได้แล้ว: ที่เครื่องนั้นพิมพ์  ssh $env:USERNAME@$me"
}

function Show-SshLanMenu {
    Clear-Host
    $server = Test-SshLanIsServer
    $role = if ($server) { 'เครื่องรับ SSH' } else { 'เครื่องที่ใช้เชื่อมต่อ' }
    $adm = if ($server) { if (Test-SshLanAdmin) { 'สิทธิ์ผู้ดูแล' } else { 'ยังไม่ใช่ผู้ดูแล' } } else { 'ไม่ต้องใช้สิทธิ์ผู้ดูแล' }
    Write-Host ''
    Write-Host '  +--------------------------------+' -ForegroundColor Magenta
    Write-Host '  |  SSH ในบ้าน' -ForegroundColor Cyan
    Write-Host "  |  $($env:COMPUTERNAME)  $role" -ForegroundColor White
    Write-Host "  |  $adm" -ForegroundColor DarkGray
    Write-Host '  +--------------------------------+' -ForegroundColor Magenta
    Write-Host ''
    Write-Host '  [1]  จัดการให้ครบ' -ForegroundColor Green
    if ($server) {
        Write-Host '       เปิดรับ, กุญแจเดียว, ปิดรหัสผ่าน' -ForegroundColor DarkGray
        Write-Host '  [2]  ใส่กุญแจบนเครื่องนี้อีกครั้ง (ไม่บังคับ)' -ForegroundColor Yellow
        Write-Host '  [3]  ดูสถานะ' -ForegroundColor Cyan
        Write-Host '  [4]  ถอน' -ForegroundColor Red
    } else {
        Write-Host '       ตั้ง Windows, จัด SSH, ทดสอบเข้าเครื่องรับ SSH' -ForegroundColor DarkGray
        Write-Host '  [2]  ทดสอบเชื่อมต่ออีกครั้ง' -ForegroundColor Cyan
    }
    Write-Host '  [0]  ออก' -ForegroundColor DarkGray
    Write-Host ''
}

function Start-SshLanTui {
    Show-SshLanBoot
    while ($true) {
        Show-SshLanMenu
        Write-Host '  > ' -NoNewline -ForegroundColor Cyan
        $c = Read-Host
        try {
            $server = Test-SshLanIsServer
            switch ($c) {
                '1' { if ($server) { Start-SshLanEnable } else { Repair-ThisClient }; Pause }
                '2' {
                    if ($server) { Invoke-SshLanAddClient }
                    else {
                        Show-SshLanFill -Label 'ทดสอบ'
                        $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
                        if (Test-Path $ssh) { & $ssh -o BatchMode=yes -o ConnectTimeout=8 $script:SshLanCfg.hostAlias hostname }
                    }
                    Pause
                }
                '3' { if ($server) { Get-SshLanStatus; Pause } }
                '4' { if ($server) { Start-SshLanDisable; Pause } }
                '0' { return }
                default { Write-Host '  กดหมายเลขในเมนู' -ForegroundColor Yellow; Start-Sleep -Milliseconds 600 }
            }
        } catch {
            Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
            Pause
        }
    }
}

# --- entry (ข้ามเมื่อ UI dot-source ฟังก์ชันเข้ามา) ---
if ($env:SSH_LAN_UI -ne '1' -and $MyInvocation.InvocationName -ne '.') {
if ($Action) {
    switch ($Action) {
        'help' { Show-SshLanMenu }
        'status' { Get-SshLanStatus }
        'add-client' { Invoke-SshLanAddClient -Path $MyPubKeyPath -Line $MyPubKey }
        'harden' {
            if (-not $Subnet) { throw 'Pass -Subnet, e.g. 192.0.2.0/24' }
            Invoke-SshLanHarden -SubnetIn $Subnet -Path $MyPubKeyPath -Line $MyPubKey
        }
        'remove' { Invoke-SshLanRemove -Uninstall:$UninstallServer }
        'client' { Repair-ThisClient }
        'pair' { if ($Target) { Invoke-SshLanPair -Target $Target -User $AsUser -Alias $Alias -Both:$Both } else { Show-SshLanFoundHosts } }
    }
} else {
    Start-SshLanTui
}
}
