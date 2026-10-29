# SSH LAN — one script, menu TUI or CLI. Run on the Windows machine that ACCEPTS ssh (server).
#Requires -Version 5.1
param(
    [ValidateSet('', 'help', 'status', 'harden', 'add-client', 'remove', 'client', 'pair', 'scan', 'discoverable', 'wake', 'run', 'diagnose', 'invite', 'audit')]
    [string]$Action = '',
    [string]$LoginUser = $env:USERNAME,
    [string]$Subnet = '',
    [string]$MyPubKeyPath = '',
    [string]$MyPubKey = '',
    [string]$Target = '',
    [string]$AsUser = '',
    [string]$Alias = '',
    [string]$Range = '',
    [string]$Mac = '',
    [string]$Command = '',
    [int]$Minutes = 15,
    [string]$Usb = '',
    [switch]$Tailscale,
    [switch]$KeyOnly,
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
        Add-Choice (ConvertTo-SshLanCidr $a.IPAddress $a.PrefixLength) 'ทั้งวง LAN · แนะนำ'
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
        # this app probes port 22 of its own PC often: read far enough back that real logins are not pushed out
        $log = @(Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 1000 -ErrorAction SilentlyContinue | ForEach-Object { $_.Message })
        foreach ($ip in Get-SshLanLoginSources $log @($local | ForEach-Object { $_.IPAddress })) { Add-Choice "$ip/32" 'เครื่องที่เคยเชื่อมต่อ' }
    } catch { }
    return $choices
}

# addresses that really tried to log in (accepted or failed), newest first; this PC's own addresses and loopback left out
function Get-SshLanLoginSources([string[]]$Messages, [string[]]$Self) {
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($m in $Messages) {
        if ("$m" -notmatch '(Accepted|Failed) \S+ for \S+ from (\d+\.\d+\.\d+\.\d+)') { continue }
        $ip = $Matches[2]
        if ($ip -match '^127\.' -or @($Self) -contains $ip -or $out.Contains($ip)) { continue }
        $out.Add($ip)
    }
    return $out.ToArray()
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
    $skip = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($e in Get-SshLanExtraIps) { [void]$skip.Add($e) }
    foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
        if ($nic.NetworkInterfaceType -eq [System.Net.NetworkInformation.NetworkInterfaceType]::Loopback) { continue }
        foreach ($addr in $nic.GetIPProperties().UnicastAddresses) {
            if ($addr.Address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
            $ip = $addr.Address.ToString()
            if ((Test-SshLanPrivateIp $ip) -and $ip -notmatch '^169\.254\.') {
                $cands.Add([pscustomobject]@{ IPAddress = $ip; InterfaceAlias = $nic.Name; SkipAsSource = $skip.Contains($ip) })
            }
        }
    }
    return Select-SshLanPrimaryIp $cands.ToArray()
}

# open / refused (something answered no: service off, or that machine's firewall rejects this PC) / timeout (nothing answered).
# Windows retries a refused connection for about 2 s before it reports it, so wait at least 3 s
function Get-SshLanPortState([string]$Ip, [int]$Port, [int]$Ms = 3000) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $t = $client.ConnectAsync($Ip, $Port)
        try { $done = $t.Wait($Ms) } catch { $done = $true }
        if (-not $done) { return 'timeout' }
        if (-not $t.IsFaulted -and $client.Connected) { return 'open' }
        $se = $t.Exception.InnerException -as [System.Net.Sockets.SocketException]
        if ($se -and $se.SocketErrorCode -eq 'ConnectionRefused') { return 'refused' }
        return 'timeout'
    } finally { $client.Close() }
}

# 'static' when the address was set by hand, 'dhcp' when the router handed it out, $null when this PC does not have it
function Get-SshLanIpMode([string]$Ip) {
    $a = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Ip -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $a) { return $null }
    if ("$($a.PrefixOrigin)" -eq 'Manual') { return 'static' }
    return 'dhcp'
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

# --- LAN scanner: every device on the router's network, what it answers on, and how to reach it ---

$script:SshLanScanPorts = @{
    5001 = 'NAS-HTTPS'; 7000 = 'AirPlay'; 8009 = 'Chromecast'
    21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 80 = 'HTTP'; 102 = 'S7'; 443 = 'HTTPS'; 445 = 'SMB'; 502 = 'Modbus'; 515 = 'LPD'; 554 = 'RTSP'
    631 = 'IPP'; 1883 = 'MQTT'; 3389 = 'RDP'; 4840 = 'OPC-UA'; 5000 = 'UPnP/NAS'; 5900 = 'VNC'; 8008 = 'Chromecast'; 8080 = 'HTTP-8080'
    9100 = 'Printer'; 44818 = 'EtherNet/IP'; 47808 = 'BACnet'
}

function ConvertTo-SshLanUInt32([string]$Ip) {
    $b = [Net.IPAddress]::Parse($Ip).GetAddressBytes()
    [Array]::Reverse($b)
    return [BitConverter]::ToUInt32($b, 0)
}

function ConvertFrom-SshLanUInt32([uint32]$N) {
    $b = [BitConverter]::GetBytes($N)
    [Array]::Reverse($b)
    return ([Net.IPAddress]::new($b)).IPAddressToString
}

# addresses to scan: a.b.c.d/nn, a.b.c.x-y or one address; empty = this PC's own network
function Get-SshLanScanTargets([string]$Range) {
    if (-not $Range) {
        # every private network this PC sits on (Ethernet and Wi-Fi); Wi-Fi clients of the same router share the subnet
        $cidrs = @(Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred -ErrorAction SilentlyContinue |
            Where-Object { (Test-SshLanPrivateIp $_.IPAddress) -and $_.IPAddress -notmatch '^169\.254\.' } |
            ForEach-Object { ConvertTo-SshLanCidr $_.IPAddress $_.PrefixLength } | Select-Object -Unique)
        if (-not $cidrs) { throw 'ไม่พบวง LAN ของเครื่องนี้' }
        return @($cidrs | ForEach-Object { Get-SshLanScanTargets $_ } | Select-Object -Unique)
    }
    $Range = $Range.Trim()
    if ($Range -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        $prefix = [int]$Matches[2]
        if ($prefix -gt 32) { throw "ช่วง IP ไม่ถูกต้อง: $Range" }
        # shortcut: wider than /22 is cut to the /24 around the address, a /16 sweep would take minutes
        if ($prefix -lt 22) { $prefix = 24 }
        $start = ConvertTo-SshLanUInt32 (ConvertTo-SshLanCidr $Matches[1] $prefix).Split('/')[0]
        $count = [uint32][math]::Pow(2, 32 - $prefix)
        $offsets = if ($count -le 2) { 0..($count - 1) } else { 1..($count - 2) }
        return @($offsets | ForEach-Object { ConvertFrom-SshLanUInt32 ($start + $_) })
    }
    if ($Range -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$') {
        $lo = [int]$Matches[2]; $hi = [int]$Matches[3]
        if ($lo -gt $hi -or $hi -gt 255) { throw "ช่วง IP ไม่ถูกต้อง: $Range" }
        $base = $Matches[1]
        return @($lo..$hi | ForEach-Object { "$base.$_" } | Where-Object { [Net.IPAddress]::Parse($_) })
    }
    if ($Range -match '^\d{1,3}(\.\d{1,3}){3}$' -and [Net.IPAddress]::Parse($Range)) { return , $Range }
    throw "ช่วง IP ไม่ถูกต้อง: $Range (ใช้แบบ 192.168.1.0/24 หรือ 192.168.1.1-254)"
}

function Get-SshLanSshBanner([string]$Ip) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        if (-not $c.ConnectAsync($Ip, 22).Wait(800)) { return '' }
        $s = $c.GetStream()
        $s.ReadTimeout = 800
        return [string](New-Object IO.StreamReader($s)).ReadLine()
    } catch { return '' } finally { $c.Close() }
}

# NetBIOS node status (UDP 137): Windows machines answer with their name even when the router has no reverse DNS
function Get-SshLanNetBiosNames([string[]]$Ips, [int]$Ms = 1200) {
    $names = @{}
    if (-not $Ips) { return $names }
    $query = [byte[]]((0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, 0x43, 0x4B) + (, 0x41 * 30) + (0, 0, 0x21, 0, 1))
    $u = New-Object System.Net.Sockets.UdpClient(0)
    try {
        # SIO_UDP_CONNRESET off: a host without NetBIOS answers ICMP unreachable, which would break Receive
        [void]$u.Client.IOControl(-1744830452, [byte[]](0, 0, 0, 0), $null)
        foreach ($ip in $Ips) { try { [void]$u.Send($query, $query.Length, $ip, 137) } catch { } }
        $deadline = (Get-Date).AddMilliseconds($Ms)
        while ((Get-Date) -lt $deadline) {
            if ($u.Available -eq 0) { Start-Sleep -Milliseconds 50; continue }
            $from = New-Object System.Net.IPEndPoint([Net.IPAddress]::Any, 0)
            try { $r = $u.Receive([ref]$from) } catch { continue }
            if ($r.Length -lt 57) { continue }
            for ($i = 0; $i -lt $r[56]; $i++) {
                $o = 57 + 18 * $i
                if ($o + 18 -gt $r.Length) { break }
                # suffix 0x00 = workstation name; flag 0x80 = group (workgroup) name, skip it
                if ($r[$o + 15] -eq 0 -and -not ($r[$o + 16] -band 0x80)) {
                    $names[$from.Address.ToString()] = [Text.Encoding]::ASCII.GetString($r, $o, 15).Trim()
                    break
                }
            }
        }
    } finally { $u.Close() }
    return $names
}

# phones and tablets use a private random MAC per Wi-Fi network: the locally-administered bit is set (x2, x6, xA, xE)
function Test-SshLanRandomMac([string]$Mac) {
    return [bool]($Mac -match '^.[26AEae]')
}

# the device's own web page often names it (router model, printer, NAS): Server header and <title>
# shortcut: plain HTTP only, HTTPS needs a TLS handshake; add it when HTTPS-only devices matter
function Get-SshLanHttpHint([string]$Ip, [int]$Port) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        if (-not $c.ConnectAsync($Ip, $Port).Wait(800)) { return '' }
        $s = $c.GetStream()
        $s.ReadTimeout = 1000
        $req = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.0`r`nHost: $Ip`r`nConnection: close`r`n`r`n")
        $s.Write($req, 0, $req.Length)
        $buf = New-Object byte[] 8192
        $n = 0
        try { while ($n -lt $buf.Length) { $r = $s.Read($buf, $n, $buf.Length - $n); if ($r -le 0) { break }; $n += $r } } catch { }
        $text = [Text.Encoding]::UTF8.GetString($buf, 0, $n)
        $title = [regex]::Match($text, '(?is)<title[^>]*>\s*(.*?)\s*</title>').Groups[1].Value -replace '\s+', ' '
        $server = [regex]::Match($text, '(?im)^Server:\s*(.+?)\s*$').Groups[1].Value
        $hint = (@($title, $server) | Where-Object { $_ } | Select-Object -Unique) -join ' / '
        if ($hint.Length -gt 60) { $hint = $hint.Substring(0, 60) + '…' }
        return $hint
    } catch { return '' } finally { $c.Close() }
}

function Get-SshLanOsGuess([string]$Banner, [int[]]$Ports) {
    if ($Banner -match '(?i)for_windows') { return 'Windows' }
    if ($Banner -match '(?i)(ubuntu|debian|raspbian|fedora|alpine|freebsd)') { return (Get-Culture).TextInfo.ToTitleCase($Matches[1].ToLower()) }
    if ($Banner -match '(?i)dropbear') { return 'Linux (embedded)' }
    if ($Banner) { return 'Linux / macOS' }
    if ($Ports -contains 3389 -or $Ports -contains 445) { return 'Windows' }
    return ''
}

# HostName -> Host alias and User of every machine already paired in ~/.ssh/config
function Get-SshLanPairedHosts {
    $map = @{}
    $conf = Join-Path $env:USERPROFILE '.ssh\config'
    if (-not (Test-Path -LiteralPath $conf)) { return $map }
    foreach ($b in [regex]::Matches([IO.File]::ReadAllText($conf), '(?ms)^Host\s+(\S+)[^\n]*\n(.*?)(?=^Host\s|\z)')) {
        $h = [regex]::Match($b.Groups[2].Value, '(?m)^\s*HostName\s+(\S+)')
        $u = [regex]::Match($b.Groups[2].Value, '(?m)^\s*User\s+(\S+)')
        $pt = [regex]::Match($b.Groups[2].Value, '(?m)^\s*Port\s+(\d+)')
        if ($h.Success -and -not $map.ContainsKey($h.Groups[1].Value)) {
            $map[$h.Groups[1].Value] = [pscustomobject]@{
                Alias = $b.Groups[1].Value; User = $u.Groups[1].Value; HostName = $h.Groups[1].Value
                Port = $(if ($pt.Success) { [int]$pt.Groups[1].Value } else { 22 })
            }
        }
    }
    return $map
}

# an ssh-config name belongs to a machine, not an address: once proven on a MAC it follows that MAC (DHCP moves),
# and an address that never proved it only gets the name while it answers on the alias's SSH port
function Resolve-SshLanPair([string]$Ip, [int[]]$Ports, [string]$Mac, [object[]]$Known, [hashtable]$Paired) {
    if ($Mac) {
        $k = @($Known | Where-Object { $_.Mac -eq $Mac -and $_.PairAlias })[0]
        $p = if ($k) { @($Paired.Values | Where-Object { $_.Alias -eq $k.PairAlias })[0] }
        if ($p) { return [pscustomobject]@{ Pair = $p; Moved = ($p.HostName -ne $Ip) } }
    }
    $p = $Paired[$Ip]
    if (-not $p) { return $null }
    # another MAC still holds this alias on a *different* IP → do not steal. Same IP + new MAC (NIC/ARP) may reclaim.
    $heldElsewhere = @($Known | Where-Object {
        $_.PairAlias -eq $p.Alias -and $_.Mac -and $_.Mac -ne $Mac -and $_.Ip -and $_.Ip -ne $Ip -and
        (Test-SshLanRecentlySeen ([string]$_.LastSeen))
    }).Count
    if ($heldElsewhere) { return $null }
    if ($Ports -contains $p.Port) { return [pscustomobject]@{ Pair = $p; Moved = $false } }
    return $null
}

# before 'open SSH' or 'pair': empty when an SSH server answers, otherwise why it cannot work
function Get-SshLanNoSshReason([string]$Ip, [int]$Port = 22) {
    switch (Get-SshLanPortState $Ip $Port 3000) {
        'open' { return '' }
        'refused' { return "$Ip ปฏิเสธพอร์ต ${Port}: เครื่องนั้นไม่ได้เปิด SSH server (Windows: OpenSSH Server, Android: sshd ใน Termux) จึงเปิด SSH หรือจับคู่ไปหาไม่ได้ ถ้าเครื่องนั้นแค่ต่อเข้ามาหาเครื่องนี้ ไม่ต้องจับคู่ฝั่งนี้" }
        default { return "$Ip ไม่มีอะไรตอบที่พอร์ต ${Port}: เครื่องปิด/หลับ หรือไฟร์วอลล์ของเครื่องนั้นทิ้งการเชื่อมต่อ หรือไม่ได้เปิด SSH server" }
    }
}

# devices.json LastSeen: a machine silent for a day is gone from the list (the record stays for Wake-on-LAN)
function Test-SshLanRecentlySeen([string]$LastSeen, [datetime]$Now = (Get-Date), [int]$Hours = 24) {
    $t = [datetime]::MinValue
    if (-not [datetime]::TryParse($LastSeen, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$t)) { return $false }
    return ($Now - $t).TotalHours -le $Hours
}

# another MAC held this IP within a day: a fixed IP inside the router's DHCP pool, handed out while its owner slept
function Get-SshLanIpClash([string]$Ip, [string]$Mac, [object[]]$Known, [datetime]$Now = (Get-Date)) {
    if (-not $Mac) { return $null }
    return @($Known | Where-Object { $_.Ip -eq $Ip -and $_.Mac -and $_.Mac -ne $Mac -and (Test-SshLanRecentlySeen ([string]$_.LastSeen) $Now) })[0]
}

function Get-SshLanIpClashText($Other) {
    $who = if ($Other.Name) { "$($Other.Name) (MAC $($Other.Mac))" } else { "MAC $($Other.Mac)" }
    "IP ชน: $who ก็ใช้ IP $($Other.Ip) ภายใน 24 ชม. ถ้าเครื่องใดตั้ง IP เอง ให้จองไว้ใน router (DHCP reservation) หรือย้ายไปนอกช่วงที่ router แจก ไม่งั้นสองเครื่องจะหลุดสลับกัน"
}

# point an ssh-config Host at the address its machine moved to (backup first, other hosts untouched)
function Set-SshLanHostName([string]$Alias, [string]$Ip, [string]$Path = (Join-Path $env:USERPROFILE '.ssh\config')) {
    $text = [IO.File]::ReadAllText($Path)
    $rx = '(?ms)(^Host\s+' + [regex]::Escape($Alias) + '\b[^\n]*\n(?:(?!^Host\s).)*?^\s*HostName\s+)\S+'
    if (-not [regex]::IsMatch($text, $rx)) { return }
    Backup-SshLanFile $Path
    [IO.File]::WriteAllText($Path, [regex]::Replace($text, $rx, "`${1}$Ip", 1))
}

function Get-SshLanKnownDevicesPath { Join-Path (Initialize-SshLanDataDirectory) 'devices.json' }

# PS 5.1 ConvertFrom-Json of a JSON array often stays one Object[] that @() and the pipeline will not unroll
function ConvertFrom-SshLanJsonList([string]$Text) {
    if (-not "$Text".Trim()) { return @() }
    $raw = $Text | ConvertFrom-Json
    if ($null -eq $raw) { return @() }
    if ($raw -is [System.Array]) { return [object[]]$raw }
    return @($raw)
}

# ranges.json: [{ "cidr": "a.b.c.0/24", "safe": true, "label": "..." }]. A safe range (machines on a production line)
# only gets ARP and slow pings, never a TCP packet. No file = this PC's own network, not safe
function Get-SshLanRangesConfig {
    $path = Join-Path (Get-SshLanDataDirectory) 'ranges.json'
    if (Test-Path -LiteralPath $path) {
        try {
            # Windows PowerShell passes a JSON array down the pipeline as one object: unroll it first
            $items = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
            return @(@($items) | Where-Object { "$($_.cidr)" -match '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$' } |
                ForEach-Object { @{ cidr = [string]$_.cidr; safe = [bool]$_.safe; label = [string]$_.label } })
        } catch { throw "อ่าน $path ไม่ได้: $($_.Exception.Message)" }
    }
    $own = Get-SshLanLocalCidr
    return @(if ($own) { @{ cidr = $own; safe = $false; label = 'วงของเครื่องนี้' } })
}

function Get-SshLanScanPlan([string[]]$Ips, [object[]]$Ranges) {
    $safe = @($Ranges | Where-Object { $_ -and $_.safe })
    return @(foreach ($ip in $Ips) {
        $isSafe = @($safe | Where-Object { Test-SshLanIpInCidr $ip $_.cidr }).Count -gt 0
        @{ ip = $ip; probePorts = -not $isSafe; pingDelayMs = $(if ($isSafe) { 50 } else { 0 }) }
    })
}

# ping + common ports + ARP table at once, like a classic IP scanner; devices seen before stay listed as offline
function Find-SshLanLanDevices([string]$Range) {
    $ips = @(Get-SshLanScanTargets $Range)
    $ports = @($script:SshLanScanPorts.Keys | Sort-Object)
    $plan = @{}
    foreach ($s in Get-SshLanScanPlan $ips (Get-SshLanRangesConfig)) { $plan[$s.ip] = $s }
    $pings = @{}
    $conns = New-Object System.Collections.Generic.List[object]
    foreach ($ip in $ips) {
        if ($plan[$ip].pingDelayMs) { Start-Sleep -Milliseconds $plan[$ip].pingDelayMs }
        $pinger = New-Object System.Net.NetworkInformation.Ping
        $pings[$ip] = [pscustomobject]@{ Pinger = $pinger; Task = $pinger.SendPingAsync($ip, 1200) }
        if (-not $plan[$ip].probePorts) { continue }
        foreach ($p in $ports) {
            $c = New-Object System.Net.Sockets.TcpClient
            $conns.Add([pscustomobject]@{ Ip = $ip; Port = $p; Client = $c; Task = $c.ConnectAsync($ip, $p) })
        }
    }
    Start-Sleep -Milliseconds 1600

    $open = @{}
    foreach ($j in $conns) {
        if ($j.Task.IsCompleted -and -not $j.Task.IsFaulted -and $j.Client.Connected) {
            if (-not $open.ContainsKey($j.Ip)) { $open[$j.Ip] = New-Object System.Collections.Generic.List[int] }
            $open[$j.Ip].Add($j.Port)
        }
        $j.Client.Close()
    }
    $alive = @{}
    $pinged = @{}
    $arped = @{}
    foreach ($ip in $ips) {
        $t = $pings[$ip].Task
        if ($t.IsCompleted -and -not $t.IsFaulted -and "$($t.Result.Status)" -eq 'Success') { $pinged[$ip] = $(if ($t.Result.Options) { [int]$t.Result.Options.Ttl } else { 0 }) }
        if ($open.ContainsKey($ip) -or $pinged.ContainsKey($ip)) { $alive[$ip] = $true }
        $pings[$ip].Pinger.Dispose()
    }

    # the sweep made Windows ARP every address: a fresh entry means the device is there even if it blocks ping and ports
    $macs = @{}
    Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { "$($_.State)" -in 'Reachable', 'Delay', 'Probe', 'Permanent', 'Stale' -and $_.LinkLayerAddress -match '^[0-9A-F]{2}(-[0-9A-F]{2}){5}$' -and $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF|01-00-5E)' } |
        ForEach-Object {
            $macs[$_.IPAddress] = $_.LinkLayerAddress
            if ("$($_.State)" -ne 'Stale' -and $ips -contains $_.IPAddress) { $alive[$_.IPAddress] = $true; $arped[$_.IPAddress] = $true }
        }

    $own = @{}
    foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        # a temporary extra address (SkipAsSource) is this PC too, but not the address it goes by: no row of its own
        if ($a.SkipAsSource) { $alive.Remove($a.IPAddress); continue }
        $nic = Get-NetAdapter -InterfaceIndex $a.InterfaceIndex -ErrorAction SilentlyContinue
        if ($nic) { $own[$a.IPAddress] = $nic.MacAddress }
    }
    foreach ($ip in $ips) { if ($own.ContainsKey($ip)) { $alive[$ip] = $true; $macs[$ip] = $own[$ip] } }
    $gateways = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | ForEach-Object { $_.NextHop })

    $dns = @{}
    foreach ($ip in $alive.Keys) { $dns[$ip] = [System.Net.Dns]::GetHostEntryAsync($ip) }
    # safe ranges get nothing but ARP and ping: no NetBIOS query either
    $netbios = Get-SshLanNetBiosNames @($alive.Keys | Where-Object { $plan[$_].probePorts -ne $false })
    $deadline = (Get-Date).AddMilliseconds(2500)
    while ((Get-Date) -lt $deadline -and @($dns.Values | Where-Object { -not $_.IsCompleted }).Count) { Start-Sleep -Milliseconds 100 }

    $paired = Get-SshLanPairedHosts
    $knownPath = Get-SshLanKnownDevicesPath
    $known = @()
    # Windows PowerShell passes a JSON array down the pipeline as one object: unroll it first
    if (Test-Path -LiteralPath $knownPath) { try { $known = ConvertFrom-SshLanJsonList (Get-Content -LiteralPath $knownPath -Raw -Encoding UTF8) } catch { } }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($ip in $alive.Keys) {
        # evidence first: every column says what proved it; nothing proven stays blank instead of guessed
        $proof = New-Object System.Collections.Generic.List[string]
        $seen = @()
        if ($pinged.ContainsKey($ip)) { $seen += 'ping' }
        if ($arped.ContainsKey($ip)) { $seen += 'ARP' }
        $p = if ($open.ContainsKey($ip)) { @($open[$ip] | Sort-Object) } else { @() }
        if ($p) { $seen += 'port ' + ($p -join ',') }
        if ($seen) { $proof.Add('ตอบ: ' + ($seen -join ' + ')) }
        $t = $dns[$ip]
        $name = ''
        $nameFrom = ''
        if ($t.IsCompleted -and -not $t.IsFaulted -and $t.Result.HostName -ne $ip) { $name = ($t.Result.HostName -split '\.')[0]; $nameFrom = 'DNS'; $proof.Add('ชื่อ: DNS') }
        if (-not $name -and $netbios.ContainsKey($ip)) { $name = $netbios[$ip]; $nameFrom = 'NetBIOS'; $proof.Add('ชื่อ: NetBIOS') }
        $banner = if ($p -contains 22) { Get-SshLanSshBanner $ip } else { '' }
        if ($banner) { $proof.Add($banner.Trim()) }
        $os = Get-SshLanOsGuess $banner $p
        # a machine that told us its OS before (banner while port 22 was open) still is that OS
        $m0 = [string]$macs[$ip]
        $was = @($known | Where-Object { ($m0 -and $_.Mac -eq $m0) -or (-not $m0 -and $_.Ip -eq $ip) })[0]
        # Tailscale often omits LAN endpoints: a name the user (or a prior scan) stored still labels the box and merges the tailnet peer by name
        if (-not $name -and $was -and $was.Name) { $name = [string]$was.Name; $nameFrom = 'บันทึกไว้'; $proof.Add("ชื่อ: $name (บันทึกไว้)") }
        if (-not $os -and $was -and $was.Os) { $os = [string]$was.Os; $proof.Add("ระบบ: $os (จากสแกนครั้งก่อน)") }
        if ($os -and -not $banner) { $proof.Add('ระบบ: เดาจากพอร์ต 445/3389') }
        foreach ($wp in @(80, 8080) | Where-Object { $p -contains $_ }) {
            $hint = Get-SshLanHttpHint $ip $wp
            if ($hint) { $proof.Add("เว็บ ${wp}: $hint"); break }
        }
        if ($own.ContainsKey($ip)) { $name = $env:COMPUTERNAME; $nameFrom = 'เครื่องนี้'; $os = 'Windows' }
        $mac = [string]$macs[$ip]
        $note = if ($own.ContainsKey($ip)) { 'เครื่องนี้' } elseif ($gateways -contains $ip) { 'เราเตอร์' } elseif (Test-SshLanRandomMac $mac) { 'MAC สุ่ม (มือถือ?)' } else { '' }
        # an alias on a port the sweep does not try (Termux 8021) is checked on its own
        $cp = $paired[$ip]
        if ($cp -and $p -notcontains $cp.Port -and $ports -notcontains $cp.Port -and $plan[$ip].probePorts -ne $false -and
            (Get-SshLanPortState $ip $cp.Port 1500) -eq 'open') { $p = @($p) + $cp.Port }
        $hit = Resolve-SshLanPair $ip $p $mac $known $paired
        $pair = if ($hit) { $hit.Pair }
        if ($cp -and -not $hit) { $proof.Add("ไม่ใช่ $($cp.Alias): ไม่ตอบ SSH พอร์ต $($cp.Port) หรือ MAC ไม่ตรงกับที่จับคู่ไว้") }
        if ($hit -and $hit.Moved) {
            try { Set-SshLanHostName $pair.Alias $ip; $proof.Add("$($pair.Alias) ย้าย IP จาก $($pair.HostName): แก้ ~/.ssh/config แล้ว") }
            catch { $proof.Add("$($pair.Alias) ย้าย IP จาก $($pair.HostName) แต่แก้ ~/.ssh/config ไม่ได้") }
        }
        $other = if (-not $own.ContainsKey($ip)) { Get-SshLanIpClash $ip $mac $known }
        $clash = if ($other) { Get-SshLanIpClashText $other } else { '' }
        if ($clash) { $proof.Add($clash) }
        $rows.Add([pscustomobject]@{
            Online = $true; Dot = '#4ADE80'; Name = $name; NameFrom = $nameFrom; Ip = $ip; Mac = $mac; Os = $os; Ttl = [int]$pinged[$ip]
            Ports = [int[]]$p; Services = (($p | ForEach-Object { $script:SshLanScanPorts[$_] }) -join ', ')
            Alias = $(if ($pair) { $pair.Alias } else { '' }); User = $(if ($pair) { $pair.User } else { '' }); Note = $note
            Evidence = ($proof -join ' | '); Clash = $clash
        })
    }
    $seenMacs = @($rows | ForEach-Object { $_.Mac } | Where-Object { $_ })
    foreach ($k in $known) {
        if (-not $k.Ip -or $alive.ContainsKey($k.Ip) -or $ips -notcontains $k.Ip) { continue }
        if ($k.Mac -and $seenMacs -contains $k.Mac) { continue }
        # gone for a day = left the network (or DHCP gave it away): no ghost box
        if (-not (Test-SshLanRecentlySeen ([string]$k.LastSeen))) { continue }
        $pair = if ($k.PairAlias) { @($paired.Values | Where-Object { $_.Alias -eq $k.PairAlias })[0] }
        $rows.Add([pscustomobject]@{
            Online = $false; Dot = '#6B7487'; Name = [string]$k.Name; Ip = [string]$k.Ip; Mac = [string]$k.Mac; Os = [string]$k.Os
            Ports = [int[]]@(); Services = ''; Alias = $(if ($pair) { $pair.Alias } else { '' }); User = $(if ($pair) { $pair.User } else { '' }); Note = 'ออฟไลน์'
            Evidence = 'ไม่ตอบรอบนี้ (เคยเห็นในสแกนก่อน)'
        })
    }

    # remember by MAC (DHCP can move the IP), so Wake-on-LAN still knows a machine that is switched off
    $store = @{}
    foreach ($k in $known) { if ($k.Ip -or $k.Mac) { $store[$(if ($k.Mac) { $k.Mac } else { $k.Ip })] = $k } }
    foreach ($r in $rows) {
        if (-not $r.Online -or $r.Note -eq 'เครื่องนี้') { continue }
        $id = if ($r.Mac) { $r.Mac } else { $r.Ip }
        # a kind the user picked on the map survives every rescan
        # the ssh-config name is kept as PairAlias (bound to this MAC), never as the device's own name
        # Name = last discovered hostname/DNS only. TsPeer = explicit Tailscale link (survives rescan)
        $keptName = if ($r.NameFrom -eq '~/.ssh/config') { '' } elseif ($r.Name) { $r.Name } elseif ($store[$id] -and $store[$id].Name) { [string]$store[$id].Name } else { '' }
        $store[$id] = [pscustomobject]@{
            Ip = $r.Ip; Mac = $r.Mac; Name = $keptName; Os = $r.Os
            Kind = $(if ($store[$id]) { [string]$store[$id].Kind } else { '' })
            TsPeer = $(if ($store[$id] -and $store[$id].TsPeer) { [string]$store[$id].TsPeer } else { '' })
            PairAlias = $(if ($r.Mac) { $r.Alias } else { '' })
            LastSeen = (Get-Date).ToString('o')
        }
    }
    ConvertTo-Json -InputObject @($store.Values) -Depth 3 | Set-Content -LiteralPath $knownPath -Encoding UTF8

    return @($rows | Sort-Object { ConvertTo-SshLanUInt32 $_.Ip })
}

function Show-SshLanScan([string]$Range) {
    foreach ($d in (Find-SshLanLanDevices $Range)) {
        $who = if ($d.Alias) { "ssh $($d.Alias)" } else { '' }
        Write-Host ('{0,-15} {1,-17} {2,-18} {3,-16} {4,-24} {5} {6}' -f $d.Ip, $d.Mac, $d.Name, $d.Os, $d.Services, $d.Note, $who)
        if ($d.Evidence) { Write-Host "    $($d.Evidence)" -ForegroundColor DarkGray }
    }
}

function Send-SshLanWakeOnLan([string]$Mac) {
    $hex = $Mac -replace '[-:.]', ''
    if ($hex -notmatch '^[0-9A-Fa-f]{12}$') { throw "MAC ไม่ถูกต้อง: $Mac" }
    $m = [byte[]]@($hex -split '(..)' | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_, 16) })
    $packet = [byte[]]((, 0xFF * 6) + ($m * 16))
    $targets = @('255.255.255.255')
    $cidr = Get-SshLanLocalCidr
    if ($cidr) {
        $net, $prefix = $cidr.Split('/')
        $targets += ConvertFrom-SshLanUInt32 ((ConvertTo-SshLanUInt32 $net) + [uint32][math]::Pow(2, 32 - [int]$prefix) - 1)
    }
    $u = New-Object System.Net.Sockets.UdpClient
    try {
        $u.EnableBroadcast = $true
        foreach ($t in $targets) { [void]$u.Send($packet, $packet.Length, $t, 9) }
    } finally { $u.Close() }
    Write-Host " [✓] ส่งสัญญาณปลุกไปที่ $Mac แล้ว (เครื่องนั้นต้องเปิด Wake-on-LAN ใน BIOS/การ์ดแลน)"
}

# run one command on a machine over SSH with this PC's key; Target is a Host alias or user@address
function Invoke-SshLanRemote([string]$Target, [string]$Command) {
    if ($Target -notmatch '^([A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*$') { throw "ปลายทางไม่ถูกต้อง: $Target" }
    if (-not $Command.Trim()) { throw 'พิมพ์คำสั่งก่อน' }
    # ssh writes warnings to stderr; under Stop, PowerShell 5.1 would turn each line into a terminating error
    $ErrorActionPreference = 'Continue'
    $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    $opts = @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8')
    if ($Target -match '@') {
        $key = Join-Path $env:USERPROFILE ".ssh\$($script:SshLanCfg.identityFile)"
        $opts += @('-o', 'StrictHostKeyChecking=accept-new', '-o', 'IdentitiesOnly=yes', '-i', $key)
    }
    $out = & $ssh @opts $Target $Command 2>&1
    $code = $LASTEXITCODE
    foreach ($line in $out) { Write-Host "  $line" }
    if ($code -ne 0) { throw "คำสั่งบน $Target จบด้วยรหัส $code — ยังไม่ได้จับคู่ หรือคำสั่งต้องใช้สิทธิ์ที่ไม่มี" }
    Write-Host " [✓] รันบน $Target เสร็จ"
}

# walk the path to a machine one layer at a time and stop at the first one that fails, with that layer's own fix
# -Port only changes the reachability check (step 2); the SSH steps after it use 22
function Test-SshLanReach([string]$Ip, [string]$User, [string]$Alias, [int]$Port = 22) {
    if ($Ip -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') { throw "ปลายทางไม่ถูกต้อง: $Ip" }
    if ($User -and $User -notmatch '^[A-Za-z0-9._-]+$') { throw "ชื่อผู้ใช้ไม่ถูกต้อง: $User" }
    $ping = New-Object System.Net.NetworkInformation.Ping
    try { $ok = "$($ping.Send($Ip, 1000).Status)" -eq 'Success' } catch { $ok = $false } finally { $ping.Dispose() }
    if ($ok) { Write-Host " [✓] 1. ping: ตอบ" } else { Write-Host " [!] 1. ping: ไม่ตอบ (Windows บล็อก ping เป็นค่าเริ่มต้น ไม่ใช่ปัญหาถ้าข้อ 2 ผ่าน)" }

    $state = Get-SshLanPortState $Ip $Port
    $me = Get-SshLanPrimaryLanIp
    if ($state -eq 'refused') {
        Write-Host " [!] 2. พอร์ต ${Port}: เครื่องนั้นปฏิเสธ (ตอบกลับมาว่าไม่รับ)"
        Write-Host "     สาเหตุ: SSH บนเครื่องนั้นไม่ได้รัน หรือไฟร์วอลล์ของเครื่องนั้นไม่อนุญาต IP ของเครื่องนี้ ($me)"
        Write-Host "     ถ้าเพิ่งเปลี่ยน IP เครื่องนี้: เครื่องนั้นอาจอนุญาตแค่ IP เดิม ให้เพิ่ม $me (Linux: sudo ufw allow from $me to any port $Port)"
        return
    }
    if ($state -ne 'open') {
        Write-Host " [!] 2. พอร์ต ${Port}: ไม่มีอะไรตอบ — เครื่องนั้นยังไม่รับ SSH หรือถูกกั้น"
        Write-Host "     แก้: Windows ติดตั้ง OpenSSH Server แล้วกด 'เปิดรับ SSH' ในโปรแกรมนี้ / Linux: sudo apt install openssh-server / macOS: เปิด Remote Login"
        Write-Host "     ถ้าเปิดแล้ว: ไฟร์วอลล์ของเครื่องนั้นทิ้งแพ็กเก็ตเงียบ ๆ หรือเราเตอร์แยกเครื่อง Wi-Fi (AP isolation)"
        return
    }
    Write-Host " [✓] 2. พอร์ต ${Port}: เปิด"
    $banner = Get-SshLanSshBanner $Ip
    $os = Get-SshLanOsGuess $banner @(22)
    Write-Host " [✓] 3. แบนเนอร์: $banner ($os)"

    $ErrorActionPreference = 'Continue'
    $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    $probe = @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=6', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL', '-o', 'LogLevel=ERROR')
    if (-not $User) { $User = $script:SshLanCfg.serverUser }
    $key = Join-Path $env:USERPROFILE ".ssh\$($script:SshLanCfg.identityFile)"
    $dest = if ($Alias) { $Alias } else { "$User@$Ip" }
    $keyArgs = if ($Alias) { @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=6') } elseif (Test-Path -LiteralPath $key) { $probe + @('-o', 'IdentitiesOnly=yes', '-i', $key) } else { $null }
    if ($keyArgs) {
        $null = & $ssh @keyArgs $dest exit 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Host " [✓] 4. กุญแจของเครื่องนี้เข้า $dest ได้ — เชื่อถึงกันแล้ว"; return }
    }
    # ask the server which login methods it offers without trying any
    $methods = (& $ssh @probe -o PreferredAuthentications=none "$User@$Ip" exit 2>&1 | Out-String)
    $offer = [regex]::Match($methods, 'Permission denied \(([^)]*)\)').Groups[1].Value
    Write-Host " [!] 4. กุญแจของเครื่องนี้ยังเข้า $User@$Ip ไม่ได้ (เครื่องนั้นรับ: $(if ($offer) { $offer } else { 'ไม่ทราบ' }))"
    if ($offer -match 'password') {
        Write-Host "     แก้: กด 'จับคู่' ด้วยชื่อผู้ใช้ $User แล้วใส่รหัสผ่านของเครื่องนั้นครั้งเดียว"
    } elseif ($offer -match 'keyboard-interactive') {
        # keyboard-interactive is offered even when password login is off, so it proves nothing either way
        Write-Host "     ไม่แน่ชัดว่ายังใช้รหัสผ่านได้: ลองกด 'จับคู่' ด้วยชื่อผู้ใช้ $User ก่อน"
        Write-Host "     ถ้าไม่ผ่าน: คัดลอก ~/.ssh/$($script:SshLanCfg.identityFile).pub ของเครื่องนี้ไปกด 'เพิ่มกุญแจเครื่องอื่น' บนเครื่องนั้น"
    } else {
        Write-Host "     แก้: เครื่องนั้นปิดล็อกอินด้วยรหัสผ่านแล้ว คัดลอก public key ของเครื่องนี้ (~/.ssh/$($script:SshLanCfg.identityFile).pub) ไปกด 'เพิ่มกุญแจเครื่องอื่น' บนเครื่องนั้น"
        Write-Host "     หรือชื่อผู้ใช้ไม่ถูก: เครื่องนั้นอนุญาตเฉพาะผู้ใช้ใน AllowUsers"
    }
}

function Invoke-SshLanPower([string]$Target, [string]$Os, [switch]$Restart) {
    $cmd = if ($Os -eq 'Windows') { if ($Restart) { 'shutdown /r /t 5' } else { 'shutdown /s /t 5' } }
           elseif ($Restart) { 'sudo -n reboot' } else { 'sudo -n shutdown -h now' }
    Invoke-SshLanRemote $Target $cmd
}

# let other machines on the LAN see this one: Private profile, Network Discovery and file/printer sharing (LocalSubnet only)
function Invoke-SshLanDiscoverable {
    Assert-SshLanAdmin
    $ip = Get-SshLanPrimaryLanIp
    if (-not $ip) { throw 'ไม่พบวง LAN ของเครื่องนี้' }
    $idx = (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $ip).InterfaceIndex
    Set-NetConnectionProfile -InterfaceIndex $idx -NetworkCategory Private
    Write-Host " [✓] ตั้งเครือข่ายนี้เป็น Private"
    # group ids, not names: names change with the Windows display language
    foreach ($g in '@FirewallAPI.dll,-32752', '@FirewallAPI.dll,-28502') {
        Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue | Where-Object { "$($_.Profile)" -match 'Private|Any' } | Enable-NetFirewallRule
    }
    Write-Host " [✓] เปิด Network Discovery, แชร์ไฟล์ และ ping (เฉพาะวง LAN)"
    foreach ($s in 'FDResPub', 'fdPHost', 'SSDPSRV', 'upnphost') {
        try { Set-Service $s -StartupType Automatic; Start-Service $s } catch { Write-Host " [!] เปิดบริการ $s ไม่ได้: $($_.Exception.Message)" }
    }
    Write-Host " [✓] เครื่องอื่นในวง LAN มองเห็นเครื่องนี้แล้ว ($ip)"
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

. (Join-Path $PSScriptRoot 'invite.ps1')
. (Join-Path $PSScriptRoot 'audit-rules.ps1')
. (Join-Path $PSScriptRoot 'audit-collect.ps1')
. (Join-Path $PSScriptRoot 'fleet.ps1')
. (Join-Path $PSScriptRoot 'router.ps1')
. (Join-Path $PSScriptRoot 'audit.ps1')
. (Join-Path $PSScriptRoot 'topology.ps1')
. (Join-Path $PSScriptRoot 'traffic.ps1')
. (Join-Path $PSScriptRoot 'control.ps1')

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
        'scan' { Show-SshLanScan $Range }
        'discoverable' { Invoke-SshLanDiscoverable }
        'wake' { Send-SshLanWakeOnLan $Mac }
        'run' { Invoke-SshLanRemote $Target $Command }
        'diagnose' { Test-SshLanReach $Target $AsUser $Alias }
        'audit' { Show-SshLanAudit $Range }
        'invite' {
            if ($Usb) {
                $p = New-SshLanJoinPackage $Usb '' -Tailscale:$Tailscale
                Write-Host " [✓] ชุดติดตั้งอยู่ที่ $Usb  รหัสยืนยัน $($p.ConfirmCode)"
                Write-Host '  ที่เครื่องใหม่ ดับเบิลคลิก join.cmd (Linux/macOS: sh join.sh)'
                return
            }
            Assert-SshLanAdmin
            $s = Start-SshLanInviteServer -Minutes $Minutes -Tailscale:$Tailscale
            try {
                Write-Host "  Windows: เปิด $($s.Url)join.cmd บนเครื่องใหม่ แล้วดับเบิลคลิกไฟล์ที่ได้"
                Write-Host "  Linux/macOS: curl -fsS $($s.Url)join.sh | sh"
                Write-Host "  รหัสยืนยัน $($s.ConfirmCode)  ใช้ได้ถึง $($s.Expires.ToString('HH:mm'))  (Ctrl+C เพื่อหยุด)"
                while ((Get-Date) -lt $s.Expires) {
                    $h = $null
                    while ($s.Hellos.TryDequeue([ref]$h)) {
                        try { [void](Complete-SshLanJoin $h -KeyOnly:$KeyOnly) } catch { Write-Host " [!] $($_.Exception.Message)" }
                    }
                    Start-Sleep -Milliseconds 500
                }
            } finally { & $s.Stop }
        }
    }
} else {
    Start-SshLanTui
}
}
