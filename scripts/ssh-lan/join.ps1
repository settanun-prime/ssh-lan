# SSH LAN join: runs on the machine that joins (started by join.cmd, already elevated).
# Steps in order, each logged to join.log; the first one that fails stops the rest.
param(
    [string]$BaseUrl = '',
    [string]$ConfirmCode = '',
    [string]$InviterPubPath = '',
    [string]$InstallFrom = '',
    [switch]$Tailscale,
    [switch]$DryRun,
    [switch]$NoPrompt
)
$ErrorActionPreference = 'Stop'
$env:SSH_LAN_UI = '1'
. (Join-Path $PSScriptRoot '..\ssh-lan-common.ps1')
. (Join-Path $PSScriptRoot 'ssh-lan.ps1')

function Write-SshLanJoinLog([string]$Step, [string]$Result, [string]$Text = '') {
    $line = '{0} {1} {2} {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Step, $Result, $Text
    Add-Content -LiteralPath (Join-Path (Initialize-SshLanDataDirectory) 'join.log') -Value $line -Encoding UTF8
}

# what the inviting PC needs to pair back: names, where to reach this machine, and its PUBLIC key
function New-SshLanHelloPayload {
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { (Test-SshLanPrivateIp $_.IPAddress) -or $_.IPAddress -match '^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.' } |
        ForEach-Object { $_.IPAddress })
    $key = Get-SshLanOwnKey
    return [ordered]@{
        hostname = $env:COMPUTERNAME
        user     = $env:USERNAME
        ips      = $ips
        pubkey   = (Get-Content -LiteralPath "$key.pub" -TotalCount 1).Trim()
        os       = 'Windows'
        chassis  = [string]@((Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue).ChassisTypes)[0]
    }
}

# installing OpenSSH Server adds a rule open to any address; only the LAN and Tailscale may reach port 22
function Set-SshLanJoinFirewall {
    Get-NetFirewallRule -Name '*OpenSSH-Server*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Get-NetFirewallRule -Name sshd-lan -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -Name sshd-lan -DisplayName 'OpenSSH LAN' -Protocol TCP -LocalPort 22 -Action Allow -RemoteAddress LocalSubnet, '100.64.0.0/10' -Profile Any | Out-Null
}

# USB join has no way to call the inviter: leave the hello where the inviter can read it over SSH later
function Save-SshLanHelloFile {
    $path = Join-Path (Initialize-SshLanDataDirectory) 'hello.json'
    [IO.File]::WriteAllText($path, (New-SshLanHelloPayload | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
    return $path
}

function Invoke-SshLanJoin {
    param([string]$BaseUrl, [string]$ConfirmCode, [string]$InviterPubPath, [string]$InstallFrom, [switch]$Tailscale, [switch]$DryRun, [switch]$NoPrompt)
    $mode = if ($DryRun) { '(dry-run)' } else { '' }
    function Step([string]$Name, [string]$Thai, [scriptblock]$Do) {
        Write-Host "  $Thai..."
        try {
            if (-not $DryRun) { & $Do }
            Write-SshLanJoinLog $Name 'ok' $mode
        } catch {
            Write-SshLanJoinLog $Name 'fail' $_.Exception.Message
            Write-Host " [!] $Thai ไม่สำเร็จ: $($_.Exception.Message)"
            throw
        }
    }

    # always runs, also in a dry run: a wrong or missing inviter key must stop everything
    try {
        if (-not (Test-Path -LiteralPath $InviterPubPath)) { throw "ไม่พบกุญแจของเครื่องแม่: $InviterPubPath" }
        $inviterPub = (Get-Content -LiteralPath $InviterPubPath -TotalCount 1).Trim()
        if (-not (Test-SshLanPublicKeyLine $inviterPub)) { throw 'กุญแจของเครื่องแม่ผิดรูปแบบ' }
        $code = Get-SshLanConfirmCode $inviterPub
        if ($code -ne $ConfirmCode) { throw "รหัสยืนยันไม่ตรง ($code ≠ $ConfirmCode) — อย่าติดตั้งต่อ" }
        Write-Host ''
        Write-Host "  รหัสยืนยัน: $code   ต้องตรงกับหน้าจอของเครื่องที่เชิญ" -ForegroundColor Yellow
        if (-not $NoPrompt -and (Read-Host '  ตรงกันไหม [y/N]') -notmatch '^[yY]') { throw 'ผู้ใช้ยกเลิก' }
        Write-SshLanJoinLog 'confirm' 'ok' $mode
    } catch {
        Write-SshLanJoinLog 'confirm' 'fail' $_.Exception.Message
        throw
    }

    $installDir = Join-Path $env:LOCALAPPDATA 'Programs\SSH LAN'
    Step 'install' 'ติดตั้ง SSH LAN' {
        New-Item -ItemType Directory -Force -Path $installDir | Out-Null
        foreach ($item in 'scripts', 'assets', 'VERSION', 'LICENSE', 'SSH LAN.exe') {
            $src = Join-Path $InstallFrom $item
            if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $installDir -Recurse -Force }
        }
    }
    Step 'openssh' 'ติดตั้งและเปิด OpenSSH Server' {
        if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
            Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
        }
        Set-Service sshd -StartupType Automatic
        Start-Service sshd
    }
    Step 'firewall' 'อนุญาตพอร์ต 22 เฉพาะวง LAN และ Tailscale' { Set-SshLanJoinFirewall }
    Step 'authorize' 'อนุญาตกุญแจของเครื่องแม่' {
        $info = Get-SshLanAdminKeyFile -User $env:USERNAME
        [void](Add-SshLanKeyLine -Path $info.Path -Key $inviterPub)
        if ($info.IsAdminUser) { Set-SshLanKeyAcl -Path $info.Path }
    }
    Step 'ownkey' 'สร้างกุญแจของเครื่องนี้' { [void](Get-SshLanOwnKey) }
    Step 'hello' 'ส่งกุญแจของเครื่องนี้กลับไปที่เครื่องแม่' {
        if (-not $BaseUrl) {
            [void](Save-SshLanHelloFile)
            Write-Host '  (ชุด USB: ที่เครื่องแม่ สแกน เลือกเครื่องนี้ แล้วกด "จับคู่" ไม่ต้องใส่รหัสผ่าน)'
            return
        }
        $body = New-SshLanHelloPayload | ConvertTo-Json -Compress
        Invoke-RestMethod -Method Post -Uri "${BaseUrl}hello" -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body)) | Out-Null
    }
    if ($Tailscale) {
        Step 'tailscale' 'ติดตั้ง Tailscale' {
            winget install --id Tailscale.Tailscale -e --silent --accept-package-agreements --accept-source-agreements
            & (Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe') up
        }
    }
    if (-not $DryRun) { Write-Host "  รหัสกุญแจของเครื่องนี้: $(Get-SshLanConfirmCode (Get-Content -LiteralPath "$(Get-SshLanOwnKey).pub" -TotalCount 1))  เครื่องแม่จะถามให้เทียบรหัสนี้" -ForegroundColor Yellow }
    Write-Host ' [✓] เครื่องนี้พร้อมแล้ว เครื่องแม่จะจับคู่ให้ (รหัสผ่านยังใช้ได้ เว้นแต่เครื่องแม่เลือกใช้กุญแจอย่างเดียว)'
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SshLanJoin @PSBoundParameters
}
