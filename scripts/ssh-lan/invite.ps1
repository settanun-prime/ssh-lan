# --- invite: a new machine joins with one touch (a link on the LAN, or a USB/shared folder) ---
# dot-sourced by ssh-lan.ps1 after its own functions, so it can use them

$script:SshLanInviteFiles = @('join.cmd', 'join.sh', 'ssh-lan.zip', 'inviter.pub', 'hello')

function New-SshLanInviteToken {
    $b = New-Object byte[] 16
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    return (($b | ForEach-Object { $_.ToString('x2') }) -join '')
}

# both screens show it, so the person can see the joining PC talks to the real inviter and not an impostor on the LAN
function Get-SshLanConfirmCode([string]$PubKeyLine) {
    $blob = [Convert]::FromBase64String(($PubKeyLine.Trim() -split '\s+')[1])
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash($blob) } finally { $sha.Dispose() }
    return (($h[0..2] | ForEach-Object { $_.ToString('X2') }) -join '')
}

# /t/<token>/<file>: a wrong token or an unlisted file is 404, the right token after expiry is 410
function Resolve-SshLanInviteRequest([string]$Path, [string]$Token, [datetime]$Expires, [datetime]$Now) {
    $notFound = [pscustomobject]@{ Status = 'notfound'; File = '' }
    if ($Path -notmatch '^/t/([0-9a-f]{32})/([A-Za-z.-]+)$') { return $notFound }
    if (-not [string]::Equals($Matches[1], $Token, [StringComparison]::Ordinal)) { return $notFound }
    $file = $Matches[2]
    if ($script:SshLanInviteFiles -cnotcontains $file) { return $notFound }
    if ($Now -gt $Expires) { return [pscustomobject]@{ Status = 'expired'; File = $file } }
    return [pscustomobject]@{ Status = 'ok'; File = $file }
}

# everything a joining machine needs; BaseUrl '' = USB/shared folder, the scripts read the files next to themselves
function New-SshLanJoinPackage([string]$OutDir, [string]$BaseUrl, [switch]$Tailscale) {
    $root = Get-SshLanPackageRoot
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $zip = Join-Path $OutDir 'ssh-lan.zip'
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $z = [IO.Compression.ZipFile]::Open($zip, 'Create')
    try {
        foreach ($item in 'scripts', 'assets', 'VERSION', 'LICENSE', 'SSH LAN.exe') {
            $path = Join-Path $root $item
            if (-not (Test-Path -LiteralPath $path)) { continue }
            $files = if ((Get-Item -LiteralPath $path).PSIsContainer) { Get-ChildItem -LiteralPath $path -Recurse -File } else { Get-Item -LiteralPath $path }
            foreach ($f in $files) {
                $name = $f.FullName.Substring($root.Length).TrimStart('\').Replace('\', '/')
                [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($z, $f.FullName, $name)
            }
        }
    } finally { $z.Dispose() }

    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    $key = Get-SshLanOwnKey
    $pub = (Get-Content -LiteralPath "$key.pub" -TotalCount 1).Trim()
    $code = Get-SshLanConfirmCode $pub
    $ascii = New-Object Text.ASCIIEncoding
    [IO.File]::WriteAllText((Join-Path $OutDir 'inviter.pub'), "$pub`n", $ascii)
    $ts = if ($Tailscale) { '-Tailscale' } else { '' }
    foreach ($t in 'join.cmd', 'join.sh') {
        $text = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "$t.template"))
        $text = $text.Replace('{{BASEURL}}', $BaseUrl).Replace('{{ZIPHASH}}', $hash).Replace('{{CODE}}', $code).Replace('{{TAILSCALE}}', $ts).Replace('{{KEYNAME}}', $script:SshLanCfg.identityFile)
        $text = if ($t -eq 'join.cmd') { $text -replace "`r?`n", "`r`n" } else { $text -replace "`r", '' }
        [IO.File]::WriteAllText((Join-Path $OutDir $t), $text, $ascii)
    }
    $info = [ordered]@{ inviter = $env:COMPUTERNAME; confirmCode = $code; baseUrl = $BaseUrl; zipHash = $hash }
    [IO.File]::WriteAllText((Join-Path $OutDir 'inviter.json'), ($info | ConvertTo-Json), $ascii)
    return [pscustomobject]@{ Dir = $OutDir; ZipHash = $hash; ConfirmCode = $code }
}

# one request at a time, 5 s per client, bodies up to 8 KB; runs in its own runspace and stops itself at expiry
$script:SshLanInviteLoop = {
    param($State, $InvitePath)
    . $InvitePath
    function Send([Net.Sockets.NetworkStream]$S, [int]$Code, [string]$Type, [byte[]]$Body, [string]$Extra = '') {
        $reason = @{ 200 = 'OK'; 400 = 'Bad Request'; 404 = 'Not Found'; 410 = 'Gone'; 413 = 'Payload Too Large' }[$Code]
        $head = "HTTP/1.1 $Code $reason`r`nContent-Type: $Type`r`nContent-Length: $($Body.Length)`r`n$($Extra)Connection: close`r`n`r`n"
        $h = [Text.Encoding]::ASCII.GetBytes($head)
        $S.Write($h, 0, $h.Length)
        $S.Write($Body, 0, $Body.Length)
    }
    $utf8 = [Text.Encoding]::UTF8
    $l = $State.Listener
    try {
        while (-not $State.Stop -and (Get-Date) -lt $State.Expires) {
            if (-not $l.Pending()) { Start-Sleep -Milliseconds 50; continue }
            $c = $l.AcceptTcpClient()
            try {
                $c.SendTimeout = 5000
                $st = $c.GetStream()
                # one 5 s budget for the whole request: a per-read timeout lets a client trickle a byte every few seconds forever
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $budget = { $left = 5000 - $sw.ElapsedMilliseconds; if ($left -le 0) { throw 'too slow' }; $st.ReadTimeout = [int]$left }
                $buf = New-Object byte[] 16384
                $n = 0
                $end = -1
                while ($n -lt 8192) {
                    & $budget
                    $r = $st.Read($buf, $n, 8192 - $n)
                    if ($r -le 0) { break }
                    $n += $r
                    $end = [Text.Encoding]::ASCII.GetString($buf, 0, $n).IndexOf("`r`n`r`n")
                    if ($end -ge 0) { break }
                }
                if ($end -lt 0) { continue }
                $head = [Text.Encoding]::ASCII.GetString($buf, 0, $end)
                if ($head -notmatch '^(GET|POST) (\S+) HTTP/1\.[01]') { continue }
                $method = $Matches[1]
                $req = Resolve-SshLanInviteRequest $Matches[2] $State.Token $State.Expires (Get-Date)
                if ($req.Status -eq 'notfound' -or ($req.File -eq 'hello') -ne ($method -eq 'POST')) {
                    Send $st 404 'text/plain' $utf8.GetBytes('not found'); continue
                }
                if ($req.Status -eq 'expired') {
                    Send $st 410 'text/html; charset=utf-8' $utf8.GetBytes('<meta charset="utf-8"><p>ลิงก์หมดอายุแล้ว ขอลิงก์ใหม่จากเครื่องที่เชิญ</p>'); continue
                }
                if ($req.File -ne 'hello') {
                    $type = @{ 'ssh-lan.zip' = 'application/zip'; 'join.cmd' = 'application/octet-stream' }[$req.File]
                    if (-not $type) { $type = 'text/plain; charset=utf-8' }
                    $extra = if ($req.File -eq 'join.cmd') { "Content-Disposition: attachment; filename=`"join.cmd`"`r`n" } else { '' }
                    Send $st 200 $type ([IO.File]::ReadAllBytes((Join-Path $State.Dir $req.File))) $extra; continue
                }
                $len = if ($head -match '(?im)^Content-Length:\s*(\d+)') { [int64]$Matches[1] } else { 0 }
                if ($len -gt 8192) {
                    # drain what the client is still sending, or it sees a reset instead of the 413
                    $left = [math]::Min($len, 65536) - ($n - ($end + 4))
                    $sink = New-Object byte[] 4096
                    while ($left -gt 0) { & $budget; $r = $st.Read($sink, 0, [int][math]::Min(4096, $left)); if ($r -le 0) { break }; $left -= $r }
                    Send $st 413 'text/plain' $utf8.GetBytes('too large'); continue
                }
                $got = $n - ($end + 4)
                while ($got -lt $len) {
                    & $budget
                    $r = $st.Read($buf, $n, [int]($len - $got))
                    if ($r -le 0) { break }
                    $n += $r
                    $got += $r
                }
                try { $hello = $utf8.GetString($buf, $end + 4, [int]$got) | ConvertFrom-Json } catch { $hello = $null }
                if ($hello -isnot [pscustomobject]) { Send $st 400 'text/plain' $utf8.GetBytes('bad json'); continue }
                Add-Member -InputObject $hello -NotePropertyName remote -NotePropertyValue $c.Client.RemoteEndPoint.Address.ToString() -Force
                $State.Hellos.Enqueue($hello)
                Send $st 200 'text/plain' $utf8.GetBytes('ok')
            } catch {
                # a client that stalls or drops only loses its own request
            } finally { $c.Close() }
        }
    } finally {
        $l.Stop()
        $State.Done = $true
    }
}

function Start-SshLanInviteServer {
    param([int]$Port = 8765, [int]$Minutes = 15, [switch]$NoFirewall, [switch]$Tailscale)
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any, $Port)
    try { $listener.Start() } catch { throw "พอร์ต $Port ถูกโปรแกรมอื่นใช้อยู่ ปิดโปรแกรมนั้นหรือเลือกพอร์ตอื่น" }
    try {
        $token = New-SshLanInviteToken
        $ip = Get-SshLanPrimaryLanIp
        if (-not $ip) { $ip = '127.0.0.1' }
        $url = "http://${ip}:$Port/t/$token/"
        $dir = Join-Path $env:TEMP "sshlan-invite-$token"
        $pkg = New-SshLanJoinPackage $dir $url -Tailscale:$Tailscale
        if (-not $NoFirewall) {
            Get-NetFirewallRule -Name sshlan-invite -ErrorAction SilentlyContinue | Remove-NetFirewallRule
            New-NetFirewallRule -Name sshlan-invite -DisplayName 'SSH LAN invite' -Protocol TCP -LocalPort $Port -Action Allow -RemoteAddress LocalSubnet, '100.64.0.0/10' -Profile Any | Out-Null
        }
    } catch {
        $listener.Stop()
        throw
    }
    $state = [hashtable]::Synchronized(@{
        Listener = $listener; Token = $token; Expires = (Get-Date).AddMinutes($Minutes); Dir = $dir
        Hellos = New-Object 'Collections.Concurrent.ConcurrentQueue[object]'; Stop = $false; Done = $false
    })
    $ps = [powershell]::Create()
    [void]$ps.AddScript($script:SshLanInviteLoop).AddArgument($state).AddArgument((Join-Path $PSScriptRoot 'invite.ps1'))
    $handle = $ps.BeginInvoke()
    $script:SshLanInviteActive = $true
    $stop = {
        $state.Stop = $true
        $deadline = (Get-Date).AddSeconds(3)
        while (-not $state.Done -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 50 }
        try { $state.Listener.Stop() } catch { }
        try { $ps.Dispose() } catch { }
        if (-not $NoFirewall) { Get-NetFirewallRule -Name sshlan-invite -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        $script:SshLanInviteActive = $false
    }.GetNewClosure()
    return [pscustomobject]@{
        Url = $url; Token = $token; Expires = $state.Expires; ConfirmCode = $pkg.ConfirmCode; Dir = $dir
        Hellos = $state.Hellos; State = $state; Stop = $stop
    }
}

# remote harden: password login off, nothing else. Windows: no AllowUsers/AuthenticationMethods (a domain user would be locked
# out); sshd restarts from a SYSTEM task so it cannot stop half way inside this session. Linux: drop-in file checked with sshd -t
# before the reload (a bad option kills sshd on reload), removed if invalid, then sshd -T must really show passwords off
function Get-SshLanHardenCommand([string]$Os) {
    if ($Os -eq 'Windows') {
        $remote = @"
`$env:SSH_LAN_UI='1'; `$r=Join-Path `$env:LOCALAPPDATA 'Programs\SSH LAN\scripts'
. "`$r\ssh-lan-common.ps1"; . "`$r\ssh-lan\ssh-lan.ps1"
Set-SshLanSshdConfig -Settings @{ PasswordAuthentication='no'; KbdInteractiveAuthentication='no'; PubkeyAuthentication='yes'; PermitEmptyPasswords='no'; MaxAuthTries='3' }
Test-SshLanSshdConfig
schtasks /Create /TN SshLanRestartSshd /SC ONCE /ST 23:59 /RU SYSTEM /TR "powershell -NoProfile -Command Restart-Service sshd" /F | Out-Null
schtasks /Run /TN SshLanRestartSshd | Out-Null
"@
        return 'powershell -NoProfile -EncodedCommand ' + (ConvertTo-SshLanEncodedCommand $remote)
    }
    $f = '/etc/ssh/sshd_config.d/10-ssh-lan.conf'
    return "sudo -n mkdir -p /etc/ssh/sshd_config.d && printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' | sudo -n tee $f >/dev/null && " +
        "{ sudo -n sshd -t 2>/dev/null || { printf 'PasswordAuthentication no\n' | sudo -n tee $f >/dev/null; sudo -n sshd -t 2>/dev/null; } || { sudo -n rm -f $f; exit 1; }; } && " +
        "(sudo -n systemctl reload ssh 2>/dev/null || sudo -n systemctl reload sshd) && sudo -n sshd -T 2>/dev/null | grep -qi '^passwordauthentication no'"
}

# a joined machine said hello: check every field, prove our key opens it, pair both ways, then turn its passwords off.
# TestKey / Harden / Authorize are the side-effect steps; tests pass fakes, the app uses the defaults
function Complete-SshLanJoin {
    param([object]$Hello, [scriptblock]$TestKey, [scriptblock]$Harden, [scriptblock]$Authorize, [scriptblock]$Approve, [switch]$KeyOnly)
    $h = [pscustomobject]$Hello
    $ip = [string]$h.remote
    if ([string]$h.hostname -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,62}$') { throw "ชื่อเครื่องไม่ถูกต้อง: $($h.hostname)" }
    if ([string]$h.user -notmatch '^[A-Za-z0-9._-]+$') { throw "ชื่อผู้ใช้ไม่ถูกต้อง: $($h.user)" }
    $tailnet = $ip -match '^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.'
    if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or -not ((Test-SshLanPrivateIp $ip) -or $tailnet)) { throw "ที่อยู่นอกวง LAN/Tailscale: $ip" }
    if (-not (Test-SshLanPublicKeyLine ([string]$h.pubkey))) { throw 'public key ของเครื่องนั้นผิดรูปแบบ' }

    $alias = $h.hostname.ToLower()
    # a hello must never re-point an alias the user already has for another machine
    $cfgPath = Join-Path $env:USERPROFILE '.ssh\config'
    if (Test-Path -LiteralPath $cfgPath) {
        $m = [regex]::Match([IO.File]::ReadAllText($cfgPath), "(?ms)^Host\s+$([regex]::Escape($alias))\s*\r?\n(.*?)(?=^Host\s|\z)")
        $was = [regex]::Match($m.Groups[1].Value, '(?m)^\s*HostName\s+(\S+)').Groups[1].Value
        if ($m.Success -and $was -and $was -ne $ip) { throw "ชื่อ $alias ใช้กับ $was อยู่แล้ว ไม่เปลี่ยนให้เครื่อง $ip — เปลี่ยนชื่อเครื่องนั้นหรือลบ Host $alias ใน ~/.ssh/config ก่อน" }
    }
    # anyone holding the link can say hello: a person approves each machine, comparing the code of ITS key on both screens
    if (-not $Approve) {
        $Approve = {
            param($H, $Code)
            $text = "เครื่อง $($H.hostname) ($($H.remote)) ขอเข้าวง`nรหัสกุญแจของเครื่องนั้น: $Code (ต้องตรงกับหน้าจอเครื่องนั้น)`n`nให้เครื่องนี้กับเครื่องนั้นเข้าหากันด้วย SSH หรือไม่"
            if ($env:SSH_LAN_UI -and ('System.Windows.MessageBox' -as [type])) { return ([Windows.MessageBox]::Show($text, 'SSH LAN', 'YesNo', 'Question') -eq 'Yes') }
            Write-Host $text
            return ((Read-Host '  [y/N]') -match '^[yY]')
        }
    }
    if (-not (& $Approve $h (Get-SshLanConfirmCode ([string]$h.pubkey)))) {
        Write-Host " [!] ไม่อนุญาตเครื่อง $($h.hostname) ($ip) — ไม่ได้เปลี่ยนอะไร"
        return [pscustomobject]@{ Alias = $alias; Ip = $ip; Hardened = $false }
    }

    $key = Get-SshLanOwnKey
    $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    if (-not $TestKey) {
        $TestKey = {
            param($Target)
            $ErrorActionPreference = 'Continue'
            # the joined machine started sshd seconds ago: give it a few tries
            for ($i = 0; $i -lt 3; $i++) {
                $null = & $ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i $key $Target exit 2>$null
                if ($LASTEXITCODE -eq 0) { return $true }
                Start-Sleep -Seconds 2
            }
            return $false
        }.GetNewClosure()
    }
    if (-not $Authorize) {
        $Authorize = {
            param($PubKey)
            if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) { Write-Host ' [!] เครื่องนี้ไม่มี OpenSSH Server เครื่องนั้นจึงยังเข้ามาที่เครื่องนี้ไม่ได้'; return }
            $info = Get-SshLanAdminKeyFile -User $env:USERNAME
            if ($info.IsAdminUser -and -not (Test-SshLanAdmin)) { Write-Host ' [!] เปิดโปรแกรมแบบผู้ดูแล เพื่อให้เครื่องนั้นเข้ามาที่เครื่องนี้ได้'; return }
            [void](Add-SshLanKeyLine -Path $info.Path -Key $PubKey)
            if ($info.IsAdminUser) { Set-SshLanKeyAcl -Path $info.Path }
        }
    }
    if (-not $Harden) {
        $Harden = {
            param($Alias, $Os, $User)
            $ErrorActionPreference = 'Continue'
            $cmd = Get-SshLanHardenCommand $Os
            $null = & $ssh -o BatchMode=yes -o ConnectTimeout=8 $Alias $cmd 2>$null
            if ($LASTEXITCODE -ne 0) { return $false }
            Start-Sleep -Seconds 5
            return $true
        }.GetNewClosure()
    }

    $target = "$($h.user)@$ip"
    if (-not (& $TestKey $target)) {
        Write-Host " [!] กุญแจของเครื่องนี้ยังเข้า $target ไม่ได้ จึงยังไม่ปิดรหัสผ่านบนเครื่องนั้น — กด 'ตรวจว่าทำไมเข้าไม่ได้'"
        return [pscustomobject]@{ Alias = $alias; Ip = $ip; Hardened = $false }
    }
    Add-SshLanHostEntry $alias $ip $h.user $key
    Write-Host " [✓] เครื่องนี้เข้า $alias ($ip) ด้วยกุญแจได้แล้ว"
    & $Authorize ([string]$h.pubkey)
    # password login stays unless the person asked for key-only
    if (-not $KeyOnly) {
        Write-Host " [✓] $alias เข้าได้ทั้งกุญแจและรหัสผ่าน"
        return [pscustomobject]@{ Alias = $alias; Ip = $ip; Hardened = $false }
    }
    $hard = [bool](& $Harden $alias ([string]$h.os) $h.user)
    if ($hard -and -not (& $TestKey $alias)) {
        Write-Host " [!] ปิดรหัสผ่านบน $alias แล้ว แต่กุญแจเข้าไม่ได้ — ตรวจที่เครื่องนั้นทันที"
        $hard = $false
    }
    if ($hard) { Write-Host " [✓] $alias ใช้กุญแจอย่างเดียวแล้ว (ปิดล็อกอินด้วยรหัสผ่าน)" }
    else { Write-Host " [!] ยังปิดรหัสผ่านบน $alias ไม่ได้ (Linux ต้องใช้ sudo แบบไม่ถามรหัส) — ทำเองบนเครื่องนั้น" }
    return [pscustomobject]@{ Alias = $alias; Ip = $ip; Hardened = $hard }
}

# a USB-joined machine already trusts our key and left hello.json behind; read it over SSH.
# remote is the address we scanned, never what the file says
function Get-SshLanRemoteHello([string]$Target, [string]$Ip, [string]$Os, [scriptblock]$Run) {
    if (-not $Run) {
        $Run = {
            param($T, $Cmd)
            $ErrorActionPreference = 'Continue'
            $key = Join-Path $env:USERPROFILE ".ssh\$($script:SshLanCfg.identityFile)"
            $out = & (Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe') -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i $key $T $Cmd 2>$null
            if ($LASTEXITCODE -eq 0) { return ($out -join "`n") }
        }
    }
    $cmd = if ($Os -eq 'Windows') { 'powershell -NoProfile -Command "Get-Content -Raw (Join-Path $env:LOCALAPPDATA ''Ssh-Lan-Prime-Studio\hello.json'')"' } else { 'cat ~/.config/ssh-lan/hello.json' }
    $text = & $Run $Target $cmd
    if (-not $text) { return $null }
    try { $h = $text | ConvertFrom-Json } catch { return $null }
    Add-Member -InputObject $h -NotePropertyName remote -NotePropertyValue $Ip -Force
    return $h
}

# an invite rule left behind by a crash would keep port 8765 open; nothing in this process is inviting, so drop it
function Remove-SshLanStaleInviteRule {
    if ($script:SshLanInviteActive) { return }
    Get-NetFirewallRule -Name sshlan-invite -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
