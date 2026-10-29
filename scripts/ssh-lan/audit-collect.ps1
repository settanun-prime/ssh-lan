# --- audit: collect facts about one machine (read-only) ---
# The Windows collector is one self-contained script: it runs here as is, and on a paired machine through ssh -EncodedCommand

# which firewall rule lets a listening port in, and from where. Rules come pre-filtered to the active profile.
# Names and enums only: DisplayName changes with the Windows display language
function Get-SshLanPortExposure([int]$Port, [string]$Program, [object[]]$Rules, [string]$ListenAddress, [string[]]$Services = @()) {
    if ($ListenAddress -match '^(127\.|::1$)') { return @{ exposure = 'local'; rule = $null } }
    $hits = @(foreach ($r in $Rules) {
        if (-not $r.enabled -or "$($r.direction)" -ne 'Inbound') { continue }
        # a Store-app rule only lets that app in; a service rule only that service
        if ($r.package) { continue }
        if ($r.service -and "$($r.service)" -ne '*' -and -not @($Services | Where-Object { "$_" -eq "$($r.service)" })) { continue }
        $portOk = $false
        foreach ($lp in @($r.localPorts)) {
            $lp = "$lp"
            if ($lp -eq 'Any' -or $lp -eq "$Port") { $portOk = $true; break }
            if ($lp -match '^(\d+)-(\d+)$' -and $Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { $portOk = $true; break }
        }
        if (-not $portOk) { continue }
        $prog = "$($r.program)"
        if ($prog -and $prog -ne 'Any' -and [IO.Path]::GetFileNameWithoutExtension([Environment]::ExpandEnvironmentVariables($prog)) -ne $Program) { continue }
        $r
    })
    $block = @($hits | Where-Object { "$($_.action)" -eq 'Block' }) | Select-Object -First 1
    if ($block) { return @{ exposure = 'blocked'; rule = $block.name } }
    $allow = @($hits | Where-Object { "$($_.action)" -eq 'Allow' })
    if (-not $allow) { return @{ exposure = 'blocked'; rule = $null } }
    # a rule bound to the Tailscale adapter or to this PC's tailnet addresses (Tailscale's own "allow all") only opens the port to the tailnet
    $tailnetOnly = {
        param($r)
        $ifs = @($r.interfaces | Where-Object { $_ })
        $las = @($r.localAddresses | Where-Object { $_ -and "$_" -ne '*' })
        ($ifs -and -not @($ifs | Where-Object { "$_" -notmatch 'tailscale' })) -or
        ($las -and -not @($las | Where-Object { "$_" -notmatch '^(100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|fd7a:115c:a1e0:)' }))
    }
    $wide = @($allow | Where-Object { -not (& $tailnetOnly $_) })
    foreach ($r in $wide) {
        if (@($r.remote | Where-Object { "$_" -in 'Any', '*' })) { return @{ exposure = 'any'; rule = $r.name } }
    }
    foreach ($r in $wide) {
        if (@($r.remote | Where-Object { "$_" -notmatch '^100\.64\.0\.0/(10|255\.192\.0\.0)$' })) { return @{ exposure = 'lan'; rule = $r.name } }
    }
    return @{ exposure = 'tailscale'; rule = $allow[0].name }
}

function Get-SshLanTempRuleNamesFromRules([object[]]$Rules) {
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        $name = ''
        if ($r -is [hashtable]) {
            if ($r.ContainsKey('Name') -and "$($r['Name'])") { $name = [string]$r['Name'] }
            elseif ($r.ContainsKey('name') -and "$($r['name'])") { $name = [string]$r['name'] }
        } else {
            $nameProp = $r.PSObject.Properties['Name']
            $lower = $r.PSObject.Properties['name']
            if ($nameProp -and "$($nameProp.Value)") { $name = [string]$nameProp.Value }
            elseif ($lower -and "$($lower.Value)") { $name = [string]$lower.Value }
        }
        if ($name -like 'sshlan-temp-*') { [void]$list.Add($name) }
    }
    return $list.ToArray()
}

function Get-SshLanWindowsFactsScript {
    $exposure = 'function Get-SshLanPortExposure {' + ${function:Get-SshLanPortExposure}.ToString() + '}'
    $temps = 'function Get-SshLanTempRuleNamesFromRules {' + ${function:Get-SshLanTempRuleNamesFromRules}.ToString() + '}'
    return $exposure + "`n" + $temps + @'

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$cp = Get-NetConnectionProfile | Where-Object { "$($_.IPv4Connectivity)" -ne 'Disconnected' } | Select-Object -First 1
$profile = switch ("$($cp.NetworkCategory)") { 'Public' { 'Public' } 'Private' { 'Private' } 'DomainAuthenticated' { 'Domain' } default { $null } }
# the firewall COM API: every rule with its ports, addresses and program in one call, readable without admin
# (Get-NetFirewall*Filter -All is denied to normal users and rule-by-rule takes minutes)
$fwp = New-Object -ComObject HNetCfg.FwPolicy2
$bit = @{ Domain = 1; Private = 2; Public = 4 }[[string]$profile]
if (-not $bit) { $bit = [int]$fwp.CurrentProfileTypes }
$fwOn = try { [bool]$fwp.FirewallEnabled($bit) } catch { $null }
$tempPick = New-Object System.Collections.Generic.List[object]
$rules = @(foreach ($r in $fwp.Rules) {
    [void]$tempPick.Add(@{ name = [string]$r.Name })
    if ($r.Direction -ne 1 -or -not $r.Enabled -or -not ($r.Profiles -band $bit) -or $r.Protocol -notin 6, 256) { continue }
    @{ name = $r.Name; enabled = $true; direction = 'Inbound'; action = $(if ($r.Action -eq 1) { 'Allow' } else { 'Block' }); profiles = "$($r.Profiles)"
       localPorts = @(if (-not $r.LocalPorts -or $r.LocalPorts -eq '*') { 'Any' } else { $r.LocalPorts -split ',' })
       remote = @(if (-not $r.RemoteAddresses -or $r.RemoteAddresses -eq '*') { 'Any' } else { $r.RemoteAddresses -split ',' })
       program = $(if ($r.ApplicationName) { $r.ApplicationName } else { 'Any' })
       interfaces = @($r.Interfaces | Where-Object { $_ })
       localAddresses = @(if ($r.LocalAddresses -and $r.LocalAddresses -ne '*') { $r.LocalAddresses -split ',' })
       # Store-app rules: a package id, or (older ones) just an owning user and no program path
       package = $(if ($r.LocalAppPackageId) { [string]$r.LocalAppPackageId } elseif ($r.LocalUserOwner -and -not $r.ApplicationName) { "owner $($r.LocalUserOwner)" } else { '' })
       service = [string]$r.serviceName }
})
$tempRules = @(Get-SshLanTempRuleNamesFromRules $tempPick.ToArray())
# which services live in each process, for rules bound to one service (svchost hosts many)
$svc = @{}
foreach ($s in Get-CimInstance Win32_Service -Filter 'ProcessId > 0') { $svc[[int]$s.ProcessId] = @($svc[[int]$s.ProcessId]) + $s.Name | Where-Object { $_ } }
$seen = @{}
$listeners = @(foreach ($c in Get-NetTCPConnection -State Listen | Sort-Object { $_.LocalAddress -match '^(127\.|::1)' }) {
    $p = [int]$c.LocalPort
    if ($seen.ContainsKey($p)) { continue }
    $seen[$p] = $true
    $name = if ($c.OwningProcess -eq 4) { 'System' } else { (Get-Process -Id $c.OwningProcess).Name }
    if (-not $name) { $name = 'ไม่ทราบ' }
    $e = Get-SshLanPortExposure $p $name $rules $c.LocalAddress @($svc[[int]$c.OwningProcess])
    @{ port = $p; address = $c.LocalAddress; process = $name; exposure = $e.exposure; rule = $e.rule }
})
$sshd = $null
if (Get-Service sshd) {
    $cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
    $m = [regex]::Match([string](Get-Content -LiteralPath $cfg -Raw), '(?im)^\s*PasswordAuthentication\s+(yes|no)')
    # sshd takes the first value it reads; unset means yes
    $sshd = if ($m.Success) { $m.Groups[1].Value -eq 'yes' } elseif (Test-Path -LiteralPath $cfg) { $true } else { $null }
}
$smb = Get-SmbServerConfiguration
$ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdpTcp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$ip = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' } | Select-Object -First 1)[0]
$nic = if ($ip) { Get-NetAdapter -InterfaceIndex $ip.InterfaceIndex } else { $null }
$media = switch -Regex ("$($nic.PhysicalMediaType)") { '802\.3' { 'wired' } '802\.11' { 'wifi' } default { $null } }
@{
    machine = $env:COMPUTERNAME; hostname = $env:COMPUTERNAME; ip = $ip.IPAddress; member = $true; os = 'Windows'; profile = $profile
    firewallOn = $fwOn
    tempRules = @($tempRules)
    listeners = $listeners; sshdPassword = $sshd
    smb1 = $(if ($smb) { [bool]$smb.EnableSMB1Protocol } else { $null })
    rdp = $(if ($ts) { @{ on = ($ts.fDenyTSConnections -eq 0); nla = ($rdpTcp.UserAuthentication -eq 1) } } else { $null })
    scannedPorts = @(); chassis = [string]@((Get-CimInstance Win32_SystemEnclosure).ChassisTypes)[0]; media = $media
    server = $(if ($osInfo = Get-CimInstance Win32_OperatingSystem) { [int]$osInfo.ProductType -ne 1 } else { $null })
} | ConvertTo-Json -Depth 5 -Compress
'@
}

# ConvertFrom-Json gives PSCustomObject; the rest of the audit works on hashtables
function ConvertTo-SshLanHashtable($Object) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [Management.Automation.PSCustomObject]) {
        $h = @{}
        foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = ConvertTo-SshLanHashtable $p.Value }
        return $h
    }
    if ($Object -is [Array]) { return , @($Object | ForEach-Object { ConvertTo-SshLanHashtable $_ }) }
    return $Object
}

function Get-SshLanWindowsFacts {
    $json = & ([scriptblock]::Create((Get-SshLanWindowsFactsScript)))
    return ConvertTo-SshLanHashtable ($json | ConvertFrom-Json)
}

# --- Linux: one sh script prints raw sections; parsing stays here so it can be tested on saved output ---
function Get-SshLanLinuxFactsScript {
    $sh = @'
S=''; if sudo -n true 2>/dev/null; then S='sudo -n'; fi
echo '### os'; ( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-$(uname -s)}" )
echo '### ss'; $S ss -ltnp 2>/dev/null || ss -ltn
echo '### ufw'
if [ -x /usr/sbin/ufw ] || [ -f /etc/ufw/ufw.conf ]; then
  grep -i '^ENABLED=' /etc/ufw/ufw.conf 2>/dev/null
  [ -n "$S" ] && $S /usr/sbin/ufw status verbose 2>/dev/null
else echo none; fi
echo '### sshd'
if [ -x /usr/sbin/sshd ]; then
  echo present
  $S /usr/sbin/sshd -T 2>/dev/null | grep -i '^passwordauthentication' ||
    cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | grep -i '^[[:space:]]*passwordauthentication'
fi
echo '### chassis'; cat /sys/class/dmi/id/chassis_type 2>/dev/null
echo '### target'; systemctl get-default 2>/dev/null
echo '### host'; hostname 2>/dev/null
echo '### media'
D=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
if [ -n "$D" ]; then if [ -d "/sys/class/net/$D/wireless" ]; then echo wifi; elif [ -e "/sys/class/net/$D/device" ]; then echo wired; fi; fi
'@
    return $sh -replace "`r", ''
}

function ConvertFrom-SshLanLinuxFacts([string]$Text, [string]$Machine, [string]$Ip) {
    $sec = @{}
    $cur = $null
    foreach ($line in ($Text -replace "`r", '') -split "`n") {
        if ($line -match '^### (\w+)') { $cur = $Matches[1]; $sec[$cur] = New-Object System.Collections.Generic.List[string]; continue }
        if ($cur -and $line.Trim()) { $sec[$cur].Add($line) }
    }
    $ufw = @($sec['ufw'])
    $tempSeen = @{}
    $tempRules = New-Object System.Collections.Generic.List[string]
    foreach ($l in @($ufw)) {
        if ($l -match '\s+#\s*(sshlan-temp-\d{1,5}-\d{12})\s*$') {
            $tempName = $Matches[1]
            if (-not $tempSeen.ContainsKey($tempName)) {
                $tempSeen[$tempName] = $true
                [void]$tempRules.Add($tempName)
            }
        }
    }
    $fwOn = $null
    if (@($ufw | Where-Object { $_ -match '^Status: active|^ENABLED=yes' })) { $fwOn = $true }
    if (@($ufw | Where-Object { $_ -match '^Status: inactive|^ENABLED=no' })) { $fwOn = $false }
    # ufw rules in the same shape as Windows rules, so one exposure function serves both
    $rules = $null
    if ($fwOn -and @($ufw | Where-Object { $_ -match '^Status: active' })) {
        $rules = @(foreach ($l in $ufw) {
            $bare = [regex]::Replace([string]$l, '\s+#.*$', '')
            if ($bare -notmatch '^(\S+(?: \(v6\))?)\s+(ALLOW|DENY|REJECT|LIMIT)(?: IN)?\s+(.+?)\s*$') { continue }
            $to = $Matches[1] -replace ' \(v6\)', ''; $act = $Matches[2]; $from = $Matches[3] -replace ' \(v6\)', ''
            if ($to -eq 'OpenSSH') { $to = '22/tcp' }
            if ($to -match '/udp$' -or $to -notmatch '^(\d+)(?::(\d+))?(/tcp)?$') { continue }
            $port = if ($Matches[2]) { "$($Matches[1])-$($Matches[2])" } else { $Matches[1] }
            @{ name = "ufw $to $act $from"; enabled = $true; direction = 'Inbound'; action = $(if ($act -in 'ALLOW', 'LIMIT') { 'Allow' } else { 'Block' })
               profiles = 'Any'; localPorts = @($port); remote = @($(if ($from -eq 'Anywhere') { 'Any' } else { $from })); program = 'Any' }
        })
        if (@($ufw | Where-Object { $_ -match '^Default:.*allow \(incoming\)' })) {
            $rules += @{ name = 'ufw default allow'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = 'Any'; localPorts = @('Any'); remote = @('Any'); program = 'Any' }
        }
    }
    $seen = @{}
    $parsed = @(foreach ($l in @($sec['ss'])) {
        $c = -split $l
        if ($c[0] -ne 'LISTEN' -or $c[3] -notmatch '^(.*):(\d+)$') { continue }
        $port = [int]$Matches[2]
        $addr = $Matches[1] -replace '\]?%.*$', '' -replace '^\[|\]$', ''
        $iface = if ($c[3] -match '%([^:\]]+)') { $Matches[1] } else { '' }
        $proc = if ($l -match 'users:\(\("([^"]+)"') { $Matches[1] } else { 'ไม่ทราบ' }
        [pscustomobject]@{ port = $port; address = $addr; iface = $iface; process = $proc; local = ($addr -match '^(127\.|::1$)') }
    })
    $listeners = @(foreach ($p in $parsed | Sort-Object local) {
        if ($seen.ContainsKey($p.port)) { continue }
        $seen[$p.port] = $true
        if ($p.local) { $e = @{ exposure = 'local'; rule = $null } }
        elseif ($p.iface -match 'tailscale' -or $p.address -match '^(100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|fd7a:115c:a1e0:)') { $e = @{ exposure = 'tailscale'; rule = $null } }
        elseif ($null -ne $rules) { $e = Get-SshLanPortExposure $p.port $p.process $rules $p.address }
        # shortcut: ufw off, missing or unreadable (no sudo) counts as open to everyone; nftables/iptables are not read
        else { $e = @{ exposure = 'any'; rule = $null } }
        @{ port = $p.port; address = $p.address; process = $p.process; exposure = $e.exposure; rule = $e.rule }
    })
    $sshd = $null
    if (@($sec['sshd']) -contains 'present') {
        $m = @($sec['sshd'] | Where-Object { $_ -match '^\s*passwordauthentication\s+(yes|no)' }) | Select-Object -First 1
        # sshd takes the first value it reads; unset means yes
        $sshd = if ($m) { $m -match '(?i)\s(yes)\s*$' } else { $true }
    }
    $chassis = @($sec['chassis'])[0]
    $target = [string]@($sec['target'])[0]
    return @{
        machine = $Machine; hostname = [string]@($sec['host'])[0]; ip = $Ip; member = $true; os = [string]@($sec['os'])[0]; profile = $null; firewallOn = $fwOn
        tempRules = @($tempRules.ToArray())
        listeners = $listeners; sshdPassword = $sshd; smb1 = $null; rdp = $null; scannedPorts = @()
        chassis = $(if ($chassis) { [string]$chassis } else { $null })
        # no desktop session to boot into = a server (spec: systemctl get-default)
        server = $(if ($target) { $target.Trim() -eq 'multi-user.target' } else { $null })
        media = $(switch ([string]@($sec['media'])[0]) { 'wifi' { 'wifi' } 'wired' { 'wired' } default { $null } })
    }
}

# ssh with stdin read from a file: Windows' ssh.exe never sends stdin that arrives through a pipe, so the remote side waits forever
function Invoke-SshLanSshCapture([string[]]$SshArgs, [string]$Stdin, [int]$TimeoutSec = 18, [string]$Exe = (Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe')) {
    $tmp = Join-Path $env:TEMP ('ssh-lan-' + [guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllText("$tmp.in", $Stdin)
        $argLine = ($SshArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
        $p = Start-Process -FilePath $Exe -ArgumentList $argLine -WindowStyle Hidden -PassThru `
            -RedirectStandardInput "$tmp.in" -RedirectStandardOutput "$tmp.out" -RedirectStandardError "$tmp.err"
        $null = $p.Handle   # without the handle cached, ExitCode stays empty after exit
        if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch { }; throw "ไม่ตอบภายใน $TimeoutSec วินาที" }
        $p.WaitForExit()
        $read = { param($f) if (Test-Path -LiteralPath $f) { [IO.File]::ReadAllText($f, [Text.Encoding]::UTF8) } else { '' } }
        return [pscustomobject]@{ Code = $p.ExitCode; Out = (& $read "$tmp.out"); Err = (& $read "$tmp.err") }
    } finally {
        Remove-Item -LiteralPath "$tmp.in", "$tmp.out", "$tmp.err" -Force -ErrorAction SilentlyContinue
    }
}

# the Windows collector over SSH: the script goes in on stdin and the JSON comes back, both as base64.
# cmd.exe (the default SSH shell) caps a command line at 8191 characters and the remote code page would mangle Thai text
function Get-SshLanWindowsRemoteCall {
    $boot = '$b = [Console]::In.ReadToEnd(); $s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b.Trim())); ' +
            '$o = & ([scriptblock]::Create($s)) | Out-String; [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($o.Trim()))'
    return @{
        command = 'powershell -NoProfile -NonInteractive -EncodedCommand ' + (ConvertTo-SshLanEncodedCommand $boot)
        stdin = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-SshLanWindowsFactsScript))) + "`n"
    }
}

function ConvertFrom-SshLanWindowsRemoteOutput([string]$Out) {
    $b64 = @($Out -split "`r?`n" | Where-Object { $_ -match '^[A-Za-z0-9+/]{16,}={0,2}$' }) | Select-Object -Last 1
    if (-not $b64) { return $null }
    return ConvertTo-SshLanHashtable ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)) | ConvertFrom-Json)
}

# --- a paired machine (Host alias in ~/.ssh/config): same collectors, run over SSH with this PC's key ---
function Get-SshLanMemberFacts([object]$Device) {
    $alias = [string]$Device.Alias
    if ($alias -notmatch '^[A-Za-z0-9._-]+$') { throw "ชื่อเครื่องไม่ถูกต้อง: $alias" }
    $opts = @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2', $alias)
    $why = { param($r) $l = @("$($r.Err)" -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) | Select-Object -Last 1; if ($l) { $l } else { $(if ($null -eq $r.Code) { 'ssh ไม่ส่งรหัสออกกลับมา' } elseif ($r.Code -eq 255) { 'ssh เชื่อมต่อไม่ได้ (รหัส 255)' } else { "ssh จบด้วยรหัส $($r.Code)" }) } }
    $win = "$($Device.Os)" -match 'Windows'
    if (-not $win) {
        $r = Invoke-SshLanSshCapture ($opts + 'sh -s') (Get-SshLanLinuxFactsScript)
        if ($r.Code -eq 0 -and $r.Out -match '(?m)^### ss') {
            $f = ConvertFrom-SshLanLinuxFacts $r.Out $alias ([string]$Device.Ip)
        } elseif ("$($Device.Os)" -or $r.Code -eq 255) {
            throw "อ่านข้อมูลจาก $alias ไม่ได้: $(& $why $r)"
        } else { $win = $true }   # unknown OS and sh failed: maybe Windows with cmd as the SSH shell
    }
    if ($win) {
        $call = Get-SshLanWindowsRemoteCall
        $r = Invoke-SshLanSshCapture ($opts + $call.command) $call.stdin
        $f = if ($r.Code -eq 0) { ConvertFrom-SshLanWindowsRemoteOutput $r.Out } else { $null }
        if (-not $f) { throw "อ่านข้อมูลจาก $alias ไม่ได้: $(& $why $r)" }
    }
    if ($Device.Ip) { $f.ip = [string]$Device.Ip }
    if ($Device.Name) { $f.machine = [string]$Device.Name }
    return $f
}
