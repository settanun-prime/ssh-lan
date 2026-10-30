# security audit window, dot-sourced by app.ps1: runs Invoke-SshLanAudit in the background and shows the findings,
# red first. The สั่ง column changes a machine only after a confirm. The audit round itself stays read-only.
# Uses app.ps1's $window, $markup, $root, Add-Log
$script:AuditWin = $null
$script:AuditDot = @{ red = '#F87171'; amber = '#F5C451'; green = '#4ADE80'; gray = '#8F9BB3' }
$script:AuditActPs = $null
$script:AuditActHandle = $null
$script:AuditActTimer = $null
$script:AuditActGen = 0
$script:AuditActRow = $null
$script:AuditQueue = $null
$script:AuditQueueAt = 0
$script:AuditSudoProc = $null

function Find-Audit([string]$Name) { $script:AuditWin.FindName($Name) }

function Test-AuditBusy {
    return [bool]($script:AuditPs -or $script:AuditActPs -or $script:AuditSudoProc)
}

function Update-AuditFixAllButton {
    if (-not $script:AuditWin) { return }
    $btn = Find-Audit 'BtnAuditFixAll'
    $grid = Find-Audit 'FindingGrid'
    if (-not $btn) { return }
    $n = 0
    if ($grid -and $grid.ItemsSource) {
        $n = @($grid.ItemsSource | Where-Object { $_.Color -eq 'red' -and $_.SwitchEnabled }).Count
    }
    $btn.Content = "ปิดทุกพอร์ตที่เสี่ยง ($n)"
    $btn.IsEnabled = ($n -gt 0) -and -not (Test-AuditBusy)
}

function Set-AuditBusy([bool]$Busy) {
    if (-not $script:AuditWin) { return }
    $run = Find-Audit 'BtnAuditRun'
    $probe = Find-Audit 'BtnAuditProbe'
    $grid = Find-Audit 'FindingGrid'
    if ($Busy) {
        if ($run) { $run.IsEnabled = $false }
        if ($probe) { $probe.IsEnabled = $false }
        if ($grid) { $grid.IsEnabled = $false }
        $fix = Find-Audit 'BtnAuditFixAll'
        if ($fix) { $fix.IsEnabled = $false }
        return
    }
    if ($run) { $run.IsEnabled = $true }
    if ($probe) {
        $probe.IsEnabled = @($script:AuditExitNodes).Count -gt 0
        $probe.ToolTip = if ($probe.IsEnabled) { "ใช้ $($script:AuditExitNodes[0]) เป็นทางออกชั่วคราว แล้วเคาะ IP สาธารณะของบ้าน ตั้งค่า exit node คืนเสมอ" }
                         else { 'ต้องมีมือถือ Android ใน Tailscale ที่เปิด "Run as exit node" และออนไลน์อยู่ (ใช้เน็ตมือถือ ไม่ใช่ Wi-Fi บ้าน)' }
    }
    if ($grid) { $grid.IsEnabled = $true }
    Update-AuditFixAllButton
}

function Get-AuditDialogOwner {
    $cands = New-Object System.Collections.Generic.List[object]
    foreach ($w in @($script:AuditWin, $script:MapWin)) { if ($w) { [void]$cands.Add($w) } }
    if (Get-Variable -Name window -Scope Script -ErrorAction SilentlyContinue) {
        if ($script:window) { [void]$cands.Add($script:window) }
    }
    foreach ($w in $cands) { if ($w.IsActive) { return $w } }
    foreach ($w in $cands) { if ($w.IsLoaded) { return $w } }
    return $null
}

function Show-AuditYesNo([string]$Text) {
    $owner = Get-AuditDialogOwner
    $ask = if ($owner) { [Windows.MessageBox]::Show($owner, $Text, 'SSH LAN', 'YesNo', 'Question') }
           else { [Windows.MessageBox]::Show($Text, 'SSH LAN', 'YesNo', 'Question') }
    return ($ask -eq 'Yes')
}

# $ExitNode set = first knock our public IP from outside through that Tailscale exit node and fold it into this round
function Start-AuditRun([object[]]$Devices, [string]$ExitNode = '') {
    if (Test-AuditBusy) { return }
    Set-AuditBusy $true
    try { Start-SshLanBusyMotion } catch { }
    try { if (Get-Command Start-MapLoadMotion -ErrorAction SilentlyContinue) { Start-MapLoadMotion 'กำลังตรวจความปลอดภัย...' } } catch { }
    $script:AuditPs = [powershell]::Create()
    $null = $script:AuditPs.AddScript({
        param($Root, $Devices, $ExitNode)
        $env:SSH_LAN_UI = '1'
        . (Join-Path $Root 'scripts\ssh-lan-common.ps1')
        . (Join-Path $Root 'scripts\ssh-lan\ssh-lan.ps1')
        if (-not @($Devices).Count) { $Devices = @(Find-SshLanLanDevices '') }
        $col = @{}
        if ($ExitNode) {
            $public = Get-SshLanPublicIp
            if (-not $public) { throw 'ไม่รู้ IP สาธารณะ (tailscale netcheck ไม่ตอบ)' }
            # a port open from outside lands on the router first; which machine it forwards to is only known through UPnP
            $gw = [string]@($Devices | Where-Object { $_.Note -eq 'เราเตอร์' })[0].Ip
            $probe = @(Invoke-SshLanExitNodeProbe $ExitNode $public @($script:SshLanAuditPorts.Keys | Sort-Object) | ForEach-Object { $_.target = $gw; $_ })
            $col.Internet = { param($router) Get-SshLanInternetExposure $router.wanIp $public @($router.mappings) $probe }.GetNewClosure()
        }
        $audit = Invoke-SshLanAudit $Devices $col
        # Linux expiry is a timer on that machine, and a reboot drops the timer. Drop the rule after the round so the audit function stays read-only.
        $notes = New-Object System.Collections.Generic.List[string]
        try {
            foreach ($d in @($Devices)) {
                if (-not $d) { continue }
                $bm = $audit.ByMachine[[string]$d.Ip]
                if (-not $bm) { continue }
                $facts = $bm.Facts
                $hasTemp = $false
                foreach ($n in @(Get-SshLanBag $facts 'tempRules')) { if ($n) { $hasTemp = $true; break } }
                if (-not $hasTemp) { continue }
                $isMember = [bool](Get-SshLanBag $facts 'member') -or ((Get-SshLanText $d 'Note') -eq 'เครื่องนี้')
                if (-not $isMember) { continue }
                try {
                    foreach ($gone in @(Remove-SshLanExpiredTempRules $d $facts)) {
                        if ($gone) { [void]$notes.Add("[✓] ลบกฎชั่วคราวที่หมดเวลา $gone บน $($d.Name)") }
                    }
                } catch {
                    [void]$notes.Add("[!] ลบกฎชั่วคราวบน $($d.Name) ไม่ได้: $($_.Exception.Message)")
                }
            }
        } catch {
            [void]$notes.Add("[!] ลบกฎชั่วคราวที่หมดเวลาไม่ได้: $($_.Exception.Message)")
        }
        @{ Audit = $audit; Devices = $Devices; ExitNodes = @(Get-SshLanExitNodeCandidates); Cleared = $notes.ToArray() }
    }).AddArgument($root).AddArgument(@($Devices)).AddArgument($ExitNode)
    $script:AuditHandle = $script:AuditPs.BeginInvoke()
    $script:AuditStarted = Get-Date
    $script:AuditTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:AuditTimer.Interval = [TimeSpan]::FromMilliseconds(250)
    $script:AuditTimer.Add_Tick({
        if (-not $script:AuditWin) { $script:AuditTimer.Stop(); return }
        $secs = [int]((Get-Date) - $script:AuditStarted).TotalSeconds
        if (-not $script:AuditHandle.IsCompleted) { (Find-Audit 'AuditStatus').Text = "กำลังตรวจ... $secs วินาที (สแกน, อ่านแต่ละเครื่องผ่าน SSH, ถามเราเตอร์)"; return }
        $script:AuditTimer.Stop()
        try {
            $raw = @($script:AuditPs.EndInvoke($script:AuditHandle))
            $out = @($raw | Where-Object { $_ -and $_.Audit }) | Select-Object -Last 1
            if (-not $out) { throw 'ไม่มีผลตรวจ' }
            $script:AuditDevices = @($out.Devices)
            Show-AuditResult $out.Audit
            $script:AuditExitNodes = @($out.ExitNodes)
            (Find-Audit 'AuditStatus').Text = "ตรวจ $(@($out.Audit.ByMachine.Keys).Count) เครื่อง ($secs วินาที) · บันทึกที่ $($out.Audit.Path)"
            $script:AuditPath = $out.Audit.Path
            foreach ($line in @($out.Cleared)) { if ($line) { Add-Log ([string]$line) } }
        } catch {
            $e = $_.Exception
            while ($e.InnerException) { $e = $e.InnerException }
            (Find-Audit 'AuditStatus').Text = '[!] ' + $e.Message
        } finally {
            try { if (Get-Command Stop-MapLoadMotion -ErrorAction SilentlyContinue) { Stop-MapLoadMotion } } catch { }
            try { if (-not $script:Busy) { Stop-SshLanBusyMotion } } catch { }
            if ($script:AuditPs) {
                try { $script:AuditPs.Dispose() } catch {}
                $script:AuditPs = $null
            }
            Set-AuditBusy $false
        }
    })
    $script:AuditTimer.Start()
}

function Get-AuditSwitchWho($Device, $Finding) {
    $machine = Get-SshLanText $Device 'Name'
    if (-not $machine) { $machine = Get-SshLanText $Finding 'Machine' }
    $ip = Get-SshLanText $Device 'ip'
    if (-not $ip) { $ip = Get-SshLanText $Finding 'Ip' }
    return @{ Machine = $machine; Ip = $ip }
}

function Get-AuditSwitchEffect($Device, $Finding, $Switch) {
    $action = Get-SshLanText $Switch 'Action'
    if ($action -eq 'firewall-on') {
        $ip = Get-SshLanText $Device 'ip'
        if (-not $ip) { $ip = Get-SshLanText $Finding 'Ip' }
        try {
            $lan = Get-SshLanControlLanCidr $ip
            return [string](Get-SshLanFirewallOnPlan (Get-SshLanSwitchFacts $Device) $lan).Text
        } catch {
            return 'เปิดไฟร์วอลล์ และคง SSH ไว้ให้เข้าจากวงแลนและ Tailscale'
        }
    }
    if ($action -eq 'close') {
        $also = New-Object System.Collections.Generic.List[int]
        foreach ($p in @(Get-SshLanBag $Switch 'AlsoPorts')) {
            if ("$p" -match '^\d+$' -and [int]$p -gt 0) { [void]$also.Add([int]$p) }
        }
        if ($also.Count) { return "พอร์ต $($also -join ', ') ที่กฎเดียวกันครอบจะปิดด้วย" }
        return 'ปิดพอร์ตนี้'
    }
    if ($action -eq 'reopen') { return 'เปิดพอร์ตนี้คืน' }
    if ($action -eq 'upnp-delete') { return 'ลบการเปิดพอร์ตที่เราเตอร์' }
    $label = Get-SshLanText $Switch 'Label'
    if ($label) { return $label }
    return 'เปลี่ยนการตั้งค่าเครื่องนี้'
}

function Confirm-SshLanSwitch($Device, $Finding, $Switch) {
    $who = Get-AuditSwitchWho $Device $Finding
    $label = Get-SshLanText $Switch 'Label'
    $effect = Get-AuditSwitchEffect $Device $Finding $Switch
    $text = "จะ $label บน $($who.Machine) ($($who.Ip))`nผล: $effect`nย้อนได้ที่ปุ่ม เปิดคืน หรือในแผนผัง"
    return (Show-AuditYesNo $text)
}

function Confirm-AuditRiskyRows($Rows) {
    $blocks = New-Object System.Collections.Generic.List[string]
    foreach ($row in @($Rows)) {
        $who = Get-AuditSwitchWho $row.Device $row.Finding
        $label = Get-SshLanText $row.Switch 'Label'
        $effect = Get-AuditSwitchEffect $row.Device $row.Finding $row.Switch
        [void]$blocks.Add("จะ $label บน $($who.Machine) ($($who.Ip))`nผล: $effect")
    }
    $text = ($blocks -join "`n`n") + "`nย้อนได้ที่ปุ่ม เปิดคืน หรือในแผนผัง"
    return (Show-AuditYesNo $text)
}

# one remote argv: ssh -t <alias> "sudo sh -c '<script>'". Join lines so the Windows command line stays one argument, and escape quotes for sh -c.
function Get-AuditSudoRemote($Device, $Finding, $Switch) {
    if ((Get-SshLanControlOsName $Finding $Device) -ne 'Linux') { return $null }
    $alias = Get-SshLanText $Device 'Alias'
    if ($alias -notmatch '^[A-Za-z0-9._-]+$') { return $null }
    $action = Get-SshLanText $Switch 'Action'
    if ($action -notin @('close', 'reopen', 'firewall-on')) { return $null }
    $port = 0
    $portText = Get-SshLanText $Finding 'Port'
    if ($portText -match '^\d+$') { $port = [int]$portText }
    $arg = @{ Port = $port }
    if ($action -eq 'firewall-on') {
        $ip = Get-SshLanText $Device 'ip'
        if (-not $ip) { $ip = Get-SshLanText $Finding 'Ip' }
        $lan = Get-SshLanControlLanCidr $ip
        $plan = Get-SshLanFirewallOnPlan (Get-SshLanSwitchFacts $Device) $lan
        $arg['Lan'] = $lan
        $arg['Keep'] = [int[]]@($plan.Keep)
        $arg['Port'] = 0
    }
    $script = Get-SshLanControlScript 'Linux' $action $arg
    $one = ((@($script -split "`r?`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join '; ')
    $remote = "sudo sh -c '" + $one.Replace("'", "'\''") + "'"
    return @{ Alias = $alias; Remote = $remote }
}

function Start-AuditSudoWindow($Device, $Finding, $Switch) {
    $cmd = Get-AuditSudoRemote $Device $Finding $Switch
    if (-not $cmd) { return $null }
    $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    if (-not (Test-Path -LiteralPath $ssh)) { $ssh = 'ssh' }
    $argLine = "-t $($cmd.Alias) `"$($cmd.Remote)`""
    $proc = Start-Process -FilePath $ssh -ArgumentList $argLine -PassThru
    $null = $proc.Handle
    return $proc
}

function Get-AuditButtonRow($Source) {
    $cur = $Source
    while ($cur) {
        if ($cur -is [System.Windows.Controls.Button]) {
            $row = $cur.DataContext
            if ($row -and $row.Switch -and $row.Finding) { return $row }
            return $null
        }
        if ($cur -isnot [System.Windows.DependencyObject]) { return $null }
        $cur = [System.Windows.Media.VisualTreeHelper]::GetParent($cur)
    }
    return $null
}

function Start-AuditSwitchNext {
    if (-not $script:AuditWin) { return }
    $queue = $script:AuditQueue
    if (-not $queue -or $script:AuditQueueAt -ge $queue.Count) {
        $script:AuditQueue = $null
        $script:AuditActRow = $null
        Start-AuditRun $script:AuditDevices
        return
    }
    $row = $queue[$script:AuditQueueAt]
    $script:AuditQueueAt++
    $script:AuditActRow = $row
    $who = Get-AuditSwitchWho $row.Device $row.Finding
    $label = Get-SshLanText $row.Switch 'Label'
    (Find-Audit 'AuditStatus').Text = "กำลัง $label บน $($who.Machine)…"
    $script:AuditActPs = [powershell]::Create()
    $null = $script:AuditActPs.AddScript({
        param($Root, $Device, $Finding, $Switch)
        $ErrorActionPreference = 'Continue'
        $env:SSH_LAN_UI = '1'
        . (Join-Path $Root 'scripts\ssh-lan-common.ps1')
        . (Join-Path $Root 'scripts\ssh-lan\ssh-lan.ps1')
        $soap = $null
        $mapping = $null
        if ((Get-SshLanText $Switch 'Action') -eq 'upnp-delete') {
            try {
                $loc = Find-SshLanIgd 1500
                if ($loc) {
                    $desc = ConvertFrom-SshLanWebContent (Invoke-WebRequest $loc -UseBasicParsing -TimeoutSec 3)
                    $ctl = Get-SshLanIgdControl ([string]$desc) $loc
                    if ($ctl) {
                        $script:AuditSoap = New-SshLanIgdSoap $ctl 3
                        $soap = $script:AuditSoap
                        $maps = @(Get-SshLanIgdMappings {
                            param($i)
                            $r = & $script:AuditSoap 'GetGenericPortMappingEntry' @{ NewPortMappingIndex = $i }
                            @{ external = [int]$r.NewExternalPort; internalClient = [string]$r.NewInternalClient; internalPort = [int]$r.NewInternalPort
                               protocol = [string]$r.NewProtocol; description = [string]$r.NewPortMappingDescription }
                        })
                        $port = 0
                        $pt = Get-SshLanText $Finding 'Port'
                        if ($pt -match '^\d+$') { $port = [int]$pt }
                        $ip = Get-SshLanText $Finding 'Ip'
                        $mapping = @($maps | Where-Object { [int]$_.external -eq $port -and [string]$_.internalClient -eq $ip -and [string]$_.protocol -ne 'UDP' }) | Select-Object -First 1
                    }
                }
            } catch {
                $soap = $null
                $mapping = $null
            }
        }
        try { return (Invoke-SshLanSwitch $Device $Finding $Switch $null $null $soap $mapping) }
        catch { return @{ Ok = $false; Message = $_.Exception.Message; ChangeId = '' } }
    }).AddArgument($root).AddArgument($row.Device).AddArgument($row.Finding).AddArgument($row.Switch)
    $script:AuditActHandle = $script:AuditActPs.BeginInvoke()
    if ($script:AuditActTimer) { $script:AuditActTimer.Stop() }
    $gen = ++$script:AuditActGen
    $script:AuditActTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:AuditActTimer.Interval = [TimeSpan]::FromMilliseconds(250)
    $script:AuditActTimer.Tag = $gen
    # A tick already queued on the previous timer carries that timer as sender, so its old tag no longer matches.
    $script:AuditActTimer.Add_Tick({
        param($sender, $e)
        if ($sender -and $script:AuditActGen -eq $sender.Tag) { Watch-AuditAct }
    })
    $script:AuditActTimer.Start()
}

function Watch-AuditAct {
    if (-not $script:AuditWin) {
        if ($script:AuditActTimer) { $script:AuditActTimer.Stop() }
        return
    }
    $row = $script:AuditActRow
    if (-not $row) { return }
    $who = Get-AuditSwitchWho $row.Device $row.Finding
    $label = Get-SshLanText $row.Switch 'Label'
    if ($script:AuditSudoProc) {
        if (-not $script:AuditSudoProc.HasExited) { return }
        $code = $script:AuditSudoProc.ExitCode
        $script:AuditSudoProc = $null
        $script:AuditActTimer.Stop()
        if ($code -eq 0) { Add-Log "[✓] $label บน $($who.Machine) ($($who.Ip)): ใส่รหัสแล้ว" }
        else { Add-Log "[!] $label บน $($who.Machine) ($($who.Ip)): หน้าต่างรหัสปิดก่อนเสร็จ" }
        Start-AuditSwitchNext
        return
    }
    if (-not $script:AuditActHandle -or -not $script:AuditActHandle.IsCompleted) { return }
    $script:AuditActTimer.Stop()
    $result = $null
    try {
        $raw = @($script:AuditActPs.EndInvoke($script:AuditActHandle))
        $result = @($raw | Where-Object { $_ -is [System.Collections.IDictionary] -and $_.Contains('Ok') }) | Select-Object -Last 1
    } catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        $result = @{ Ok = $false; Message = $e.Message }
    } finally {
        try { $script:AuditActPs.Dispose() } catch {}
        $script:AuditActPs = $null
        $script:AuditActHandle = $null
    }
    if (-not $result) { $result = @{ Ok = $false; Message = 'ไม่แน่ใจว่าเปลี่ยนแล้วหรือยัง ให้กดตรวจใหม่' } }
    if ([string]$result.Message -eq 'ต้องใส่รหัสของเครื่องนั้น') {
        $ask = Show-AuditYesNo 'เครื่องนี้ต้องใส่รหัส sudo จะเปิดหน้าต่างให้พิมพ์รหัสไหม'
        if ($ask) {
            try { $proc = Start-AuditSudoWindow $row.Device $row.Finding $row.Switch }
            catch { $proc = $null; Add-Log "[!] $($_.Exception.Message)" }
            if ($proc) {
                $script:AuditSudoProc = $proc
                $script:AuditActTimer.Start()
                return
            }
        }
        Add-Log "[!] $label บน $($who.Machine) ($($who.Ip)): ต้องใส่รหัสของเครื่องนั้น"
        Start-AuditSwitchNext
        return
    }
    $mark = if ($result.Ok) { '[✓]' } else { '[!]' }
    Add-Log "$mark $label บน $($who.Machine) ($($who.Ip)): $($result.Message)"
    Start-AuditSwitchNext
}

function Start-AuditSwitchOnRows($Rows) {
    if (Test-AuditBusy) { return }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($row in @($Rows)) { if ($row -and $row.SwitchEnabled) { [void]$list.Add($row) } }
    if ($list.Count -eq 0) { return }
    $ok = if ($list.Count -eq 1) { Confirm-SshLanSwitch $list[0].Device $list[0].Finding $list[0].Switch }
          else { Confirm-AuditRiskyRows $list }
    if (-not $ok) { return }
    $script:AuditQueue = $list
    $script:AuditQueueAt = 0
    Set-AuditBusy $true
    Start-AuditSwitchNext
}

# rows for the grid: worst first, then by address and port. Each row carries the finding, its switch, and the machine the switch acts on.
function ConvertTo-AuditRows($Audit) {
    $new = @{}
    foreach ($n in @($Audit.NewSinceLast)) { $new["$($n.Ip)|$($n.Port)"] = $true }
    $byIp = @{}
    foreach ($d in @($script:AuditDevices)) { if ($d -and $d.Ip) { $byIp[[string]$d.Ip] = $d } }
    $protected = @(Get-SshLanProtected)
    return @(@($Audit.Findings) | Sort-Object { -$script:SshLanAuditRank[$_.Color] }, { ConvertTo-SshLanUInt32 $_.Ip }, Port | ForEach-Object {
        $finding = $_
        $scan = $byIp[[string]$finding.Ip]
        $bm = $null
        if ($Audit.ByMachine) { $bm = $Audit.ByMachine[[string]$finding.Ip] }
        $facts = $null
        if ($bm) { $facts = $bm.Facts }
        if ($null -eq $facts) { $facts = @{} }
        $device = [pscustomobject]@{
            Name = $(if ($scan) { [string]$scan.Name } else { [string]$finding.Machine })
            Ip = [string]$finding.Ip
            Mac = $(if ($scan) { [string]$scan.Mac } else { '' })
            Os = $(if ($scan -and $scan.Os) { [string]$scan.Os } else { [string]$finding.Os })
            Alias = $(if ($scan) { [string]$scan.Alias } else { '' })
            Note = $(if ($scan) { [string]$scan.Note } else { '' })
            Facts = $facts
        }
        $member = [bool](Get-SshLanBag $facts 'member') -or ($device.Note -eq 'เครื่องนี้')
        $fwRaw = Get-SshLanBag $facts 'firewallOn'
        $firewallOn = -not ($fwRaw -eq $false -or "$fwRaw" -eq 'False')
        $rules = New-Object System.Collections.Generic.List[object]
        foreach ($r in @(Get-SshLanBag $facts 'rules')) { if ($r) { [void]$rules.Add($r) } }
        $sw = Get-SshLanSwitch $finding $device $member $firewallOn @($protected) $rules.ToArray()
        $action = [string]$sw.Action
        $label = [string]$sw.Label
        $why = [string]$sw.Why
        # disabled rows still need a visible สั่ง cell (empty label looked like "no button")
        if (-not $label -and $action -ne 'none') { $label = $(if ($why) { $why } else { 'ดูเหตุผล' }) }
        $tip = if ($why) { $why } else { $label }
        [pscustomobject]@{
            Dot = $script:AuditDot[$finding.Color]
            New = $(if ($new.ContainsKey("$($finding.Ip)|$($finding.Port)")) { 'ใหม่' } else { '' })
            Machine = $finding.Machine; Ip = $finding.Ip
            PortText = $(if ($finding.Port) { [string]$finding.Port } else { '-' })
            Service = $finding.Service; Process = $finding.Process; OpenTo = $finding.OpenTo
            Reason = $finding.Reason; Evidence = $finding.Evidence; Fix = $finding.Fix; Color = $finding.Color
            Tip = "$($finding.Reason)`nหลักฐาน: $($finding.Evidence)`nวิธีแก้: $($finding.Fix)"
            SwitchLabel = $label; SwitchEnabled = [bool]$sw.Enabled; SwitchTip = $tip
            SwitchAction = $action; Switch = $sw; Finding = $finding; Device = $device
        }
    })
}

function Show-AuditResult($Audit) {
    $s = $Audit.Summary
    (Find-Audit 'SumRed').Text = $s.Red
    (Find-Audit 'SumAmber').Text = $s.Amber
    (Find-Audit 'SumGreen').Text = $s.Green
    (Find-Audit 'SumGray').Text = $s.Gray
    $i = $Audit.Internet
    $yn = { param($v, $yes, $no) if ($v -eq $true) { $yes } elseif ($v -eq $false) { $no } else { 'ไม่ทราบ' } }
    $open = @($i.internetPorts)
    (Find-Audit 'InternetLine').Text = "อินเทอร์เน็ต: CGNAT $(& $yn $i.cgnat 'ใช่ (เข้าจากนอกบ้านตรง ๆ ไม่ได้)' 'ไม่ใช่') · UPnP $(& $yn $i.upnp 'เปิด' 'ปิด') · " +
        $(if ($open) { "เข้าจากนอกบ้านได้: พอร์ต $(($open | ForEach-Object { $_.port }) -join ', ')" } else { 'ไม่พบพอร์ตที่เข้าจากนอกบ้านได้' })
    (Find-Audit 'InternetLine').Foreground = $(if ($open) { $script:AuditDot.red } else { '#F4F7FB' })
    (Find-Audit 'InternetEvidence').Text = (@($i.evidence) -join ' · ')
    (Find-Audit 'FindingGrid').ItemsSource = @(ConvertTo-AuditRows $Audit)
    Update-AuditFixAllButton
}

function Start-AuditProbe {
    $node = @($script:AuditExitNodes)[0]
    if (-not $node) { return }
    $ask = [Windows.MessageBox]::Show("ใช้ $node เป็นทางออกอินเทอร์เน็ตของเครื่องนี้ชั่วคราว (ประมาณ 1 นาที) แล้วเคาะ IP สาธารณะของบ้านจากข้างนอก`nระหว่างนั้นเน็ตของเครื่องนี้จะออกทางมือถือ ตั้งค่าคืนให้เมื่อเสร็จ ทำต่อไหม", 'SSH LAN', 'YesNo', 'Question')
    if ($ask -ne 'Yes') { return }
    Add-Log "ทดสอบจากข้างนอกผ่าน $node (ตั้งค่า exit node คืนเมื่อเสร็จ)"
    Start-AuditRun $script:AuditDevices $node
}

function Show-AuditWindow([object[]]$Devices) {
    if ($script:AuditWin) { $script:AuditWin.Activate() | Out-Null; return }
    $res = [regex]::Match($markup, '(?s)<Window\.Resources>.*?</Window\.Resources>').Value
    $text = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ssh-lan-audit.xaml'), [Text.Encoding]::UTF8).Replace('<!--RESOURCES-->', $res)
    $reader = [Xml.XmlReader]::Create([IO.StringReader]::new($text))
    try { $script:AuditWin = [Windows.Markup.XamlReader]::Load($reader) } finally { $reader.Dispose() }
    $owner = if ($script:ScanWin) { $script:ScanWin } elseif ($window.IsLoaded) { $window } else { $null }
    if ($owner) { $script:AuditWin.Owner = $owner }
    if ($window.Icon) { $script:AuditWin.Icon = $window.Icon }
    $script:AuditDevices = @($Devices | Where-Object { $_ })

    (Find-Audit 'BtnAuditRun').Add_Click({ Start-AuditRun $script:AuditDevices })
    (Find-Audit 'BtnAuditProbe').Add_Click({ Start-AuditProbe })
    (Find-Audit 'BtnAuditFolder').Add_Click({ Start-Process explorer.exe (Initialize-SshLanDataDirectory) })
    (Find-Audit 'BtnAuditFixAll').Add_Click({
        $grid = Find-Audit 'FindingGrid'
        $risky = @()
        if ($grid -and $grid.ItemsSource) { $risky = @($grid.ItemsSource | Where-Object { $_.Color -eq 'red' -and $_.SwitchEnabled }) }
        Start-AuditSwitchOnRows $risky
    })
    $gridClick = {
        param($sender, $e)
        $row = Get-AuditButtonRow $e.OriginalSource
        if (-not $row) { return }
        $e.Handled = $true
        Start-AuditSwitchOnRows @($row)
    }
    (Find-Audit 'FindingGrid').AddHandler([System.Windows.Controls.Button]::ClickEvent, [System.Windows.RoutedEventHandler]$gridClick)
    $script:AuditWin.Add_Closed({
        try { if ($script:AuditTimer) { $script:AuditTimer.Stop() } } catch {}
        try { if ($script:AuditActTimer) { $script:AuditActTimer.Stop() } } catch {}
        try { if ($script:AuditPs) { $script:AuditPs.Stop(); $script:AuditPs.Dispose() } } catch {}
        try { if ($script:AuditActPs) { $script:AuditActPs.Stop(); $script:AuditActPs.Dispose() } } catch {}
        $script:AuditPs = $null
        $script:AuditActPs = $null
        $script:AuditActHandle = $null
        $script:AuditQueue = $null
        $script:AuditSudoProc = $null
        $script:AuditWin = $null
    })
    $script:AuditWin.Add_Loaded({ Start-AuditRun $script:AuditDevices })
    $script:AuditWin.Show()
}
