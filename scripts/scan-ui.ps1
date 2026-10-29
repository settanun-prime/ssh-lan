# LAN scanner window, dot-sourced by app.ps1: lists every device on the router's network (cable and Wi-Fi)
# and acts on the selected one. Uses app.ps1's $window, $markup, $root, Add-Log and Invoke-Logged.
$script:ScanWin = $null

function Find-Scan([string]$Name) { $script:ScanWin.FindName($Name) }

function Get-ScanSelected {
    $row = (Find-Scan 'HostGrid').SelectedItem
    if (-not $row) { Add-Log '[!] เลือกเครื่องในตารางก่อน' }
    return $row
}

function Get-ScanUser($Row) {
    $user = (Find-Scan 'UserBox').Text.Trim()
    if (-not $user -and $Row.User) { $user = $Row.User }
    if ($user -notmatch '^[A-Za-z0-9._-]+$') { Add-Log '[!] ใส่ชื่อผู้ใช้ของเครื่องนั้นก่อน'; return $null }
    return $user
}

# Host alias when the machine is paired, otherwise user@address
function Get-ScanTarget($Row) {
    if ($Row.Alias) { return $Row.Alias }
    $user = Get-ScanUser $Row
    if ($user) { return "$user@$($Row.Ip)" }
}

function Start-LanScan {
    if ($script:ScanPs) { return }
    (Find-Scan 'BtnScan').IsEnabled = $false
    (Find-Scan 'ScanStatus').Text = 'กำลังสแกน...'
    $script:ScanPs = [powershell]::Create()
    $null = $script:ScanPs.AddScript({
        param($Root, $Range)
        $env:SSH_LAN_UI = '1'
        . (Join-Path $Root 'scripts\ssh-lan-common.ps1')
        . (Join-Path $Root 'scripts\ssh-lan\ssh-lan.ps1')
        Find-SshLanLanDevices $Range
    }).AddArgument($root).AddArgument((Find-Scan 'RangeBox').Text.Trim())
    $script:ScanHandle = $script:ScanPs.BeginInvoke()
    $script:ScanStarted = Get-Date
    $script:ScanTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:ScanTimer.Interval = [TimeSpan]::FromMilliseconds(250)
    $script:ScanTimer.Add_Tick({
        if (-not $script:ScanWin) { $script:ScanTimer.Stop(); return }
        $secs = [int]((Get-Date) - $script:ScanStarted).TotalSeconds
        if (-not $script:ScanHandle.IsCompleted) { (Find-Scan 'ScanStatus').Text = "กำลังสแกน... $secs วินาที"; return }
        $script:ScanTimer.Stop()
        try {
            $rows = @($script:ScanPs.EndInvoke($script:ScanHandle))
            (Find-Scan 'HostGrid').ItemsSource = $rows
            $on = @($rows | Where-Object { $_.Online }).Count
            (Find-Scan 'ScanStatus').Text = "พบ $on เครื่องออนไลน์ จากทั้งหมด $($rows.Count) ($secs วินาที)"
        } catch {
            $e = $_.Exception
            while ($e.InnerException) { $e = $e.InnerException }
            (Find-Scan 'ScanStatus').Text = '[!] ' + $e.Message
        } finally {
            $script:ScanPs.Dispose()
            $script:ScanPs = $null
            (Find-Scan 'BtnScan').IsEnabled = $true
        }
    })
    $script:ScanTimer.Start()
}

function Open-ScanSsh {
    $row = Get-ScanSelected
    if (-not $row) { return }
    $target = Get-ScanTarget $row
    if (-not $target) { return }
    $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    $enc = ConvertTo-SshLanEncodedCommand "& '$ssh' '$target'"
    Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList '-NoExit', '-NoProfile', '-EncodedCommand', $enc
    Add-Log "เปิด SSH ไปที่ $target"
}

function Stop-ScanInvite {
    if ($script:InviteTimer) { $script:InviteTimer.Stop() }
    if ($script:Invite) { & $script:Invite.Stop; $script:Invite = $null }
    if ($script:ScanWin) {
        (Find-Scan 'InvitePanel').Visibility = 'Collapsed'
        (Find-Scan 'BtnInvite').IsEnabled = $true
    }
}

function Start-ScanInvite {
    if (-not (Test-SshLanUiAdmin)) { Add-Log (Find 'StrNeedAdmin').Text; return }
    try { $script:Invite = Start-SshLanInviteServer -Tailscale:([bool](Find-Scan 'InviteTs').IsChecked) }
    catch { Add-Log ('[!] ' + $_.Exception.Message); return }
    (Find-Scan 'InviteUrl').Text = "$($script:Invite.Url)join.cmd"
    (Find-Scan 'InviteSh').Text = "curl -fsS $($script:Invite.Url)join.sh | sh"
    (Find-Scan 'InviteCode').Text = $script:Invite.ConfirmCode
    (Find-Scan 'InvitePanel').Visibility = 'Visible'
    (Find-Scan 'BtnInvite').IsEnabled = $false
    Add-Log "เริ่มเชิญแล้ว ลิงก์ใช้ได้ถึง $($script:Invite.Expires.ToString('HH:mm')) รหัสยืนยัน $($script:Invite.ConfirmCode)"
    $script:InviteTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:InviteTimer.Interval = [TimeSpan]::FromMilliseconds(500)
    $script:InviteTimer.Add_Tick({
        if (-not $script:Invite) { $script:InviteTimer.Stop(); return }
        $left = $script:Invite.Expires - (Get-Date)
        if ($left.TotalSeconds -le 0) { Stop-ScanInvite; Add-Log 'หมดเวลาเชิญ ปิดลิงก์และไฟร์วอลล์แล้ว'; return }
        (Find-Scan 'InviteLeft').Text = 'เหลือ {0:mm\:ss}' -f $left
        # a pairing already running keeps the next hello in the queue for the next tick
        if ($script:Busy) { return }
        $hello = $null
        if ($script:Invite.Hellos.TryDequeue([ref]$hello)) {
            Invoke-Logged {
                Add-Log "เครื่อง $($hello.hostname) ($($hello.remote)) ติดตั้งเสร็จ กำลังจับคู่..."
                [void](Complete-SshLanJoin $hello -KeyOnly:([bool](Find-Scan 'InviteKeyOnly').IsChecked))
            }
            Start-LanScan
        }
    })
    $script:InviteTimer.Start()
}

function Show-ScanWindow {
    if ($script:ScanWin) { $script:ScanWin.Activate() | Out-Null; return }
    $res = [regex]::Match($markup, '(?s)<Window\.Resources>.*?</Window\.Resources>').Value
    $text = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ssh-lan-scan.xaml'), [Text.Encoding]::UTF8).Replace('<!--RESOURCES-->', $res)
    $reader = [Xml.XmlReader]::Create([IO.StringReader]::new($text))
    try { $script:ScanWin = [Windows.Markup.XamlReader]::Load($reader) } finally { $reader.Dispose() }
    if ($window.IsLoaded) { $script:ScanWin.Owner = $window }
    if ($window.Icon) { $script:ScanWin.Icon = $window.Icon }
    (Find-Scan 'UserBox').Text = $env:USERNAME

    (Find-Scan 'BtnScan').Add_Click({ Start-LanScan })
    (Find-Scan 'HostGrid').Add_MouseDoubleClick({ Open-ScanSsh })
    (Find-Scan 'BtnSsh').Add_Click({ Open-ScanSsh })
    (Find-Scan 'BtnDiagnose').Add_Click({
        $row = Get-ScanSelected
        if (-not $row) { return }
        $user = if ($row.Alias) { $row.User } else { Get-ScanUser $row }
        if (-not $row.Alias -and -not $user) { return }
        Invoke-Logged {
            Add-Log "ตรวจเส้นทางไปที่ $($row.Ip) ..."
            Test-SshLanReach $row.Ip $user $row.Alias
        }
    })

    (Find-Scan 'BtnPairHost').Add_Click({
        $row = Get-ScanSelected
        if (-not $row) { return }
        $user = Get-ScanUser $row
        if (-not $user) { return }
        $both = [bool](Find-Scan 'BothBox').IsChecked
        Invoke-Logged {
            Add-Log "กำลังจับคู่กับ $user@$($row.Ip) ..."
            # joined from a USB package: our key already opens it and it left a hello, so no password is needed
            $hello = Get-SshLanRemoteHello "$user@$($row.Ip)" $row.Ip $row.Os
            if ($hello) { [void](Complete-SshLanJoin $hello -KeyOnly:([bool](Find-Scan 'InviteKeyOnly').IsChecked)) }
            else { Invoke-SshLanPair -Target "$user@$($row.Ip)" -Both:$both }
        }
        Start-LanScan
    })

    (Find-Scan 'BtnRdp').Add_Click({
        $row = Get-ScanSelected
        if ($row) { Start-Process mstsc.exe "/v:$($row.Ip)" }
    })
    (Find-Scan 'BtnWeb').Add_Click({
        $row = Get-ScanSelected
        if (-not $row) { return }
        $url = if ($row.Ports -contains 80) { "http://$($row.Ip)" } elseif ($row.Ports -contains 443) { "https://$($row.Ip)" } elseif ($row.Ports -contains 8080) { "http://$($row.Ip):8080" } else { "http://$($row.Ip)" }
        Start-Process $url
    })
    (Find-Scan 'BtnShare').Add_Click({
        $row = Get-ScanSelected
        if ($row) { Start-Process explorer.exe "\\$($row.Ip)" }
    })
    (Find-Scan 'BtnWake').Add_Click({
        $row = Get-ScanSelected
        if (-not $row) { return }
        if (-not $row.Mac) { Add-Log '[!] ไม่รู้ MAC ของเครื่องนี้ (สแกนตอนเครื่องเปิดอยู่ก่อนหนึ่งครั้ง)'; return }
        Invoke-Logged { Send-SshLanWakeOnLan $row.Mac }
    })
    (Find-Scan 'BtnCopy').Add_Click({
        $row = Get-ScanSelected
        if ($row) { [Windows.Clipboard]::SetText($row.Ip); Add-Log "คัดลอก $($row.Ip) แล้ว" }
    })

    (Find-Scan 'BtnRun').Add_Click({
        $row = Get-ScanSelected
        if (-not $row) { return }
        $target = Get-ScanTarget $row
        $cmd = (Find-Scan 'CmdBox').Text
        if (-not $target) { return }
        Invoke-Logged {
            Add-Log "รันบน ${target}: $cmd"
            Invoke-SshLanRemote $target $cmd
        }
    })
    foreach ($b in 'BtnRestart', 'BtnShutdown') {
        (Find-Scan $b).Add_Click({
            param($sender)
            $restart = $sender.Name -eq 'BtnRestart'
            $row = Get-ScanSelected
            if (-not $row) { return }
            $target = Get-ScanTarget $row
            if (-not $target) { return }
            $what = if ($restart) { 'รีสตาร์ท' } else { 'ปิด' }
            $ask = [Windows.MessageBox]::Show("$what เครื่อง $($row.Name) ($($row.Ip)) หรือไม่", 'SSH LAN', 'YesNo', 'Warning')
            if ($ask -ne 'Yes') { return }
            Invoke-Logged { Invoke-SshLanPower $target $row.Os -Restart:$restart }
        })
    }

    (Find-Scan 'BtnDiscover').Add_Click({
        if (-not (Test-SshLanUiAdmin)) { Add-Log (Find 'StrNeedAdmin').Text; return }
        $ask = [Windows.MessageBox]::Show('ตั้งเครือข่ายนี้เป็น Private และเปิด Network Discovery / แชร์ไฟล์ / ping ให้เครื่องในวง LAN เดียวกันหรือไม่', 'SSH LAN', 'YesNo', 'Question')
        if ($ask -ne 'Yes') { return }
        Invoke-Logged { Invoke-SshLanDiscoverable }
    })

    (Find-Scan 'BtnExport').Add_Click({
        $rows = @((Find-Scan 'HostGrid').ItemsSource)
        if (-not $rows) { Add-Log '[!] ยังไม่มีผลสแกน'; return }
        $dlg = New-Object Microsoft.Win32.SaveFileDialog
        $dlg.Filter = 'CSV (*.csv)|*.csv'
        $dlg.FileName = 'lan-devices-' + (Get-Date -Format 'yyyyMMdd-HHmm') + '.csv'
        if (-not $dlg.ShowDialog($script:ScanWin)) { return }
        $rows | Select-Object Name, Ip, Mac, Os, Services, Alias, Note, Online, Evidence | Export-Csv -LiteralPath $dlg.FileName -NoTypeInformation -Encoding UTF8
        Add-Log " [✓] บันทึกแล้ว: $($dlg.FileName)"
    })

    (Find-Scan 'BtnAudit').Add_Click({ Show-AuditWindow @((Find-Scan 'HostGrid').ItemsSource) })
    (Find-Scan 'BtnInvite').Add_Click({ Start-ScanInvite })
    (Find-Scan 'BtnStopInvite').Add_Click({ Stop-ScanInvite; Add-Log 'หยุดเชิญแล้ว ปิดลิงก์และไฟร์วอลล์แล้ว' })
    (Find-Scan 'BtnCopyInvite').Add_Click({ [Windows.Clipboard]::SetText((Find-Scan 'InviteUrl').Text); Add-Log 'คัดลอกลิงก์เชิญแล้ว' })
    (Find-Scan 'BtnInvitePkg').Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'เลือกโฟลเดอร์ (เช่น แฟลชไดรฟ์) สำหรับชุดติดตั้ง SSH LAN'
        if ($dlg.ShowDialog() -ne 'OK') { return }
        $dir = Join-Path $dlg.SelectedPath 'SSH LAN join'
        $ts = [bool](Find-Scan 'InviteTs').IsChecked
        Invoke-Logged {
            $p = New-SshLanJoinPackage $dir '' -Tailscale:$ts
            Add-Log " [✓] ชุดติดตั้งอยู่ที่ $dir  รหัสยืนยัน $($p.ConfirmCode)"
            Add-Log '  ที่เครื่องใหม่ ดับเบิลคลิก join.cmd แล้วกลับมากดสแกน เครื่องนี้จะจับคู่กลับให้'
        }
    })

    $script:ScanWin.Add_Closed({
        Stop-ScanInvite
        try { if ($script:ScanTimer) { $script:ScanTimer.Stop() } } catch {}
        try { if ($script:ScanPs) { $script:ScanPs.Stop(); $script:ScanPs.Dispose() } } catch {}
        $script:ScanPs = $null
        $script:ScanWin = $null
    })
    $script:ScanWin.Add_Loaded({ Start-LanScan })
    $script:ScanWin.Show()
}
