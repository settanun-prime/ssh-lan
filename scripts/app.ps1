param([switch]$Startup)
$ErrorActionPreference = 'Stop'
$env:SSH_LAN_UI = '1'
Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,System.Windows.Forms
. (Join-Path $PSScriptRoot 'ssh-lan-common.ps1')
. (Get-SshLanMainScript)

$root = Get-SshLanPackageRoot
$settings = Get-SshLanSettings
$script:Busy = $false

Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class SshLanWindowIdentity {
 [DllImport("shell32.dll", CharSet=CharSet.Unicode)] public static extern int SetCurrentProcessExplicitAppUserModelID(string id);
}
'@
$null = [SshLanWindowIdentity]::SetCurrentProcessExplicitAppUserModelID('SshLan.PrimeStudio')

$markup = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ssh-lan-ui.xaml'), [Text.Encoding]::UTF8)
$reader = [Xml.XmlReader]::Create([IO.StringReader]::new($markup))
try { $window = [Windows.Markup.XamlReader]::Load($reader) } finally { $reader.Dispose() }
function Find([string]$Name) { $window.FindName($Name) }

$logoPath = Join-Path $root 'assets\ssh-lan-logo.png'
if (Test-Path -LiteralPath $logoPath) {
    try {
        $logo = New-Object Windows.Media.Imaging.BitmapImage
        $logo.BeginInit()
        $logo.UriSource = New-Object Uri($logoPath, [UriKind]::Absolute)
        $logo.CacheOption = [Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $logo.EndInit()
        (Find 'Logo').Source = $logo
        $window.Icon = $logo
    } catch {}
}

function New-Brush([string]$Hex) { (New-Object System.Windows.Media.BrushConverter).ConvertFromString($Hex) }

# lets a blocking task paint its log lines and busy bar while it is still running
function Update-Ui {
    $window.Dispatcher.Invoke([System.Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
}

function Add-Log([string]$Line) {
    $color = '#F4F7FB'
    if ($Line -match '\[✓\]') { $color = '#4ADE80' } elseif ($Line -match '\[!\]') { $color = '#F5C451' }
    $row = New-Object System.Windows.Controls.TextBlock
    $stamp = New-Object System.Windows.Documents.Run ('[' + (Get-Date -Format 'HH:mm:ss') + '] ')
    $stamp.Foreground = New-Brush '#6B7487'
    $body = New-Object System.Windows.Documents.Run $Line
    $body.Foreground = New-Brush $color
    [void]$row.Inlines.Add($stamp)
    [void]$row.Inlines.Add($body)
    $row.FontFamily = New-Object System.Windows.Media.FontFamily 'Leelawadee UI'
    $row.FontSize = 13
    $row.TextWrapping = 'Wrap'
    $row.Margin = New-Object System.Windows.Thickness(0, 0, 0, 6)
    $row.Opacity = 0
    $shift = New-Object System.Windows.Media.TranslateTransform
    $shift.Y = 8
    $row.RenderTransform = $shift
    $list = Find 'LogList'
    [void]$list.Children.Add($row)
    $dur = [TimeSpan]::FromMilliseconds(350)
    $ease = New-Object System.Windows.Media.Animation.CubicEase
    $fade = New-Object System.Windows.Media.Animation.DoubleAnimation(0, 1, $dur)
    $rise = New-Object System.Windows.Media.Animation.DoubleAnimation(8, 0, $dur)
    $rise.EasingFunction = $ease
    $row.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $fade)
    $shift.BeginAnimation([System.Windows.Media.TranslateTransform]::YProperty, $rise)
    $list.UpdateLayout()
    (Find 'LogScroll').ScrollToEnd()
    Update-Ui
}

function Start-Fade([System.Windows.UIElement]$Element, [double]$From, [int]$Ms) {
    if (-not $Element) { return }
    $anim = New-Object System.Windows.Media.Animation.DoubleAnimation($From, 1, ([TimeSpan]::FromMilliseconds($Ms)))
    $Element.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $anim)
}

(Find 'VersionText').Text = 'v' + (Get-SshLanVersion)

function Start-WindowIntro {
    $card = Find 'MainCard'
    $rise = Find 'CardRise'
    if (-not $card -or -not $rise) { return }
    $dur = [TimeSpan]::FromMilliseconds(420)
    $ease = New-Object System.Windows.Media.Animation.CubicEase
    $fade = New-Object System.Windows.Media.Animation.DoubleAnimation(0, 1, $dur)
    $move = New-Object System.Windows.Media.Animation.DoubleAnimation(18, 0, $dur)
    $move.EasingFunction = $ease
    $card.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $fade)
    $rise.BeginAnimation([System.Windows.Media.TranslateTransform]::YProperty, $move)

    $n = 0
    foreach ($el in (Find 'LeftPanel').Children) {
        $slide = New-Object System.Windows.Media.TranslateTransform
        $slide.X = -16
        $el.RenderTransform = $slide
        $el.Opacity = 0
        $span = [TimeSpan]::FromMilliseconds(380)
        $delay = [TimeSpan]::FromMilliseconds(140 + 55 * $n)
        $f = New-Object System.Windows.Media.Animation.DoubleAnimation(0, 1, $span)
        $m = New-Object System.Windows.Media.Animation.DoubleAnimation(-16, 0, $span)
        $f.BeginTime = $delay
        $m.BeginTime = $delay
        $m.EasingFunction = $ease
        $el.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $f)
        $slide.BeginAnimation([System.Windows.Media.TranslateTransform]::XProperty, $m)
        $n++
    }
}

function Test-SshLanUiAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
}

function Set-ServiceDot($Svc) {
    $hex = if (-not $Svc) { '#6B7487' } elseif ("$($Svc.Status)" -eq 'Running') { '#4ADE80' } else { '#F87171' }
    $brush = New-Brush $hex
    (Find 'SvcDot').Fill = $brush
    (Find 'SvcRing').Fill = $brush
    (Find 'SvcRing').Visibility = if ($Svc) { 'Visible' } else { 'Hidden' }
}

function Update-Chrome {
    $admin = Test-SshLanUiAdmin
    (Find 'AdminBadge').Text = if ($admin) { 'Admin' } else { '' }
    (Find 'BtnAdmin').Visibility = if ($admin) { 'Collapsed' } else { 'Visible' }
    $server = Test-SshLanIsServer
    $lan = Get-SshLanPrimaryLanIp
    if (-not $lan) { $lan = '-' }
    if ($server) {
        (Find 'RoleLine').Text = (Find 'StrRoleServer').Text
        (Find 'BtnPrimary').Content = (Find 'StrHarden').Text
    } else {
        (Find 'RoleLine').Text = (Find 'StrRoleClient').Text
        (Find 'BtnPrimary').Content = (Find 'StrClient').Text
    }
    $show = if ($server) { 'Visible' } else { 'Collapsed' }
    foreach ($name in @('BtnRemove', 'IpPanel', 'SubnetBox', 'SubnetLabel', 'BtnAddClient')) { (Find $name).Visibility = $show }
    (Find 'IpLine').Text = $lan
    $svc = Get-Service sshd -ErrorAction SilentlyContinue
    (Find 'SvcLine').Text = if ($svc) { "$($svc.Status)" } else { (Find 'StrNoSshd').Text }
    Set-ServiceDot $svc
    (Find 'Footer').Text = (Get-SshLanConfigPath)
    foreach ($name in @('RoleLine', 'IpLine', 'SvcLine')) { Start-Fade (Find $name) 0.35 280 }
}

function Set-SubnetSeed {
    $box = Find 'SubnetBox'
    if ($box.Items.Count -gt 0) { return }
    $cidr = Get-SshLanLocalCidr
    if (-not $cidr) { return }
    [void]$box.Items.Add("$cidr (ทั้งวง LAN ในบ้าน - แนะนำ)")
    $box.SelectedIndex = 0
}

function Start-SubnetChoices {
    if ($script:SubnetPs) { return }
    $script:SubnetPs = [powershell]::Create()
    $null = $script:SubnetPs.AddScript({
        param($Root)
        $ErrorActionPreference = 'Continue'
        $env:SSH_LAN_UI = '1'
        . (Join-Path $Root 'scripts\ssh-lan-common.ps1')
        . (Join-Path $Root 'scripts\ssh-lan\ssh-lan.ps1')
        @(Get-SshLanIpChoices)
    }).AddArgument($root)
    $script:SubnetHandle = $script:SubnetPs.BeginInvoke()
    $script:SubnetTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:SubnetTimer.Interval = [TimeSpan]::FromMilliseconds(200)
    $script:SubnetTimer.Add_Tick({
        if ($script:UiClosed) { return }
        if (-not $script:SubnetHandle -or -not $script:SubnetHandle.IsCompleted) { return }
        $script:SubnetTimer.Stop()
        try {
            $choices = @($script:SubnetPs.EndInvoke($script:SubnetHandle))
            $box = Find 'SubnetBox'
            if (-not $box) { return }
            $keep = [string]$box.SelectedItem
            $box.Items.Clear()
            $seen = @{}
            foreach ($item in $choices) {
                if (-not $item.Cidr) { continue }
                $label = if ($item.Note) { "$($item.Cidr) ($($item.Note))" } else { [string]$item.Cidr }
                if ($seen.ContainsKey($label)) { continue }
                $seen[$label] = $true
                [void]$box.Items.Add($label)
            }
            $idx = 0
            if ($keep) {
                $keepPrefix = ($keep -split ' ')[0]
                for ($i = 0; $i -lt $box.Items.Count; $i++) {
                    $itemStr = [string]$box.Items[$i]
                    if ($itemStr -eq $keep -or $itemStr.StartsWith($keepPrefix)) { $idx = $i; break }
                }
            }
            $box.SelectedIndex = $idx
        } catch {
        } finally {
            if ($script:SubnetPs) { $script:SubnetPs.Dispose(); $script:SubnetPs = $null }
            $script:SubnetHandle = $null
        }
    })
    $script:SubnetTimer.Start()
}

function Start-VisibleChrome {
    try {
        Update-Chrome
        Set-SubnetSeed
        $cur = Get-SshLanPrimaryLanIp
        if ($cur) { (Find 'StaticIpBox').Text = $cur }
        Add-Log ((Find 'StrReady').Text + ' ' + $env:COMPUTERNAME)
        Start-SubnetChoices
    } catch {
        try { Add-Log $_.Exception.Message } catch {}
    }
}

function Invoke-Logged([scriptblock]$Work) {
    if ($script:Busy) { return }
    $script:Busy = $true
    try {
        $window.Cursor = 'Wait'
        (Find 'BusyBar').Visibility = 'Visible'
        Update-Ui
        & $Work *>&1 | ForEach-Object {
            $text = "$_".Trim()
            if ($text) { Add-Log $text }
        }
    } catch {
        Add-Log ('[!] ' + $_.Exception.Message)
    } finally {
        $window.Cursor = 'Arrow'
        (Find 'BusyBar').Visibility = 'Hidden'
        $script:Busy = $false
        Update-Chrome
    }
}

function Start-ElevatedApp {
    $exe = Join-Path $root 'SSH LAN.exe'
    if (-not (Test-Path -LiteralPath $exe)) { $exe = Join-Path $root 'SSH LAN Prime Studio.exe' }
    if (-not (Test-Path -LiteralPath $exe)) { Add-Log (Find 'StrNoExe').Text; return }
    Start-Process -FilePath $exe -Verb RunAs
    $window.Close()
}

(Find 'TitleBar').Add_MouseLeftButtonDown({ if ($_.ChangedButton -eq 'Left') { $window.DragMove() } })
(Find 'Minimize').Add_Click({ $window.WindowState = 'Minimized' })
(Find 'CloseWindow').Add_Click({
    $fade = New-Object System.Windows.Media.Animation.DoubleAnimation(1, 0, ([TimeSpan]::FromMilliseconds(160)))
    $fade.Add_Completed({ $window.Close() })
    (Find 'MainCard').BeginAnimation([System.Windows.UIElement]::OpacityProperty, $fade)
})
(Find 'BtnAdmin').Add_Click({ Start-ElevatedApp })
(Find 'BtnRefresh').Add_Click({
    Update-Chrome
    $lan = (Find 'IpLine').Text
    $svc = (Find 'SvcLine').Text
    Add-Log "อัปเดตสถานะแล้ว: IP ในบ้าน = $lan | บริการ SSH = $svc"
})

(Find 'BtnPrimary').Add_Click({
    if (Test-SshLanIsServer) {
        if (-not (Test-SshLanUiAdmin)) { Add-Log (Find 'StrNeedAdmin').Text; return }
        $raw = [string](Find 'SubnetBox').SelectedItem
        $sn = if ($raw -match '^(\d+\.\d+\.\d+\.\d+(?:/\d+)?)') { $Matches[1] } else { $null }
        if (-not $sn) { Add-Log '[!] เลือกวง IP ที่อนุญาตก่อน'; return }
        Invoke-Logged {
            Add-Log "กำลังเปิดรับ SSH (อนุญาต: $sn)..."
            Invoke-SshLanHarden -SubnetIn $sn
        }
    } else {
        Invoke-Logged {
            Add-Log "กำลังตั้งค่าเครื่องนี้เพื่อเชื่อมต่อไปยังเซิร์ฟเวอร์..."
            Repair-ThisClient
        }
    }
})

(Find 'BtnTest').Add_Click({
    Invoke-Logged {
        if (Test-SshLanIsServer) {
            Add-Log "กำลังตรวจสอบความพร้อมของเซิร์ฟเวอร์ SSH..."
            $svc = Get-Service sshd -ErrorAction SilentlyContinue
            if (-not $svc) {
                Add-Log " [!] ไม่พบบริการ OpenSSH Server (sshd)"
                return
            }
            if ($svc.Status -ne 'Running') {
                Add-Log " [!] บริการ sshd มีสถานะ: $($svc.Status) (กดปุ่ม 'เปิดรับ SSH' เพื่อเริ่มบริการ)"
                return
            }
            Add-Log " [✓] บริการ sshd: กำลังทำงานปกติ (Running)"
            
            $listen = Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue
            if ($listen) {
                Add-Log " [✓] พอร์ต 22: เปิดรับการเชื่อมต่อแล้ว (Listening)"
            } else {
                Add-Log " [!] พอร์ต 22: ยังไม่พบการรับฟังการเชื่อมต่อ"
            }
            
            $rule = Get-NetFirewallRule -Name sshd-lan -ErrorAction SilentlyContinue
            if ($rule -and $rule.Enabled -eq 'True') {
                $addr = ($rule | Get-NetFirewallAddressFilter).RemoteAddress
                $addrNorm = $addr -replace '/255\.255\.255\.0$', '/24' -replace '/255\.255\.255\.255$', '/32'
                Add-Log " [✓] ไฟร์วอลล์ (sshd-lan): อนุญาตการเชื่อมต่อจาก $addrNorm"
            } else {
                Add-Log " [!] ไฟร์วอลล์: ยังไม่ได้เปิดรับ (กดปุ่ม 'เปิดรับ SSH' เพื่อตั้งค่าไฟร์วอลล์)"
            }
            
            Add-Log " สรุป: เซิร์ฟเวอร์พร้อมให้เครื่องอื่นในบ้านเชื่อมต่อเข้ามาได้แล้ว"
        } else {
            $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
            if (-not (Test-Path $ssh)) { throw (Find 'StrNoSsh').Text }
            $alias = (Get-SshLanSettings).hostAlias
            Add-Log "กำลังทดสอบเชื่อมต่อไปยังเซิร์ฟเวอร์ SSH ($alias)..."
            $out = & $ssh -o BatchMode=yes -o ConnectTimeout=6 $alias hostname 2>&1
            if ($LASTEXITCODE -eq 0) {
                Add-Log " [✓] เชื่อมต่อสำเร็จ! เซิร์ฟเวอร์ตอบกลับ: $(($out | Out-String).Trim())"
            } else {
                Add-Log " [!] เชื่อมต่อไม่สำเร็จ: $(($out | Out-String).Trim())"
                Add-Log " คำแนะนำ: ตรวจสอบว่าเปิดเครื่องเซิร์ฟเวอร์และกดปุ่ม 'เปิดรับ SSH' แล้วหรือยัง"
            }
        }
    }
})

$btnAddClient = Find 'BtnAddClient'
if ($btnAddClient) {
    $btnAddClient.Add_Click({
        if (-not (Test-SshLanUiAdmin)) { Add-Log (Find 'StrNeedAdmin').Text; return }
        Invoke-Logged {
            $clip = [System.Windows.Clipboard]::GetText()
            if ($clip -and $clip -match '^(ssh-(ed25519|rsa|ecdsa)|ecdsa-sha2-)\s+\S+') {
                $key = $Matches[0].Trim()
                $label = if ($clip -match '\s+(\S+@\S+|\S+)$') { $Matches[1] } else { '' }
                Add-Log "ตรวจพบกุญแจใน Clipboard ($label)... กำลังเพิ่มสิทธิ์..."
                Invoke-SshLanAddClient -Line $key
                Add-Log " [✓] เพิ่มกุญแจเครื่องลูกข่ายสำเร็จ! เครื่องนั้นสามารถเชื่อมต่อเข้ามาได้ทันที"
            } else {
                Add-Log "วิธีเพิ่มกุญแจเครื่องลูกข่าย:"
                Add-Log "1. ที่เครื่องลูกข่าย ให้คัดลอก Public Key (ข้อความที่ขึ้นต้นด้วย ssh-ed25519...)"
                Add-Log "2. นำมากด Copy ไว้ในเครื่องนี้ แล้วกดปุ่ม 'เพิ่มกุญแจเครื่องอื่น' อีกครั้ง"
            }
        }
    })
}

(Find 'StaticIpBox').Add_TextChanged({
    $box = Find 'StaticIpBox'
    $box.Tag = if ($box.Text.Trim() -match '^(\d{1,3}|\d{1,3}(\.\d{1,3}){3})$') { $null } else { 'invalid' }
})

(Find 'BtnStaticIp').Add_Click({
    if (-not (Test-SshLanUiAdmin)) { Add-Log (Find 'StrNeedAdmin').Text; return }
    $ip = (Find 'StaticIpBox').Text.Trim()
    Invoke-Logged {
        Add-Log "กำลังตั้งเลข IP คงที่เป็น $ip ..."
        & (Join-Path $PSScriptRoot 'ssh-lan\set-lan-ip.ps1') -Ip $ip
        Add-Log ' [✓] ตั้งเลข IP คงที่สำเร็จ'
    }
})

(Find 'BtnDhcp').Add_Click({
    if (-not (Test-SshLanUiAdmin)) { Add-Log (Find 'StrNeedAdmin').Text; return }
    Invoke-Logged {
        Add-Log 'กำลังคืนเป็นเลข IP อัตโนมัติ (DHCP)...'
        & (Join-Path $PSScriptRoot 'ssh-lan\set-lan-ip.ps1') -Dhcp
        Add-Log ' [✓] คืนเป็น IP อัตโนมัติแล้ว'
    }
})

(Find 'BtnPair').Add_Click({
    $target = (Find 'PairBox').Text.Trim()
    $both = [bool](Find 'PairBoth').IsChecked
    Invoke-Logged {
        if (-not $target) { Show-SshLanFoundHosts; return }
        Add-Log "กำลังจับคู่กับ $target ..."
        Invoke-SshLanPair -Target $target -Both:$both
    }
})

(Find 'BtnRemove').Add_Click({
    if (-not (Test-SshLanIsServer)) { return }
    if (-not (Test-SshLanUiAdmin)) { Add-Log (Find 'StrNeedAdmin').Text; return }
    $ask = [Windows.MessageBox]::Show((Find 'StrAskRemove').Text, 'SSH LAN', 'YesNo', 'Warning')
    if ($ask -ne 'Yes') { return }
    Invoke-Logged {
        Add-Log "กำลังปิดการรับ SSH บนเครื่องนี้..."
        Invoke-SshLanRemove
        Add-Log " [✓] ปิดบริการ SSH และลบกฎไฟร์วอลล์เรียบร้อยแล้ว"
    }
})

$window.Add_Closed({
    $script:UiClosed = $true
    try { if ($script:SubnetTimer) { $script:SubnetTimer.Stop() } } catch {}
    try { if ($script:SubnetPs) { $script:SubnetPs.Stop(); $script:SubnetPs.Dispose() } } catch {}
})
$window.Add_Loaded({
    Start-WindowIntro
    if ($script:ChromeStarted) { return }
    $script:ChromeStarted = $true
    $window.Dispatcher.BeginInvoke(
        [System.Action]{ Start-VisibleChrome },
        [System.Windows.Threading.DispatcherPriority]::ApplicationIdle
    ) | Out-Null
})
$window.ShowDialog() | Out-Null
