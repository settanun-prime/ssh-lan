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
 [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
 public const int WM_SETICON = 0x0080;
}
'@
# same id as the Start Menu shortcut below — without a matching shortcut Win11 shows a blank taskbar icon
$script:SshLanAppUserModelId = 'SshLan.PrimeStudio'
$null = [SshLanWindowIdentity]::SetCurrentProcessExplicitAppUserModelID($script:SshLanAppUserModelId)

$markup = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ssh-lan-ui.xaml'), [Text.Encoding]::UTF8)
$reader = [Xml.XmlReader]::Create([IO.StringReader]::new($markup))
try { $window = [Windows.Markup.XamlReader]::Load($reader) } finally { $reader.Dispose() }
function Find([string]$Name) { $window.FindName($Name) }

$logoPath = Join-Path $root 'assets\ssh-lan-logo.png'
$icoPath = Join-Path $root 'assets\ssh-lan.ico'
if (Test-Path -LiteralPath $logoPath) {
    try {
        $logo = New-Object Windows.Media.Imaging.BitmapImage
        $logo.BeginInit()
        $logo.UriSource = New-Object Uri($logoPath, [UriKind]::Absolute)
        $logo.CacheOption = [Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $logo.EndInit()
        (Find 'Logo').Source = $logo
    } catch {}
}
# .ico for the window/taskbar (PNG as Window.Icon often leaves the Win11 pill blank)
if (Test-Path -LiteralPath $icoPath) {
    try {
        $window.Icon = [Windows.Media.Imaging.BitmapFrame]::Create(
            (New-Object Uri($icoPath, [UriKind]::Absolute)),
            [Windows.Media.Imaging.BitmapCreateOptions]::None,
            [Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        )
    } catch {
        if ((Find 'Logo').Source) { $window.Icon = (Find 'Logo').Source }
    }
} elseif ((Find 'Logo').Source) {
    $window.Icon = (Find 'Logo').Source
}

function Install-SshLanTaskbarShortcut {
    # Win11 resolves the taskbar icon for our AppUserModelID from a Start Menu .lnk with the same id
    $programs = Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Programs'
    if (-not (Test-Path -LiteralPath $programs)) { return }
    $lnkPath = Join-Path $programs 'SSH LAN Prime Studio.lnk'
    $exe = Join-Path $root 'SSH LAN.exe'
    $ico = Join-Path $root 'assets\ssh-lan.ico'
    if (-not (Test-Path -LiteralPath $exe)) { return }
    try {
        $w = New-Object -ComObject WScript.Shell
        $s = $w.CreateShortcut($lnkPath)
        $s.TargetPath = $exe
        $s.WorkingDirectory = $root
        $s.Description = 'SSH LAN Prime Studio'
        if (Test-Path -LiteralPath $ico) { $s.IconLocation = "$ico,0" }
        $s.Save()
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($s)
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($w)
    } catch { return }
    # stamp System.AppUserModel.ID on the shortcut (WScript cannot)
    try {
        if (-not ("SshLanLnkAumid" -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class SshLanLnkAumid {
  [ComImport, Guid("00021401-0000-0000-C000-000000000046")] class ShellLink { }
  [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("000214F9-0000-0000-C000-000000000046")]
  interface IShellLinkW {
    void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszFile, int cch, IntPtr pfd, int fFlags);
    void GetIDList(out IntPtr ppidl); void SetIDList(IntPtr pidl);
    void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszName, int cch);
    void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
    void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszDir, int cch);
    void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
    void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszArgs, int cch);
    void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
    void GetHotkey(out short pwHotkey); void SetHotkey(short wHotkey);
    void GetShowCmd(out int piShowCmd); void SetShowCmd(int iShowCmd);
    void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszIconPath, int cch, out int piIcon);
    void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
    void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, int dwReserved);
    void Resolve(IntPtr hwnd, int fFlags); void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
  }
  [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99")]
  interface IPropertyStore {
    void GetCount(out uint cProps); void GetAt(uint iProp, out PropertyKey pkey);
    void GetValue(ref PropertyKey key, out PropVariant pv); void SetValue(ref PropertyKey key, ref PropVariant pv); void Commit();
  }
  [StructLayout(LayoutKind.Sequential, Pack=4)] struct PropertyKey { public Guid fmtid; public uint pid; }
  [StructLayout(LayoutKind.Explicit)] struct PropVariant {
    [FieldOffset(0)] public ushort vt;
    [FieldOffset(8)] public IntPtr p;
  }
  public static void SetAppUserModelId(string lnkPath, string aumid) {
    var link = (IShellLinkW)new ShellLink();
    var file = (IPersistFile)link;
    file.Load(lnkPath, 2); // STGM_READWRITE
    var store = (IPropertyStore)link;
    var key = new PropertyKey { fmtid = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3"), pid = 5 };
    var pv = new PropVariant { vt = 31, p = Marshal.StringToCoTaskMemUni(aumid) };
    try { store.SetValue(ref key, ref pv); store.Commit(); file.Save(null, true); }
    finally { Marshal.FreeCoTaskMem(pv.p); }
  }
}
'@
        }
        [SshLanLnkAumid]::SetAppUserModelId($lnkPath, $script:SshLanAppUserModelId)
    } catch { }
}

function New-Brush([string]$Hex) { (New-Object System.Windows.Media.BrushConverter).ConvertFromString($Hex) }

# lets a blocking task paint its log lines and busy bar while it is still running
function Update-Ui {
    $window.Dispatcher.Invoke([System.Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
}

# the right panel: 'map' (the network map, shown first) or 'log' (what each button did)
function Show-MainTab([string]$Tab) {
    $map = $Tab -eq 'map'
    (Find 'MapHost').Visibility = $(if ($map) { 'Visible' } else { 'Collapsed' })
    (Find 'LogScroll').Visibility = $(if ($map) { 'Collapsed' } else { 'Visible' })
    (Find 'TabMap').BorderBrush = New-Brush $(if ($map) { '#F5C451' } else { '#00000000' })
    (Find 'TabLog').BorderBrush = New-Brush $(if ($map) { '#00000000' } else { '#F5C451' })
    (Find 'TabMapText').Foreground = New-Brush $(if ($map) { '#F5C451' } else { '#8F9BB3' })
    (Find 'TabLogText').Foreground = New-Brush $(if ($map) { '#8F9BB3' } else { '#F5C451' })
    (Find 'TabMapText').FontWeight = $(if ($map) { 'SemiBold' } else { 'Normal' })
    (Find 'TabLogText').FontWeight = $(if ($map) { 'Normal' } else { 'SemiBold' })
    if (-not $map) { (Find 'TabLogDot').Visibility = 'Collapsed' }
}

function Add-Log([string]$Line) {
    # a new line while the map is showing: a dot on the log tab says there is something to read
    if ((Find 'LogScroll').Visibility -ne 'Visible' -and $script:ChromeStarted) { (Find 'TabLogDot').Visibility = 'Visible' }
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
    if ($script:ScanWin) { $script:ScanWin.FindName('ScanLog').Text = $Line }
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
    # says whether the fixed IP really stuck: Manual on the adapter = fixed, otherwise the router handed it out
    $mode = if ($lan -ne '-') { Get-SshLanIpMode $lan } else { $null }
    $extras = @(Get-SshLanExtraIps)
    # the address alone on the big line; how it is set and any temporary address on a quiet line under it
    (Find 'IpLine').Text = $lan
    (Find 'IpModeLine').Text = $(switch ($mode) { 'static' { 'คงที่' } 'dhcp' { 'อัตโนมัติ (DHCP)' } default { '' } }) +
        $(if ($extras) { " · รับการเชื่อมต่อทาง $($extras -join ', ') ด้วย (ชั่วคราว)" } else { '' })
    (Find 'BtnRemoveExtra').Visibility = if ($extras) { 'Visible' } else { 'Collapsed' }
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
    [void]$box.Items.Add("$cidr (ทั้งวง LAN · แนะนำ)")
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
        if (Test-SshLanUiAdmin) { Remove-SshLanStaleInviteRule }
        Start-SubnetChoices
    } catch {
        try { Add-Log $_.Exception.Message } catch {}
    }
}

function Start-SshLanBusyMotion {
    $bar = Find 'BusyBar'
    $slide = Find 'BusySlide'
    if (-not $bar) { return }
    $bar.Visibility = 'Visible'
    if (-not $slide -or -not [Windows.SystemParameters]::ClientAreaAnimation) { return }
    $track = [Math]::Max(160, [int]$bar.ActualWidth)
    if ($track -lt 40) { $track = 480 }
    $a = New-Object Windows.Media.Animation.DoubleAnimation
    $a.From = -56; $a.To = $track
    $a.Duration = [TimeSpan]::FromSeconds(2.4)
    $a.RepeatBehavior = [Windows.Media.Animation.RepeatBehavior]::Forever
    $ease = New-Object Windows.Media.Animation.SineEase
    $ease.EasingMode = 'EaseInOut'
    $a.EasingFunction = $ease
    $slide.BeginAnimation([Windows.Media.TranslateTransform]::XProperty, $a)
}

function Stop-SshLanBusyMotion {
    $slide = Find 'BusySlide'
    if ($slide) { $slide.BeginAnimation([Windows.Media.TranslateTransform]::XProperty, $null) }
    $bar = Find 'BusyBar'
    if ($bar) { $bar.Visibility = 'Collapsed' }
}

function Invoke-Logged([scriptblock]$Work) {
    if ($script:Busy) { return }
    $script:Busy = $true
    Show-MainTab 'log'
    try {
        $window.Cursor = 'Wait'
        Start-SshLanBusyMotion
        Update-Ui
        & $Work *>&1 | ForEach-Object {
            $text = "$_".Trim()
            if ($text) { Add-Log $text }
        }
    } catch {
        Add-Log ('[!] ' + $_.Exception.Message)
    } finally {
        $window.Cursor = 'Arrow'
        Stop-SshLanBusyMotion
        $script:Busy = $false
        Update-Chrome
    }
}

# the app runs straight from its folder: when VERSION there moves on (a new build was copied in or committed),
# the header button offers to restart onto it; pressed any time, it simply reloads
$script:StartedVersion = Get-SshLanVersion

function Update-SshLanUpdateButton {
    $disk = Get-SshLanVersion
    $b = Find 'BtnUpdate'
    if ($disk -ne $script:StartedVersion) {
        $b.Content = "อัปเดตเป็น v$disk"
        $b.Style = $window.FindResource('PrimaryButton')
        $b.ToolTip = "ในโฟลเดอร์มีเวอร์ชันใหม่ (v$disk) แต่หน้าต่างนี้ยังเป็น v$($script:StartedVersion): กดเพื่อเปิดใหม่"
    } else {
        $b.Content = 'รีเฟรช'
        $b.ClearValue([System.Windows.FrameworkElement]::StyleProperty)
        $b.ToolTip = "เปิดแอปใหม่เพื่อโหลดโค้ดล่าสุดจากโฟลเดอร์นี้ (ตอนนี้ v$disk)"
    }
}

function Restart-SshLanApp {
    if ($script:Busy) { Add-Log '[!] รอให้งานที่ทำอยู่เสร็จก่อน แล้วกดอีกครั้ง'; return }
    $exe = Join-Path $root 'SSH LAN.exe'
    # same rights as now: an admin window comes back as admin (Windows asks once)
    $verb = if (Test-SshLanUiAdmin) { @{ Verb = 'RunAs' } } else { @{} }
    try {
        if (Test-Path -LiteralPath $exe) { Start-Process -FilePath $exe @verb }
        else {
            $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            Start-Process -FilePath $ps -ArgumentList '-NoProfile', '-STA', '-File', ('"' + (Join-Path $PSScriptRoot 'app.ps1') + '"') @verb
        }
    } catch { Add-Log ('[!] เปิดใหม่ไม่ได้: ' + $_.Exception.Message); return }
    $window.Close()
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
(Find 'BtnUpdate').Add_Click({ Restart-SshLanApp })
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
    $extra = @((Find 'ExtraIpBox').Text -split '[,\s]+' | Where-Object { $_ })
    # machines that saved the old address lose this PC the moment it changes: say so before, offer the way to keep them
    $cur = Get-SshLanPrimaryLanIp
    $want = if ($ip -match '^\d{1,3}$' -and $cur) { (($cur -split '\.')[0..2] -join '.') + ".$ip" } else { $ip }
    if ($cur -and $want -and $want -ne $cur -and -not $extra) {
        $last = ($cur -split '\.')[-1]
        $ask = [Windows.MessageBox]::Show("เครื่องที่บันทึก $cur ไว้ (SSH, แชร์ไฟล์, Remote Desktop) จะต่อเข้าเครื่องนี้ไม่ได้ จนกว่าจะเปลี่ยนไปใช้ $want`n`nถ้าอยากให้ยังต่อได้ระหว่างนี้ ให้กด ไม่ แล้วใส่ $last ในช่อง 'IP เดิมที่ยังให้ต่อเข้ามาได้'`n`nเปลี่ยนเป็น $want เลยไหม", 'SSH LAN', 'YesNo', 'Warning')
        if ($ask -ne 'Yes') { (Find 'ExtraIpBox').Text = $last; (Find 'ExtraIpBox').Focus() | Out-Null; return }
    }
    Invoke-Logged {
        Add-Log ("กำลังตั้งเลข IP คงที่เป็น $ip" + $(if ($extra) { " และเก็บ $($extra -join ', ') ไว้ชั่วคราว" } else { '' }) + ' ...')
        & (Join-Path $PSScriptRoot 'ssh-lan\set-lan-ip.ps1') -Ip $ip -Extra $extra
        Add-Log ' [✓] ตั้งเลข IP คงที่สำเร็จ'
    }
})

(Find 'BtnRemoveExtra').Add_Click({
    if (-not (Test-SshLanUiAdmin)) { Add-Log (Find 'StrNeedAdmin').Text; return }
    Invoke-Logged {
        Add-Log 'กำลังเอา IP ชั่วคราวออก...'
        & (Join-Path $PSScriptRoot 'ssh-lan\set-lan-ip.ps1') -RemoveExtra
        if (@(Get-SshLanExtraIps).Count) { throw "ยังเหลือ IP ชั่วคราว: $((Get-SshLanExtraIps) -join ', ')" }
        (Find 'ExtraIpBox').Text = ''
        Add-Log ' [✓] เอา IP ชั่วคราวออกแล้ว'
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

. (Join-Path $PSScriptRoot 'scan-ui.ps1')
. (Join-Path $PSScriptRoot 'audit-ui.ps1')
. (Join-Path $PSScriptRoot 'topology-ui.ps1')
(Find 'BtnLanScan').Add_Click({ Show-ScanWindow })
(Find 'BtnMap').Add_Click({ Show-MainTab 'map' })
(Find 'TabMap').Add_MouseLeftButtonUp({ Show-MainTab 'map' })
(Find 'TabLog').Add_MouseLeftButtonUp({ Show-MainTab 'log' })
# the map is the first thing the window shows
Show-MapWindow @() (Find 'MapHost')

(Find 'BtnRemove').Add_Click({
    if (-not (Test-SshLanIsServer)) { return }
    if (-not (Test-SshLanUiAdmin)) { Add-Log (Find 'StrNeedAdmin').Text; return }
    $ask = [Windows.MessageBox]::Show((Find 'StrAskRemove').Text, 'SSH LAN', 'YesNo', 'Warning')
    if ($ask -ne 'Yes') { return }
    Invoke-Logged {
        Add-Log "กำลังปิดการรับ SSH บนเครื่องนี้..."
        Invoke-SshLanRemove
        Add-Log " [✓] ปิดบริการ SSH และลบกฎไฟร์วอลล์เรียบร้อยแล้ว"
        try { if ($script:MapWin -and $script:MapDevices) { Start-MapRefresh @($script:MapDevices) } } catch { }
    }
})

$window.Add_Closed({
    $script:UiClosed = $true
    try { if ($script:UpdateTimer) { $script:UpdateTimer.Stop() } } catch {}
    try { Stop-ScanInvite } catch {}
    try { Stop-SshLanInventoryHub } catch {}
    try { if ($script:SubnetTimer) { $script:SubnetTimer.Stop() } } catch {}
    try { if ($script:SubnetPs) { $script:SubnetPs.Stop(); $script:SubnetPs.Dispose() } } catch {}
})
$window.Add_Loaded({
    # never larger than the screen it opens on (the default size suits 1080p and up)
    $area = [System.Windows.SystemParameters]::WorkArea
    if ($window.Width -gt $area.Width - 20) { $window.Width = $area.Width - 20; $window.Left = $area.Left + 10 }
    if ($window.Height -gt $area.Height - 20) { $window.Height = $area.Height - 20; $window.Top = $area.Top + 10 }
    try { Install-SshLanTaskbarShortcut } catch { }
    # native icons so the taskbar pill is not blank when hosted under powershell.exe
    try {
        $icoFile = Join-Path $root 'assets\ssh-lan.ico'
        if (Test-Path -LiteralPath $icoFile) {
            Add-Type -AssemblyName System.Drawing
            $hwnd = [IntPtr](New-Object System.Windows.Interop.WindowInteropHelper($window)).Handle
            $script:SshLanNativeIcon = New-Object System.Drawing.Icon($icoFile, 256, 256)
            [void][SshLanWindowIdentity]::SendMessage($hwnd, [SshLanWindowIdentity]::WM_SETICON, [IntPtr]1, $script:SshLanNativeIcon.Handle)
            $small = New-Object System.Drawing.Icon($icoFile, 16, 16)
            $script:SshLanNativeIconSmall = $small
            [void][SshLanWindowIdentity]::SendMessage($hwnd, [SshLanWindowIdentity]::WM_SETICON, [IntPtr]0, $small.Handle)
        }
    } catch { }
    try { Start-SshLanInventoryHub | Out-Null } catch { }
    Start-WindowIntro
    Update-SshLanUpdateButton
    $script:UpdateTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:UpdateTimer.Interval = [TimeSpan]::FromSeconds(10)
    $script:UpdateTimer.Add_Tick({ Update-SshLanUpdateButton })
    $script:UpdateTimer.Start()
    if ($script:ChromeStarted) { return }
    $script:ChromeStarted = $true
    $window.Dispatcher.BeginInvoke(
        [System.Action]{ Start-VisibleChrome },
        [System.Windows.Threading.DispatcherPriority]::ApplicationIdle
    ) | Out-Null
})
$window.ShowDialog() | Out-Null
