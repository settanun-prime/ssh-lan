# network map window, dot-sourced by app.ps1: draws every device the scan, the latest audit and Tailscale found.
# Real data only; the layout is fixed by the data. One motion, one meaning; none when Windows says to reduce motion.
# Uses app.ps1's $window, $markup, $root, Add-Log, Invoke-Logged
$script:MapWin = $null
$script:MapFlow = @{}        # FlowKey -> the drawn line and its dots, so a measurement can start or stop them without a redraw
$script:MapSeen = @{}        # keys already introduced: a refresh does not replay their entrance
$script:MapPos = @{}         # key -> last position, so a regroup slides tiles instead of jumping
$script:MapView = ''         # '' = automatic (link up to 12 devices, groups above)
$script:MapGroupBy = 'subnet'
$script:MapGlyph = @{
    router = [char]0xE88A; desktop = [char]0xE977; laptop = [char]0xE7F8; server = [char]0xE968; printer = [char]0xE749; camera = [char]0xE722
    tv = [char]0xE7F4; nas = [char]0xE8F1; plc = [char]0xE950; hmi = [char]0xEDA4; phone = [char]0xE8EA; computer = [char]0xE703; unknown = [char]0xE9CE
}
$script:MapColor = @{ red = '#F87171'; amber = '#F5C451'; green = '#4ADE80'; gray = '#8F9BB3' }

function Find-Map([string]$Name) { $script:MapWin.FindName($Name) }
function New-MapBrush([string]$Hex) { (New-Object Windows.Media.BrushConverter).ConvertFromString($Hex) }
function Test-MapMotion { [bool][Windows.SystemParameters]::ClientAreaAnimation }

function New-MapEase { $e = New-Object Windows.Media.Animation.ExponentialEase; $e.EasingMode = 'EaseOut'; $e.Exponent = 6; $e }

# one property animation; $Begin in ms
function Start-MapAnim($Target, $Property, $From, $To, [int]$Ms, [int]$Begin = 0, [switch]$Forever, [switch]$Reverse, [switch]$Linear) {
    $a = New-Object Windows.Media.Animation.DoubleAnimation
    if ($null -ne $From) { $a.From = $From }
    $a.To = $To
    $a.Duration = [TimeSpan]::FromMilliseconds($Ms)
    $a.BeginTime = [TimeSpan]::FromMilliseconds($Begin)
    if (-not $Linear) { $a.EasingFunction = New-MapEase }
    if ($Forever) { $a.RepeatBehavior = [Windows.Media.Animation.RepeatBehavior]::Forever }
    if ($Reverse) { $a.AutoReverse = $true }
    $Target.BeginAnimation($Property, $a)
}

function New-MapText([string]$Text, [double]$Size = 12, [string]$Color = '#F4F7FB', [switch]$Bold, [switch]$Glyph) {
    $t = New-Object Windows.Controls.TextBlock
    $t.Text = $Text; $t.FontSize = $Size; $t.Foreground = New-MapBrush $Color
    if ($Bold) { $t.FontWeight = 'SemiBold' }
    if ($Glyph) { $t.FontFamily = 'Segoe MDL2 Assets' }
    $t.TextTrimming = 'CharacterEllipsis'
    return $t
}

function Add-MapChild($El, [double]$X, [double]$Y, [int]$Z = 0) {
    [Windows.Controls.Canvas]::SetLeft($El, $X); [Windows.Controls.Canvas]::SetTop($El, $Y); [Windows.Controls.Panel]::SetZIndex($El, $Z)
    [void](Find-Map 'MapCanvas').Children.Add($El)
}

# a cable from the bus down to a device (style = wired / wifi / unknown / internet; ssh = paired and online: green, with a moving dot);
# Tailscale edges are drawn along their whole route
function Add-MapEdge($E, [int]$Begin, [bool]$Intro) {
    # cable gray (no fake traffic dots). green SSH = pair/login evidence; dots run on those lines only.
    $color = '#8F9BB3'
    $dash = $null; $opacity = 1
    switch ($E.Style) {
        'wifi' { $dash = '4,3' }
        'unknown' { $dash = '1,4'; $opacity = 0.55 }
        'tailscale' { $color = '#A78BFA'; $dash = '3,3'; $opacity = 0.85 }
        'internet' { $color = '#6B7487' }
        # SSH: dashed = set up / logged in before; solid = session open now
        'ssh' { $color = '#4ADE80'; if (-not $E.Live) { $dash = '5,3'; $opacity = 0.8 } }
    }
    if ($E.Ssh) { $color = '#4ADE80'; $dash = $null; $opacity = 1 }
    $motion = Test-MapMotion
    if ($E.Style -in 'tailscale', 'ssh') {
        $l = New-Object Windows.Shapes.Polyline
        foreach ($pt in $E.Points) { [void]$l.Points.Add((New-Object Windows.Point $pt[0], $pt[1])) }
        if ($Intro -and $motion) { Start-MapAnim $l ([Windows.UIElement]::OpacityProperty) 0 $opacity 500 $Begin } else { $l.Opacity = $opacity }
    } else {
        $l = New-Object Windows.Shapes.Line
        $l.X1 = $E.X1; $l.Y1 = $E.Y1; $l.X2 = $E.X2; $l.Y2 = $E.Y2; $l.Opacity = $opacity
        # found: the cable draws out toward the device (500 ms, expo-out)
        if ($Intro -and $motion) {
            Start-MapAnim $l ([Windows.Shapes.Line]::X2Property) $E.X1 $E.X2 500 $Begin
            Start-MapAnim $l ([Windows.Shapes.Line]::Y2Property) $E.Y1 $E.Y2 500 $Begin
        }
    }
    $l.StrokeThickness = 2
    if ($dash) { $l.StrokeDashArray = [Windows.Media.DoubleCollection]::Parse($dash) }
    $l.Stroke = New-MapBrush $color
    Add-MapChild $l 0 0 1
    # an arrowhead pointing up into the box at each end the SSH goes to: one = one way, two = both ways
    if ($E.Style -eq 'ssh') {
        $ends = @(); if ($E.Dir -in 'out', 'both') { $ends += , $E.Points[-1] }; if ($E.Dir -in 'in', 'both') { $ends += , $E.Points[0] }
        foreach ($pt in $ends) {
            $tri = New-Object Windows.Shapes.Polygon
            foreach ($q in @(@(0, 0), @(-5, 8), @(5, 8))) { [void]$tri.Points.Add((New-Object Windows.Point ($pt[0] + $q[0]), ($pt[1] + $q[1]))) }
            $tri.Fill = New-MapBrush $color; $tri.Opacity = $opacity
            Add-MapChild $tri 0 0 1
        }
    }
    #     # a dot only ever follows a measurement (Set-MapEdgeFlow): nothing here runs on its own, so a fresh map is still.
    # Canvas Left/Top stay 0 for the dots: DoubleAnimationUsingPath writes absolute path coords into the translate.
    if ($E.FlowKey) {
        $script:MapFlow[[string]$E.FlowKey] = @{ Edge = $E; Line = $l; Dots = @(); Dash = $dash; Opacity = $opacity; Color = $color; Sig = '' }
        # a redraw (the 30 s rescan) keeps what the last samples showed instead of going still until the next one
        Set-MapEdgeFlow ([string]$E.FlowKey) (Get-SshLanFlowState $E $script:MapFlowPrev $script:MapFlowNow)
    }
}

# the dots of one route: the path the dot follows (forward = From to To, or back) and its length
function New-MapFlowPath($Points, [bool]$Forward) {
    $pts = if ($Forward) { @($Points) } else { $r = @($Points); [array]::Reverse($r); @($r) }
    if (@($pts).Count -lt 2) { return $null }
    $fig = New-Object Windows.Media.PathFigure
    $fig.StartPoint = New-Object Windows.Point ([double]$pts[0][0]), ([double]$pts[0][1])
    $len = 0.0
    for ($i = 1; $i -lt $pts.Count; $i++) {
        $x = [double]$pts[$i][0]; $y = [double]$pts[$i][1]
        [void]$fig.Segments.Add((New-Object Windows.Media.LineSegment ((New-Object Windows.Point $x, $y), $true)))
        $len += [Math]::Abs($x - [double]$pts[$i - 1][0]) + [Math]::Abs($y - [double]$pts[$i - 1][1])
    }
    if ($len -lt 1) { return $null }
    $geo = New-Object Windows.Media.PathGeometry
    [void]$geo.Figures.Add($fig)
    return @{ Geo = $geo; Len = $len }
}

# put one edge into the state a measurement gave it (Get-SshLanFlowState): flow = dots run, offline = faint, anything else = still.
# Rx runs along the edge (From to To, router to device), Tx back; a fixed-speed line (SSH) follows its Dir
function Set-MapEdgeFlow([string]$FlowKey, $State) {
    $f = $script:MapFlow[$FlowKey]
    if (-not $f) { return }
    $f.Sig = Get-SshLanFlowSig $State
    $canvas = Find-Map 'MapCanvas'
    foreach ($d in @($f.Dots)) {
        foreach ($p in [Windows.Media.TranslateTransform]::XProperty, [Windows.Media.TranslateTransform]::YProperty) { $d.Tt.BeginAnimation($p, $null) }
        $canvas.Children.Remove($d.El)
    }
    $f.Dots = @()
    $l = $f.Line
    $l.BeginAnimation([Windows.UIElement]::OpacityProperty, $null)
    # an end that is down wins over any measurement: nothing runs to a machine that is off
    $kind = if ($f.Edge.Online -eq $false) { 'offline' } else { [string]$State.State }
    if ($kind -eq 'offline') {
        $l.StrokeDashArray = [Windows.Media.DoubleCollection]::Parse('1,4'); $l.Opacity = 0.35
    } else {
        if ($f.Dash) { $l.StrokeDashArray = [Windows.Media.DoubleCollection]::Parse($f.Dash) } else { $l.ClearValue([Windows.Shapes.Shape]::StrokeDashArrayProperty) }
        $l.Opacity = $f.Opacity
    }
    # the internet line has a ping, not a counter: green = got out, red dashed = did not, grey = no result
    $l.Stroke = New-MapBrush $(switch ([string]$State.Net) { 'up' { '#4ADE80' } 'down' { '#F87171' } default { $f.Color } })
    if ($State.Net -eq 'down') { $l.StrokeDashArray = [Windows.Media.DoubleCollection]::Parse('6,4') }
    if ($kind -ne 'flow' -or -not (Test-MapMotion)) { return }
    $runs = @()
    if ($State.Fixed) {
        $spec = @{ Dots = 1; Ms = 2000 }
        if ($f.Edge.Dir -in 'out', 'both') { $runs += @{ Fwd = $true; Spec = $spec } }
        if ($f.Edge.Dir -in 'in', 'both') { $runs += @{ Fwd = $false; Spec = $spec } }
    } else {
        $rx = ConvertTo-SshLanDotSpec ([double]$State.RxBps)
        $tx = ConvertTo-SshLanDotSpec ([double]$State.TxBps)
        if ($rx.Dots) { $runs += @{ Fwd = $true; Spec = $rx } }
        if ($tx.Dots) { $runs += @{ Fwd = $false; Spec = $tx } }
    }
    $fill = if ($f.Edge.Style -eq 'ssh') { '#86EFAC' } else { '#8FB8FF' }
    foreach ($run in $runs) {
        $path = New-MapFlowPath $f.Edge.Points $run.Fwd
        if (-not $path) { continue }
        for ($k = 0; $k -lt $run.Spec.Dots; $k++) {
            $dot = New-Object Windows.Shapes.Ellipse
            $dot.Width = 9; $dot.Height = 9; $dot.Fill = New-MapBrush $fill
            $dot.Stroke = New-MapBrush '#0B1220'; $dot.StrokeThickness = 1; $dot.IsHitTestVisible = $false
            $tt = New-Object Windows.Media.TranslateTransform
            $dot.RenderTransform = $tt
            Add-MapChild $dot -4.5 -4.5 4
            foreach ($axis in 'X', 'Y') {
                $a = New-Object Windows.Media.Animation.DoubleAnimationUsingPath
                $a.PathGeometry = $path.Geo; $a.Source = $axis
                $a.Duration = [TimeSpan]::FromMilliseconds($run.Spec.Ms)
                # dot k starts k/n of the trip in, now: a positive delay would leave it resting at the canvas corner until its turn
                $begin = -[int]($k * $run.Spec.Ms / $run.Spec.Dots)
                $a.BeginTime = [TimeSpan]::FromMilliseconds($begin)
                $a.RepeatBehavior = [Windows.Media.Animation.RepeatBehavior]::Forever
                $tt.BeginAnimation($(if ($axis -eq 'X') { [Windows.Media.TranslateTransform]::XProperty } else { [Windows.Media.TranslateTransform]::YProperty }), $a)
            }
            $f.Dots += @{ El = $dot; Tt = $tt; Fwd = [bool]$run.Fwd; Begin = $begin }
        }
    }
}

# the shared cabling under the router: spine and one bus per row
function Add-MapTrunk([object[]]$Segments, [bool]$Intro) {
    foreach ($seg in $Segments) {
        $l = New-Object Windows.Shapes.Line
        $l.X1 = $seg[0][0]; $l.Y1 = $seg[0][1]; $l.X2 = $seg[1][0]; $l.Y2 = $seg[1][1]
        $l.Stroke = New-MapBrush '#3A4560'; $l.StrokeThickness = 2
        Add-MapChild $l 0 0 0
        if ($Intro -and (Test-MapMotion)) { Start-MapAnim $l ([Windows.UIElement]::OpacityProperty) 0 1 300 }
    }
}

# a device: icon, name, address, audit dot, online pulse. Tiles in the group view are smaller
function Add-MapNode($Node, $Place, [int]$Begin, [bool]$Intro) {
    $small = [bool]$Place.Small
    $tile = [bool]$Place.Tile
    $b = New-Object Windows.Controls.Border
    $b.Width = $Place.W; $b.Height = $Place.H; $b.CornerRadius = $(if ($small) { 8 } else { 12 })
    $b.Background = New-MapBrush $(if ($Node.IsSelf) { '#1C2540' } else { '#151C2C' })
    $b.BorderThickness = 1
    $b.BorderBrush = New-MapBrush $(if ($script:MapSelected -eq $Node.Key) { '#F5C451' } elseif ($Node.Color -eq 'red') { '#7F2D33' } else { '#2A3348' })
    $b.Cursor = 'Hand'; $b.Tag = $Node.Key
    $grid = New-Object Windows.Controls.Grid
    if ($small) {
        # glyph, then "name  os · age" trimmed to the room left; the state dot sits at the right edge
        $row = New-Object Windows.Controls.DockPanel; $row.Margin = '8,0,24,0'; $row.VerticalAlignment = 'Center'; $row.LastChildFill = $true
        $g = New-MapText ([string]$script:MapGlyph[$Node.Kind]) 14 '#C4B5FD' -Glyph; $g.Margin = '0,0,8,0'; $g.VerticalAlignment = 'Center'
        [Windows.Controls.DockPanel]::SetDock($g, 'Left'); [void]$row.Children.Add($g)
        $age = if ($Node.Online) { 'ออนไลน์' } elseif ($Node.TsSeen) { Format-MapAge $Node.TsSeen } else { 'ออฟไลน์' }
        $t = New-Object Windows.Controls.TextBlock
        $t.TextTrimming = 'CharacterEllipsis'; $t.VerticalAlignment = 'Center'
        $r1 = New-Object Windows.Documents.Run "$($Node.Label)"; $r1.FontSize = 12; $r1.Foreground = New-MapBrush '#F4F7FB'
        $r2 = New-Object Windows.Documents.Run "  $($Node.Os) · $age"; $r2.FontSize = 11; $r2.Foreground = New-MapBrush $(if ($Node.Online) { '#86EFAC' } else { '#8F9BB3' })
        [void]$t.Inlines.Add($r1); [void]$t.Inlines.Add($r2)
        $t.ToolTip = "$($Node.Label) · $($Node.Os) · $age"
        [void]$row.Children.Add($t)
        [void]$grid.Children.Add($row)
    } else {
        $st = New-Object Windows.Controls.StackPanel; $st.VerticalAlignment = 'Center'; $st.Margin = '6,0,6,0'
        $g = New-MapText ([string]$script:MapGlyph[$Node.Kind]) $(if ($tile) { 20 } else { 28 }) $(if ($Node.IsRouter) { '#F5C451' } elseif ($Node.Kind -eq 'unknown') { '#6B7487' } else { '#DCE3F0' }) -Glyph
        $g.HorizontalAlignment = 'Center'; $g.Margin = $(if ($tile) { '0,0,0,2' } else { '0,0,0,4' })
        $n = New-MapText "$($Node.Label)" $(if ($tile) { 11 } else { 13 }) -Bold:(-not $tile); $n.HorizontalAlignment = 'Center'; $n.MaxWidth = $Place.W - 10
        [void]$st.Children.Add($g); [void]$st.Children.Add($n)
        if (-not $tile -or $Node.Name) {
            $ip = New-MapText $(if ($Node.Name) { $Node.Ip } else { $script:SshLanKinds[$Node.Kind] }) $(if ($tile) { 10 } else { 11 }) '#8F9BB3'
            $ip.HorizontalAlignment = 'Center'
            [void]$st.Children.Add($ip)
        }
        [void]$grid.Children.Add($st)
    }
    # audit result in the corner
    $dot = New-Object Windows.Shapes.Ellipse
    $dot.Width = 10; $dot.Height = 10; $dot.Fill = New-MapBrush $script:MapColor[[string]$Node.Color]
    $dot.HorizontalAlignment = 'Right'; $dot.VerticalAlignment = 'Top'; $dot.Margin = '0,6,6,0'
    # in the Tailscale list the dot is the node's state in the tailnet (it was never audited from here)
    if (-not $Node.InLan) { $dot.Fill = New-MapBrush $(if ($Node.Online) { '#4ADE80' } else { '#4B5568' }) }
    if ($small) { $dot.VerticalAlignment = 'Center'; $dot.Margin = '0,0,8,0' }
    [void]$grid.Children.Add($dot)
    # online: a slow pulse; offline: faded
    $live = New-Object Windows.Shapes.Ellipse
    $live.Width = 7; $live.Height = 7; $live.HorizontalAlignment = 'Left'; $live.VerticalAlignment = 'Top'; $live.Margin = '7,7,0,0'
    $live.Fill = New-MapBrush $(if ($Node.Online) { '#4ADE80' } else { '#4B5568' })
    if (-not $small) { [void]$grid.Children.Add($live) }
    if ($Node.Paired -and -not $small) {
        $k = New-MapText ([string][char]0xE8D7) 10 '#4ADE80' -Glyph
        $k.HorizontalAlignment = 'Left'; $k.ToolTip = "จับคู่ SSH แล้ว ($($Node.Alias))"
        if ($tile) { $k.VerticalAlignment = 'Top'; $k.Margin = '18,4,0,0' } else { $k.VerticalAlignment = 'Bottom'; $k.Margin = '7,0,0,6' }
        [void]$grid.Children.Add($k)
    }
    # purple mark = on the tailnet (membership). Top-right, left of the audit dot — never over the IP line.
    if (@($Node.TsIps).Count -and $Node.InLan -ne $false -and -not $small) {
        $tsMark = New-MapText 'TS' 9 '#C4B5FD' -Bold
        $tsMark.HorizontalAlignment = 'Right'; $tsMark.VerticalAlignment = 'Top'; $tsMark.Margin = '0,4,18,0'
        $tsMark.ToolTip = "มี Tailscale ($($Node.TsIps[0])) · ไม่ได้แปลว่าเข้าทุกบริการได้ ดูพอร์ตในแผงข้าง"
        [void]$grid.Children.Add($tsMark)
    }
    $soon = $null
    if ($Node.TempOpen -and -not $small) {
        foreach ($t in $Node.TempOpen) {
            if (-not $t -or -not $t.Expires) { continue }
            if (-not $soon -or ([datetime]$t.Expires) -lt ([datetime]$soon.Expires)) { $soon = $t }
        }
    }
    if ($soon) {
        $badge = New-Object Windows.Controls.StackPanel
        $badge.Orientation = 'Horizontal'
        $badge.HorizontalAlignment = 'Left'
        $badge.VerticalAlignment = 'Bottom'
        $badge.Margin = '6,0,28,4'
        $pulse = New-Object Windows.Shapes.Ellipse
        $pulse.Width = 6; $pulse.Height = 6; $pulse.Fill = New-MapBrush '#F5C451'; $pulse.Margin = '0,0,4,0'; $pulse.VerticalAlignment = 'Center'
        $tb = New-MapText ("เปิด $($soon.Port) · " + (Format-MapTempLeft $soon.Expires)) 9 '#F5C451'
        $tb.VerticalAlignment = 'Center'
        $tb.MaxWidth = [Math]::Max(40, $Place.W - 40)
        $tipLines = New-Object System.Collections.Generic.List[string]
        foreach ($t in $Node.TempOpen) { if ($t -and $t.Expires) { [void]$tipLines.Add("พอร์ต $($t.Port) เหลือ $(Format-MapTempLeft $t.Expires)") } }
        $badge.ToolTip = ($tipLines -join "`n")
        [void]$badge.Children.Add($pulse)
        [void]$badge.Children.Add($tb)
        [void]$grid.Children.Add($badge)
        if (-not $script:MapTempBadges) { $script:MapTempBadges = New-Object System.Collections.Generic.List[object] }
        [void]$script:MapTempBadges.Add(@{ Block = $tb; Badge = $badge; NodeKey = $Node.Key })
        if (Test-MapMotion) { Start-MapAnim $pulse ([Windows.UIElement]::OpacityProperty) 1 0.25 1200 0 -Forever -Reverse -Linear }
    }
    $b.Child = $grid
    if (-not $Node.Online) { $b.Opacity = 0.5 }
    $tr = New-Object Windows.Media.TranslateTransform
    $b.RenderTransform = $tr
    $old = $script:MapPos[$Node.Key]
    $startX = $Place.X; $startY = $Place.Y
    if ($old -and -not $Intro -and (Test-MapMotion)) { $startX = $old.X; $startY = $old.Y }
    Add-MapChild $b $startX $startY 5
    $script:MapPos[$Node.Key] = @{ X = $Place.X; Y = $Place.Y }
    $motion = Test-MapMotion
    if ($motion) {
        if ($Intro) {
            # found: floats up at the end of its line
            $b.Opacity = 0
            Start-MapAnim $b ([Windows.UIElement]::OpacityProperty) 0 $(if ($Node.Online) { 1 } else { 0.5 }) 550 $Begin
            Start-MapAnim $tr ([Windows.Media.TranslateTransform]::YProperty) 14 0 550 $Begin
        } elseif ($startX -ne $Place.X -or $startY -ne $Place.Y) {
            # regrouped: slides to its new place
            Start-MapAnim $b ([Windows.Controls.Canvas]::LeftProperty) $startX $Place.X 600
            Start-MapAnim $b ([Windows.Controls.Canvas]::TopProperty) $startY $Place.Y 600
        }
        if ($Node.Online -and -not $small) { Start-MapAnim $live ([Windows.UIElement]::OpacityProperty) 1 0.25 1200 0 -Forever -Reverse -Linear }
        if ($Node.Color -eq 'red') { Start-MapAnim $dot ([Windows.UIElement]::OpacityProperty) 1 0.3 1000 0 -Forever -Reverse -Linear }
    }
    $b.Add_MouseEnter({ param($s) Start-MapHover $s })
    $b.Add_MouseLeave({ Stop-MapHover })
    $b.Add_MouseLeftButtonUp({ param($s) Select-MapNode ([string]$s.Tag) })
    $script:MapEls[$Node.Key] = $b
}

function Get-MapNode([string]$Key) { @(@($script:MapModel.Nodes) + @($script:MapModel.Tailscale) | Where-Object { $_.Key -eq $Key })[0] }

# --- hover: after 300 ms a card floats beside the device (fade + 6 px slide, 180 ms) ---
function Start-MapHover($El) {
    Stop-MapHover
    $script:MapHoverEl = $El
    $script:MapHoverTimer = New-Object Windows.Threading.DispatcherTimer
    $script:MapHoverTimer.Interval = [TimeSpan]::FromMilliseconds(300)
    $script:MapHoverTimer.Add_Tick({ $script:MapHoverTimer.Stop(); Show-MapCard $script:MapHoverEl })
    $script:MapHoverTimer.Start()
}

function Stop-MapHover {
    if ($script:MapHoverTimer) { $script:MapHoverTimer.Stop() }
    if ($script:MapCard) { (Find-Map 'MapCanvas').Children.Remove($script:MapCard); $script:MapCard = $null }
}

# which way SSH goes between this PC and the machine, and the proof for each way
function Get-MapSshWay($N) {
    $ways = @()
    if ($N.SshOut) { $ways += "เครื่องนี้ → เครื่องนั้น (จับคู่ไว้ใน ~/.ssh/config)" }
    if ($N.SshIn) { $ways += "เครื่องนั้น → เครื่องนี้ ($(if ($N.SshInAt) { 'ล็อกอินเข้ามาล่าสุด ' + (Format-MapAge $N.SshInAt) } else { 'ต่อเข้ามาอยู่ตอนนี้' }))" }
    if (-not $ways) { return '' }
    $head = if ($N.SshOut -and $N.SshIn) { 'SSH สองทาง' } else { 'SSH ทางเดียว' }
    return "${head}$(if ($N.SshLive) { ' · มี session เปิดอยู่' }): " + ($ways -join ' · ')
}

function Show-MapCard($El) {
    $n = Get-MapNode ([string]$El.Tag)
    if (-not $n) { return }
    $c = New-Object Windows.Controls.Border
    $c.Width = 260; $c.Padding = '12,10'; $c.CornerRadius = 10; $c.Background = New-MapBrush '#1A2133'; $c.BorderBrush = New-MapBrush '#3A4560'; $c.BorderThickness = 1
    $c.IsHitTestVisible = $false
    $st = New-Object Windows.Controls.StackPanel
    $line = { param($t, $s = 12, $col = '#C5CEDD', [switch]$b) $x = New-MapText $t $s $col -Bold:$b; $x.TextWrapping = 'Wrap'; $x.Margin = '0,0,0,3'; [void]$st.Children.Add($x) }
    & $line $n.Label 14 '#F4F7FB' -b
    & $line "$($script:SshLanKinds[$n.Kind]) · $($n.KindEvidence)" 11 '#8F9BB3'
    & $line "IP $($n.Ip)$(if ($n.Mac) { "  ·  MAC $($n.Mac)" })"
    if ($n.Clash) { & $line $n.Clash 12 $script:MapColor['amber'] }
    & $line "ระบบ: $(if ($n.Os) { "$($n.Os) ($($n.OsFrom))" } else { 'ไม่ทราบ' })"
    & $line "ต่อแบบ: $(@{ wired = 'สายแลน'; wifi = 'Wi-Fi'; tailscale = 'Tailscale'; unknown = 'ไม่ทราบ' }[$n.Link])"
    & $line "พอร์ตที่เปิด: $(if ($n.Services) { $n.Services } elseif (@($n.Ports).Count) { @($n.Ports) -join ', ' } else { 'ไม่พบ' })"
    & $line "SSH: $(if ($n.Paired) { "จับคู่แล้ว ($($n.Alias))" } else { 'ยังไม่จับคู่' }) · $(if ($n.Online) { 'ออนไลน์' } else { 'ออฟไลน์' })"
    $way = Get-MapSshWay $n
    if ($way) { & $line $way 12 '#4ADE80' }
    & $line (Get-MapNodeFlowText $n) 12 '#8FB8FF'
    $au = if ($n.Audited) { "audit: แดง $($n.Red) เหลือง $($n.Amber)" + $(if ($n.AuditError) { " · $($n.AuditError)" }) } else { 'audit: ยังไม่ได้ตรวจ' }
    & $line $au 12 $script:MapColor[[string]$n.Color]
    & $line 'คลิกเพื่อดูทั้งหมดและสั่งงาน' 11 '#6B7487'
    $c.Child = $st
    $x = [Windows.Controls.Canvas]::GetLeft($El); $y = [Windows.Controls.Canvas]::GetTop($El)
    $canvas = Find-Map 'MapCanvas'
    # on the side with room, never on top of the device
    $cx = if ($x + $El.Width + 12 + 260 -le $canvas.Width) { $x + $El.Width + 12 } else { [Math]::Max(0, $x - 272) }
    # keep the card inside the part of the map that is on screen
    $sv = Find-Map 'MapScroll'; $z = (Find-Map 'MapScale').ScaleX
    $bottom = if ($sv.ViewportHeight) { ($sv.VerticalOffset + $sv.ViewportHeight) / $z } else { $canvas.Height }
    $cy = [Math]::Max(0, [Math]::Min($y, [Math]::Min($canvas.Height, $bottom) - 250))
    $tr = New-Object Windows.Media.TranslateTransform
    $c.RenderTransform = $tr
    Add-MapChild $c $cx $cy 50
    $script:MapCard = $c
    if (Test-MapMotion) {
        Start-MapAnim $c ([Windows.UIElement]::OpacityProperty) 0 1 180
        Start-MapAnim $tr ([Windows.Media.TranslateTransform]::YProperty) 6 0 180
    }
}

# --- click: the full record pinned in the side panel ---
# one section of the record: a quiet heading, then label / value rows on a fixed grid; values never truncate
function Add-SideSection([string]$Title, [object[]]$Rows) {
    $body = Find-Map 'SideBody'
    $h = New-MapText $Title 11 '#8F9BB3' -Bold
    $h.Margin = $(if ($body.Children.Count) { '0,18,0,8' } else { '0,4,0,8' })
    [void]$body.Children.Add($h)
    Add-SideRows $Rows
}

function Add-SideRows([object[]]$Rows) {
    $body = Find-Map 'SideBody'
    foreach ($r in @($Rows)) {
        if (-not $r) { continue }
        $g = New-Object Windows.Controls.Grid
        $g.Margin = '0,0,0,7'
        foreach ($w in 96, 1, 26) {
            $c = New-Object Windows.Controls.ColumnDefinition
            $c.Width = $(if ($w -eq 1) { New-Object Windows.GridLength 1, 'Star' } else { New-Object Windows.GridLength $w })
            [void]$g.ColumnDefinitions.Add($c)
        }
        $k = New-MapText $r.K 12 '#8F9BB3'
        $k.TextWrapping = 'Wrap'; $k.TextTrimming = 'None'; $k.Margin = '0,1,10,0'
        [void]$g.Children.Add($k)
        $textRow = New-Object Windows.Controls.StackPanel
        $textRow.Orientation = 'Horizontal'
        if ($r.Dot) {
            $d = New-Object Windows.Shapes.Ellipse
            $d.Width = 8; $d.Height = 8; $d.Fill = New-MapBrush $r.Dot; $d.Margin = '0,6,8,0'; $d.VerticalAlignment = 'Top'
            [void]$textRow.Children.Add($d)
        }
        $shown = [string]$r.V
        if ($r.Clock) { $shown = "พอร์ต $($r.Clock.Port) เหลือ $(Format-MapTempLeft $r.Clock.Expires)" }
        $v = New-MapText $(if ($shown) { $shown } else { 'ไม่ทราบ' }) 13 $(if (-not $shown) { '#6B7487' } elseif ($r.C) { $r.C } else { '#E4E9F2' })
        $v.TextWrapping = 'Wrap'; $v.TextTrimming = 'None'
        $v.MaxWidth = 210 - $(if ($r.Dot) { 16 } else { 0 })
        if ($r.Mono) { $v.FontFamily = 'Consolas, Leelawadee UI' }
        [void]$textRow.Children.Add($v)
        if ($r.Clock) {
            if (-not $script:MapTempRows) { $script:MapTempRows = New-Object System.Collections.Generic.List[object] }
            [void]$script:MapTempRows.Add(@{ Block = $v; Port = [int]$r.Clock.Port; Expires = [datetime]$r.Clock.Expires })
        }
        $cell = $textRow
        if ($r.Btn -and [string]$r.Btn.Label) {
            $cell = New-Object Windows.Controls.StackPanel
            [void]$cell.Children.Add($textRow)
            $act = New-Object Windows.Controls.Button
            $act.Style = $body.FindResource('MapTool')
            $act.Content = [string]$r.Btn.Label
            $act.IsEnabled = [bool]$r.Btn.Enabled
            if ($r.Btn.Tip) { $act.ToolTip = [string]$r.Btn.Tip }
            [Windows.Controls.ToolTipService]::SetShowOnDisabled($act, $true)
            $act.Height = 28; $act.FontSize = 12; $act.Padding = '10,0,10,0'; $act.HorizontalAlignment = 'Left'; $act.Margin = '0,4,0,0'
            if ($r.Btn.Do) {
                $act.Tag = $r.Btn.Do
                $act.Add_Click({ param($s, $e) if ($s.Tag) { & $s.Tag } })
            } elseif ($r.Btn.Job) {
                $act.Tag = $r.Btn.Job
                $act.Add_Click({
                    param($s, $e)
                    $b = $s.Tag
                    if (-not $b) { return }
                    Start-MapControl -Key $b.Key -Mode $b.Mode -Finding $b.Finding -Switch $b.Switch -Label $b.Label -ChangeId $b.ChangeId -What $b.What -Port ([int]$b.Port) -Hours ([int]$b.Hours)
                })
            }
            [void]$cell.Children.Add($act)
        }
        [Windows.Controls.Grid]::SetColumn($cell, 1)
        [void]$g.Children.Add($cell)
        if ($r.Copy) {
            $btn = New-Object Windows.Controls.Button
            $btn.Style = $body.FindResource('MapIcon')
            $btn.Content = [string][char]0xE8C8; $btn.Tag = [string]$r.Copy; $btn.ToolTip = "คัดลอก $($r.Copy)"; $btn.VerticalAlignment = 'Top'
            $btn.Add_Click({ param($s) [Windows.Clipboard]::SetText([string]$s.Tag); Add-Log "คัดลอก $($s.Tag) แล้ว" })
            [Windows.Controls.Grid]::SetColumn($btn, 2)
            [void]$g.Children.Add($btn)
        }
        [void]$body.Children.Add($g)
    }
}

# a small rounded label in the record header
function Add-SideChip([string]$Text, [string]$Fg = '#C5CEDD', [string]$Bg = '#1C2539') {
    $c = New-Object Windows.Controls.Border
    $c.CornerRadius = 9; $c.Padding = '8,2,8,3'; $c.Margin = '0,0,6,4'; $c.Background = New-MapBrush $Bg
    $c.Child = New-MapText $Text 11 $Fg
    [void](Find-Map 'SideChips').Children.Add($c)
}

# "10 ชม. ก่อน" style age for Tailscale's last-seen
function Format-MapAge($When) {
    if (-not $When) { return '' }
    $m = [int]((Get-Date) - [datetime]$When).TotalMinutes
    if ($m -lt 2) { return 'เมื่อสักครู่' }
    if ($m -lt 60) { return "$m นาทีก่อน" }
    if ($m -lt 1440) { return "$([int]($m / 60)) ชม. ก่อน" }
    return "$([int]($m / 1440)) วันก่อน"
}

function Format-MapTempLeft($Expires) {
    $left = ([datetime]$Expires) - (Get-Date)
    if ($left.TotalSeconds -lt 60) { return '0 ชม. 0 นาที' }
    $h = [int][Math]::Floor($left.TotalHours)
    return "$h ชม. $($left.Minutes) นาที"
}

function ConvertTo-MapSwitchDevice($Node) {
    [pscustomobject]@{
        Name = [string]$Node.Label; Ip = [string]$Node.Ip; Mac = [string]$Node.Mac; Os = [string]$Node.Os
        Alias = [string]$Node.Alias; Note = [string]$Node.Note; Facts = $Node.Facts
    }
}

function Test-MapMember($Node) {
    if ($Node.IsSelf -or "$($Node.Note)" -eq 'เครื่องนี้') { return $true }
    $member = Get-SshLanBag $Node.Facts 'member'
    if ($member -eq $true -or "$member" -eq 'True') { return $true }
    if ($Node.Paired) { return $true }
    return $false
}

function Get-MapFirewallOn($Node) {
    $raw = Get-SshLanBag $Node.Facts 'firewallOn'
    if ($raw -eq $false -or "$raw" -eq 'False') { return $false }
    if ($raw -eq $true -or "$raw" -eq 'True') { return $true }
    foreach ($f in @($Node.Findings)) { if ("$($f.Reason)" -like 'ไฟร์วอลล์ปิด*') { return $false } }
    if ($Node.Audited -and (Test-MapMember $Node)) { return $true }
    return $null
}

function Get-MapSwitchLabel($Switch) {
    $label = [string]$Switch.Label
    if (-not $label -and [string]$Switch.Action -ne 'none') { $label = [string]$Switch.Why }
    return $label
}

function New-MapJob([string]$Key, [string]$Mode, $Finding, $Switch, [string]$Label, [string]$ChangeId, [string]$What, [int]$Port, [int]$Hours) {
    @{ Key = $Key; Mode = $Mode; Finding = $Finding; Switch = $Switch; Label = $Label; ChangeId = $ChangeId; What = $What; Port = $Port; Hours = $Hours }
}

function New-MapProtectDo([string]$Key) {
    $k = $Key
    return { Invoke-MapProtect $k }.GetNewClosure()
}

function Invoke-MapProtect([string]$Key) {
    if ($script:MapBusy) { return }
    $n = Get-MapNode $Key
    if (-not $n) { return }
    $device = ConvertTo-MapSwitchDevice $n
    $on = Test-SshLanProtected $device @(Get-SshLanProtected)
    Set-SshLanProtected ([string]$n.Mac) ([string]$n.Ip) ([string]$n.Label) (-not $on)
    if ($on) { Add-Log "เลิกห้ามแก้ $($n.Label)" } else { Add-Log "ตั้ง $($n.Label) เป็นห้ามแก้" }
    Select-MapNode $Key
}

function Format-MapChangeLine($Change) {
    $t = ConvertTo-SshLanChangeTime (Get-SshLanText $Change 'time')
    $when = if ($t -ne [datetime]::MinValue) { $t.ToString('dd/MM HH:mm') } else { '' }
    $port = [int](Get-SshLanText $Change 'port')
    $act = switch (Get-SshLanText $Change 'action') {
        'close' { "ปิดพอร์ต $port" }
        'firewall-on' { 'เปิดไฟร์วอลล์' }
        'temp-open' { "เปิดพอร์ต $port จากนอกบ้าน" }
        'upnp-delete' { "ลบการเปิดพอร์ต $port ที่เราเตอร์" }
        default { Get-SshLanText $Change 'action' }
    }
    if (Get-SshLanText $Change 'undoneAt') { $act = "$act · ย้อนแล้ว" }
    @{ When = $when; Text = $act }
}

function Add-MapComboItem($Box, [string]$Text, $Tag) {
    $it = New-Object Windows.Controls.ComboBoxItem
    $it.Content = $Text; $it.Tag = $Tag
    [void]$Box.Items.Add($it)
}

function Add-MapTempOpenPicker($Node) {
    $key = [string]$Node.Key
    $os = [string]$Node.Os
    if (-not $os -and $Node.IsSelf) { $os = 'Windows' }
    $wrap = New-Object Windows.Controls.StackPanel
    $wrap.Margin = '0,2,0,8'
    $cap = New-MapText 'เปิดจากนอกบ้าน' 12 '#8F9BB3'
    $cap.Margin = '0,0,0,6'
    [void]$wrap.Children.Add($cap)
    $row = New-Object Windows.Controls.StackPanel
    $row.Orientation = 'Horizontal'
    $what = New-Object Windows.Controls.ComboBox
    $what.Width = 148; $what.Height = 32; $what.Margin = '0,0,8,0'; $what.VerticalContentAlignment = 'Center'
    Add-MapComboItem $what 'SSH' 'ssh'
    if ($os -match 'Windows') { Add-MapComboItem $what 'Remote Desktop' 'rdp' }
    Add-MapComboItem $what 'พอร์ตอื่น…' 'port'
    $what.SelectedIndex = 0
    $hours = New-Object Windows.Controls.ComboBox
    $hours.Width = 84; $hours.Height = 32; $hours.Margin = '0,0,8,0'; $hours.VerticalContentAlignment = 'Center'
    foreach ($h in 1, 2, 4, 8) { Add-MapComboItem $hours "$h ชม." $h }
    $hours.SelectedIndex = 0
    $btn = New-Object Windows.Controls.Button
    $btn.Style = (Find-Map 'SideBody').FindResource('MapTool')
    $btn.Content = 'เปิด'; $btn.Height = 32; $btn.Padding = '12,0,12,0'
    $btn.Tag = @{ What = $what; Hours = $hours; Key = $key }
    $btn.Add_Click({
        param($s, $e)
        $bag = $s.Tag
        $picked = [string]$bag.What.SelectedItem.Tag
        $span = [int]$bag.Hours.SelectedItem.Tag
        $port = 0
        if ($picked -eq 'port') {
            Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue
            $text = [Microsoft.VisualBasic.Interaction]::InputBox('เลขพอร์ตที่เปิดจากนอกบ้าน', 'SSH LAN', '')
            if (-not "$text") { return }
            try { $port = ConvertTo-SshLanControlPort $text } catch { Add-Log ('[!] ' + $_.Exception.Message); return }
        }
        Start-MapControl -Key $bag.Key -Mode 'temp-open' -Label "เปิดจากนอกบ้าน $span ชม." -What $picked -Port $port -Hours $span
    })
    [void]$row.Children.Add($what); [void]$row.Children.Add($hours); [void]$row.Children.Add($btn)
    [void]$wrap.Children.Add($row)
    [void](Find-Map 'SideBody').Children.Add($wrap)
}

function Show-MapControls($Node) {
    if (-not (Test-MapMember $Node)) {
        Add-SideSection 'ควบคุม' @(@{ K = 'สถานะ'; V = 'ยังไม่ได้เข้าวง: ตั้งค่าได้ที่หน้าเว็บของอุปกรณ์' })
        return
    }
    $device = ConvertTo-MapSwitchDevice $Node
    $protected = @(Get-SshLanProtected)
    $rules = New-Object System.Collections.Generic.List[object]
    $rawRules = Get-SshLanBag $Node.Facts 'rules'
    if ($rawRules) { foreach ($r in $rawRules) { if ($r) { [void]$rules.Add($r) } } }
    $fwOn = Get-MapFirewallOn $Node
    $fwText = 'ไม่ทราบ'
    if ($fwOn -eq $true) { $fwText = 'เปิดอยู่' }
    if ($fwOn -eq $false) { $fwText = 'ปิดอยู่' }
    $fwRow = @{ K = 'ไฟร์วอลล์'; V = $fwText; Dot = $(if ($fwOn -eq $false) { $script:MapColor['red'] } elseif ($fwOn -eq $true) { '#4ADE80' }) }
    if ($fwOn -eq $false) {
        $fwFinding = $null
        foreach ($f in @($Node.Findings)) { if ("$($f.Reason)" -like 'ไฟร์วอลล์ปิด*') { $fwFinding = $f; break } }
        if (-not $fwFinding) {
            $fwFinding = [pscustomobject]@{ Port = 0; Os = [string]$Node.Os; Ip = [string]$Node.Ip; Machine = [string]$Node.Label; Reason = 'ไฟร์วอลล์ปิดอยู่'; Via = ''; Exposure = ''; Process = ''; Rule = '' }
        }
        $fwSwitch = Get-SshLanSwitch $fwFinding $device $true $false $protected $rules.ToArray()
        $fwLabel = Get-MapSwitchLabel $fwSwitch
        if ($fwLabel) {
            $fwRow.Btn = @{
                Label = $fwLabel; Enabled = [bool]$fwSwitch.Enabled; Tip = $(if ($fwSwitch.Why) { [string]$fwSwitch.Why } else { $fwLabel })
                Job = (New-MapJob $Node.Key 'switch' $fwFinding $fwSwitch $fwLabel '' '' 0 0)
            }
        }
    }
    $prot = Test-SshLanProtected $device $protected
    $protLabel = if ($prot) { 'เลิกห้ามแก้' } else { 'ตั้งเป็นห้ามแก้' }
    Add-SideSection 'ควบคุม' @(
        $fwRow
        @{ K = 'ห้ามแอปแก้'; V = $(if ($prot) { 'ห้ามแอปแก้ไว้' } else { 'แอปแก้ได้' }); Btn = @{ Label = $protLabel; Enabled = $true; Tip = $protLabel; Do = (New-MapProtectDo $Node.Key) } }
    )
    Add-MapTempOpenPicker $Node
    $openRows = New-Object System.Collections.Generic.List[object]
    foreach ($t in $Node.TempOpen) {
        if (-not $t) { continue }
        [void]$openRows.Add(@{
            K = 'เปิดอยู่'; V = ''; Clock = @{ Port = [int]$t.Port; Expires = [datetime]$t.Expires }
            Btn = @{ Label = 'ปิดตอนนี้'; Enabled = $true; Tip = 'ปิดการเปิดแบบมีเวลานี้'; Job = (New-MapJob $Node.Key 'temp-close' $null $null 'ปิดตอนนี้' ([string]$t.ChangeId) '' ([int]$t.Port) 0) }
        })
    }
    if ($openRows.Count) { Add-SideRows $openRows.ToArray() }
    $changeRows = New-Object System.Collections.Generic.List[object]
    $seen = @()
    if ($Node.Mac) { $seen = @(Get-SshLanChanges ([string]$Node.Mac) 5) }
    if (-not $seen.Count) { [void]$changeRows.Add(@{ K = 'รายการ'; V = 'ยังไม่มี' }) }
    foreach ($c in $seen) {
        $line = Format-MapChangeLine $c
        $row = @{ K = $line.When; V = $line.Text }
        if (-not (Get-SshLanText $c 'undoneAt')) {
            $row.Btn = @{ Label = 'ย้อน'; Enabled = $true; Tip = 'ย้อนรายการนี้'; Job = (New-MapJob $Node.Key 'undo' $null $null 'ย้อน' ([string]$c.id) '' 0 0) }
        }
        [void]$changeRows.Add($row)
    }
    Add-SideSection 'เปลี่ยนล่าสุด' $changeRows.ToArray()
}

function Add-MapTempChange($Device, [string]$Os, [int]$Port, $Expires) {
    $minute = Get-SshLanTempMinute ([datetime]$Expires)
    $rule = Get-SshLanTempRuleName $Port $minute
    Add-SshLanChange @{
        machine = (Get-SshLanText $Device 'Name'); ip = (Get-SshLanText $Device 'Ip'); mac = (Get-SshLanText $Device 'Mac')
        os = $Os; action = 'temp-open'; port = $Port; rules = @($rule); before = @{}; expires = $minute.ToString('o')
    } | Out-Null
}

function Start-MapSudo([string]$Alias, [string]$ScriptText) {
    if ($Alias -notmatch '^[A-Za-z0-9._-]+$') { return $null }
    $one = ((@($ScriptText -split "`r?`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join '; ')
    $remote = "sudo sh -c '" + $one.Replace("'", "'\''") + "'"
    $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    if (-not (Test-Path -LiteralPath $ssh)) { $ssh = 'ssh' }
    $proc = Start-Process -FilePath $ssh -ArgumentList @('-t', $Alias, $remote) -PassThru
    $null = $proc.Handle
    return $proc
}

function Complete-MapControl([bool]$Ok, [string]$Message) {
    $mark = if ($Ok) { '[✓]' } else { '[!]' }
    Add-Log "$mark $($script:MapActLabel) บน $($script:MapActMachine) ($($script:MapActIp)): $Message"
    $script:MapBusy = $false
    $script:MapSudo = $null
    $script:MapSudoProc = $null
    try { if ($script:MapActPs) { $script:MapActPs.Dispose() } } catch {}
    $script:MapActPs = $null
    $script:MapActHandle = $null
    if ($script:MapActTimer) { $script:MapActTimer.Stop() }
    Stop-MapLoadMotion
    if ($script:MapWin) {
        try { (Find-Map 'SideBody').IsEnabled = $true } catch {}
        try { (Find-Map 'BtnMapScan').IsEnabled = $true } catch {}
        if ($script:MapModel) { Update-MapModel }
    }
}

function Start-MapControl([string]$Key, [string]$Mode, $Finding, $Switch, [string]$Label, [string]$ChangeId, [string]$What, [int]$Port, [int]$Hours) {
    if ($script:MapBusy) { return }
    $n = Get-MapNode $Key
    if (-not $n) { return }
    $device = ConvertTo-MapSwitchDevice $n
    if ($Mode -eq 'switch') {
        if (-not (Confirm-SshLanSwitch $device $Finding $Switch)) { return }
        if (-not $Label) { $Label = Get-MapSwitchLabel $Switch }
    } else {
        $fake = @{ Action = $Mode; Enabled = $true; Label = $Label; AlsoPorts = @() }
        $who = $Finding
        if (-not $who) { $who = [pscustomobject]@{ Port = $Port; Os = [string]$n.Os; Ip = [string]$n.Ip; Machine = [string]$n.Label } }
        if (-not (Confirm-SshLanSwitch $device $who $fake)) { return }
    }
    $os = [string]$n.Os
    if (-not $os -and $n.IsSelf) { $os = 'Windows' }
    $script:MapBusy = $true
    $script:MapActLabel = $Label
    $script:MapActMachine = [string]$n.Label
    $script:MapActIp = [string]$n.Ip
    $script:MapActDevice = $device
    $script:MapActFinding = $Finding
    $script:MapActSwitch = $Switch
    $script:MapActMode = $Mode
    $script:MapSudo = $null
    $script:MapSudoProc = $null
    try { (Find-Map 'SideBody').IsEnabled = $false; (Find-Map 'BtnMapScan').IsEnabled = $false } catch {}
    Start-MapLoadMotion "กำลัง $Label บน $($n.Label)…"
    $script:MapActPs = [powershell]::Create()
    $null = $script:MapActPs.AddScript({
        param($Root, $Mode, $Device, $Finding, $Switch, $Os, $What, $Port, $Hours, $ChangeId)
        $ErrorActionPreference = 'Continue'
        $env:SSH_LAN_UI = '1'
        . (Join-Path $Root 'scripts\ssh-lan-common.ps1')
        . (Join-Path $Root 'scripts\ssh-lan\ssh-lan.ps1')
        $sudo = 'ต้องใส่รหัสของเครื่องนั้น'
        try {
            if ($Mode -eq 'switch') { return (Invoke-SshLanSwitch $Device $Finding $Switch) }
            if ($Mode -eq 'temp-open') {
                $osName = ConvertTo-SshLanControlOs $Os
                $target = Resolve-SshLanTempTarget $osName $What $Port
                $result = Open-SshLanTemp $Device $Os $What $Port $Hours
                if ([string]$result.Message -eq $sudo) {
                    $expires = $result.Expires
                    if (-not $expires) { $expires = Get-SshLanTempExpiry $Hours }
                    $result['Script'] = Get-SshLanTempOpenScript $osName $target.Port $expires ([bool]$target.Rdp)
                    $result['Alias'] = Get-SshLanText $Device 'Alias'
                    $result['Expires'] = $expires
                    $result['Port'] = $target.Port
                    $result['Os'] = $osName
                }
                return $result
            }
            if ($Mode -eq 'temp-close' -or ($Mode -eq 'undo' -and (Get-SshLanText (Get-SshLanChangeById $ChangeId) 'action') -eq 'temp-open')) {
                $result = Close-SshLanTempNow $Device $ChangeId
                if ([string]$result.Message -eq $sudo) {
                    $row = Get-SshLanChangeById $ChangeId
                    $rule = ''
                    foreach ($r in $row.rules) { if ($r) { $rule = [string]$r; break } }
                    $osName = ConvertTo-SshLanControlOs (Get-SshLanText $row 'os')
                    $result['Script'] = Get-SshLanTempCleanupScript $osName @($rule) @{ $rule = $row.before }
                    $result['Alias'] = Get-SshLanText $Device 'Alias'
                    $result['MarkUndone'] = $ChangeId
                }
                return $result
            }
            if ($Mode -eq 'undo') {
                $row = Get-SshLanChangeById $ChangeId
                if (-not $row) { return @{ Ok = $false; Message = "ไม่พบรายการ $ChangeId"; ChangeId = $ChangeId } }
                $action = Get-SshLanText $row 'action'
                if ($action -eq 'close') {
                    $rule = ''
                    foreach ($r in $row.rules) { if ($r) { $rule = [string]$r; break } }
                    $finding = [pscustomobject]@{ Port = [int](Get-SshLanText $row 'port'); Os = (Get-SshLanText $row 'os'); Ip = (Get-SshLanText $row 'ip'); Machine = (Get-SshLanText $row 'machine'); Rule = $rule }
                    $sw = @{ Action = 'reopen'; Enabled = $true; Label = 'ย้อน'; Why = ''; AlsoPorts = @() }
                    $result = Invoke-SshLanSwitch $Device $finding $sw
                    if ([string]$result.Message -eq $sudo) {
                        $pending = Get-SshLanPendingCloseRow $Device ([int]$finding.Port)
                        $result['Finding'] = $finding
                        $result['Switch'] = $sw
                        if ($pending) { $result['MarkUndone'] = [string]$pending.id }
                    }
                    return $result
                }
                if ($action -eq 'firewall-on') {
                    $osName = ConvertTo-SshLanControlOs (Get-SshLanText $row 'os')
                    $keep = New-Object System.Collections.Generic.List[int]
                    $ids = New-Object System.Collections.Generic.List[string]
                    foreach ($r in $row.rules) {
                        if (-not $r) { continue }
                        [void]$ids.Add([string]$r)
                        if ("$r" -match '^sshlan-keep-(\d+)$') { [void]$keep.Add([int]$Matches[1]) }
                    }
                    $ip = Get-SshLanText $Device 'ip'
                    if (-not $ip) { $ip = Get-SshLanText $row 'ip' }
                    $arg = @{ Before = $row.before; RuleIds = $ids.ToArray(); Keep = $keep.ToArray(); Port = 0 }
                    if ($osName -eq 'Linux') { $arg['Lan'] = Get-SshLanControlLanCidr $ip }
                    $ranScript = Get-SshLanControlScript $osName 'firewall-on-undo' $arg
                    $ran = Invoke-SshLanControl $Device $osName $ranScript
                    if ($ran.NeedSudo) { return @{ Ok = $false; Message = $sudo; ChangeId = $ChangeId; Script = $ranScript; Alias = (Get-SshLanText $Device 'Alias'); MarkUndone = $ChangeId } }
                    if (-not $ran.Ok) { return @{ Ok = $false; Message = 'ไม่แน่ใจว่าเปลี่ยนแล้วหรือยัง ให้กดตรวจใหม่'; ChangeId = $ChangeId } }
                    Set-SshLanChangeUndone $ChangeId
                    return @{ Ok = $true; Message = 'ย้อนแล้ว'; ChangeId = $ChangeId }
                }
                if ($action -eq 'upnp-delete') {
                    $loc = Find-SshLanIgd 1500
                    if (-not $loc) { return @{ Ok = $false; Message = 'เราเตอร์ไม่ตอบ UPnP'; ChangeId = $ChangeId } }
                    $desc = ConvertFrom-SshLanWebContent (Invoke-WebRequest $loc -UseBasicParsing -TimeoutSec 3)
                    $ctl = Get-SshLanIgdControl ([string]$desc) $loc
                    if (-not $ctl) { return @{ Ok = $false; Message = 'เราเตอร์ไม่ตอบ UPnP'; ChangeId = $ChangeId } }
                    return (Undo-SshLanIgdChange $ChangeId (New-SshLanIgdSoap $ctl 3))
                }
                return @{ Ok = $false; Message = 'ไม่รู้จักคำสั่งนี้'; ChangeId = $ChangeId }
            }
            return @{ Ok = $false; Message = 'ไม่รู้จักคำสั่งนี้'; ChangeId = '' }
        } catch {
            return @{ Ok = $false; Message = $_.Exception.Message; ChangeId = '' }
        }
    }).AddArgument($root).AddArgument($Mode).AddArgument($device).AddArgument($Finding).AddArgument($Switch).AddArgument($os).AddArgument($What).AddArgument($Port).AddArgument($Hours).AddArgument($ChangeId)
    $script:MapActHandle = $script:MapActPs.BeginInvoke()
    if ($script:MapActTimer) { $script:MapActTimer.Stop() }
    $gen = ++$script:MapActGen
    $script:MapActTimer = New-Object Windows.Threading.DispatcherTimer
    $script:MapActTimer.Interval = [TimeSpan]::FromMilliseconds(250)
    $script:MapActTimer.Tag = $gen
    $script:MapActTimer.Add_Tick({
        param($sender, $e)
        if ($sender -and $script:MapActGen -eq $sender.Tag) { Watch-MapControl }
    })
    $script:MapActTimer.Start()
}

function Watch-MapControl {
    if (-not $script:MapWin) {
        if ($script:MapActTimer) { $script:MapActTimer.Stop() }
        return
    }
    if ($script:MapSudoProc) {
        if (-not $script:MapSudoProc.HasExited) { return }
        $code = $script:MapSudoProc.ExitCode
        $script:MapSudoProc = $null
        if ($code -eq 0) {
            try {
                if ($script:MapSudo -and $script:MapSudo.MarkUndone) { Set-SshLanChangeUndone ([string]$script:MapSudo.MarkUndone) }
                elseif ($script:MapSudo -and $script:MapSudo.RecordTemp) { Add-MapTempChange $script:MapSudo.Device $script:MapSudo.Os $script:MapSudo.Port $script:MapSudo.Expires }
            } catch { Complete-MapControl $false $_.Exception.Message; return }
            Complete-MapControl $true 'ใส่รหัสแล้ว'
        } else { Complete-MapControl $false 'หน้าต่างรหัสปิดก่อนเสร็จ' }
        return
    }
    if (-not $script:MapActHandle -or -not $script:MapActHandle.IsCompleted) { return }
    $result = $null
    try {
        $raw = @($script:MapActPs.EndInvoke($script:MapActHandle))
        $result = @($raw | Where-Object { $_ -is [System.Collections.IDictionary] -and $_.Contains('Ok') }) | Select-Object -Last 1
    } catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        $result = @{ Ok = $false; Message = $e.Message }
    }
    try { $script:MapActPs.Dispose() } catch {}
    $script:MapActPs = $null
    $script:MapActHandle = $null
    if (-not $result) { $result = @{ Ok = $false; Message = 'ไม่แน่ใจว่าเปลี่ยนแล้วหรือยัง ให้กดตรวจใหม่' } }
    if ([string]$result.Message -eq 'ต้องใส่รหัสของเครื่องนั้น') {
        $ask = Show-AuditYesNo 'เครื่องนี้ต้องใส่รหัส sudo จะเปิดหน้าต่างให้พิมพ์รหัสไหม'
        if ($ask) {
            $proc = $null
            try {
                if ($result.Script) { $proc = Start-MapSudo ([string]$result.Alias) ([string]$result.Script) }
                elseif ($result.Finding) { $proc = Start-AuditSudoWindow $script:MapActDevice $result.Finding $result.Switch }
                elseif ($script:MapActMode -eq 'switch') { $proc = Start-AuditSudoWindow $script:MapActDevice $script:MapActFinding $script:MapActSwitch }
            } catch { $proc = $null; Add-Log ('[!] ' + $_.Exception.Message) }
            if ($proc) {
                $script:MapSudoProc = $proc
                $script:MapSudo = @{
                    MarkUndone = [string]$result.MarkUndone
                    RecordTemp = ($script:MapActMode -eq 'temp-open')
                    Expires = $result.Expires
                    Port = $(if ($result.Port) { [int]$result.Port } else { 0 })
                    Os = [string]$result.Os
                    Device = $script:MapActDevice
                }
                return
            }
        }
        Complete-MapControl $false 'ต้องใส่รหัสของเครื่องนั้น'
        return
    }
    Complete-MapControl ([bool]$result.Ok) ([string]$result.Message)
}

function Update-MapTempClocks {
    if (-not $script:MapWin) { return }
    $expired = $false
    $now = Get-Date
    foreach ($r in $script:MapTempRows) {
        if (-not $r.Block) { continue }
        $r.Block.Text = "พอร์ต $($r.Port) เหลือ $(Format-MapTempLeft $r.Expires)"
        if (([datetime]$r.Expires) -le $now) { $expired = $true }
    }
    foreach ($b in $script:MapTempBadges) {
        $n = Get-MapNode ([string]$b.NodeKey)
        if (-not $n) { continue }
        $temps = @($n.TempOpen | Where-Object { $_ -and $_.Expires })
        if (-not $temps.Count -or -not $b.Block) { continue }
        $soon = $temps[0]
        foreach ($t in $temps) { if (([datetime]$t.Expires) -lt ([datetime]$soon.Expires)) { $soon = $t } }
        $b.Block.Text = "เปิด $($soon.Port) · $(Format-MapTempLeft $soon.Expires)"
        if ($b.Badge) {
            $lines = New-Object System.Collections.Generic.List[string]
            foreach ($t in $temps) { [void]$lines.Add("พอร์ต $($t.Port) เหลือ $(Format-MapTempLeft $t.Expires)") }
            $b.Badge.ToolTip = ($lines -join "`n")
        }
        if (([datetime]$soon.Expires) -le $now) { $expired = $true }
    }
    if ($expired -and -not $script:MapBusy -and -not $script:MapPs) { Update-MapModel }
}

function Start-MapTempClock {
    if ($script:MapTempTimer) { return }
    $script:MapTempTimer = New-Object Windows.Threading.DispatcherTimer
    $script:MapTempTimer.Interval = [TimeSpan]::FromSeconds(30)
    $script:MapTempTimer.Add_Tick({ if ($script:MapWin) { Update-MapTempClocks } })
    $script:MapTempTimer.Start()
}

# --- live traffic: one sample every 2.5 s in a runspace of its own, then each line takes the state its measurement gave ---
$script:MapFlowPrev = $null; $script:MapFlowNow = $null; $script:MapFlowState = @{}
$script:MapFlowRs = $null; $script:MapFlowPs = $null; $script:MapFlowReady = $false; $script:MapFlowLast = [datetime]::MinValue; $script:MapFlowSwept = [datetime]::MinValue

function Format-MapRate($Bps) {
    if ($null -eq $Bps) { return '-' }
    $b = [double]$Bps
    if ($b -ge 1000000) { return ('{0:N1} MB/s' -f ($b / 1000000)) }
    if ($b -ge 1000) { return ('{0:N1} KB/s' -f ($b / 1000)) }
    return ('{0:N0} B/s' -f $b)
}

# rows of the Tailscale pairing picker: peers not yet paired (this PC left out); the peer that announced $NodeIp
# as its LAN address first (it is very likely the same device), then online, then by name
function Get-MapTsPickRows($Peers, [string[]]$Linked, [string]$NodeIp) {
    $glyph = @{ android = [char]0xE8EA; ios = [char]0xE8EA; windows = [char]0xE7F8; macos = [char]0xE7F8; linux = [char]0xE968 }
    @($Peers | Where-Object { $_ -and -not $_.self -and @($Linked) -notcontains [string]$_.name } | ForEach-Object {
        $match = [bool]($NodeIp -and @($_.lanIps) -contains $NodeIp)
        $parts = @([string]$_.os) + @($_.ips | Select-Object -First 1)
        if (-not $_.online -and $_.lastSeen) { $parts += 'ล่าสุด ' + ([datetime]$_.lastSeen).ToString('d MMM HH:mm') }
        [pscustomobject]@{
            Name = [string]$_.name; Match = $match; Online = [bool]$_.online
            Glyph = $(if ($glyph[[string]$_.os]) { [string]$glyph[[string]$_.os] } else { [string][char]0xE774 })
            Detail = (@($parts | Where-Object { $_ }) -join ' · ')
            Hint = $(if ($match) { 'แนะนำ: IP ใน LAN ตรงกันกับเครื่องนี้' } else { '' })
            HintShown = $(if ($match) { 'Visible' } else { 'Collapsed' })
            Status = $(if ($_.online) { 'ออนไลน์' } else { 'ออฟไลน์' })
            DotColor = $(if ($_.online) { '#4ADE80' } else { '#6B7487' })
            Fade = $(if ($_.online) { 1.0 } else { 0.6 })
        }
    } | Sort-Object @{ e = { $_.Match }; Descending = $true }, @{ e = { $_.Online }; Descending = $true }, Name)
}

# the picker window; returns the chosen peer name or $null (double-click or Enter picks, Esc cancels)
function Show-MapTsPicker([string]$Label, $Rows) {
    $w = [Windows.Markup.XamlReader]::Parse([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ssh-lan-tspick.xaml'), [Text.Encoding]::UTF8))
    if ($script:MapWin -and $script:MapWin.IsLoaded) { $w.Owner = $script:MapWin }
    $w.FindName('PickTitle').Text = "จับคู่ $Label กับ Tailscale"
    $list = $w.FindName('PickList'); $ok = $w.FindName('PickOk')
    $list.ItemsSource = @($Rows)
    if (@($Rows)[0].Match) { $list.SelectedIndex = 0 }
    $ok.IsEnabled = $null -ne $list.SelectedItem
    $list.Add_SelectionChanged({ $ok.IsEnabled = $null -ne $list.SelectedItem }.GetNewClosure())
    $ok.Add_Click({ $w.DialogResult = $true }.GetNewClosure())
    $list.Add_MouseDoubleClick({ if ($list.SelectedItem) { $w.DialogResult = $true } }.GetNewClosure())
    if ($w.ShowDialog()) { return [string]$list.SelectedItem.Name }
    return $null
}

# what a node says about its traffic: the line that reaches it (this PC = the NIC, the router = the internet line, others = their cable)
function Get-MapNodeFlowText($Node) {
    $key = if ($Node.IsSelf) { 'nic' } elseif ($Node.IsRouter) { 'internet' } else { "lan:$($Node.Key)" }
    $st = $script:MapFlowState[$key]
    # a device card needs no sample to say "cannot be measured" or "offline": the group view draws no lines, so no state is ever stored for it
    if (-not $st -and $key -like 'lan:*') {
        $st = if ($Node.InLan -eq $false) { @{ State = 'unknown'; Why = 'อยู่นอกวง LAN วัดได้เฉพาะตัวเลข Tailscale' } }
              else { Get-SshLanFlowState @{ FlowKey = $key; Online = ($Node.Online -ne $false); PeerIp = '' } $null $null }
    }
    $lines = @()
    if (-not $st) { $lines += 'ทราฟฟิก: กำลังวัด' }
    elseif ($st.State -in 'flow', 'idle') { $lines += "ทราฟฟิก ↓ $(Format-MapRate $st.RxBps) ↑ $(Format-MapRate $st.TxBps) · การ์ดเน็ตของเครื่องนี้ (ไม่ใช่ของทั้งบ้าน)" }
    else { $lines += "ทราฟฟิก: $($st.Why)" }
    $ts = @($Node.Names | Where-Object { $_.from -eq 'Tailscale' })[0]
    if ($ts) {
        $r = $null
        if ($script:MapFlowPrev -and $script:MapFlowNow) {
            $r = Get-SshLanTsRate $script:MapFlowPrev.Ts $script:MapFlowNow.Ts ([string]$ts.name) (([datetime]$script:MapFlowNow.Time - [datetime]$script:MapFlowPrev.Time).TotalSeconds)
        }
        $lines += $(if ($r) { "Tailscale ↓ $(Format-MapRate $r.Rx) ↑ $(Format-MapRate $r.Tx)" } else { 'Tailscale: กำลังวัด' })
    }
    return ($lines -join "`n")
}

# a new sample in: every line whose measurement now looks different gets its dots started, changed or stopped (no redraw)
function Add-MapFlowSample($Sample) {
    $script:MapFlowPrev = $script:MapFlowNow
    $script:MapFlowNow = $Sample
    Update-MapFlowStates
}

# every state re-read against the newest sample and the clock. Also runs when no sample arrives, so a stopped sampler stops the dots.
# This PC's card and the internet card are always kept (the group view draws no lines, the cards still read them)
function Update-MapFlowStates([datetime]$Now = (Get-Date)) {
    foreach ($c in @{ FlowKey = 'nic'; Online = $true; PeerIp = '' }, @{ FlowKey = 'internet'; Online = $true; PeerIp = '' }) {
        $script:MapFlowState[$c.FlowKey] = Get-SshLanFlowState $c $script:MapFlowPrev $script:MapFlowNow $Now
    }
    if (-not $script:MapLayout) { return }
    foreach ($e in @($script:MapLayout.Edges)) {
        if (-not $e.FlowKey) { continue }
        $st = Get-SshLanFlowState $e $script:MapFlowPrev $script:MapFlowNow $Now
        $script:MapFlowState[[string]$e.FlowKey] = $st
        $f = $script:MapFlow[[string]$e.FlowKey]
        if ($f -and $f.Sig -ne (Get-SshLanFlowSig $st)) { Set-MapEdgeFlow ([string]$e.FlowKey) $st }
    }
}

# a forever-running dot clock stays alive in WPF after its element leaves the canvas: stop them before a redraw drops the elements
function Stop-MapFlowDots {
    foreach ($f in @($script:MapFlow.Values)) {
        foreach ($d in @($f.Dots)) {
            foreach ($p in [Windows.Media.TranslateTransform]::XProperty, [Windows.Media.TranslateTransform]::YProperty) { $d.Tt.BeginAnimation($p, $null) }
        }
        $f.Dots = @()
    }
}

function Stop-MapFlowRead {
    try { if ($script:MapFlowPs) { $script:MapFlowPs.Dispose() } } catch { }
    $script:MapFlowPs = $null
    try { if ($script:MapFlowRs) { $script:MapFlowRs.CloseAsync() } } catch { }
    $script:MapFlowRs = $null
    $script:MapFlowReady = $false
}

function Update-MapFlow {
    if (-not $script:MapWin) { return }
    $now = Get-Date
    # no new sample for over 10 s (tab hidden, reads failing): re-read the states so the dots stop instead of running on the last one
    if ($script:MapFlowNow -and ($now - [datetime]$script:MapFlowNow.Time).TotalSeconds -gt 10 -and ($now - $script:MapFlowSwept).TotalSeconds -gt 2) {
        $script:MapFlowSwept = $now
        Update-MapFlowStates $now
    }
    if ($script:MapFlowPs) {
        if ($script:MapFlowHandle.IsCompleted) {
            try { $s = @($script:MapFlowPs.EndInvoke($script:MapFlowHandle))[0]; if ($s) { $script:MapFlowReady = $true; Add-MapFlowSample $s } } catch { }
            $script:MapFlowPs.Dispose(); $script:MapFlowPs = $null
        } elseif (($now - $script:MapFlowStarted).TotalSeconds -gt $(if ($script:MapFlowReady) { 2 } else { 8 })) {
            Stop-MapFlowRead   # a read that hangs costs this round only; the next one starts clean
        }
        return
    }
    if (($now - $script:MapFlowLast).TotalSeconds -lt 2.5) { return }
    if (-not (Find-Map 'MapScroll').IsVisible) { return }
    if (-not $script:MapFlowRs) {
        $script:MapFlowRs = [runspacefactory]::CreateRunspace()
        $script:MapFlowRs.Open()
    }
    $script:MapFlowPs = [powershell]::Create()
    $script:MapFlowPs.Runspace = $script:MapFlowRs
    # the first read in a runspace loads the app's functions (stay loaded after); later reads only read the counters
    [void]$script:MapFlowPs.AddScript({
        param($Root)
        if (-not (Get-Command Read-SshLanTrafficSample -ErrorAction SilentlyContinue)) {
            $env:SSH_LAN_UI = '1'
            . (Join-Path $Root 'scripts\ssh-lan-common.ps1')
            . (Join-Path $Root 'scripts\ssh-lan\ssh-lan.ps1')
        }
        Read-SshLanTrafficSample (Get-SshLanPrimaryLanIp)
    }).AddArgument($root)
    $script:MapFlowStarted = $now
    $script:MapFlowLast = $now
    $script:MapFlowHandle = $script:MapFlowPs.BeginInvoke()
}

function Start-MapFlowTimer {
    if ($script:MapFlowTimer) { return }
    $script:MapFlowTimer = New-Object Windows.Threading.DispatcherTimer
    $script:MapFlowTimer.Interval = [TimeSpan]::FromMilliseconds(500)
    $script:MapFlowTimer.Add_Tick({ try { Update-MapFlow } catch { } })
    $script:MapFlowTimer.Start()
}

function Select-MapNode([string]$Key) {
    $n = Get-MapNode $Key
    if (-not $n) { return }
    $prev = $script:MapSelected
    $script:MapSelected = $Key
    foreach ($k in @($prev, $Key) | Where-Object { $_ }) {
        $el = $script:MapEls[$k]; $nn = Get-MapNode $k
        if ($el -and $nn) { $el.BorderBrush = New-MapBrush $(if ($k -eq $Key) { '#F5C451' } elseif ($nn.Color -eq 'red') { '#7F2D33' } else { '#2A3348' }) }
    }
    (Find-Map 'MapSide').Visibility = 'Visible'
    (Find-Map 'SideGlyph').Text = [string]$script:MapGlyph[$n.Kind]
    (Find-Map 'SideTitle').Text = $n.Label
    (Find-Map 'SideChips').Children.Clear()
    Add-SideChip $script:SshLanKinds[$n.Kind]
    if ($n.Online) { Add-SideChip 'ออนไลน์' '#4ADE80' '#14301F' } else { Add-SideChip 'ออฟไลน์' '#A8B3C7' '#1C2539' }
    if ($n.IsSelf) { Add-SideChip 'เครื่องนี้' '#F5C451' '#2E2614' }
    if ($n.Paired) { Add-SideChip 'จับคู่ SSH แล้ว' '#4ADE80' '#14301F' }
    if ($n.TsPeer) { Add-SideChip 'จับคู่ Tailscale' '#A78BFA' '#2A1F3D' }
    if (@($n.TsIps).Count) { Add-SideChip 'TS' '#A78BFA' '#2A1F3D' }
    if ($n.Clash) { Add-SideChip 'IP ชน' $script:MapColor['amber'] '#33280F' }
    $tsBtn = Find-Map 'BtnSideTs'
    if ($n.InLan -and -not $n.IsSelf) {
        $tsBtn.Visibility = 'Visible'
        $tsBtn.Content = $(if ($n.TsPeer) { "เลิกจับคู่ Tailscale ($($n.TsPeer))" } else { 'จับคู่ Tailscale…' })
    } else { $tsBtn.Visibility = 'Collapsed' }
    (Find-Map 'SideUser').Text = $(if ($n.User) { $n.User } else { $env:USERNAME })
    $body = Find-Map 'SideBody'
    $body.Children.Clear()
    $script:MapTempRows = New-Object System.Collections.Generic.List[object]
    $audited = @{ red = 'แก้ด่วน'; amber = 'ควรตรวจ'; green = 'ปลอดภัย'; gray = 'ตรวจไม่ได้' }
    # rows with nothing to say are left out, except the ones that answer "is it known?"
    $names = @($n.Names | Select-Object -Skip 1 | ForEach-Object { "$($_.name) ($($_.from))" }) -join ', '
    Add-SideSection 'ตัวตน' @(
        @{ K = 'ชื่อ'; V = $(if ($n.Name) { "$($n.Name) · จาก $(@($n.Names)[0].from)" } else { '' }) }
        $(if ($names) { @{ K = 'ชื่ออื่น'; V = $names } })
        $(if ($n.TsPeer) { @{ K = 'จับคู่ TS'; V = $n.TsPeer } })
        @{ K = 'ชนิด'; V = "$($script:SshLanKinds[$n.Kind]) · $($n.KindEvidence)" }
        @{ K = 'ระบบ'; V = $(if ($n.Os) { "$($n.Os) · $($n.OsFrom)" } else { '' }) })
    $subnet = if ($n.Ip -match '^(\d+\.\d+\.\d+)\.') { "$($Matches[1]).0/24" } else { '' }
    $tsText = if (@($n.TsIps).Count) {
        (@($n.TsIps) -join ', ') + $(if ($n.TsOnline) { ' · ออนไลน์' } else { ' · ออฟไลน์' + $(if ($n.TsSeen) { ' (เห็นล่าสุด ' + (Format-MapAge $n.TsSeen) + ')' }) })
    } else { 'ไม่ได้อยู่ใน tailnet' }
    Add-SideSection 'เครือข่าย' @(
        @{ K = 'IP'; V = $n.Ip; Copy = $n.Ip; Mono = $true }
        $(if ($n.Clash) { @{ K = 'IP ชน'; V = $n.Clash; Dot = $script:MapColor['amber'] } })
        @{ K = 'วง IP'; V = $subnet; Mono = $true }
        @{ K = 'MAC'; V = $(if ($n.Mac) { $n.Mac + $(if ($n.RandomMac) { '  สุ่ม' }) } else { '' }); Copy = $n.Mac; Mono = $true }
        @{ K = 'ต่อแบบ'; V = @{ wired = 'สายแลน'; wifi = 'Wi-Fi'; tailscale = 'Tailscale เท่านั้น'; unknown = '' }[$n.Link] }
        @{ K = 'Tailscale'; V = $tsText; Dot = $(if (@($n.TsIps).Count) { if ($n.TsOnline) { '#4ADE80' } else { '#4B5568' } }) }
        @{ K = 'ทราฟฟิก'; V = (Get-MapNodeFlowText $n) }
        @{ K = 'หลักฐาน'; V = $n.Evidence })
    $mapDevice = ConvertTo-MapSwitchDevice $n
    $mapMember = Test-MapMember $n
    $mapFw = Get-MapFirewallOn $n
    $mapFwFlag = $(if ($null -eq $mapFw) { $true } else { [bool]$mapFw })
    $mapProtected = @(Get-SshLanProtected)
    $mapRules = New-Object System.Collections.Generic.List[object]
    $rawRules = Get-SshLanBag $n.Facts 'rules'
    if ($rawRules) { foreach ($rr in $rawRules) { if ($rr) { [void]$mapRules.Add($rr) } } }
    $portRows = if (@($n.Findings).Count) {
        @($n.Findings | Sort-Object { -$script:SshLanAuditRank[[string]$_.Color] }, Port | ForEach-Object {
            $sw = Get-SshLanSwitch $_ $mapDevice $mapMember $mapFwFlag $mapProtected $mapRules.ToArray()
            $label = Get-MapSwitchLabel $sw
            $row = @{ K = $(if ($_.Port) { "พอร์ต $($_.Port)" } else { 'ทั้งเครื่อง' }); Dot = $script:MapColor[[string]$_.Color]
               V = ((@("$($_.Service)".Trim(), "$($_.Process)".Trim(), "$($_.OpenTo)".Trim()) | Where-Object { $_ -and $_ -ne 'ไม่ทราบ' }) -join ' · ') + "`n" + $_.Reason }
            if ($label) {
                $tip = if ($sw.Why) { [string]$sw.Why } else { $label }
                $row.Btn = @{ Label = $label; Enabled = [bool]$sw.Enabled; Tip = $tip; Job = (New-MapJob ([string]$n.Key) 'switch' $_ $sw $label '' '' 0 0) }
            }
            $row
        })
    } elseif (@($n.Ports).Count) {
        @(@{ K = 'จากสแกน'; V = $(if ($n.Services) { $n.Services } else { @($n.Ports) -join ', ' }) }, @{ K = ''; V = 'กดตรวจความปลอดภัยเพื่อดูโปรเซสและกฎที่เปิดให้'; C = '#8F9BB3' })
    } else { @(@{ K = 'พอร์ต'; V = 'ไม่พบพอร์ตที่เปิด' }) }
    Add-SideSection 'พอร์ตที่เปิด' $portRows
    Add-SideSection 'การเชื่อมต่อ' @(
        @{ K = 'SSH'; V = $(if ($n.Paired) { 'จับคู่กุญแจแล้ว' } else { 'ยังไม่จับคู่' }); Dot = $(if ($n.Paired) { '#4ADE80' } else { '#4B5568' }) }
        $(if ($n.Alias) { @{ K = 'ชื่อใน ssh'; V = $n.Alias; Copy = $n.Alias; Mono = $true } })
        $(if ($n.User) { @{ K = 'ผู้ใช้'; V = $n.User } }))
    Add-SideSection 'ความปลอดภัย' @(
        @{ K = 'ผล audit'; V = $(if ($n.Audited) { "$($audited[[string]$n.Color]) · แดง $($n.Red) · เหลือง $($n.Amber)" } else { 'ยังไม่ได้ตรวจ' }); Dot = $script:MapColor[[string]$n.Color] }
        $(if ($n.AuditError) { @{ K = 'สาเหตุ'; V = $n.AuditError } })
        $(if ($n.FactsFrom) { @{ K = 'ข้อมูลเครื่อง'; V = "จากรอบที่เข้าถึงได้ล่าสุด $(Format-MapAge ([datetime]$n.FactsFrom))"; C = '#A8B3C7' } })
        @{ K = 'ตรวจล่าสุด'; V = $(if ($script:MapModel.AuditTime) { ($script:MapModel.AuditTime -replace 'T', ' ') -replace ':\d\d$', '' } else { '' }) })
    Show-MapControls $n
    $kb = Find-Map 'SideKind'
    $script:MapKindLoading = $true
    $kb.Items.Clear()
    $auto = New-Object Windows.Controls.ComboBoxItem; $auto.Content = 'อัตโนมัติ'; $auto.ToolTip = 'ตามหลักฐานที่ตรวจพบ'; $auto.Tag = ''; [void]$kb.Items.Add($auto)
    foreach ($k in $script:SshLanKinds.Keys) { $it = New-Object Windows.Controls.ComboBoxItem; $it.Content = $script:SshLanKinds[$k]; $it.Tag = $k; [void]$kb.Items.Add($it) }
    $userKind = (Get-SshLanDeviceKinds)[$n.Key]
    $kb.SelectedItem = @($kb.Items | Where-Object { $_.Tag -eq $(if ($userKind) { $userKind } else { '' }) })[0]
    $script:MapKindLoading = $false
    (Find-Map 'BtnSideSsh').IsEnabled = [bool]($n.Alias -or $n.InLan)
    (Find-Map 'BtnSidePair').IsEnabled = [bool]($n.InLan -and -not $n.IsSelf -and -not $n.IsRouter)
}

function Start-MapLoadMotion([string]$Label = 'กำลังสแกน...') {
    try { Start-SshLanBusyMotion } catch { }
    $emptyLoad = Find-Map 'MapEmptyLoad'
    $slide = Find-Map 'MapEmptySlide'
    if ($emptyLoad) {
        $emptyLoad.Visibility = 'Visible'
        if ($slide -and (Test-MapMotion)) {
            $a = New-Object Windows.Media.Animation.DoubleAnimation
            $a.From = -36; $a.To = 96
            $a.Duration = [TimeSpan]::FromSeconds(1.8)
            $a.RepeatBehavior = [Windows.Media.Animation.RepeatBehavior]::Forever
            $ease = New-Object Windows.Media.Animation.SineEase
            $ease.EasingMode = 'EaseInOut'
            $a.EasingFunction = $ease
            $slide.BeginAnimation([Windows.Media.TranslateTransform]::XProperty, $a)
        }
    }
    try { (Find-Map 'MapStatus').Text = $Label } catch { }
}

function Stop-MapLoadMotion {
    $slide = Find-Map 'MapEmptySlide'
    if ($slide) { $slide.BeginAnimation([Windows.Media.TranslateTransform]::XProperty, $null); $slide.X = -36 }
    $emptyLoad = Find-Map 'MapEmptyLoad'
    if ($emptyLoad) { $emptyLoad.Visibility = 'Collapsed' }
    try { if (-not $script:Busy) { Stop-SshLanBusyMotion } } catch { }
}

# --- data: scan + Tailscale + latest audit in the background, then draw ---
function Start-MapRefresh([object[]]$Devices) {
    if ($script:MapPs) { return }
    (Find-Map 'BtnMapScan').IsEnabled = $false
    # first scan: say what is happening instead of an empty map
    if (-not $script:MapModel) {
        (Find-Map 'MapEmptyText').Text = 'กำลังสแกนวง LAN ราว 10–20 วินาที...'
        (Find-Map 'MapEmpty').Visibility = 'Visible'
    }
    Start-MapLoadMotion 'กำลังสแกน...'
    $script:MapPs = [powershell]::Create()
    $null = $script:MapPs.AddScript({
        param($Root, $Devices)
        $env:SSH_LAN_UI = '1'
        . (Join-Path $Root 'scripts\ssh-lan-common.ps1')
        . (Join-Path $Root 'scripts\ssh-lan\ssh-lan.ps1')
        if (-not @($Devices).Count) { $Devices = @(Find-SshLanLanDevices '') }
        @{ Devices = $Devices; Peers = @(Get-SshLanTailscalePeers); Audit = (Get-SshLanLatestAudit); Local = (Get-SshLanLocalKindFacts); Ssh = (Get-SshLanSshTraffic) }
    }).AddArgument($root).AddArgument(@($Devices | Where-Object { $_ }))
    $script:MapHandle = $script:MapPs.BeginInvoke()
    $script:MapStarted = Get-Date
    $script:MapTimer = New-Object Windows.Threading.DispatcherTimer
    $script:MapTimer.Interval = [TimeSpan]::FromMilliseconds(250)
    $script:MapTimer.Add_Tick({
        if (-not $script:MapWin) { $script:MapTimer.Stop(); Stop-MapLoadMotion; return }
        $secs = [int]((Get-Date) - $script:MapStarted).TotalSeconds
        if (-not $script:MapHandle.IsCompleted) { (Find-Map 'MapStatus').Text = "กำลังสแกน... $secs วินาที"; return }
        $script:MapTimer.Stop()
        try {
            $out = @($script:MapPs.EndInvoke($script:MapHandle))[0]
            $script:MapDevices = @($out.Devices)
            $script:MapData = $out
            Update-MapModel
        } catch {
            $e = $_.Exception
            while ($e.InnerException) { $e = $e.InnerException }
            (Find-Map 'MapStatus').Text = '[!] ' + $e.Message
        } finally {
            Stop-MapLoadMotion
            $script:MapPs.Dispose()
            $script:MapPs = $null
            (Find-Map 'BtnMapScan').IsEnabled = $true
        }
    })
    $script:MapTimer.Start()
}

function Update-MapModel {
    $script:MapModel = Get-SshLanTopologyModel $script:MapDevices $script:MapData.Audit @($script:MapData.Peers) (Get-SshLanDeviceKinds) $script:MapData.Local $script:MapData.Ssh (Get-SshLanTsLinks)
    $nodes = @($script:MapModel.Nodes)
    $on = @($nodes | Where-Object { $_.Online }).Count
    $st = Find-Map 'MapStatus'
    $st.Inlines.Clear()
    $st.Inlines.Add((New-Object Windows.Documents.Run "$($nodes.Count) เครื่องในวง LAN · ออนไลน์ $on · Tailscale นอกวง $(@($script:MapModel.Tailscale).Count) · อัปเดต $(Get-Date -Format 'HH:mm:ss') · "))
    # the colours on the map are only as fresh as the last audit: say how old it is, and when it predates this PC's address
    $warn = ''
    if (-not $script:MapModel.AuditTime) { $msg = 'ยังไม่เคยตรวจความปลอดภัย'; $warn = 'สีบนแผนผังยังเป็นเทาทั้งหมด' }
    else {
        $at = [datetime]$script:MapModel.AuditTime
        $msg = "ตรวจความปลอดภัยล่าสุด $(Format-MapAge $at) ($($at.ToString('HH:mm')))"
        $self = @($nodes | Where-Object { $_.IsSelf })[0]
        if ($self -and -not $self.Audited) { $warn = 'ตรวจก่อนเครื่องนี้เปลี่ยน IP กดตรวจใหม่' }
        elseif (((Get-Date) - $at).TotalHours -ge 6) { $warn = 'ผลเก่าแล้ว กดตรวจใหม่' }
    }
    $st.Inlines.Add((New-Object Windows.Documents.Run $msg))
    if ($warn) { $r = New-Object Windows.Documents.Run "  ·  $warn"; $r.Foreground = New-MapBrush '#F5C451'; $st.Inlines.Add($r) }
    Show-MapLayout
    if ($script:MapSelected -and (Get-MapNode $script:MapSelected)) { Select-MapNode $script:MapSelected }
}

function Show-MapLayout {
    $canvas = Find-Map 'MapCanvas'
    Stop-MapHover
    Stop-MapFlowDots
    $canvas.Children.Clear()
    $script:MapEls = @{}
    $script:MapFlow = @{}
    $script:MapTempBadges = New-Object System.Collections.Generic.List[object]
    $nodes = @($script:MapModel.Nodes)
    (Find-Map 'MapEmptyText').Text = 'ยังไม่พบเครื่อง กดสแกนใหม่'
    (Find-Map 'MapEmpty').Visibility = $(if ($nodes.Count) { 'Collapsed' } else { 'Visible' })
    if (-not $nodes.Count -and -not @($script:MapModel.Tailscale).Count) { return }
    $avail = (Find-Map 'MapScroll').ActualWidth
    if (-not $avail) { $avail = 1000 }
    $width = [Math]::Max(500, [int]($avail / (Find-Map 'MapScale').ScaleX) - 24)
    $lay = Get-SshLanTopologyLayout $script:MapModel $script:MapView $script:MapGroupBy $width
    $script:MapLayout = $lay
    $canvas.Width = $lay.Width; $canvas.Height = [Math]::Max($lay.Height, 400)
    $link = $lay.View -eq 'link'
    # the active half of the view switch
    (Find-Map 'BtnMapLink').Tag = $(if ($link) { 'on' } else { '' })
    (Find-Map 'BtnMapGroup').Tag = $(if ($link) { '' } else { 'on' })
    (Find-Map 'MapGroupBy').IsEnabled = -not $link
    $first = $script:MapSeen.Count -eq 0
    $stagger = if ($link) { 80 } else { 12 }

    foreach ($g in @($lay.Groups)) {
        $gb = New-Object Windows.Controls.Border
        $gb.Width = $g.W; $gb.Height = $g.H; $gb.CornerRadius = 12; $gb.BorderThickness = 1
        $gb.BorderBrush = New-MapBrush $(if ($g.Label -like 'Tailscale*') { '#5B4B8A' } else { '#232C40' }); $gb.Background = New-MapBrush '#101521'
        $t = New-MapText $g.Label 12 '#8F9BB3' -Bold; $t.Margin = '14,7,0,0'; $gb.Child = $t
        Add-MapChild $gb $g.X $g.Y 0
    }
    if ($link) {
        $a = $lay.Anchors
        $inet = New-Object Windows.Controls.Border
        $inet.Width = $a.internet.W; $inet.Height = $a.internet.H; $inet.CornerRadius = 28; $inet.Background = New-MapBrush '#121826'; $inet.BorderBrush = New-MapBrush '#2A3348'; $inet.BorderThickness = 1
        $ip = New-Object Windows.Controls.StackPanel; $ip.Orientation = 'Horizontal'; $ip.HorizontalAlignment = 'Center'; $ip.VerticalAlignment = 'Center'
        $gl = New-MapText ([string][char]0xE774) 20 '#8FB8FF' -Glyph; $gl.Margin = '0,0,8,0'
        [void]$ip.Children.Add($gl); [void]$ip.Children.Add((New-MapText 'อินเทอร์เน็ต' 13 -Bold))
        $inet.Child = $ip
        $inet.ToolTip = 'จุดออกอินเทอร์เน็ตของวงนี้ (ไม่ใช่เครื่อง)'
        Add-MapChild $inet $a.internet.X $a.internet.Y 3
        if (-not $script:MapModel.Router) {
            $hub = New-Object Windows.Controls.Border
            $hub.Width = $a.router.W; $hub.Height = $a.router.H; $hub.CornerRadius = 12; $hub.BorderBrush = New-MapBrush '#3A4560'; $hub.BorderThickness = 1
            $hub.BorderBrush.Opacity = 0.6; $hub.Background = New-MapBrush '#0E121B'
            $ht = New-MapText 'วง LAN (สแกนไม่พบเราเตอร์)' 11 '#8F9BB3'; $ht.TextWrapping = 'Wrap'; $ht.TextAlignment = 'Center'; $ht.VerticalAlignment = 'Center'; $ht.Margin = '6'
            $hub.Child = $ht
            Add-MapChild $hub $a.router.X $a.router.Y 3
        }
        if ($a.tailscale) {
            $tb = New-Object Windows.Controls.Border
            $tb.Width = $a.tailscale.W; $tb.Height = $a.tailscale.H; $tb.CornerRadius = 12; $tb.BorderThickness = 1
            $tb.BorderBrush = New-MapBrush '#5B4B8A'; $tb.Background = New-MapBrush '#141026'
            $tt = New-Object Windows.Controls.StackPanel; $tt.Orientation = 'Horizontal'; $tt.Margin = '12,10,0,0'; $tt.VerticalAlignment = 'Top'
            $tg = New-MapText ([string][char]0xE7EF) 14 '#C4B5FD' -Glyph; $tg.Margin = '0,0,8,0'
            [void]$tt.Children.Add($tg)
            [void]$tt.Children.Add((New-MapText "Tailscale · เครื่องนอกวงนี้ $(@($script:MapModel.Tailscale).Count)" 12 '#C4B5FD' -Bold))
            $tb.Child = $tt
            Add-MapChild $tb $a.tailscale.X $a.tailscale.Y 3
        }
    }
    if ($link -and $lay.Anchors.trunk) { Add-MapTrunk $lay.Anchors.trunk $first }
    $i = 0
    $order = @{}
    foreach ($p in $lay.Places) { $order[$p.Key] = $i; $i++ }
    foreach ($e in @($lay.Edges)) {
        $intro = -not $script:MapSeen.ContainsKey([string]$e.To)
        Add-MapEdge $e $(if ($order.ContainsKey([string]$e.To)) { $order[[string]$e.To] * $stagger } else { 0 }) $intro
    }
    foreach ($p in $lay.Places) {
        $n = Get-MapNode $p.Key
        if (-not $n) { continue }
        $intro = -not $script:MapSeen.ContainsKey($n.Key)
        Add-MapNode $n $p ($order[$n.Key] * $stagger + $(if ($link) { 300 } else { 0 })) $intro
        $script:MapSeen[$n.Key] = $true
    }
}

# $Into = a ContentControl in the main window: the map lives there (the first thing the app shows);
# without it the map opens as a window of its own
function Show-MapWindow([object[]]$Devices, $Into) {
    if ($script:MapWin) {
        if ($script:MapEmbedded) {
            Show-MainTab 'map'
            if (@($Devices | Where-Object { $_ }).Count) { $script:MapDevices = @($Devices | Where-Object { $_ }); Start-MapRefresh $script:MapDevices }
            # scan window often sits on top of the main window: flash Topmost so แผนผัง is visible
            $window.WindowState = 'Normal'
            $window.Activate() | Out-Null
            $window.Topmost = $true; $window.Topmost = $false
        } else {
            $script:MapWin.WindowState = 'Normal'
            $script:MapWin.Activate() | Out-Null
            $script:MapWin.Topmost = $true; $script:MapWin.Topmost = $false
        }
        return
    }
    $res = [regex]::Match($markup, '(?s)<Window\.Resources>.*?</Window\.Resources>').Value
    $text = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ssh-lan-topology.xaml'), [Text.Encoding]::UTF8).Replace('<!--RESOURCES-->', $res)
    $reader = [Xml.XmlReader]::Create([IO.StringReader]::new($text))
    try { $script:MapWin = [Windows.Markup.XamlReader]::Load($reader) } finally { $reader.Dispose() }
    $script:MapEmbedded = [bool]$Into
    if ($Into) {
        # names stay registered on the loaded window, so Find-Map keeps working after the move
        $content = $script:MapWin.Content
        $script:MapWin.Content = $null
        $content.Margin = '0'
        $Into.Content = $content
        $script:MapShell = $window
    } else {
        $owner = if ($script:ScanWin) { $script:ScanWin } elseif ($window.IsLoaded) { $window } else { $null }
        if ($owner) { $script:MapWin.Owner = $owner }
        if ($window.Icon) { $script:MapWin.Icon = $window.Icon }
        $script:MapShell = $script:MapWin
    }
    $script:MapSeen = @{}; $script:MapPos = @{}; $script:MapSelected = $null; $script:MapEls = @{}
    $script:MapDevices = @($Devices | Where-Object { $_ })

    (Find-Map 'BtnMapScan').Add_Click({ Start-MapRefresh @() })
    (Find-Map 'BtnMapLink').Add_Click({ $script:MapView = 'link'; if ($script:MapModel) { Show-MapLayout } })
    (Find-Map 'BtnMapGroup').Add_Click({ $script:MapView = 'group'; if ($script:MapModel) { Show-MapLayout } })
    (Find-Map 'MapGroupBy').Add_SelectionChanged({
        $script:MapGroupBy = [string](Find-Map 'MapGroupBy').SelectedItem.Tag
        if ($script:MapModel) { Show-MapLayout }
    })
    (Find-Map 'MapZoom').Add_ValueChanged({ $s = Find-Map 'MapScale'; $s.ScaleX = $s.ScaleY = (Find-Map 'MapZoom').Value })
    (Find-Map 'MapScroll').Add_PreviewMouseWheel({
        param($s, $e)
        if ([Windows.Input.Keyboard]::Modifiers -band [Windows.Input.ModifierKeys]::Control) {
            $z = Find-Map 'MapZoom'; $z.Value = [Math]::Max($z.Minimum, [Math]::Min($z.Maximum, $z.Value + $e.Delta / 1200)); $e.Handled = $true
        }
    })
    (Find-Map 'BtnSideClose').Add_Click({
        (Find-Map 'MapSide').Visibility = 'Collapsed'
        $old = $script:MapSelected; $script:MapSelected = $null
        $el = $script:MapEls[$old]; $n = Get-MapNode $old
        if ($el -and $n) { $el.BorderBrush = New-MapBrush $(if ($n.Color -eq 'red') { '#7F2D33' } else { '#2A3348' }) }
    })
    (Find-Map 'SideKind').Add_SelectionChanged({
        if ($script:MapKindLoading -or -not $script:MapSelected) { return }
        $kind = [string](Find-Map 'SideKind').SelectedItem.Tag
        try { Set-SshLanDeviceKind $script:MapSelected $kind; Update-MapModel; Add-Log "ตั้งชนิดเครื่องแล้ว" } catch { Add-Log ('[!] ' + $_.Exception.Message) }
    })
    (Find-Map 'BtnSideTs').Add_Click({
        $n = Get-MapNode $script:MapSelected
        if (-not $n -or -not $n.InLan -or $n.IsSelf) { return }
        $key = if ($n.Mac) { [string]$n.Mac } else { [string]$n.Key }
        if ($n.TsPeer) {
            $ask = [Windows.MessageBox]::Show("เลิกจับคู่กับ Tailscale เครื่อง $($n.TsPeer)?", 'SSH LAN', 'YesNo', 'Question')
            if ($ask -ne 'Yes') { return }
            try { Set-SshLanTsPeer $key ''; Update-MapModel; Add-Log "เลิกจับคู่ Tailscale แล้ว" } catch { Add-Log ('[!] ' + $_.Exception.Message) }
            return
        }
        $avail = @(Get-MapTsPickRows $script:MapData.Peers @((Get-SshLanTsLinks).Values) ([string]$n.Ip))
        if (-not $avail.Count) { Add-Log '[!] ไม่มีเครื่อง Tailscale ที่ยังว่างให้จับคู่'; return }
        $pick = Show-MapTsPicker ([string]$n.Label) $avail
        if (-not $pick) { return }
        try {
            Set-SshLanTsPeer $key $pick
            Update-MapModel
            Add-Log "จับคู่ $($n.Label) กับ Tailscale $pick แล้ว"
        } catch { Add-Log ('[!] ' + $_.Exception.Message) }
    })
    (Find-Map 'BtnSideSsh').Add_Click({
        $n = Get-MapNode $script:MapSelected
        if (-not $n) { return }
        $target = if ($n.Alias) { $n.Alias } else { "$((Find-Map 'SideUser').Text.Trim())@$($n.Ip)" }
        if ($target -notmatch '^([A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*$') { Add-Log '[!] ชื่อผู้ใช้ไม่ถูกต้อง'; return }
        # a paired alias may use another port (ssh config knows it); a bare address must answer on 22
        if (-not $n.Alias) { $why = Get-SshLanNoSshReason $n.Ip; if ($why) { Add-Log "[!] $why"; return } }
        $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
        Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList '-NoExit', '-NoProfile', '-EncodedCommand', (ConvertTo-SshLanEncodedCommand "& '$ssh' '$target'")
        Add-Log "เปิด SSH ไปที่ $target"
    })
    (Find-Map 'BtnSidePair').Add_Click({
        $n = Get-MapNode $script:MapSelected
        $user = (Find-Map 'SideUser').Text.Trim()
        if (-not $n -or $user -notmatch '^[A-Za-z0-9._-]+$') { Add-Log '[!] ใส่ชื่อผู้ใช้ของเครื่องนั้นก่อน'; return }
        $why = Get-SshLanNoSshReason $n.Ip
        if ($why) { Add-Log "[!] $why"; return }
        Invoke-Logged { Add-Log "กำลังจับคู่กับ $user@$($n.Ip) ..."; Invoke-SshLanPair -Target "$user@$($n.Ip)" -Both }
        Start-MapRefresh @()
    })
    (Find-Map 'BtnSideDiagnose').Add_Click({
        $n = Get-MapNode $script:MapSelected
        if (-not $n) { return }
        $user = (Find-Map 'SideUser').Text.Trim()
        Invoke-Logged { Add-Log "ตรวจเส้นทางไปที่ $($n.Ip) ..."; Test-SshLanReach $n.Ip $user $n.Alias }
    })
    (Find-Map 'BtnSideAudit').Add_Click({ Show-AuditWindow $script:MapDevices })

    # every 30 s: rescan quietly; known devices stay still, new ones arrive with their entrance
    $script:MapAuto = New-Object Windows.Threading.DispatcherTimer
    $script:MapAuto.Interval = [TimeSpan]::FromSeconds(30)
    $script:MapAuto.Add_Tick({ if ($script:MapWin -and -not $script:MapPs -and $script:MapShell.IsActive -and (Find-Map 'MapScroll').IsVisible) { Start-MapRefresh @() } })
    # the map area changed size (window resized, side panel opened or closed): lay it out again for the new width
    (Find-Map 'MapScroll').Add_SizeChanged({ param($s, $e) if ($script:MapModel -and $e.WidthChanged) { Show-MapLayout } })
    $script:MapShell.Add_Closed({
        foreach ($t in $script:MapTimer, $script:MapAuto, $script:MapHoverTimer, $script:MapTempTimer, $script:MapActTimer, $script:MapFlowTimer) { try { if ($t) { $t.Stop() } } catch {} }
        Stop-MapFlowRead
        try { if ($script:MapPs) { $script:MapPs.Stop(); $script:MapPs.Dispose() } } catch {}
        try { if ($script:MapActPs) { $script:MapActPs.Stop(); $script:MapActPs.Dispose() } } catch {}
        $script:MapPs = $null
        $script:MapActPs = $null
        $script:MapWin = $null
    })
    if ($script:MapShell.IsLoaded) { Start-MapRefresh $script:MapDevices; $script:MapAuto.Start(); Start-MapTempClock; Start-MapFlowTimer }
    else { $script:MapShell.Add_Loaded({ Start-MapRefresh $script:MapDevices; $script:MapAuto.Start(); Start-MapTempClock; Start-MapFlowTimer }) }
    if (-not $script:MapEmbedded) { $script:MapWin.Show() }
}
