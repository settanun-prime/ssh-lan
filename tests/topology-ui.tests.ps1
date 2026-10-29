# --- the map draws no dot until a measurement says so (headless WPF: shapes and animations need no window) ---
. "$PSScriptRoot\assert.ps1"
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
. (Join-Path $TestRoot 'scripts\ssh-lan-common.ps1')
. (Join-Path $TestRoot 'scripts\ssh-lan\ssh-lan.ps1')
. (Join-Path $TestRoot 'scripts\topology-ui.ps1')
$script:TestCanvas = New-Object Windows.Controls.Canvas
function Find-Map([string]$Name) { $script:TestCanvas }
function Test-MapMotion { $true }
function Get-Dots { @($script:TestCanvas.Children | Where-Object { $_ -is [Windows.Shapes.Ellipse] }) }
function New-TestEdge([string]$Key, [string]$Style, [bool]$Online, [string]$Dir = 'out', [string]$PeerIp = '') {
    @{ From = 'a'; To = 'b'; Style = $Style; Ssh = $false; Live = $false; Dir = $Dir; FlowKey = $Key; Online = $Online; PeerIp = $PeerIp
       X1 = 10; Y1 = 10; X2 = 10; Y2 = 90; Points = @(@(10, 10), @(10, 50), @(60, 50), @(60, 90)) }
}
$flow = { param($rx, $tx) @{ State = 'flow'; RxBps = $rx; TxBps = $tx; Fixed = $false; Why = '' } }

$script:MapFlow = @{}
Add-MapEdge (New-TestEdge 'ssh:a>b' 'ssh' $true 'both' '192.0.2.5') 0 $false
Add-MapEdge (New-TestEdge 'nic' 'wired' $true) 0 $false
Add-MapEdge (New-TestEdge 'lan:x' 'wired' $false) 0 $false
Assert-Equal (Get-Dots).Count 0 'a freshly drawn map has no dots at all, whatever the edge claims'
$off = $script:MapFlow['lan:x'].Line
Assert-True ($off.Opacity -lt 0.5) 'an offline cable is drawn faint from the start'

Set-MapEdgeFlow 'nic' (& $flow 2000000 0)
Assert-Equal (Get-Dots).Count 3 '2 MB/s one way: three dots'
Set-MapEdgeFlow 'nic' (& $flow 2000000 2000000)
Assert-Equal (Get-Dots).Count 6 'both ways: three dots each, the old ones replaced not stacked'
Set-MapEdgeFlow 'nic' (& $flow 20000 0)
Assert-Equal (Get-Dots).Count 2 '20 KB/s: two dots'
Set-MapEdgeFlow 'nic' @{ State = 'idle'; RxBps = 0; TxBps = 0; Fixed = $false; Why = '' }
Assert-Equal (Get-Dots).Count 0 'idle: no dots'
Set-MapEdgeFlow 'nic' @{ State = 'unknown'; RxBps = $null; TxBps = $null; Fixed = $false; Why = 'x' }
Assert-Equal (Get-Dots).Count 0 'unknown: no dots'

Set-MapEdgeFlow 'ssh:a>b' @{ State = 'flow'; RxBps = $null; TxBps = $null; Fixed = $true; Why = '' }
Assert-Equal (Get-Dots).Count 2 'a live ssh line both ways: one dot each way at a fixed speed'
Set-MapEdgeFlow 'ssh:a>b' @{ State = 'idle'; RxBps = $null; TxBps = $null; Fixed = $false; Why = '' }
Assert-Equal (Get-Dots).Count 0 'ssh session closed: dots gone'

Set-MapEdgeFlow 'lan:x' (& $flow 5000000 5000000)
Assert-Equal (Get-Dots).Count 0 'a state that says flow on an offline edge still draws nothing'
Set-MapEdgeFlow 'lan:x' @{ State = 'offline'; RxBps = $null; TxBps = $null; Fixed = $false; Why = 'x' }
Assert-True ($off.Opacity -lt 0.5) 'offline stays faint'
Set-MapEdgeFlow 'nic' (& $flow 5000 0)
Assert-Equal $script:MapFlow['nic'].Line.Opacity 1 'a measured edge is drawn at full strength'
Assert-Equal (Get-Dots).Count 1 'dots only for the measured edge: 5 KB/s is one dot'
Set-MapEdgeFlow 'nope' (& $flow 1 1)
# the internet line: green when a ping got out, red dashed when not, its own grey when nothing says; never dots
Add-MapEdge (New-TestEdge 'internet' 'internet' $true) 0 $false
$il = $script:MapFlow['internet'].Line
$before = (Get-Dots).Count
Set-MapEdgeFlow 'internet' @{ State = 'unknown'; Net = 'up'; RxBps = $null; TxBps = $null; Fixed = $false; Why = 'x' }
Assert-Equal $il.Stroke.Color.ToString() '#FF4ADE80' 'internet up: green'
Assert-Equal (Get-Dots).Count $before 'internet up: still no dots (a ping is not traffic)'
Set-MapEdgeFlow 'internet' @{ State = 'unknown'; Net = 'down'; RxBps = $null; TxBps = $null; Fixed = $false; Why = 'x' }
Assert-Equal $il.Stroke.Color.ToString() '#FFF87171' 'internet down: red'
Assert-True ($il.StrokeDashArray.Count -gt 0) 'internet down: dashed'
Set-MapEdgeFlow 'internet' @{ State = 'unknown'; RxBps = $null; TxBps = $null; Fixed = $false; Why = 'x' }
Assert-Equal $il.Stroke.Color.ToString() '#FF6B7487' 'no ping result: back to its own grey'

# --- the Tailscale pairing picker: free peers only, the one whose LAN address matches first, then online ones ---
$peers = @(
    @{ name = 'zz-tab'; os = 'ios'; online = $true; ips = @('100.64.0.3'); self = $false; lanIps = @(); lastSeen = $null }
    @{ name = 'aa-old'; os = 'windows'; online = $false; ips = @('100.64.0.4'); self = $false; lanIps = @(); lastSeen = (Get-Date '2026-10-01T08:30:00') }
    @{ name = 'mm-phone'; os = 'android'; online = $true; ips = @('100.64.0.5'); self = $false; lanIps = @('192.0.2.10'); lastSeen = $null }
    @{ name = 'me'; os = 'windows'; online = $true; ips = @('100.64.0.1'); self = $true; lanIps = @(); lastSeen = $null }
    @{ name = 'taken'; os = 'linux'; online = $true; ips = @('100.64.0.6'); self = $false; lanIps = @(); lastSeen = $null })
$rows = @(Get-MapTsPickRows $peers @('taken') '192.0.2.10')
Assert-Equal (($rows | ForEach-Object { $_.Name }) -join ',') 'mm-phone,zz-tab,aa-old' 'match first, then online, then offline; this PC and paired peers left out'
Assert-True $rows[0].Match 'the peer that announced this LAN address is recommended'
Assert-True ($rows[0].Hint -match 'ตรงกัน') 'and says why'
Assert-Equal $rows[1].HintShown 'Collapsed' 'no hint without a match'
Assert-True ($rows[0].Detail -match '100\.64\.0\.5') 'shows the tailnet address'
Assert-True ($rows[2].Detail -match 'ล่าสุด') 'an offline peer says when it was last seen'
Assert-True ($rows[2].Fade -lt 1) 'an offline peer is dimmed'
Assert-Equal @(Get-MapTsPickRows $peers @() '').Where({ $_.Match }).Count 0 'no address, no recommendation'
$xaml = [IO.File]::ReadAllText((Join-Path $TestRoot 'scripts\ssh-lan-tspick.xaml'), [Text.Encoding]::UTF8)
$pw = [Windows.Markup.XamlReader]::Parse($xaml)
Assert-True ($pw.FindName('PickList') -and $pw.FindName('PickOk')) 'the picker window loads'

# --- what a node says about its traffic (card on hover and side panel) ---
$t0 = Get-Date '2026-10-29T10:00:00'
$script:MapFlowPrev = @{ Time = $t0; Ts = @{ box = @{ Rx = 0; Tx = 0; Online = $true } } }
$script:MapFlowNow = @{ Time = $t0.AddSeconds(2); Ts = @{ box = @{ Rx = 20000; Tx = 0; Online = $true } } }
$script:MapFlowState = @{
    nic = @{ State = 'flow'; RxBps = 12000; TxBps = 3000; Fixed = $false; Why = '' }
    'lan:k1' = @{ State = 'unknown'; RxBps = $null; TxBps = $null; Fixed = $false; Why = 'วัดไม่ได้: ไม่มี SNMP' }
    'lan:k2' = @{ State = 'offline'; RxBps = $null; TxBps = $null; Fixed = $false; Why = 'ออฟไลน์' }
    internet = @{ State = 'unknown'; RxBps = $null; TxBps = $null; Fixed = $false; Why = 'วัดไม่ได้: router ไม่ตอบ UPnP' } }
$self = @{ Key = 'k0'; IsSelf = $true; IsRouter = $false; Names = @() }
$txt = Get-MapNodeFlowText $self
Assert-True ($txt -match '12\.0 KB/s' -and $txt -match '3\.0 KB/s') "this PC shows both rates (got: $txt)"
Assert-True ($txt -match 'ไม่ใช่ของทั้งบ้าน') 'and says whose traffic it is'
Assert-True ((Get-MapNodeFlowText @{ Key = 'k1'; IsSelf = $false; IsRouter = $false; Names = @() }) -match 'ไม่มี SNMP') 'another device says why it cannot be measured'
Assert-True ((Get-MapNodeFlowText @{ Key = 'k2'; IsSelf = $false; IsRouter = $false; Names = @() }) -match 'ออฟไลน์') 'an offline device says so'
Assert-True ((Get-MapNodeFlowText @{ Key = 'r'; IsSelf = $false; IsRouter = $true; Names = @() }) -match 'UPnP') 'the router carries the internet line'
Assert-True ((Get-MapNodeFlowText @{ Key = 'k9'; IsSelf = $false; IsRouter = $false; Names = @() }) -match 'SNMP') 'a device with no state yet still says why it cannot be measured (group view draws no lines)'
Assert-True ((Get-MapNodeFlowText @{ Key = 'k8'; IsSelf = $false; IsRouter = $false; Online = $false; Names = @() }) -match 'ออฟไลน์') 'an offline device with no state says offline'
$script:MapFlowState = @{}
Assert-True ((Get-MapNodeFlowText $self) -match 'กำลังวัด') 'this PC with no sample yet: still measuring'
$script:MapFlowState = @{ nic = @{ State = 'flow'; RxBps = 12000; TxBps = 3000; Fixed = $false; Why = '' } }
$withTs = Get-MapNodeFlowText @{ Key = 'k1'; IsSelf = $false; IsRouter = $false; Names = @(@{ name = 'box'; from = 'Tailscale' }) }
Assert-True ($withTs -match 'Tailscale ↓ 10\.0 KB/s ↑ 0 B/s') "a Tailscale peer shows its rate (got: $withTs)"
$script:MapFlowPrev = $null
Assert-True ((Get-MapNodeFlowText @{ Key = 'k1'; IsSelf = $false; IsRouter = $false; Names = @(@{ name = 'box'; from = 'Tailscale' }) }) -match 'Tailscale.*กำลังวัด') 'Tailscale without two samples: measuring'
# Windows animation effects off: the state is still computed, but nothing moves
function Test-MapMotion { $false }
Set-MapEdgeFlow 'nic' (& $flow 5000000 5000000)
Assert-Equal (Get-Dots).Count 0 'with animations off a flowing line draws no dots'
function Test-MapMotion { $true }
# --- review fixes ---
$script:TestCanvas.Children.Clear(); $script:MapFlow = @{}
Add-MapEdge (New-TestEdge 'nic' 'wired' $true) 0 $false
Set-MapEdgeFlow 'nic' (& $flow 2000000 0)
$kept = @($script:MapFlow['nic'].Dots)
Assert-Equal $kept.Count 3 'three dots to follow'
Assert-Equal @($kept | Where-Object { $_.Begin -gt 0 }).Count 0 'dots start mid-trip: none rests at the corner waiting for its turn'
Assert-Equal @($kept | Where-Object { -not $_.Fwd }).Count 0 'download only: every dot runs router to device'
Set-MapEdgeFlow 'nic' (& $flow 0 2000000)
Assert-Equal @($script:MapFlow['nic'].Dots | Where-Object { $_.Fwd }).Count 0 'upload only: every dot runs back'
Set-MapEdgeFlow 'nic' (& $flow 2000000 0)
$kept = @($script:MapFlow['nic'].Dots)
Stop-MapFlowDots
Assert-Equal @($kept | Where-Object { $_.Tt.HasAnimatedProperties }).Count 0 'before a redraw every dot clock is stopped (a forever clock left behind keeps ticking)'

# this PC's card and the internet card have their state even when the view draws no lines (group view)
$script:MapLayout = $null; $script:MapFlowPrev = $null; $script:MapFlowNow = $null; $script:MapFlowState = @{}
$stamp = Get-Date
Add-MapFlowSample @{ Time = $stamp.AddSeconds(-2); NicId = 'e'; NicRx = 1000; NicTx = 0; SshLive = @() }
Add-MapFlowSample @{ Time = $stamp; NicId = 'e'; NicRx = 21000; NicTx = 0; SshLive = @() }
Assert-Equal $script:MapFlowState['nic'].State 'flow' 'this PC has its state with no layout'
Assert-Equal $script:MapFlowState['internet'].State 'unknown' 'the internet line likewise'

# nothing new for a minute: the dots stop, they do not keep running on the last sample
$script:TestCanvas.Children.Clear(); $script:MapFlow = @{}
$edge = New-TestEdge 'nic' 'wired' $true
$script:MapLayout = @{ Edges = @($edge) }
Add-MapEdge $edge 0 $false
Add-MapFlowSample @{ Time = (Get-Date).AddSeconds(-2); NicId = 'e'; NicRx = 21000; NicTx = 0; SshLive = @() }
Add-MapFlowSample @{ Time = (Get-Date); NicId = 'e'; NicRx = 4021000; NicTx = 0; SshLive = @() }
Assert-True ((Get-Dots).Count -ge 1) 'a fresh sample: dots run'
Update-MapFlowStates ((Get-Date).AddSeconds(60))
Assert-Equal (Get-Dots).Count 0 'a minute without a new sample: the dots stop'
Assert-Equal $script:MapFlowState['nic'].State 'unknown' 'and the card says unknown, not the old rate'