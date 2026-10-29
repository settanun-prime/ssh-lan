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
