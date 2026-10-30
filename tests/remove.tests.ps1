. "$PSScriptRoot\assert.ps1"
. (Join-Path $TestRoot 'scripts\ssh-lan-common.ps1')
. (Join-Path $TestRoot 'scripts\ssh-lan\ssh-lan.ps1')

# Remove must strip the same any-address OpenSSH rules Harden drops, plus sshd-lan and temp-22
$fw = [Collections.ArrayList]@()
$tasks = [Collections.ArrayList]@()
$svc = [pscustomobject]@{ Status = 'Running'; StartType = 'Automatic' }
$stopped = [Collections.ArrayList]@()

function Assert-SshLanAdmin { }
function Get-Service { [CmdletBinding()] param($Name) if ($Name -eq 'sshd') { return $svc } }
function Stop-Service { [CmdletBinding()] param($Name, [switch]$Force) [void]$stopped.Add("stop $Name") }
function Set-Service { [CmdletBinding()] param($Name, $StartupType) [void]$stopped.Add("startup $StartupType") }
function Get-NetTCPConnection { [CmdletBinding()] param($LocalPort, $State) @() }
function Get-SshLanLatestAudit { $null }
function Get-SshLanPrimaryLanIp { '10.9.8.20' }
function Unregister-ScheduledTask { [CmdletBinding()] param($TaskName, [switch]$Confirm) [void]$tasks.Add($TaskName) }
function Get-NetFirewallRule {
    [CmdletBinding()]
    param($Name)
    [void]$fw.Add("get $Name")
    if ($Name -eq '*OpenSSH-Server*') { return ,[pscustomobject]@{ Name = 'OpenSSH-Server-In-TCP' } }
    if ($Name -eq 'sshd-lan') { return ,[pscustomobject]@{ Name = 'sshd-lan' } }
    if ($Name -eq 'sshlan-temp-22-*') { return ,[pscustomobject]@{ Name = 'sshlan-temp-22-202001011200' } }
    return @()
}
function Remove-NetFirewallRule {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$InputObject, $Name)
    process {
        if ($Name) { [void]$fw.Add("remove-name $Name"); return }
        if ($null -ne $InputObject) { [void]$fw.Add("remove $($InputObject.Name)") }
    }
}

$env:SSH_LAN_UI = '1'
$out = Invoke-SshLanRemove *>&1 | Out-String
Assert-True ($fw -contains 'get *OpenSSH-Server*') "strips Windows OpenSSH any-address rules: $fw"
Assert-True ($fw -contains 'remove OpenSSH-Server-In-TCP') "removes OpenSSH-Server-In-TCP: $fw"
Assert-True ($fw -contains 'get sshd-lan') "looks up sshd-lan: $fw"
Assert-True (($fw -contains 'remove sshd-lan') -or ($fw -contains 'remove-name sshd-lan')) "removes sshd-lan: $fw"
Assert-True ($fw -contains 'get sshlan-temp-22-*') "looks up temp open on 22: $fw"
Assert-True ($fw -contains 'remove-name sshlan-temp-22-202001011200') "removes temp-22 rule: $fw"
Assert-True ($tasks -contains 'SSH LAN expire sshlan-temp-22-202001011200') "drops expire task: $tasks"
Assert-True ($stopped -contains 'stop sshd') "stops sshd: $stopped"
Assert-True ($stopped -contains 'startup Disabled') "disables sshd: $stopped"
Assert-True ($out -match 'พอร์ต 22 ไม่รับ') "reports port 22 closed: $out"
Assert-True ($out -match 'จุดวิ่ง') "warns map motion is not inbound SSH: $out"

'remove.tests.ps1 OK'
