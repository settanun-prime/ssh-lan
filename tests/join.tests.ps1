. "$PSScriptRoot\assert.ps1"
$env:SSH_LAN_DATA_DIR = Join-Path $env:TEMP 'sshlan-join-test'
Remove-Item $env:SSH_LAN_DATA_DIR -Recurse -Force -ErrorAction SilentlyContinue
. (Join-Path $TestRoot 'scripts\ssh-lan\join.ps1')

$h = New-SshLanHelloPayload
foreach ($k in 'hostname', 'user', 'ips', 'pubkey', 'os', 'chassis') { Assert-True $h.Contains($k) "hello.$k" }
Assert-True (Test-SshLanPublicKeyLine $h.pubkey) 'hello pubkey valid'

$tmpKey = Join-Path $env:TEMP 'sshlan-join-test-key'
Remove-Item "$tmpKey*" -Force -ErrorAction SilentlyContinue
Assert-True (New-SshLanKey $tmpKey 'inviter-test') 'temp inviter key'
$pubFile = "$tmpKey.pub"
$code = Get-SshLanConfirmCode (Get-Content $pubFile -TotalCount 1)
$url = 'http://127.0.0.1:9/t/0123456789abcdef0123456789abcdef/'
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\SSH LAN'
$installedBefore = Test-Path $installDir

Assert-Throws { Invoke-SshLanJoin -BaseUrl $url -ConfirmCode $code -InviterPubPath 'nope.pub' -DryRun -NoPrompt } 'missing inviter pub'
Assert-Throws { Invoke-SshLanJoin -BaseUrl $url -ConfirmCode 'ABCDEF' -InviterPubPath $pubFile -DryRun -NoPrompt } 'confirm code mismatch'

Invoke-SshLanJoin -BaseUrl $url -ConfirmCode $code -InviterPubPath $pubFile -DryRun -NoPrompt
$log = Get-Content (Join-Path $env:SSH_LAN_DATA_DIR 'join.log')
foreach ($s in 'confirm', 'install', 'openssh', 'firewall', 'authorize', 'ownkey', 'hello') { Assert-True ($log -match " $s ok") "dry-run step $s" }
Assert-Equal (Test-Path $installDir) $installedBefore 'dry run installed nothing'
Assert-True ($log -match ' confirm fail') 'failed step logged'
# USB join leaves its hello in the data folder for the inviter to read over SSH later
$saved = Save-SshLanHelloFile
Assert-Equal $saved (Join-Path $env:SSH_LAN_DATA_DIR 'hello.json') 'hello file path'
$back = Get-Content $saved -Raw | ConvertFrom-Json
Assert-Equal $back.hostname $env:COMPUTERNAME 'hello file content'
Assert-True (Test-SshLanPublicKeyLine $back.pubkey) 'hello file pubkey'

# a failed confirm must not have logged ok first
Remove-Item (Join-Path $env:SSH_LAN_DATA_DIR 'join.log') -Force
Assert-Throws { Invoke-SshLanJoin -BaseUrl $url -ConfirmCode 'ABCDEF' -InviterPubPath $pubFile -DryRun -NoPrompt } 'mismatch again'
Assert-True (-not ((Get-Content (Join-Path $env:SSH_LAN_DATA_DIR 'join.log')) -match ' confirm ok')) 'no confirm ok on mismatch'

# the firewall step drops the any-address rule that installing OpenSSH Server creates
$fw = [Collections.ArrayList]@()
function Get-NetFirewallRule { [CmdletBinding()] param($Name) [void]$fw.Add("get $Name"); [pscustomobject]@{ Name = $Name } }
function Remove-NetFirewallRule { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process { [void]$fw.Add("remove $($InputObject.Name)") } }
function New-NetFirewallRule { [CmdletBinding()] param($Name, $DisplayName, $Protocol, $LocalPort, $Action, $RemoteAddress, $Profile) [void]$fw.Add("new $Name $($RemoteAddress -join ',')") }
Set-SshLanJoinFirewall
Assert-True ($fw -contains 'remove *OpenSSH-Server*') "any-address OpenSSH rule removed: $fw"
Assert-True ($fw -contains 'new sshd-lan LocalSubnet,100.64.0.0/10') "sshd-lan from LAN + Tailscale: $fw"
