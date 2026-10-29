. "$PSScriptRoot\assert.ps1"
. (Join-Path $TestRoot 'scripts\ssh-lan-common.ps1')
. (Join-Path $TestRoot 'scripts\ssh-lan\ssh-lan.ps1')

# the folder is baked in: fleet runspaces call this too, and they have no $PSScriptRoot
$fixtureDir = "$PSScriptRoot\fixtures\audit"
New-Item function:fixture -Value ([scriptblock]::Create("param([string]`$Name) Get-Content -LiteralPath (Join-Path '$fixtureDir' `"`$Name.json`") -Raw -Encoding UTF8 | ConvertFrom-Json")) | Out-Null

# --- colour rules: one fixture per rule in the spec ---
$cases = @(
    @{ f = 'any-on-public'; port = 3389; color = 'red' },
    @{ f = 'telnet'; port = 23; color = 'red' },
    @{ f = 'ftp'; port = 21; color = 'red' },
    @{ f = 'smb1'; port = 445; color = 'red' },
    @{ f = 'sshd-password'; port = 22; color = 'red' },
    @{ f = 'rdp-no-nla'; port = 3389; color = 'red' },
    @{ f = 'firewall-off'; port = 0; color = 'red' },
    @{ f = 'internet-upnp-22'; port = 22; color = 'red' },
    @{ f = 'modbus-from-office'; port = 502; color = 'red' },
    @{ f = 'rdp-lan'; port = 3389; color = 'amber' },
    @{ f = 'device-web'; port = 80; color = 'amber' },
    @{ f = 'unknown-process-any-iface'; port = 49999; color = 'amber' },
    @{ f = 'upnp-on-no-mapping'; port = 0; color = 'amber' },
    @{ f = 'loopback-only'; port = 5432; color = 'green' },
    @{ f = 'blocked'; port = 445; color = 'green' },
    @{ f = 'ssh-key-lan'; port = 22; color = 'green' },
    @{ f = 'not-audited'; port = 0; color = 'gray' })
foreach ($c in $cases) {
    $x = fixture $c.f
    $r = @(Get-SshLanAuditFindings $x.facts (ConvertTo-Hashtable $x.context) | Where-Object { $_.Port -eq $c.port })
    Assert-True ($r.Count -ge 1) "$($c.f): a finding for port $($c.port)"
    Assert-Equal $r[0].Color $c.color $c.f
    Assert-True ($r[0].Evidence -and $r[0].Fix -and $r[0].Reason) "$($c.f) has evidence, fix, reason"
}
Assert-Equal (Get-SshLanAuditSummary @([pscustomobject]@{ Color = 'green' }, [pscustomobject]@{ Color = 'red' })).Color 'red' 'worst wins'
$sum = Get-SshLanAuditSummary @([pscustomobject]@{ Color = 'amber' }, [pscustomobject]@{ Color = 'amber' }, [pscustomobject]@{ Color = 'gray' })
Assert-Equal $sum.Amber 2 'counts amber'
Assert-Equal $sum.Color 'amber' 'amber beats gray'

# --- Windows facts: which firewall rule exposes a listening port ---
$rules = @(
    @{ name = 'r-any'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = 'Any'; localPorts = @('3389'); remote = @('Any'); program = 'Any' },
    @{ name = 'r-lan'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = 'Any'; localPorts = @('22'); remote = @('LocalSubnet', '100.64.0.0/10'); program = 'Any' },
    @{ name = 'r-off'; enabled = $false; direction = 'Inbound'; action = 'Allow'; profiles = 'Any'; localPorts = @('8080'); remote = @('Any'); program = 'Any' },
    @{ name = 'r-block'; enabled = $true; direction = 'Inbound'; action = 'Block'; profiles = 'Any'; localPorts = @('445'); remote = @('Any'); program = 'Any' },
    @{ name = 'r-allow445'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = 'Any'; localPorts = @('445'); remote = @('Any'); program = 'Any' },
    @{ name = 'r-range'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = 'Any'; localPorts = @('5000-5010'); remote = @('Any'); program = 'Any' },
    @{ name = 'r-ts'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = 'Any'; localPorts = @('5900'); remote = @('100.64.0.0/10'); program = 'Any' },
    @{ name = 'r-app'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = 'Any'; localPorts = @('Any'); remote = @('Any'); program = 'C:\Tools\weird.exe' })
Assert-Equal (Get-SshLanPortExposure 3389 'svchost' $rules '0.0.0.0').exposure 'any' 'any'
Assert-Equal (Get-SshLanPortExposure 3389 'svchost' $rules '0.0.0.0').rule 'r-any' 'names the rule'
Assert-Equal (Get-SshLanPortExposure 22 'sshd' $rules '0.0.0.0').exposure 'lan' 'lan + tailscale counts as lan'
Assert-Equal (Get-SshLanPortExposure 5900 'x' $rules '0.0.0.0').exposure 'tailscale' 'tailscale only'
Assert-Equal (Get-SshLanPortExposure 8080 'x' $rules '0.0.0.0').exposure 'blocked' 'disabled rule'
Assert-Equal (Get-SshLanPortExposure 445 'System' $rules '0.0.0.0').exposure 'blocked' 'block wins'
Assert-Equal (Get-SshLanPortExposure 5005 'x' $rules '0.0.0.0').exposure 'any' 'port range'
Assert-Equal (Get-SshLanPortExposure 3389 'svchost' $rules '127.0.0.1').exposure 'local' 'loopback'
Assert-Equal (Get-SshLanPortExposure 9 'x' $rules '0.0.0.0').exposure 'blocked' 'no rule'
Assert-Equal (Get-SshLanPortExposure 7777 'weird' $rules '0.0.0.0').exposure 'any' 'program rule, any port'
Assert-Equal (Get-SshLanPortExposure 7777 'other' $rules '0.0.0.0').exposure 'blocked' 'program rule is not for other programs'
# Tailscale's own rule allows everything, but only on the Tailscale adapter
$tsRule = @(@{ name = 'Tailscale-In'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = 'Any'; localPorts = @('Any'); remote = @('Any'); program = 'Any'; interfaces = @('Tailscale') })
Assert-Equal (Get-SshLanPortExposure 8080 'python' $tsRule '0.0.0.0').exposure 'tailscale' 'interface-bound rule is not open to everyone'
Assert-Equal (Get-SshLanPortExposure 22 'sshd' ($tsRule + $rules) '0.0.0.0').exposure 'lan' 'a LAN rule still wins over the Tailscale-only rule'
# how Tailscale really scopes it: the rule only applies to traffic sent to this PC's tailnet addresses
$tsReal = @(@{ name = 'Tailscale-In'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = '3'; localPorts = @('Any'); remote = @('Any'); program = 'Any'; interfaces = @(); localAddresses = @('100.64.0.102/255.255.255.255', 'fd7a:115c:a1e0::101/128') })
Assert-Equal (Get-SshLanPortExposure 8080 'python' $tsReal '0.0.0.0').exposure 'tailscale' 'local-address-bound to the tailnet'
Assert-Equal (Get-SshLanPortExposure 3389 'svchost' ($tsRule + $rules) '0.0.0.0').exposure 'any' 'an Any rule still wins'
# a Store-app rule (ports *, remote *, no program) must not open every port on the PC
$appx = @(@{ name = 'ZuneVideo'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = '7'; localPorts = @('Any'); remote = @('Any'); program = 'Any'; package = 'S-1-15-2-1' })
Assert-Equal (Get-SshLanPortExposure 445 'System' $appx '0.0.0.0').exposure 'blocked' 'packaged-app rule is only for that app'
$svcRule = @(@{ name = 'RemoteDesktop-UserMode-In-TCP'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = '7'; localPorts = @('3389'); remote = @('Any'); program = 'C:\Windows\system32\svchost.exe'; service = 'termservice' })
Assert-Equal (Get-SshLanPortExposure 3389 'svchost' $svcRule '0.0.0.0' @('TermService')).exposure 'any' 'service rule for the service in that process'
Assert-Equal (Get-SshLanPortExposure 3389 'svchost' $svcRule '0.0.0.0' @('Dnscache')).exposure 'blocked' 'service rule is not for other services in svchost'

# real machine, read-only: shape only
$f = Get-SshLanWindowsFacts
foreach ($k in 'machine', 'ip', 'member', 'os', 'profile', 'firewallOn', 'listeners', 'sshdPassword', 'smb1', 'rdp', 'chassis', 'media', 'tempRules') { Assert-True $f.ContainsKey($k) "facts.$k" }
Assert-True (@($f.listeners).Count -gt 0) 'this PC listens on something'
Assert-True (@($f.listeners | Where-Object { -not $_.process }).Count -eq 0) 'every listener has a process name'
Assert-True (@($f.listeners | Where-Object { $_.exposure -notin 'any', 'lan', 'tailscale', 'blocked', 'local' }).Count -eq 0) 'exposure values'
# the remote script must work without any other file
$ErrorActionPreference = 'Continue'
$json = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand (ConvertTo-SshLanEncodedCommand (Get-SshLanWindowsFactsScript)) 2>$null | Select-Object -Last 1
$ErrorActionPreference = 'Stop'
Assert-True (@((ConvertFrom-Json $json).listeners).Count -gt 0) 'remote script standalone'

# --- Linux facts: parsed from what the sh script printed on a real Ubuntu (Ubuntu) box ---
$f = ConvertFrom-SshLanLinuxFacts (Get-Content "$PSScriptRoot\fixtures\audit\linux-ubuntu.txt" -Raw) 'asus' '192.168.1.20'
Assert-Equal ($f.listeners | Where-Object { $_.port -eq 22 }).process 'sshd' 'process from ss'
Assert-Equal ($f.listeners | Where-Object { $_.port -eq 631 }).exposure 'local' '127.0.0.1:631 is local'
Assert-Equal ($f.listeners | Where-Object { $_.port -eq 41288 }).exposure 'tailscale' 'bound to tailscale0'
Assert-Equal ($f.listeners | Where-Object { $_.port -eq 8090 }).exposure 'any' 'ufw inactive: open'
Assert-Equal @($f.listeners | Where-Object { $_.port -eq 22 }).Count 1 'one row per port'
Assert-Equal $f.sshdPassword $true 'passwordauthentication yes'
Assert-Equal $f.firewallOn $false 'ufw inactive'
Assert-Equal $f.os 'Ubuntu 24.04.1 LTS' 'os name'
Assert-Equal $f.media 'wifi' 'media from the default route'
Assert-Equal $f.chassis '10' 'chassis type'
Assert-Equal (@(Get-SshLanAuditFindings $f @{ subnets = @() } | Where-Object { $_.Port -eq 22 })[0].Color) 'red' 'Linux facts feed the colour rules'
$g = ConvertFrom-SshLanLinuxFacts (Get-Content "$PSScriptRoot\fixtures\audit\linux-nosudo.txt" -Raw) 'x' '192.168.1.21'
Assert-Equal ($g.listeners | Select-Object -First 1).process 'ไม่ทราบ' 'no sudo = unknown process'
Assert-Equal $g.firewallOn $null 'no ufw = unknown'
Assert-Equal $g.sshdPassword $true 'sshd present, no line = default yes'
$u = ConvertFrom-SshLanLinuxFacts (Get-Content "$PSScriptRoot\fixtures\audit\linux-ufw-active.txt" -Raw) 'y' '192.168.1.22'
Assert-Equal $u.firewallOn $true 'ufw active'
Assert-Equal ($u.listeners | Where-Object { $_.port -eq 22 }).exposure 'lan' 'OpenSSH from a subnet'
Assert-Equal ($u.listeners | Where-Object { $_.port -eq 80 }).exposure 'any' 'ALLOW Anywhere'
Assert-Equal ($u.listeners | Where-Object { $_.port -eq 5005 }).exposure 'any' 'ufw port range'
Assert-Equal ($u.listeners | Where-Object { $_.port -eq 3306 }).exposure 'blocked' 'DENY'
Assert-Equal $u.sshdPassword $false 'passwordauthentication no'
Assert-Equal (ConvertFrom-SshLanLinuxFacts "### os`nx" 'z' '192.168.1.23').sshdPassword $null 'no sshd = unknown'
Assert-True ((Get-SshLanLinuxFactsScript) -notmatch "`r") 'script LF only'
Assert-Equal @($u.tempRules).Count 1 'linux facts read temp rules'
Assert-Equal ([string]@($u.tempRules)[0]) 'sshlan-temp-22-202610291159' 'linux facts read temp rules'
Assert-Equal @($f.tempRules).Count 0 'linux facts read temp rules'
Assert-Equal ($u.listeners | Where-Object { $_.port -eq 22 }).exposure 'lan' 'linux facts read temp rules'
$sim = @(
    @{ name = 'sshlan-temp-22-202610291200'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = 'Private'; localPorts = @('22'); remote = @('100.64.0.0/10'); program = 'Any' }
    @{ name = 'Allow Web'; enabled = $true; direction = 'Inbound'; action = 'Allow'; profiles = 'Private'; localPorts = @('80'); remote = @('Any'); program = 'Any' }
)
Assert-Equal (Get-SshLanPortExposure 22 'sshd' $sim '0.0.0.0').exposure 'tailscale' 'windows facts list temp rules'
$listed = @(Get-SshLanTempRuleNamesFromRules $sim)
Assert-Equal $listed.Count 1 'windows facts list temp rules'
Assert-Equal $listed[0] 'sshlan-temp-22-202610291200' 'windows facts list temp rules'
Assert-Equal @(Get-SshLanTempRuleNamesFromRules @($sim[1])).Count 0 'windows facts list temp rules'
Assert-True ((Get-SshLanWindowsFactsScript) -match 'tempRules') 'windows facts list temp rules'

# --- fleet: many machines at once, each with its own time limit ---
$t0 = Get-Date
$r = Invoke-SshLanFleet @(1..16) { param($n) Start-Sleep -Milliseconds 500; $n * 2 } -Throttle 8 -TimeoutSec 5
Assert-Equal $r.Count 16 'all results'
Assert-Equal $r[15].Result 32 'order kept'
# one at a time would take 8 s; the margin absorbs a busy machine
Assert-True (((Get-Date) - $t0).TotalSeconds -lt 4.5) 'ran 8 at a time'
$t0 = Get-Date
$r = Invoke-SshLanFleet @('ok', 'hang', 'boom') { param($t) if ($t -eq 'hang') { Start-Sleep 30 }; if ($t -eq 'boom') { throw 'x' }; $t } -TimeoutSec 2
Assert-Equal $r[0].Status 'ok' 'ok'
Assert-Equal $r[0].Result 'ok' 'ok result'
Assert-Equal $r[1].Status 'timeout' 'hung target times out'
Assert-Equal $r[2].Status 'error' 'thrown target is error'
Assert-Equal $r[2].Error 'x' 'error message kept'
Assert-True (((Get-Date) - $t0).TotalSeconds -lt 10) 'a hung target does not hold the round'
$r = Invoke-SshLanFleet @('a') { param($t) (fixture 'telnet').facts.machine }
Assert-Equal $r[0].Status 'ok' "the work sees the caller's functions: $($r[0].Error)"

# --- members over SSH ---
# the Windows remote call, run the way sshd runs it with cmd.exe as the shell: command line + stdin file, no other file
$call = Get-SshLanWindowsRemoteCall
Assert-True ($call.command.Length -lt 8000) "fits cmd.exe's 8191 limit ($($call.command.Length))"
$rr = Invoke-SshLanSshCapture @('/c', $call.command) $call.stdin 60 "$env:SystemRoot\System32\cmd.exe"
$wf = ConvertFrom-SshLanWindowsRemoteOutput $rr.Out
Assert-True ($wf -and @($wf.listeners).Count -gt 0) "Windows facts back through cmd + stdin: $($rr.Err)"
Assert-Equal $wf.machine $env:COMPUTERNAME 'machine name came back'
Assert-Equal (ConvertFrom-SshLanWindowsRemoteOutput "#< CLIXML`r`nnoise") $null 'no payload = null'
# a machine that cannot be reached fails fast with the reason
$t0 = Get-Date
$err = $null
try { Get-SshLanMemberFacts ([pscustomobject]@{ Alias = 'no-such-host.invalid'; Os = 'Ubuntu'; Ip = '192.0.2.1'; Name = '' }) } catch { $err = "$_" }
Assert-True ($err -match 'no-such-host') "unreachable member throws with the reason: $err"
Assert-True (((Get-Date) - $t0).TotalSeconds -lt 20) 'unreachable member is quick'
Assert-Throws { Get-SshLanMemberFacts ([pscustomobject]@{ Alias = 'x; calc'; Os = 'Windows' }) } 'alias is checked before ssh'

# --- router (UPnP IGD) and the internet ---
$desc = Get-Content "$PSScriptRoot\fixtures\router\igd-wanip2.xml" -Raw
$ctl = Get-SshLanIgdControl $desc 'http://192.168.1.1:5000/rootDesc.xml'
Assert-Equal $ctl.service 'urn:schemas-upnp-org:service:WANIPConnection:2' 'finds WANIPConnection:2'
Assert-Equal $ctl.url 'http://192.168.1.1:5000/ctl/IPConn' 'control URL resolved against the description URL'
Assert-Equal (Get-SshLanIgdControl (Get-Content "$PSScriptRoot\fixtures\router\not-igd.xml" -Raw) 'http://192.168.1.1/') $null 'no WAN service = null'
Assert-Equal (Get-SshLanIgdControl '<not xml' 'http://192.168.1.1/') $null 'broken XML = null'
Assert-Equal (Get-SshLanIgdExternalIp { param($a, $x) @{ NewExternalIPAddress = '100.64.0.103' } }) '100.64.0.103' 'WAN ip'
Assert-Equal (Get-SshLanIgdExternalIp { param($a, $x) throw 'fault' }) $null 'WAN ip fault = unknown'
Assert-Equal (Get-SshLanIgdExternalIp { param($a, $x) @{ NewExternalIPAddress = '' } }) $null 'empty WAN ip = unknown'
$maps = Get-SshLanIgdMappings { param($i) if ($i -lt 2) { @{ external = 3389 + $i; internalClient = '192.168.1.30'; internalPort = 3389; protocol = 'TCP'; description = 'x' } } else { throw 'SpecifiedArrayIndexInvalid' } }
Assert-Equal $maps.Count 2 'reads until fault'
Assert-Equal (Get-SshLanIgdMappings { param($i) @{ external = 1 } }).Count 64 'stops at 64'
Assert-True (Get-SshLanInternetExposure '100.64.0.103' '203.0.113.7' @() @()).cgnat 'CGNAT WAN'
Assert-Equal (Get-SshLanInternetExposure $null $null @() @()).cgnat $null 'unknown stays unknown'
Assert-Equal (Get-SshLanInternetExposure '203.0.113.7' '203.0.113.7' @() @()).cgnat $false 'public WAN'
Assert-True (Get-SshLanInternetExposure '203.0.113.9' '203.0.113.7' @() @()).cgnat 'WAN differs from what the world sees'
$ix = Get-SshLanInternetExposure '203.0.113.7' '203.0.113.7' $maps @()
Assert-Equal $ix.internetPorts.Count 2 'upnp mappings exposed'
Assert-Equal $ix.internetPorts[0].target '192.168.1.30' 'mapping target'
Assert-Equal (Get-SshLanInternetExposure '100.64.0.103' '203.0.113.7' $maps @()).internetPorts.Count 0 'CGNAT: mappings do not reach the internet'
$px = Get-SshLanInternetExposure $null '203.0.113.7' @() @(@{ port = 22; open = $true; target = '192.168.1.1' }, @{ port = 80; open = $false })
Assert-Equal $px.internetPorts.Count 1 'only open probe ports'
Assert-Equal $px.internetPorts[0].via 'probe' 'probe source'
# the internet ports feed the colour rules
$ctx = @{ subnets = @('192.168.1.0/24'); internetPorts = $ix.internetPorts; upnp = $true; cgnat = $false }
Assert-Equal (@(Get-SshLanAuditFindings @{ machine = 'PC'; ip = '192.168.1.30'; member = $false; scannedPorts = @() } $ctx | Where-Object { $_.Port -eq 3389 })[0].Color) 'red' 'forwarded port is red'
$calls = [Collections.ArrayList]@()
$ts = { [void]$calls.Add(($args -join ' ')) }
Assert-Throws { Invoke-SshLanExitNodeProbe 'phone' '203.0.113.7' @(22) $ts { throw 'network down' } -SettleMs 0 } 'probe error surfaces'
Assert-Equal $calls[0] 'set --exit-node=phone' 'exit node set'
Assert-Equal $calls[-1] 'set --exit-node=' 'exit node restored after a crash'
$calls.Clear()
$res = Invoke-SshLanExitNodeProbe 'phone' '203.0.113.7' @(22, 80) $ts { param($ip, $p) $p -eq 22 } -SettleMs 0
Assert-Equal (@($res | Where-Object { $_.open }).Count) 1 'knock results'
Assert-Equal $calls[-1] 'set --exit-node=' 'exit node restored after success'
Assert-Throws { Invoke-SshLanExitNodeProbe 'x; rm' '203.0.113.7' @(22) $ts { $true } } 'exit node name checked'
$t0 = Get-Date; [void](Find-SshLanIgd -TimeoutMs 300)
Assert-True (((Get-Date) - $t0).TotalSeconds -lt 2) 'discovery returns within its timeout, router or not'
$t0 = Get-Date; $rf = Get-SshLanRouterFacts
Assert-True (((Get-Date) - $t0).TotalSeconds -lt 12) 'router facts within budget'
Assert-True ($rf.upnp -in $true, $null -and $rf.evidence) "router facts say what they saw: $($rf.evidence)"
# the real SOAP caller against a local stand-in router: one answer, then a fault
$port = Get-Random -Minimum 20000 -Maximum 40000
$hl = New-Object Net.HttpListener
$hl.Prefixes.Add("http://localhost:$port/")
$hl.Start()
$srv = [powershell]::Create().AddScript({
    param($hl)
    $seen = @()
    for ($n = 0; $n -lt 2; $n++) {
        $c = $hl.GetContext()
        $seen += $c.Request.Headers['SOAPAction']
        $body = if ($n -eq 0) { '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2"><NewExternalIPAddress>203.0.113.7</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>' }
                else { $c.Response.StatusCode = 500; '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultstring>UPnPError</faultstring></s:Fault></s:Body></s:Envelope>' }
        $b = [Text.Encoding]::UTF8.GetBytes($body)
        $c.Response.OutputStream.Write($b, 0, $b.Length); $c.Response.Close()
    }
    $seen
}).AddArgument($hl)
$h = $srv.BeginInvoke()
try {
$soap = New-SshLanIgdSoap @{ url = "http://localhost:$port/ctl/IPConn"; service = 'urn:schemas-upnp-org:service:WANIPConnection:2' } 3
Assert-Equal (Get-SshLanIgdExternalIp $soap) '203.0.113.7' 'SOAP answer parsed'
Assert-Equal (Get-SshLanIgdMappings { param($i) & $soap 'GetGenericPortMappingEntry' @{ NewPortMappingIndex = $i } }).Count 0 'SOAP fault ends the mapping list'
$heard = $srv.EndInvoke($h)
} finally { $hl.Stop(); $srv.Dispose() }
Assert-Equal $heard[0] '"urn:schemas-upnp-org:service:WANIPConnection:2#GetExternalIPAddress"' 'SOAPAction header'

# --- remove one UPnP mapping and put that mapping back ---
$oldUpnpData = $env:SSH_LAN_DATA_DIR
$env:SSH_LAN_DATA_DIR = Join-Path $env:TEMP ('ssh-lan-test-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $env:SSH_LAN_DATA_DIR | Out-Null
    $calls = [Collections.ArrayList]@()
    $soap = {
        param($Action, $Arguments)
        [void]$calls.Add(@{ Action = $Action; Args = $Arguments })
        return @{}
    }
    Assert-True (Remove-SshLanIgdMapping $soap 3389 'TCP') 'delete sends DeletePortMapping with the external port'
    Assert-Equal $calls[0].Action 'DeletePortMapping' 'delete sends DeletePortMapping with the external port'
    Assert-Equal $calls[0].Args.NewExternalPort 3389 'delete sends DeletePortMapping with the external port'
    Assert-Equal $calls[0].Args.NewProtocol 'TCP' 'delete sends DeletePortMapping with the external port'
    Assert-Equal $calls[0].Args.NewRemoteHost '' 'delete sends DeletePortMapping with the external port'
    Assert-True (-not (Remove-SshLanIgdMapping { param($a, $x) throw 'fault' } 3389 'TCP')) 'delete sends DeletePortMapping with the external port'

    $calls.Clear()
    $map = @{ external = 3389; internalClient = '192.168.1.30'; internalPort = 3390; protocol = 'TCP'; description = 'rdp' }
    $device = [pscustomobject]@{ mac = '02-00-00-00-00-30'; ip = '192.168.1.30'; Name = 'pc'; Note = '' }
    $finding = New-SshLanFinding @{ machine = 'pc'; ip = '192.168.1.30'; os = 'Windows' } 3389 'red' 'เข้าจากอินเทอร์เน็ตได้' 'เราเตอร์ forward ผ่าน UPnP พอร์ต 3389' 'ลบ port forward ที่เราเตอร์' '' 'any' '' 'upnp'
    $switch = Get-SshLanSwitch $finding $device $true $true @()
    $deleted = Invoke-SshLanSwitch $device $finding $switch $null $null $soap $map
    Assert-True $deleted.Ok 'delete sends DeletePortMapping with the external port'
    $sent = @($calls | Where-Object { $_.Action -eq 'DeletePortMapping' })
    Assert-Equal $sent.Count 1 'delete sends DeletePortMapping with the external port'
    Assert-Equal $sent[0].Args.NewExternalPort 3389 'delete sends DeletePortMapping with the external port'
    Assert-Equal $sent[0].Args.NewProtocol 'TCP' 'delete sends DeletePortMapping with the external port'

    $row = @(@(Get-SshLanChanges) | Where-Object { $_.id -eq $deleted.ChangeId })[0]
    Assert-Equal $row.action 'upnp-delete' 'undo re-adds the same mapping'
    Assert-Equal ([int]$row.before.external) 3389 'undo re-adds the same mapping'
    Assert-Equal ([string]$row.before.internalClient) '192.168.1.30' 'undo re-adds the same mapping'
    Assert-Equal ([int]$row.before.internalPort) 3390 'undo re-adds the same mapping'
    Assert-Equal ([string]$row.before.protocol) 'TCP' 'undo re-adds the same mapping'
    Assert-Equal ([string]$row.before.description) 'rdp' 'undo re-adds the same mapping'

    $calls.Clear()
    $back = Undo-SshLanIgdChange $deleted.ChangeId $soap
    Assert-True $back.Ok 'undo re-adds the same mapping'
    $add = @($calls | Where-Object { $_.Action -eq 'AddPortMapping' })
    Assert-Equal $add.Count 1 'undo re-adds the same mapping'
    Assert-Equal $add[0].Args.NewRemoteHost '' 'undo re-adds the same mapping'
    Assert-Equal $add[0].Args.NewExternalPort 3389 'undo re-adds the same mapping'
    Assert-Equal $add[0].Args.NewProtocol 'TCP' 'undo re-adds the same mapping'
    Assert-Equal $add[0].Args.NewInternalPort 3390 'undo re-adds the same mapping'
    Assert-Equal $add[0].Args.NewInternalClient '192.168.1.30' 'undo re-adds the same mapping'
    Assert-Equal $add[0].Args.NewPortMappingDescription 'rdp' 'undo re-adds the same mapping'
    Assert-Equal $add[0].Args.NewEnabled 1 'undo re-adds the same mapping'
    Assert-Equal $add[0].Args.NewLeaseDuration 0 'undo re-adds the same mapping'
    $marked = @(@(Get-SshLanChanges) | Where-Object { $_.id -eq $deleted.ChangeId })[0]
    Assert-True ([string]$marked.undoneAt) 'undo re-adds the same mapping'
} finally {
    Remove-Item -LiteralPath $env:SSH_LAN_DATA_DIR -Recurse -Force -ErrorAction SilentlyContinue
    $env:SSH_LAN_DATA_DIR = $oldUpnpData
}

# --- extended scan ports and safe ranges ---
$ranges = @(@{ cidr = '10.10.0.0/24'; safe = $true; label = 'สายการผลิต' }, @{ cidr = '192.168.1.0/24'; safe = $false; label = 'สำนักงาน' })
$plan = Get-SshLanScanPlan @('10.10.0.5', '192.168.1.40') $ranges
Assert-Equal ($plan | Where-Object { $_.ip -eq '10.10.0.5' }).probePorts $false 'safe range: no port probes'
Assert-True (($plan | Where-Object { $_.ip -eq '10.10.0.5' }).pingDelayMs -ge 50) 'safe range: at most 20 pings/s'
Assert-Equal ($plan | Where-Object { $_.ip -eq '192.168.1.40' }).probePorts $true 'normal range probed'
Assert-Equal ($plan | Where-Object { $_.ip -eq '192.168.1.40' }).pingDelayMs 0 'normal range not slowed'
foreach ($p in 21, 23, 502, 102, 44818, 4840, 47808, 554, 9100, 1883, 631, 515, 8008, 5000) { Assert-True $script:SshLanScanPorts.ContainsKey($p) "scan port $p" }
Assert-True (-not (Test-SshLanPrivateIp '100.64.0.104')) 'the scanner never treats the Tailscale /10 as a LAN'
$old = $env:SSH_LAN_DATA_DIR
$env:SSH_LAN_DATA_DIR = Join-Path $env:TEMP ('ssh-lan-test-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $env:SSH_LAN_DATA_DIR | Out-Null
    $cfg = @(Get-SshLanRangesConfig)
    Assert-True ($cfg.Count -le 1 -and -not @($cfg | Where-Object { $_.safe })) 'no ranges.json: own network, not safe'
    $me = Get-SshLanPrimaryLanIp
    Assert-True (Test-SshLanPort $me 445 500) 'this PC answers on 445 (the next check needs an open port)'
    $normal = @(Find-SshLanLanDevices $me | Where-Object { $_.Ip -eq $me })[0]
    Assert-True (@($normal.Ports | Where-Object { $_ }).Count -gt 0) 'normal range: ports probed'
    ConvertTo-Json -InputObject @(@{ cidr = "$me/32"; safe = $true; label = 'test' }, @{ cidr = 'junk'; safe = $true }) | Set-Content -LiteralPath (Join-Path $env:SSH_LAN_DATA_DIR 'ranges.json') -Encoding UTF8
    Assert-Equal @(Get-SshLanRangesConfig).Count 1 'bad cidr dropped'
    $safe = @(Find-SshLanLanDevices $me | Where-Object { $_.Ip -eq $me })[0]
    Assert-True ($safe -and @($safe.Ports | Where-Object { $_ }).Count -eq 0) 'safe range: still listed, no port touched'
} finally {
    Remove-Item -LiteralPath $env:SSH_LAN_DATA_DIR -Recurse -Force -ErrorAction SilentlyContinue
    $env:SSH_LAN_DATA_DIR = $old
}

# --- the audit round: fake collectors, temp data folder ---
$old = $env:SSH_LAN_DATA_DIR
$env:SSH_LAN_DATA_DIR = Join-Path $env:TEMP ('ssh-lan-test-' + [guid]::NewGuid().ToString('N'))
try {
    $devs = @([pscustomobject]@{ Ip = '192.168.1.10'; Name = 'ME'; Note = 'เครื่องนี้'; Alias = ''; Ports = @(22) },
              [pscustomobject]@{ Ip = '192.168.1.20'; Name = 'ASUS'; Note = ''; Alias = 'asus'; Os = 'Ubuntu'; Ports = @(22, 80) },
              [pscustomobject]@{ Ip = '192.168.1.30'; Name = 'OFF'; Note = ''; Alias = 'off'; Os = 'Windows'; Ports = @() },
              [pscustomobject]@{ Ip = '192.168.1.1'; Name = ''; Note = 'เราเตอร์'; Alias = ''; Ports = @(80) },
              [pscustomobject]@{ Ip = '192.168.1.50'; Name = 'GONE'; Note = 'ออฟไลน์'; Alias = 'gone'; Online = $false; Ports = @() })
    $col = @{ Local = { (fixture 'ssh-key-lan').facts }
              Member = { param($d) if ($d.Alias -eq 'off') { throw 'ssh: connect timed out' }; (fixture 'sshd-password').facts }
              Router = { @{ upnp = $false } }; Internet = { @{ cgnat = $true; internetPorts = @() } } }
    $a = Invoke-SshLanAudit $devs $col @('192.168.1.0/24')
    Assert-Equal @($a.ByMachine.Keys).Count 5 'every device has a row'
    Assert-Equal ($a.Findings | Where-Object { $_.Ip -eq '192.168.1.30' }).Color 'gray' 'unreachable member is gray'
    Assert-True (($a.Findings | Where-Object { $_.Ip -eq '192.168.1.30' }).Reason -match 'timed out') 'gray says why'
    Assert-Equal $a.ByMachine['192.168.1.50'].Color 'gray' 'offline device is gray without contacting it'
    Assert-Equal ($a.Findings | Where-Object { $_.Ip -eq '192.168.1.20' -and $_.Port -eq 22 }).Color 'red' 'member facts coloured with its own IP'
    Assert-Equal $a.ByMachine['192.168.1.10'].Color 'green' 'this PC from the local collector'
    Assert-Equal ($a.Findings | Where-Object { $_.Ip -eq '192.168.1.1' -and $_.Port -eq 80 }).Color 'amber' 'router web page from the scan'
    Assert-Equal $a.Summary.Color 'red' 'worst colour'
    Assert-Equal $a.Internet.cgnat $true 'internet facts kept'
    Assert-True (Test-Path $a.Path) 'saved'
    Assert-True ((Split-Path $a.Path -Leaf) -match '^audit-\d{8}-\d{4}(-\d\d)?\.json$') 'file name'
    Assert-True ((Split-Path $a.Path -Leaf).StartsWith('audit-' + (Get-Date).Year)) 'Gregorian year in the file name, whatever the culture'
    Assert-True (@($a.NewSinceLast).Count -gt 0) 'first round: everything is new'
    $b = Invoke-SshLanAudit $devs $col @('192.168.1.0/24')
    Assert-Equal @($b.NewSinceLast).Count 0 'same round: nothing new'
    Assert-True ($b.Path -ne $a.Path) 'second round in the same minute keeps the first file'
    $col.Member = { param($d) if ($d.Alias -eq 'off') { throw 'ssh: connect timed out' }; (fixture 'telnet').facts }
    $c = Invoke-SshLanAudit $devs $col @('192.168.1.0/24')
    Assert-True (@($c.NewSinceLast | Where-Object { $_.Port -eq 23 }).Count -eq 1) 'a newly opened port shows as new'
    $u = Invoke-SshLanAudit @($devs[0]) @{ Local = { (fixture 'ssh-key-lan').facts }; Router = { throw 'boom' }; Internet = { throw 'bang' } } @()
    Assert-True ($u.Internet.evidence -match 'boom') 'a router error is kept as evidence, not thrown'
} finally {
    Remove-Item -LiteralPath $env:SSH_LAN_DATA_DIR -Recurse -Force -ErrorAction SilentlyContinue
    $env:SSH_LAN_DATA_DIR = $old
}

# --- Linux colour rules for part 4 switches (firewall wording, tailnet green, open-to-all amber) ---
$lx = @{ machine = 'srv'; ip = '192.0.2.20'; member = $true; os = 'Ubuntu 24.04'; profile = $null; firewallOn = $false; sshdPassword = $true
         listeners = @(@{ port = 8080; address = '::'; process = 'docker-proxy'; exposure = 'any'; rule = $null }
                       @{ port = 41288; address = '100.64.0.9'; process = 'tailscaled'; exposure = 'tailscale'; rule = $null }
                       @{ port = 22; address = '::'; process = 'sshd'; exposure = 'any'; rule = $null }) }
$fx = @(Get-SshLanAuditFindings $lx @{ subnets = @('192.0.2.0/24') })
$fw = @($fx | Where-Object { $_.Port -eq 0 })[0]
Assert-True ($fw.Evidence -match 'ufw') 'Linux firewall evidence names ufw'
Assert-True ($fw.Fix -notmatch 'Windows') 'Linux fix does not say Windows'
Assert-equal @($fx | Where-Object { $_.Port -eq 8080 })[0].Color 'amber' 'no firewall: a known web port open to everyone is amber, not "Private"'
Assert-equal @($fx | Where-Object { $_.Port -eq 41288 })[0].Color 'green' 'tailnet-only listener is green'
Assert-True (@($fx | Where-Object { $_.Port -eq 22 })[0].Evidence -match 'passwordauthentication yes') 'password finding cites sshd'
Assert-equal @($fx | Where-Object { $_.Port -eq 8080 })[0].Exposure 'any' 'raw exposure carried'
Assert-equal @($fx | Where-Object { $_.Port -eq 8080 })[0].Os 'Linux' 'os carried'

# --- CLI: -Action audit runs without admin and prints the summary and one row per finding ---
$old = $env:SSH_LAN_DATA_DIR
$env:SSH_LAN_DATA_DIR = Join-Path $env:TEMP ('ssh-lan-test-' + [guid]::NewGuid().ToString('N'))
$enc = [Console]::OutputEncoding
try {
    $ErrorActionPreference = 'Continue'
    [Console]::OutputEncoding = [Text.Encoding]::UTF8   # the child writes UTF-8
    $env:SSH_LAN_UI = ''   # inherited by the child; set, it would skip the CLI entry
    $said = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File (Join-Path $TestRoot 'scripts\ssh-lan\ssh-lan.ps1') -Action audit -Range (Get-SshLanPrimaryLanIp) 2>&1 | Out-String
    $env:SSH_LAN_UI = '1'
    $ErrorActionPreference = 'Stop'
    Assert-True ($said -match 'สรุป: แดง \d+ เหลือง \d+ เขียว \d+ เทา \d+') "cli summary line: $said"
    Assert-True ($said -match '(?m)^\[(แดง|เหลือง|เขียว|เทา)\] ') 'cli finding rows'
    Assert-True ($said -match 'อินเทอร์เน็ต: CGNAT') 'cli internet line'
    Assert-True (@(Get-ChildItem $env:SSH_LAN_DATA_DIR -Filter 'audit-*.json').Count -eq 1) 'cli saved the round'
} finally {
    [Console]::OutputEncoding = $enc
    $env:SSH_LAN_UI = '1'
    Remove-Item -LiteralPath $env:SSH_LAN_DATA_DIR -Recurse -Force -ErrorAction SilentlyContinue
    $env:SSH_LAN_DATA_DIR = $old
}
