$script:SshLanChangeActions = @('close', 'firewall-on', 'temp-open', 'upnp-delete')

function Get-SshLanText($Object, [string]$Name) {
    if ($null -eq $Object) { return '' }
    $v = $Object.$Name
    if ($null -eq $v) { return '' }
    return [string]$v
}

function Read-SshLanJsonArray([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    # Windows PowerShell passes a JSON array down the pipeline as one object: unroll it first
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "อ่าน $Path ไม่ได้: $($_.Exception.Message)"
    }
    if ($null -eq $raw) { return @() }
    return @($raw)
}

function Write-SshLanJsonArray([string]$Path, $Items) {
    $list = New-Object System.Collections.Generic.List[object]
    # @() on a generic List throws "Argument types do not match" in Windows PowerShell 5.1
    if ($Items -is [System.Collections.IList]) {
        foreach ($i in $Items) { if ($null -ne $i) { [void]$list.Add($i) } }
    } elseif ($null -ne $Items) {
        [void]$list.Add($Items)
    }
    $json = if ($list.Count -eq 0) { '[]' } else { ConvertTo-Json -InputObject $list.ToArray() -Depth 5 }
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
}

function ConvertTo-SshLanRuleList($Value) {
    $list = New-Object 'System.Collections.Generic.List[string]'
    if ($Value -is [string]) {
        [void]$list.Add($Value)
    } elseif ($Value -is [System.Collections.IEnumerable]) {
        foreach ($r in $Value) { if ($null -ne $r) { [void]$list.Add([string]$r) } }
    }
    # return enumerates a List, so one rule would come back as a string and [0] would be its first character
    return ,$list
}

function Get-SshLanProtected {
    @(Read-SshLanJsonArray (Join-Path (Get-SshLanDataDirectory) 'protected.json'))
}

function Set-SshLanProtected([string]$Mac, [string]$Ip, [string]$Label, [bool]$On) {
    $path = Join-Path (Initialize-SshLanDataDirectory) 'protected.json'
    $kept = New-Object System.Collections.Generic.List[object]
    foreach ($p in @(Read-SshLanJsonArray $path)) {
        if ($null -eq $p) { continue }
        $same = if ($Mac) {
            [string]::Equals((Get-SshLanText $p 'mac'), $Mac, [StringComparison]::OrdinalIgnoreCase)
        } else {
            (Get-SshLanText $p 'ip') -eq $Ip -and -not (Get-SshLanText $p 'mac')
        }
        if (-not $same) { [void]$kept.Add($p) }
    }
    if ($On) { [void]$kept.Add([pscustomobject]@{ mac = $Mac; ip = $Ip; label = $Label }) }
    Write-SshLanJsonArray $path $kept
}

function Test-SshLanProtected($Device, [object[]]$List) {
    $mac = Get-SshLanText $Device 'mac'
    $ip = Get-SshLanText $Device 'ip'
    $rows = @($List | Where-Object { $_ })
    if ($mac) {
        return @($rows | Where-Object { (Get-SshLanText $_ 'mac') -and [string]::Equals((Get-SshLanText $_ 'mac'), $mac, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
    }
    if (-not $ip) { return $false }
    return @($rows | Where-Object { (Get-SshLanText $_ 'ip') -eq $ip }).Count -gt 0
}

function ConvertTo-SshLanChangeTime([string]$Text) {
    $t = [datetime]::MinValue
    if ([datetime]::TryParse($Text, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$t)) { return $t }
    return [datetime]::MinValue
}

function ConvertTo-SshLanChangeView($Entry) {
    [pscustomobject]@{
        id = Get-SshLanText $Entry 'id'
        time = Get-SshLanText $Entry 'time'
        machine = Get-SshLanText $Entry 'machine'
        ip = Get-SshLanText $Entry 'ip'
        mac = Get-SshLanText $Entry 'mac'
        os = Get-SshLanText $Entry 'os'
        action = Get-SshLanText $Entry 'action'
        port = [int](Get-SshLanText $Entry 'port')
        rules = (ConvertTo-SshLanRuleList $Entry.rules)
        before = $Entry.before
        expires = Get-SshLanText $Entry 'expires'
        undoneAt = Get-SshLanText $Entry 'undoneAt'
    }
}

function Add-SshLanChange([hashtable]$Entry) {
    $action = [string]$Entry['action']
    if ($script:SshLanChangeActions -notcontains $action) { throw "การกระทำไม่ถูกต้อง: $action" }
    $time = if ($Entry.ContainsKey('time') -and [string]$Entry['time']) { [string]$Entry['time'] } else { (Get-Date).ToString('o') }
    $expires = if ($Entry.ContainsKey('expires') -and $null -ne $Entry['expires']) { [string]$Entry['expires'] } else { '' }
    $before = if ($Entry.ContainsKey('before') -and $null -ne $Entry['before']) { $Entry['before'] } else { @{} }
    $port = if ($Entry.ContainsKey('port') -and $null -ne $Entry['port'] -and "$($Entry['port'])" -ne '') { [int]$Entry['port'] } else { 0 }
    $id = [guid]::NewGuid().ToString('N')
    $row = [pscustomobject]@{
        id = $id
        time = $time
        machine = [string]$Entry['machine']
        ip = [string]$Entry['ip']
        mac = [string]$Entry['mac']
        os = [string]$Entry['os']
        action = $action
        port = $port
        rules = (ConvertTo-SshLanRuleList $Entry['rules'])
        before = $before
        expires = $expires
        undoneAt = ''
    }
    $path = Join-Path (Initialize-SshLanDataDirectory) 'changes.json'
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($i in @(Read-SshLanJsonArray $path)) { if ($null -ne $i) { [void]$all.Add($i) } }
    [void]$all.Add($row)
    Write-SshLanJsonArray $path $all
    return $id
}

function Get-SshLanChanges([string]$Mac = '', [int]$Last = 0) {
    $path = Join-Path (Get-SshLanDataDirectory) 'changes.json'
    $rows = @(foreach ($e in @(Read-SshLanJsonArray $path)) { if ($e) { ConvertTo-SshLanChangeView $e } })
    if ($Mac) {
        $rows = @($rows | Where-Object { [string]::Equals([string]$_.mac, $Mac, [StringComparison]::OrdinalIgnoreCase) })
    }
    $rows = @($rows | Sort-Object { ConvertTo-SshLanChangeTime ([string]$_.time) } -Descending)
    if ($Last -gt 0) { $rows = @($rows | Select-Object -First $Last) }
    return @($rows)
}

function Set-SshLanChangeUndone([string]$Id) {
    $path = Join-Path (Initialize-SshLanDataDirectory) 'changes.json'
    $items = @(Read-SshLanJsonArray $path)
    $hit = $null
    foreach ($e in $items) {
        if ($e -and [string]$e.id -eq $Id) { $hit = $e; break }
    }
    if (-not $hit) { throw "ไม่พบรายการ $Id" }
    if (Get-SshLanText $hit 'undoneAt') { throw 'ย้อนรายการนี้ไปแล้ว' }
    $hit | Add-Member -NotePropertyName undoneAt -NotePropertyValue (Get-Date).ToString('o') -Force
    Write-SshLanJsonArray $path $items
}

function Test-SshLanPendingClose($Device, [int]$Port) {
    if ($Port -le 0) { return $false }
    foreach ($c in @(Get-SshLanChanges)) {
        if ((Get-SshLanText $c 'action') -ne 'close') { continue }
        if ([int](Get-SshLanText $c 'port') -ne $Port) { continue }
        if (Get-SshLanText $c 'undoneAt') { continue }
        $dmac = Get-SshLanText $Device 'mac'
        $cmac = Get-SshLanText $c 'mac'
        $same = if ($dmac -and $cmac) {
            [string]::Equals($dmac, $cmac, [StringComparison]::OrdinalIgnoreCase)
        } else {
            (Get-SshLanText $Device 'ip') -eq (Get-SshLanText $c 'ip')
        }
        if ($same) { return $true }
    }
    return $false
}

function Test-SshLanRuleCoversPort($Rule, [int]$Port) {
    foreach ($lp in @($Rule.localPorts)) {
        $text = "$lp"
        if ($text -eq 'Any' -or $text -eq '*') { return $true }
        if ($text -match '^\d+$' -and [int]$text -eq $Port) { return $true }
        if ($text -match '^(\d+)-(\d+)$' -and $Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
    }
    return $false
}

function Get-SshLanAlsoPorts([int]$Port, [string]$RuleName, [object[]]$Rules) {
    $mine = @($Rules | Where-Object { $_ -and [string]::Equals((Get-SshLanText $_ 'name'), $RuleName, [StringComparison]::OrdinalIgnoreCase) })
    if (-not $mine) { return ,[int[]]@() }
    # the rule list has no listener table, so a concrete allow port stands in for one
    $used = New-Object System.Collections.Generic.List[int]
    foreach ($r in @($Rules)) {
        if (-not $r) { continue }
        if ("$($r.direction)" -ne 'Inbound') { continue }
        if ("$($r.action)" -ne 'Allow') { continue }
        if ("$($r.enabled)" -eq 'False') { continue }
        foreach ($lp in @($r.localPorts)) {
            if ("$lp" -match '^\d+$') {
                $n = [int]$lp
                if ($n -gt 0 -and $n -ne $Port) { [void]$used.Add($n) }
            }
        }
    }
    $hit = New-Object System.Collections.Generic.List[int]
    foreach ($n in $used) {
        foreach ($r in $mine) {
            if (Test-SshLanRuleCoversPort $r $n) { [void]$hit.Add($n); break }
        }
    }
    $ports = [int[]]@($hit | Sort-Object -Unique)
    return ,$ports
}

function Get-SshLanSwitch($Finding, $Device, [bool]$Member, [bool]$FirewallOn, [object[]]$Protected, [object[]]$Rules = @()) {
    $port = 0
    $portText = Get-SshLanText $Finding 'Port'
    if ($portText -match '^\d+$') { $port = [int]$portText }
    $via = Get-SshLanText $Finding 'Via'
    $exposure = Get-SshLanText $Finding 'Exposure'
    $os = Get-SshLanText $Finding 'Os'
    $process = Get-SshLanText $Finding 'Process'
    $ruleName = Get-SshLanText $Finding 'Rule'
    $action = 'none'
    $enabled = $false
    $label = ''
    $why = ''

    if ($port -eq 0 -and -not $FirewallOn) {
        $action = 'firewall-on'; $enabled = $true; $label = 'เปิดไฟร์วอลล์'
    } elseif ($via -eq 'upnp') {
        $action = 'upnp-delete'; $enabled = $true; $label = 'ลบการเปิดพอร์ตที่เราเตอร์'
    } elseif ($via -eq 'probe') {
        $action = 'none'; $why = "ปิดที่หน้าตั้งค่าเราเตอร์: ลบ port forward พอร์ต $port"
    } elseif ($exposure -in @('local', 'blocked', 'tailscale')) {
        $action = 'none'
    } elseif ($port -eq 22) {
        $action = 'close'; $why = 'ไม่ปิด SSH: ปิดแล้วแอปจะสั่งเครื่องนี้ไม่ได้อีก'
    } elseif (-not $Member -and (Get-SshLanText $Device 'Note') -ne 'เครื่องนี้') {
        $action = 'close'; $why = 'ยังไม่ได้เข้าวง: ตั้งค่าได้ที่หน้าเว็บของอุปกรณ์'
    } elseif ($os -eq 'Linux' -and $process -eq 'docker-proxy') {
        $action = 'close'; $why = "Docker ข้ามไฟร์วอลล์: แก้ใน compose ให้ผูก 127.0.0.1:${port}"
    } elseif ($port -gt 0 -and -not $FirewallOn) {
        $action = 'close'; $why = 'เปิดไฟร์วอลล์ก่อน แล้วค่อยปิดพอร์ตนี้'
    } elseif ($port -gt 0 -and $os -eq 'Windows' -and -not $ruleName) {
        $action = 'close'; $why = 'หากฎที่เปิดพอร์ตนี้ไม่เจอ'
    } elseif ($port -gt 0 -and (Test-SshLanPendingClose $Device $port)) {
        $action = 'reopen'; $enabled = $true; $label = 'เปิดคืน'
    } elseif ($port -gt 0) {
        $action = 'close'; $enabled = $true; $label = 'ปิดพอร์ตนี้'
    }

    # protected wins over every switch that would change something, including rows above it
    if ($action -ne 'none' -and (Test-SshLanProtected $Device @($Protected))) {
        $action = 'close'; $enabled = $false; $label = ''; $why = 'ตั้งเป็น "ห้ามแอปแก้" ไว้'
    }

    $also = [int[]]@()
    if ($action -in @('close', 'reopen') -and $ruleName) {
        $also = Get-SshLanAlsoPorts $port $ruleName @($Rules)
    }
    return @{
        Action = $action
        Enabled = [bool]$enabled
        Label = [string]$label
        Why = [string]$why
        AlsoPorts = $also
    }
}

function ConvertTo-SshLanControlPort($Value) {
    $text = "$Value"
    if ($text -notmatch '^\d{1,5}$') { throw "พอร์ตไม่ถูกต้อง: $text" }
    $n = [int]$text
    if ($n -lt 1 -or $n -gt 65535) { throw "พอร์ตไม่ถูกต้อง: $text" }
    return $n
}

function ConvertTo-SshLanControlRule([string]$Value) {
    if ($Value -notmatch '^[\w .()-]+$') { throw "ชื่อกฎไม่ถูกต้อง: $Value" }
    return $Value
}

function ConvertTo-SshLanControlLan([string]$Value) {
    if ($Value -notmatch '^\d{1,3}(\.\d{1,3}){3}/([0-9]|[12][0-9]|3[0-2])$') { throw "วงแลนไม่ถูกต้อง: $Value" }
    return $Value
}

function Get-SshLanBag($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [hashtable]) {
        if ($Object.ContainsKey($Name)) { return $Object[$Name] }
        return $null
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function Get-SshLanFactRows($Facts, [string]$Name) {
    $raw = Get-SshLanBag $Facts $Name
    if ($null -eq $raw) { return @() }
    return @($raw)
}

function Get-SshLanLinuxControlText([string]$Body) {
    $head = @((Get-SshLanLinuxFactsScript) -split "`n")[0].TrimEnd("`r")
    $gate = 'if [ -z "$S" ]; then exit 77; fi'
    return (($head, $gate, $Body.Trim()) -join "`n") + "`n"
}

function Get-SshLanWindowsCloseScript([string]$Rule) {
    $q = "'" + $Rule + "'"
    $filter = '$_.Enabled -eq ''True'' -and $_.Direction -eq ''Inbound'' -and $_.Action -eq ''Allow'''
    return @(
        '$ErrorActionPreference = ''Stop'''
        ('$rules = @(Get-NetFirewallRule -DisplayName {0} | Where-Object {{ {1} }})' -f $q, $filter)
        '$rules | ForEach-Object { Disable-NetFirewallRule -Name $_.Name; $_.Name }'
    ) -join "`n"
}

function Get-SshLanWindowsReopenScript([string[]]$RuleIds) {
    $quoted = ($RuleIds | ForEach-Object { "'" + $_ + "'" }) -join ','
    return @(
        '$ErrorActionPreference = ''Stop'''
        "Enable-NetFirewallRule -Name $quoted | Out-Null"
    ) -join "`n"
}

function Get-SshLanWindowsKeepLines([int]$Port) {
    $name = "sshlan-keep-$Port"
    return @(
        ('$named = @(Get-NetFirewallRule -Name ''{0}'' -ErrorAction SilentlyContinue)' -f $name)
        ('if ($named) {{ ''{0}'' }} else {{' -f $name)
        '  $covered = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Where-Object {'
        '    $f = $_ | Get-NetFirewallPortFilter'
        ('    "$($f.Protocol)" -in @(''TCP'',''Any'') -and (@($f.LocalPort) -contains ''{0}'' -or @($f.LocalPort) -contains ''Any'')' -f $Port)
        '  })'
        '  if (-not $covered) {'
        ('    New-NetFirewallRule -Name ''{0}'' -DisplayName ''{0}'' -Direction Inbound -Protocol TCP -LocalPort {1} -RemoteAddress @(''LocalSubnet'',''100.64.0.0/10'') -Action Allow | Out-Null' -f $name, $Port)
        ('    ''{0}''' -f $name)
        '  }'
        '}'
    )
}

function Get-SshLanWindowsFirewallOnScript([int[]]$Keep) {
    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add('$ErrorActionPreference = ''Stop''')
    [void]$lines.Add('$before = @{}')
    [void]$lines.Add('foreach ($name in ''Domain'',''Private'',''Public'') { $before[$name] = [bool](Get-NetFirewallProfile -Name $name).Enabled }')
    [void]$lines.Add('$pairs = foreach ($name in ''Domain'',''Private'',''Public'') { "$name=$($before[$name])" }')
    [void]$lines.Add("'SSHLAN-BEFORE ' + (`$pairs -join ';')")
    foreach ($p in @($Keep)) { foreach ($line in (Get-SshLanWindowsKeepLines $p)) { [void]$lines.Add($line) } }
    [void]$lines.Add('Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True | Out-Null')
    return ($lines.ToArray() -join "`n")
}

function Get-SshLanBeforeBool($Before, [string]$Name) {
    if ($null -eq $Before) { return $null }
    $val = $null
    $seen = $false
    if ($Before -is [hashtable]) {
        if (-not $Before.ContainsKey($Name)) { return $null }
        $val = $Before[$Name]
        $seen = $true
    } else {
        $prop = $Before.PSObject.Properties[$Name]
        if (-not $prop) { return $null }
        $val = $prop.Value
        $seen = $true
    }
    if (-not $seen) { return $null }
    if ($val -is [bool]) { return $val }
    if ("$val" -eq 'True') { return $true }
    if ("$val" -eq 'False') { return $false }
    return $null
}

function Get-SshLanWindowsFirewallUndoScript($Before, [string[]]$Names) {
    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add('$ErrorActionPreference = ''Stop''')
    foreach ($name in @('Domain', 'Private', 'Public')) {
        $flag = Get-SshLanBeforeBool $Before $name
        if ($null -eq $flag) { continue }
        $text = if ($flag) { 'True' } else { 'False' }
        [void]$lines.Add("Set-NetFirewallProfile -Name $name -Enabled $text | Out-Null")
    }
    $safe = @(foreach ($n in @($Names)) { if ($n -and $n -match '^sshlan-keep-') { ConvertTo-SshLanControlRule $n } })
    if (@($safe).Count -gt 0) {
        $quoted = ($safe | ForEach-Object { "'" + $_ + "'" }) -join ','
        [void]$lines.Add("Remove-NetFirewallRule -Name $quoted")
    }
    return ($lines.ToArray() -join "`n")
}

function Get-SshLanLinuxCloseBody([int]$Port) {
    return ('$S ufw insert 1 deny {0}/tcp comment ''sshlan-close-{0}''' -f $Port)
}

function Get-SshLanLinuxReopenBody([int]$Port) {
    return ('$S ufw delete deny {0}/tcp' -f $Port)
}

function Get-SshLanLinuxFirewallOnBody([string]$Lan, [int[]]$Keep) {
    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add(('$S ufw allow from {0} to any port 22 proto tcp comment sshlan-keep-ssh' -f $Lan))
    [void]$lines.Add('$S ufw allow in on tailscale0 comment sshlan-keep-tailscale')
    foreach ($p in @($Keep)) {
        [void]$lines.Add(('$S ufw allow from {0} to any port {1} proto tcp comment sshlan-keep-{1}' -f $Lan, $p))
    }
    [void]$lines.Add('$S ufw --force enable')
    return ($lines.ToArray() -join "`n")
}

function Get-SshLanLinuxFirewallUndoBody([string]$Lan, [int[]]$Keep) {
    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add('$S ufw --force disable')
    [void]$lines.Add(('$S ufw delete allow from {0} to any port 22 proto tcp' -f $Lan))
    [void]$lines.Add('$S ufw delete allow in on tailscale0')
    foreach ($p in @($Keep)) {
        [void]$lines.Add(('$S ufw delete allow from {0} to any port {1} proto tcp' -f $Lan, $p))
    }
    return ($lines.ToArray() -join "`n")
}

function Get-SshLanControlPorts($Value) {
    $list = New-Object System.Collections.Generic.List[int]
    foreach ($p in @($Value)) {
        if ($null -eq $p -or "$p" -eq '') { continue }
        [void]$list.Add((ConvertTo-SshLanControlPort $p))
    }
    return [int[]]@($list | Sort-Object -Unique)
}

function Get-SshLanControlRuleIds($Value) {
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Value)) {
        if ($null -eq $r -or "$r" -eq '') { continue }
        [void]$list.Add((ConvertTo-SshLanControlRule ([string]$r)))
    }
    return [string[]]$list.ToArray()
}

function Get-SshLanControlScript([string]$Os, [string]$Action, [hashtable]$Arg) {
    if ($null -eq $Arg) { $Arg = @{} }
    if ($Os -ne 'Windows' -and $Os -ne 'Linux') { throw "ระบบปฏิบัติการไม่ถูกต้อง: $Os" }
    $needsPort = $Action -in @('close', 'reopen') -and $Os -eq 'Linux'
    $port = 0
    $portText = if ($Arg.ContainsKey('Port')) { "$($Arg['Port'])" } else { '' }
    if ($portText -and $portText -ne '0') { $port = ConvertTo-SshLanControlPort $portText }
    elseif ($needsPort) { throw 'พอร์ตไม่ถูกต้อง: ' }
    $rule = ''
    if ($Arg.ContainsKey('Rule') -and "$($Arg['Rule'])") { $rule = ConvertTo-SshLanControlRule ([string]$Arg['Rule']) }
    $lan = ''
    if ($Arg.ContainsKey('Lan') -and "$($Arg['Lan'])") { $lan = ConvertTo-SshLanControlLan ([string]$Arg['Lan']) }
    $keep = [int[]]@()
    if ($Arg.ContainsKey('Keep') -and $null -ne $Arg['Keep']) { $keep = Get-SshLanControlPorts $Arg['Keep'] }
    $ids = [string[]]@()
    if ($Arg.ContainsKey('RuleIds') -and $null -ne $Arg['RuleIds']) { $ids = Get-SshLanControlRuleIds $Arg['RuleIds'] }

    if ($Os -eq 'Windows' -and $Action -eq 'close') {
        if (-not $rule) { throw 'ชื่อกฎไม่ถูกต้อง: ' }
        return Get-SshLanWindowsCloseScript $rule
    }
    if ($Os -eq 'Windows' -and $Action -eq 'reopen') {
        if (-not $ids) { throw 'ไม่มีกฎที่จะเปิดคืน' }
        return Get-SshLanWindowsReopenScript $ids
    }
    if ($Os -eq 'Windows' -and $Action -eq 'firewall-on') {
        return Get-SshLanWindowsFirewallOnScript $keep
    }
    if ($Os -eq 'Windows' -and $Action -eq 'firewall-on-undo') {
        return Get-SshLanWindowsFirewallUndoScript $Arg['Before'] $ids
    }
    if ($Os -eq 'Linux' -and $Action -eq 'close') {
        return (Get-SshLanLinuxControlText (Get-SshLanLinuxCloseBody $port))
    }
    if ($Os -eq 'Linux' -and $Action -eq 'reopen') {
        return (Get-SshLanLinuxControlText (Get-SshLanLinuxReopenBody $port))
    }
    if ($Os -eq 'Linux' -and $Action -eq 'firewall-on') {
        if (-not $lan) { throw 'วงแลนไม่ถูกต้อง: ' }
        return (Get-SshLanLinuxControlText (Get-SshLanLinuxFirewallOnBody $lan $keep))
    }
    if ($Os -eq 'Linux' -and $Action -eq 'firewall-on-undo') {
        if (-not $lan) { throw 'วงแลนไม่ถูกต้อง: ' }
        return (Get-SshLanLinuxControlText (Get-SshLanLinuxFirewallUndoBody $lan $keep))
    }
    throw "ไม่รู้จักคำสั่ง: $Os $Action"
}

function Get-SshLanFirewallOnPlan($Facts, [string]$LanCidr) {
    if ($LanCidr) { ConvertTo-SshLanControlLan $LanCidr | Out-Null }
    $keep = New-Object System.Collections.Generic.List[int]
    foreach ($row in @(Get-SshLanFactRows $Facts 'listeners')) {
        $portText = Get-SshLanText $row 'port'
        if ($portText -notmatch '^\d+$') { continue }
        $port = [int]$portText
        if ($port -le 0 -or $port -eq 22) { continue }
        if ((Get-SshLanText $row 'process') -eq 'docker-proxy') { continue }
        $exposure = Get-SshLanText $row 'exposure'
        if ($exposure -eq 'local' -or $exposure -eq 'tailscale') { continue }
        [void]$keep.Add($port)
    }
    $ports = [int[]]@($keep | Sort-Object -Unique)
    $text = if (@($ports).Count) {
        "คงพอร์ต $($ports -join ', ') ให้เข้าได้จากวงแลนและ Tailscale และคง SSH ไว้"
    } else {
        'คง SSH ให้เข้าได้จากวงแลนและ Tailscale'
    }
    return @{ Keep = $ports; Text = $text }
}

function ConvertTo-SshLanControlResult($Raw) {
    $out = ''
    $err = ''
    $ok = $false
    $need = $false
    if ($null -ne $Raw) {
        $code = Get-SshLanBag $Raw 'Code'
        $okField = Get-SshLanBag $Raw 'Ok'
        $outField = Get-SshLanBag $Raw 'Out'
        $errField = Get-SshLanBag $Raw 'Err'
        if ($null -ne $outField) { $out = [string]$outField }
        if ($null -ne $errField) { $err = [string]$errField }
        if ($null -ne $code -and "$code" -ne '') {
            $need = ([int]$code -eq 77)
            if ($null -eq $okField) { $ok = ([int]$code -eq 0) }
        }
        if ($null -ne $okField) { $ok = [bool]$okField }
        if ($need) { $ok = $false }
    }
    return @{ Ok = [bool]$ok; Out = $out; Err = $err; NeedSudo = [bool]$need }
}

function Get-SshLanControlAlias([string]$Alias) {
    if ($Alias -notmatch '^[A-Za-z0-9._-]+$') { throw "ชื่อเครื่องไม่ถูกต้อง: $Alias" }
    return @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2', $Alias)
}

function ConvertFrom-SshLanRemoteEncodedText([string]$Out) {
    $b64 = @("$Out" -split "`r?`n" | Where-Object { $_ -match '^[A-Za-z0-9+/]{8,}={0,2}$' }) | Select-Object -Last 1
    if (-not $b64) { return $Out }
    try { return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$b64)) } catch { return $Out }
}

function Invoke-SshLanControlLinuxRemote($Device, [string]$Script) {
    $opts = Get-SshLanControlAlias (Get-SshLanText $Device 'Alias')
    return Invoke-SshLanSshCapture ($opts + 'sh -s') $Script
}

function Invoke-SshLanControlWindowsRemote($Device, [string]$Script) {
    $opts = Get-SshLanControlAlias (Get-SshLanText $Device 'Alias')
    $boot = '$b = [Console]::In.ReadToEnd(); $s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b.Trim())); $o = & ([scriptblock]::Create($s)) | Out-String; [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($o.Trim()))'
    $command = 'powershell -NoProfile -NonInteractive -EncodedCommand ' + (ConvertTo-SshLanEncodedCommand $boot)
    $stdin = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Script)) + "`n"
    $ran = Invoke-SshLanSshCapture ($opts + $command) $stdin
    return @{ Code = $ran.Code; Out = (ConvertFrom-SshLanRemoteEncodedText $ran.Out); Err = $ran.Err }
}

function Invoke-SshLanControlElevated([string]$Script) {
    $id = [guid]::NewGuid().ToString('N')
    $dir = $env:TEMP
    $scriptPath = Join-Path $dir "sshlan-ctl-$id.ps1"
    $outPath = Join-Path $dir "sshlan-ctl-$id.out"
    $errPath = Join-Path $dir "sshlan-ctl-$id.err"
    $codePath = Join-Path $dir "sshlan-ctl-$id.code"
    $utf8 = New-Object Text.UTF8Encoding $true
    [IO.File]::WriteAllText($scriptPath, $Script + "`r`n", $utf8)
    $q = {
        param($Path)
        "'" + $Path.Replace("'", "''") + "'"
    }
    $wrapper = @(
        '$ErrorActionPreference = ''Stop'''
        'try {'
        ('  $out = & {0} | Out-String' -f (& $q $scriptPath))
        ('  [IO.File]::WriteAllText({0}, $out, (New-Object Text.UTF8Encoding $false))' -f (& $q $outPath))
        ('  [IO.File]::WriteAllText({0}, ''0'', (New-Object Text.UTF8Encoding $false))' -f (& $q $codePath))
        '} catch {'
        ('  [IO.File]::WriteAllText({0}, $_.Exception.Message, (New-Object Text.UTF8Encoding $false))' -f (& $q $errPath))
        ('  [IO.File]::WriteAllText({0}, ''1'', (New-Object Text.UTF8Encoding $false))' -f (& $q $codePath))
        '}'
    ) -join "`r`n"
    $enc = ConvertTo-SshLanEncodedCommand $wrapper
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        $proc = Start-Process -FilePath $exe -ArgumentList @('-NoProfile', '-EncodedCommand', $enc) -Verb RunAs -Wait -PassThru
        $code = 1
        $out = ''
        $err = ''
        if (Test-Path -LiteralPath $codePath) { $code = [int]([IO.File]::ReadAllText($codePath).Trim()) }
        if (Test-Path -LiteralPath $outPath) { $out = [IO.File]::ReadAllText($outPath) }
        if (Test-Path -LiteralPath $errPath) { $err = [IO.File]::ReadAllText($errPath) }
        if (-not (Test-Path -LiteralPath $codePath)) {
            if (-not $err) { $err = 'ไม่แน่ใจว่าเปลี่ยนแล้วหรือยัง' }
            if ($proc -and $null -ne $proc.ExitCode) { $code = [int]$proc.ExitCode }
        }
        return @{ Code = $code; Out = $out; Err = $err }
    } finally {
        Remove-Item -LiteralPath $scriptPath, $outPath, $errPath, $codePath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-SshLanControl($Device, [string]$Os, [string]$Script, [scriptblock]$Runner = $null) {
    try {
        $raw = $null
        if ($Runner) { $raw = & $Runner $Script }
        elseif ((Get-SshLanText $Device 'Note') -eq 'เครื่องนี้') { $raw = Invoke-SshLanControlElevated $Script }
        elseif ($Os -match 'Windows') { $raw = Invoke-SshLanControlWindowsRemote $Device $Script }
        else { $raw = Invoke-SshLanControlLinuxRemote $Device $Script }
        return ConvertTo-SshLanControlResult $raw
    } catch {
        return @{ Ok = $false; Out = ''; Err = $_.Exception.Message; NeedSudo = $false }
    }
}

function Get-SshLanControlOsName($Finding, $Device) {
    $os = Get-SshLanText $Finding 'Os'
    if (-not $os) { $os = Get-SshLanText $Device 'Os' }
    if ($os -match 'Windows') { return 'Windows' }
    if ($os) { return 'Linux' }
    return 'Windows'
}

function Test-SshLanSameMachine($Device, $Row) {
    $dmac = Get-SshLanText $Device 'mac'
    $cmac = Get-SshLanText $Row 'mac'
    if ($dmac -and $cmac) { return [string]::Equals($dmac, $cmac, [StringComparison]::OrdinalIgnoreCase) }
    return (Get-SshLanText $Device 'ip') -eq (Get-SshLanText $Row 'ip')
}

function Get-SshLanPendingCloseRow($Device, [int]$Port) {
    foreach ($c in @(Get-SshLanChanges)) {
        if ((Get-SshLanText $c 'action') -ne 'close') { continue }
        if ([int](Get-SshLanText $c 'port') -ne $Port) { continue }
        if (Get-SshLanText $c 'undoneAt') { continue }
        if (Test-SshLanSameMachine $Device $c) { return $c }
    }
    return $null
}

function ConvertFrom-SshLanControlOutput([string]$Out) {
    $rules = New-Object System.Collections.Generic.List[string]
    $before = @{}
    foreach ($line in ("$Out" -split "`r?`n")) {
        $t = $line.Trim()
        if (-not $t) { continue }
        if ($t -match '^SSHLAN-BEFORE\s+(.+)$') {
            foreach ($pair in $Matches[1].Split(';')) {
                if ($pair -match '^(Domain|Private|Public)=(True|False)$') { $before[$Matches[1]] = ($Matches[2] -eq 'True') }
            }
            continue
        }
        if ($t -match '^[\w .()-]+$') { [void]$rules.Add($t) }
    }
    return @{ Rules = (ConvertTo-SshLanRuleList $rules.ToArray()); Before = $before }
}

function Get-SshLanListenerView($Facts, [int]$Port) {
    foreach ($row in @(Get-SshLanFactRows $Facts 'listeners')) {
        $text = Get-SshLanText $row 'port'
        if ($text -notmatch '^\d+$' -or [int]$text -ne $Port) { continue }
        return @{ Exposure = (Get-SshLanText $row 'exposure'); Rule = (Get-SshLanText $row 'rule') }
    }
    return $null
}

function Get-SshLanControlLanCidr([string]$Ip) {
    if ($Ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw "ที่อยู่ไม่ถูกต้อง: $Ip" }
    $own = @()
    try { $own = @(Get-SshLanOwnSubnets) } catch { $own = @() }
    foreach ($c in $own) {
        if ($c -and (Test-SshLanIpInCidr $Ip ([string]$c))) { return [string]$c }
    }
    $parts = $Ip.Split('.')
    return "$($parts[0]).$($parts[1]).$($parts[2]).0/24"
}

function Get-SshLanSwitchFacts($Device) {
    $facts = Get-SshLanBag $Device 'Facts'
    if ($null -eq $facts) { $facts = Get-SshLanBag $Device 'facts' }
    if ($null -ne $facts) { return $facts }
    if ((Get-SshLanText $Device 'Note') -eq 'เครื่องนี้') { return Get-SshLanWindowsFacts }
    return Get-SshLanMemberFacts $Device
}

function Get-SshLanSwitchRecheck($Device, [scriptblock]$Recheck) {
    if ($Recheck) { return (& $Recheck) }
    if ((Get-SshLanText $Device 'Note') -eq 'เครื่องนี้') { return Get-SshLanWindowsFacts }
    return Get-SshLanMemberFacts $Device
}

# internet findings drop UDP, so a missing protocol is TCP. A missing internal port is the external port.
function ConvertTo-SshLanIgdBefore($Mapping, $Finding, $Device, [int]$Port) {
    $external = $Port
    $client = ''
    $internal = 0
    $protocol = ''
    $description = ''
    if ($null -ne $Mapping) {
        $ext = Get-SshLanBag $Mapping 'external'
        if ("$ext" -match '^\d+$') { $external = [int]$ext }
        $got = Get-SshLanBag $Mapping 'internalClient'
        if ($null -ne $got) { $client = [string]$got }
        $inn = Get-SshLanBag $Mapping 'internalPort'
        if ("$inn" -match '^\d+$') { $internal = [int]$inn }
        $got = Get-SshLanBag $Mapping 'protocol'
        if ($null -ne $got) { $protocol = [string]$got }
        $got = Get-SshLanBag $Mapping 'description'
        if ($null -ne $got) { $description = [string]$got }
    }
    if (-not $client) { $client = Get-SshLanText $Finding 'Ip' }
    if (-not $client) { $client = Get-SshLanText $Device 'ip' }
    if (-not $protocol) { $protocol = 'TCP' }
    if ($internal -le 0) { $internal = $external }
    return @{
        external = $external
        internalClient = $client
        internalPort = $internal
        protocol = $protocol
        description = $description
    }
}

function Invoke-SshLanSwitch($Device, $Finding, $Switch, [scriptblock]$Runner = $null, [scriptblock]$Recheck = $null, [scriptblock]$Soap = $null, $Mapping = $null) {
    $action = Get-SshLanText $Switch 'Action'
    $enabled = [bool](Get-SshLanBag $Switch 'Enabled')
    if (-not $enabled) {
        $why = Get-SshLanText $Switch 'Why'
        if (-not $why) { $why = 'กดไม่ได้' }
        return @{ Ok = $false; Message = $why; ChangeId = '' }
    }
    $os = Get-SshLanControlOsName $Finding $Device
    $port = 0
    $portText = Get-SshLanText $Finding 'Port'
    if ($portText -match '^\d+$') { $port = [int]$portText }
    $arg = @{ Port = $port }
    $pending = $null
    if ($action -eq 'close') {
        if ($os -eq 'Windows') { $arg['Rule'] = Get-SshLanText $Finding 'Rule' }
    } elseif ($action -eq 'reopen') {
        $pending = Get-SshLanPendingCloseRow $Device $port
        if (-not $pending) { return @{ Ok = $false; Message = 'ไม่พบรายการที่จะเปิดคืน'; ChangeId = '' } }
        if ($os -eq 'Windows') { $arg['RuleIds'] = @($pending.rules) }
    } elseif ($action -eq 'firewall-on') {
        $ip = Get-SshLanText $Device 'ip'
        if (-not $ip) { $ip = Get-SshLanText $Finding 'Ip' }
        $lan = Get-SshLanControlLanCidr $ip
        $plan = Get-SshLanFirewallOnPlan (Get-SshLanSwitchFacts $Device) $lan
        $arg['Lan'] = $lan
        $arg['Keep'] = [int[]]@($plan.Keep)
        $arg['Port'] = 0
    } elseif ($action -eq 'upnp-delete') {
        if (-not $Soap) { return @{ Ok = $false; Message = 'เราเตอร์ไม่ตอบ UPnP'; ChangeId = '' } }
        $before = ConvertTo-SshLanIgdBefore $Mapping $Finding $Device $port
        $removed = Remove-SshLanIgdMapping $Soap ([int]$before.external) ([string]$before.protocol)
        if (-not $removed) { return @{ Ok = $false; Message = 'ไม่แน่ใจว่าเปลี่ยนแล้วหรือยัง ให้กดตรวจใหม่'; ChangeId = '' } }
        $machine = Get-SshLanText $Device 'Name'
        if (-not $machine) { $machine = Get-SshLanText $Finding 'Machine' }
        $ip = Get-SshLanText $Device 'ip'
        if (-not $ip) { $ip = Get-SshLanText $Finding 'Ip' }
        $changeId = Add-SshLanChange @{
            machine = $machine
            ip = $ip
            mac = (Get-SshLanText $Device 'mac')
            os = $os
            action = 'upnp-delete'
            port = [int]$before.external
            rules = @()
            before = $before
            expires = ''
        }
        return @{ Ok = $true; Message = 'ลบแล้ว'; ChangeId = $changeId }
    } else {
        return @{ Ok = $false; Message = 'ไม่รู้จักคำสั่งนี้'; ChangeId = '' }
    }

    $script = Get-SshLanControlScript $os $action $arg
    $ran = Invoke-SshLanControl $Device $os $script $Runner
    if ($ran.NeedSudo) { return @{ Ok = $false; Message = 'ต้องใส่รหัสของเครื่องนั้น'; ChangeId = '' } }
    if (-not $ran.Ok) { return @{ Ok = $false; Message = 'ไม่แน่ใจว่าเปลี่ยนแล้วหรือยัง ให้กดตรวจใหม่'; ChangeId = '' } }

    $parsed = ConvertFrom-SshLanControlOutput $ran.Out
    $rules = @(foreach ($r in @($parsed.Rules)) { if ("$r") { [string]$r } })
    $before = $parsed.Before
    if ($action -eq 'close' -and @($rules).Count -eq 0) {
        if ($os -eq 'Linux') { $rules = @("sshlan-close-$port") }
        elseif (Get-SshLanText $Finding 'Rule') { $rules = @((Get-SshLanText $Finding 'Rule')) }
    }
    if ($action -eq 'firewall-on') {
        if (@($rules).Count -eq 0) {
            $rules = @('sshlan-keep-ssh', 'sshlan-keep-tailscale')
            foreach ($p in @($arg['Keep'])) { $rules += "sshlan-keep-$p" }
        }
        if ($before.Count -eq 0) { $before = @{ firewallOn = $false } }
    }
    if ($action -eq 'close' -and $before.Count -eq 0) { $before = @{ enabled = $true } }

    $machine = Get-SshLanText $Device 'Name'
    if (-not $machine) { $machine = Get-SshLanText $Finding 'Machine' }
    $ip = Get-SshLanText $Device 'ip'
    if (-not $ip) { $ip = Get-SshLanText $Finding 'Ip' }
    $changeId = ''
    if ($action -eq 'reopen') {
        Set-SshLanChangeUndone ([string]$pending.id)
        $changeId = [string]$pending.id
    } else {
        $changeId = Add-SshLanChange @{
            machine = $machine
            ip = $ip
            mac = (Get-SshLanText $Device 'mac')
            os = $os
            action = $action
            port = $(if ($action -eq 'firewall-on') { 0 } else { $port })
            rules = $rules
            before = $before
            expires = ''
        }
    }

    try { $facts = Get-SshLanSwitchRecheck $Device $Recheck }
    catch { return @{ Ok = $false; Message = 'ไม่แน่ใจว่าเปลี่ยนแล้วหรือยัง ให้กดตรวจใหม่'; ChangeId = $changeId } }

    if ($action -eq 'firewall-on') {
        $on = [bool](Get-SshLanBag $facts 'firewallOn')
        if ($on) { return @{ Ok = $true; Message = 'เปิดไฟร์วอลล์แล้ว'; ChangeId = $changeId } }
        return @{ Ok = $false; Message = 'ไม่แน่ใจว่าเปิดไฟร์วอลล์แล้วหรือยัง ให้กดตรวจใหม่'; ChangeId = $changeId }
    }
    $view = Get-SshLanListenerView $facts $port
    if ($action -eq 'reopen') {
        if ($view -and $view.Exposure -eq 'blocked') { return @{ Ok = $false; Message = 'ยังปิดอยู่'; ChangeId = $changeId } }
        return @{ Ok = $true; Message = 'เปิดคืนแล้ว'; ChangeId = $changeId }
    }
    if ($null -eq $view -or $view.Exposure -eq 'blocked') { return @{ Ok = $true; Message = 'ปิดแล้ว'; ChangeId = $changeId } }
    $who = $view.Rule
    if (-not $who) { $who = 'ไม่ทราบชื่อ' }
    return @{ Ok = $false; Message = "ยังเปิดอยู่: กฎ $who ยังให้เข้า"; ChangeId = $changeId }
}

function Undo-SshLanIgdChange([string]$Id, [scriptblock]$Soap) {
    $row = Get-SshLanChangeById $Id
    if (-not $row) { throw "ไม่พบรายการ $Id" }
    if (Get-SshLanText $row 'undoneAt') { throw 'ย้อนรายการนี้ไปแล้ว' }
    if ((Get-SshLanText $row 'action') -ne 'upnp-delete') { throw 'รายการนี้ไม่ใช่การลบ UPnP' }
    if (-not (Add-SshLanIgdMapping $Soap $row.before)) {
        return @{ Ok = $false; Message = 'ไม่แน่ใจว่าเปลี่ยนแล้วหรือยัง ให้กดตรวจใหม่'; ChangeId = $Id }
    }
    Set-SshLanChangeUndone $Id
    return @{ Ok = $true; Message = 'เปิดคืนแล้ว'; ChangeId = $Id }
}

# The stamp is the local expiry minute, so a later pass can drop the rule without changes.json.
function Get-SshLanTempRuleName([int]$Port, [datetime]$Expires) {
    $p = ConvertTo-SshLanControlPort $Port
    return (ConvertTo-SshLanControlRule ('sshlan-temp-{0}-{1}' -f $p, $Expires.ToString('yyyyMMddHHmm', [Globalization.CultureInfo]::InvariantCulture)))
}

function ConvertFrom-SshLanTempRuleName([string]$Name) {
    if ($Name -notmatch '^sshlan-temp-(\d{1,5})-(\d{12})$') { return $null }
    $port = 0
    try { $port = ConvertTo-SshLanControlPort $Matches[1] } catch { return $null }
    $expires = [datetime]::MinValue
    $ok = [datetime]::TryParseExact($Matches[2], 'yyyyMMddHHmm', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$expires)
    if (-not $ok) { return $null }
    return @{ Port = $port; Expires = $expires }
}

function Get-SshLanExpiredTempRules([string[]]$Names, [datetime]$Now) {
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($Names)) {
        if (-not $n) { continue }
        $parsed = ConvertFrom-SshLanTempRuleName ([string]$n)
        if ($null -eq $parsed) { continue }
        if ($parsed.Expires -le $Now) { [void]$list.Add([string]$n) }
    }
    return $list.ToArray()
}

function ConvertTo-SshLanControlOs([string]$Os) {
    if ($Os -match 'Windows') { return 'Windows' }
    if ($Os) { return 'Linux' }
    throw "ระบบปฏิบัติการไม่ถูกต้อง: $Os"
}

function Resolve-SshLanTempTarget([string]$Os, [string]$What, $Port) {
    $known = @{
        ssh = @{ Port = 22; Rdp = $false; Os = '' }
        rdp = @{ Port = 3389; Rdp = $true; Os = 'Windows' }
    }
    if ($known.ContainsKey($What)) {
        $row = $known[$What]
        if ($row.Os -and $row.Os -ne $Os) { throw 'Remote Desktop ใช้ได้บน Windows' }
        return @{ Port = [int]$row.Port; Rdp = [bool]$row.Rdp }
    }
    if ($What -eq 'port') { return @{ Port = (ConvertTo-SshLanControlPort $Port); Rdp = $false } }
    throw "ไม่รู้จักสิ่งที่จะเปิด: $What"
}

function Get-SshLanTempMinute([datetime]$Expires) {
    return Get-Date -Year $Expires.Year -Month $Expires.Month -Day $Expires.Day -Hour $Expires.Hour -Minute $Expires.Minute -Second 0 -Millisecond 0
}

function Get-SshLanLinuxTempOpenBody([string]$Name, [int]$Port, [datetime]$Expires) {
    $when = $Expires.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)
    $allow = '$S ufw allow from 100.64.0.0/10 to any port {0} proto tcp comment ''{1}''' -f $Port, $Name
    $timer = '$S systemd-run --unit={0} --on-calendar=''{1}'' /usr/sbin/ufw delete allow from 100.64.0.0/10 to any port {2} proto tcp' -f $Name, $when, $Port
    return (($allow, $timer) -join "`n")
}

function Get-SshLanWindowsTempOpenScript([string]$Name, [int]$Port, [datetime]$Expires, [bool]$Rdp) {
    $at = $Expires.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add('$ErrorActionPreference = ''Stop''')
    if ($Rdp) {
        [void]$lines.Add('$ts = Get-ItemProperty ''HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server''')
        [void]$lines.Add('$tcp = Get-ItemProperty ''HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp''')
        [void]$lines.Add('$deny = [int]$ts.fDenyTSConnections')
        [void]$lines.Add('$nla = [int]$tcp.UserAuthentication')
        [void]$lines.Add('Write-Output (''SSHLAN-RDP fDenyTSConnections={0};UserAuthentication={1}'' -f $deny, $nla)')
        [void]$lines.Add('Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'' -Name fDenyTSConnections -Value 0')
        [void]$lines.Add('Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'' -Name UserAuthentication -Value 1')
    }
    [void]$lines.Add(('New-NetFirewallRule -Name ''{0}'' -DisplayName ''{0}'' -Direction Inbound -Protocol TCP -LocalPort {1} -RemoteAddress 100.64.0.0/10 -Action Allow | Out-Null' -f $Name, $Port))
    $mid = ''
    if ($Rdp) {
        $mid = 'Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'' -Name fDenyTSConnections -Value $deny; Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'' -Name UserAuthentication -Value $nla; '
    }
    $commandLine = '$command = "Remove-NetFirewallRule -Name ''{0}''; {1}Unregister-ScheduledTask -TaskName ''SSH LAN expire {0}'' -Confirm:`$false"' -f $Name, $mid
    [void]$lines.Add($commandLine)
    [void]$lines.Add('$action = New-ScheduledTaskAction -Execute ''powershell.exe'' -Argument "-NoProfile -Command `"$command`""')
    [void]$lines.Add(('$trigger = New-ScheduledTaskTrigger -Once -At ([datetime]::ParseExact(''{0}'', ''yyyy-MM-dd HH:mm:ss'', [Globalization.CultureInfo]::InvariantCulture))' -f $at))
    [void]$lines.Add('$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable')
    [void]$lines.Add(('Register-ScheduledTask -TaskName ''SSH LAN expire {0}'' -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null' -f $Name))
    return ($lines.ToArray() -join "`n")
}

function Get-SshLanTempOpenScript([string]$Os, [int]$Port, [datetime]$Expires, [bool]$Rdp) {
    if ($Os -ne 'Windows' -and $Os -ne 'Linux') { throw "ระบบปฏิบัติการไม่ถูกต้อง: $Os" }
    if ($Rdp -and $Os -ne 'Windows') { throw 'Remote Desktop ใช้ได้บน Windows' }
    $port = ConvertTo-SshLanControlPort $Port
    $minute = Get-SshLanTempMinute $Expires
    $name = Get-SshLanTempRuleName $port $minute
    if ($Os -eq 'Windows') { return (Get-SshLanWindowsTempOpenScript $name $port $minute $Rdp) }
    return (Get-SshLanLinuxControlText (Get-SshLanLinuxTempOpenBody $name $port $minute))
}

function Get-SshLanTempExpiry([int]$Hours) {
    $at = (Get-Date).AddHours($Hours)
    return (Get-SshLanTempMinute $at)
}

function ConvertFrom-SshLanTempBefore([string]$Out) {
    $before = @{}
    foreach ($line in ("$Out" -split "`r?`n")) {
        if ($line.Trim() -match '^SSHLAN-RDP\s+fDenyTSConnections=(\d+);UserAuthentication=(\d+)$') {
            $before['fDenyTSConnections'] = [int]$Matches[1]
            $before['UserAuthentication'] = [int]$Matches[2]
        }
    }
    return $before
}

function Open-SshLanTemp($Device, [string]$Os, [string]$What, [int]$Port, [int]$Hours, [scriptblock]$Runner = $null) {
    if (@(1, 2, 4, 8) -notcontains $Hours) { throw 'ชั่วโมงต้องเป็น 1, 2, 4 หรือ 8' }
    $osName = ConvertTo-SshLanControlOs $Os
    $target = Resolve-SshLanTempTarget $osName $What $Port
    if (Test-SshLanProtected $Device @(Get-SshLanProtected)) {
        return @{ Ok = $false; Message = 'ตั้งเป็น "ห้ามแอปแก้" ไว้'; ChangeId = ''; Expires = $null }
    }
    $facts = Get-SshLanSwitchFacts $Device
    if ((Get-SshLanBag $facts 'firewallOn') -eq $false) {
        return @{ Ok = $false; Message = 'ไฟร์วอลล์ปิดอยู่ เครื่องนี้เปิดทุกพอร์ตให้ทุกคนอยู่แล้ว กด "เปิดไฟร์วอลล์" ก่อน'; ChangeId = ''; Expires = $null }
    }
    $expires = Get-SshLanTempExpiry $Hours
    $script = Get-SshLanTempOpenScript $osName $target.Port $expires $target.Rdp
    $ran = Invoke-SshLanControl $Device $osName $script $Runner
    if ($ran.NeedSudo) { return @{ Ok = $false; Message = 'ต้องใส่รหัสของเครื่องนั้น'; ChangeId = ''; Expires = $expires } }
    if (-not $ran.Ok) { return @{ Ok = $false; Message = 'ไม่แน่ใจว่าเปลี่ยนแล้วหรือยัง ให้กดตรวจใหม่'; ChangeId = ''; Expires = $expires } }
    $rule = Get-SshLanTempRuleName $target.Port $expires
    $machine = Get-SshLanText $Device 'Name'
    if (-not $machine) { $machine = Get-SshLanText $Device 'machine' }
    $changeId = Add-SshLanChange @{
        machine = $machine
        ip = (Get-SshLanText $Device 'ip')
        mac = (Get-SshLanText $Device 'mac')
        os = $osName
        action = 'temp-open'
        port = $target.Port
        rules = @($rule)
        before = (ConvertFrom-SshLanTempBefore $ran.Out)
        expires = $expires.ToString('o')
    }
    return @{ Ok = $true; Message = ('เปิดแล้ว ให้เข้าจาก Tailscale ถึง ' + $expires.ToString('dd/MM/yyyy HH:mm')); ChangeId = $changeId; Expires = $expires }
}

function ConvertTo-SshLanTempDword($Value) {
    $text = "$Value"
    if ($text -notmatch '^\d{1,10}$') { return $null }
    return [int]$text
}

function Get-SshLanTempBeforeValue($Before, [string]$Name) {
    if ($null -eq $Before) { return $null }
    $val = $null
    if ($Before -is [hashtable]) {
        if (-not $Before.ContainsKey($Name)) { return $null }
        $val = $Before[$Name]
    } else {
        $prop = $Before.PSObject.Properties[$Name]
        if (-not $prop) { return $null }
        $val = $prop.Value
    }
    return (ConvertTo-SshLanTempDword $val)
}

function Get-SshLanWindowsTempCleanupScript([string[]]$Names, $BeforeByName) {
    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add('$ErrorActionPreference = ''Continue''')
    foreach ($name in @($Names)) {
        if (-not $name) { continue }
        $safe = ConvertTo-SshLanControlRule ([string]$name)
        $task = ConvertTo-SshLanControlRule ("SSH LAN expire $safe")
        [void]$lines.Add(('Remove-NetFirewallRule -Name ''{0}'' -ErrorAction SilentlyContinue' -f $safe))
        $before = $null
        if ($BeforeByName -is [hashtable] -and $BeforeByName.ContainsKey($safe)) { $before = $BeforeByName[$safe] }
        $deny = Get-SshLanTempBeforeValue $before 'fDenyTSConnections'
        $nla = Get-SshLanTempBeforeValue $before 'UserAuthentication'
        if ($null -ne $deny) {
            [void]$lines.Add(('Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'' -Name fDenyTSConnections -Value {0}' -f $deny))
        }
        if ($null -ne $nla) {
            [void]$lines.Add(('Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'' -Name UserAuthentication -Value {0}' -f $nla))
        }
        [void]$lines.Add(('Unregister-ScheduledTask -TaskName ''{0}'' -Confirm:$false -ErrorAction SilentlyContinue' -f $task))
    }
    return ($lines.ToArray() -join "`n")
}

function Get-SshLanLinuxTempCleanupBody([string[]]$Names) {
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($name in @($Names)) {
        if (-not $name) { continue }
        $parsed = ConvertFrom-SshLanTempRuleName ([string]$name)
        if ($null -eq $parsed) { continue }
        $safe = ConvertTo-SshLanControlRule ([string]$name)
        [void]$lines.Add(('$S ufw delete allow from 100.64.0.0/10 to any port {0} proto tcp || true' -f $parsed.Port))
        [void]$lines.Add(('$S systemctl stop {0}.timer || true' -f $safe))
        [void]$lines.Add(('$S systemctl reset-failed {0}.timer || true' -f $safe))
    }
    [void]$lines.Add('exit 0')
    return ($lines.ToArray() -join "`n")
}

function Get-SshLanTempCleanupScript([string]$Os, [string[]]$Names, $BeforeByName) {
    if ($Os -eq 'Windows') { return (Get-SshLanWindowsTempCleanupScript $Names $BeforeByName) }
    if ($Os -eq 'Linux') { return (Get-SshLanLinuxControlText (Get-SshLanLinuxTempCleanupBody $Names)) }
    throw "ระบบปฏิบัติการไม่ถูกต้อง: $Os"
}

function Get-SshLanChangeById([string]$Id) {
    foreach ($c in @(Get-SshLanChanges)) {
        if ([string]$c.id -eq $Id) { return $c }
    }
    return $null
}

function Get-SshLanTempBeforeByName([string[]]$Names) {
    $want = @{}
    foreach ($n in @($Names)) { if ($n) { $want[[string]$n] = $true } }
    $map = @{}
    foreach ($c in @(Get-SshLanChanges)) {
        if ((Get-SshLanText $c 'action') -ne 'temp-open') { continue }
        foreach ($r in @($c.rules)) {
            $rule = [string]$r
            if ($rule -and $want.ContainsKey($rule) -and -not $map.ContainsKey($rule)) { $map[$rule] = $c.before }
        }
    }
    return $map
}

function Close-SshLanTempNow($Device, [string]$ChangeId, [scriptblock]$Runner = $null) {
    $row = Get-SshLanChangeById $ChangeId
    if (-not $row) { throw "ไม่พบรายการ $ChangeId" }
    if (Get-SshLanText $row 'undoneAt') { throw 'ย้อนรายการนี้ไปแล้ว' }
    if ((Get-SshLanText $row 'action') -ne 'temp-open') { throw 'รายการนี้ไม่ใช่การเปิดแบบมีเวลา' }
    if (Test-SshLanProtected $Device @(Get-SshLanProtected)) {
        return @{ Ok = $false; Message = 'ตั้งเป็น "ห้ามแอปแก้" ไว้'; ChangeId = $ChangeId }
    }
    $rule = ''
    foreach ($r in @($row.rules)) { if ($r) { $rule = [string]$r; break } }
    if (-not $rule) { throw 'ไม่มีกฎที่จะปิด' }
    $osName = ConvertTo-SshLanControlOs (Get-SshLanText $row 'os')
    $script = Get-SshLanTempCleanupScript $osName @($rule) @{ $rule = $row.before }
    $ran = Invoke-SshLanControl $Device $osName $script $Runner
    if ($ran.NeedSudo) { return @{ Ok = $false; Message = 'ต้องใส่รหัสของเครื่องนั้น'; ChangeId = $ChangeId } }
    if (-not $ran.Ok) { return @{ Ok = $false; Message = 'ไม่แน่ใจว่าเปลี่ยนแล้วหรือยัง ให้กดตรวจใหม่'; ChangeId = $ChangeId } }
    Set-SshLanChangeUndone $ChangeId
    return @{ Ok = $true; Message = 'ปิดแล้ว'; ChangeId = $ChangeId }
}

function Remove-SshLanExpiredTempRules($Device, $Facts, [scriptblock]$Runner = $null) {
    if (Test-SshLanProtected $Device @(Get-SshLanProtected)) { return @() }
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($n in @(Get-SshLanBag $Facts 'tempRules')) { if ($n) { [void]$names.Add([string]$n) } }
    $expired = New-Object System.Collections.Generic.List[string]
    foreach ($n in @(Get-SshLanExpiredTempRules $names.ToArray() (Get-Date))) { if ($n) { [void]$expired.Add([string]$n) } }
    if ($expired.Count -eq 0) { return @() }
    $osText = Get-SshLanText $Facts 'os'
    if (-not $osText) { $osText = Get-SshLanText $Device 'Os' }
    if (-not $osText) { $osText = Get-SshLanText $Device 'os' }
    $osName = ConvertTo-SshLanControlOs $osText
    $script = Get-SshLanTempCleanupScript $osName $expired.ToArray() (Get-SshLanTempBeforeByName $expired.ToArray())
    $ran = Invoke-SshLanControl $Device $osName $script $Runner
    if (-not $ran.Ok) { return @() }
    return $expired.ToArray()
}
