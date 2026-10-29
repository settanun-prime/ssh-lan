# shared by every *.tests.ps1: asserts plus the app's functions loaded the way the window loads them
$ErrorActionPreference = 'Stop'
$env:SSH_LAN_UI = '1'
$TestRoot = Split-Path -Parent $PSScriptRoot

function Assert-True($Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERT FAILED: $Message" }
}

function Assert-Equal($Actual, $Expected, [string]$Message = '') {
    if ($Actual -ne $Expected) { throw "ASSERT FAILED: $Message expected [$Expected] got [$Actual]" }
}

function Assert-Throws([scriptblock]$Block, [string]$Message) {
    $threw = $false
    try { & $Block } catch { $threw = $true }
    if (-not $threw) { throw "ASSERT FAILED (did not throw): $Message" }
}

# JSON fixtures come back as PSCustomObject; the code under test takes hashtables for context
function ConvertTo-Hashtable($Object) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [Management.Automation.PSCustomObject]) {
        $h = @{}
        foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = ConvertTo-Hashtable $p.Value }
        return $h
    }
    if ($Object -is [Array]) { return , @($Object | ForEach-Object { ConvertTo-Hashtable $_ }) }
    return $Object
}

# HTTP status even for 4xx/5xx (Invoke-WebRequest throws on those); -1 = no answer
function Get-StatusCode([string]$Uri, [string]$Method = 'GET', [string]$Body = $null) {
    $extra = if ($Method -ne 'GET') { @{ Body = $Body } } else { @{} }
    try { return (Invoke-WebRequest $Uri -Method $Method -UseBasicParsing -TimeoutSec 10 @extra).StatusCode }
    catch [Net.WebException] { if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode } else { return -1 } }
}
