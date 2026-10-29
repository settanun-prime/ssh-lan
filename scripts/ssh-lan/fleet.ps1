# --- fleet: run one piece of work against many machines at once, each with its own time limit ---
# results come back in the order of Targets; a hung or failing target only costs its own slot

function Invoke-SshLanFleet([object[]]$Targets, [scriptblock]$Work, [int]$Throttle = 8, [int]$TimeoutSec = 20) {
    # the work sees the same script functions as the caller (runspaces start empty); script variables and $PSScriptRoot do not come along
    $iss = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($f in Get-ChildItem function: | Where-Object { -not $_.ModuleName }) {
        $iss.Commands.Add((New-Object Management.Automation.Runspaces.SessionStateFunctionEntry $f.Name, $f.Definition))
    }
    $started = [hashtable]::Synchronized(@{})
    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $Throttle), $iss, $Host)
    $pool.Open()
    $jobs = @(for ($i = 0; $i -lt @($Targets).Count; $i++) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript('param($i, $t, $w, $s) $s[$i] = [DateTime]::UtcNow; & ([scriptblock]::Create($w)) $t').AddArgument($i).AddArgument($Targets[$i]).AddArgument($Work.ToString()).AddArgument($started)
        [pscustomobject]@{ Ps = $ps; Handle = $ps.BeginInvoke(); Result = $null }
    })
    try {
        while (@($jobs | Where-Object { -not $_.Result }).Count) {
            for ($i = 0; $i -lt $jobs.Count; $i++) {
                $j = $jobs[$i]
                if ($j.Result) { continue }
                $t0 = $started[$i]
                $secs = if ($t0) { ([DateTime]::UtcNow - $t0).TotalSeconds } else { 0 }
                if ($j.Handle.IsCompleted) {
                    try {
                        $out = @($j.Ps.EndInvoke($j.Handle))
                        $val = if ($out.Count -eq 1) { $out[0] } else { $out }
                        $j.Result = [pscustomobject]@{ Target = $Targets[$i]; Status = 'ok'; Result = $val; Error = $null; Seconds = [Math]::Round($secs, 1) }
                    } catch {
                        $e = $_.Exception
                        while ($e.InnerException) { $e = $e.InnerException }
                        $j.Result = [pscustomobject]@{ Target = $Targets[$i]; Status = 'error'; Result = $null; Error = $e.Message; Seconds = [Math]::Round($secs, 1) }
                    }
                } elseif ($t0 -and $secs -gt $TimeoutSec) {
                    [void]$j.Ps.BeginStop($null, $null)
                    $j.Result = [pscustomobject]@{ Target = $Targets[$i]; Status = 'timeout'; Result = $null; Error = "เกิน $TimeoutSec วินาที"; Seconds = [Math]::Round($secs, 1) }
                }
            }
            if (Get-Command Update-Ui -CommandType Function -ErrorAction SilentlyContinue) { Update-Ui }
            Start-Sleep -Milliseconds 50
        }
    } finally {
        # a stopped target may still be unwinding: close the pool in the background instead of waiting for it
        [void]$pool.BeginClose($null, $null)
    }
    return @($jobs | ForEach-Object { $_.Result })
}
