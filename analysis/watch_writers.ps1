<#
.SYNOPSIS
Observe transient writer process starts for the duration of one snapshot capture.

.DESCRIPTION
Creates one temporary WMI Win32_ProcessStartTrace subscription in a dedicated
background runspace, so event delivery never depends on the main runspace while
it blocks on stdin. The subscription only records process name and PID.

Protocol on stdout (UTF-8, one line each):
  READY
  {"complete":true,"drained":true,"started":["bztransmit.exe:1234"]}

Watched basenames are read from the BZCOMPACTOR_WATCH_NAMES environment
variable as a comma-separated list (the Python caller sets it per process, so
no argument-quoting layer can merge or split the list). READY is printed only
after the subscription is live; the caller may then capture writer state or
create the VSS shadow copy. Any line on stdin (or EOF) requests a bounded drain.
The summary reports observed queue quiescence, not a guarantee against WMI
provider loss or arbitrarily delayed delivery.

A failure before READY prints one JSON line with complete=false and exits 2.
After READY the summary is still printed, and an incomplete observation exits 1.

No service, process, audit-policy, registry or live Backblaze state is changed.
#>
[CmdletBinding()]
param(
    [ValidateRange(0, 60000)][int]$GraceMilliseconds = 750,
    [ValidateRange(1000, 120000)][int]$ReadyTimeoutMilliseconds = 25000
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [Console]::InputEncoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
} catch {
}

function Write-ProtocolLine([string]$Text) {
    [Console]::Out.WriteLine($Text)
    [Console]::Out.Flush()
}

function New-Summary([bool]$Complete, [string[]]$Started, [string]$ErrorText, [bool]$Drained = $false) {
    $payload = [ordered]@{ complete = $Complete; drained = $Drained; started = @($Started) }
    if (-not [string]::IsNullOrEmpty($ErrorText)) {
        $payload['error'] = $ErrorText
    }
    return ($payload | ConvertTo-Json -Compress -Depth 3)
}

$namesValue = [string]$env:BZCOMPACTOR_WATCH_NAMES
$nameSet = @($namesValue.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_.Length -gt 0 })
if ($nameSet.Count -eq 0) {
    Write-ProtocolLine (New-Summary -Complete $false -Started @() -ErrorText 'No process names were supplied in BZCOMPACTOR_WATCH_NAMES.')
    exit 2
}
foreach ($name in $nameSet) {
    if ($name.IndexOfAny([char[]]'\/:*?"<>|') -ge 0 -or $name -match '[\x00-\x1f]') {
        Write-ProtocolLine (New-Summary -Complete $false -Started @() -ErrorText 'Invalid process basename.')
        exit 2
    }
}
$grace = [Math]::Min(9000, [Math]::Max(750, $GraceMilliseconds))
$conditions = @($nameSet | ForEach-Object { "ProcessName = '$($_.Replace("'", "\'"))'" })
$queryText = 'SELECT * FROM Win32_ProcessStartTrace WHERE ' + ($conditions -join ' OR ')

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-ProtocolLine (New-Summary -Complete $false -Started @() -ErrorText 'Win32_ProcessStartTrace requires an elevated administrator process.')
    exit 2
}

try {
    Add-Type -AssemblyName System.Management
} catch {
    Write-ProtocolLine (New-Summary -Complete $false -Started @() -ErrorText ('Cannot load System.Management: ' + $_.Exception.Message))
    exit 2
}

$state = [hashtable]::Synchronized(@{
    Ready = $false
    StopCutoff = [long]0
    Drained = $false
    Stopped = $false
    Error = $null
    Queue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
})

# Runs on its own runspace thread. WaitForNextEvent blocks there, never in the
# main runspace, so events keep queuing while the parent captures the snapshot.
$worker = {
    $watcher = $null
    try {
        $scope = New-Object System.Management.ManagementScope -ArgumentList '\\.\root\cimv2'
        $query = New-Object System.Management.WqlEventQuery -ArgumentList $QueryText
        $options = New-Object System.Management.EventWatcherOptions
        $options.Timeout = [TimeSpan]::FromMilliseconds(250)
        $watcher = New-Object System.Management.ManagementEventWatcher -ArgumentList $scope, $query, $options

        # WaitForNextEvent creates the synchronous subscription on its first
        # call. A Timedout result proves the query is live with no start event
        # yet, which is the readiness point. The short options timeout also
        # bounds each wait, so Stop is honored without relying on cancellation.
        $first = $true
        $consecutiveTimeouts = 0
        while ($true) {
            $cutoff = [long]$State.StopCutoff
            if ($cutoff -ne 0 -and
                ([System.Diagnostics.Stopwatch]::GetTimestamp() - $cutoff) * 1000.0 / [System.Diagnostics.Stopwatch]::Frequency -ge 10000) {
                throw 'Writer observation drain deadline expired before observed quiescence.'
            }
            $waitStartedAfterStop = $cutoff -ne 0
            $processEvent = $null
            $timedOut = $false
            try {
                $processEvent = $watcher.WaitForNextEvent()
            } catch [System.Management.ManagementException] {
                if ([int]$_.Exception.ErrorCode -ne 262148) { throw }
                $timedOut = $true
            }
            if ($first) {
                $State.Ready = $true
                $first = $false
            }
            if ($null -ne $processEvent) {
                $consecutiveTimeouts = 0
                $name = [string]$processEvent.Properties['ProcessName'].Value
                if ($NameSet -contains $name.ToLowerInvariant()) {
                    $State.Queue.Enqueue(('{0}:{1}' -f $name, [string]$processEvent.Properties['ProcessID'].Value))
                }
            } elseif ($timedOut -and $waitStartedAfterStop) {
                $consecutiveTimeouts++
                $elapsed = ([System.Diagnostics.Stopwatch]::GetTimestamp() - $cutoff) * 1000.0 / [System.Diagnostics.Stopwatch]::Frequency
                if ($elapsed -ge 10000) {
                    throw 'Writer observation drain deadline expired before observed quiescence.'
                }
                if ($consecutiveTimeouts -ge 2 -and $elapsed -ge $Grace) {
                    $State.Drained = $true
                    break
                }
            }
        }
    } catch {
        $State.Error = $_.Exception.Message
        if ([string]::IsNullOrEmpty($State.Error)) {
            $State.Error = 'Writer subscription failed.'
        }
    } finally {
        $State.Stopped = $true
        if ($null -ne $watcher) {
            try { $watcher.Stop() } catch { }
            try { $watcher.Dispose() } catch { }
        }
    }
}

$runspace = $null
$powerShell = $null
$handle = $null
$ready = $false
$startupError = $null

try {
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $runspace.SessionStateProxy.SetVariable('State', $state)
    $runspace.SessionStateProxy.SetVariable('NameSet', $nameSet)
    $runspace.SessionStateProxy.SetVariable('QueryText', $queryText)
    $runspace.SessionStateProxy.SetVariable('Grace', $grace)
    $powerShell = [powershell]::Create()
    $powerShell.Runspace = $runspace
    $handle = $powerShell.AddScript($worker.ToString()).BeginInvoke()

    $deadline = [DateTime]::UtcNow.AddMilliseconds($ReadyTimeoutMilliseconds)
    while (-not $state.Ready -and -not $state.Stopped -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 25
    }
    if (-not $state.Ready) {
        if (-not [string]::IsNullOrEmpty($state.Error)) { throw $state.Error }
        if ($state.Stopped) { throw 'Writer subscription stopped before it became ready.' }
        throw 'Writer subscription did not become ready before the deadline.'
    }

    $ready = $true
    Write-ProtocolLine 'READY'

    [void][Console]::In.ReadLine()
} catch {
    if (-not $ready) {
        $startupError = $_.Exception.Message
        if ([string]::IsNullOrEmpty($startupError)) {
            $startupError = 'Writer subscription startup failed.'
        }
    } else {
        $state.Error = $_.Exception.Message
        if ([string]::IsNullOrEmpty($state.Error)) {
            $state.Error = 'Writer observation failed.'
        }
    }
} finally {
    # Signal with a monotonic cutoff; the worker owns the subscription and drains it.
    $state.StopCutoff = [System.Diagnostics.Stopwatch]::GetTimestamp()
    if ($ready -and $null -ne $handle) {
        if (-not $handle.AsyncWaitHandle.WaitOne(10500)) {
            if ([string]::IsNullOrEmpty($state.Error)) {
                $state.Error = 'Writer observation did not stop.'
            }
        } elseif ($handle.IsCompleted) {
            try {
                [void]$powerShell.EndInvoke($handle)
            } catch {
                if ([string]::IsNullOrEmpty($state.Error)) {
                    $state.Error = $_.Exception.Message
                    if ([string]::IsNullOrEmpty($state.Error)) {
                        $state.Error = 'Writer observation pipeline failed.'
                    }
                }
            }
        }
    }
}

if (-not $ready) {
    Write-ProtocolLine (New-Summary -Complete $false -Started @() -ErrorText $startupError)
    exit 2
}

$started = New-Object System.Collections.Generic.List[string]
$item = $null
while ($state.Queue.TryDequeue([ref]$item)) {
    if ($null -ne $item) {
        [void]$started.Add([string]$item)
    }
}

$errorText = [string]$state.Error
$complete = [string]::IsNullOrEmpty($errorText) -and $state.Drained -and $state.Stopped -and $null -ne $handle -and $handle.IsCompleted
if (-not $complete -and [string]::IsNullOrEmpty($errorText)) {
    $errorText = 'Writer observation did not stop cleanly.'
}

Write-ProtocolLine (New-Summary -Complete $complete -Drained ([bool]$state.Drained) -Started $started.ToArray() -ErrorText $errorText)

if ($null -ne $handle -and $handle.IsCompleted) {
    try { $powerShell.Dispose() } catch { }
    try { $runspace.Dispose() } catch { }
}

if ($complete) {
    exit 0
}
exit 1
