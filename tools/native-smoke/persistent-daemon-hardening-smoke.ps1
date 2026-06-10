param(
    [string]$BuildDir = "build\native\Debug"
)

$ErrorActionPreference = "Stop"

function Wait-SampleReady
{
    param(
        [string]$OutputPath,
        [int]$TimeoutMs = 5000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline)
    {
        if ((Test-Path -LiteralPath $OutputPath) -and ((Get-Content -LiteralPath $OutputPath -Raw -ErrorAction SilentlyContinue) -match "attach-loop-ready"))
        {
            return
        }

        Start-Sleep -Milliseconds 100
    }

    throw "Sample target did not report attach-loop-ready."
}

function Start-Sample
{
    param(
        [string]$SamplePath,
        [string]$Root,
        [string]$Name
    )

    $stdout = Join-Path $Root "$Name.stdout.txt"
    $stderr = Join-Path $Root "$Name.stderr.txt"
    $process = Start-Process -FilePath $SamplePath -ArgumentList "--attach-loop --iterations 800 --delay-ms 100" -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
    Wait-SampleReady -OutputPath $stdout
    return $process
}

function Wait-DaemonSessionState
{
    param(
        [string]$HelperPath,
        [string]$RuntimeDir,
        [string]$SessionId,
        [string]$ExpectedState,
        [int]$TimeoutMs = 10000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline)
    {
        $audit = & $HelperPath daemon-audit --runtime-dir $RuntimeDir | ConvertFrom-Json
        $session = @($audit.sessions) | Where-Object { $_.sessionId -eq $SessionId } | Select-Object -First 1
        if ($session -and $session.recoveryState -eq $ExpectedState)
        {
            return $session
        }

        Start-Sleep -Milliseconds 150
    }

    throw "Timed out waiting for daemon session $SessionId state $ExpectedState."
}

function Assert-Message
{
    param(
        [object]$Result,
        [string]$Expected,
        [string]$Label
    )

    if ($Result.success)
    {
        throw "$Label unexpectedly succeeded."
    }

    if ($Result.message -ne $Expected)
    {
        throw "$Label message mismatch: expected=$Expected actual=$($Result.message)"
    }
}

$helperPath = Join-Path $BuildDir "knmon-native-helper.exe"
$samplePath = Join-Path $BuildDir "knmon-sample-fileio.exe"

if (-not (Test-Path -LiteralPath $helperPath))
{
    throw "Helper not found: $helperPath"
}

if (-not (Test-Path -LiteralPath $samplePath))
{
    throw "Sample target not found: $samplePath"
}

$tmpDir = Join-Path (Get-Location) ".tmp"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$root = Join-Path $tmpDir "persistent-daemon-hardening-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
$runtimeDir = Join-Path $root "runtime"
New-Item -ItemType Directory -Force -Path $root | Out-Null

$primarySample = $null
$pathSample = $null
$writerCrashSample = $null

try
{
    $primarySample = Start-Sample -SamplePath $samplePath -Root $root -Name "primary"
    $primaryKnapm = Join-Path $root "primary.knapm"
    $primary = & $helperPath daemon-start-session --runtime-dir $runtimeDir --pid $primarySample.Id --duration-ms 30000 --timeout-ms 7000 --operation-id "daemon-hardening-primary-op" --session-id "daemon-hardening-primary" --write-knapm $primaryKnapm | ConvertFrom-Json
    if (-not $primary.success)
    {
        throw "primary daemon-start-session failed: $($primary.message)"
    }

    $healthy = Wait-DaemonSessionState -HelperPath $helperPath -RuntimeDir $runtimeDir -SessionId $primary.session.sessionId -ExpectedState "healthy"
    if ($healthy.recoveryReason -ne "owned" -or -not $healthy.daemonAlive -or -not $healthy.sessionProcessAlive -or -not $healthy.targetAlive -or -not $healthy.knapmValid)
    {
        throw "Healthy daemon audit fields are incomplete."
    }

    $duplicateTargetPath = Join-Path $root "duplicate-target.knapm"
    $duplicateTarget = & $helperPath daemon-start-session --runtime-dir $runtimeDir --pid $primarySample.Id --duration-ms 1000 --timeout-ms 3000 --operation-id "daemon-hardening-dup-target-op" --session-id "daemon-hardening-dup-target" --write-knapm $duplicateTargetPath | ConvertFrom-Json
    Assert-Message -Result $duplicateTarget -Expected "already_supervised" -Label "duplicate target"
    if (Test-Path -LiteralPath $duplicateTargetPath)
    {
        throw "Duplicate target rejection created a KNAPM path."
    }

    $pathSample = Start-Sample -SamplePath $samplePath -Root $root -Name "path-conflict"
    $duplicatePath = & $helperPath daemon-start-session --runtime-dir $runtimeDir --pid $pathSample.Id --duration-ms 1000 --timeout-ms 3000 --operation-id "daemon-hardening-dup-path-op" --session-id "daemon-hardening-dup-path" --write-knapm $primaryKnapm | ConvertFrom-Json
    Assert-Message -Result $duplicatePath -Expected "knapm_path_in_use" -Label "duplicate KNAPM path"

    $duplicateSessionPath = Join-Path $root "duplicate-session.knapm"
    $duplicateSession = & $helperPath daemon-start-session --runtime-dir $runtimeDir --pid $pathSample.Id --duration-ms 1000 --timeout-ms 3000 --operation-id "daemon-hardening-dup-session-op" --session-id $primary.session.sessionId --write-knapm $duplicateSessionPath | ConvertFrom-Json
    Assert-Message -Result $duplicateSession -Expected "session_id_in_use" -Label "duplicate session id"
    if (Test-Path -LiteralPath $duplicateSessionPath)
    {
        throw "Duplicate session rejection created a KNAPM path."
    }

    Stop-Process -Id $primary.daemon.daemonProcessId -Force
    Start-Sleep -Milliseconds 400
    $staleStatus = & $helperPath daemon-status --runtime-dir $runtimeDir | ConvertFrom-Json
    if ($staleStatus.daemonState -ne "stale")
    {
        throw "daemon-status did not surface stale daemon state: $($staleStatus.daemonState)"
    }

    $daemonCrash = Wait-DaemonSessionState -HelperPath $helperPath -RuntimeDir $runtimeDir -SessionId $primary.session.sessionId -ExpectedState "daemon_crashed"
    if (-not $daemonCrash.sessionProcessAlive -or -not $daemonCrash.targetAlive -or $primarySample.HasExited)
    {
        throw "Daemon crash audit mutated the live target or lost writer evidence."
    }

    $stoppedPrimary = & $helperPath daemon-stop-session --runtime-dir $runtimeDir --session-id $primary.session.sessionId | ConvertFrom-Json
    if (-not $stoppedPrimary.success -or $stoppedPrimary.session.sessionState -ne "stopped")
    {
        throw "daemon-stop-session after daemon crash failed: $($stoppedPrimary.message)"
    }

    $writerCrashSample = Start-Sample -SamplePath $samplePath -Root $root -Name "writer-crash"
    $writerCrashKnapm = Join-Path $root "writer-crash.knapm"
    $writerCrash = & $helperPath daemon-start-session --runtime-dir $runtimeDir --pid $writerCrashSample.Id --duration-ms 30000 --timeout-ms 7000 --operation-id "daemon-hardening-writer-op" --session-id "daemon-hardening-writer" --write-knapm $writerCrashKnapm | ConvertFrom-Json
    if (-not $writerCrash.success)
    {
        throw "writer-crash daemon-start-session failed: $($writerCrash.message)"
    }

    Stop-Process -Id $writerCrash.sessionProcessId -Force
    Start-Sleep -Milliseconds 500
    $writerCrashAudit = Wait-DaemonSessionState -HelperPath $helperPath -RuntimeDir $runtimeDir -SessionId $writerCrash.session.sessionId -ExpectedState "writer_crashed"
    if (-not $writerCrashAudit.targetAlive -or -not $writerCrashAudit.pruneEligible -or $writerCrashSample.HasExited)
    {
        throw "Writer crash audit did not report target-alive prune-eligible stale registry."
    }

    $currentDaemon = & $helperPath daemon-status --runtime-dir $runtimeDir | ConvertFrom-Json
    $sessionsDir = Join-Path $runtimeDir "sessions"
    New-Item -ItemType Directory -Force -Path $sessionsDir | Out-Null
    $keepRecord = [ordered]@{
        schemaVersion = "0.1.0"
        sessionId = "daemon-hardening-keep"
        operationId = "daemon-hardening-keep-op"
        targetProcessId = $PID
        daemonProcessId = $currentDaemon.daemonProcessId
        daemonInstanceId = $currentDaemon.daemonInstanceId
        daemonStartedUtc = $currentDaemon.daemonStartedUtc
        daemonControlEndpoint = $currentDaemon.controlEndpoint
        sessionProcessId = $PID
        knapmPath = "tests/fixtures/session/knapm-daemon-running.knapm"
        cancellationEventName = "Local\KNMonCancel_daemon-hardening-keep-op"
        startedUtc = "2026-06-10T00:00:00.000Z"
        durationMs = 30000
    }
    $keepRecord | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $sessionsDir "daemon-hardening-keep.json") -Encoding UTF8

    $staleStart = & $helperPath daemon-start-session --runtime-dir $runtimeDir --pid $writerCrashSample.Id --duration-ms 1000 --timeout-ms 3000 --operation-id "daemon-hardening-stale-op" --session-id "daemon-hardening-stale" --write-knapm (Join-Path $root "stale-conflict.knapm") | ConvertFrom-Json
    Assert-Message -Result $staleStart -Expected "stale_registry_requires_prune" -Label "stale registry duplicate"

    $dryRun = & $helperPath daemon-prune-stale --runtime-dir $runtimeDir --dry-run | ConvertFrom-Json
    if ($dryRun.mutationAttempted -or $dryRun.pruneEligibleCount -lt 1 -or -not (@($dryRun.sessions) | Where-Object { $_.sessionId -eq $writerCrash.session.sessionId -and $_.pruneEligible }))
    {
        throw "daemon-prune-stale dry-run did not report the expected prune candidate."
    }

    $pruned = & $helperPath daemon-prune-stale --runtime-dir $runtimeDir | ConvertFrom-Json
    if (-not $pruned.success -or @($pruned.prunedSessionIds).Count -lt 1)
    {
        throw "daemon-prune-stale failed to prune stale records: $($pruned.message)"
    }

    $afterPrune = & $helperPath daemon-audit --runtime-dir $runtimeDir | ConvertFrom-Json
    $kept = @($afterPrune.sessions) | Where-Object { $_.sessionId -eq "daemon-hardening-keep" } | Select-Object -First 1
    $removed = @($afterPrune.sessions) | Where-Object { $_.sessionId -eq $writerCrash.session.sessionId } | Select-Object -First 1
    if (-not $kept -or $kept.recoveryState -ne "healthy" -or $removed)
    {
        throw "Prune did not leave the active record and remove the stale writer record."
    }

    $validation = & $helperPath validate-session --session $primaryKnapm | ConvertFrom-Json
    if (-not $validation.success -or $validation.recoveryState -ne "none")
    {
        throw "Finalized daemon KNAPM validation failed after pruning: $($validation.message)"
    }

    $replay = & $helperPath replay-session --session $primaryKnapm | ConvertFrom-Json
    if (-not $replay.success -or @($replay.traceEvents).Count -eq 0)
    {
        throw "Finalized daemon KNAPM replay failed after pruning."
    }

    Write-Output "x64 persistent daemon hardening smoke passed: healthy=$($healthy.sessionId) daemonCrash=$($daemonCrash.recoveryState) writerCrash=$($writerCrashAudit.recoveryState) pruned=$(@($pruned.prunedSessionIds).Count) replay=$(@($replay.traceEvents).Count)"
}
finally
{
    & $helperPath daemon-stop --runtime-dir $runtimeDir | Out-Null

    foreach ($process in @($primarySample, $pathSample, $writerCrashSample))
    {
        if ($process -ne $null -and -not $process.HasExited)
        {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}
