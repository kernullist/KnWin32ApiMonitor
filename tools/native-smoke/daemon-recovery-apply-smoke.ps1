param(
    [string]$BuildDir = "build\native\Debug"
)

$ErrorActionPreference = "Stop"

function Get-DeadPid
{
    $candidate = 42424242
    while ($candidate -gt 40000000)
    {
        $process = Get-Process -Id $candidate -ErrorAction SilentlyContinue
        if ($null -eq $process)
        {
            return $candidate
        }

        $candidate -= 1
    }

    throw "Unable to find a dead PID fixture."
}

function Write-DaemonRecord
{
    param(
        [string]$RuntimeDir,
        [string]$SessionId,
        [int]$DaemonPid,
        [int]$WriterPid,
        [int]$TargetPid,
        [string]$KnapmPath
    )

    $sessionsDir = Join-Path $RuntimeDir "sessions"
    New-Item -ItemType Directory -Force -Path $sessionsDir | Out-Null

    $record = [ordered]@{
        schemaVersion = "0.1.0"
        sessionId = $SessionId
        operationId = "$SessionId-op"
        targetProcessId = $TargetPid
        daemonProcessId = $DaemonPid
        daemonInstanceId = "daemon-recovery-apply-fixture"
        daemonStartedUtc = "2026-06-19T00:00:00.000Z"
        daemonControlEndpoint = "file-registry:$RuntimeDir"
        sessionProcessId = $WriterPid
        knapmPath = $KnapmPath
        cancellationEventName = "Local\KNMonCancel_$SessionId"
        startedUtc = "2026-06-19T00:00:00.000Z"
        durationMs = 30000
    }

    $recordPath = Join-Path $sessionsDir "$SessionId.json"
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $recordPath -Encoding UTF8
    return $recordPath
}

function Assert-Contains
{
    param(
        [object[]]$Values,
        [string]$Expected,
        [string]$Label
    )

    if (-not (@($Values) -contains $Expected))
    {
        throw "$Label did not include $Expected."
    }
}

$helperPath = Join-Path $BuildDir "knmon-native-helper.exe"
if (-not (Test-Path -LiteralPath $helperPath))
{
    throw "Helper not found: $helperPath"
}

$fixturePath = (Resolve-Path -LiteralPath "tests\fixtures\session\knapm-daemon-running.knapm").Path
$tmpDir = Join-Path (Get-Location) ".tmp"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$root = Join-Path $tmpDir "daemon-recovery-apply-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
$runtimeDir = Join-Path $root "runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null

$deadPid = Get-DeadPid
$daemonCrashedRecord = Write-DaemonRecord -RuntimeDir $runtimeDir -SessionId "apply-daemon-crashed" -DaemonPid $deadPid -WriterPid $PID -TargetPid $PID -KnapmPath $fixturePath
$writerCrashedRecord = Write-DaemonRecord -RuntimeDir $runtimeDir -SessionId "apply-writer-crashed" -DaemonPid $PID -WriterPid $deadPid -TargetPid $PID -KnapmPath $fixturePath
$orphanRiskRecord = Write-DaemonRecord -RuntimeDir $runtimeDir -SessionId "apply-orphan-risk" -DaemonPid $deadPid -WriterPid $deadPid -TargetPid $PID -KnapmPath $fixturePath

$dryRun = & $helperPath daemon-recovery-apply --runtime-dir $runtimeDir --dry-run | ConvertFrom-Json
if (-not $dryRun.success -or -not $dryRun.dryRun -or $dryRun.mutationAttempted)
{
    throw "Recovery apply dry-run violated mutation boundary."
}

if ($dryRun.operation -ne "daemon_recovery_apply" -or $dryRun.automaticRecoveryAllowed -or $dryRun.targetMutationAllowed)
{
    throw "Recovery apply dry-run returned unsafe global fields."
}

if (@($dryRun.recoveryPlans).Count -ne 3 -or @($dryRun.sessions).Count -ne 3)
{
    throw "Recovery apply dry-run did not include all registry records."
}

if (@($dryRun.prunedSessionIds).Count -ne 2)
{
    throw "Recovery apply dry-run should identify exactly two registry-prune candidates."
}

Assert-Contains -Values $dryRun.prunedSessionIds -Expected "apply-writer-crashed" -Label "dry-run prune candidates"
Assert-Contains -Values $dryRun.prunedSessionIds -Expected "apply-orphan-risk" -Label "dry-run prune candidates"

foreach ($path in @($daemonCrashedRecord, $writerCrashedRecord, $orphanRiskRecord))
{
    if (-not (Test-Path -LiteralPath $path))
    {
        throw "Recovery apply dry-run removed registry record $path."
    }
}

$apply = & $helperPath daemon-recovery-apply --runtime-dir $runtimeDir --apply-registry-prune | ConvertFrom-Json
if (-not $apply.success -or $apply.dryRun -or -not $apply.mutationAttempted)
{
    throw "Recovery apply did not perform explicit registry-only cleanup."
}

if ($apply.automaticRecoveryAllowed -or $apply.targetMutationAllowed)
{
    throw "Recovery apply unexpectedly allowed automatic recovery or target mutation."
}

Assert-Contains -Values $apply.prunedSessionIds -Expected "apply-writer-crashed" -Label "apply prune candidates"
Assert-Contains -Values $apply.prunedSessionIds -Expected "apply-orphan-risk" -Label "apply prune candidates"

if (-not (Test-Path -LiteralPath $daemonCrashedRecord))
{
    throw "Recovery apply removed a non-prune daemon-crashed registry record."
}

if (Test-Path -LiteralPath $writerCrashedRecord)
{
    throw "Recovery apply did not remove writer-crashed registry record."
}

if (Test-Path -LiteralPath $orphanRiskRecord)
{
    throw "Recovery apply did not remove orphan-risk registry record."
}

if (-not (Test-Path -LiteralPath $fixturePath))
{
    throw "Recovery apply deleted KNAPM fixture data."
}

if ($null -eq (Get-Process -Id $PID -ErrorAction SilentlyContinue))
{
    throw "Recovery apply mutated the live target fixture."
}

Write-Output "x64 daemon recovery apply smoke passed: dryRun=$(@($dryRun.prunedSessionIds).Count) applied=$(@($apply.prunedSessionIds).Count) kept=apply-daemon-crashed"
