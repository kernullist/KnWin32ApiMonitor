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
        daemonInstanceId = "daemon-recovery-plan-fixture"
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

function Get-Plan
{
    param(
        [object]$Plan,
        [string]$SessionId
    )

    $item = @($Plan.recoveryPlans) | Where-Object { $_.sessionId -eq $SessionId } | Select-Object -First 1
    if ($null -eq $item)
    {
        throw "Missing recovery plan item for $SessionId."
    }

    return $item
}

function Assert-BlockedMutation
{
    param(
        [object]$Plan,
        [string]$Mutation
    )

    if (-not (@($Plan.blockedMutations) -contains $Mutation))
    {
        throw "Plan $($Plan.sessionId) did not block $Mutation."
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
$root = Join-Path $tmpDir "daemon-recovery-plan-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
$runtimeDir = Join-Path $root "runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null

$deadPid = Get-DeadPid
$records = @()
$records += Write-DaemonRecord -RuntimeDir $runtimeDir -SessionId "plan-daemon-crashed" -DaemonPid $deadPid -WriterPid $PID -TargetPid $PID -KnapmPath $fixturePath
$records += Write-DaemonRecord -RuntimeDir $runtimeDir -SessionId "plan-writer-crashed" -DaemonPid $PID -WriterPid $deadPid -TargetPid $PID -KnapmPath $fixturePath
$records += Write-DaemonRecord -RuntimeDir $runtimeDir -SessionId "plan-orphan-risk" -DaemonPid $deadPid -WriterPid $deadPid -TargetPid $PID -KnapmPath $fixturePath

$plan = & $helperPath daemon-recovery-plan --runtime-dir $runtimeDir | ConvertFrom-Json

if (-not $plan.success -or -not $plan.dryRun -or $plan.mutationAttempted)
{
    throw "Recovery plan did not remain dry-run only."
}

if ($plan.automaticRecoveryAllowed -or $plan.targetMutationAllowed)
{
    throw "Recovery plan unexpectedly allowed automatic recovery or target mutation."
}

if (@($plan.recoveryPlans).Count -ne 3 -or @($plan.sessions).Count -ne 3)
{
    throw "Recovery plan did not include all registry records."
}

$daemonCrashed = Get-Plan -Plan $plan -SessionId "plan-daemon-crashed"
$writerCrashed = Get-Plan -Plan $plan -SessionId "plan-writer-crashed"
$orphanRisk = Get-Plan -Plan $plan -SessionId "plan-orphan-risk"

if ($daemonCrashed.recoveryState -ne "daemon_crashed" -or $daemonCrashed.recommendedAction -ne "operator_restart_daemon_then_audit")
{
    throw "Daemon crash plan mismatch: $($daemonCrashed.recoveryState)/$($daemonCrashed.recommendedAction)"
}

if ($writerCrashed.recoveryState -ne "writer_crashed" -or -not $writerCrashed.registryPruneAllowed)
{
    throw "Writer crash plan mismatch: $($writerCrashed.recoveryState)"
}

if ($orphanRisk.recoveryState -ne "orphaned_agent_risk" -or -not $orphanRisk.registryPruneAllowed)
{
    throw "Orphan risk plan mismatch: $($orphanRisk.recoveryState)"
}

foreach ($item in @($daemonCrashed, $writerCrashed, $orphanRisk))
{
    if ($item.automaticRecoveryAllowed -or $item.targetMutationAllowed -or $item.safetyState -ne "dry_run_only")
    {
        throw "Plan $($item.sessionId) violated dry-run safety fields."
    }

    Assert-BlockedMutation -Plan $item -Mutation "kill_target_process"
    Assert-BlockedMutation -Plan $item -Mutation "unload_agent_module"
    Assert-BlockedMutation -Plan $item -Mutation "reinjection_repair"
}

foreach ($record in $records)
{
    if (-not (Test-Path -LiteralPath $record))
    {
        throw "Recovery plan deleted registry record $record."
    }
}

if ($null -eq (Get-Process -Id $PID -ErrorAction SilentlyContinue))
{
    throw "Recovery plan mutated the live target fixture."
}

Write-Output "x64 daemon recovery plan smoke passed: daemon=$($daemonCrashed.recommendedAction) writer=$($writerCrashed.recommendedAction) orphan=$($orphanRisk.recommendedAction) blocked=$($plan.blockedMutationCount)"
