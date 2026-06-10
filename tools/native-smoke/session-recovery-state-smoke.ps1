param(
    [string]$BuildDir = "build\native\Debug"
)

$ErrorActionPreference = "Stop"

$helperPath = Join-Path $BuildDir "knmon-native-helper.exe"
if (-not (Test-Path -LiteralPath $helperPath))
{
    throw "Helper not found: $helperPath"
}

$tmpDir = Join-Path (Get-Location) ".tmp"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

function Write-SessionRecord
{
    param(
        [string]$Path,
        [string]$SessionId,
        [string]$OperationId,
        [int]$TargetProcessId
    )

    $record = [ordered]@{
        schemaVersion = "0.1.0"
        sessionId = $SessionId
        operationId = $OperationId
        sessionKind = "attach_capture"
        ownerProcessId = 999999
        helperProcessId = 999998
        targetProcessId = $TargetProcessId
        sessionState = "running"
        startedUtc = "2026-06-10T00:00:00.000Z"
        updatedUtc = "2026-06-10T00:00:01.000Z"
        cancellationEventName = "Local\KNMonCancel_$OperationId"
        lastTransportSequence = 7
        recordsStreamed = 7
    }

    $record | ConvertTo-Json -Compress | Set-Content -LiteralPath $Path -Encoding UTF8
}

$recoveryRecord = Join-Path $tmpDir "session-recovery-required.json"
Write-SessionRecord -Path $recoveryRecord -SessionId "stale-live-target" -OperationId "stale-live-op" -TargetProcessId $PID

$recovery = & $helperPath classify-session --session-record $recoveryRecord | ConvertFrom-Json
if (-not $recovery.success)
{
    throw "Recovery classification failed: $($recovery.message)"
}

if ($recovery.mutationAttempted)
{
    throw "Recovery classification attempted mutation."
}

if ($recovery.session.sessionState -ne "recovery_required")
{
    throw "Expected recovery_required, got $($recovery.session.sessionState)"
}

if ($recovery.session.staleReason -ne "owner_missing_target_alive")
{
    throw "Unexpected recovery stale reason: $($recovery.session.staleReason)"
}

if ($recovery.session.recoveryAction -ne "manual_same_bitness_cleanup_required")
{
    throw "Unexpected recovery action: $($recovery.session.recoveryAction)"
}

$staleRecord = Join-Path $tmpDir "session-stale-target-exited.json"
Write-SessionRecord -Path $staleRecord -SessionId "stale-dead-target" -OperationId "stale-dead-op" -TargetProcessId 0

$stale = & $helperPath classify-session --session-record $staleRecord | ConvertFrom-Json
if (-not $stale.success)
{
    throw "Stale classification failed: $($stale.message)"
}

if ($stale.mutationAttempted)
{
    throw "Stale classification attempted mutation."
}

if ($stale.session.sessionState -ne "stale")
{
    throw "Expected stale, got $($stale.session.sessionState)"
}

if ($stale.session.staleReason -ne "owner_missing_target_exited")
{
    throw "Unexpected stale reason: $($stale.session.staleReason)"
}

Write-Host "session recovery-state smoke passed: live=$($recovery.session.sessionState) dead=$($stale.session.sessionState)"
