param(
    [string]$SamplePath = "build\native\Debug\knmon-sample-fileio.exe",
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

function Assert-True
{
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition)
    {
        throw $Message
    }
}

Assert-True (Test-Path -LiteralPath $SamplePath) "Sample target not found: $SamplePath"
Assert-True (Test-Path -LiteralPath $HelperPath) "Native helper not found: $HelperPath"

$resolvedSample = (Resolve-Path -LiteralPath $SamplePath).Path
$resolvedHelper = (Resolve-Path -LiteralPath $HelperPath).Path
$workingDir = Split-Path -Parent $resolvedSample
$targetPid = 0

$output = @(
    & $resolvedHelper launch-session `
        --target $resolvedSample `
        --cwd $workingDir `
        --stream-batches `
        --batch-size 64
)
$exitCode = $LASTEXITCODE

try
{
    Assert-True ($exitCode -eq 0) "Launch-session helper exited with code $exitCode."
    Assert-True ($output.Count -gt 0) "Launch-session did not emit any frames."

    $frames = @()
    foreach ($line in $output)
    {
        Assert-True ($line -match '^\{"schemaVersion"') "Launch-session stdout was polluted by a non-JSON line: $line"
        $frames += ($line | ConvertFrom-Json)
    }

    $captureResultFrames = @($frames | Where-Object { $_.frameType -eq "capture_result" })
    Assert-True ($captureResultFrames.Count -eq 1) "Launch-session did not emit exactly one capture_result frame."

    $captureResult = $captureResultFrames[0].captureResult
    $targetPid = [int]$captureResult.targetProcessId

    Assert-True ($captureResult.success -eq $true) "Launch-session capture failed: $($captureResult.operation): $($captureResult.message)"
    Assert-True ($captureResult.sessionState -eq "stopped") "Launch-session final state mismatch: $($captureResult.sessionState)"
    Assert-True ($captureResult.recordsStreamed -gt 0) "Launch-session reported zero streamed records."
    Assert-True ($captureResult.transportRecordsProduced -gt 0) "Launch-session reported zero produced records."
    Assert-True ($captureResult.transportDroppedEvents -eq 0) "Launch-session dropped transport events: $($captureResult.transportDroppedEvents)"

    $events = @()
    foreach ($frame in $frames)
    {
        if ($frame.frameType -eq "trace_batch")
        {
            $events += @($frame.events)
        }
    }

    Assert-True ($events.Count -gt 0) "Launch-session did not stream trace events for the short-lived sample."

    $createFileEvents = @($events | Where-Object { $_.module -eq "kernel32.dll" -and $_.api -eq "CreateFileW" })
    Assert-True ($createFileEvents.Count -gt 0) "Short-lived launch did not capture kernel32.dll!CreateFileW."

    $fileNameArguments = @()
    foreach ($event in $createFileEvents)
    {
        $fileNameArguments += @($event.arguments | Where-Object { $_.name -eq "lpFileName" })
    }

    Assert-True ($fileNameArguments.Count -gt 0) "CreateFileW events did not include lpFileName arguments."

    $auditEvents = @($captureResult.auditEvents)
    $auditTypes = @($auditEvents | ForEach-Object { $_.eventType })
    Assert-True ($auditTypes -contains "early_bird_apc_queued") "Launch audit is missing early_bird_apc_queued."
    Assert-True ($auditTypes -contains "early_bird_grace_apc_queued") "Launch audit is missing early_bird_grace_apc_queued."

    Write-Host "Launch session short-lived smoke passed: events=$($events.Count) createFileW=$($createFileEvents.Count) records=$($captureResult.recordsStreamed)"
}
finally
{
    if ($targetPid -ne 0)
    {
        Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
    }
}
