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

function Wait-Frames
{
    param(
        [string]$Path,
        [scriptblock]$Predicate,
        [string]$Label,
        [int]$TimeoutMs = 10000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline)
    {
        if (Test-Path -LiteralPath $Path)
        {
            $frames = @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
                try
                {
                    $_ | ConvertFrom-Json
                }
                catch
                {
                    $null
                }
            } | Where-Object { $_ -ne $null })

            $matches = @($frames | Where-Object { & $Predicate $_ })
            if ($matches.Count -gt 0)
            {
                return $matches
            }
        }

        Start-Sleep -Milliseconds 100
    }

    throw "Timed out waiting for $Label in $Path"
}

function Invoke-CancelOperation
{
    param(
        [string]$HelperPath,
        [string]$OperationId,
        [int]$TimeoutMs = 5000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    $last = $null
    while ([DateTime]::UtcNow -lt $deadline)
    {
        $last = & $HelperPath cancel-operation --operation-id $OperationId | ConvertFrom-Json
        if ($last.success)
        {
            return $last
        }

        Start-Sleep -Milliseconds 100
    }

    throw "Cancellation signal failed for $OperationId`: $($last.message)"
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
$sampleStdout = Join-Path $tmpDir "streaming-session.sample.stdout.txt"
$sampleStderr = Join-Path $tmpDir "streaming-session.sample.stderr.txt"
$helperStdout = Join-Path $tmpDir "streaming-session.helper.stdout.jsonl"
$helperStderr = Join-Path $tmpDir "streaming-session.helper.stderr.txt"
Remove-Item -Force -ErrorAction SilentlyContinue $sampleStdout,$sampleStderr,$helperStdout,$helperStderr

$sessionId = "stream-session-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
$operationId = "stream-op-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
$sample = Start-Process -FilePath $samplePath -ArgumentList "--attach-loop --iterations 500 --delay-ms 100" -RedirectStandardOutput $sampleStdout -RedirectStandardError $sampleStderr -PassThru -WindowStyle Hidden
$helper = $null

try
{
    Wait-SampleReady -OutputPath $sampleStdout
    $helper = Start-Process -FilePath $helperPath -ArgumentList @(
        "attach-session",
        "--pid", "$($sample.Id)",
        "--duration-ms", "12000",
        "--timeout-ms", "15000",
        "--operation-id", $operationId,
        "--session-id", $sessionId,
        "--stream-batches",
        "--batch-size", "4",
        "--batch-interval-ms", "100"
    ) -RedirectStandardOutput $helperStdout -RedirectStandardError $helperStderr -PassThru -WindowStyle Hidden

    $started = Wait-Frames -Path $helperStdout -Label "session_started" -Predicate {
        param($frame)
        $frame.frameType -eq "session_started" -and $frame.session.sessionId -eq $sessionId
    }

    if ($started[0].session.operationId -ne $operationId)
    {
        throw "Started frame operation id mismatch."
    }

    Wait-Frames -Path $helperStdout -Label "running session_state" -Predicate {
        param($frame)
        $frame.frameType -eq "session_state" -and $frame.session.sessionState -eq "running"
    } | Out-Null

    Wait-Frames -Path $helperStdout -Label "non-empty trace_batch" -Predicate {
        param($frame)
        $frame.frameType -eq "trace_batch" -and $frame.eventCount -gt 0
    } | Out-Null

    Invoke-CancelOperation -HelperPath $helperPath -OperationId $operationId | Out-Null

    Wait-Frames -Path $helperStdout -Label "session_stopping" -Predicate {
        param($frame)
        $frame.frameType -eq "session_stopping"
    } | Out-Null

    if (-not $helper.WaitForExit(25000))
    {
        throw "Attach session helper did not exit after stop."
    }

    $frames = @(Get-Content -LiteralPath $helperStdout | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_ | ConvertFrom-Json })
    $batches = @($frames | Where-Object { $_.frameType -eq "trace_batch" })
    if ($batches.Count -lt 1)
    {
        throw "No trace_batch frames were emitted."
    }

    $expectedBatch = [uint64]$batches[0].batchSequence
    $lastRecord = $null
    foreach ($batch in $batches)
    {
        if ([uint64]$batch.batchSequence -ne $expectedBatch)
        {
            throw "Batch sequence gap: expected=$expectedBatch actual=$($batch.batchSequence)"
        }

        if ([uint64]$batch.eventCount -ne [uint64]$batch.events.Count)
        {
            throw "Batch event count mismatch at batch=$($batch.batchSequence)"
        }

        if ([uint64]$batch.lastRecordSequence -lt [uint64]$batch.firstRecordSequence)
        {
            throw "Batch record sequence range is invalid at batch=$($batch.batchSequence)"
        }

        if ($lastRecord -ne $null -and [uint64]$batch.firstRecordSequence -le [uint64]$lastRecord)
        {
            throw "Record sequence did not advance at batch=$($batch.batchSequence)"
        }

        $lastRecord = [uint64]$batch.lastRecordSequence
        ++$expectedBatch
    }

    $stoppedFrame = @($frames | Where-Object { $_.frameType -eq "session_stopped" } | Select-Object -Last 1)
    if ($stoppedFrame.Count -ne 1 -or $stoppedFrame[0].session.sessionState -ne "stopped")
    {
        throw "Session stopped frame missing or invalid."
    }

    $captureFrame = @($frames | Where-Object { $_.frameType -eq "capture_result" } | Select-Object -Last 1)
    if ($captureFrame.Count -ne 1)
    {
        throw "Capture result frame missing."
    }

    $lastBatch = $batches[$batches.Count - 1]
    $capture = $captureFrame[0].captureResult
    if ([uint64]$capture.recordsStreamed -ne [uint64]$lastBatch.recordsStreamed)
    {
        throw "Final recordsStreamed mismatch: final=$($capture.recordsStreamed) batch=$($lastBatch.recordsStreamed)"
    }

    if ([uint64]$capture.transportDroppedEvents -ne [uint64]$lastBatch.droppedEvents)
    {
        throw "Final transportDroppedEvents mismatch: final=$($capture.transportDroppedEvents) batch=$($lastBatch.droppedEvents)"
    }

    if (-not $capture.agentCleanupAttempted -or -not $capture.agentCleanupSucceeded)
    {
        throw "Streaming attach did not prove cleanup."
    }

    $shutdown = @($capture.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
    if ($shutdown.Count -ne 1 -or $shutdown[0].reason -ne "self_disable")
    {
        throw "Streaming attach shutdown evidence mismatch."
    }

    Write-Host "x64 streaming session UI batch smoke passed: batches=$($batches.Count) records=$($capture.recordsStreamed) cleanup=$($capture.agentCleanupSucceeded)"
}
finally
{
    if ($helper -ne $null -and -not $helper.HasExited)
    {
        Stop-Process -Id $helper.Id -Force -ErrorAction SilentlyContinue
    }

    if ($sample -ne $null -and -not $sample.HasExited)
    {
        Stop-Process -Id $sample.Id -Force -ErrorAction SilentlyContinue
    }
}
