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
$sampleStdout = Join-Path $tmpDir "knapm-streaming.sample.stdout.txt"
$sampleStderr = Join-Path $tmpDir "knapm-streaming.sample.stderr.txt"
$helperStdout = Join-Path $tmpDir "knapm-streaming.helper.stdout.jsonl"
$helperStderr = Join-Path $tmpDir "knapm-streaming.helper.stderr.txt"
$knapmPath = Join-Path $tmpDir "knapm-streaming-$([Guid]::NewGuid().ToString("N").Substring(0, 12)).knapm"
Remove-Item -Force -ErrorAction SilentlyContinue $sampleStdout,$sampleStderr,$helperStdout,$helperStderr
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $knapmPath

$sessionId = "knapm-session-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
$operationId = "knapm-op-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
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
        "--batch-interval-ms", "100",
        "--write-knapm", $knapmPath
    ) -RedirectStandardOutput $helperStdout -RedirectStandardError $helperStderr -PassThru -WindowStyle Hidden

    $started = Wait-Frames -Path $helperStdout -Label "session_started" -Predicate {
        param($frame)
        $frame.frameType -eq "session_started" -and $frame.session.sessionId -eq $sessionId
    }

    if ($started[0].session.operationId -ne $operationId)
    {
        throw "Started frame operation id mismatch."
    }

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

    $captureFrame = @($frames | Where-Object { $_.frameType -eq "capture_result" } | Select-Object -Last 1)
    if ($captureFrame.Count -ne 1)
    {
        throw "Capture result frame missing."
    }

    $capture = $captureFrame[0].captureResult
    if (-not $capture.agentCleanupSucceeded)
    {
        throw "Streaming attach did not prove cleanup."
    }

    $shutdown = @($capture.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
    if ($shutdown.Count -ne 1 -or $shutdown[0].reason -ne "self_disable")
    {
        throw "Streaming attach shutdown evidence mismatch."
    }

    $validate = & $helperPath validate-session --session $knapmPath | ConvertFrom-Json
    if (-not $validate.success -or $validate.format -ne "knapm" -or -not $validate.finalized)
    {
        throw "KNAPM validation failed: $($validate.message) $($validate.validationErrors -join '; ')"
    }

    $replay = & $helperPath replay-session --session $knapmPath | ConvertFrom-Json
    if (-not $replay.success -or $replay.session.sessionId -ne $sessionId)
    {
        throw "KNAPM replay failed or session identity mismatch."
    }

    $manifest = Get-Content -LiteralPath (Join-Path $knapmPath "manifest.json") -Raw | ConvertFrom-Json
    $index = Get-Content -LiteralPath (Join-Path $knapmPath "index.json") -Raw | ConvertFrom-Json

    if ($manifest.sessionId -ne $sessionId -or $manifest.operationId -ne $operationId)
    {
        throw "Manifest identity mismatch."
    }

    if ($index.sessionId -ne $sessionId -or $index.operationId -ne $operationId)
    {
        throw "Index identity mismatch."
    }

    if ([int]$manifest.chunkCount -lt 1 -or [int]$manifest.chunkCount -ne @($index.chunks).Count)
    {
        throw "Chunk count mismatch."
    }

    $expectedBatch = [uint64]$index.chunks[0].batchSequence
    $lastRecord = $null
    $indexedTraceCount = [uint64]0
    foreach ($chunk in @($index.chunks))
    {
        if ([uint64]$chunk.batchSequence -ne $expectedBatch)
        {
            throw "Chunk batch sequence gap: expected=$expectedBatch actual=$($chunk.batchSequence)"
        }

        if ([uint64]$chunk.lastRecordSequence -lt [uint64]$chunk.firstRecordSequence)
        {
            throw "Chunk record range is invalid."
        }

        if ($lastRecord -ne $null -and [uint64]$chunk.firstRecordSequence -le [uint64]$lastRecord)
        {
            throw "Chunk record range is not monotonic."
        }

        $chunkPath = Join-Path $knapmPath $chunk.file
        if (-not (Test-Path -LiteralPath $chunkPath))
        {
            throw "Chunk file is missing: $($chunk.file)"
        }

        $hash = (Get-FileHash -LiteralPath $chunkPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -ne $chunk.sha256)
        {
            throw "Chunk hash mismatch for $($chunk.file)."
        }

        $rows = @(Get-Content -LiteralPath $chunkPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_ | ConvertFrom-Json })
        if ([uint64]$rows.Count -ne [uint64]$chunk.eventCount)
        {
            throw "Chunk event count mismatch for $($chunk.file)."
        }

        $indexedTraceCount += [uint64]$chunk.eventCount
        $lastRecord = [uint64]$chunk.lastRecordSequence
        ++$expectedBatch
    }

    if ([uint64]$replay.traceEvents.Count -ne $indexedTraceCount)
    {
        throw "Replay count mismatch: replay=$($replay.traceEvents.Count) indexed=$indexedTraceCount"
    }

    if ([uint64]$manifest.eventCounts.traceEvents -ne $indexedTraceCount)
    {
        throw "Manifest trace count mismatch."
    }

    if ([uint64]$manifest.session.recordsStreamed -ne [uint64]$capture.recordsStreamed)
    {
        throw "Manifest recordsStreamed mismatch."
    }

    if ([uint64]$manifest.transportDroppedEvents -ne [uint64]$capture.transportDroppedEvents)
    {
        throw "Manifest transportDroppedEvents mismatch."
    }

    if ([uint64]$validate.traceEventCount -ne $indexedTraceCount)
    {
        throw "Validation traceEventCount mismatch."
    }

    $sample.Refresh()
    if ($sample.HasExited)
    {
        throw "Validate/replay should not terminate or mutate the sample target."
    }

    Write-Host "x64 KNAPM streaming replay smoke passed: chunks=$($manifest.chunkCount) replay=$($replay.traceEvents.Count) cleanup=$($capture.agentCleanupSucceeded)"
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
