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

function Wait-DaemonRecords
{
    param(
        [string]$HelperPath,
        [string]$RuntimeDir,
        [string]$SessionId,
        [int]$TimeoutMs = 8000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline)
    {
        $list = & $HelperPath daemon-list-sessions --runtime-dir $RuntimeDir | ConvertFrom-Json
        $session = @($list.sessions) | Where-Object { $_.sessionId -eq $SessionId } | Select-Object -First 1
        if ($session -and $session.recordsStreamed -gt 0 -and $session.sessionState -eq "running")
        {
            return $session
        }

        Start-Sleep -Milliseconds 150
    }

    throw "Daemon session did not stream records before timeout."
}

function Assert-ZstdSession
{
    param(
        [string]$HelperPath,
        [string]$KnapmPath,
        [string]$SessionId
    )

    $validation = & $HelperPath validate-session --session $KnapmPath | ConvertFrom-Json
    if (-not $validation.success -or $validation.compression -ne "zstd" -or $validation.storedBytes -le 0 -or $validation.uncompressedBytes -le 0)
    {
        throw "zstd validation failed for $KnapmPath`: $($validation.message) $($validation.validationErrors -join '; ')"
    }

    $replay = & $HelperPath replay-session --session $KnapmPath | ConvertFrom-Json
    if (-not $replay.success -or $replay.session.sessionId -ne $SessionId -or @($replay.traceEvents).Count -eq 0)
    {
        throw "zstd replay failed for $KnapmPath."
    }

    $manifest = Get-Content -LiteralPath (Join-Path $KnapmPath "manifest.json") -Raw | ConvertFrom-Json
    $index = Get-Content -LiteralPath (Join-Path $KnapmPath "index.json") -Raw | ConvertFrom-Json
    if ($manifest.compression -ne "zstd" -or @($manifest.compressionAlgorithms)[0] -ne "zstd")
    {
        throw "Manifest zstd compression metadata is missing."
    }

    foreach ($chunk in @($index.chunks))
    {
        if ($chunk.compression -ne "zstd" -or -not $chunk.file.EndsWith(".jsonl.zst"))
        {
            throw "Index chunk is not zstd: $($chunk.file)"
        }

        if ($chunk.uncompressedByteLength -le 0 -or [string]::IsNullOrWhiteSpace($chunk.uncompressedSha256))
        {
            throw "Index chunk is missing uncompressed integrity metadata."
        }
    }

    return $replay
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
$root = Join-Path $tmpDir "knapm-compression-catalog-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
$runtimeDir = Join-Path $root "runtime"
New-Item -ItemType Directory -Force -Path $root | Out-Null

$sample = $null
$daemonSample = $null

try
{
    $sampleStdout = Join-Path $root "attach.sample.stdout.txt"
    $sampleStderr = Join-Path $root "attach.sample.stderr.txt"
    $helperStdout = Join-Path $root "attach.helper.stdout.jsonl"
    $helperStderr = Join-Path $root "attach.helper.stderr.txt"
    $attachKnapm = Join-Path $root "attach-zstd.knapm"
    $attachSessionId = "zstd-attach-$([Guid]::NewGuid().ToString("N").Substring(0, 8))"
    $attachOperationId = "zstd-attach-op-$([Guid]::NewGuid().ToString("N").Substring(0, 8))"

    $sample = Start-Process -FilePath $samplePath -ArgumentList "--attach-loop --iterations 500 --delay-ms 100" -RedirectStandardOutput $sampleStdout -RedirectStandardError $sampleStderr -PassThru -WindowStyle Hidden
    Wait-SampleReady -OutputPath $sampleStdout

    $attachHelper = Start-Process -FilePath $helperPath -ArgumentList @(
        "attach-session",
        "--pid", "$($sample.Id)",
        "--duration-ms", "12000",
        "--timeout-ms", "15000",
        "--operation-id", $attachOperationId,
        "--session-id", $attachSessionId,
        "--stream-batches",
        "--batch-size", "4",
        "--batch-interval-ms", "100",
        "--write-knapm", $attachKnapm,
        "--knapm-compression", "zstd"
    ) -RedirectStandardOutput $helperStdout -RedirectStandardError $helperStderr -PassThru -WindowStyle Hidden

    Wait-Frames -Path $helperStdout -Label "session_started" -Predicate {
        param($frame)
        $frame.frameType -eq "session_started" -and $frame.session.sessionId -eq $attachSessionId
    } | Out-Null

    Wait-Frames -Path $helperStdout -Label "non-empty trace_batch" -Predicate {
        param($frame)
        $frame.frameType -eq "trace_batch" -and $frame.eventCount -gt 0
    } | Out-Null

    Invoke-CancelOperation -HelperPath $helperPath -OperationId $attachOperationId | Out-Null
    if (-not $attachHelper.WaitForExit(25000))
    {
        throw "Compressed attach helper did not exit after cancellation."
    }

    $attachReplay = Assert-ZstdSession -HelperPath $helperPath -KnapmPath $attachKnapm -SessionId $attachSessionId

    $daemonSampleStdout = Join-Path $root "daemon.sample.stdout.txt"
    $daemonSampleStderr = Join-Path $root "daemon.sample.stderr.txt"
    $daemonKnapm = Join-Path $root "daemon-zstd.knapm"
    $daemonSample = Start-Process -FilePath $samplePath -ArgumentList "--attach-loop --iterations 500 --delay-ms 100" -RedirectStandardOutput $daemonSampleStdout -RedirectStandardError $daemonSampleStderr -PassThru -WindowStyle Hidden
    Wait-SampleReady -OutputPath $daemonSampleStdout

    $daemon = & $helperPath daemon-start --runtime-dir $runtimeDir | ConvertFrom-Json
    if (-not $daemon.success -or $daemon.daemonProcessId -eq 0)
    {
        throw "daemon-start failed: $($daemon.message)"
    }

    $daemonSessionId = "zstd-daemon-$([Guid]::NewGuid().ToString("N").Substring(0, 8))"
    $daemonStarted = & $helperPath daemon-start-session --runtime-dir $runtimeDir --pid $daemonSample.Id --duration-ms 20000 --timeout-ms 7000 --session-id $daemonSessionId --operation-id "$daemonSessionId-op" --write-knapm $daemonKnapm --knapm-compression zstd | ConvertFrom-Json
    if (-not $daemonStarted.success)
    {
        throw "daemon-start-session zstd failed: $($daemonStarted.message)"
    }

    Wait-DaemonRecords -HelperPath $helperPath -RuntimeDir $runtimeDir -SessionId $daemonSessionId | Out-Null
    $daemonStopped = & $helperPath daemon-stop-session --runtime-dir $runtimeDir --session-id $daemonSessionId | ConvertFrom-Json
    if (-not $daemonStopped.success -or -not $daemonStopped.session.agentCleanupSucceeded)
    {
        throw "daemon-stop-session zstd failed: $($daemonStopped.message)"
    }

    $daemonReplay = Assert-ZstdSession -HelperPath $helperPath -KnapmPath $daemonKnapm -SessionId $daemonSessionId

    $catalogMissing = Join-Path $root "catalog-missing.knapm"
    Copy-Item -Recurse -LiteralPath "tests\fixtures\session\knapm-zstd-valid.knapm" -Destination $catalogMissing
    $catalogPath = Join-Path $root "catalog.json"
    $catalog = & $helperPath catalog-sessions --root $root --catalog $catalogPath --rebuild | ConvertFrom-Json
    if (-not $catalog.success -or $catalog.sessionCount -lt 3 -or $catalog.validSessionCount -lt 3)
    {
        throw "catalog-sessions failed: $($catalog.message)"
    }

    $query = & $helperPath catalog-query --catalog $catalogPath --state valid --limit 10 | ConvertFrom-Json
    $zstdRows = @($query.sessions | Where-Object { $_.compression -eq "zstd" })
    if (-not $query.success -or $zstdRows.Count -lt 2)
    {
        throw "catalog-query failed to find zstd sessions."
    }

    Remove-Item -Recurse -Force -LiteralPath $catalogMissing
    $dryRun = & $helperPath catalog-remove-missing --catalog $catalogPath --dry-run | ConvertFrom-Json
    if (-not $dryRun.success -or @($dryRun.missingSessionPaths).Count -ne 1)
    {
        throw "catalog-remove-missing dry-run did not report one missing session."
    }

    if (-not (Test-Path -LiteralPath $attachKnapm) -or -not (Test-Path -LiteralPath $daemonKnapm))
    {
        throw "catalog dry-run mutated live session directories."
    }

    $pruned = & $helperPath catalog-remove-missing --catalog $catalogPath | ConvertFrom-Json
    if (-not $pruned.success -or @($pruned.missingSessionPaths).Count -ne 1 -or $pruned.sessionCount -ne ($catalog.sessionCount - 1))
    {
        throw "catalog-remove-missing did not prune only the missing catalog row."
    }

    Write-Output "KNAPM compression/catalog smoke passed: attachReplay=$(@($attachReplay.traceEvents).Count) daemonReplay=$(@($daemonReplay.traceEvents).Count) catalog=$($catalog.sessionCount) pruned=$($pruned.sessionCount)"
}
finally
{
    & $helperPath daemon-stop --runtime-dir $runtimeDir | Out-Null

    if ($sample -and -not $sample.HasExited)
    {
        Stop-Process -Id $sample.Id -Force -ErrorAction SilentlyContinue
    }

    if ($daemonSample -and -not $daemonSample.HasExited)
    {
        Stop-Process -Id $daemonSample.Id -Force -ErrorAction SilentlyContinue
    }
}
