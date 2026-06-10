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
$root = Join-Path $tmpDir "persistent-daemon-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
$runtimeDir = Join-Path $root "runtime"
$knapmPath = Join-Path $root "daemon-session.knapm"
New-Item -ItemType Directory -Force -Path $root | Out-Null

$sampleStdout = Join-Path $root "sample.stdout.txt"
$sampleStderr = Join-Path $root "sample.stderr.txt"
$sample = Start-Process -FilePath $samplePath -ArgumentList "--attach-loop --iterations 500 --delay-ms 100" -RedirectStandardOutput $sampleStdout -RedirectStandardError $sampleStderr -PassThru -WindowStyle Hidden

try
{
    Wait-SampleReady -OutputPath $sampleStdout

    $daemon = & $helperPath daemon-start --runtime-dir $runtimeDir | ConvertFrom-Json
    if (-not $daemon.success -or $daemon.daemonProcessId -eq 0)
    {
        throw "daemon-start failed: $($daemon.message)"
    }

    $started = & $helperPath daemon-start-session --runtime-dir $runtimeDir --pid $sample.Id --duration-ms 20000 --timeout-ms 7000 --write-knapm $knapmPath | ConvertFrom-Json
    if (-not $started.success)
    {
        throw "daemon-start-session failed: $($started.message)"
    }

    if ($started.session.daemonProcessId -ne $daemon.daemonProcessId)
    {
        throw "Daemon PID mismatch in start-session result."
    }

    if (-not (Get-Process -Id $daemon.daemonProcessId -ErrorAction SilentlyContinue))
    {
        throw "Daemon process is not alive after start-session returned."
    }

    if (-not (Get-Process -Id $started.sessionProcessId -ErrorAction SilentlyContinue))
    {
        throw "Daemon session process is not alive after start-session returned."
    }

    $listedSession = Wait-DaemonRecords -HelperPath $helperPath -RuntimeDir $runtimeDir -SessionId $started.session.sessionId

    if ($sample.HasExited)
    {
        throw "Daemon validation mutated or terminated the live sample target."
    }

    $stopped = & $helperPath daemon-stop-session --runtime-dir $runtimeDir --session-id $started.session.sessionId | ConvertFrom-Json
    if (-not $stopped.success -or $stopped.session.sessionState -ne "stopped")
    {
        throw "daemon-stop-session failed: state=$($stopped.session.sessionState) message=$($stopped.message)"
    }

    if (-not $stopped.session.agentCleanupSucceeded)
    {
        throw "Daemon stop did not prove agent cleanup."
    }

    $validation = & $helperPath validate-session --session $knapmPath | ConvertFrom-Json
    if (-not $validation.success)
    {
        throw "Daemon KNAPM validation failed: $($validation.validationErrors -join '; ')"
    }

    if ($validation.recoveryState -ne "none" -or $validation.recoveryReason -ne "finalized")
    {
        throw "Daemon KNAPM recovery mismatch: $($validation.recoveryState)/$($validation.recoveryReason)"
    }

    $replay = & $helperPath replay-session --session $knapmPath | ConvertFrom-Json
    if (-not $replay.success -or @($replay.traceEvents).Count -eq 0)
    {
        throw "Daemon KNAPM replay failed or returned no trace events."
    }

    $manifest = Get-Content -LiteralPath (Join-Path $knapmPath "manifest.json") -Raw | ConvertFrom-Json
    if ($manifest.owner.ownerKind -ne "persistent-daemon")
    {
        throw "Manifest ownerKind is not persistent-daemon."
    }

    if ($manifest.owner.daemonProcessId -ne $daemon.daemonProcessId -or [string]::IsNullOrWhiteSpace($manifest.owner.daemonInstanceId))
    {
        throw "Manifest daemon owner identity is incomplete."
    }

    if ($manifest.checkpoint.lastCommittedChunkSequence -ne $manifest.chunkCount)
    {
        throw "Manifest checkpoint does not match chunkCount."
    }

    $daemonStopped = & $helperPath daemon-stop --runtime-dir $runtimeDir | ConvertFrom-Json
    if (-not $daemonStopped.success)
    {
        throw "daemon-stop failed: $($daemonStopped.message)"
    }

    Write-Output "x64 persistent daemon session smoke passed: daemon=$($daemon.daemonProcessId) session=$($started.session.sessionId) records=$($listedSession.recordsStreamed) replay=$(@($replay.traceEvents).Count) owner=$($manifest.owner.ownerKind)"
}
finally
{
    & $helperPath daemon-stop --runtime-dir $runtimeDir | Out-Null

    if ($sample -ne $null -and -not $sample.HasExited)
    {
        Stop-Process -Id $sample.Id -Force -ErrorAction SilentlyContinue
    }
}
