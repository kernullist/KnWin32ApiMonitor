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

function Wait-AgentModuleLoaded
{
    param(
        [int]$ProcessId,
        [string]$ModuleName,
        [int]$TimeoutMs = 7000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline)
    {
        try
        {
            $process = [System.Diagnostics.Process]::GetProcessById($ProcessId)
            $modules = @($process.Modules | ForEach-Object { $_.ModuleName })
            if ($modules -contains $ModuleName)
            {
                return
            }
        }
        catch
        {
        }

        Start-Sleep -Milliseconds 100
    }

    throw "Agent module was not observed in target process: $ModuleName"
}

function Wait-JsonlFrame
{
    param(
        [string]$Path,
        [string]$FrameType,
        [string]$SessionState,
        [int]$TimeoutMs = 7000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline)
    {
        if (Test-Path -LiteralPath $Path)
        {
            $lines = @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)
            foreach ($line in $lines)
            {
                if ([string]::IsNullOrWhiteSpace($line))
                {
                    continue
                }

                try
                {
                    $frame = $line | ConvertFrom-Json
                    if ($frame.frameType -eq $FrameType -and $frame.session.sessionState -eq $SessionState)
                    {
                        return $frame
                    }
                }
                catch
                {
                }
            }
        }

        Start-Sleep -Milliseconds 100
    }

    throw "Timed out waiting for $FrameType/$SessionState in $Path"
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

$collectorPath = Join-Path $BuildDir "knmon-collector.exe"
$helperPath = Join-Path $BuildDir "knmon-native-helper.exe"
$samplePath = Join-Path $BuildDir "knmon-sample-fileio.exe"

if (-not (Test-Path -LiteralPath $collectorPath))
{
    throw "Collector not found: $collectorPath"
}

if (-not (Test-Path -LiteralPath $helperPath))
{
    throw "Helper not found: $helperPath"
}

if (-not (Test-Path -LiteralPath $samplePath))
{
    throw "Sample target not found: $samplePath"
}

$threaded = & $collectorPath smoke-threaded-session-reader --capacity 8 --records 6 | ConvertFrom-Json
if (-not $threaded.success)
{
    throw "Threaded reader smoke failed: $($threaded.message)"
}

if ($threaded.sessionState -ne "stopped" -or $threaded.recordsStreamed -ne 6 -or $threaded.lastTransportSequence -ne 6)
{
    throw "Threaded reader metrics mismatch: state=$($threaded.sessionState) streamed=$($threaded.recordsStreamed) last=$($threaded.lastTransportSequence)"
}

$tmpDir = Join-Path (Get-Location) ".tmp"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$sampleStdout = Join-Path $tmpDir "threaded-session.sample.stdout.txt"
$sampleStderr = Join-Path $tmpDir "threaded-session.sample.stderr.txt"
$helperStdout = Join-Path $tmpDir "threaded-session.helper.stdout.jsonl"
$helperStderr = Join-Path $tmpDir "threaded-session.helper.stderr.txt"
Remove-Item -Force -ErrorAction SilentlyContinue $sampleStdout,$sampleStderr,$helperStdout,$helperStderr

$sessionId = "session-smoke-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
$operationId = "session-op-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
$sample = Start-Process -FilePath $samplePath -ArgumentList "--attach-loop --iterations 500 --delay-ms 100" -RedirectStandardOutput $sampleStdout -RedirectStandardError $sampleStderr -PassThru -WindowStyle Hidden
$helper = $null

try
{
    Wait-SampleReady -OutputPath $sampleStdout
    $helper = Start-Process -FilePath $helperPath -ArgumentList @("attach-session", "--pid", "$($sample.Id)", "--duration-ms", "12000", "--timeout-ms", "15000", "--operation-id", $operationId, "--session-id", $sessionId) -RedirectStandardOutput $helperStdout -RedirectStandardError $helperStderr -PassThru -WindowStyle Hidden

    $runningFrame = Wait-JsonlFrame -Path $helperStdout -FrameType "session_state" -SessionState "running"
    if ($runningFrame.session.sessionId -ne $sessionId -or $runningFrame.session.operationId -ne $operationId)
    {
        throw "Running session frame identity mismatch."
    }

    Wait-AgentModuleLoaded -ProcessId $sample.Id -ModuleName "knmon-agent64.dll"
    Start-Sleep -Milliseconds 800
    Invoke-CancelOperation -HelperPath $helperPath -OperationId $operationId | Out-Null

    if (-not $helper.WaitForExit(25000))
    {
        throw "Attach session helper did not exit after stop."
    }

    $frames = @(Get-Content -LiteralPath $helperStdout | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_ | ConvertFrom-Json })
    $stoppedFrame = @($frames | Where-Object { $_.frameType -eq "session_stopped" } | Select-Object -Last 1)
    if ($stoppedFrame.Count -ne 1)
    {
        throw "Session stopped frame missing."
    }

    if ($stoppedFrame[0].session.sessionState -ne "stopped" -or -not $stoppedFrame[0].session.agentCleanupSucceeded)
    {
        throw "Session stopped frame cleanup mismatch: state=$($stoppedFrame[0].session.sessionState)"
    }

    $captureFrame = @($frames | Where-Object { $_.frameType -eq "capture_result" } | Select-Object -Last 1)
    if ($captureFrame.Count -ne 1)
    {
        throw "Capture result frame missing."
    }

    $capture = $captureFrame[0].captureResult
    if ($capture.operation -ne "operation_cancelled" -or $capture.sessionState -ne "stopped")
    {
        throw "Capture result stop state mismatch: operation=$($capture.operation) session=$($capture.sessionState)"
    }

    if (-not $capture.agentCleanupAttempted -or -not $capture.agentCleanupSucceeded)
    {
        throw "Attach session did not prove cleanup."
    }

    $shutdown = @($capture.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
    if ($shutdown.Count -ne 1 -or $shutdown[0].reason -ne "self_disable")
    {
        throw "Attach session shutdown evidence mismatch."
    }

    Write-Host "x64 threaded collector/session smoke passed: threaded=$($threaded.recordsStreamed) session=$($stoppedFrame[0].session.sessionState) cleanup=$($capture.agentCleanupSucceeded)"
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
