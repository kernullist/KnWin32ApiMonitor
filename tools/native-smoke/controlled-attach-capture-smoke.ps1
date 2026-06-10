param(
    [string]$BuildDir = "build\native\Debug",
    [string]$Win32BuildDir = "build\native-win32\Debug"
)

$ErrorActionPreference = "Stop"

function Wait-SampleReady {
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

function Invoke-AttachSmoke {
    param(
        [string]$HelperPath,
        [string]$SamplePath,
        [string]$Architecture
    )

    if (-not (Test-Path -LiteralPath $HelperPath))
    {
        throw "Helper not found: $HelperPath"
    }

    if (-not (Test-Path -LiteralPath $SamplePath))
    {
        throw "Sample target not found: $SamplePath"
    }

    $tmpDir = Join-Path (Get-Location) ".tmp"
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
    $stdoutPath = Join-Path $tmpDir "attach-$Architecture.stdout.txt"
    $stderrPath = Join-Path $tmpDir "attach-$Architecture.stderr.txt"
    Remove-Item -Force -ErrorAction SilentlyContinue $stdoutPath,$stderrPath

    $sample = Start-Process -FilePath $SamplePath -ArgumentList "--attach-loop --iterations 24 --delay-ms 150" -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru -WindowStyle Hidden

    try
    {
        Wait-SampleReady -OutputPath $stdoutPath
        $json = & $HelperPath attach-capture --pid $sample.Id --duration-ms 2000 | ConvertFrom-Json

        if (-not $json.success)
        {
            throw "$Architecture attach-capture failed: $($json.operation): $($json.message)"
        }

        if ($json.captureMode -ne "bounded-native-attach")
        {
            throw "$Architecture attach capture mode mismatch: $($json.captureMode)"
        }

        if ($json.injectionMethod -ne "remote LoadLibraryW")
        {
            throw "$Architecture attach injection method mismatch: $($json.injectionMethod)"
        }

        if ($json.detachPolicy -ne "self-disable-no-unload")
        {
            throw "$Architecture attach detach policy mismatch: $($json.detachPolicy)"
        }

        if ($json.attachProcessId -ne $sample.Id -or $json.targetProcessId -ne $sample.Id)
        {
            throw "$Architecture attach PID mismatch: attach=$($json.attachProcessId) target=$($json.targetProcessId) sample=$($sample.Id)"
        }

        if ($json.architecture -ne $Architecture)
        {
            throw "$Architecture attach architecture mismatch: $($json.architecture)"
        }

        if ($json.transportMode -ne "shared-memory")
        {
            throw "$Architecture attach transport mode mismatch: $($json.transportMode)"
        }

        if ($json.transportDroppedEvents -ne 0 -or $json.droppedEvents -ne 0)
        {
            throw "$Architecture attach reported dropped events: dropped=$($json.droppedEvents) transport=$($json.transportDroppedEvents)"
        }

        if (-not $json.handshake.received -or $json.handshake.operationId -ne $json.operationId -or $json.handshake.architecture -ne $Architecture)
        {
            throw "$Architecture attach handshake mismatch."
        }

        $requiredApis = @("CreateFileW", "CreateFileA", "NtCreateFile", "ReadFile", "WriteFile", "CloseHandle")
        $capturedApis = @($json.capturedEvents | ForEach-Object { $_.api } | Sort-Object -Unique)
        foreach ($api in $requiredApis)
        {
            if ($capturedApis -notcontains $api)
            {
                throw "$Architecture attach missing required API: $api"
            }
        }

        $shutdown = @($json.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
        if ($shutdown.Count -ne 1)
        {
            throw "$Architecture attach did not receive agent_shutdown."
        }

        if ($shutdown[0].reason -ne "self_disable")
        {
            throw "$Architecture attach shutdown reason mismatch: $($shutdown[0].reason)"
        }

        if ($shutdown[0].restoredHooks -lt $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
        {
            throw "$Architecture attach hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
        }

        $auditTypes = @($json.auditEvents | ForEach-Object { $_.eventType })
        foreach ($eventType in @("attach_preflight_started", "attach_preflight_passed", "target_process_opened", "attach_transport_created", "remote_loadlibrary_started", "remote_loadlibrary_completed", "remote_agent_initialize_started", "remote_agent_initialize_completed", "agent_stop_requested", "agent_self_disabled", "attach_cleanup_completed"))
        {
            if ($auditTypes -notcontains $eventType)
            {
                throw "$Architecture attach audit event missing: $eventType"
            }
        }

        $namedPipeApiEvents = @($json.auditEvents | Where-Object { $_.eventType -eq "api_call_received" -and $_.operation -eq "agent_event_read" })
        if ($namedPipeApiEvents.Count -ne 0)
        {
            throw "$Architecture attach appears to have received API JSON through the named pipe."
        }

        if (-not $sample.HasExited)
        {
            $sample.WaitForExit(5000) | Out-Null
        }

        Write-Host "$Architecture controlled attach smoke passed: events=$($json.capturedEvents.Count) hooks=$($shutdown[0].installedHooks) overheadAvgUs=$($json.hookOverheadAvgUs)"
    }
    finally
    {
        if ($sample -ne $null -and -not $sample.HasExited)
        {
            Stop-Process -Id $sample.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

Invoke-AttachSmoke -HelperPath (Join-Path $BuildDir "knmon-native-helper.exe") -SamplePath (Join-Path $BuildDir "knmon-sample-fileio.exe") -Architecture "x64"

$win32Helper = Join-Path $Win32BuildDir "knmon-native-helper.exe"
$win32Sample = Join-Path $Win32BuildDir "knmon-sample-fileio.exe"
if ((Test-Path -LiteralPath $win32Helper) -and (Test-Path -LiteralPath $win32Sample))
{
    Invoke-AttachSmoke -HelperPath $win32Helper -SamplePath $win32Sample -Architecture "x86"
}
else
{
    Write-Host "Win32 attach smoke skipped: build/native-win32/Debug helper or sample not found."
}
