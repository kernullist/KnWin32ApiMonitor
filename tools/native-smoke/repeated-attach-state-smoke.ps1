param(
    [string]$BuildDir = "build\native\Debug",
    [string]$Win32BuildDir = "build\native-win32\Debug"
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
        [int]$TimeoutMs = 5000
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

function Assert-RequiredAttachEvidence
{
    param(
        [object]$Result,
        [int]$ProcessId,
        [string]$Architecture,
        [string]$ExpectedState,
        [string]$ExpectedStrategy,
        [bool]$ExpectedLoaded
    )

    if (-not $Result.success)
    {
        throw "$Architecture attach failed: $($Result.operation): $($Result.message)"
    }

    if ($Result.captureMode -ne "bounded-native-attach")
    {
        throw "$Architecture attach capture mode mismatch: $($Result.captureMode)"
    }

    if ($Result.detachPolicy -ne "self-disable-no-unload")
    {
        throw "$Architecture attach detach policy mismatch: $($Result.detachPolicy)"
    }

    if ($Result.attachProcessId -ne $ProcessId -or $Result.targetProcessId -ne $ProcessId)
    {
        throw "$Architecture attach PID mismatch: attach=$($Result.attachProcessId) target=$($Result.targetProcessId) sample=$ProcessId"
    }

    if ($Result.architecture -ne $Architecture)
    {
        throw "$Architecture attach architecture mismatch: $($Result.architecture)"
    }

    if ($Result.attachState -ne $ExpectedState)
    {
        throw "$Architecture attach state mismatch: expected=$ExpectedState actual=$($Result.attachState)"
    }

    if ($Result.attachStrategy -ne $ExpectedStrategy)
    {
        throw "$Architecture attach strategy mismatch: expected=$ExpectedStrategy actual=$($Result.attachStrategy)"
    }

    if ([bool]$Result.loadedAgentDetected -ne $ExpectedLoaded)
    {
        throw "$Architecture loaded-agent detection mismatch: expected=$ExpectedLoaded actual=$($Result.loadedAgentDetected)"
    }

    if ($ExpectedLoaded -and ([uint64]$Result.loadedAgentModuleBase -eq 0 -or [string]::IsNullOrWhiteSpace([string]$Result.loadedAgentPath)))
    {
        throw "$Architecture loaded-agent evidence is incomplete."
    }

    if ($Result.transportMode -ne "shared-memory")
    {
        throw "$Architecture attach transport mode mismatch: $($Result.transportMode)"
    }

    if ($Result.transportDroppedEvents -ne 0 -or $Result.droppedEvents -ne 0)
    {
        throw "$Architecture attach reported dropped events: dropped=$($Result.droppedEvents) transport=$($Result.transportDroppedEvents)"
    }

    if (-not $Result.handshake.received -or $Result.handshake.operationId -ne $Result.operationId -or $Result.handshake.architecture -ne $Architecture)
    {
        throw "$Architecture attach handshake mismatch."
    }

    $requiredApis = @("CreateFileW", "CreateFileA", "NtCreateFile", "ReadFile", "WriteFile", "CloseHandle")
    $capturedApis = @($Result.capturedEvents | ForEach-Object { $_.api } | Sort-Object -Unique)
    foreach ($api in $requiredApis)
    {
        if ($capturedApis -notcontains $api)
        {
            throw "$Architecture attach missing required API: $api"
        }
    }

    $shutdown = @($Result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
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
}

function Invoke-RepeatedAttachSmoke
{
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
    $stdoutPath = Join-Path $tmpDir "repeat-attach-$Architecture.stdout.txt"
    $stderrPath = Join-Path $tmpDir "repeat-attach-$Architecture.stderr.txt"
    Remove-Item -Force -ErrorAction SilentlyContinue $stdoutPath,$stderrPath

    $sample = Start-Process -FilePath $SamplePath -ArgumentList "--attach-loop --iterations 300 --delay-ms 100" -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru -WindowStyle Hidden

    try
    {
        Wait-SampleReady -OutputPath $stdoutPath

        $first = & $HelperPath attach-capture --pid $sample.Id --duration-ms 1500 --timeout-ms 15000 | ConvertFrom-Json
        Assert-RequiredAttachEvidence -Result $first -ProcessId $sample.Id -Architecture $Architecture -ExpectedState "not_loaded" -ExpectedStrategy "load_library_initialize" -ExpectedLoaded $false

        $second = & $HelperPath attach-capture --pid $sample.Id --duration-ms 1500 --timeout-ms 15000 | ConvertFrom-Json
        Assert-RequiredAttachEvidence -Result $second -ProcessId $sample.Id -Architecture $Architecture -ExpectedState "loaded_disabled" -ExpectedStrategy "loaded_agent_reinitialize" -ExpectedLoaded $true

        $firstAuditTypes = @($first.auditEvents | ForEach-Object { $_.eventType })
        if ($firstAuditTypes -notcontains "remote_loadlibrary_started" -or $firstAuditTypes -notcontains "remote_loadlibrary_completed")
        {
            throw "$Architecture first attach did not use LoadLibraryW evidence."
        }

        if ($firstAuditTypes -notcontains "agent_cleanup_verified")
        {
            throw "$Architecture first attach did not verify cleanup with agent state."
        }

        $secondAuditTypes = @($second.auditEvents | ForEach-Object { $_.eventType })
        if ($secondAuditTypes -contains "remote_loadlibrary_started" -or $secondAuditTypes -contains "remote_loadlibrary_completed")
        {
            throw "$Architecture loaded-agent reattach unexpectedly used LoadLibraryW."
        }

        if ($secondAuditTypes -notcontains "loaded_agent_detected" -or $secondAuditTypes -notcontains "loaded_agent_state_queried" -or $secondAuditTypes -notcontains "attach_strategy_selected")
        {
            throw "$Architecture loaded-agent reattach audit evidence is incomplete."
        }

        if ($secondAuditTypes -notcontains "agent_cleanup_verified")
        {
            throw "$Architecture loaded-agent reattach did not verify cleanup with agent state."
        }

        Write-Host "$Architecture repeated attach smoke passed: first=$($first.capturedEvents.Count) second=$($second.capturedEvents.Count) strategy=$($second.attachStrategy)"
    }
    finally
    {
        if ($sample -ne $null -and -not $sample.HasExited)
        {
            Stop-Process -Id $sample.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-ActiveRejectSmoke
{
    param(
        [string]$HelperPath,
        [string]$SamplePath
    )

    $tmpDir = Join-Path (Get-Location) ".tmp"
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
    $sampleStdout = Join-Path $tmpDir "repeat-active-x64.sample.stdout.txt"
    $sampleStderr = Join-Path $tmpDir "repeat-active-x64.sample.stderr.txt"
    $helperStdout = Join-Path $tmpDir "repeat-active-x64.helper.stdout.txt"
    $helperStderr = Join-Path $tmpDir "repeat-active-x64.helper.stderr.txt"
    Remove-Item -Force -ErrorAction SilentlyContinue $sampleStdout,$sampleStderr,$helperStdout,$helperStderr

    $sample = Start-Process -FilePath $SamplePath -ArgumentList "--attach-loop --iterations 300 --delay-ms 100" -RedirectStandardOutput $sampleStdout -RedirectStandardError $sampleStderr -PassThru -WindowStyle Hidden
    $firstHelper = $null

    try
    {
        Wait-SampleReady -OutputPath $sampleStdout
        $firstHelper = Start-Process -FilePath $HelperPath -ArgumentList @("attach-capture", "--pid", "$($sample.Id)", "--duration-ms", "6000", "--timeout-ms", "15000") -RedirectStandardOutput $helperStdout -RedirectStandardError $helperStderr -PassThru -WindowStyle Hidden
        Wait-AgentModuleLoaded -ProcessId $sample.Id -ModuleName "knmon-agent64.dll"

        $reject = & $HelperPath attach-capture --pid $sample.Id --duration-ms 500 --timeout-ms 5000 | ConvertFrom-Json
        if ($reject.success)
        {
            throw "Active repeated attach unexpectedly succeeded."
        }

        if (-not $reject.loadedAgentDetected)
        {
            throw "Active repeated attach did not detect the loaded agent."
        }

        if (@("loaded_active", "loaded_busy") -notcontains $reject.attachState)
        {
            throw "Active repeated attach state mismatch: $($reject.attachState)"
        }

        if ($reject.attachStrategy -ne "reject_already_active")
        {
            throw "Active repeated attach strategy mismatch: $($reject.attachStrategy)"
        }

        $rejectAuditTypes = @($reject.auditEvents | ForEach-Object { $_.eventType })
        if ($rejectAuditTypes -contains "remote_loadlibrary_started" -or $rejectAuditTypes -contains "attach_transport_created")
        {
            throw "Active repeated attach performed mutation or transport setup before rejecting."
        }

        if (-not $firstHelper.WaitForExit(20000))
        {
            throw "Primary active attach helper did not finish."
        }

        $first = Get-Content -LiteralPath $helperStdout -Raw | ConvertFrom-Json
        Assert-RequiredAttachEvidence -Result $first -ProcessId $sample.Id -Architecture "x64" -ExpectedState "not_loaded" -ExpectedStrategy "load_library_initialize" -ExpectedLoaded $false
        Write-Host "x64 active repeated attach reject smoke passed: state=$($reject.attachState)"
    }
    finally
    {
        if ($firstHelper -ne $null -and -not $firstHelper.HasExited)
        {
            Stop-Process -Id $firstHelper.Id -Force -ErrorAction SilentlyContinue
        }

        if ($sample -ne $null -and -not $sample.HasExited)
        {
            Stop-Process -Id $sample.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

Invoke-RepeatedAttachSmoke -HelperPath (Join-Path $BuildDir "knmon-native-helper.exe") -SamplePath (Join-Path $BuildDir "knmon-sample-fileio.exe") -Architecture "x64"

$win32Helper = Join-Path $Win32BuildDir "knmon-native-helper.exe"
$win32Sample = Join-Path $Win32BuildDir "knmon-sample-fileio.exe"
if ((Test-Path -LiteralPath $win32Helper) -and (Test-Path -LiteralPath $win32Sample))
{
    Invoke-RepeatedAttachSmoke -HelperPath $win32Helper -SamplePath $win32Sample -Architecture "x86"
}
else
{
    Write-Host "Win32 repeated attach smoke skipped: build/native-win32/Debug helper or sample not found."
}

Invoke-ActiveRejectSmoke -HelperPath (Join-Path $BuildDir "knmon-native-helper.exe") -SamplePath (Join-Path $BuildDir "knmon-sample-fileio.exe")
