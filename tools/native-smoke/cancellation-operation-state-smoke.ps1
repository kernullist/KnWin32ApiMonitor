param(
    [string]$BuildDir = "build\native\Debug"
)

$ErrorActionPreference = "Stop"

function New-SmokeOperationId
{
    param(
        [string]$Prefix
    )

    return "$Prefix-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
}

function Wait-SampleReady
{
    param(
        [string]$OutputPath,
        [int]$TimeoutMs = 5000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline)
    {
        if ((Test-Path -LiteralPath $OutputPath) -and ((Get-Content -LiteralPath $OutputPath -Raw -ErrorAction SilentlyContinue) -match "attach-loop-ready|root-ready"))
        {
            return
        }

        Start-Sleep -Milliseconds 100
    }

    throw "Sample target did not report ready state."
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

function Assert-CancelledAttachResult
{
    param(
        [object]$Result,
        [int]$ProcessId
    )

    if ($Result.success)
    {
        throw "Cancelled attach unexpectedly succeeded."
    }

    if ($Result.operation -ne "operation_cancelled" -or $Result.operationState -ne "cancelled")
    {
        throw "Cancelled attach state mismatch: operation=$($Result.operation) state=$($Result.operationState)"
    }

    if (-not $Result.cancelObserved -or $Result.win32ErrorCode -ne 1223)
    {
        throw "Cancelled attach did not report ERROR_CANCELLED evidence."
    }

    if (-not $Result.agentCleanupAttempted -or -not $Result.agentCleanupSucceeded)
    {
        throw "Cancelled attach did not prove cleanup success."
    }

    if ($Result.targetProcessId -ne $ProcessId)
    {
        throw "Cancelled attach target PID mismatch."
    }

    $shutdown = @($Result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
    if ($shutdown.Count -ne 1)
    {
        throw "Cancelled attach did not receive agent_shutdown."
    }

    if ($shutdown[0].reason -ne "self_disable")
    {
        throw "Cancelled attach shutdown reason mismatch: $($shutdown[0].reason)"
    }

    if ($shutdown[0].restoredHooks -lt $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
    {
        throw "Cancelled attach hook lifecycle mismatch."
    }
}

function Assert-ReattachAfterCancel
{
    param(
        [object]$Result,
        [int]$ProcessId
    )

    if (-not $Result.success)
    {
        throw "Post-cancel attach failed: $($Result.operation): $($Result.message)"
    }

    if ($Result.attachState -ne "loaded_disabled" -or $Result.attachStrategy -ne "loaded_agent_reinitialize" -or -not $Result.loadedAgentDetected)
    {
        throw "Post-cancel attach did not use loaded-agent reinitialize."
    }

    if ($Result.targetProcessId -ne $ProcessId)
    {
        throw "Post-cancel attach target PID mismatch."
    }

    $auditTypes = @($Result.auditEvents | ForEach-Object { $_.eventType })
    if ($auditTypes -contains "remote_loadlibrary_started")
    {
        throw "Post-cancel attach unexpectedly used LoadLibraryW."
    }
}

function Invoke-AttachCancellationSmoke
{
    param(
        [string]$HelperPath,
        [string]$SamplePath
    )

    $tmpDir = Join-Path (Get-Location) ".tmp"
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
    $sampleStdout = Join-Path $tmpDir "cancel-attach.sample.stdout.txt"
    $sampleStderr = Join-Path $tmpDir "cancel-attach.sample.stderr.txt"
    $helperStdout = Join-Path $tmpDir "cancel-attach.helper.stdout.txt"
    $helperStderr = Join-Path $tmpDir "cancel-attach.helper.stderr.txt"
    Remove-Item -Force -ErrorAction SilentlyContinue $sampleStdout,$sampleStderr,$helperStdout,$helperStderr

    $sample = Start-Process -FilePath $SamplePath -ArgumentList "--attach-loop --iterations 500 --delay-ms 100" -RedirectStandardOutput $sampleStdout -RedirectStandardError $sampleStderr -PassThru -WindowStyle Hidden
    $helper = $null

    try
    {
        Wait-SampleReady -OutputPath $sampleStdout
        $operationId = New-SmokeOperationId -Prefix "cancel-attach"
        $helper = Start-Process -FilePath $HelperPath -ArgumentList @("attach-capture", "--pid", "$($sample.Id)", "--duration-ms", "12000", "--timeout-ms", "15000", "--operation-id", $operationId) -RedirectStandardOutput $helperStdout -RedirectStandardError $helperStderr -PassThru -WindowStyle Hidden

        Wait-AgentModuleLoaded -ProcessId $sample.Id -ModuleName "knmon-agent64.dll"
        Start-Sleep -Milliseconds 800
        Invoke-CancelOperation -HelperPath $HelperPath -OperationId $operationId | Out-Null

        if (-not $helper.WaitForExit(25000))
        {
            throw "Attach helper did not exit after cancellation."
        }

        $cancelled = Get-Content -LiteralPath $helperStdout -Raw | ConvertFrom-Json
        Assert-CancelledAttachResult -Result $cancelled -ProcessId $sample.Id

        $reattach = & $HelperPath attach-capture --pid $sample.Id --duration-ms 1500 --timeout-ms 15000 | ConvertFrom-Json
        Assert-ReattachAfterCancel -Result $reattach -ProcessId $sample.Id

        Write-Host "x64 attach cancellation smoke passed: events=$($cancelled.capturedEvents.Count) reattach=$($reattach.attachStrategy)"
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
}

function Invoke-ProcessTreeCancellationSmoke
{
    param(
        [string]$HelperPath,
        [string]$SamplePath
    )

    $tmpDir = Join-Path (Get-Location) ".tmp"
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
    $rootStdout = Join-Path $tmpDir "cancel-tree.root.stdout.txt"
    $rootStderr = Join-Path $tmpDir "cancel-tree.root.stderr.txt"
    $helperStdout = Join-Path $tmpDir "cancel-tree.helper.stdout.txt"
    $helperStderr = Join-Path $tmpDir "cancel-tree.helper.stderr.txt"
    Remove-Item -Force -ErrorAction SilentlyContinue $rootStdout,$rootStderr,$helperStdout,$helperStderr

    $root = Start-Process -FilePath $SamplePath -ArgumentList "--spawn-child-loop --children 1 --child-iterations 120 --delay-ms 150" -RedirectStandardOutput $rootStdout -RedirectStandardError $rootStderr -PassThru -WindowStyle Hidden
    $helper = $null

    try
    {
        Wait-SampleReady -OutputPath $rootStdout
        $operationId = New-SmokeOperationId -Prefix "cancel-tree"
        $helper = Start-Process -FilePath $HelperPath -ArgumentList @("supervise-tree", "--pid", "$($root.Id)", "--duration-ms", "10000", "--timeout-ms", "15000", "--child-policy", "observe", "--operation-id", $operationId) -RedirectStandardOutput $helperStdout -RedirectStandardError $helperStderr -PassThru -WindowStyle Hidden

        Start-Sleep -Milliseconds 800
        Invoke-CancelOperation -HelperPath $HelperPath -OperationId $operationId | Out-Null

        if (-not $helper.WaitForExit(20000))
        {
            throw "Process-tree helper did not exit after cancellation."
        }

        $cancelled = Get-Content -LiteralPath $helperStdout -Raw | ConvertFrom-Json
        if ($cancelled.success -or $cancelled.operation -ne "operation_cancelled" -or $cancelled.operationState -ne "cancelled")
        {
            throw "Process-tree cancellation state mismatch: success=$($cancelled.success) operation=$($cancelled.operation) state=$($cancelled.operationState)"
        }

        if (-not $cancelled.cancelObserved -or $cancelled.win32ErrorCode -ne 1223)
        {
            throw "Process-tree cancellation did not report ERROR_CANCELLED evidence."
        }

        if (@($cancelled.childAttachResults).Count -ne 0)
        {
            throw "Observe policy cancellation unexpectedly produced child attach results."
        }

        Write-Host "x64 process-tree cancellation smoke passed: nodes=$(@($cancelled.processNodes).Count) stage=$($cancelled.cancelStage)"
    }
    finally
    {
        if ($helper -ne $null -and -not $helper.HasExited)
        {
            Stop-Process -Id $helper.Id -Force -ErrorAction SilentlyContinue
        }

        if ($root -ne $null -and -not $root.HasExited)
        {
            Stop-Process -Id $root.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

$helperPath = Join-Path $BuildDir "knmon-native-helper.exe"
$samplePath = Join-Path $BuildDir "knmon-sample-fileio.exe"

Invoke-AttachCancellationSmoke -HelperPath $helperPath -SamplePath $samplePath
Invoke-ProcessTreeCancellationSmoke -HelperPath $helperPath -SamplePath $samplePath
