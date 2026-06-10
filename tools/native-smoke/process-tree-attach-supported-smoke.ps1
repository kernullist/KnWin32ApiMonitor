param(
    [string]$BuildDir = "build\native\Debug",
    [string]$Win32BuildDir = "build\native-win32\Debug"
)

$ErrorActionPreference = "Stop"

function Stop-ProcessTree {
    param([int]$ProcessId)

    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$ProcessId" -ErrorAction SilentlyContinue)
    foreach ($child in $children)
    {
        Stop-ProcessTree -ProcessId ([int]$child.ProcessId)
    }

    Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
}

function Wait-RootReady {
    param(
        [string]$OutputPath,
        [int]$TimeoutMs = 5000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline)
    {
        if ((Test-Path -LiteralPath $OutputPath) -and ((Get-Content -LiteralPath $OutputPath -Raw -ErrorAction SilentlyContinue) -match "tree-root-ready"))
        {
            return
        }

        Start-Sleep -Milliseconds 100
    }

    throw "Sample root did not report tree-root-ready."
}

function Invoke-AttachSupportedSmoke {
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
        throw "Sample not found: $SamplePath"
    }

    $tmpDir = Join-Path (Get-Location) ".tmp"
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
    $stdoutPath = Join-Path $tmpDir "tree-attach-$Architecture.stdout.txt"
    $stderrPath = Join-Path $tmpDir "tree-attach-$Architecture.stderr.txt"
    Remove-Item -Force -ErrorAction SilentlyContinue $stdoutPath,$stderrPath

    $root = Start-Process -FilePath $SamplePath -ArgumentList "--spawn-child-loop --children 1 --child-iterations 80 --delay-ms 150" -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru -WindowStyle Hidden

    try
    {
        Wait-RootReady -OutputPath $stdoutPath
        $json = & $HelperPath supervise-tree --pid $root.Id --duration-ms 5000 --child-policy attach-supported | ConvertFrom-Json

        if (-not $json.success)
        {
            throw "$Architecture attach-supported supervise-tree failed: $($json.operation): $($json.message)"
        }

        if ($json.childPolicy -ne "attach-supported")
        {
            throw "$Architecture child policy mismatch: $($json.childPolicy)"
        }

        $sampleChildren = @($json.processNodes | Where-Object { -not $_.isRoot -and $_.parentProcessId -eq $root.Id -and $_.imageName -eq "knmon-sample-fileio.exe" -and $_.architecture -eq $Architecture })
        if ($sampleChildren.Count -lt 1)
        {
            throw "$Architecture did not discover an attachable sample child."
        }

        $sampleChild = $sampleChildren[0]
        $decision = @($json.policyDecisions | Where-Object { $_.processId -eq $sampleChild.processId } | Select-Object -First 1)
        if ($decision.Count -ne 1)
        {
            throw "$Architecture missing attach-supported decision."
        }

        if ($decision[0].eligibilityStatus -ne "eligible" -or $decision[0].decision -ne "attach_allowed" -or -not $decision[0].mutationAttempted -or -not $decision[0].attachSucceeded)
        {
            throw "$Architecture attach-supported decision mismatch: eligibility=$($decision[0].eligibilityStatus) decision=$($decision[0].decision) mutation=$($decision[0].mutationAttempted) success=$($decision[0].attachSucceeded)"
        }

        $attachResults = @($json.childAttachResults | Where-Object { $_.success -and $_.targetProcessId -eq $sampleChild.processId -and $_.captureMode -eq "bounded-native-attach" })
        if ($attachResults.Count -lt 1)
        {
            throw "$Architecture missing successful child attach result."
        }

        $attach = $attachResults[0]
        if ($attach.injectionMethod -ne "remote LoadLibraryW" -or $attach.detachPolicy -ne "self-disable-no-unload")
        {
            throw "$Architecture child attach method/detach mismatch."
        }

        if ($attach.transportDroppedEvents -ne 0 -or $attach.droppedEvents -ne 0)
        {
            throw "$Architecture child attach reported dropped events."
        }

        $requiredApis = @("CreateFileW", "CreateFileA", "NtCreateFile", "ReadFile", "WriteFile", "CloseHandle")
        $capturedApis = @($attach.capturedEvents | ForEach-Object { $_.api } | Sort-Object -Unique)
        foreach ($api in $requiredApis)
        {
            if ($capturedApis -notcontains $api)
            {
                throw "$Architecture child attach missing required API: $api"
            }
        }

        $shutdown = @($attach.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
        if ($shutdown.Count -ne 1)
        {
            throw "$Architecture child attach did not receive agent_shutdown."
        }

        if ($shutdown[0].reason -ne "self_disable" -or $shutdown[0].restoredHooks -lt $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
        {
            throw "$Architecture child attach shutdown evidence mismatch."
        }

        $auditTypes = @($json.auditEvents | ForEach-Object { $_.eventType })
        foreach ($eventType in @("child_attach_started", "child_attach_completed", "process_tree_supervision_completed"))
        {
            if ($auditTypes -notcontains $eventType)
            {
                throw "$Architecture attach-supported missing audit event: $eventType"
            }
        }

        Write-Host "$Architecture process-tree attach-supported smoke passed: child=$($sampleChild.processId) events=$($attach.capturedEvents.Count)"
    }
    finally
    {
        if ($root -ne $null)
        {
            Stop-ProcessTree -ProcessId $root.Id
        }
    }
}

function Invoke-AttachSupportedSmokeWithRetry
{
    param(
        [string]$HelperPath,
        [string]$SamplePath,
        [string]$Architecture,
        [int]$Attempts = 3
    )

    $lastError = $null
    for ($attempt = 1; $attempt -le $Attempts; ++$attempt)
    {
        try
        {
            Invoke-AttachSupportedSmoke -HelperPath $HelperPath -SamplePath $SamplePath -Architecture $Architecture
            return
        }
        catch
        {
            $lastError = $_
            Write-Host "$Architecture process-tree attach-supported attempt $attempt failed: $($_.Exception.Message)"
        }
    }

    throw $lastError
}

Invoke-AttachSupportedSmokeWithRetry -HelperPath (Join-Path $BuildDir "knmon-native-helper.exe") -SamplePath (Join-Path $BuildDir "knmon-sample-fileio.exe") -Architecture "x64"

$win32Helper = Join-Path $Win32BuildDir "knmon-native-helper.exe"
$win32Sample = Join-Path $Win32BuildDir "knmon-sample-fileio.exe"
if ((Test-Path -LiteralPath $win32Helper) -and (Test-Path -LiteralPath $win32Sample))
{
    Invoke-AttachSupportedSmokeWithRetry -HelperPath $win32Helper -SamplePath $win32Sample -Architecture "x86"
}
else
{
    Write-Host "Win32 process-tree attach-supported smoke skipped: build/native-win32/Debug helper or sample not found."
}

Write-Host "Process-tree attach-supported smoke passed."
