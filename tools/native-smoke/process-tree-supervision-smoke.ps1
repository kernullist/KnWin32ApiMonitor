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

function Invoke-ExpectTreeFailure {
    param(
        [string]$HelperPath,
        [string[]]$Arguments,
        [string[]]$ExpectedOperations,
        [string]$Label
    )

    $json = & $HelperPath @Arguments | ConvertFrom-Json
    if ($json.success)
    {
        throw "$Label unexpectedly succeeded."
    }

    if ($ExpectedOperations -notcontains $json.operation)
    {
        throw "$Label operation mismatch: $($json.operation)"
    }

    $auditTypes = @($json.auditEvents | ForEach-Object { $_.eventType })
    if ($auditTypes -notcontains "process_tree_supervision_failed")
    {
        throw "$Label missing process_tree_supervision_failed audit event."
    }
}

function Invoke-ObserveSmoke {
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
    $stdoutPath = Join-Path $tmpDir "tree-observe-$Architecture.stdout.txt"
    $stderrPath = Join-Path $tmpDir "tree-observe-$Architecture.stderr.txt"
    Remove-Item -Force -ErrorAction SilentlyContinue $stdoutPath,$stderrPath

    $root = Start-Process -FilePath $SamplePath -ArgumentList "--spawn-child-loop --children 1 --child-iterations 40 --delay-ms 150" -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru -WindowStyle Hidden

    try
    {
        Wait-RootReady -OutputPath $stdoutPath
        $json = & $HelperPath supervise-tree --pid $root.Id --duration-ms 2500 --child-policy observe | ConvertFrom-Json

        if (-not $json.success)
        {
            throw "$Architecture observe supervise-tree failed: $($json.operation): $($json.message)"
        }

        if ($json.rootProcessId -ne $root.Id)
        {
            throw "$Architecture root PID mismatch: $($json.rootProcessId) != $($root.Id)"
        }

        if ($json.childPolicy -ne "observe")
        {
            throw "$Architecture child policy mismatch: $($json.childPolicy)"
        }

        $sampleChildren = @($json.processNodes | Where-Object { -not $_.isRoot -and $_.parentProcessId -eq $root.Id -and $_.imageName -eq "knmon-sample-fileio.exe" })
        if ($sampleChildren.Count -lt 1)
        {
            throw "$Architecture did not discover a repository sample child."
        }

        $sampleChild = $sampleChildren[0]
        if ($sampleChild.architecture -ne $Architecture)
        {
            throw "$Architecture child architecture mismatch: $($sampleChild.architecture)"
        }

        if ($sampleChild.eligibilityStatus -ne "eligible" -or $sampleChild.policyDecision -ne "observe_only")
        {
            throw "$Architecture child policy mismatch: eligibility=$($sampleChild.eligibilityStatus) decision=$($sampleChild.policyDecision)"
        }

        $decision = @($json.policyDecisions | Where-Object { $_.processId -eq $sampleChild.processId } | Select-Object -First 1)
        if ($decision.Count -ne 1)
        {
            throw "$Architecture missing policy decision for sample child."
        }

        if ($decision[0].decision -ne "observe_only" -or $decision[0].mutationAttempted)
        {
            throw "$Architecture observe policy attempted mutation or wrong decision."
        }

        if (@($json.childAttachResults).Count -ne 0)
        {
            throw "$Architecture observe policy produced child attach results."
        }

        $auditTypes = @($json.auditEvents | ForEach-Object { $_.eventType })
        foreach ($eventType in @("process_tree_supervision_started", "root_process_validated", "process_snapshot_taken", "child_process_discovered", "child_policy_evaluated", "process_tree_supervision_completed"))
        {
            if ($auditTypes -notcontains $eventType)
            {
                throw "$Architecture observe missing audit event: $eventType"
            }
        }

        if ($auditTypes -contains "child_attach_started")
        {
            throw "$Architecture observe policy emitted child_attach_started."
        }

        Write-Host "$Architecture process-tree observe smoke passed: nodes=$($json.processNodes.Count) child=$($sampleChild.processId)"
    }
    finally
    {
        if ($root -ne $null)
        {
            Stop-ProcessTree -ProcessId $root.Id
        }
    }
}

function Invoke-CrossBitnessChildSkip {
    param(
        [string]$HelperPath,
        [string]$RootSamplePath,
        [string]$ChildSamplePath
    )

    $tmpDir = Join-Path (Get-Location) ".tmp"
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
    $stdoutPath = Join-Path $tmpDir "tree-cross-bitness.stdout.txt"
    $stderrPath = Join-Path $tmpDir "tree-cross-bitness.stderr.txt"
    Remove-Item -Force -ErrorAction SilentlyContinue $stdoutPath,$stderrPath

    $arguments = "--spawn-child-loop --children 1 --child-iterations 40 --delay-ms 150 --child-path `"$ChildSamplePath`""
    $root = Start-Process -FilePath $RootSamplePath -ArgumentList $arguments -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru -WindowStyle Hidden

    try
    {
        Wait-RootReady -OutputPath $stdoutPath
        $json = & $HelperPath supervise-tree --pid $root.Id --duration-ms 2500 --child-policy attach-supported | ConvertFrom-Json

        if (-not $json.success)
        {
            throw "cross-bitness child supervision failed: $($json.operation): $($json.message)"
        }

        $x86Children = @($json.processNodes | Where-Object { -not $_.isRoot -and $_.parentProcessId -eq $root.Id -and $_.imageName -eq "knmon-sample-fileio.exe" -and $_.architecture -eq "x86" })
        if ($x86Children.Count -lt 1)
        {
            throw "cross-bitness child was not discovered as x86."
        }

        $decision = @($json.policyDecisions | Where-Object { $_.processId -eq $x86Children[0].processId } | Select-Object -First 1)
        if ($decision.Count -ne 1)
        {
            throw "cross-bitness child decision is missing."
        }

        if ($decision[0].eligibilityStatus -ne "helper_target_mismatch" -or $decision[0].mutationAttempted)
        {
            throw "cross-bitness child was not skipped before mutation."
        }

        Write-Host "Cross-bitness child skip smoke passed: child=$($x86Children[0].processId)"
    }
    finally
    {
        if ($root -ne $null)
        {
            Stop-ProcessTree -ProcessId $root.Id
        }
    }
}

$helper = Join-Path $BuildDir "knmon-native-helper.exe"
$sample = Join-Path $BuildDir "knmon-sample-fileio.exe"
Invoke-ObserveSmoke -HelperPath $helper -SamplePath $sample -Architecture "x64"

Invoke-ExpectTreeFailure -HelperPath $helper -Arguments @("supervise-tree", "--pid", "4294967295") -ExpectedOperations @("missing_root_process") -Label "missing-root"
Invoke-ExpectTreeFailure -HelperPath $helper -Arguments @("supervise-tree", "--pid", "0") -ExpectedOperations @("missing_root_process") -Label "pid-zero"
Invoke-ExpectTreeFailure -HelperPath $helper -Arguments @("supervise-tree", "--pid", "4") -ExpectedOperations @("missing_root_process") -Label "pid-four"
Invoke-ExpectTreeFailure -HelperPath $helper -Arguments @("supervise-tree", "--pid", "self") -ExpectedOperations @("missing_root_process") -Label "helper-self"

$win32Helper = Join-Path $Win32BuildDir "knmon-native-helper.exe"
$win32Sample = Join-Path $Win32BuildDir "knmon-sample-fileio.exe"
if ((Test-Path -LiteralPath $win32Helper) -and (Test-Path -LiteralPath $win32Sample))
{
    Invoke-ObserveSmoke -HelperPath $win32Helper -SamplePath $win32Sample -Architecture "x86"
    Invoke-CrossBitnessChildSkip -HelperPath $helper -RootSamplePath $sample -ChildSamplePath $win32Sample
}
else
{
    Write-Host "Win32 process-tree observe smoke skipped: build/native-win32/Debug helper or sample not found."
}

Write-Host "Process-tree supervision smoke passed."
