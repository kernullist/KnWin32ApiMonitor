param(
    [string]$BuildDir = "build\native\Debug",
    [string]$Win32BuildDir = "build\native-win32\Debug"
)

$ErrorActionPreference = "Stop"

function Invoke-ExpectAttachFailure {
    param(
        [string]$HelperPath,
        [string[]]$Arguments,
        [string[]]$ExpectedOperations,
        [string]$Label
    )

    if (-not (Test-Path -LiteralPath $HelperPath))
    {
        throw "Helper not found for ${Label}: $HelperPath"
    }

    $result = & $HelperPath @Arguments | ConvertFrom-Json
    if ($result.success)
    {
        throw "${Label}: expected attach-capture failure but command succeeded."
    }

    if ($ExpectedOperations -notcontains $result.operation)
    {
        throw "${Label}: operation mismatch. expected=$($ExpectedOperations -join ',') actual=$($result.operation) message=$($result.message)"
    }

    $remoteMutationEvents = @(
        "remote_agent_path_allocated",
        "remote_agent_path_written",
        "remote_config_allocated",
        "remote_config_written",
        "remote_loadlibrary_started",
        "remote_agent_initialize_started"
    )

    $auditTypes = @($result.auditEvents | ForEach-Object { $_.eventType })
    foreach ($eventType in $remoteMutationEvents)
    {
        if ($auditTypes -contains $eventType)
        {
            throw "${Label}: preflight failure unexpectedly reached remote mutation event $eventType."
        }
    }

    if ($auditTypes -notcontains "attach_preflight_failed")
    {
        throw "${Label}: attach_preflight_failed audit event missing."
    }

    return $result
}

function Start-AttachSample {
    param(
        [string]$SamplePath,
        [string]$Label
    )

    $tmpDir = Join-Path (Get-Location) ".tmp"
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
    $stdoutPath = Join-Path $tmpDir "attach-negative-$Label.stdout.txt"
    $stderrPath = Join-Path $tmpDir "attach-negative-$Label.stderr.txt"
    Remove-Item -Force -ErrorAction SilentlyContinue $stdoutPath,$stderrPath

    $process = Start-Process -FilePath $SamplePath -ArgumentList "--attach-loop --iterations 40 --delay-ms 200" -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 600
    return $process
}

$helper = Join-Path $BuildDir "knmon-native-helper.exe"
$samplePath = Join-Path $BuildDir "knmon-sample-fileio.exe"
$agentPath = Join-Path $BuildDir "knmon-agent64.dll"
$missingAgent = Join-Path (Get-Location) ".tmp\missing-knmon-agent.dll"

if (-not (Test-Path -LiteralPath $samplePath))
{
    throw "Sample target not found: $samplePath"
}

Invoke-ExpectAttachFailure -HelperPath $helper -Arguments @("attach-capture", "--pid", "4294967295") -ExpectedOperations @("missing_target_process") -Label "missing-pid" | Out-Null
Invoke-ExpectAttachFailure -HelperPath $helper -Arguments @("attach-capture", "--pid", "0") -ExpectedOperations @("missing_target_process") -Label "pid-zero" | Out-Null
Invoke-ExpectAttachFailure -HelperPath $helper -Arguments @("attach-capture", "--pid", "4") -ExpectedOperations @("missing_target_process") -Label "pid-four" | Out-Null
Invoke-ExpectAttachFailure -HelperPath $helper -Arguments @("attach-capture", "--pid", "self") -ExpectedOperations @("missing_target_process") -Label "helper-self" | Out-Null

$sample = $null
try
{
    $sample = Start-AttachSample -SamplePath $samplePath -Label "x64"
    Invoke-ExpectAttachFailure -HelperPath $helper -Arguments @("attach-capture", "--pid", "$($sample.Id)", "--agent", $missingAgent) -ExpectedOperations @("missing_agent") -Label "missing-agent" | Out-Null

    $win32Agent = Join-Path $Win32BuildDir "knmon-agent32.dll"
    if (Test-Path -LiteralPath $win32Agent)
    {
        Invoke-ExpectAttachFailure -HelperPath $helper -Arguments @("attach-capture", "--pid", "$($sample.Id)", "--agent", $win32Agent) -ExpectedOperations @("helper_agent_mismatch") -Label "agent-arch-mismatch" | Out-Null
    }
}
finally
{
    if ($sample -ne $null -and -not $sample.HasExited)
    {
        Stop-Process -Id $sample.Id -Force -ErrorAction SilentlyContinue
    }
}

$win32Helper = Join-Path $Win32BuildDir "knmon-native-helper.exe"
$win32Sample = Join-Path $Win32BuildDir "knmon-sample-fileio.exe"
if ((Test-Path -LiteralPath $win32Helper) -and (Test-Path -LiteralPath $win32Sample) -and (Test-Path -LiteralPath $agentPath))
{
    $x86Sample = $null
    try
    {
        $x86Sample = Start-AttachSample -SamplePath $win32Sample -Label "x86"
        Invoke-ExpectAttachFailure -HelperPath $helper -Arguments @("attach-capture", "--pid", "$($x86Sample.Id)", "--agent", $agentPath) -ExpectedOperations @("helper_target_mismatch") -Label "cross-bitness-target" | Out-Null
    }
    finally
    {
        if ($x86Sample -ne $null -and -not $x86Sample.HasExited)
        {
            Stop-Process -Id $x86Sample.Id -Force -ErrorAction SilentlyContinue
        }
    }
}
else
{
    Write-Host "Cross-bitness negative attach smoke skipped: Win32 helper/sample or x64 agent not found."
}

Write-Host "Attach preflight negative smoke passed."
