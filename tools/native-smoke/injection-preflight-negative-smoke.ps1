param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe",
    [string]$X86BuildDir = "build\native-win32\Debug"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $HelperPath))
{
    throw "Helper not found: $HelperPath"
}

function Invoke-ExpectedPreflightFailure
{
    param(
        [string[]]$Arguments,
        [string]$ExpectedOperation,
        [string]$Name
    )

    $result = & $HelperPath @Arguments | ConvertFrom-Json

    if ($result.success)
    {
        throw "$Name unexpectedly succeeded."
    }

    if ($result.operation -ne $ExpectedOperation)
    {
        throw "$Name operation mismatch: expected $ExpectedOperation got $($result.operation). Message: $($result.message)"
    }

    $preflight = @($result.auditEvents | Where-Object { $_.eventType -eq "preflight_failed" })
    if ($preflight.Count -lt 1)
    {
        throw "$Name did not include preflight_failed audit event."
    }

    $mutationEvents = @(
        "process_created_suspended",
        "agent_path_written",
        "early_bird_apc_queued",
        "primary_thread_resumed"
    )

    foreach ($eventType in $mutationEvents)
    {
        $matches = @($result.auditEvents | Where-Object { $_.eventType -eq $eventType })
        if ($matches.Count -gt 0)
        {
            throw "$Name performed remote mutation before preflight failure: $eventType"
        }
    }

    Write-Host "$Name preflight failure passed: operation=$($result.operation) message=$($result.message)"
}

$missingTarget = Join-Path ([System.IO.Path]::GetTempPath()) "knmon-missing-target-do-not-create.exe"
$missingAgent = Join-Path ([System.IO.Path]::GetTempPath()) "knmon-missing-agent-do-not-create.dll"

Invoke-ExpectedPreflightFailure -Name "missing-target" -ExpectedOperation "missing_target" -Arguments @("capture-sample", "--target", $missingTarget)
Invoke-ExpectedPreflightFailure -Name "missing-agent" -ExpectedOperation "missing_agent" -Arguments @("capture-sample", "--agent", $missingAgent)

$x86Agent = Join-Path $X86BuildDir "knmon-agent32.dll"
if (Test-Path -LiteralPath $x86Agent)
{
    Invoke-ExpectedPreflightFailure -Name "architecture-mismatch" -ExpectedOperation "helper_agent_mismatch" -Arguments @("capture-sample", "--agent", $x86Agent)
}
else
{
    Write-Host "architecture-mismatch skipped: x86 agent not found at $x86Agent"
}

Write-Host "Injection preflight negative smoke passed."
