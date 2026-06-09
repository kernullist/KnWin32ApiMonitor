param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$requiredApis = @(
    "CreateFileW",
    "CreateFileA",
    "NtCreateFile",
    "ReadFile",
    "WriteFile",
    "CloseHandle"
)

if (-not (Test-Path -LiteralPath $HelperPath))
{
    throw "Helper not found: $HelperPath"
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Shared-memory capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

if ($result.transportRecordsProduced -lt $requiredApis.Count)
{
    throw "Shared-memory transport produced too few records: $($result.transportRecordsProduced)"
}

if ($result.transportRecordsConsumed -ne $result.transportRecordsProduced)
{
    throw "Shared-memory consumed/produced mismatch: $($result.transportRecordsConsumed)/$($result.transportRecordsProduced)"
}

if ($result.transportDroppedEvents -ne 0 -or $result.droppedEvents -ne 0)
{
    throw "Healthy shared-memory capture reported drops: transport=$($result.transportDroppedEvents) result=$($result.droppedEvents)"
}

if ($result.hookOverheadMaxUs -le 0)
{
    throw "Hook overhead metric was not recorded."
}

$apis = @($result.capturedEvents | ForEach-Object { $_.api } | Sort-Object -Unique)
foreach ($api in $requiredApis)
{
    if ($apis -notcontains $api)
    {
        throw "Shared-memory capture missing API: $api"
    }
}

$ntEvents = @($result.capturedEvents | Where-Object { $_.api -eq "NtCreateFile" })
if ($ntEvents.Count -lt 1)
{
    throw "Shared-memory capture did not include NtCreateFile."
}

$ntEvent = $ntEvents[0]
if ($ntEvent.module -ne "ntdll.dll")
{
    throw "NtCreateFile module mismatch: $($ntEvent.module)"
}

if ($ntEvent.returnValue -notmatch "^0x[0-9a-fA-F]{8}$")
{
    throw "NtCreateFile returnValue is not NTSTATUS hex: $($ntEvent.returnValue)"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Shared-memory capture did not receive exactly one agent_shutdown event."
}

if ($shutdown[0].installedHooks -lt 6 -or $shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Unexpected hook lifecycle counts: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Shared-memory transport smoke passed: records=$($result.transportRecordsConsumed)/$($result.transportRecordsProduced) overheadAvgUs=$($result.hookOverheadAvgUs) apis=$($apis -join ',')"
