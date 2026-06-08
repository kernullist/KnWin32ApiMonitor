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
    throw "Capture failed: $($result.operation): $($result.message)"
}

if (-not $result.handshake.received)
{
    throw "Capture did not receive HELLO."
}

if ($result.droppedEvents -ne 0)
{
    throw "Capture reported dropped events: $($result.droppedEvents)"
}

$apis = @($result.capturedEvents | ForEach-Object { $_.api } | Sort-Object -Unique)
foreach ($api in $requiredApis)
{
    if ($apis -notcontains $api)
    {
        throw "Capture missing API: $api"
    }
}

$ntEvents = @($result.capturedEvents | Where-Object { $_.api -eq "NtCreateFile" })
if ($ntEvents.Count -lt 1)
{
    throw "Capture did not include NtCreateFile."
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

$objectAttributes = @($ntEvent.arguments | Where-Object { $_.name -eq "ObjectAttributes" } | Select-Object -First 1)
if ($objectAttributes.Count -ne 1)
{
    throw "NtCreateFile ObjectAttributes argument is missing."
}

if ([string]::IsNullOrWhiteSpace($objectAttributes[0].decodedValue) -or $objectAttributes[0].decodedValue -notmatch "knmon-fileio-sample\.dat")
{
    throw "NtCreateFile ObjectAttributes does not include decoded sample path evidence: $($objectAttributes[0].decodedValue)"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Capture did not receive exactly one agent_shutdown event."
}

if ($shutdown[0].installedHooks -ne 6)
{
    throw "Unexpected installedHooks: $($shutdown[0].installedHooks)"
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks)
{
    throw "restoredHooks did not match installedHooks."
}

if ($shutdown[0].failedHooks -ne 0)
{
    throw "Capture reported failedHooks: $($shutdown[0].failedHooks)"
}

Write-Host "NtCreateFile capture smoke passed: apis=$($apis -join ',') ntStatus=$($ntEvent.returnValue) restoredHooks=$($shutdown[0].restoredHooks) object=$($objectAttributes[0].decodedValue)"
