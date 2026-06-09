param(
    [string]$BuildDir = "build\native-win32\Debug"
)

$ErrorActionPreference = "Stop"

$helperPath = Join-Path $BuildDir "knmon-native-helper.exe"
$requiredApis = @(
    "CreateFileW",
    "CreateFileA",
    "NtCreateFile",
    "ReadFile",
    "WriteFile",
    "CloseHandle"
)

if (-not (Test-Path -LiteralPath $helperPath))
{
    throw "x86 helper not found: $helperPath"
}

$result = & $helperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "x86 capture failed: $($result.operation): $($result.message)"
}

if ($result.architecture -ne "x86")
{
    throw "x86 capture result architecture mismatch: $($result.architecture)"
}

if (-not $result.handshake.received)
{
    throw "x86 capture did not receive HELLO."
}

if ($result.handshake.architecture -ne "x86")
{
    throw "x86 HELLO architecture mismatch: $($result.handshake.architecture)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "x86 capture did not use shared-memory transport: $($result.transportMode)"
}

if ($result.droppedEvents -ne 0)
{
    throw "x86 capture reported dropped events: $($result.droppedEvents)"
}

$apis = @($result.capturedEvents | ForEach-Object { $_.api } | Sort-Object -Unique)
foreach ($api in $requiredApis)
{
    if ($apis -notcontains $api)
    {
        throw "x86 capture missing API: $api"
    }
}

$ntEvents = @($result.capturedEvents | Where-Object { $_.api -eq "NtCreateFile" })
if ($ntEvents.Count -lt 1)
{
    throw "x86 capture did not include NtCreateFile."
}

$ntEvent = $ntEvents[0]
if ($ntEvent.module -ne "ntdll.dll")
{
    throw "x86 NtCreateFile module mismatch: $($ntEvent.module)"
}

if ($ntEvent.returnValue -notmatch "^0x[0-9a-fA-F]{8}$")
{
    throw "x86 NtCreateFile returnValue is not NTSTATUS hex: $($ntEvent.returnValue)"
}

$stackEvidence = @($ntEvent.stack | Where-Object { $_ -eq "knmon-agent32.dll!IatHook" })
if ($stackEvidence.Count -ne 1)
{
    throw "x86 NtCreateFile stack did not include knmon-agent32.dll!IatHook."
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "x86 capture did not receive exactly one agent_shutdown event."
}

if ($shutdown[0].installedHooks -ne 6)
{
    throw "x86 unexpected installedHooks: $($shutdown[0].installedHooks)"
}

if ($shutdown[0].restoredHooks -ne 6)
{
    throw "x86 unexpected restoredHooks: $($shutdown[0].restoredHooks)"
}

if ($shutdown[0].failedHooks -ne 0)
{
    throw "x86 capture reported failedHooks: $($shutdown[0].failedHooks)"
}

Write-Host "x86 capture smoke passed: apis=$($apis -join ',') ntStatus=$($ntEvent.returnValue) restoredHooks=$($shutdown[0].restoredHooks)"
