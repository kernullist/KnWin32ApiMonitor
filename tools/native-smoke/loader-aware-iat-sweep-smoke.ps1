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
    throw "Loader-aware capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

if ($result.transportDroppedEvents -ne 0 -or $result.droppedEvents -ne 0)
{
    throw "Healthy loader-aware capture reported drops: transport=$($result.transportDroppedEvents) result=$($result.droppedEvents)"
}

$inventory = @($result.agentMessages | Where-Object { $_.messageType -eq "module_inventory" } | Select-Object -First 1)
if ($inventory.Count -ne 1)
{
    throw "Module inventory evidence is missing."
}

if ($inventory[0].scannedModules -le 1)
{
    throw "Module inventory did not scan beyond the main executable: scanned=$($inventory[0].scannedModules)"
}

$initialSweep = @($result.agentMessages | Where-Object { $_.messageType -eq "iat_sweep" -and $_.reason -eq "initial" } | Select-Object -First 1)
if ($initialSweep.Count -ne 1)
{
    throw "Initial IAT sweep evidence is missing."
}

if ($initialSweep[0].patchedSlots -lt 6)
{
    throw "Initial IAT sweep patched too few slots: $($initialSweep[0].patchedSlots)"
}

if ($initialSweep[0].failedSlots -ne 0)
{
    throw "Initial IAT sweep reported failed slots: $($initialSweep[0].failedSlots)"
}

$apis = @($result.capturedEvents | ForEach-Object { $_.api } | Sort-Object -Unique)
foreach ($api in $requiredApis)
{
    if ($apis -notcontains $api)
    {
        throw "Loader-aware capture missing API: $api"
    }
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Loader-aware capture did not receive agent_shutdown."
}

if ($shutdown[0].installedHooks -lt 6 -or $shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Unexpected hook lifecycle counts: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Loader-aware IAT sweep smoke passed: scanned=$($inventory[0].scannedModules) eligible=$($inventory[0].eligibleModules) patched=$($initialSweep[0].patchedSlots) hooks=$($shutdown[0].installedHooks)"
