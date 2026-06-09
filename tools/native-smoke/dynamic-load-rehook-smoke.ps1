param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $HelperPath))
{
    throw "Helper not found: $HelperPath"
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Dynamic-load capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$loaderEvents = @($result.capturedEvents | Where-Object { $_.api -in @("LoadLibraryW", "LoadLibraryA", "LoadLibraryExW", "LoadLibraryExA", "LdrLoadDll") })
if ($loaderEvents.Count -lt 1)
{
    throw "Dynamic-load capture did not include a loader API event."
}

$loadLibrary = @($loaderEvents | Where-Object { $_.api -eq "LoadLibraryW" } | Select-Object -First 1)
if ($loadLibrary.Count -ne 1)
{
    throw "Dynamic-load capture did not include LoadLibraryW."
}

$loadArgText = ($loadLibrary[0].arguments | ConvertTo-Json -Depth 8)
if ($loadArgText -notmatch "knmon-dynamic-probe\.dll")
{
    throw "LoadLibraryW event did not include dynamic probe DLL evidence: $loadArgText"
}

$dynamicSweep = @($result.agentMessages | Where-Object { $_.messageType -eq "iat_sweep" -and $_.reason -eq "dynamic_load" } | Select-Object -Last 1)
if ($dynamicSweep.Count -ne 1)
{
    throw "Dynamic-load re-hook sweep evidence is missing."
}

if ($dynamicSweep[0].eligibleModules -lt 2)
{
    throw "Dynamic-load sweep did not see the newly loaded eligible module: eligible=$($dynamicSweep[0].eligibleModules)"
}

if ($dynamicSweep[0].patchedSlots -lt 1)
{
    throw "Dynamic-load sweep did not patch any new slots."
}

if ($dynamicSweep[0].failedSlots -ne 0)
{
    throw "Dynamic-load sweep reported failed slots: $($dynamicSweep[0].failedSlots)"
}

$dynamicProbeEvents = @($result.capturedEvents | Where-Object {
    ($_.api -in @("CreateFileW", "WriteFile", "CloseHandle")) -and
    (($_.arguments | ConvertTo-Json -Depth 8) -match "knmon-dynamic-probe")
})

if ($dynamicProbeEvents.Count -lt 1)
{
    throw "Dynamic probe post-load API evidence is missing."
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Dynamic-load capture did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Unexpected hook lifecycle counts: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Dynamic-load re-hook smoke passed: loaderEvents=$($loaderEvents.Count) eligible=$($dynamicSweep[0].eligibleModules) patched=$($dynamicSweep[0].patchedSlots) postLoadEvents=$($dynamicProbeEvents.Count)"
