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
    throw "Resolver monitoring capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Resolver monitoring did not use shared-memory transport: $($result.transportMode)"
}

if ($result.droppedEvents -ne 0)
{
    throw "Resolver monitoring reported dropped events: $($result.droppedEvents)"
}

$resolverApis = @(
    "GetProcAddress",
    "LdrGetProcedureAddress"
)

$apis = @($result.capturedEvents | ForEach-Object { $_.api } | Sort-Object -Unique)
foreach ($api in $resolverApis)
{
    if ($apis -notcontains $api)
    {
        throw "Resolver monitoring missing API: $api"
    }
}

$getProc = @($result.capturedEvents | Where-Object { $_.api -eq "GetProcAddress" } | Select-Object -First 1)
if ($getProc.Count -ne 1)
{
    throw "Resolver monitoring did not capture exactly one GetProcAddress sample event."
}

if ($getProc[0].module -ne "kernel32.dll")
{
    throw "GetProcAddress module mismatch: $($getProc[0].module)"
}

if ($getProc[0].tags -notcontains "resolver" -or $getProc[0].tags -notcontains "dynamic_symbol_lookup")
{
    throw "GetProcAddress resolver tags missing: $($getProc[0].tags -join ',')"
}

if ($getProc[0].returnValue -notmatch "^0x[0-9a-fA-F]+$")
{
    throw "GetProcAddress returnValue is not a hex pointer: $($getProc[0].returnValue)"
}

$getProcArgs = ($getProc[0].arguments | ConvertTo-Json -Depth 8)
if ($getProcArgs -notmatch "KnMonDynamicProbe")
{
    throw "GetProcAddress arguments did not include dynamic probe evidence: $getProcArgs"
}

$ldr = @($result.capturedEvents | Where-Object { $_.api -eq "LdrGetProcedureAddress" } | Select-Object -First 1)
if ($ldr.Count -ne 1)
{
    throw "Resolver monitoring did not capture exactly one LdrGetProcedureAddress sample event."
}

if ($ldr[0].module -ne "ntdll.dll")
{
    throw "LdrGetProcedureAddress module mismatch: $($ldr[0].module)"
}

if ($ldr[0].tags -notcontains "resolver" -or $ldr[0].tags -notcontains "dynamic_symbol_lookup_nt")
{
    throw "LdrGetProcedureAddress resolver tags missing: $($ldr[0].tags -join ',')"
}

if ($ldr[0].returnValue -notmatch "^0x[0-9a-fA-F]{8}$")
{
    throw "LdrGetProcedureAddress returnValue is not NTSTATUS hex: $($ldr[0].returnValue)"
}

$ldrArgs = ($ldr[0].arguments | ConvertTo-Json -Depth 8)
if ($ldrArgs -notmatch "KnMonDynamicProbe")
{
    throw "LdrGetProcedureAddress arguments did not include dynamic probe evidence: $ldrArgs"
}

if ($ldrArgs -notmatch "0x[0-9a-fA-F]+")
{
    throw "LdrGetProcedureAddress arguments did not include pointer evidence: $ldrArgs"
}

$resolverHooks = @($result.agentMessages | Where-Object {
    $_.messageType -eq "hook_installed" -and
    $_.api -in $resolverApis
})

foreach ($api in $resolverApis)
{
    $hook = @($resolverHooks | Where-Object { $_.api -eq $api })
    if ($hook.Count -lt 1)
    {
        throw "Resolver hook installation evidence missing for $api."
    }
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Resolver monitoring did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Unexpected resolver hook lifecycle counts: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Resolver monitoring smoke passed: apis=$($resolverApis -join ',') hooks=$($shutdown[0].installedHooks) events=$($result.capturedEvents.Count)"
