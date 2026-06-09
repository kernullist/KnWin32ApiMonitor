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
    "CloseHandle",
    "GetProcAddress",
    "LdrGetProcedureAddress",
    "RegOpenKeyExW",
    "RegCreateKeyExW",
    "RegQueryValueExW",
    "RegSetValueExW",
    "RegDeleteValueW",
    "RegCloseKey",
    "BCryptOpenAlgorithmProvider",
    "BCryptCloseAlgorithmProvider",
    "BCryptGetProperty",
    "BCryptGenRandom",
    "RpcStringBindingComposeW",
    "RpcBindingFromStringBindingW",
    "RpcStringFreeW",
    "RpcBindingFree",
    "WSAStartup",
    "WSACleanup",
    "socket",
    "closesocket",
    "getaddrinfo",
    "freeaddrinfo",
    "WSAGetLastError"
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

$loaderEvents = @($result.capturedEvents | Where-Object { $_.api -eq "LoadLibraryW" })
if ($loaderEvents.Count -lt 1)
{
    throw "x86 capture did not include LoadLibraryW dynamic-load evidence."
}

$resolverEvents = @($result.capturedEvents | Where-Object { $_.api -in @("GetProcAddress", "LdrGetProcedureAddress") })
if ($resolverEvents.Count -lt 2)
{
    throw "x86 capture did not include both resolver API events."
}

$getProc = @($resolverEvents | Where-Object { $_.api -eq "GetProcAddress" } | Select-Object -First 1)
if ($getProc.Count -ne 1 -or $getProc[0].tags -notcontains "resolver" -or $getProc[0].tags -notcontains "dynamic_symbol_lookup")
{
    throw "x86 GetProcAddress resolver event is missing resolver tags."
}

$getProcArgs = ($getProc[0].arguments | ConvertTo-Json -Depth 8)
if ($getProcArgs -notmatch "KnMonDynamicProbe")
{
    throw "x86 GetProcAddress arguments did not include dynamic probe evidence: $getProcArgs"
}

$ldr = @($resolverEvents | Where-Object { $_.api -eq "LdrGetProcedureAddress" } | Select-Object -First 1)
if ($ldr.Count -ne 1 -or $ldr[0].tags -notcontains "resolver" -or $ldr[0].tags -notcontains "dynamic_symbol_lookup_nt")
{
    throw "x86 LdrGetProcedureAddress resolver event is missing resolver tags."
}

$ldrArgs = ($ldr[0].arguments | ConvertTo-Json -Depth 8)
if ($ldrArgs -notmatch "KnMonDynamicProbe")
{
    throw "x86 LdrGetProcedureAddress arguments did not include dynamic probe evidence: $ldrArgs"
}

$registryEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "registry" })
if ($registryEvents.Count -lt 6)
{
    throw "x86 capture did not include the selected registry API family slice."
}

$registryCreate = @($registryEvents | Where-Object { $_.api -eq "RegCreateKeyExW" } | Select-Object -First 1)
if ($registryCreate.Count -ne 1 -or $registryCreate[0].module -ne "advapi32.dll" -or $registryCreate[0].hookPolicy -ne "iat" -or $registryCreate[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 RegCreateKeyExW metadata mismatch."
}

$registryCreateArgs = ($registryCreate[0].arguments | ConvertTo-Json -Depth 8)
if ($registryCreateArgs -notmatch "KNMonApiMonitorSample")
{
    throw "x86 registry arguments did not include sample key evidence: $registryCreateArgs"
}

$registrySet = @($registryEvents | Where-Object { $_.api -eq "RegSetValueExW" } | Select-Object -First 1)
if ($registrySet.Count -ne 1)
{
    throw "x86 capture did not include RegSetValueExW."
}

$registrySetArgs = ($registrySet[0].arguments | ConvertTo-Json -Depth 8)
if ($registrySetArgs -notmatch "SampleValue")
{
    throw "x86 registry arguments did not include sample value evidence: $registrySetArgs"
}

$cryptoEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "crypto" })
if ($cryptoEvents.Count -lt 4)
{
    throw "x86 capture did not include the selected bcrypt CNG API family slice."
}

$bcryptOpen = @($cryptoEvents | Where-Object { $_.api -eq "BCryptOpenAlgorithmProvider" } | Select-Object -First 1)
if ($bcryptOpen.Count -ne 1 -or $bcryptOpen[0].module -ne "bcrypt.dll" -or $bcryptOpen[0].hookPolicy -ne "iat" -or $bcryptOpen[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 BCryptOpenAlgorithmProvider metadata mismatch."
}

$bcryptOpenArgs = ($bcryptOpen[0].arguments | ConvertTo-Json -Depth 8)
if ($bcryptOpenArgs -notmatch "RNG")
{
    throw "x86 bcrypt open arguments did not include RNG evidence: $bcryptOpenArgs"
}

$bcryptProperty = @($cryptoEvents | Where-Object { $_.api -eq "BCryptGetProperty" } | Select-Object -First 1)
if ($bcryptProperty.Count -ne 1)
{
    throw "x86 capture did not include BCryptGetProperty."
}

$bcryptPropertyArgs = ($bcryptProperty[0].arguments | ConvertTo-Json -Depth 8)
if ($bcryptPropertyArgs -notmatch "AlgorithmName" -or $bcryptPropertyArgs -notmatch "RNG")
{
    throw "x86 bcrypt property arguments did not include AlgorithmName/RNG evidence: $bcryptPropertyArgs"
}

$bcryptRandom = @($cryptoEvents | Where-Object { $_.api -eq "BCryptGenRandom" } | Select-Object -First 1)
if ($bcryptRandom.Count -ne 1 -or -not [string]::IsNullOrEmpty($bcryptRandom[0].bufferPreview))
{
    throw "x86 BCryptGenRandom exposed buffer preview or was not captured."
}

$rpcEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "rpc" })
if ($rpcEvents.Count -lt 4)
{
    throw "x86 capture did not include the selected RPCRT4 binding API family slice."
}

$rpcCompose = @($rpcEvents | Where-Object { $_.api -eq "RpcStringBindingComposeW" } | Select-Object -First 1)
if ($rpcCompose.Count -ne 1 -or $rpcCompose[0].module -ne "rpcrt4.dll" -or $rpcCompose[0].hookPolicy -ne "iat" -or $rpcCompose[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 RpcStringBindingComposeW metadata mismatch."
}

$rpcComposeArgs = ($rpcCompose[0].arguments | ConvertTo-Json -Depth 8)
if ($rpcComposeArgs -notmatch "ncalrpc" -or $rpcComposeArgs -notmatch "KNMonRpcSample")
{
    throw "x86 RPC compose arguments did not include local binding evidence: $rpcComposeArgs"
}

$rpcStringFree = @($rpcEvents | Where-Object { $_.api -eq "RpcStringFreeW" } | Select-Object -First 1)
if ($rpcStringFree.Count -ne 1)
{
    throw "x86 capture did not include RpcStringFreeW."
}

$rpcStringFreeArgs = ($rpcStringFree[0].arguments | ConvertTo-Json -Depth 8)
if ($rpcStringFreeArgs -notmatch "ncalrpc" -or $rpcStringFreeArgs -notmatch "KNMonRpcSample")
{
    throw "x86 RPC string-free arguments did not include pre-free binding evidence: $rpcStringFreeArgs"
}

$dynamicSweep = @($result.agentMessages | Where-Object { $_.messageType -eq "iat_sweep" -and $_.reason -eq "dynamic_load" } | Select-Object -Last 1)
if ($dynamicSweep.Count -ne 1)
{
    throw "x86 capture did not include dynamic-load re-hook sweep evidence."
}

if ($dynamicSweep[0].patchedSlots -lt 1)
{
    throw "x86 dynamic-load sweep did not patch any new slots."
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

if ($shutdown[0].installedHooks -lt 6)
{
    throw "x86 unexpected installedHooks: $($shutdown[0].installedHooks)"
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks)
{
    throw "x86 unexpected restoredHooks: $($shutdown[0].restoredHooks)"
}

if ($shutdown[0].failedHooks -ne 0)
{
    throw "x86 capture reported failedHooks: $($shutdown[0].failedHooks)"
}

Write-Host "x86 capture smoke passed: apis=$($apis -join ',') ntStatus=$($ntEvent.returnValue) resolverEvents=$($resolverEvents.Count) restoredHooks=$($shutdown[0].restoredHooks)"
