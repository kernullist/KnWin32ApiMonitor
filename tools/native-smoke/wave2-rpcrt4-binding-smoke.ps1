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
    throw "Wave 2 RPCRT4 binding capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

if ($result.transportDroppedEvents -ne 0)
{
    throw "RPCRT4 healthy capture dropped transport events: $($result.transportDroppedEvents)"
}

$expected = @(
    @{ Api = "RpcStringBindingComposeW"; Category = "rpc_string_binding_compose"; Args = @("ObjUuid", "ProtSeq", "NetworkAddr", "Endpoint", "Options", "StringBinding") },
    @{ Api = "RpcBindingFromStringBindingW"; Category = "rpc_binding_from_string"; Args = @("StringBinding", "Binding") },
    @{ Api = "RpcStringFreeW"; Category = "rpc_string_free"; Args = @("String") },
    @{ Api = "RpcBindingFree"; Category = "rpc_binding_free"; Args = @("Binding") }
)

foreach ($item in $expected)
{
    $event = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api } | Select-Object -First 1)
    if ($event.Count -ne 1)
    {
        throw "Wave 2 RPCRT4 smoke did not capture $($item.Api)."
    }

    if ($event[0].module -ne "rpcrt4.dll")
    {
        throw "$($item.Api) module mismatch: $($event[0].module)"
    }

    if ($event[0].apiFamily -ne "rpc" -or $event[0].apiCategory -ne $item.Category)
    {
        throw "$($item.Api) metadata mismatch: family=$($event[0].apiFamily) category=$($event[0].apiCategory)"
    }

    if ($event[0].hookPolicy -ne "iat" -or $event[0].coverageStatus -ne "smoke_verified")
    {
        throw "$($item.Api) hook metadata mismatch: hook=$($event[0].hookPolicy) coverage=$($event[0].coverageStatus)"
    }

    if ($event[0].returnValue -notmatch "^0 \(0x00000000\)$")
    {
        throw "$($item.Api) return value mismatch: $($event[0].returnValue)"
    }

    foreach ($argName in $item.Args)
    {
        $argument = @($event[0].arguments | Where-Object { $_.name -eq $argName } | Select-Object -First 1)
        if ($argument.Count -ne 1)
        {
            throw "$($item.Api) argument missing: $argName"
        }

        if ([string]::IsNullOrWhiteSpace($argument[0].decodeAlias))
        {
            throw "$($item.Api) argument decode alias missing: $argName"
        }
    }
}

$composeEvent = @($result.capturedEvents | Where-Object { $_.api -eq "RpcStringBindingComposeW" } | Select-Object -First 1)
$composeArgs = $composeEvent[0].arguments | ConvertTo-Json -Depth 8
if ($composeArgs -notmatch "ncalrpc" -or $composeArgs -notmatch "KNMonRpcSample")
{
    throw "RpcStringBindingComposeW did not include local binding evidence: $composeArgs"
}

$fromBindingEvent = @($result.capturedEvents | Where-Object { $_.api -eq "RpcBindingFromStringBindingW" } | Select-Object -First 1)
$fromBindingArgs = $fromBindingEvent[0].arguments | ConvertTo-Json -Depth 8
if ($fromBindingArgs -notmatch "ncalrpc" -or $fromBindingArgs -notmatch "KNMonRpcSample")
{
    throw "RpcBindingFromStringBindingW did not include string binding evidence: $fromBindingArgs"
}

$stringFreeEvent = @($result.capturedEvents | Where-Object { $_.api -eq "RpcStringFreeW" } | Select-Object -First 1)
$stringFreeArgs = $stringFreeEvent[0].arguments | ConvertTo-Json -Depth 8
if ($stringFreeArgs -notmatch "ncalrpc" -or $stringFreeArgs -notmatch "KNMonRpcSample")
{
    throw "RpcStringFreeW did not include pre-free binding evidence: $stringFreeArgs"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 2 RPCRT4 smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -lt $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 2 RPCRT4 binding smoke passed: events=$($result.capturedEvents.Count) rpcApis=$($expected.Count) overheadAvgUs=$($result.hookOverheadAvgUs)"
