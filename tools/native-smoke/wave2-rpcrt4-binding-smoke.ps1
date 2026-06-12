param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $HelperPath))
{
    throw "Helper not found: $HelperPath"
}

$idPath = Join-Path (Get-Location) "generated\definition-ids.json"
if (-not (Test-Path -LiteralPath $idPath))
{
    throw "Generated ID file not found: $idPath"
}

$ids = Get-Content -LiteralPath $idPath -Raw | ConvertFrom-Json
$provider = @($ids.modules | Where-Object { $_.name -ieq "rpcrt4.dll" } | Select-Object -First 1)
if ($provider.Count -ne 1 -or $provider[0].id -ne 7)
{
    throw "Generated provider module mismatch for rpcrt4.dll: $($provider | ConvertTo-Json -Depth 4)"
}

$bindingSetOptionId = @($ids.apis | Where-Object { $_.module -ieq "rpcrt4.dll" -and $_.name -eq "RpcBindingSetOption" } | Select-Object -First 1)
if ($bindingSetOptionId.Count -ne 1 -or $bindingSetOptionId[0].id -ne 54)
{
    throw "Generated ID mismatch for RpcBindingSetOption: $($bindingSetOptionId | ConvertTo-Json -Depth 4)"
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
    @{ Api = "RpcBindingFree"; Category = "rpc_binding_free"; Args = @("Binding") },
    @{ Api = "RpcBindingSetOption"; Category = "rpc_binding_option_set"; Args = @("hBinding", "option", "optionValue") }
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

$bindingSetOptionEvent = @($result.capturedEvents | Where-Object { $_.api -eq "RpcBindingSetOption" } | Select-Object -First 1)
if ($bindingSetOptionEvent.Count -ne 1)
{
    throw "RpcBindingSetOption event was not captured."
}

if ($bindingSetOptionEvent[0].returnValue -notmatch "^0 \(0x00000000\)$")
{
    throw "RpcBindingSetOption return value mismatch: $($bindingSetOptionEvent[0].returnValue)"
}

if (-not [string]::IsNullOrEmpty($bindingSetOptionEvent[0].bufferPreview))
{
    throw "RpcBindingSetOption exposed bufferPreview: $($bindingSetOptionEvent[0] | ConvertTo-Json -Depth 8)"
}

$bindingHandle = @($bindingSetOptionEvent[0].arguments | Where-Object { $_.name -eq "hBinding" } | Select-Object -First 1)
if ($bindingHandle.Count -ne 1 -or
    $bindingHandle[0].decodeAlias -ne "rpc_binding_handle" -or
    $bindingHandle[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "RpcBindingSetOption binding handle evidence mismatch: $($bindingHandle | ConvertTo-Json -Depth 8)"
}

$option = @($bindingSetOptionEvent[0].arguments | Where-Object { $_.name -eq "option" } | Select-Object -First 1)
if ($option.Count -ne 1 -or
    $option[0].decodeAlias -ne "byte_count" -or
    ($option[0].decodedValue -ne "12 (0x0000000C)" -and $option[0].decodedValue -ne "12"))
{
    throw "RpcBindingSetOption option evidence mismatch: $($option | ConvertTo-Json -Depth 8)"
}

$optionValue = @($bindingSetOptionEvent[0].arguments | Where-Object { $_.name -eq "optionValue" } | Select-Object -First 1)
if ($optionValue.Count -ne 1 -or
    $optionValue[0].decodeAlias -ne "byte_count" -or
    $optionValue[0].decodedValue -ne "5000")
{
    throw "RpcBindingSetOption optionValue evidence mismatch: $($optionValue | ConvertTo-Json -Depth 8)"
}

$bindingSetOptionPayload = $bindingSetOptionEvent[0] | ConvertTo-Json -Depth 12
if ($bindingSetOptionPayload -cmatch "RpcBindingSetAuthInfo|RpcMgmtEp|EndpointMapper|Annotation|ServerPrinc|AuthIdentity|Authn|Authz|Credential|Password|Token|SID|ACL|SecurityDescriptor|send|recv|WinHttp|InternetOpenUrl|HttpSend|Cookie|Authorization|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|Injection|BEGIN CERTIFICATE|PRIVATE KEY|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "RpcBindingSetOption event appears to expose forbidden auth, endpoint, credential, payload, remote-memory, stack, injection, or byte-preview evidence: $bindingSetOptionPayload"
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
