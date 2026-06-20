param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "rpcrt4.dll"
$SelectedApi = "RpcMgmtEpEltInqDone"

function Assert-PointerValue
{
    param(
        [string]$Value,
        [string]$Name,
        [bool]$AllowNull = $false
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^0x[0-9a-fA-F]+$")
    {
        throw "$Name is not a pointer value: $Value"
    }

    if (-not $AllowNull -and $Value -match "^0x0+$")
    {
        throw "$Name unexpectedly used a null pointer."
    }
}

function Get-ArgumentByName
{
    param(
        [object]$Event,
        [string]$Name
    )

    $argument = @($Event.arguments | Where-Object { $_.name -eq $Name } | Select-Object -First 1)
    if ($argument.Count -ne 1)
    {
        throw "$($Event.api) argument missing: $Name"
    }

    return $argument[0]
}

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
$provider = @($ids.modules | Where-Object { $_.name -ieq $ProviderModule } | Select-Object -First 1)
if ($provider.Count -ne 1 -or $provider[0].id -ne 7)
{
    throw "Generated provider module mismatch for $ProviderModule`: $($provider | ConvertTo-Json -Depth 4)"
}

$entry = @($ids.apis | Where-Object { $_.module -ieq $ProviderModule -and $_.name -eq $SelectedApi } | Select-Object -First 1)
if ($entry.Count -ne 1 -or $entry[0].id -ne 57)
{
    throw "Generated ID mismatch for $SelectedApi`: expected=57 actual=$($entry | ConvertTo-Json -Depth 4)"
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Wave 2 RPCRT4 endpoint-inquiry cleanup capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 2 RPCRT4 endpoint-inquiry cleanup healthy capture dropped transport events: $droppedEvents"
}

$events = @($result.capturedEvents | Where-Object { $_.module -eq $ProviderModule -and $_.api -eq $SelectedApi })
if ($events.Count -lt 1)
{
    throw "Wave 2 RPCRT4 endpoint-inquiry cleanup capture did not include $SelectedApi."
}

$event = $events[0]
if ($event.apiFamily -ne "rpc" -or $event.apiCategory -ne "rpc_endpoint_inquiry_done")
{
    throw "$SelectedApi metadata mismatch: family=$($event.apiFamily) category=$($event.apiCategory)"
}

if ($event.hookPolicy -ne "iat" -or $event.coverageStatus -ne "smoke_verified")
{
    throw "$SelectedApi hook metadata mismatch: hook=$($event.hookPolicy) coverage=$($event.coverageStatus)"
}

if ($event.returnValue -notmatch "^0 \(0x00000000\)$")
{
    throw "$SelectedApi did not return RPC_S_OK: $($event | ConvertTo-Json -Depth 8)"
}

if ($null -eq $event.durationUs -or $event.durationUs -lt 0)
{
    throw "$SelectedApi missing duration evidence."
}

if (-not [string]::IsNullOrEmpty($event.bufferPreview))
{
    throw "$SelectedApi exposed bufferPreview: $($event.bufferPreview)"
}

$inquiryContext = Get-ArgumentByName -Event $event -Name "InquiryContext"
if ($inquiryContext.decodeAlias -ne "pointer_pointer" -or $inquiryContext.captureTiming -ne "pre_post")
{
    throw "$SelectedApi InquiryContext metadata mismatch: $($inquiryContext | ConvertTo-Json -Depth 8)"
}

Assert-PointerValue -Value $inquiryContext.rawValue -Name "$SelectedApi InquiryContext pointer"
Assert-PointerValue -Value $inquiryContext.preCallValue -Name "$SelectedApi InquiryContext pointer"
Assert-PointerValue -Value $inquiryContext.decodedValue -Name "$SelectedApi pre-call inquiry handle"
Assert-PointerValue -Value $inquiryContext.postCallValue -Name "$SelectedApi post-call inquiry handle" -AllowNull $true

$eventData = $events | ConvertTo-Json -Depth 12
if ($eventData -cmatch "RpcMgmtEpEltInqBegin|RpcMgmtEpEltInqNext|Annotation|RPC_IF_ID|ObjectUuid|EndpointMapper|endpoint mapper|StringBinding|RpcBindingSetAuthInfo|ServerPrinc|AuthIdentity|Authn|Authz|Credential|Password|Token|SID|ACL|SecurityDescriptor|send|recv|WinHttp|InternetOpenUrl|HttpSend|Cookie|Authorization|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|Injection|BEGIN CERTIFICATE|PRIVATE KEY|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 2 RPCRT4 endpoint-inquiry cleanup event appears to expose endpoint, auth, credential, network, payload, remote-memory, stack, injection, or byte-preview evidence: $eventData"
}

$installed = @($result.agentMessages | Where-Object {
    $_.messageType -eq "hook_installed" -and
    $_.module -eq $ProviderModule -and
    $_.api -eq $SelectedApi
})
if ($installed.Count -lt 1)
{
    throw "Wave 2 RPCRT4 endpoint-inquiry cleanup hook install evidence is incomplete."
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 2 RPCRT4 endpoint-inquiry cleanup capture did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Unexpected hook lifecycle counts: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 2 RPCRT4 endpoint-inquiry cleanup smoke passed: events=$($events.Count) installed=$($installed.Count) restored=$($shutdown[0].restoredHooks)"
