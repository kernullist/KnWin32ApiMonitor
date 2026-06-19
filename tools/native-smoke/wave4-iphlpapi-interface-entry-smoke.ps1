param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "iphlpapi.dll"
$SelectedApi = "GetIfEntry2"

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
$provider = @($ids.modules | Where-Object { $_.name -eq $ProviderModule } | Select-Object -First 1)
if ($provider.Count -ne 1 -or $provider[0].id -ne 22)
{
    throw "Generated provider module mismatch for $ProviderModule`: $($provider | ConvertTo-Json -Depth 4)"
}

$entry = @($ids.apis | Where-Object { $_.module -eq $ProviderModule -and $_.name -eq $SelectedApi } | Select-Object -First 1)
if ($entry.Count -ne 1 -or $entry[0].id -ne 171)
{
    throw "Generated ID mismatch for $SelectedApi`: expected=171 actual=$($entry | ConvertTo-Json -Depth 4)"
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Wave 4 IPHLPAPI capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 4 IPHLPAPI healthy capture dropped transport events: $droppedEvents"
}

$iphlpapiEvents = @($result.capturedEvents | Where-Object { $_.module -eq $ProviderModule -and $_.api -eq $SelectedApi })
if ($iphlpapiEvents.Count -lt 1)
{
    throw "Wave 4 IPHLPAPI capture did not include $SelectedApi."
}

$event = $iphlpapiEvents[0]
if ($event.apiFamily -ne "network-metadata" -or $event.apiCategory -ne "interface_entry_query")
{
    throw "$SelectedApi metadata mismatch: family=$($event.apiFamily) category=$($event.apiCategory)"
}

if ($event.hookPolicy -ne "iat" -or $event.coverageStatus -ne "smoke_verified")
{
    throw "$SelectedApi hook metadata mismatch: hook=$($event.hookPolicy) coverage=$($event.coverageStatus)"
}

if ($event.returnValue -notmatch "^0 \(0x00000000\)$")
{
    throw "$SelectedApi return evidence mismatch: $($event | ConvertTo-Json -Depth 8)"
}

if ($event.lastErrorCode -ne 0)
{
    throw "$SelectedApi unexpected lastErrorCode: $($event.lastErrorCode)"
}

if ($null -eq $event.durationUs -or $event.durationUs -lt 0)
{
    throw "$SelectedApi missing duration evidence."
}

if (-not [string]::IsNullOrEmpty($event.bufferPreview))
{
    throw "$SelectedApi exposed bufferPreview: $($event.bufferPreview)"
}

$row = Get-ArgumentByName -Event $event -Name "Row"
if ($row.decodeAlias -ne "pointer" -or $row.captureTiming -ne "pre_post")
{
    throw "$SelectedApi Row metadata mismatch: $($row | ConvertTo-Json -Depth 8)"
}

Assert-PointerValue -Value $row.rawValue -Name "$SelectedApi Row rawValue"
Assert-PointerValue -Value $row.decodedValue -Name "$SelectedApi Row decodedValue"

$eventData = $iphlpapiEvents | ConvertTo-Json -Depth 12
if ($eventData -cmatch "GetAdaptersAddresses|GetIfTable2|FriendlyName|Description|PhysicalAddress|PermanentPhysicalAddress|Unicast|Anycast|Multicast|DnsSuffix|Gateway|TransmitLinkSpeed|ReceiveLinkSpeed|InOctets|OutOctets|NetworkGuid|AdapterName|InterfaceAlias|IfDescr|MAC|([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|StackWalk|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 4 IPHLPAPI event appears to expose adapter inventory, interface payload, stack, injection, credential, or byte-preview evidence: $eventData"
}

$installed = @($result.agentMessages | Where-Object {
    $_.messageType -eq "hook_installed" -and
    $_.module -eq $ProviderModule -and
    $_.api -eq $SelectedApi
})
if ($installed.Count -lt 1)
{
    throw "Wave 4 IPHLPAPI hook install evidence is incomplete."
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 4 IPHLPAPI capture did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Unexpected hook lifecycle counts: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 4 IPHLPAPI interface-entry smoke passed: events=$($iphlpapiEvents.Count) installed=$($installed.Count) restored=$($shutdown[0].restoredHooks)"
