param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "iphlpapi.dll"
$SelectedApis = @("GetAdaptersAddresses", "GetIfEntry2")

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

$expectedIds = @{
    GetAdaptersAddresses = 170
    GetIfEntry2 = 171
}

foreach ($apiName in $SelectedApis)
{
    $entry = @($ids.apis | Where-Object { $_.module -eq $ProviderModule -and $_.name -eq $apiName } | Select-Object -First 1)
    if ($entry.Count -ne 1 -or $entry[0].id -ne $expectedIds[$apiName])
    {
        throw "Generated ID mismatch for $apiName`: expected=$($expectedIds[$apiName]) actual=$($entry | ConvertTo-Json -Depth 4)"
    }
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

$adapterEvents = @($result.capturedEvents | Where-Object { $_.module -eq $ProviderModule -and $_.api -eq "GetAdaptersAddresses" })
if ($adapterEvents.Count -lt 1)
{
    throw "Wave 4 IPHLPAPI capture did not include GetAdaptersAddresses."
}

$adapterEvent = @($adapterEvents | Where-Object { $_.returnValue -match "^0 \(0x00000000\)$" } | Select-Object -First 1)
if ($adapterEvent.Count -ne 1)
{
    $adapterEvent = @($adapterEvents | Select-Object -First 1)
}

if ($adapterEvent[0].apiFamily -ne "network-metadata" -or $adapterEvent[0].apiCategory -ne "adapter_addresses_query")
{
    throw "GetAdaptersAddresses metadata mismatch: family=$($adapterEvent[0].apiFamily) category=$($adapterEvent[0].apiCategory)"
}

if ($adapterEvent[0].hookPolicy -ne "iat" -or $adapterEvent[0].coverageStatus -ne "smoke_verified")
{
    throw "GetAdaptersAddresses hook metadata mismatch: hook=$($adapterEvent[0].hookPolicy) coverage=$($adapterEvent[0].coverageStatus)"
}

if ($adapterEvent[0].returnValue -notmatch "^(0 \(0x00000000\)|111 \(0x0000006[fF]\)|232 \(0x000000[eE]8\))$")
{
    throw "GetAdaptersAddresses return evidence mismatch: $($adapterEvent[0] | ConvertTo-Json -Depth 8)"
}

if ($null -eq $adapterEvent[0].durationUs -or $adapterEvent[0].durationUs -lt 0)
{
    throw "GetAdaptersAddresses missing duration evidence."
}

if (-not [string]::IsNullOrEmpty($adapterEvent[0].bufferPreview))
{
    throw "GetAdaptersAddresses exposed bufferPreview: $($adapterEvent[0].bufferPreview)"
}

$family = Get-ArgumentByName -Event $adapterEvent[0] -Name "Family"
if ($family.decodeAlias -ne "dword_value" -or $family.decodedValue -notmatch "AF_UNSPEC")
{
    throw "GetAdaptersAddresses Family metadata mismatch: $($family | ConvertTo-Json -Depth 8)"
}

$flags = Get-ArgumentByName -Event $adapterEvent[0] -Name "Flags"
if ($flags.decodeAlias -ne "dword_value" -or $flags.decodedValue -notmatch "GAA_FLAG_SKIP_UNICAST")
{
    throw "GetAdaptersAddresses Flags metadata mismatch: $($flags | ConvertTo-Json -Depth 8)"
}

$reserved = Get-ArgumentByName -Event $adapterEvent[0] -Name "Reserved"
if ($reserved.decodeAlias -ne "pointer" -or $reserved.captureTiming -ne "pre")
{
    throw "GetAdaptersAddresses Reserved metadata mismatch: $($reserved | ConvertTo-Json -Depth 8)"
}
Assert-PointerValue -Value $reserved.decodedValue -Name "GetAdaptersAddresses Reserved" -AllowNull $true

$addresses = Get-ArgumentByName -Event $adapterEvent[0] -Name "AdapterAddresses"
if ($addresses.decodeAlias -ne "pointer" -or $addresses.captureTiming -ne "post")
{
    throw "GetAdaptersAddresses AdapterAddresses metadata mismatch: $($addresses | ConvertTo-Json -Depth 8)"
}
Assert-PointerValue -Value $addresses.decodedValue -Name "GetAdaptersAddresses AdapterAddresses" -AllowNull $true

$sizePointer = Get-ArgumentByName -Event $adapterEvent[0] -Name "SizePointer"
if ($sizePointer.decodeAlias -ne "dword_pointer" -or
    $sizePointer.captureTiming -ne "pre_post" -or
    $sizePointer.decodeStatus -ne "decoded" -or
    $sizePointer.decodedValue -notmatch "pre=.*post=")
{
    throw "GetAdaptersAddresses SizePointer evidence mismatch: $($sizePointer | ConvertTo-Json -Depth 8)"
}
Assert-PointerValue -Value $sizePointer.rawValue -Name "GetAdaptersAddresses SizePointer"

$interfaceEvents = @($result.capturedEvents | Where-Object { $_.module -eq $ProviderModule -and $_.api -eq "GetIfEntry2" })
if ($interfaceEvents.Count -lt 1)
{
    throw "Wave 4 IPHLPAPI capture did not include GetIfEntry2."
}

$event = $interfaceEvents[0]
if ($event.apiFamily -ne "network-metadata" -or $event.apiCategory -ne "interface_entry_query")
{
    throw "GetIfEntry2 metadata mismatch: family=$($event.apiFamily) category=$($event.apiCategory)"
}

if ($event.hookPolicy -ne "iat" -or $event.coverageStatus -ne "smoke_verified")
{
    throw "GetIfEntry2 hook metadata mismatch: hook=$($event.hookPolicy) coverage=$($event.coverageStatus)"
}

if ($event.returnValue -notmatch "^0 \(0x00000000\)$")
{
    throw "GetIfEntry2 return evidence mismatch: $($event | ConvertTo-Json -Depth 8)"
}

if ($event.lastErrorCode -ne 0)
{
    throw "GetIfEntry2 unexpected lastErrorCode: $($event.lastErrorCode)"
}

if ($null -eq $event.durationUs -or $event.durationUs -lt 0)
{
    throw "GetIfEntry2 missing duration evidence."
}

if (-not [string]::IsNullOrEmpty($event.bufferPreview))
{
    throw "GetIfEntry2 exposed bufferPreview: $($event.bufferPreview)"
}

$row = Get-ArgumentByName -Event $event -Name "Row"
if ($row.decodeAlias -ne "pointer" -or $row.captureTiming -ne "pre_post")
{
    throw "GetIfEntry2 Row metadata mismatch: $($row | ConvertTo-Json -Depth 8)"
}

Assert-PointerValue -Value $row.rawValue -Name "GetIfEntry2 Row rawValue"
Assert-PointerValue -Value $row.decodedValue -Name "GetIfEntry2 Row decodedValue"

$eventData = @($adapterEvents + $interfaceEvents) | ConvertTo-Json -Depth 12
if ($eventData -cmatch "GetIfTable2|FriendlyName|Description|PhysicalAddress|PermanentPhysicalAddress|Unicast|Anycast|Multicast|DnsSuffix|Gateway|TransmitLinkSpeed|ReceiveLinkSpeed|InOctets|OutOctets|NetworkGuid|AdapterName|InterfaceAlias|IfDescr|MAC|([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|StackWalk|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 4 IPHLPAPI event appears to expose adapter inventory, interface payload, stack, injection, credential, or byte-preview evidence: $eventData"
}

foreach ($apiName in $SelectedApis)
{
    $installed = @($result.agentMessages | Where-Object {
        $_.messageType -eq "hook_installed" -and
        $_.module -eq $ProviderModule -and
        $_.api -eq $apiName
    })
    if ($installed.Count -lt 1)
    {
        throw "Wave 4 IPHLPAPI hook install evidence is incomplete for $apiName."
    }
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

Write-Host "Wave 4 IPHLPAPI adapter/interface smoke passed: adapterEvents=$($adapterEvents.Count) interfaceEvents=$($interfaceEvents.Count) restored=$($shutdown[0].restoredHooks)"
