param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

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

function Assert-RpcStatusOk
{
    param(
        [string]$Value,
        [string]$Name
    )

    if ($Value -ne "0 (0x00000000)")
    {
        throw "$Name did not return RPC_S_OK: $Value"
    }
}

function Assert-RpcStatusUuidCreate
{
    param(
        [string]$Value,
        [string]$Name
    )

    if ($Value -ne "0 (0x00000000)" -and $Value -ne "1824 (0x00000720)")
    {
        throw "$Name did not return a UUID-producing RPC status: $Value"
    }
}

function Assert-UuidValue
{
    param(
        [string]$Value,
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^UUID=\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
    {
        throw "$Name is not canonical UUID value evidence: $Value"
    }
}

function Assert-UuidString
{
    param(
        [string]$Value,
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    {
        throw "$Name is not canonical UUID string evidence: $Value"
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

function Get-EventByApi
{
    param(
        [object[]]$Events,
        [string]$Api
    )

    $event = @($Events | Where-Object { $_.api -eq $Api } | Select-Object -First 1)
    if ($event.Count -ne 1)
    {
        throw "Wave 3 RPCRT4 UUID smoke did not capture $Api."
    }

    return $event[0]
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
$expectedIds = @(
    @{ Api = "UuidCreate"; Id = 58 },
    @{ Api = "UuidToStringW"; Id = 111 },
    @{ Api = "UuidFromStringW"; Id = 112 }
)

foreach ($expectedId in $expectedIds)
{
    $entry = @($ids.apis | Where-Object { $_.module -eq "rpcrt4.dll" -and $_.name -eq $expectedId.Api } | Select-Object -First 1)
    if ($entry.Count -ne 1 -or $entry[0].id -ne $expectedId.Id)
    {
        throw "Generated ID mismatch for $($expectedId.Api): expected=$($expectedId.Id) actual=$($entry | ConvertTo-Json -Depth 4)"
    }
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Wave 3 RPCRT4 UUID capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 RPCRT4 UUID healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "UuidCreate"; Module = "rpcrt4.dll"; Family = "rpc"; Category = "uuid_create"; Args = @(
        @{ Name = "Uuid"; Alias = "guid_pointer"; Timing = "post" }
    ) },
    @{ Api = "UuidToStringW"; Module = "rpcrt4.dll"; Family = "rpc"; Category = "uuid_to_string"; Args = @(
        @{ Name = "Uuid"; Alias = "guid_pointer"; Timing = "pre" },
        @{ Name = "StringUuid"; Alias = "rpc_string_pointer"; Timing = "post" }
    ) },
    @{ Api = "UuidFromStringW"; Module = "rpcrt4.dll"; Family = "rpc"; Category = "uuid_from_string"; Args = @(
        @{ Name = "StringUuid"; Alias = "utf16_string"; Timing = "pre" },
        @{ Name = "Uuid"; Alias = "guid_pointer"; Timing = "post" }
    ) }
)

foreach ($item in $expected)
{
    $events = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api })
    if ($events.Count -lt 1)
    {
        throw "Wave 3 RPCRT4 UUID smoke did not capture $($item.Api)."
    }

    foreach ($event in $events)
    {
        if ($event.module -ne $item.Module)
        {
            throw "$($item.Api) module mismatch: $($event.module)"
        }

        if ($event.apiFamily -ne $item.Family -or $event.apiCategory -ne $item.Category)
        {
            throw "$($item.Api) metadata mismatch: family=$($event.apiFamily) category=$($event.apiCategory)"
        }

        if ($event.hookPolicy -ne "iat" -or $event.coverageStatus -ne "smoke_verified")
        {
            throw "$($item.Api) hook metadata mismatch: hook=$($event.hookPolicy) coverage=$($event.coverageStatus)"
        }

        if (-not [string]::IsNullOrEmpty($event.bufferPreview))
        {
            throw "$($item.Api) exposed bufferPreview: $($event.bufferPreview)"
        }

        foreach ($expectedArg in $item.Args)
        {
            $argument = Get-ArgumentByName -Event $event -Name $expectedArg.Name
            if ($argument.decodeAlias -ne $expectedArg.Alias -or $argument.captureTiming -ne $expectedArg.Timing)
            {
                throw "$($item.Api) $($expectedArg.Name) metadata mismatch: decode=$($argument.decodeAlias) timing=$($argument.captureTiming)"
            }
        }
    }
}

$uuidEvents = @($result.capturedEvents | Where-Object { $_.api -eq "UuidCreate" -or $_.api -eq "UuidToStringW" -or $_.api -eq "UuidFromStringW" })
if ($uuidEvents.Count -lt 3)
{
    throw "Wave 3 RPCRT4 UUID smoke expected at least three UUID helper events."
}

$uuidCreate = Get-EventByApi -Events $uuidEvents -Api "UuidCreate"
Assert-RpcStatusUuidCreate -Value $uuidCreate.returnValue -Name "UuidCreate"

$createdArg = Get-ArgumentByName -Event $uuidCreate -Name "Uuid"
Assert-PointerValue -Value $createdArg.preCallValue -Name "UuidCreate Uuid"
Assert-UuidValue -Value $createdArg.decodedValue -Name "UuidCreate Uuid"

$uuidToString = Get-EventByApi -Events $uuidEvents -Api "UuidToStringW"
Assert-RpcStatusOk -Value $uuidToString.returnValue -Name "UuidToStringW"

$toStringInputArg = Get-ArgumentByName -Event $uuidToString -Name "Uuid"
Assert-PointerValue -Value $toStringInputArg.preCallValue -Name "UuidToStringW Uuid"
Assert-UuidValue -Value $toStringInputArg.decodedValue -Name "UuidToStringW input Uuid"

$toStringOutputArg = Get-ArgumentByName -Event $uuidToString -Name "StringUuid"
Assert-PointerValue -Value $toStringOutputArg.preCallValue -Name "UuidToStringW StringUuid"
Assert-PointerValue -Value $toStringOutputArg.postCallValue -Name "UuidToStringW returned StringUuid"
Assert-UuidString -Value $toStringOutputArg.decodedValue -Name "UuidToStringW output string"

$createdUuidText = $createdArg.decodedValue -replace "^UUID=\{", "" -replace "\}$", ""
if ($createdUuidText.ToLowerInvariant() -ne $toStringOutputArg.decodedValue.ToLowerInvariant())
{
    throw "UuidCreate and UuidToStringW evidence diverged: created=$createdUuidText string=$($toStringOutputArg.decodedValue)"
}

$uuidFromString = Get-EventByApi -Events $uuidEvents -Api "UuidFromStringW"
Assert-RpcStatusOk -Value $uuidFromString.returnValue -Name "UuidFromStringW"

$fromStringInputArg = Get-ArgumentByName -Event $uuidFromString -Name "StringUuid"
Assert-PointerValue -Value $fromStringInputArg.preCallValue -Name "UuidFromStringW StringUuid"
Assert-UuidString -Value $fromStringInputArg.decodedValue -Name "UuidFromStringW input string"

$fromStringOutputArg = Get-ArgumentByName -Event $uuidFromString -Name "Uuid"
Assert-PointerValue -Value $fromStringOutputArg.preCallValue -Name "UuidFromStringW Uuid"
Assert-UuidValue -Value $fromStringOutputArg.decodedValue -Name "UuidFromStringW output Uuid"

$expectedParsed = "UUID={$($fromStringInputArg.decodedValue)}"
if ($expectedParsed.ToLowerInvariant() -ne $fromStringOutputArg.decodedValue.ToLowerInvariant())
{
    throw "UuidFromStringW input and output evidence diverged: input=$($fromStringInputArg.decodedValue) output=$($fromStringOutputArg.decodedValue)"
}

$uuidStringFree = @($result.capturedEvents | Where-Object {
    $_.api -eq "RpcStringFreeW" -and (($_.arguments | ConvertTo-Json -Depth 8) -match "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
} | Select-Object -First 1)
if ($uuidStringFree.Count -ne 1)
{
    throw "Wave 3 RPCRT4 UUID smoke did not observe RpcStringFreeW cleanup for UuidToStringW output."
}

$uuidPayload = $uuidEvents | ConvertTo-Json -Depth 12
if ($uuidPayload -cmatch "RpcMgmtEp|RpcBindingSetAuth|RpcBindingSetOption|Endpoint|Annotation|ServerPrinc|AuthIdentity|Authn|Authz|NetworkAddr|connect|send|recv|WinHttp|InternetOpenUrl|HttpSend|Authorization|Cookie|Password|Credential|Token|SecurityDescriptor|Sid|Acl|CoCreateInstance|CoGetClassObject|IClassFactory|IUnknown|IDispatch|vtable|Vtbl|IMarshal|IStream|IStorage|IDataObject|Clipboard|DragDrop|Moniker|RunningObjectTable|ROT|Users\\\\|AppData|Downloads|Desktop|Documents|CommandLine|Environment|BEGIN CERTIFICATE|PRIVATE KEY|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 RPCRT4 UUID events appear to expose endpoint, auth, network, COM, credential, path, PE/file/hash, or byte-preview evidence: $uuidPayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 RPCRT4 UUID smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 RPCRT4 UUID helper smoke passed: events=$($result.capturedEvents.Count) uuidEvents=$($uuidEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
