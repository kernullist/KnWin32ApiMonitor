param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "api-ms-win-core-winrt-l1-1-0.dll"

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

function Assert-HResultSucceeded
{
    param(
        [string]$Value,
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^0x[0-9a-fA-F]{8}$")
    {
        throw "$Name did not expose HRESULT hex evidence: $Value"
    }

    $number = [Convert]::ToUInt32($Value.Substring(2), 16)
    if (($number -band 0x80000000) -ne 0)
    {
        throw "$Name returned a failing HRESULT: $Value"
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
        throw "Wave 3 COMBASE WinRT smoke did not capture $Api."
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
$provider = @($ids.modules | Where-Object { $_.name -eq $ProviderModule } | Select-Object -First 1)
if ($provider.Count -ne 1 -or $provider[0].id -ne 17)
{
    throw "Generated provider module mismatch for $ProviderModule`: $($provider | ConvertTo-Json -Depth 4)"
}

$expectedIds = @(
    @{ Api = "RoInitialize"; Id = 113 },
    @{ Api = "RoUninitialize"; Id = 114 },
    @{ Api = "RoGetApartmentIdentifier"; Id = 115 }
)

foreach ($expectedId in $expectedIds)
{
    $entry = @($ids.apis | Where-Object { $_.module -eq $ProviderModule -and $_.name -eq $expectedId.Api } | Select-Object -First 1)
    if ($entry.Count -ne 1 -or $entry[0].id -ne $expectedId.Id)
    {
        throw "Generated ID mismatch for $($expectedId.Api): expected=$($expectedId.Id) actual=$($entry | ConvertTo-Json -Depth 4)"
    }
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Wave 3 COMBASE WinRT capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 COMBASE WinRT healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "RoInitialize"; Family = "com"; Category = "winrt_apartment_init"; Args = @(
        @{ Name = "initType"; Alias = "ro_init_type"; Timing = "pre" }
    ) },
    @{ Api = "RoUninitialize"; Family = "com"; Category = "winrt_apartment_uninit"; Args = @() },
    @{ Api = "RoGetApartmentIdentifier"; Family = "com"; Category = "winrt_apartment_identifier"; Args = @(
        @{ Name = "apartmentIdentifier"; Alias = "uint64_pointer"; Timing = "post" }
    ) }
)

foreach ($item in $expected)
{
    $events = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api })
    if ($events.Count -lt 1)
    {
        throw "Wave 3 COMBASE WinRT smoke did not capture $($item.Api)."
    }

    foreach ($event in $events)
    {
        if ($event.module -ne $ProviderModule)
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

$winrtEvents = @($result.capturedEvents | Where-Object { $_.api -eq "RoInitialize" -or $_.api -eq "RoUninitialize" -or $_.api -eq "RoGetApartmentIdentifier" })
if ($winrtEvents.Count -lt 3)
{
    throw "Wave 3 COMBASE WinRT smoke expected at least three lifecycle events."
}

$roInitialize = Get-EventByApi -Events $winrtEvents -Api "RoInitialize"
Assert-HResultSucceeded -Value $roInitialize.returnValue -Name "RoInitialize"

$initArg = Get-ArgumentByName -Event $roInitialize -Name "initType"
if ($initArg.decodedValue -notmatch "RO_INIT_MULTITHREADED" -or $initArg.rawValue -ne "0x00000001")
{
    throw "RoInitialize did not include expected init type evidence: $($initArg | ConvertTo-Json -Depth 8)"
}

$roApartment = Get-EventByApi -Events $winrtEvents -Api "RoGetApartmentIdentifier"
Assert-HResultSucceeded -Value $roApartment.returnValue -Name "RoGetApartmentIdentifier"

$apartmentArg = Get-ArgumentByName -Event $roApartment -Name "apartmentIdentifier"
Assert-PointerValue -Value $apartmentArg.rawValue -Name "RoGetApartmentIdentifier apartmentIdentifier"
if ($apartmentArg.decodeStatus -ne "decoded" -or $apartmentArg.postCallValue -notmatch "^\d+$" -or $apartmentArg.decodedValue -notmatch "value=\d+")
{
    throw "RoGetApartmentIdentifier did not include decoded UINT64 evidence: $($apartmentArg | ConvertTo-Json -Depth 8)"
}

$roUninitialize = Get-EventByApi -Events $winrtEvents -Api "RoUninitialize"
if ($roUninitialize.returnValue -ne "void" -or @($roUninitialize.arguments).Count -ne 0)
{
    throw "RoUninitialize did not render as void lifecycle event: $($roUninitialize | ConvertTo-Json -Depth 8)"
}

$winrtPayload = $winrtEvents | ConvertTo-Json -Depth 12
if ($winrtPayload -cmatch "RoGetActivationFactory|RoActivateInstance|RoRegisterActivationFactories|RoRevokeActivationFactories|WindowsCreateString|WindowsGetStringRawBuffer|HSTRING|RuntimeClass|ActivationFactory|IActivationFactory|IInspectable|IClassFactory|IUnknown|IDispatch|vtable|Vtbl|IMarshal|IStream|IStorage|IDataObject|Clipboard|DragDrop|Moniker|RunningObjectTable|ROT|RestrictedError|ErrorInfo|Users\\\\|AppData|Downloads|Desktop|Documents|CommandLine|Environment|Password|Credential|Token|SecurityDescriptor|Sid|Acl|BEGIN CERTIFICATE|PRIVATE KEY|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 COMBASE WinRT events appear to expose activation, HSTRING, COM object, error-info, credential, path, PE/file/hash, or byte-preview evidence: $winrtPayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 COMBASE WinRT smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 COMBASE WinRT lifecycle smoke passed: provider=$ProviderModule events=$($result.capturedEvents.Count) winrtEvents=$($winrtEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
