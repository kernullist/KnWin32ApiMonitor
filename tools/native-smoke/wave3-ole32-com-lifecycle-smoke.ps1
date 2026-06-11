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

function Assert-IntegerValue
{
    param(
        [string]$Value,
        [string]$Name,
        [bool]$AllowZero = $true
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^-?[0-9]+$")
    {
        throw "$Name is not an integer value: $Value"
    }

    if (-not $AllowZero -and [int]$Value -eq 0)
    {
        throw "$Name unexpectedly used zero."
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
        throw "Wave 3 OLE32 smoke did not capture $Api."
    }

    return $event[0]
}

function Assert-GuidText
{
    param(
        [string]$Value,
        [string]$Name,
        [bool]$AllowPrefix = $false
    )

    $pattern = if ($AllowPrefix)
    {
        "^GUID=\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$"
    }
    else
    {
        "^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$"
    }

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch $pattern)
    {
        throw "$Name is not canonical GUID evidence: $Value"
    }
}

if (-not (Test-Path -LiteralPath $HelperPath))
{
    throw "Helper not found: $HelperPath"
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Wave 3 OLE32 capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 OLE32 healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "CoInitializeEx"; Module = "ole32.dll"; Family = "com"; Category = "com_apartment_init"; Args = @(
        @{ Name = "pvReserved"; Alias = "pointer"; Timing = "pre" },
        @{ Name = "dwCoInit"; Alias = "com_init_flags"; Timing = "pre" }
    ) },
    @{ Api = "CoUninitialize"; Module = "ole32.dll"; Family = "com"; Category = "com_apartment_uninit"; Args = @() },
    @{ Api = "CoCreateGuid"; Module = "ole32.dll"; Family = "com"; Category = "com_guid_create"; Args = @(
        @{ Name = "pguid"; Alias = "guid_pointer"; Timing = "post" }
    ) },
    @{ Api = "StringFromGUID2"; Module = "ole32.dll"; Family = "com"; Category = "com_guid_string"; Args = @(
        @{ Name = "rguid"; Alias = "guid_pointer"; Timing = "pre" },
        @{ Name = "lpsz"; Alias = "guid_string_buffer_pointer"; Timing = "post" },
        @{ Name = "cchMax"; Alias = "dword_value"; Timing = "pre" }
    ) }
)

foreach ($item in $expected)
{
    $events = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api })
    if ($events.Count -lt 1)
    {
        throw "Wave 3 OLE32 smoke did not capture $($item.Api)."
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

$comEvents = @($result.capturedEvents | Where-Object { $_.module -eq "ole32.dll" })
if ($comEvents.Count -lt 4)
{
    throw "Wave 3 OLE32 smoke expected at least four COM lifecycle events."
}

$initEvent = Get-EventByApi -Events $comEvents -Api "CoInitializeEx"
if ($initEvent.returnValue -ne "0x00000000" -and $initEvent.returnValue -ne "0x00000001")
{
    throw "CoInitializeEx returned unexpected HRESULT: $($initEvent.returnValue)"
}

$reservedArg = Get-ArgumentByName -Event $initEvent -Name "pvReserved"
Assert-PointerValue -Value $reservedArg.decodedValue -Name "CoInitializeEx pvReserved" -AllowNull $true

$initFlagsArg = Get-ArgumentByName -Event $initEvent -Name "dwCoInit"
if ($initFlagsArg.decodedValue -notmatch "COINIT_MULTITHREADED")
{
    throw "CoInitializeEx did not decode COM init flags: $($initFlagsArg | ConvertTo-Json -Depth 8)"
}

$uninitEvent = Get-EventByApi -Events $comEvents -Api "CoUninitialize"
if ($uninitEvent.returnValue -ne "void" -or @($uninitEvent.arguments).Count -ne 0)
{
    throw "CoUninitialize should be lifecycle-only with no arguments: $($uninitEvent | ConvertTo-Json -Depth 8)"
}

$createGuidEvent = Get-EventByApi -Events $comEvents -Api "CoCreateGuid"
if ($createGuidEvent.returnValue -ne "0x00000000")
{
    throw "CoCreateGuid did not report S_OK: $($createGuidEvent.returnValue)"
}

$createdGuidArg = Get-ArgumentByName -Event $createGuidEvent -Name "pguid"
Assert-PointerValue -Value $createdGuidArg.preCallValue -Name "CoCreateGuid pguid"
Assert-GuidText -Value $createdGuidArg.decodedValue -Name "CoCreateGuid GUID" -AllowPrefix $true

$stringGuidEvent = Get-EventByApi -Events $comEvents -Api "StringFromGUID2"
Assert-IntegerValue -Value $stringGuidEvent.returnValue -Name "StringFromGUID2 returnValue" -AllowZero $false

$inputGuidArg = Get-ArgumentByName -Event $stringGuidEvent -Name "rguid"
Assert-PointerValue -Value $inputGuidArg.preCallValue -Name "StringFromGUID2 rguid"
Assert-GuidText -Value $inputGuidArg.decodedValue -Name "StringFromGUID2 input GUID" -AllowPrefix $true

$stringArg = Get-ArgumentByName -Event $stringGuidEvent -Name "lpsz"
Assert-PointerValue -Value $stringArg.preCallValue -Name "StringFromGUID2 lpsz"
Assert-GuidText -Value $stringArg.decodedValue -Name "StringFromGUID2 output GUID"

$cchMaxArg = Get-ArgumentByName -Event $stringGuidEvent -Name "cchMax"
if ($cchMaxArg.decodedValue -ne "64")
{
    throw "StringFromGUID2 used unexpected cchMax: $($cchMaxArg.decodedValue)"
}

$createdGuid = $createdGuidArg.decodedValue -replace "^GUID=", ""
if ($createdGuid.ToLowerInvariant() -ne $stringArg.decodedValue.ToLowerInvariant())
{
    throw "CoCreateGuid and StringFromGUID2 evidence diverged: created=$createdGuid string=$($stringArg.decodedValue)"
}

$olePayload = $comEvents | ConvertTo-Json -Depth 12
if ($olePayload -cmatch "CoCreateInstance|CoGetClassObject|CoGetObject|IClassFactory|IUnknown|IDispatch|vtable|Vtbl|IMarshal|IStream|IStorage|IDataObject|Clipboard|DragDrop|Moniker|RunningObjectTable|ROT|ShellExecute|PIDL|ITEMIDLIST|Users\\\\|AppData|Downloads|Desktop|Documents|Recent|Startup|SendTo|CommandLine|Environment|BEGIN CERTIFICATE|PRIVATE KEY|Authorization|Cookie|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 OLE32 events appear to expose activation, object, marshaling, storage, user-path, credential, PE/file/hash, or byte-preview evidence: $olePayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 OLE32 smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 OLE32 COM lifecycle smoke passed: events=$($result.capturedEvents.Count) comEvents=$($comEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
