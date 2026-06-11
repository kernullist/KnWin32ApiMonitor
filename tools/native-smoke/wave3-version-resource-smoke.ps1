param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

function Assert-IntegerValue
{
    param(
        [string]$Value,
        [string]$Name,
        [bool]$AllowZero = $true
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^[0-9]+$")
    {
        throw "$Name is not a decimal integer: $Value"
    }

    if (-not $AllowZero -and [uint64]$Value -eq 0)
    {
        throw "$Name unexpectedly used zero."
    }
}

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

function Get-EventByApi
{
    param(
        [object]$Result,
        [string]$Api
    )

    $event = @($Result.capturedEvents | Where-Object { $_.api -eq $Api } | Select-Object -First 1)
    if ($event.Count -ne 1)
    {
        throw "Wave 3 version smoke did not capture $Api."
    }

    return $event[0]
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

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Wave 3 version capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 version healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "GetFileVersionInfoSizeW"; Module = "version.dll"; Family = "resource"; Category = "version_info_size_query"; Args = @(
        @{ Name = "lptstrFilename"; Alias = "utf16_string"; Timing = "pre" },
        @{ Name = "lpdwHandle"; Alias = "dword_pointer"; Timing = "post" }
    ) },
    @{ Api = "GetFileVersionInfoW"; Module = "version.dll"; Family = "resource"; Category = "version_info_load"; Args = @(
        @{ Name = "lptstrFilename"; Alias = "utf16_string"; Timing = "pre" },
        @{ Name = "dwHandle"; Alias = "dword_value"; Timing = "pre" },
        @{ Name = "dwLen"; Alias = "byte_count"; Timing = "pre" },
        @{ Name = "lpData"; Alias = "version_info_buffer_pointer"; Timing = "post" }
    ) },
    @{ Api = "VerQueryValueW"; Module = "version.dll"; Family = "resource"; Category = "version_value_query"; Args = @(
        @{ Name = "pBlock"; Alias = "version_info_buffer_pointer"; Timing = "pre" },
        @{ Name = "lpSubBlock"; Alias = "utf16_string"; Timing = "pre" },
        @{ Name = "lplpBuffer"; Alias = "version_info_value_pointer"; Timing = "post" },
        @{ Name = "puLen"; Alias = "dword_pointer"; Timing = "post" }
    ) }
)

foreach ($item in $expected)
{
    $events = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api })
    if ($events.Count -lt 1)
    {
        throw "Wave 3 version smoke did not capture $($item.Api)."
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

$sizeEvent = Get-EventByApi -Result $result -Api "GetFileVersionInfoSizeW"
Assert-IntegerValue -Value $sizeEvent.returnValue -Name "GetFileVersionInfoSizeW returnValue" -AllowZero $false
$sizePath = Get-ArgumentByName -Event $sizeEvent -Name "lptstrFilename"
if ($sizePath.decodedValue -notmatch "kernel32\.dll$")
{
    throw "GetFileVersionInfoSizeW did not include the stable kernel32 path evidence: $($sizePath | ConvertTo-Json -Depth 8)"
}

$sizeHandle = Get-ArgumentByName -Event $sizeEvent -Name "lpdwHandle"
Assert-IntegerValue -Value $sizeHandle.decodedValue -Name "GetFileVersionInfoSizeW lpdwHandle"

$loadEvent = Get-EventByApi -Result $result -Api "GetFileVersionInfoW"
if ($loadEvent.returnValue -ne "1")
{
    throw "GetFileVersionInfoW did not report success: $($loadEvent.returnValue)"
}

$loadPath = Get-ArgumentByName -Event $loadEvent -Name "lptstrFilename"
if ($loadPath.decodedValue -notmatch "kernel32\.dll$")
{
    throw "GetFileVersionInfoW did not include the stable kernel32 path evidence: $($loadPath | ConvertTo-Json -Depth 8)"
}

$loadLength = Get-ArgumentByName -Event $loadEvent -Name "dwLen"
Assert-IntegerValue -Value $loadLength.decodedValue -Name "GetFileVersionInfoW dwLen" -AllowZero $false
$loadData = Get-ArgumentByName -Event $loadEvent -Name "lpData"
Assert-PointerValue -Value $loadData.decodedValue -Name "GetFileVersionInfoW lpData"

$verQueries = @($result.capturedEvents | Where-Object { $_.api -eq "VerQueryValueW" })
if ($verQueries.Count -lt 2)
{
    throw "Wave 3 version smoke expected root and translation VerQueryValueW events."
}

$rootQuery = @($verQueries | Where-Object {
    $subBlock = Get-ArgumentByName -Event $_ -Name "lpSubBlock"
    $subBlock.decodedValue -eq "\"
} | Select-Object -First 1)
if ($rootQuery.Count -ne 1)
{
    throw "Wave 3 version smoke did not capture VerQueryValueW root fixed-info query."
}

if ($rootQuery[0].returnValue -ne "1")
{
    throw "VerQueryValueW root query did not report success: $($rootQuery[0].returnValue)"
}

$rootValue = Get-ArgumentByName -Event $rootQuery[0] -Name "lplpBuffer"
if ($rootValue.decodedValue -notmatch "sig=0xfeef04bd" -or
    $rootValue.decodedValue -notmatch "fileMS=0x[0-9a-fA-F]{8}" -or
    $rootValue.decodedValue -notmatch "fileLS=0x[0-9a-fA-F]{8}" -or
    $rootValue.decodedValue -notmatch "prodMS=0x[0-9a-fA-F]{8}" -or
    $rootValue.decodedValue -notmatch "prodLS=0x[0-9a-fA-F]{8}" -or
    $rootValue.decodedValue -notmatch "mask=0x[0-9a-fA-F]{8}" -or
    $rootValue.decodedValue -notmatch "flags=0x[0-9a-fA-F]{8}" -or
    $rootValue.decodedValue -notmatch "os=0x[0-9a-fA-F]{8}" -or
    $rootValue.decodedValue -notmatch "type=0x[0-9a-fA-F]{8}" -or
    $rootValue.decodedValue -notmatch "sub=0x[0-9a-fA-F]{8}")
{
    throw "VerQueryValueW root query did not include fixed-file-info numeric evidence: $($rootValue | ConvertTo-Json -Depth 8)"
}

$rootLength = Get-ArgumentByName -Event $rootQuery[0] -Name "puLen"
Assert-IntegerValue -Value $rootLength.decodedValue -Name "VerQueryValueW root puLen" -AllowZero $false

$translationQuery = @($verQueries | Where-Object {
    $subBlock = Get-ArgumentByName -Event $_ -Name "lpSubBlock"
    $subBlock.decodedValue -eq "\VarFileInfo\Translation"
} | Select-Object -First 1)
if ($translationQuery.Count -ne 1)
{
    throw "Wave 3 version smoke did not capture VerQueryValueW translation query."
}

if ($translationQuery[0].returnValue -ne "1")
{
    throw "VerQueryValueW translation query did not report success: $($translationQuery[0].returnValue)"
}

$translationValue = Get-ArgumentByName -Event $translationQuery[0] -Name "lplpBuffer"
if ($translationValue.decodedValue -notmatch "translation=lang=0x[0-9a-fA-F]{4},codepage=0x[0-9a-fA-F]{4}")
{
    throw "VerQueryValueW translation query did not include language/codepage evidence: $($translationValue | ConvertTo-Json -Depth 8)"
}

$translationLength = Get-ArgumentByName -Event $translationQuery[0] -Name "puLen"
Assert-IntegerValue -Value $translationLength.decodedValue -Name "VerQueryValueW translation puLen" -AllowZero $false

$versionEvents = @($result.capturedEvents | Where-Object { $_.module -eq "version.dll" })
$versionPayload = $versionEvents | ConvertTo-Json -Depth 12
if ($versionPayload -cmatch "CompanyName|ProductName|FileDescription|OriginalFilename|StringFileInfo|VS_VERSION_INFO|BEGIN CERTIFICATE|PRIVATE KEY|Authorization|Cookie|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|Authenticode|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 version events appear to expose raw resource, PE, file-content, hash, signature, string-table, credential, or byte-preview evidence: $versionPayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 version smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 version-resource smoke passed: events=$($result.capturedEvents.Count) versionEvents=$($versionEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
