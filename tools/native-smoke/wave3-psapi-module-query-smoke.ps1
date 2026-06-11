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
        throw "Wave 3 PSAPI smoke did not capture $Api."
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
    throw "Wave 3 PSAPI capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 PSAPI healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "EnumProcessModules"; Module = "psapi.dll"; Family = "module"; Category = "process_module_enumeration"; Args = @(
        @{ Name = "hProcess"; Alias = "handle"; Timing = "pre" },
        @{ Name = "lphModule"; Alias = "module_handle_array_pointer"; Timing = "post" },
        @{ Name = "cb"; Alias = "byte_count"; Timing = "pre" },
        @{ Name = "lpcbNeeded"; Alias = "dword_pointer"; Timing = "post" }
    ) },
    @{ Api = "GetModuleInformation"; Module = "psapi.dll"; Family = "module"; Category = "process_module_information"; Args = @(
        @{ Name = "hProcess"; Alias = "handle"; Timing = "pre" },
        @{ Name = "hModule"; Alias = "module_handle"; Timing = "pre" },
        @{ Name = "lpmodinfo"; Alias = "module_info_pointer"; Timing = "post" },
        @{ Name = "cb"; Alias = "byte_count"; Timing = "pre" }
    ) },
    @{ Api = "GetModuleBaseNameW"; Module = "psapi.dll"; Family = "module"; Category = "process_module_base_name"; Args = @(
        @{ Name = "hProcess"; Alias = "handle"; Timing = "pre" },
        @{ Name = "hModule"; Alias = "module_handle"; Timing = "pre" },
        @{ Name = "lpBaseName"; Alias = "utf16_string"; Timing = "post" },
        @{ Name = "nSize"; Alias = "byte_count"; Timing = "pre" }
    ) },
    @{ Api = "GetModuleFileNameExW"; Module = "psapi.dll"; Family = "module"; Category = "process_module_file_name"; Args = @(
        @{ Name = "hProcess"; Alias = "handle"; Timing = "pre" },
        @{ Name = "hModule"; Alias = "module_handle"; Timing = "pre" },
        @{ Name = "lpFilename"; Alias = "utf16_string"; Timing = "post" },
        @{ Name = "nSize"; Alias = "byte_count"; Timing = "pre" }
    ) }
)

foreach ($item in $expected)
{
    $event = Get-EventByApi -Result $result -Api $item.Api
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

$enumModules = Get-EventByApi -Result $result -Api "EnumProcessModules"
if ($enumModules.returnValue -ne "1")
{
    throw "EnumProcessModules did not report success: $($enumModules.returnValue)"
}

$enumProcess = Get-ArgumentByName -Event $enumModules -Name "hProcess"
Assert-PointerValue -Value $enumProcess.decodedValue -Name "EnumProcessModules hProcess"
$moduleArray = Get-ArgumentByName -Event $enumModules -Name "lphModule"
if ($moduleArray.decodedValue -notmatch "^firstModule=0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "EnumProcessModules did not include bounded first-module evidence: $($moduleArray | ConvertTo-Json -Depth 8)"
}

$requestedBytes = Get-ArgumentByName -Event $enumModules -Name "cb"
Assert-IntegerValue -Value $requestedBytes.decodedValue -Name "EnumProcessModules cb" -AllowZero $false
$neededBytes = Get-ArgumentByName -Event $enumModules -Name "lpcbNeeded"
Assert-IntegerValue -Value $neededBytes.decodedValue -Name "EnumProcessModules lpcbNeeded" -AllowZero $false

$moduleInfo = Get-EventByApi -Result $result -Api "GetModuleInformation"
if ($moduleInfo.returnValue -ne "1")
{
    throw "GetModuleInformation did not report success: $($moduleInfo.returnValue)"
}

$infoArgument = Get-ArgumentByName -Event $moduleInfo -Name "lpmodinfo"
if ($infoArgument.decodedValue -notmatch "base=0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*" -or
    $infoArgument.decodedValue -notmatch "size=[1-9][0-9]*" -or
    $infoArgument.decodedValue -notmatch "entry=0x[0-9a-fA-F]+")
{
    throw "GetModuleInformation did not include MODULEINFO numeric evidence: $($infoArgument | ConvertTo-Json -Depth 8)"
}

$baseName = Get-EventByApi -Result $result -Api "GetModuleBaseNameW"
Assert-IntegerValue -Value $baseName.returnValue -Name "GetModuleBaseNameW returnValue" -AllowZero $false
$baseNameArgument = Get-ArgumentByName -Event $baseName -Name "lpBaseName"
if ($baseNameArgument.decodedValue -notmatch "knmon-sample-fileio\.exe")
{
    throw "GetModuleBaseNameW did not include sample base name evidence: $($baseNameArgument | ConvertTo-Json -Depth 8)"
}

$fileName = Get-EventByApi -Result $result -Api "GetModuleFileNameExW"
Assert-IntegerValue -Value $fileName.returnValue -Name "GetModuleFileNameExW returnValue" -AllowZero $false
$fileNameArgument = Get-ArgumentByName -Event $fileName -Name "lpFilename"
if ($fileNameArgument.decodedValue -notmatch "knmon-sample-fileio\.exe")
{
    throw "GetModuleFileNameExW did not include sample path evidence: $($fileNameArgument | ConvertTo-Json -Depth 8)"
}

$psapiEvents = @($result.capturedEvents | Where-Object { $_.module -eq "psapi.dll" })
if ($psapiEvents.Count -lt 4)
{
    throw "Wave 3 PSAPI capture did not include all module-query events."
}

$psapiPayload = $psapiEvents | ConvertTo-Json -Depth 12
if ($psapiPayload -cmatch "BEGIN CERTIFICATE|PRIVATE KEY|Authorization|Cookie|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|Authenticode|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 PSAPI events appear to expose PE, module-memory, file-content, hash, signature, credential, or byte-preview evidence: $psapiPayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 PSAPI smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 PSAPI module-query smoke passed: events=$($result.capturedEvents.Count) psapiEvents=$($psapiEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
