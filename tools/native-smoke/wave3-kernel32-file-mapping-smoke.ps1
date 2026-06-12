param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "kernel32.dll"
$SelectedApis = @(
    "CreateFileMappingW",
    "OpenFileMappingW",
    "MapViewOfFile",
    "UnmapViewOfFile"
)

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

function Get-EventByApi
{
    param(
        [object[]]$Events,
        [string]$Api
    )

    $event = @($Events | Where-Object { $_.api -eq $Api } | Select-Object -First 1)
    if ($event.Count -ne 1)
    {
        throw "Wave 3 KERNEL32 file-mapping smoke did not capture $Api."
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
if ($provider.Count -ne 1 -or $provider[0].id -ne 1)
{
    throw "Generated provider module mismatch for $ProviderModule`: $($provider | ConvertTo-Json -Depth 4)"
}

$expectedIds = @(
    @{ Api = "CreateFileMappingW"; Id = 136 },
    @{ Api = "OpenFileMappingW"; Id = 137 },
    @{ Api = "MapViewOfFile"; Id = 138 },
    @{ Api = "UnmapViewOfFile"; Id = 139 }
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
    throw "Wave 3 KERNEL32 file-mapping capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 KERNEL32 file-mapping healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "CreateFileMappingW"; Family = "memory"; Category = "file_mapping_create"; Args = @(
        @{ Name = "hFile"; Alias = "handle"; Timing = "pre" },
        @{ Name = "lpFileMappingAttributes"; Alias = "pointer"; Timing = "pre" },
        @{ Name = "flProtect"; Alias = "file_mapping_protection_flags"; Timing = "pre" },
        @{ Name = "dwMaximumSizeHigh"; Alias = "file_mapping_size_high"; Timing = "pre" },
        @{ Name = "dwMaximumSizeLow"; Alias = "file_mapping_size_low"; Timing = "pre" },
        @{ Name = "lpName"; Alias = "file_mapping_name_pointer"; Timing = "pre" }
    ) },
    @{ Api = "OpenFileMappingW"; Family = "memory"; Category = "file_mapping_open"; Args = @(
        @{ Name = "dwDesiredAccess"; Alias = "file_mapping_access_flags"; Timing = "pre" },
        @{ Name = "bInheritHandle"; Alias = "dword_value"; Timing = "pre" },
        @{ Name = "lpName"; Alias = "file_mapping_name_pointer"; Timing = "pre" }
    ) },
    @{ Api = "MapViewOfFile"; Family = "memory"; Category = "file_mapping_map_view"; Args = @(
        @{ Name = "hFileMappingObject"; Alias = "handle"; Timing = "pre" },
        @{ Name = "dwDesiredAccess"; Alias = "file_mapping_access_flags"; Timing = "pre" },
        @{ Name = "dwFileOffsetHigh"; Alias = "file_mapping_offset_high"; Timing = "pre" },
        @{ Name = "dwFileOffsetLow"; Alias = "file_mapping_offset_low"; Timing = "pre" },
        @{ Name = "dwNumberOfBytesToMap"; Alias = "file_mapping_view_size"; Timing = "pre" }
    ) },
    @{ Api = "UnmapViewOfFile"; Family = "memory"; Category = "file_mapping_unmap_view"; Args = @(
        @{ Name = "lpBaseAddress"; Alias = "mapped_view_pointer"; Timing = "pre" }
    ) }
)

foreach ($item in $expected)
{
    $event = Get-EventByApi -Events $result.capturedEvents -Api $item.Api
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

$createMapping = Get-EventByApi -Events $result.capturedEvents -Api "CreateFileMappingW"
Assert-PointerValue -Value $createMapping.returnValue -Name "CreateFileMappingW returnValue"
$backingFile = Get-ArgumentByName -Event $createMapping -Name "hFile"
if ($backingFile.decodedValue -notmatch "^0x[fF]+$")
{
    throw "CreateFileMappingW did not report INVALID_HANDLE_VALUE backing handle: $($backingFile | ConvertTo-Json -Depth 8)"
}
$mappingAttributes = Get-ArgumentByName -Event $createMapping -Name "lpFileMappingAttributes"
Assert-PointerValue -Value $mappingAttributes.decodedValue -Name "CreateFileMappingW lpFileMappingAttributes" -AllowNull $true
$mappingProtect = Get-ArgumentByName -Event $createMapping -Name "flProtect"
if ($mappingProtect.decodedValue -notmatch "PAGE_READWRITE")
{
    throw "CreateFileMappingW did not decode PAGE_READWRITE: $($mappingProtect | ConvertTo-Json -Depth 8)"
}
$mappingSizeHigh = Get-ArgumentByName -Event $createMapping -Name "dwMaximumSizeHigh"
if ($mappingSizeHigh.decodedValue -notmatch "^0")
{
    throw "CreateFileMappingW high size mismatch: $($mappingSizeHigh | ConvertTo-Json -Depth 8)"
}
$mappingSizeLow = Get-ArgumentByName -Event $createMapping -Name "dwMaximumSizeLow"
if ($mappingSizeLow.decodedValue -notmatch "4096" -or $mappingSizeLow.decodedValue -notmatch "0x00001000")
{
    throw "CreateFileMappingW low size mismatch: $($mappingSizeLow | ConvertTo-Json -Depth 8)"
}
$createMappingName = Get-ArgumentByName -Event $createMapping -Name "lpName"
Assert-PointerValue -Value $createMappingName.decodedValue -Name "CreateFileMappingW lpName"

$openMapping = Get-EventByApi -Events $result.capturedEvents -Api "OpenFileMappingW"
Assert-PointerValue -Value $openMapping.returnValue -Name "OpenFileMappingW returnValue"
$mappingAccess = Get-ArgumentByName -Event $openMapping -Name "dwDesiredAccess"
if ($mappingAccess.decodedValue -notmatch "FILE_MAP_READ" -or $mappingAccess.decodedValue -notmatch "FILE_MAP_WRITE")
{
    throw "OpenFileMappingW did not decode mapping access flags: $($mappingAccess | ConvertTo-Json -Depth 8)"
}
$mappingInherit = Get-ArgumentByName -Event $openMapping -Name "bInheritHandle"
if ($mappingInherit.decodedValue -ne "FALSE")
{
    throw "OpenFileMappingW inherit flag mismatch: $($mappingInherit | ConvertTo-Json -Depth 8)"
}
$openMappingName = Get-ArgumentByName -Event $openMapping -Name "lpName"
Assert-PointerValue -Value $openMappingName.decodedValue -Name "OpenFileMappingW lpName"

$mapView = Get-EventByApi -Events $result.capturedEvents -Api "MapViewOfFile"
Assert-PointerValue -Value $mapView.returnValue -Name "MapViewOfFile returnValue"
$mapHandle = Get-ArgumentByName -Event $mapView -Name "hFileMappingObject"
Assert-PointerValue -Value $mapHandle.decodedValue -Name "MapViewOfFile hFileMappingObject"
$mapAccess = Get-ArgumentByName -Event $mapView -Name "dwDesiredAccess"
if ($mapAccess.decodedValue -notmatch "FILE_MAP_WRITE")
{
    throw "MapViewOfFile did not decode FILE_MAP_WRITE: $($mapAccess | ConvertTo-Json -Depth 8)"
}
$offsetHigh = Get-ArgumentByName -Event $mapView -Name "dwFileOffsetHigh"
$offsetLow = Get-ArgumentByName -Event $mapView -Name "dwFileOffsetLow"
if ($offsetHigh.decodedValue -notmatch "^0" -or $offsetLow.decodedValue -notmatch "^0")
{
    throw "MapViewOfFile offset mismatch: high=$($offsetHigh | ConvertTo-Json -Depth 8) low=$($offsetLow | ConvertTo-Json -Depth 8)"
}
$bytesToMap = Get-ArgumentByName -Event $mapView -Name "dwNumberOfBytesToMap"
if ($bytesToMap.decodedValue -ne "4096")
{
    throw "MapViewOfFile byte count mismatch: $($bytesToMap | ConvertTo-Json -Depth 8)"
}

$unmapView = Get-EventByApi -Events $result.capturedEvents -Api "UnmapViewOfFile"
if ($unmapView.returnValue -ne "TRUE")
{
    throw "UnmapViewOfFile return mismatch: $($unmapView | ConvertTo-Json -Depth 8)"
}
$baseAddress = Get-ArgumentByName -Event $unmapView -Name "lpBaseAddress"
Assert-PointerValue -Value $baseAddress.decodedValue -Name "UnmapViewOfFile lpBaseAddress"

$mappingEvents = @($result.capturedEvents | Where-Object { $SelectedApis -contains $_.api })
if ($mappingEvents.Count -lt $SelectedApis.Count)
{
    throw "Wave 3 KERNEL32 file-mapping capture did not include all selected events."
}

$mappingPayload = $mappingEvents | ConvertTo-Json -Depth 12
if ($mappingPayload -cmatch "KnMonFileMappingProbe|Global\\|Local\\|BaseNamedObjects|ObjectName|ObjectDirectory|ObjectManager|SecurityDescriptor|SECURITY_DESCRIPTOR|SID|ACL|TOKEN_|Privilege|Integrity|DuplicateHandle|NtMapViewOfSection|VirtualAllocEx|VirtualFreeEx|VirtualProtectEx|ReadProcessMemory|WriteProcessMemory|CreateRemoteThread|QueueUserAPC|NtQueueApcThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|TerminateThread|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 KERNEL32 file-mapping events appear to expose mapping-name, namespace, mapped memory, security, stack, injection, PE/file/hash, credential, or byte-preview evidence: $mappingPayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 KERNEL32 file-mapping smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 KERNEL32 file-mapping smoke passed: events=$($result.capturedEvents.Count) mappingEvents=$($mappingEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
