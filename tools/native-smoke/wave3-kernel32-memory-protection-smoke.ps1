param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "kernel32.dll"

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

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^[0-9]+$")
    {
        throw "$Name is not a decimal integer: $Value"
    }

    if (-not $AllowZero -and [uint64]$Value -eq 0)
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
        throw "Wave 3 KERNEL32 memory smoke did not capture $Api."
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
    @{ Api = "VirtualAlloc"; Id = 116 },
    @{ Api = "VirtualFree"; Id = 117 },
    @{ Api = "VirtualProtect"; Id = 118 },
    @{ Api = "VirtualQuery"; Id = 119 }
)

$memoryProtectionApis = @(
    "VirtualAlloc",
    "VirtualFree",
    "VirtualProtect",
    "VirtualQuery"
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
    throw "Wave 3 KERNEL32 memory capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 KERNEL32 memory healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "VirtualAlloc"; Family = "memory"; Category = "memory_allocate"; Args = @(
        @{ Name = "lpAddress"; Alias = "pointer"; Timing = "pre" },
        @{ Name = "dwSize"; Alias = "byte_count"; Timing = "pre" },
        @{ Name = "flAllocationType"; Alias = "memory_allocation_type"; Timing = "pre" },
        @{ Name = "flProtect"; Alias = "memory_protection_flags"; Timing = "pre" }
    ) },
    @{ Api = "VirtualFree"; Family = "memory"; Category = "memory_free"; Args = @(
        @{ Name = "lpAddress"; Alias = "pointer"; Timing = "pre" },
        @{ Name = "dwSize"; Alias = "byte_count"; Timing = "pre" },
        @{ Name = "dwFreeType"; Alias = "memory_free_type"; Timing = "pre" }
    ) },
    @{ Api = "VirtualProtect"; Family = "memory"; Category = "memory_protect"; Args = @(
        @{ Name = "lpAddress"; Alias = "pointer"; Timing = "pre" },
        @{ Name = "dwSize"; Alias = "byte_count"; Timing = "pre" },
        @{ Name = "flNewProtect"; Alias = "memory_protection_flags"; Timing = "pre" },
        @{ Name = "lpflOldProtect"; Alias = "dword_pointer"; Timing = "post" }
    ) },
    @{ Api = "VirtualQuery"; Family = "memory"; Category = "memory_query"; Args = @(
        @{ Name = "lpAddress"; Alias = "pointer"; Timing = "pre" },
        @{ Name = "lpBuffer"; Alias = "memory_basic_information_pointer"; Timing = "post" },
        @{ Name = "dwLength"; Alias = "byte_count"; Timing = "pre" }
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

$virtualAlloc = Get-EventByApi -Events $result.capturedEvents -Api "VirtualAlloc"
Assert-PointerValue -Value $virtualAlloc.returnValue -Name "VirtualAlloc returnValue"
$allocAddress = Get-ArgumentByName -Event $virtualAlloc -Name "lpAddress"
Assert-PointerValue -Value $allocAddress.decodedValue -Name "VirtualAlloc lpAddress" -AllowNull $true
$allocSize = Get-ArgumentByName -Event $virtualAlloc -Name "dwSize"
if ($allocSize.decodedValue -ne "12288")
{
    throw "VirtualAlloc did not include expected allocation size: $($allocSize | ConvertTo-Json -Depth 8)"
}

$allocType = Get-ArgumentByName -Event $virtualAlloc -Name "flAllocationType"
if ($allocType.decodedValue -notmatch "MEM_COMMIT" -or $allocType.decodedValue -notmatch "MEM_RESERVE")
{
    throw "VirtualAlloc did not decode allocation flags: $($allocType | ConvertTo-Json -Depth 8)"
}

$allocProtect = Get-ArgumentByName -Event $virtualAlloc -Name "flProtect"
if ($allocProtect.decodedValue -notmatch "PAGE_READWRITE")
{
    throw "VirtualAlloc did not decode protection flags: $($allocProtect | ConvertTo-Json -Depth 8)"
}

$virtualProtect = Get-EventByApi -Events $result.capturedEvents -Api "VirtualProtect"
if ($virtualProtect.returnValue -ne "TRUE")
{
    throw "VirtualProtect did not report success: $($virtualProtect.returnValue)"
}

$newProtect = Get-ArgumentByName -Event $virtualProtect -Name "flNewProtect"
if ($newProtect.decodedValue -notmatch "PAGE_READONLY")
{
    throw "VirtualProtect did not decode new protection: $($newProtect | ConvertTo-Json -Depth 8)"
}

$oldProtect = Get-ArgumentByName -Event $virtualProtect -Name "lpflOldProtect"
if ($oldProtect.decodeStatus -ne "decoded" -or $oldProtect.postCallValue -ne "0x00000004" -or $oldProtect.decodedValue -notmatch "PAGE_READWRITE")
{
    throw "VirtualProtect did not decode old protection: $($oldProtect | ConvertTo-Json -Depth 8)"
}

$virtualQuery = Get-EventByApi -Events $result.capturedEvents -Api "VirtualQuery"
Assert-IntegerValue -Value $virtualQuery.returnValue -Name "VirtualQuery returnValue" -AllowZero $false
$queryBuffer = Get-ArgumentByName -Event $virtualQuery -Name "lpBuffer"
if ($queryBuffer.decodeStatus -ne "decoded" -or
    $queryBuffer.decodedValue -notmatch "base=0x" -or
    $queryBuffer.decodedValue -notmatch "allocationBase=0x" -or
    $queryBuffer.decodedValue -notmatch "regionSize=[1-9][0-9]*" -or
    $queryBuffer.decodedValue -notmatch "MEM_COMMIT" -or
    $queryBuffer.decodedValue -notmatch "PAGE_READONLY" -or
    $queryBuffer.decodedValue -notmatch "MEM_PRIVATE")
{
    throw "VirtualQuery did not decode MEMORY_BASIC_INFORMATION metadata: $($queryBuffer | ConvertTo-Json -Depth 8)"
}

$queryLength = Get-ArgumentByName -Event $virtualQuery -Name "dwLength"
Assert-IntegerValue -Value $queryLength.decodedValue -Name "VirtualQuery dwLength" -AllowZero $false

$virtualFree = Get-EventByApi -Events $result.capturedEvents -Api "VirtualFree"
if ($virtualFree.returnValue -ne "TRUE")
{
    throw "VirtualFree did not report success: $($virtualFree.returnValue)"
}

$freeType = Get-ArgumentByName -Event $virtualFree -Name "dwFreeType"
if ($freeType.decodedValue -notmatch "MEM_RELEASE")
{
    throw "VirtualFree did not decode free type: $($freeType | ConvertTo-Json -Depth 8)"
}

$memoryEvents = @($result.capturedEvents | Where-Object { $memoryProtectionApis -contains $_.api })
if ($memoryEvents.Count -lt 4)
{
    throw "Wave 3 KERNEL32 memory capture did not include all memory events."
}

$memoryPayload = $memoryEvents | ConvertTo-Json -Depth 12
if ($memoryPayload -cmatch "VirtualAllocEx|VirtualFreeEx|VirtualProtectEx|ReadProcessMemory|WriteProcessMemory|CreateRemoteThread|QueueUserAPC|NtMapViewOfSection|MapViewOfFile|SECTION_|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 KERNEL32 memory events appear to expose remote-memory, injection, file/PE/hash, credential, or byte-preview evidence: $memoryPayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 KERNEL32 memory smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 KERNEL32 memory-protection smoke passed: events=$($result.capturedEvents.Count) memoryEvents=$($memoryEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
