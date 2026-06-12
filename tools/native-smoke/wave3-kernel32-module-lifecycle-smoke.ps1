param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "kernel32.dll"
$SelectedApis = @(
    "GetModuleHandleW",
    "GetModuleHandleExW",
    "GetModuleFileNameW",
    "FreeLibrary"
)

function Assert-PointerShape
{
    param(
        [string]$Value,
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^0x[0-9a-fA-F]+$")
    {
        throw "$Name is not a pointer value: $Value"
    }
}

function Assert-NonNullPointer
{
    param(
        [string]$Value,
        [string]$Name
    )

    Assert-PointerShape -Value $Value -Name $Name
    if ($Value -match "^0x0+$")
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
if ($provider.Count -ne 1 -or $provider[0].id -ne 1)
{
    throw "Generated provider module mismatch for $ProviderModule`: $($provider | ConvertTo-Json -Depth 4)"
}

$expectedIds = @(
    @{ Api = "GetModuleHandleW"; Id = 150 },
    @{ Api = "GetModuleHandleExW"; Id = 151 },
    @{ Api = "GetModuleFileNameW"; Id = 152 },
    @{ Api = "FreeLibrary"; Id = 153 }
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
    throw "Wave 3 KERNEL32 module lifecycle capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 KERNEL32 module lifecycle healthy capture dropped transport events: $droppedEvents"
}

$moduleEvents = @($result.capturedEvents | Where-Object { $SelectedApis -contains $_.api })
if ($moduleEvents.Count -lt $SelectedApis.Count)
{
    throw "Wave 3 KERNEL32 module lifecycle capture did not include all selected events."
}

$expected = @(
    @{ Api = "GetModuleHandleW"; Family = "module"; Category = "module_lookup"; Args = @(
        @{ Name = "lpModuleName"; Alias = "module_lookup_name"; Timing = "pre" }
    ) },
    @{ Api = "GetModuleHandleExW"; Family = "module"; Category = "module_lookup"; Args = @(
        @{ Name = "dwFlags"; Alias = "get_module_handle_ex_flags"; Timing = "pre" },
        @{ Name = "lpModuleName"; Alias = "module_lookup_name"; Timing = "pre" },
        @{ Name = "phModule"; Alias = "module_handle_pointer"; Timing = "post" }
    ) },
    @{ Api = "GetModuleFileNameW"; Family = "module"; Category = "module_path"; Args = @(
        @{ Name = "hModule"; Alias = "module_handle"; Timing = "pre" },
        @{ Name = "lpFilename"; Alias = "module_file_name_buffer_pointer"; Timing = "post" },
        @{ Name = "nSize"; Alias = "byte_count"; Timing = "pre" }
    ) },
    @{ Api = "FreeLibrary"; Family = "module"; Category = "module_lifecycle"; Args = @(
        @{ Name = "hLibModule"; Alias = "module_handle"; Timing = "pre" }
    ) }
)

foreach ($item in $expected)
{
    $events = @($moduleEvents | Where-Object { $_.api -eq $item.Api })
    if ($events.Count -lt 1)
    {
        throw "Wave 3 KERNEL32 module lifecycle smoke did not capture $($item.Api)."
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

        if ($null -eq $event.durationUs -or $event.durationUs -lt 0)
        {
            throw "$($item.Api) missing duration evidence."
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

$moduleHandle = @($moduleEvents | Where-Object {
    $_.api -eq "GetModuleHandleW" -and
    (Get-ArgumentByName -Event $_ -Name "lpModuleName").decodedValue -ieq "version.dll"
} | Select-Object -First 1)
if ($moduleHandle.Count -ne 1)
{
    throw "GetModuleHandleW did not capture version.dll lookup."
}

Assert-NonNullPointer -Value $moduleHandle[0].returnValue -Name "GetModuleHandleW returnValue"

$moduleHandleEx = @($moduleEvents | Where-Object {
    $_.api -eq "GetModuleHandleExW" -and
    (Get-ArgumentByName -Event $_ -Name "lpModuleName").decodedValue -ieq "version.dll"
} | Select-Object -First 1)
if ($moduleHandleEx.Count -ne 1 -or $moduleHandleEx[0].returnValue -ne "TRUE")
{
    throw "GetModuleHandleExW did not capture successful version.dll lookup: $($moduleHandleEx | ConvertTo-Json -Depth 8)"
}

$flags = Get-ArgumentByName -Event $moduleHandleEx[0] -Name "dwFlags"
if ($flags.decodedValue -notmatch "GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT")
{
    throw "GetModuleHandleExW did not capture unchanged-refcount flag: $($flags | ConvertTo-Json -Depth 8)"
}

$modulePointer = Get-ArgumentByName -Event $moduleHandleEx[0] -Name "phModule"
Assert-NonNullPointer -Value $modulePointer.rawValue -Name "GetModuleHandleExW phModule rawValue"
Assert-NonNullPointer -Value $modulePointer.decodedValue -Name "GetModuleHandleExW phModule decodedValue"
if ($modulePointer.decodeStatus -ne "decoded" -or $modulePointer.decodedValue -ne $moduleHandle[0].returnValue)
{
    throw "GetModuleHandleExW module handle mismatch: $($modulePointer | ConvertTo-Json -Depth 8)"
}

$moduleFileName = @($moduleEvents | Where-Object {
    $_.api -eq "GetModuleFileNameW" -and
    (Get-ArgumentByName -Event $_ -Name "hModule").decodedValue -eq $moduleHandle[0].returnValue
} | Select-Object -First 1)
if ($moduleFileName.Count -ne 1)
{
    throw "GetModuleFileNameW did not capture the version.dll module handle."
}

if ($moduleFileName[0].returnValue -notmatch "^[1-9][0-9]* \(0x[0-9a-fA-F]{8}\)$")
{
    throw "GetModuleFileNameW return count mismatch: $($moduleFileName[0].returnValue)"
}

$fileName = Get-ArgumentByName -Event $moduleFileName[0] -Name "lpFilename"
Assert-NonNullPointer -Value $fileName.rawValue -Name "GetModuleFileNameW lpFilename rawValue"
if ($fileName.decodeStatus -ne "decoded" -or $fileName.decodedValue -notmatch "(?i)version\.dll")
{
    throw "GetModuleFileNameW did not expose bounded version.dll path text: $($fileName | ConvertTo-Json -Depth 8)"
}

$size = Get-ArgumentByName -Event $moduleFileName[0] -Name "nSize"
if ($size.decodedValue -notmatch "^260 ")
{
    throw "GetModuleFileNameW did not capture expected buffer size: $($size | ConvertTo-Json -Depth 8)"
}

$freeLibrary = @($moduleEvents | Where-Object {
    $_.api -eq "FreeLibrary" -and
    (Get-ArgumentByName -Event $_ -Name "hLibModule").decodedValue -eq $moduleHandle[0].returnValue
} | Select-Object -First 1)
if ($freeLibrary.Count -ne 1 -or $freeLibrary[0].returnValue -ne "TRUE")
{
    throw "FreeLibrary did not capture successful release of version.dll module handle: $($freeLibrary | ConvertTo-Json -Depth 8)"
}

$modulePayload = $moduleEvents | ConvertTo-Json -Depth 12
if ($modulePayload -cmatch "IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SectionHeader|CodeBytes|Disassembly|SHA256|SHA1|MD5|Authenticode|WinVerifyTrust|CertVerify|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b|CreateToolhelp32Snapshot|Module32First|Module32Next|EnumProcesses|PEB|LDR_DATA_TABLE_ENTRY|InLoadOrderModuleList|CommandLine|Environment|GetEnvironment|TOKEN_|TokenPrivileges|LookupAccount|SecurityDescriptor|SECURITY_DESCRIPTOR|\bSID\b|\bACL\b|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|VirtualFreeEx|VirtualProtectEx|CreateRemoteThread|QueueUserAPC|NtQueueApcThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential")
{
    throw "Wave 3 KERNEL32 module lifecycle events appear to expose module-memory, PE/hash/signature, enumeration, command-line, environment, token/security, remote-memory, remote-thread, stack, injection, credential, or byte-preview evidence: $modulePayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 KERNEL32 module lifecycle smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 KERNEL32 module lifecycle smoke passed: events=$($result.capturedEvents.Count) moduleEvents=$($moduleEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
