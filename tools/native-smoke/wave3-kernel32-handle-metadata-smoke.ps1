param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "kernel32.dll"
$SelectedApis = @(
    "GetStdHandle",
    "GetFileType",
    "GetHandleInformation",
    "SetHandleInformation"
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

function Get-EventByApi
{
    param(
        [object[]]$Events,
        [string]$Api
    )

    $event = @($Events | Where-Object { $_.api -eq $Api } | Select-Object -First 1)
    if ($event.Count -ne 1)
    {
        throw "Wave 3 KERNEL32 handle metadata smoke did not capture $Api."
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
    @{ Api = "GetStdHandle"; Id = 146 },
    @{ Api = "GetFileType"; Id = 147 },
    @{ Api = "GetHandleInformation"; Id = 148 },
    @{ Api = "SetHandleInformation"; Id = 149 }
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
    throw "Wave 3 KERNEL32 handle metadata capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 KERNEL32 handle metadata healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "GetStdHandle"; Family = "handle"; Category = "standard_handle"; Args = @(
        @{ Name = "nStdHandle"; Alias = "std_handle_selector"; Timing = "pre" }
    ) },
    @{ Api = "GetFileType"; Family = "handle"; Category = "handle_metadata"; Args = @(
        @{ Name = "hFile"; Alias = "handle"; Timing = "pre" }
    ) },
    @{ Api = "GetHandleInformation"; Family = "handle"; Category = "handle_metadata"; Args = @(
        @{ Name = "hObject"; Alias = "handle"; Timing = "pre" },
        @{ Name = "lpdwFlags"; Alias = "handle_information_flags_pointer"; Timing = "post" }
    ) },
    @{ Api = "SetHandleInformation"; Family = "handle"; Category = "handle_metadata"; Args = @(
        @{ Name = "hObject"; Alias = "handle"; Timing = "pre" },
        @{ Name = "dwMask"; Alias = "handle_information_mask"; Timing = "pre" },
        @{ Name = "dwFlags"; Alias = "handle_information_flags"; Timing = "pre" }
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

$stdHandle = Get-EventByApi -Events $result.capturedEvents -Api "GetStdHandle"
Assert-PointerShape -Value $stdHandle.returnValue -Name "GetStdHandle returnValue"
$stdSelector = Get-ArgumentByName -Event $stdHandle -Name "nStdHandle"
if ($stdSelector.decodedValue -notmatch "STD_OUTPUT_HANDLE")
{
    throw "GetStdHandle did not capture STD_OUTPUT_HANDLE selector: $($stdSelector | ConvertTo-Json -Depth 8)"
}

$fileType = Get-EventByApi -Events $result.capturedEvents -Api "GetFileType"
if ($fileType.returnValue -notmatch "FILE_TYPE_DISK")
{
    throw "GetFileType did not return FILE_TYPE_DISK: $($fileType.returnValue)"
}

$fileTypeHandle = Get-ArgumentByName -Event $fileType -Name "hFile"
Assert-NonNullPointer -Value $fileTypeHandle.decodedValue -Name "GetFileType hFile"

$getHandleInfoEvents = @($result.capturedEvents | Where-Object { $_.api -eq "GetHandleInformation" })
if ($getHandleInfoEvents.Count -lt 2)
{
    throw "Expected at least two GetHandleInformation events, got $($getHandleInfoEvents.Count)."
}

foreach ($event in $getHandleInfoEvents)
{
    if ($event.returnValue -ne "TRUE")
    {
        throw "GetHandleInformation did not succeed: $($event | ConvertTo-Json -Depth 8)"
    }

    $handleArg = Get-ArgumentByName -Event $event -Name "hObject"
    Assert-NonNullPointer -Value $handleArg.decodedValue -Name "GetHandleInformation hObject"

    $flagsArg = Get-ArgumentByName -Event $event -Name "lpdwFlags"
    Assert-NonNullPointer -Value $flagsArg.rawValue -Name "GetHandleInformation lpdwFlags rawValue"
    if ($flagsArg.decodeStatus -ne "decoded" -or $flagsArg.decodedValue -notmatch "0x[0-9a-fA-F]{8}")
    {
        throw "GetHandleInformation flags were not decoded: $($flagsArg | ConvertTo-Json -Depth 8)"
    }
}

$setHandleInfo = Get-EventByApi -Events $result.capturedEvents -Api "SetHandleInformation"
if ($setHandleInfo.returnValue -ne "TRUE")
{
    throw "SetHandleInformation did not succeed: $($setHandleInfo | ConvertTo-Json -Depth 8)"
}

$setHandle = Get-ArgumentByName -Event $setHandleInfo -Name "hObject"
Assert-NonNullPointer -Value $setHandle.decodedValue -Name "SetHandleInformation hObject"

$mask = Get-ArgumentByName -Event $setHandleInfo -Name "dwMask"
if ($mask.decodedValue -notmatch "HANDLE_FLAG_INHERIT")
{
    throw "SetHandleInformation mask did not include HANDLE_FLAG_INHERIT: $($mask | ConvertTo-Json -Depth 8)"
}

$flags = Get-ArgumentByName -Event $setHandleInfo -Name "dwFlags"
if ($flags.decodedValue -notmatch "none")
{
    throw "SetHandleInformation flags should clear selected bits: $($flags | ConvertTo-Json -Depth 8)"
}

$handleEvents = @($result.capturedEvents | Where-Object { $SelectedApis -contains $_.api })
if ($handleEvents.Count -lt $SelectedApis.Count)
{
    throw "Wave 3 KERNEL32 handle metadata capture did not include all selected events."
}

$handlePayload = $handleEvents | ConvertTo-Json -Depth 12
if ($handlePayload -cmatch "ObjectName|ObjectType|NtQueryObject|SystemHandle|SystemExtendedHandle|DuplicateHandle|SecurityDescriptor|SECURITY_DESCRIPTOR|\bSID\b|\bACL\b|TOKEN_|TokenPrivileges|LookupAccount|CommandLine|Environment|GetEnvironment|Process32First|Process32Next|CreateToolhelp32Snapshot|EnumProcesses|OpenProcess|CreateProcessW|TerminateProcess|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|VirtualFreeEx|VirtualProtectEx|CreateRemoteThread|QueueUserAPC|NtQueueApcThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 KERNEL32 handle metadata events appear to expose object-name, security, duplication, payload, command-line, environment, remote-memory, remote-thread, stack, injection, PE/file/hash, credential, or byte-preview evidence: $handlePayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 KERNEL32 handle metadata smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 KERNEL32 handle metadata smoke passed: events=$($result.capturedEvents.Count) handleEvents=$($handleEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
