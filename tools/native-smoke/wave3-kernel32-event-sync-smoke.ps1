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
        throw "Wave 3 KERNEL32 event synchronization smoke did not capture $Api."
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
    @{ Api = "CreateEventW"; Id = 124 },
    @{ Api = "OpenEventW"; Id = 125 },
    @{ Api = "SetEvent"; Id = 126 },
    @{ Api = "ResetEvent"; Id = 127 },
    @{ Api = "WaitForSingleObjectEx"; Id = 128 }
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
    throw "Wave 3 KERNEL32 event synchronization capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 KERNEL32 event synchronization healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "CreateEventW"; Family = "synchronization"; Category = "event_create"; Args = @(
        @{ Name = "lpEventAttributes"; Alias = "pointer"; Timing = "pre" },
        @{ Name = "bManualReset"; Alias = "event_manual_reset_bool"; Timing = "pre" },
        @{ Name = "bInitialState"; Alias = "event_initial_state_bool"; Timing = "pre" },
        @{ Name = "lpName"; Alias = "event_name_pointer"; Timing = "pre" }
    ) },
    @{ Api = "OpenEventW"; Family = "synchronization"; Category = "event_open"; Args = @(
        @{ Name = "dwDesiredAccess"; Alias = "event_access_flags"; Timing = "pre" },
        @{ Name = "bInheritHandle"; Alias = "dword_value"; Timing = "pre" },
        @{ Name = "lpName"; Alias = "event_name_pointer"; Timing = "pre" }
    ) },
    @{ Api = "SetEvent"; Family = "synchronization"; Category = "event_set"; Args = @(
        @{ Name = "hEvent"; Alias = "handle"; Timing = "pre" }
    ) },
    @{ Api = "ResetEvent"; Family = "synchronization"; Category = "event_reset"; Args = @(
        @{ Name = "hEvent"; Alias = "handle"; Timing = "pre" }
    ) },
    @{ Api = "WaitForSingleObjectEx"; Family = "synchronization"; Category = "event_wait"; Args = @(
        @{ Name = "hHandle"; Alias = "handle"; Timing = "pre" },
        @{ Name = "dwMilliseconds"; Alias = "wait_timeout_ms"; Timing = "pre" },
        @{ Name = "bAlertable"; Alias = "wait_alertable_bool"; Timing = "pre" }
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

$createEvent = Get-EventByApi -Events $result.capturedEvents -Api "CreateEventW"
Assert-PointerValue -Value $createEvent.returnValue -Name "CreateEventW returnValue"

$eventAttributes = Get-ArgumentByName -Event $createEvent -Name "lpEventAttributes"
Assert-PointerValue -Value $eventAttributes.decodedValue -Name "CreateEventW lpEventAttributes" -AllowNull $true

$manualReset = Get-ArgumentByName -Event $createEvent -Name "bManualReset"
if ($manualReset.decodedValue -ne "TRUE")
{
    throw "CreateEventW manual reset flag mismatch: $($manualReset | ConvertTo-Json -Depth 8)"
}

$initialState = Get-ArgumentByName -Event $createEvent -Name "bInitialState"
if ($initialState.decodedValue -ne "FALSE")
{
    throw "CreateEventW initial state flag mismatch: $($initialState | ConvertTo-Json -Depth 8)"
}

$createName = Get-ArgumentByName -Event $createEvent -Name "lpName"
Assert-PointerValue -Value $createName.decodedValue -Name "CreateEventW lpName"

$openEvent = Get-EventByApi -Events $result.capturedEvents -Api "OpenEventW"
Assert-PointerValue -Value $openEvent.returnValue -Name "OpenEventW returnValue"

$desiredAccess = Get-ArgumentByName -Event $openEvent -Name "dwDesiredAccess"
if ($desiredAccess.decodedValue -notmatch "EVENT_MODIFY_STATE" -or $desiredAccess.decodedValue -notmatch "SYNCHRONIZE")
{
    throw "OpenEventW did not decode event access flags: $($desiredAccess | ConvertTo-Json -Depth 8)"
}

$inheritHandle = Get-ArgumentByName -Event $openEvent -Name "bInheritHandle"
if ($inheritHandle.decodedValue -ne "FALSE")
{
    throw "OpenEventW inherit flag mismatch: $($inheritHandle | ConvertTo-Json -Depth 8)"
}

$openName = Get-ArgumentByName -Event $openEvent -Name "lpName"
Assert-PointerValue -Value $openName.decodedValue -Name "OpenEventW lpName"

$setEvent = Get-EventByApi -Events $result.capturedEvents -Api "SetEvent"
if ($setEvent.returnValue -ne "TRUE")
{
    throw "SetEvent return mismatch: $($setEvent | ConvertTo-Json -Depth 8)"
}

$setHandle = Get-ArgumentByName -Event $setEvent -Name "hEvent"
Assert-PointerValue -Value $setHandle.decodedValue -Name "SetEvent hEvent"

$waitEvent = Get-EventByApi -Events $result.capturedEvents -Api "WaitForSingleObjectEx"
if ($waitEvent.returnValue -notmatch "WAIT_OBJECT_0")
{
    throw "WaitForSingleObjectEx return mismatch: $($waitEvent | ConvertTo-Json -Depth 8)"
}

$waitHandle = Get-ArgumentByName -Event $waitEvent -Name "hHandle"
Assert-PointerValue -Value $waitHandle.decodedValue -Name "WaitForSingleObjectEx hHandle"

$timeout = Get-ArgumentByName -Event $waitEvent -Name "dwMilliseconds"
if ($timeout.decodedValue -notmatch "1000" -or $timeout.decodedValue -notmatch "0x000003e8")
{
    throw "WaitForSingleObjectEx timeout mismatch: $($timeout | ConvertTo-Json -Depth 8)"
}

$alertable = Get-ArgumentByName -Event $waitEvent -Name "bAlertable"
if ($alertable.decodedValue -ne "FALSE")
{
    throw "WaitForSingleObjectEx alertable flag mismatch: $($alertable | ConvertTo-Json -Depth 8)"
}

$resetEvent = Get-EventByApi -Events $result.capturedEvents -Api "ResetEvent"
if ($resetEvent.returnValue -ne "TRUE")
{
    throw "ResetEvent return mismatch: $($resetEvent | ConvertTo-Json -Depth 8)"
}

$resetHandle = Get-ArgumentByName -Event $resetEvent -Name "hEvent"
Assert-PointerValue -Value $resetHandle.decodedValue -Name "ResetEvent hEvent"

$syncEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "synchronization" })
if ($syncEvents.Count -lt 5)
{
    throw "Wave 3 KERNEL32 event synchronization capture did not include all selected events."
}

$syncPayload = $syncEvents | ConvertTo-Json -Depth 12
if ($syncPayload -cmatch "KnMonEventProbe|Global\\|Local\\|BaseNamedObjects|ObjectName|ObjectDirectory|ObjectManager|SecurityDescriptor|SECURITY_DESCRIPTOR|SID|ACL|TOKEN_|Privilege|Integrity|DuplicateHandle|WaitChain|WCT|Apc|APC|QueueUserAPC|NtQueueApcThread|CreateRemoteThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|TerminateThread|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Disassembly|VirtualAllocEx|WriteProcessMemory|ReadProcessMemory|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 KERNEL32 event synchronization events appear to expose event-name, namespace, security, wait-chain, APC, context, stack, injection, PE/file/hash, credential, or byte-preview evidence: $syncPayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 KERNEL32 event synchronization smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 KERNEL32 event-synchronization smoke passed: events=$($result.capturedEvents.Count) syncEvents=$($syncEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
