param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "kernel32.dll"
$SelectedApis = @(
    "GetCurrentProcess",
    "GetCurrentProcessId",
    "GetCurrentThread",
    "GetCurrentThreadId",
    "GetProcessId",
    "GetThreadId"
)

function Assert-PointerValue
{
    param(
        [string]$Value,
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^0x[0-9a-fA-F]+$")
    {
        throw "$Name is not a pointer value: $Value"
    }

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
        throw "Wave 3 KERNEL32 process/thread identity smoke did not capture $Api."
    }

    return $event[0]
}

function ConvertFrom-DwordDecimalHex
{
    param(
        [string]$Value,
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^([0-9]+) \(0x[0-9a-fA-F]{8}\)$")
    {
        throw "$Name is not a DWORD decimal/hex value: $Value"
    }

    $parsed = [UInt64]$Matches[1]
    if ($parsed -eq 0 -or $parsed -gt [UInt32]::MaxValue)
    {
        throw "$Name is outside nonzero DWORD range: $Value"
    }

    return [UInt32]$parsed
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
    @{ Api = "GetCurrentProcess"; Id = 140 },
    @{ Api = "GetCurrentProcessId"; Id = 141 },
    @{ Api = "GetCurrentThread"; Id = 142 },
    @{ Api = "GetCurrentThreadId"; Id = 143 },
    @{ Api = "GetProcessId"; Id = 144 },
    @{ Api = "GetThreadId"; Id = 145 }
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
    throw "Wave 3 KERNEL32 process/thread identity capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 KERNEL32 process/thread identity healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "GetCurrentProcess"; Family = "process"; Category = "process_identity"; Args = @() },
    @{ Api = "GetCurrentProcessId"; Family = "process"; Category = "process_identity"; Args = @() },
    @{ Api = "GetCurrentThread"; Family = "process"; Category = "thread_identity"; Args = @() },
    @{ Api = "GetCurrentThreadId"; Family = "process"; Category = "thread_identity"; Args = @() },
    @{ Api = "GetProcessId"; Family = "process"; Category = "process_identity"; Args = @(
        @{ Name = "Process"; Alias = "process_handle_value"; Timing = "pre" }
    ) },
    @{ Api = "GetThreadId"; Family = "process"; Category = "thread_identity"; Args = @(
        @{ Name = "Thread"; Alias = "thread_handle_value"; Timing = "pre" }
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

    if ($item.Args.Count -eq 0 -and @($event.arguments).Count -ne 0)
    {
        throw "$($item.Api) unexpectedly captured arguments: $($event.arguments | ConvertTo-Json -Depth 8)"
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

$currentProcess = Get-EventByApi -Events $result.capturedEvents -Api "GetCurrentProcess"
Assert-PointerValue -Value $currentProcess.returnValue -Name "GetCurrentProcess returnValue"

$currentProcessIds = @($result.capturedEvents |
    Where-Object { $_.api -eq "GetCurrentProcessId" } |
    ForEach-Object { ConvertFrom-DwordDecimalHex -Value $_.returnValue -Name "GetCurrentProcessId returnValue" })
if ($currentProcessIds.Count -lt 1)
{
    throw "GetCurrentProcessId returned no current PID values."
}

$processId = Get-EventByApi -Events $result.capturedEvents -Api "GetProcessId"
$handleProcessId = ConvertFrom-DwordDecimalHex -Value $processId.returnValue -Name "GetProcessId returnValue"
if ($currentProcessIds -notcontains $handleProcessId)
{
    throw "GetProcessId did not match captured current PID values: handle=$handleProcessId current=$($currentProcessIds -join ',')"
}

$processHandle = Get-ArgumentByName -Event $processId -Name "Process"
Assert-PointerValue -Value $processHandle.decodedValue -Name "GetProcessId Process"

$currentThread = Get-EventByApi -Events $result.capturedEvents -Api "GetCurrentThread"
Assert-PointerValue -Value $currentThread.returnValue -Name "GetCurrentThread returnValue"

$currentThreadIds = @($result.capturedEvents |
    Where-Object { $_.api -eq "GetCurrentThreadId" } |
    ForEach-Object { ConvertFrom-DwordDecimalHex -Value $_.returnValue -Name "GetCurrentThreadId returnValue" })
if ($currentThreadIds.Count -lt 1)
{
    throw "GetCurrentThreadId returned no current TID values."
}

$threadId = Get-EventByApi -Events $result.capturedEvents -Api "GetThreadId"
$handleThreadId = ConvertFrom-DwordDecimalHex -Value $threadId.returnValue -Name "GetThreadId returnValue"
if ($currentThreadIds -notcontains $handleThreadId)
{
    throw "GetThreadId did not match captured current TID values: handle=$handleThreadId current=$($currentThreadIds -join ',')"
}

$threadHandle = Get-ArgumentByName -Event $threadId -Name "Thread"
Assert-PointerValue -Value $threadHandle.decodedValue -Name "GetThreadId Thread"

$identityEvents = @($result.capturedEvents | Where-Object { $SelectedApis -contains $_.api })
if ($identityEvents.Count -lt $SelectedApis.Count)
{
    throw "Wave 3 KERNEL32 process/thread identity capture did not include all selected events."
}

$identityPayload = $identityEvents | ConvertTo-Json -Depth 12
if ($identityPayload -cmatch "CommandLine|Environment|GetEnvironment|TOKEN_|TokenPrivileges|LookupAccount|SecurityDescriptor|SECURITY_DESCRIPTOR|\bSID\b|\bACL\b|Process32First|Process32Next|CreateToolhelp32Snapshot|EnumProcesses|OpenProcess|CreateProcessW|TerminateProcess|DuplicateHandle|OpenThread|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|VirtualFreeEx|VirtualProtectEx|CreateRemoteThread|QueueUserAPC|NtQueueApcThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 KERNEL32 process/thread identity events appear to expose command-line, environment, token, security, enumeration, remote-memory, remote-thread, stack, injection, PE/file/hash, credential, or byte-preview evidence: $identityPayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 KERNEL32 process/thread identity smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 KERNEL32 process/thread identity smoke passed: events=$($result.capturedEvents.Count) identityEvents=$($identityEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
