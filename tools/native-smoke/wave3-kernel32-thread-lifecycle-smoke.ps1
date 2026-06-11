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
        throw "Wave 3 KERNEL32 thread smoke did not capture $Api."
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
    @{ Api = "CreateThread"; Id = 120 },
    @{ Api = "OpenThread"; Id = 121 },
    @{ Api = "WaitForSingleObject"; Id = 122 },
    @{ Api = "GetExitCodeThread"; Id = 123 }
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
    throw "Wave 3 KERNEL32 thread capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 KERNEL32 thread healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "CreateThread"; Family = "thread"; Category = "thread_create"; Args = @(
        @{ Name = "lpThreadAttributes"; Alias = "security_attributes"; Timing = "pre" },
        @{ Name = "dwStackSize"; Alias = "byte_count"; Timing = "pre" },
        @{ Name = "lpStartAddress"; Alias = "thread_start_routine_pointer"; Timing = "pre" },
        @{ Name = "lpParameter"; Alias = "pointer"; Timing = "pre" },
        @{ Name = "dwCreationFlags"; Alias = "thread_creation_flags"; Timing = "pre" },
        @{ Name = "lpThreadId"; Alias = "thread_id_pointer"; Timing = "post" }
    ) },
    @{ Api = "OpenThread"; Family = "thread"; Category = "thread_open"; Args = @(
        @{ Name = "dwDesiredAccess"; Alias = "thread_access_flags"; Timing = "pre" },
        @{ Name = "bInheritHandle"; Alias = "dword_value"; Timing = "pre" },
        @{ Name = "dwThreadId"; Alias = "dword_value"; Timing = "pre" }
    ) },
    @{ Api = "WaitForSingleObject"; Family = "thread"; Category = "thread_wait"; Args = @(
        @{ Name = "hHandle"; Alias = "handle"; Timing = "pre" },
        @{ Name = "dwMilliseconds"; Alias = "wait_timeout_ms"; Timing = "pre" }
    ) },
    @{ Api = "GetExitCodeThread"; Family = "thread"; Category = "thread_exit_code"; Args = @(
        @{ Name = "hThread"; Alias = "handle"; Timing = "pre" },
        @{ Name = "lpExitCode"; Alias = "thread_exit_code_pointer"; Timing = "post" }
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

$openThread = @(($result.capturedEvents | Where-Object { $_.api -eq "OpenThread" }) | Select-Object -First 1)
if ($openThread.Count -ne 1)
{
    throw "OpenThread event was not captured."
}

Assert-PointerValue -Value $openThread[0].returnValue -Name "OpenThread returnValue"

$desiredAccess = Get-ArgumentByName -Event $openThread[0] -Name "dwDesiredAccess"
if ($desiredAccess.decodedValue -notmatch "THREAD_QUERY_LIMITED_INFORMATION" -or $desiredAccess.decodedValue -notmatch "SYNCHRONIZE")
{
    throw "OpenThread did not decode thread access flags: $($desiredAccess | ConvertTo-Json -Depth 8)"
}

$inheritHandle = Get-ArgumentByName -Event $openThread[0] -Name "bInheritHandle"
if ($inheritHandle.decodedValue -ne "FALSE")
{
    throw "OpenThread inherit flag mismatch: $($inheritHandle | ConvertTo-Json -Depth 8)"
}

$threadIdArg = Get-ArgumentByName -Event $openThread[0] -Name "dwThreadId"
Assert-IntegerValue -Value $threadIdArg.postCallValue -Name "OpenThread dwThreadId" -AllowZero $false
$threadId = $threadIdArg.postCallValue

$createThread = @($result.capturedEvents | Where-Object {
    $_.api -eq "CreateThread" -and
    ((Get-ArgumentByName -Event $_ -Name "lpThreadId").postCallValue -eq $threadId)
} | Select-Object -First 1)
if ($createThread.Count -ne 1)
{
    throw "CreateThread event for OpenThread thread ID $threadId was not captured."
}

Assert-PointerValue -Value $createThread[0].returnValue -Name "CreateThread returnValue"

$threadIdOut = Get-ArgumentByName -Event $createThread[0] -Name "lpThreadId"
if ($threadIdOut.decodeStatus -ne "decoded" -or $threadIdOut.postCallValue -ne $threadId -or $threadIdOut.decodedValue -notmatch "value=$threadId")
{
    throw "CreateThread did not decode lpThreadId: $($threadIdOut | ConvertTo-Json -Depth 8)"
}

$startRoutine = Get-ArgumentByName -Event $createThread[0] -Name "lpStartAddress"
Assert-PointerValue -Value $startRoutine.decodedValue -Name "CreateThread lpStartAddress"

$creationFlags = Get-ArgumentByName -Event $createThread[0] -Name "dwCreationFlags"
if ($creationFlags.decodedValue -notmatch "none")
{
    throw "CreateThread used unexpected creation flags: $($creationFlags | ConvertTo-Json -Depth 8)"
}

$waitEvent = @($result.capturedEvents | Where-Object {
    $_.api -eq "WaitForSingleObject" -and
    $_.returnValue -match "WAIT_OBJECT_0" -and
    ((Get-ArgumentByName -Event $_ -Name "hHandle").rawValue -eq $createThread[0].returnValue)
} | Select-Object -First 1)
if ($waitEvent.Count -ne 1)
{
    throw "WaitForSingleObject event for CreateThread handle was not captured."
}

$waitHandle = Get-ArgumentByName -Event $waitEvent[0] -Name "hHandle"
Assert-PointerValue -Value $waitHandle.decodedValue -Name "WaitForSingleObject hHandle"

$timeout = Get-ArgumentByName -Event $waitEvent[0] -Name "dwMilliseconds"
if ($timeout.decodedValue -notmatch "INFINITE")
{
    throw "WaitForSingleObject timeout did not decode INFINITE: $($timeout | ConvertTo-Json -Depth 8)"
}

$exitEvent = @($result.capturedEvents | Where-Object {
    $_.api -eq "GetExitCodeThread" -and
    $_.returnValue -eq "TRUE" -and
    ((Get-ArgumentByName -Event $_ -Name "hThread").rawValue -eq $createThread[0].returnValue) -and
    ((Get-ArgumentByName -Event $_ -Name "lpExitCode").postCallValue -eq "42")
} | Select-Object -First 1)
if ($exitEvent.Count -ne 1)
{
    throw "GetExitCodeThread event with exit code 42 was not captured."
}

$exitCode = Get-ArgumentByName -Event $exitEvent[0] -Name "lpExitCode"
if ($exitCode.decodeStatus -ne "decoded" -or $exitCode.decodedValue -notmatch "value=42" -or $exitCode.decodedValue -notmatch "0x0000002a")
{
    throw "GetExitCodeThread did not decode exit code 42: $($exitCode | ConvertTo-Json -Depth 8)"
}

$threadEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "thread" })
if ($threadEvents.Count -lt 4)
{
    throw "Wave 3 KERNEL32 thread capture did not include all thread lifecycle events."
}

$threadPayload = $threadEvents | ConvertTo-Json -Depth 12
if ($threadPayload -cmatch "CreateRemoteThread|QueueUserAPC|NtQueueApcThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|TerminateThread|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Disassembly|VirtualAllocEx|WriteProcessMemory|ReadProcessMemory|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 KERNEL32 thread events appear to expose remote-thread, APC, context, stack, injection, PE/file/hash, credential, or byte-preview evidence: $threadPayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 KERNEL32 thread smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 KERNEL32 thread-lifecycle smoke passed: events=$($result.capturedEvents.Count) threadEvents=$($threadEvents.Count) threadId=$threadId restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
