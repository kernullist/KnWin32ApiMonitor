param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "kernel32.dll"
$SelectedApis = @(
    "CreateMutexW",
    "OpenMutexW",
    "ReleaseMutex",
    "CreateSemaphoreW",
    "OpenSemaphoreW",
    "ReleaseSemaphore",
    "WaitForMultipleObjectsEx"
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
        throw "Wave 3 KERNEL32 mutex/semaphore smoke did not capture $Api."
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
    @{ Api = "CreateMutexW"; Id = 129 },
    @{ Api = "OpenMutexW"; Id = 130 },
    @{ Api = "ReleaseMutex"; Id = 131 },
    @{ Api = "CreateSemaphoreW"; Id = 132 },
    @{ Api = "OpenSemaphoreW"; Id = 133 },
    @{ Api = "ReleaseSemaphore"; Id = 134 },
    @{ Api = "WaitForMultipleObjectsEx"; Id = 135 }
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
    throw "Wave 3 KERNEL32 mutex/semaphore capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 KERNEL32 mutex/semaphore healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "CreateMutexW"; Family = "synchronization"; Category = "mutex_create"; Args = @(
        @{ Name = "lpMutexAttributes"; Alias = "pointer"; Timing = "pre" },
        @{ Name = "bInitialOwner"; Alias = "mutex_initial_owner_bool"; Timing = "pre" },
        @{ Name = "lpName"; Alias = "sync_object_name_pointer"; Timing = "pre" }
    ) },
    @{ Api = "OpenMutexW"; Family = "synchronization"; Category = "mutex_open"; Args = @(
        @{ Name = "dwDesiredAccess"; Alias = "mutex_access_flags"; Timing = "pre" },
        @{ Name = "bInheritHandle"; Alias = "dword_value"; Timing = "pre" },
        @{ Name = "lpName"; Alias = "sync_object_name_pointer"; Timing = "pre" }
    ) },
    @{ Api = "ReleaseMutex"; Family = "synchronization"; Category = "mutex_release"; Args = @(
        @{ Name = "hMutex"; Alias = "handle"; Timing = "pre" }
    ) },
    @{ Api = "CreateSemaphoreW"; Family = "synchronization"; Category = "semaphore_create"; Args = @(
        @{ Name = "lpSemaphoreAttributes"; Alias = "pointer"; Timing = "pre" },
        @{ Name = "lInitialCount"; Alias = "semaphore_count_value"; Timing = "pre" },
        @{ Name = "lMaximumCount"; Alias = "semaphore_count_value"; Timing = "pre" },
        @{ Name = "lpName"; Alias = "sync_object_name_pointer"; Timing = "pre" }
    ) },
    @{ Api = "OpenSemaphoreW"; Family = "synchronization"; Category = "semaphore_open"; Args = @(
        @{ Name = "dwDesiredAccess"; Alias = "semaphore_access_flags"; Timing = "pre" },
        @{ Name = "bInheritHandle"; Alias = "dword_value"; Timing = "pre" },
        @{ Name = "lpName"; Alias = "sync_object_name_pointer"; Timing = "pre" }
    ) },
    @{ Api = "ReleaseSemaphore"; Family = "synchronization"; Category = "semaphore_release"; Args = @(
        @{ Name = "hSemaphore"; Alias = "handle"; Timing = "pre" },
        @{ Name = "lReleaseCount"; Alias = "semaphore_count_value"; Timing = "pre" },
        @{ Name = "lpPreviousCount"; Alias = "semaphore_previous_count_pointer"; Timing = "post" }
    ) },
    @{ Api = "WaitForMultipleObjectsEx"; Family = "synchronization"; Category = "multi_wait"; Args = @(
        @{ Name = "nCount"; Alias = "dword_value"; Timing = "pre" },
        @{ Name = "lpHandles"; Alias = "wait_handle_array_pointer"; Timing = "pre" },
        @{ Name = "bWaitAll"; Alias = "wait_all_bool"; Timing = "pre" },
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

$createMutex = Get-EventByApi -Events $result.capturedEvents -Api "CreateMutexW"
Assert-PointerValue -Value $createMutex.returnValue -Name "CreateMutexW returnValue"
$mutexAttributes = Get-ArgumentByName -Event $createMutex -Name "lpMutexAttributes"
Assert-PointerValue -Value $mutexAttributes.decodedValue -Name "CreateMutexW lpMutexAttributes" -AllowNull $true
$initialOwner = Get-ArgumentByName -Event $createMutex -Name "bInitialOwner"
if ($initialOwner.decodedValue -ne "FALSE")
{
    throw "CreateMutexW initial owner flag mismatch: $($initialOwner | ConvertTo-Json -Depth 8)"
}
$createMutexName = Get-ArgumentByName -Event $createMutex -Name "lpName"
Assert-PointerValue -Value $createMutexName.decodedValue -Name "CreateMutexW lpName"

$openMutex = Get-EventByApi -Events $result.capturedEvents -Api "OpenMutexW"
Assert-PointerValue -Value $openMutex.returnValue -Name "OpenMutexW returnValue"
$mutexAccess = Get-ArgumentByName -Event $openMutex -Name "dwDesiredAccess"
if ($mutexAccess.decodedValue -notmatch "MUTEX_MODIFY_STATE" -or $mutexAccess.decodedValue -notmatch "SYNCHRONIZE")
{
    throw "OpenMutexW did not decode mutex access flags: $($mutexAccess | ConvertTo-Json -Depth 8)"
}
$mutexInherit = Get-ArgumentByName -Event $openMutex -Name "bInheritHandle"
if ($mutexInherit.decodedValue -ne "FALSE")
{
    throw "OpenMutexW inherit flag mismatch: $($mutexInherit | ConvertTo-Json -Depth 8)"
}
$openMutexName = Get-ArgumentByName -Event $openMutex -Name "lpName"
Assert-PointerValue -Value $openMutexName.decodedValue -Name "OpenMutexW lpName"

$releaseMutex = Get-EventByApi -Events $result.capturedEvents -Api "ReleaseMutex"
if ($releaseMutex.returnValue -ne "TRUE")
{
    throw "ReleaseMutex return mismatch: $($releaseMutex | ConvertTo-Json -Depth 8)"
}
$releaseMutexHandle = Get-ArgumentByName -Event $releaseMutex -Name "hMutex"
Assert-PointerValue -Value $releaseMutexHandle.decodedValue -Name "ReleaseMutex hMutex"

$createSemaphore = Get-EventByApi -Events $result.capturedEvents -Api "CreateSemaphoreW"
Assert-PointerValue -Value $createSemaphore.returnValue -Name "CreateSemaphoreW returnValue"
$semaphoreAttributes = Get-ArgumentByName -Event $createSemaphore -Name "lpSemaphoreAttributes"
Assert-PointerValue -Value $semaphoreAttributes.decodedValue -Name "CreateSemaphoreW lpSemaphoreAttributes" -AllowNull $true
$initialCount = Get-ArgumentByName -Event $createSemaphore -Name "lInitialCount"
if ($initialCount.decodedValue -ne "0")
{
    throw "CreateSemaphoreW initial count mismatch: $($initialCount | ConvertTo-Json -Depth 8)"
}
$maximumCount = Get-ArgumentByName -Event $createSemaphore -Name "lMaximumCount"
if ($maximumCount.decodedValue -ne "1")
{
    throw "CreateSemaphoreW maximum count mismatch: $($maximumCount | ConvertTo-Json -Depth 8)"
}
$createSemaphoreName = Get-ArgumentByName -Event $createSemaphore -Name "lpName"
Assert-PointerValue -Value $createSemaphoreName.decodedValue -Name "CreateSemaphoreW lpName"

$openSemaphore = Get-EventByApi -Events $result.capturedEvents -Api "OpenSemaphoreW"
Assert-PointerValue -Value $openSemaphore.returnValue -Name "OpenSemaphoreW returnValue"
$semaphoreAccess = Get-ArgumentByName -Event $openSemaphore -Name "dwDesiredAccess"
if ($semaphoreAccess.decodedValue -notmatch "SEMAPHORE_MODIFY_STATE" -or $semaphoreAccess.decodedValue -notmatch "SYNCHRONIZE")
{
    throw "OpenSemaphoreW did not decode semaphore access flags: $($semaphoreAccess | ConvertTo-Json -Depth 8)"
}
$semaphoreInherit = Get-ArgumentByName -Event $openSemaphore -Name "bInheritHandle"
if ($semaphoreInherit.decodedValue -ne "FALSE")
{
    throw "OpenSemaphoreW inherit flag mismatch: $($semaphoreInherit | ConvertTo-Json -Depth 8)"
}
$openSemaphoreName = Get-ArgumentByName -Event $openSemaphore -Name "lpName"
Assert-PointerValue -Value $openSemaphoreName.decodedValue -Name "OpenSemaphoreW lpName"

$releaseSemaphore = Get-EventByApi -Events $result.capturedEvents -Api "ReleaseSemaphore"
if ($releaseSemaphore.returnValue -ne "TRUE")
{
    throw "ReleaseSemaphore return mismatch: $($releaseSemaphore | ConvertTo-Json -Depth 8)"
}
$releaseSemaphoreHandle = Get-ArgumentByName -Event $releaseSemaphore -Name "hSemaphore"
Assert-PointerValue -Value $releaseSemaphoreHandle.decodedValue -Name "ReleaseSemaphore hSemaphore"
$releaseCount = Get-ArgumentByName -Event $releaseSemaphore -Name "lReleaseCount"
if ($releaseCount.decodedValue -ne "1")
{
    throw "ReleaseSemaphore release count mismatch: $($releaseCount | ConvertTo-Json -Depth 8)"
}
$previousCount = Get-ArgumentByName -Event $releaseSemaphore -Name "lpPreviousCount"
Assert-PointerValue -Value $previousCount.preCallValue -Name "ReleaseSemaphore lpPreviousCount"
if ($previousCount.decodeStatus -ne "decoded" -or $previousCount.postCallValue -ne "0" -or $previousCount.decodedValue -notmatch "value=0")
{
    throw "ReleaseSemaphore previous count mismatch: $($previousCount | ConvertTo-Json -Depth 8)"
}

$multiWait = Get-EventByApi -Events $result.capturedEvents -Api "WaitForMultipleObjectsEx"
if ($multiWait.returnValue -notmatch "WAIT_OBJECT_0")
{
    throw "WaitForMultipleObjectsEx return mismatch: $($multiWait | ConvertTo-Json -Depth 8)"
}
$waitCount = Get-ArgumentByName -Event $multiWait -Name "nCount"
if ($waitCount.decodedValue -ne "1")
{
    throw "WaitForMultipleObjectsEx count mismatch: $($waitCount | ConvertTo-Json -Depth 8)"
}
$waitHandles = Get-ArgumentByName -Event $multiWait -Name "lpHandles"
Assert-PointerValue -Value $waitHandles.decodedValue -Name "WaitForMultipleObjectsEx lpHandles"
$waitAll = Get-ArgumentByName -Event $multiWait -Name "bWaitAll"
if ($waitAll.decodedValue -ne "FALSE")
{
    throw "WaitForMultipleObjectsEx wait-all flag mismatch: $($waitAll | ConvertTo-Json -Depth 8)"
}
$timeout = Get-ArgumentByName -Event $multiWait -Name "dwMilliseconds"
if ($timeout.decodedValue -notmatch "1000" -or $timeout.decodedValue -notmatch "0x000003e8")
{
    throw "WaitForMultipleObjectsEx timeout mismatch: $($timeout | ConvertTo-Json -Depth 8)"
}
$alertable = Get-ArgumentByName -Event $multiWait -Name "bAlertable"
if ($alertable.decodedValue -ne "FALSE")
{
    throw "WaitForMultipleObjectsEx alertable flag mismatch: $($alertable | ConvertTo-Json -Depth 8)"
}

$syncEvents = @($result.capturedEvents | Where-Object { $SelectedApis -contains $_.api })
if ($syncEvents.Count -lt $SelectedApis.Count)
{
    throw "Wave 3 KERNEL32 mutex/semaphore capture did not include all selected events."
}

$syncPayload = $syncEvents | ConvertTo-Json -Depth 12
if ($syncPayload -cmatch "KnMonMutexProbe|KnMonSemaphoreProbe|Global\\|Local\\|BaseNamedObjects|ObjectName|ObjectDirectory|ObjectManager|SecurityDescriptor|SECURITY_DESCRIPTOR|SID|ACL|TOKEN_|Privilege|Integrity|DuplicateHandle|WaitChain|WCT|Apc|APC|QueueUserAPC|NtQueueApcThread|CreateRemoteThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|TerminateThread|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Disassembly|VirtualAllocEx|WriteProcessMemory|ReadProcessMemory|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 KERNEL32 mutex/semaphore events appear to expose object-name, namespace, security, handle-array, wait-chain, APC, context, stack, injection, PE/file/hash, credential, or byte-preview evidence: $syncPayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 KERNEL32 mutex/semaphore smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 KERNEL32 mutex/semaphore smoke passed: events=$($result.capturedEvents.Count) syncEvents=$($syncEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
