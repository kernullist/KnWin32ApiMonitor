param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "kernel32.dll"
$SelectedApis = @(
    "GetFileSizeEx",
    "GetFileTime",
    "GetFileInformationByHandle"
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
        throw "Wave 3 KERNEL32 file metadata smoke did not capture $Api."
    }

    return $event[0]
}

function ConvertFrom-DecimalHexValue
{
    param(
        [string]$Value,
        [string]$Name
    )

    if ($Value -notmatch "^([0-9]+) \(0x[0-9a-fA-F]{16}\)$")
    {
        throw "$Name is not a decimal+hex value: $Value"
    }

    return [UInt64]$Matches[1]
}

function Assert-DecodedPointerArgument
{
    param(
        [object]$Argument,
        [string]$Name
    )

    Assert-NonNullPointer -Value $Argument.rawValue -Name "$Name rawValue"
    if ($Argument.decodeStatus -ne "decoded")
    {
        throw "$Name was not decoded: $($Argument | ConvertTo-Json -Depth 8)"
    }
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
    @{ Api = "GetFileSizeEx"; Id = 154 },
    @{ Api = "GetFileTime"; Id = 155 },
    @{ Api = "GetFileInformationByHandle"; Id = 156 }
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
    throw "Wave 3 KERNEL32 file metadata capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 KERNEL32 file metadata healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "GetFileSizeEx"; Family = "file"; Category = "file_size_query"; Args = @(
        @{ Name = "hFile"; Alias = "handle"; Timing = "pre" },
        @{ Name = "lpFileSize"; Alias = "file_size_pointer"; Timing = "post" }
    ) },
    @{ Api = "GetFileTime"; Family = "file"; Category = "file_time_query"; Args = @(
        @{ Name = "hFile"; Alias = "handle"; Timing = "pre" },
        @{ Name = "lpCreationTime"; Alias = "file_time_pointer"; Timing = "post" },
        @{ Name = "lpLastAccessTime"; Alias = "file_time_pointer"; Timing = "post" },
        @{ Name = "lpLastWriteTime"; Alias = "file_time_pointer"; Timing = "post" }
    ) },
    @{ Api = "GetFileInformationByHandle"; Family = "file"; Category = "file_information_query"; Args = @(
        @{ Name = "hFile"; Alias = "handle"; Timing = "pre" },
        @{ Name = "lpFileInformation"; Alias = "by_handle_file_information_pointer"; Timing = "post" }
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

$fileSizeEx = Get-EventByApi -Events $result.capturedEvents -Api "GetFileSizeEx"
if ($fileSizeEx.returnValue -ne "TRUE")
{
    throw "GetFileSizeEx did not succeed: $($fileSizeEx | ConvertTo-Json -Depth 8)"
}

$fileSizeHandle = Get-ArgumentByName -Event $fileSizeEx -Name "hFile"
Assert-NonNullPointer -Value $fileSizeHandle.decodedValue -Name "GetFileSizeEx hFile"
$fileSizePointer = Get-ArgumentByName -Event $fileSizeEx -Name "lpFileSize"
Assert-DecodedPointerArgument -Argument $fileSizePointer -Name "GetFileSizeEx lpFileSize"
$fileSizeValue = ConvertFrom-DecimalHexValue -Value $fileSizePointer.decodedValue -Name "GetFileSizeEx lpFileSize decodedValue"

$fileTime = Get-EventByApi -Events $result.capturedEvents -Api "GetFileTime"
if ($fileTime.returnValue -ne "TRUE")
{
    throw "GetFileTime did not succeed: $($fileTime | ConvertTo-Json -Depth 8)"
}

$fileTimeHandle = Get-ArgumentByName -Event $fileTime -Name "hFile"
Assert-NonNullPointer -Value $fileTimeHandle.decodedValue -Name "GetFileTime hFile"
foreach ($timeArgumentName in @("lpCreationTime", "lpLastAccessTime", "lpLastWriteTime"))
{
    $timeArgument = Get-ArgumentByName -Event $fileTime -Name $timeArgumentName
    Assert-DecodedPointerArgument -Argument $timeArgument -Name "GetFileTime $timeArgumentName"
    if ($timeArgument.decodedValue -notmatch "^[0-9]+$")
    {
        throw "GetFileTime $timeArgumentName is not numeric FILETIME: $($timeArgument | ConvertTo-Json -Depth 8)"
    }
}

$fileInfo = Get-EventByApi -Events $result.capturedEvents -Api "GetFileInformationByHandle"
if ($fileInfo.returnValue -ne "TRUE")
{
    throw "GetFileInformationByHandle did not succeed: $($fileInfo | ConvertTo-Json -Depth 8)"
}

$fileInfoHandle = Get-ArgumentByName -Event $fileInfo -Name "hFile"
Assert-NonNullPointer -Value $fileInfoHandle.decodedValue -Name "GetFileInformationByHandle hFile"
$fileInfoPointer = Get-ArgumentByName -Event $fileInfo -Name "lpFileInformation"
Assert-DecodedPointerArgument -Argument $fileInfoPointer -Name "GetFileInformationByHandle lpFileInformation"

$fileInfoSizeMatch = [regex]::Match($fileInfoPointer.decodedValue, "nFileSize=([0-9]+) \(0x[0-9a-fA-F]{16}\)")
if ($fileInfoPointer.decodedValue -notmatch "dwFileAttributes=0x[0-9a-fA-F]{8}" -or
    $fileInfoPointer.decodedValue -notmatch "dwVolumeSerialNumber=[0-9]+ \(0x[0-9a-fA-F]{8}\)" -or
    -not $fileInfoSizeMatch.Success -or
    $fileInfoPointer.decodedValue -notmatch "nNumberOfLinks=[0-9]+ \(0x[0-9a-fA-F]{8}\)" -or
    $fileInfoPointer.decodedValue -notmatch "nFileIndex=[0-9]+ \(0x[0-9a-fA-F]{16}\)" -or
    $fileInfoPointer.decodedValue -notmatch "ftCreationTime=[0-9]+" -or
    $fileInfoPointer.decodedValue -notmatch "ftLastAccessTime=[0-9]+" -or
    $fileInfoPointer.decodedValue -notmatch "ftLastWriteTime=[0-9]+")
{
    throw "GetFileInformationByHandle scalar metadata missing: $($fileInfoPointer | ConvertTo-Json -Depth 8)"
}

$fileInfoSize = [UInt64]$fileInfoSizeMatch.Groups[1].Value
if ($fileSizeValue -ne $fileInfoSize)
{
    throw "File size mismatch between GetFileSizeEx and GetFileInformationByHandle: sizeEx=$fileSizeValue info=$fileInfoSize"
}

$fileEvents = @($result.capturedEvents | Where-Object { $SelectedApis -contains $_.api })
if ($fileEvents.Count -lt $SelectedApis.Count)
{
    throw "Wave 3 KERNEL32 file metadata capture did not include all selected events."
}

$filePayload = $fileEvents | ConvertTo-Json -Depth 12
if ($filePayload -cmatch "GetFinalPathNameByHandle|GetFileInformationByHandleEx|FileNameInfo|FileStreamInfo|FileIdInfo|FileIdBothDirectoryInfo|FindFirstFile|FindNextFile|DirectoryListing|ObjectName|ObjectType|NtQueryObject|SystemHandle|SystemExtendedHandle|DuplicateHandle|SecurityDescriptor|SECURITY_DESCRIPTOR|\bSID\b|\bACL\b|TOKEN_|TokenPrivileges|LookupAccount|CommandLine|Environment|GetEnvironment|Process32First|Process32Next|CreateToolhelp32Snapshot|EnumProcesses|OpenProcess|CreateProcessW|TerminateProcess|ReadFile|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|VirtualFreeEx|VirtualProtectEx|CreateRemoteThread|QueueUserAPC|NtQueueApcThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 KERNEL32 file metadata events appear to expose path/name/content, object-name, security, duplication, command-line, environment, remote-memory, remote-thread, stack, injection, PE/file/hash, credential, or byte-preview evidence: $filePayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 KERNEL32 file metadata smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 KERNEL32 file metadata smoke passed: events=$($result.capturedEvents.Count) fileEvents=$($fileEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
