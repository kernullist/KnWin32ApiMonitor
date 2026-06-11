param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

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

function Get-ShellEvent
{
    param(
        [object[]]$Events,
        [string]$Api,
        [string]$Argument,
        [string]$Pattern
    )

    $match = @($Events | Where-Object {
        $_.api -eq $Api -and
        ((Get-ArgumentByName -Event $_ -Name $Argument).decodedValue -match $Pattern)
    } | Select-Object -First 1)

    if ($match.Count -ne 1)
    {
        throw "Wave 3 shell smoke did not find $Api with $Argument matching $Pattern."
    }

    return $match[0]
}

if (-not (Test-Path -LiteralPath $HelperPath))
{
    throw "Helper not found: $HelperPath"
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Wave 3 shell capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 shell healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "SHGetKnownFolderPath"; Module = "shell32.dll"; Family = "shell"; Category = "known_folder_path_query"; Args = @(
        @{ Name = "rfid"; Alias = "known_folder_id_pointer"; Timing = "pre" },
        @{ Name = "dwFlags"; Alias = "dword_value"; Timing = "pre" },
        @{ Name = "hToken"; Alias = "handle"; Timing = "pre" },
        @{ Name = "ppszPath"; Alias = "shell_folder_path_pointer_pointer"; Timing = "post" }
    ) },
    @{ Api = "SHGetSpecialFolderPathW"; Module = "shell32.dll"; Family = "shell"; Category = "special_folder_path_query"; Args = @(
        @{ Name = "hwnd"; Alias = "hwnd_handle"; Timing = "pre" },
        @{ Name = "pszPath"; Alias = "shell_folder_path_pointer"; Timing = "post" },
        @{ Name = "csidl"; Alias = "csidl_value"; Timing = "pre" },
        @{ Name = "fCreate"; Alias = "dword_value"; Timing = "pre" }
    ) }
)

foreach ($item in $expected)
{
    $events = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api })
    if ($events.Count -lt 1)
    {
        throw "Wave 3 shell smoke did not capture $($item.Api)."
    }

    foreach ($event in $events)
    {
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
}

$shellEvents = @($result.capturedEvents | Where-Object { $_.module -eq "shell32.dll" })
if ($shellEvents.Count -lt 8)
{
    throw "Wave 3 shell smoke expected allowlisted and non-allowlisted shell events."
}

$knownExpectations = @(
    @{ Name = "FOLDERID_Windows"; PathPattern = "(?i)status=decoded_safe_path;.*path=[A-Z]:\\WINDOWS$" },
    @{ Name = "FOLDERID_System"; PathPattern = "(?i)status=decoded_safe_path;.*path=[A-Z]:\\WINDOWS\\system32$" },
    @{ Name = "FOLDERID_ProgramFiles"; PathPattern = "(?i)status=decoded_safe_path;.*path=[A-Z]:\\Program Files(?: \(x86\))?$" }
)

foreach ($expectation in $knownExpectations)
{
    $event = Get-ShellEvent -Events $shellEvents -Api "SHGetKnownFolderPath" -Argument "rfid" -Pattern $expectation.Name
    if ($event.returnValue -ne "0x00000000")
    {
        throw "$($expectation.Name) SHGetKnownFolderPath did not report S_OK: $($event.returnValue)"
    }

    $path = Get-ArgumentByName -Event $event -Name "ppszPath"
    Assert-PointerValue -Value $path.postCallValue -Name "$($expectation.Name) ppszPath post value"
    if ($path.decodedValue -notmatch $expectation.PathPattern)
    {
        throw "$($expectation.Name) did not expose expected allowlisted path evidence: $($path | ConvertTo-Json -Depth 8)"
    }
}

$fontsKnown = Get-ShellEvent -Events $shellEvents -Api "SHGetKnownFolderPath" -Argument "rfid" -Pattern "FOLDERID_Fonts"
$fontsKnownPath = Get-ArgumentByName -Event $fontsKnown -Name "ppszPath"
Assert-PointerValue -Value $fontsKnownPath.postCallValue -Name "FOLDERID_Fonts ppszPath post value"
if ($fontsKnownPath.decodedValue -notmatch "status=non_allowlisted_no_path" -or $fontsKnownPath.decodedValue -match "path=")
{
    throw "FOLDERID_Fonts should not expose a returned path: $($fontsKnownPath | ConvertTo-Json -Depth 8)"
}

$specialExpectations = @(
    @{ Name = "CSIDL_WINDOWS"; PathPattern = "(?i)status=decoded_safe_path;.*path=[A-Z]:\\WINDOWS$" },
    @{ Name = "CSIDL_SYSTEM"; PathPattern = "(?i)status=decoded_safe_path;.*path=[A-Z]:\\WINDOWS\\system32$" },
    @{ Name = "CSIDL_PROGRAM_FILES"; PathPattern = "(?i)status=decoded_safe_path;.*path=[A-Z]:\\Program Files(?: \(x86\))?$" }
)

foreach ($expectation in $specialExpectations)
{
    $event = Get-ShellEvent -Events $shellEvents -Api "SHGetSpecialFolderPathW" -Argument "csidl" -Pattern $expectation.Name
    if ($event.returnValue -ne "1")
    {
        throw "$($expectation.Name) SHGetSpecialFolderPathW did not report success: $($event.returnValue)"
    }

    $path = Get-ArgumentByName -Event $event -Name "pszPath"
    Assert-PointerValue -Value $path.postCallValue -Name "$($expectation.Name) pszPath post value"
    if ($path.decodedValue -notmatch $expectation.PathPattern)
    {
        throw "$($expectation.Name) did not expose expected allowlisted path evidence: $($path | ConvertTo-Json -Depth 8)"
    }

    $create = Get-ArgumentByName -Event $event -Name "fCreate"
    if ($create.decodedValue -ne "FALSE")
    {
        throw "$($expectation.Name) used unexpected fCreate value: $($create.decodedValue)"
    }
}

$fontsCsidl = Get-ShellEvent -Events $shellEvents -Api "SHGetSpecialFolderPathW" -Argument "csidl" -Pattern "CSIDL_FONTS"
$fontsCsidlPath = Get-ArgumentByName -Event $fontsCsidl -Name "pszPath"
Assert-PointerValue -Value $fontsCsidlPath.postCallValue -Name "CSIDL_FONTS pszPath post value"
if ($fontsCsidlPath.decodedValue -notmatch "status=non_allowlisted_no_path" -or $fontsCsidlPath.decodedValue -match "path=")
{
    throw "CSIDL_FONTS should not expose a returned path: $($fontsCsidlPath | ConvertTo-Json -Depth 8)"
}

$shellPayload = $shellEvents | ConvertTo-Json -Depth 12
if ($shellPayload -cmatch "Users\\\\|AppData|Downloads|Desktop|Documents|Recent|Startup|SendTo|OneDrive|ShellExecute|SHFileOperation|SHGetFileInfo|PIDL|ITEMIDLIST|PropertyStore|CommandLine|Environment|BEGIN CERTIFICATE|PRIVATE KEY|Authorization|Cookie|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 shell events appear to expose user paths, shell payloads, credentials, PE/file/hash data, or byte-preview evidence: $shellPayload"
}

if ($shellPayload -cmatch "path=[^`"]*Fonts")
{
    throw "Wave 3 shell non-allowlisted Font queries exposed a path: $shellPayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 shell smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 shell known-folder smoke passed: events=$($result.capturedEvents.Count) shellEvents=$($shellEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
