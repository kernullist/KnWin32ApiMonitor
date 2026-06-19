param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "userenv.dll"
$SelectedApi = "DestroyEnvironmentBlock"

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
if ($provider.Count -ne 1 -or $provider[0].id -ne 20)
{
    throw "Generated provider module mismatch for $ProviderModule`: $($provider | ConvertTo-Json -Depth 4)"
}

$entry = @($ids.apis | Where-Object { $_.module -eq $ProviderModule -and $_.name -eq $SelectedApi } | Select-Object -First 1)
if ($entry.Count -ne 1 -or $entry[0].id -ne 167)
{
    throw "Generated ID mismatch for $SelectedApi`: expected=167 actual=$($entry | ConvertTo-Json -Depth 4)"
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Wave 4 USERENV capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 4 USERENV healthy capture dropped transport events: $droppedEvents"
}

$userenvEvents = @($result.capturedEvents | Where-Object { $_.module -eq $ProviderModule -and $_.api -eq $SelectedApi })
if ($userenvEvents.Count -lt 1)
{
    throw "Wave 4 USERENV capture did not include $SelectedApi."
}

$event = $userenvEvents[0]
if ($event.apiFamily -ne "profile" -or $event.apiCategory -ne "environment_block_destroy")
{
    throw "$SelectedApi metadata mismatch: family=$($event.apiFamily) category=$($event.apiCategory)"
}

if ($event.hookPolicy -ne "iat" -or $event.coverageStatus -ne "smoke_verified")
{
    throw "$SelectedApi hook metadata mismatch: hook=$($event.hookPolicy) coverage=$($event.coverageStatus)"
}

if ($event.returnValue -ne "TRUE")
{
    throw "$SelectedApi return evidence mismatch: $($event | ConvertTo-Json -Depth 8)"
}

if ($null -eq $event.durationUs -or $event.durationUs -lt 0)
{
    throw "$SelectedApi missing duration evidence."
}

if (-not [string]::IsNullOrEmpty($event.bufferPreview))
{
    throw "$SelectedApi exposed bufferPreview: $($event.bufferPreview)"
}

$environment = Get-ArgumentByName -Event $event -Name "lpEnvironment"
if ($environment.decodeAlias -ne "pointer" -or $environment.captureTiming -ne "pre")
{
    throw "$SelectedApi lpEnvironment metadata mismatch: $($environment | ConvertTo-Json -Depth 8)"
}

Assert-PointerValue -Value $environment.rawValue -Name "$SelectedApi lpEnvironment rawValue"
Assert-PointerValue -Value $environment.decodedValue -Name "$SelectedApi lpEnvironment decodedValue"

$eventData = $userenvEvents | ConvertTo-Json -Depth 12
if ($eventData -cmatch "CreateEnvironmentBlock|GetUserProfileDirectory|lpProfileDir|USERPROFILE=|APPDATA=|LOCALAPPDATA=|PATH=|SystemRoot=|USERNAME=|USERDOMAIN=|TEMP=|TMP=|ProgramFiles=|ComSpec=|HOMEDRIVE=|HOMEPATH=|LOGONSERVER=|C:\\Users|Desktop|Documents|Downloads|CommandLine|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|StackWalk|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 4 USERENV event appears to expose environment strings, profile paths, payload, stack, injection, credential, or byte-preview evidence: $eventData"
}

$installed = @($result.agentMessages | Where-Object {
    $_.messageType -eq "hook_installed" -and
    $_.module -eq $ProviderModule -and
    $_.api -eq $SelectedApi
})
if ($installed.Count -lt 1)
{
    throw "Wave 4 USERENV hook install evidence is incomplete."
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 4 USERENV capture did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Unexpected hook lifecycle counts: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 4 USERENV environment-block destroy smoke passed: events=$($userenvEvents.Count) installed=$($installed.Count) restored=$($shutdown[0].restoredHooks)"
