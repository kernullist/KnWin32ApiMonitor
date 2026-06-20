param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "wintrust.dll"
$SelectedApi = "WTHelperProvDataFromStateData"

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
if ($provider.Count -ne 1 -or $provider[0].id -ne 25)
{
    throw "Generated provider module mismatch for $ProviderModule`: $($provider | ConvertTo-Json -Depth 4)"
}

$entry = @($ids.apis | Where-Object { $_.module -eq $ProviderModule -and $_.name -eq $SelectedApi } | Select-Object -First 1)
if ($entry.Count -ne 1 -or $entry[0].id -ne 177)
{
    throw "Generated ID mismatch for $SelectedApi`: expected=177 actual=$($entry | ConvertTo-Json -Depth 4)"
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Wave 4 WINTRUST capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 4 WINTRUST healthy capture dropped transport events: $droppedEvents"
}

$events = @($result.capturedEvents | Where-Object { $_.module -eq $ProviderModule -and $_.api -eq $SelectedApi })
if ($events.Count -lt 1)
{
    throw "Wave 4 WINTRUST capture did not include $SelectedApi."
}

$event = $events[0]
if ($event.apiFamily -ne "trust" -or $event.apiCategory -ne "trust_state_query")
{
    throw "$SelectedApi metadata mismatch: family=$($event.apiFamily) category=$($event.apiCategory)"
}

if ($event.hookPolicy -ne "iat" -or $event.coverageStatus -ne "smoke_verified")
{
    throw "$SelectedApi hook metadata mismatch: hook=$($event.hookPolicy) coverage=$($event.coverageStatus)"
}

Assert-PointerValue -Value $event.returnValue -Name "$SelectedApi returnValue" -AllowNull $true
if ($event.returnValue -notmatch "^0x0+$")
{
    throw "$SelectedApi null-state sample returned provider data unexpectedly: $($event | ConvertTo-Json -Depth 8)"
}

if ($null -eq $event.durationUs -or $event.durationUs -lt 0)
{
    throw "$SelectedApi missing duration evidence."
}

if (-not [string]::IsNullOrEmpty($event.bufferPreview))
{
    throw "$SelectedApi exposed bufferPreview: $($event.bufferPreview)"
}

$stateData = Get-ArgumentByName -Event $event -Name "hStateData"
if ($stateData.decodeAlias -ne "handle" -or $stateData.captureTiming -ne "pre")
{
    throw "$SelectedApi hStateData metadata mismatch: $($stateData | ConvertTo-Json -Depth 8)"
}

Assert-PointerValue -Value $stateData.rawValue -Name "$SelectedApi hStateData rawValue" -AllowNull $true
Assert-PointerValue -Value $stateData.decodedValue -Name "$SelectedApi hStateData decodedValue" -AllowNull $true
if ($stateData.rawValue -notmatch "^0x0+$" -or $stateData.decodedValue -notmatch "^0x0+$")
{
    throw "$SelectedApi hStateData was expected to stay null and pointer-only: $($stateData | ConvertTo-Json -Depth 8)"
}

$eventData = $events | ConvertTo-Json -Depth 12
if ($eventData -cmatch "WINTRUST_DATA|WIN_CERTIFICATE|Signer|Certificate|CertChain|Catalog|Subject|Issuer|Thumbprint|SHA256|SHA1|MD5|Authenticode|WinVerifyTrust|FilePath|C:\\Users|AppData|ProgramData|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|StackWalk|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 4 WINTRUST event appears to expose trust state, certificate, catalog, path, payload, stack, injection, credential, or byte-preview evidence: $eventData"
}

$installed = @($result.agentMessages | Where-Object {
    $_.messageType -eq "hook_installed" -and
    $_.module -eq $ProviderModule -and
    $_.api -eq $SelectedApi
})
if ($installed.Count -lt 1)
{
    throw "Wave 4 WINTRUST hook install evidence is incomplete."
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 4 WINTRUST capture did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Unexpected hook lifecycle counts: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 4 WINTRUST state-query smoke passed: events=$($events.Count) installed=$($installed.Count) restored=$($shutdown[0].restoredHooks)"
