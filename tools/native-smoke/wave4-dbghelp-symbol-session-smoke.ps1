param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "dbghelp.dll"
$SelectedApis = @(
    "SymInitializeW",
    "SymCleanup"
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
        throw "Wave 4 DBGHELP smoke did not capture $Api."
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
if ($provider.Count -ne 1 -or $provider[0].id -ne 26)
{
    throw "Generated provider module mismatch for $ProviderModule`: $($provider | ConvertTo-Json -Depth 4)"
}

$expectedIds = @(
    @{ Api = "SymInitializeW"; Id = 178 },
    @{ Api = "SymCleanup"; Id = 179 }
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
    throw "Wave 4 DBGHELP capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 4 DBGHELP healthy capture dropped transport events: $droppedEvents"
}

$dbghelpEvents = @($result.capturedEvents | Where-Object { $_.module -eq $ProviderModule -and $SelectedApis -contains $_.api })
if ($dbghelpEvents.Count -lt $SelectedApis.Count)
{
    throw "Wave 4 DBGHELP capture did not include all selected events."
}

$expected = @(
    @{ Api = "SymInitializeW"; Family = "symbols"; Category = "symbol_session_initialize"; Args = @(
        @{ Name = "hProcess"; Alias = "handle"; Timing = "pre" },
        @{ Name = "UserSearchPath"; Alias = "pointer"; Timing = "pre" },
        @{ Name = "fInvadeProcess"; Alias = "byte_count"; Timing = "pre" }
    ) },
    @{ Api = "SymCleanup"; Family = "symbols"; Category = "symbol_session_cleanup"; Args = @(
        @{ Name = "hProcess"; Alias = "handle"; Timing = "pre" }
    ) }
)

foreach ($item in $expected)
{
    $event = Get-EventByApi -Events $dbghelpEvents -Api $item.Api
    if ($event.apiFamily -ne $item.Family -or $event.apiCategory -ne $item.Category)
    {
        throw "$($item.Api) metadata mismatch: family=$($event.apiFamily) category=$($event.apiCategory)"
    }

    if ($event.hookPolicy -ne "iat" -or $event.coverageStatus -ne "smoke_verified")
    {
        throw "$($item.Api) hook metadata mismatch: hook=$($event.hookPolicy) coverage=$($event.coverageStatus)"
    }

    if ($event.returnValue -ne "TRUE")
    {
        throw "$($item.Api) did not return TRUE: $($event | ConvertTo-Json -Depth 8)"
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

$initialize = Get-EventByApi -Events $dbghelpEvents -Api "SymInitializeW"
$initializeProcess = Get-ArgumentByName -Event $initialize -Name "hProcess"
Assert-PointerValue -Value $initializeProcess.decodedValue -Name "SymInitializeW hProcess"

$searchPath = Get-ArgumentByName -Event $initialize -Name "UserSearchPath"
Assert-PointerValue -Value $searchPath.rawValue -Name "SymInitializeW UserSearchPath rawValue" -AllowNull $true
Assert-PointerValue -Value $searchPath.decodedValue -Name "SymInitializeW UserSearchPath decodedValue" -AllowNull $true
if ($searchPath.rawValue -notmatch "^0x0+$" -or $searchPath.decodedValue -notmatch "^0x0+$")
{
    throw "SymInitializeW UserSearchPath was expected to stay null and pointer-only: $($searchPath | ConvertTo-Json -Depth 8)"
}

$invadeProcess = Get-ArgumentByName -Event $initialize -Name "fInvadeProcess"
if ($invadeProcess.decodedValue -ne "FALSE")
{
    throw "SymInitializeW fInvadeProcess was not FALSE: $($invadeProcess | ConvertTo-Json -Depth 8)"
}

$cleanup = Get-EventByApi -Events $dbghelpEvents -Api "SymCleanup"
$cleanupProcess = Get-ArgumentByName -Event $cleanup -Name "hProcess"
Assert-PointerValue -Value $cleanupProcess.decodedValue -Name "SymCleanup hProcess"
if ($cleanupProcess.decodedValue -ne $initializeProcess.decodedValue)
{
    throw "SymCleanup process handle did not match SymInitializeW: init=$($initializeProcess.decodedValue) cleanup=$($cleanupProcess.decodedValue)"
}

$payload = $dbghelpEvents | ConvertTo-Json -Depth 12
if ($payload -cmatch "\.pdb|PDB|SymbolPath|SymEnum|SymFrom|SymLoad|LoadedModule|srv\*|symsrv|C:\\Users|AppData|ProgramData|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|StackWalk|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 4 DBGHELP events appear to expose symbol path, PDB, module, payload, stack, injection, credential, or byte-preview evidence: $payload"
}

$installed = @($result.agentMessages | Where-Object {
    $_.messageType -eq "hook_installed" -and
    $_.module -eq $ProviderModule -and
    $SelectedApis -contains $_.api
})
if ($installed.Count -lt $SelectedApis.Count)
{
    throw "Wave 4 DBGHELP hook install evidence is incomplete."
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 4 DBGHELP capture did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Unexpected hook lifecycle counts: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 4 DBGHELP symbol-session smoke passed: events=$($dbghelpEvents.Count) installed=$($installed.Count) restored=$($shutdown[0].restoredHooks)"
