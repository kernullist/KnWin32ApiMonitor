param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "dnsapi.dll"
$SelectedApi = "DnsRecordListFree"
$ImportApi = "DnsFree"

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
if ($provider.Count -ne 1 -or $provider[0].id -ne 21)
{
    throw "Generated provider module mismatch for $ProviderModule`: $($provider | ConvertTo-Json -Depth 4)"
}

$entry = @($ids.apis | Where-Object { $_.module -eq $ProviderModule -and $_.name -eq $SelectedApi } | Select-Object -First 1)
if ($entry.Count -ne 1 -or $entry[0].id -ne 169)
{
    throw "Generated ID mismatch for $SelectedApi`: expected=169 actual=$($entry | ConvertTo-Json -Depth 4)"
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Wave 4 DNSAPI capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 4 DNSAPI healthy capture dropped transport events: $droppedEvents"
}

$dnsEvents = @($result.capturedEvents | Where-Object { $_.module -eq $ProviderModule -and $_.api -eq $SelectedApi })
if ($dnsEvents.Count -lt 1)
{
    throw "Wave 4 DNSAPI capture did not include $SelectedApi."
}

$event = $dnsEvents[0]
if ($event.apiFamily -ne "dns" -or $event.apiCategory -ne "dns_record_list_free")
{
    throw "$SelectedApi metadata mismatch: family=$($event.apiFamily) category=$($event.apiCategory)"
}

if ($event.hookPolicy -ne "iat" -or $event.coverageStatus -ne "smoke_verified")
{
    throw "$SelectedApi hook metadata mismatch: hook=$($event.hookPolicy) coverage=$($event.coverageStatus)"
}

if ($event.returnValue -ne "void")
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

$recordList = Get-ArgumentByName -Event $event -Name "pRecordList"
if ($recordList.decodeAlias -ne "pointer" -or $recordList.captureTiming -ne "pre")
{
    throw "$SelectedApi pRecordList metadata mismatch: $($recordList | ConvertTo-Json -Depth 8)"
}

Assert-PointerValue -Value $recordList.rawValue -Name "$SelectedApi pRecordList rawValue" -AllowNull $true
Assert-PointerValue -Value $recordList.decodedValue -Name "$SelectedApi pRecordList decodedValue" -AllowNull $true
if ($recordList.rawValue -notmatch "^0x0+$" -or $recordList.decodedValue -notmatch "^0x0+$")
{
    throw "$SelectedApi sample should use null record-list evidence: $($recordList | ConvertTo-Json -Depth 8)"
}

$freeType = Get-ArgumentByName -Event $event -Name "FreeType"
if ($freeType.decodeAlias -ne "dword_value" -or $freeType.captureTiming -ne "pre")
{
    throw "$SelectedApi FreeType metadata mismatch: $($freeType | ConvertTo-Json -Depth 8)"
}

if ($freeType.rawValue -ne "1" -or $freeType.decodedValue -notmatch "^1( \(0x00000001\))?$")
{
    throw "$SelectedApi FreeType evidence mismatch: $($freeType | ConvertTo-Json -Depth 8)"
}

$eventData = $dnsEvents | ConvertTo-Json -Depth 12
if ($eventData -cmatch "DnsQuery|pszName|ppQueryResults|pReserved|DNS_RECORDW|DnsRecordSet|DnsExtract|DnsModify|[a-zA-Z0-9_-]+\.(com|net|org|local|test)|127\.0\.0\.1|Adapter|RouteTable|C:\\Users|AppData|ProgramData|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|StackWalk|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 4 DNSAPI event appears to expose query, record, hostname, inventory, payload, stack, injection, credential, or byte-preview evidence: $eventData"
}

$installed = @($result.agentMessages | Where-Object {
    $_.messageType -eq "hook_installed" -and
    $_.module -eq $ProviderModule -and
    $_.api -eq $ImportApi
})
if ($installed.Count -lt 1)
{
    throw "Wave 4 DNSAPI hook install evidence is incomplete."
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 4 DNSAPI capture did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Unexpected hook lifecycle counts: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 4 DNSAPI record-list smoke passed: events=$($dnsEvents.Count) installed=$($installed.Count) restored=$($shutdown[0].restoredHooks)"
