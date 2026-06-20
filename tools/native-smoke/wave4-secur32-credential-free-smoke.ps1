param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$ProviderModule = "secur32.dll"
$CredentialFreeApi = "FreeCredentialsHandle"
$ContextDeleteApi = "DeleteSecurityContext"

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
if ($provider.Count -ne 1 -or $provider[0].id -ne 19)
{
    throw "Generated provider module mismatch for $ProviderModule`: $($provider | ConvertTo-Json -Depth 4)"
}

$freeEntry = @($ids.apis | Where-Object { $_.module -eq $ProviderModule -and $_.name -eq $CredentialFreeApi } | Select-Object -First 1)
if ($freeEntry.Count -ne 1 -or $freeEntry[0].id -ne 162)
{
    throw "Generated ID mismatch for $CredentialFreeApi`: expected=162 actual=$($freeEntry | ConvertTo-Json -Depth 4)"
}

$deleteEntry = @($ids.apis | Where-Object { $_.module -eq $ProviderModule -and $_.name -eq $ContextDeleteApi } | Select-Object -First 1)
if ($deleteEntry.Count -ne 1 -or $deleteEntry[0].id -ne 164)
{
    throw "Generated ID mismatch for $ContextDeleteApi`: expected=164 actual=$($deleteEntry | ConvertTo-Json -Depth 4)"
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Wave 4 SECUR32 capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 4 SECUR32 healthy capture dropped transport events: $droppedEvents"
}

$freeEvents = @($result.capturedEvents | Where-Object { $_.module -eq $ProviderModule -and $_.api -eq $CredentialFreeApi })
if ($freeEvents.Count -lt 1)
{
    throw "Wave 4 SECUR32 capture did not include $CredentialFreeApi."
}

$event = $freeEvents[0]
if ($event.apiFamily -ne "sspi" -or $event.apiCategory -ne "credential_free")
{
    throw "$CredentialFreeApi metadata mismatch: family=$($event.apiFamily) category=$($event.apiCategory)"
}

if ($event.hookPolicy -ne "iat" -or $event.coverageStatus -ne "smoke_verified")
{
    throw "$CredentialFreeApi hook metadata mismatch: hook=$($event.hookPolicy) coverage=$($event.coverageStatus)"
}

if ($event.returnValue -ne "0x00000000")
{
    throw "$CredentialFreeApi return evidence mismatch: $($event | ConvertTo-Json -Depth 8)"
}

if ($null -eq $event.durationUs -or $event.durationUs -lt 0)
{
    throw "$CredentialFreeApi missing duration evidence."
}

if (-not [string]::IsNullOrEmpty($event.bufferPreview))
{
    throw "$CredentialFreeApi exposed bufferPreview: $($event.bufferPreview)"
}

$credential = Get-ArgumentByName -Event $event -Name "phCredential"
if ($credential.decodeAlias -ne "handle_pointer" -or $credential.captureTiming -ne "pre")
{
    throw "$CredentialFreeApi phCredential metadata mismatch: $($credential | ConvertTo-Json -Depth 8)"
}

Assert-PointerValue -Value $credential.rawValue -Name "$CredentialFreeApi phCredential rawValue"
Assert-PointerValue -Value $credential.decodedValue -Name "$CredentialFreeApi phCredential decodedValue"

$eventData = $freeEvents | ConvertTo-Json -Depth 12
if ($eventData -cmatch "AcquireCredentialsHandle|InitializeSecurityContext|DeleteSecurityContext|SecBuffer|pAuthData|AuthData|pszPackage|pszPrincipal|TargetName|LogonId|SEC_WINNT_AUTH_IDENTITY|Password|Secret|Kerberos|Negotiate|NTLM|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|StackWalk|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 4 SECUR32 event appears to expose auth package, auth data, context buffers, payload, stack, injection, secret, or byte-preview evidence: $eventData"
}

$deleteEvents = @($result.capturedEvents | Where-Object { $_.module -eq $ProviderModule -and $_.api -eq $ContextDeleteApi })
if ($deleteEvents.Count -lt 1)
{
    throw "Wave 4 SECUR32 capture did not include $ContextDeleteApi."
}

$deleteEvent = $deleteEvents[0]
if ($deleteEvent.apiFamily -ne "sspi" -or $deleteEvent.apiCategory -ne "security_context_delete")
{
    throw "$ContextDeleteApi metadata mismatch: family=$($deleteEvent.apiFamily) category=$($deleteEvent.apiCategory)"
}

if ($deleteEvent.hookPolicy -ne "iat" -or $deleteEvent.coverageStatus -ne "smoke_verified")
{
    throw "$ContextDeleteApi hook metadata mismatch: hook=$($deleteEvent.hookPolicy) coverage=$($deleteEvent.coverageStatus)"
}

if ([string]::IsNullOrWhiteSpace($deleteEvent.returnValue) -or $deleteEvent.returnValue -notmatch "^0x[0-9a-fA-F]{8}$")
{
    throw "$ContextDeleteApi return evidence mismatch: $($deleteEvent | ConvertTo-Json -Depth 8)"
}

if ($null -eq $deleteEvent.durationUs -or $deleteEvent.durationUs -lt 0)
{
    throw "$ContextDeleteApi missing duration evidence."
}

if (-not [string]::IsNullOrEmpty($deleteEvent.bufferPreview))
{
    throw "$ContextDeleteApi exposed bufferPreview: $($deleteEvent.bufferPreview)"
}

$context = Get-ArgumentByName -Event $deleteEvent -Name "phContext"
if ($context.decodeAlias -ne "handle_pointer" -or $context.captureTiming -ne "pre")
{
    throw "$ContextDeleteApi phContext metadata mismatch: $($context | ConvertTo-Json -Depth 8)"
}

Assert-PointerValue -Value $context.rawValue -Name "$ContextDeleteApi phContext rawValue"
Assert-PointerValue -Value $context.decodedValue -Name "$ContextDeleteApi phContext decodedValue"

$deleteEventData = $deleteEvents | ConvertTo-Json -Depth 12
if ($deleteEventData -cmatch "AcquireCredentialsHandle|InitializeSecurityContext|SecBuffer|pAuthData|AuthData|pszPackage|pszPrincipal|TargetName|LogonId|SEC_WINNT_AUTH_IDENTITY|Password|Secret|Kerberos|Negotiate|NTLM|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|StackWalk|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 4 SECUR32 delete event appears to expose auth package, auth data, context buffers, payload, stack, injection, secret, or byte-preview evidence: $deleteEventData"
}

$installed = @($result.agentMessages | Where-Object {
    $_.messageType -eq "hook_installed" -and
    $_.module -eq $ProviderModule -and
    ($_.api -eq $CredentialFreeApi -or $_.api -eq $ContextDeleteApi)
})
foreach ($api in @($CredentialFreeApi, $ContextDeleteApi))
{
    $installedApi = @($installed | Where-Object { $_.api -eq $api })
    if ($installedApi.Count -lt 1)
    {
        throw "Wave 4 SECUR32 hook install evidence is incomplete for $api."
    }
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 4 SECUR32 capture did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Unexpected hook lifecycle counts: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 4 SECUR32 lifecycle smoke passed: freeEvents=$($freeEvents.Count) deleteEvents=$($deleteEvents.Count) installed=$($installed.Count) restored=$($shutdown[0].restoredHooks)"
