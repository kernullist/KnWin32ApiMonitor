param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $HelperPath))
{
    throw "Helper not found: $HelperPath"
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Wave 2 registry capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

if ($result.transportDroppedEvents -ne 0)
{
    throw "Registry healthy capture dropped transport events: $($result.transportDroppedEvents)"
}

$expected = @(
    @{ Api = "RegOpenKeyExW"; Category = "registry_key_open"; Args = @("hKey", "lpSubKey", "ulOptions", "samDesired", "phkResult") },
    @{ Api = "RegCreateKeyExW"; Category = "registry_key_create"; Args = @("hKey", "lpSubKey", "Reserved", "lpClass", "dwOptions", "samDesired", "lpSecurityAttributes", "phkResult", "lpdwDisposition") },
    @{ Api = "RegQueryValueExW"; Category = "registry_value_query"; Args = @("hKey", "lpValueName", "lpReserved", "lpType", "lpData", "lpcbData") },
    @{ Api = "RegSetValueExW"; Category = "registry_value_set"; Args = @("hKey", "lpValueName", "Reserved", "dwType", "lpData", "cbData") },
    @{ Api = "RegDeleteValueW"; Category = "registry_value_delete"; Args = @("hKey", "lpValueName") },
    @{ Api = "RegCloseKey"; Category = "registry_key_close"; Args = @("hKey") }
)

foreach ($item in $expected)
{
    $event = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api } | Select-Object -First 1)
    if ($event.Count -ne 1)
    {
        throw "Wave 2 registry smoke did not capture $($item.Api)."
    }

    if ($event[0].module -ne "advapi32.dll")
    {
        throw "$($item.Api) module mismatch: $($event[0].module)"
    }

    if ($event[0].apiFamily -ne "registry" -or $event[0].apiCategory -ne $item.Category)
    {
        throw "$($item.Api) metadata mismatch: family=$($event[0].apiFamily) category=$($event[0].apiCategory)"
    }

    if ($event[0].hookPolicy -ne "iat" -or $event[0].coverageStatus -ne "smoke_verified")
    {
        throw "$($item.Api) hook metadata mismatch: hook=$($event[0].hookPolicy) coverage=$($event[0].coverageStatus)"
    }

    foreach ($argName in $item.Args)
    {
        $argument = @($event[0].arguments | Where-Object { $_.name -eq $argName } | Select-Object -First 1)
        if ($argument.Count -ne 1)
        {
            throw "$($item.Api) argument missing: $argName"
        }

        if ([string]::IsNullOrWhiteSpace($argument[0].decodeAlias))
        {
            throw "$($item.Api) argument decode alias missing: $argName"
        }
    }
}

$createEvent = @($result.capturedEvents | Where-Object { $_.api -eq "RegCreateKeyExW" } | Select-Object -First 1)
$createArgs = $createEvent[0].arguments | ConvertTo-Json -Depth 8
if ($createArgs -notmatch "KNMonApiMonitorSample")
{
    throw "RegCreateKeyExW did not include sample key evidence: $createArgs"
}

$openEvent = @($result.capturedEvents | Where-Object { $_.api -eq "RegOpenKeyExW" } | Select-Object -First 1)
$openArgs = $openEvent[0].arguments | ConvertTo-Json -Depth 8
if ($openArgs -notmatch "KNMonApiMonitorSample")
{
    throw "RegOpenKeyExW did not include sample key evidence: $openArgs"
}

$setEvent = @($result.capturedEvents | Where-Object { $_.api -eq "RegSetValueExW" } | Select-Object -First 1)
$setArgs = $setEvent[0].arguments | ConvertTo-Json -Depth 8
if ($setArgs -notmatch "SampleValue" -or $setArgs -notmatch "KNMon registry sample value")
{
    throw "RegSetValueExW did not include value-name/data evidence: $setArgs"
}

$queryEvent = @($result.capturedEvents | Where-Object { $_.api -eq "RegQueryValueExW" } | Select-Object -First 1)
$queryArgs = $queryEvent[0].arguments | ConvertTo-Json -Depth 8
if ($queryArgs -notmatch "SampleValue" -or $queryArgs -notmatch "KNMon registry sample value")
{
    throw "RegQueryValueExW did not include value-name/data evidence: $queryArgs"
}

$deleteEvent = @($result.capturedEvents | Where-Object { $_.api -eq "RegDeleteValueW" } | Select-Object -First 1)
$deleteArgs = $deleteEvent[0].arguments | ConvertTo-Json -Depth 8
if ($deleteArgs -notmatch "SampleValue")
{
    throw "RegDeleteValueW did not include value-name evidence: $deleteArgs"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 2 registry smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -lt $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 2 registry smoke passed: events=$($result.capturedEvents.Count) registryApis=$($expected.Count) overheadAvgUs=$($result.hookOverheadAvgUs)"
