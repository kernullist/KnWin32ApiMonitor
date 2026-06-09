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
    throw "Wave 2 advapi32 token query capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

if ($result.transportDroppedEvents -ne 0)
{
    throw "Token query healthy capture dropped transport events: $($result.transportDroppedEvents)"
}

$expected = @(
    @{ Api = "OpenProcessToken"; Category = "token_open"; Args = @("ProcessHandle", "DesiredAccess", "TokenHandle") },
    @{ Api = "LookupPrivilegeValueW"; Category = "privilege_lookup"; Args = @("lpSystemName", "lpName", "lpLuid") }
)

foreach ($item in $expected)
{
    $event = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api } | Select-Object -First 1)
    if ($event.Count -ne 1)
    {
        throw "Wave 2 token query smoke did not capture $($item.Api)."
    }

    if ($event[0].module -ne "advapi32.dll")
    {
        throw "$($item.Api) module mismatch: $($event[0].module)"
    }

    if ($event[0].apiFamily -ne "security" -or $event[0].apiCategory -ne $item.Category)
    {
        throw "$($item.Api) metadata mismatch: family=$($event[0].apiFamily) category=$($event[0].apiCategory)"
    }

    if ($event[0].hookPolicy -ne "iat" -or $event[0].coverageStatus -ne "smoke_verified")
    {
        throw "$($item.Api) hook metadata mismatch: hook=$($event[0].hookPolicy) coverage=$($event[0].coverageStatus)"
    }

    if (-not [string]::IsNullOrEmpty($event[0].bufferPreview))
    {
        throw "$($item.Api) exposed bufferPreview: $($event[0].bufferPreview)"
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

$openToken = @($result.capturedEvents | Where-Object { $_.api -eq "OpenProcessToken" } | Select-Object -First 1)
$openArgs = $openToken[0].arguments | ConvertTo-Json -Depth 8
if ($openArgs -notmatch "0x00000008")
{
    throw "OpenProcessToken did not include TOKEN_QUERY evidence: $openArgs"
}

$tokenHandle = @($openToken[0].arguments | Where-Object { $_.name -eq "TokenHandle" } | Select-Object -First 1)
if ($tokenHandle.Count -ne 1 -or $tokenHandle[0].postCallValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "OpenProcessToken did not include a non-null token handle value: $($tokenHandle[0] | ConvertTo-Json -Depth 8)"
}

$lookup = @($result.capturedEvents | Where-Object { $_.api -eq "LookupPrivilegeValueW" } | Select-Object -First 1)
$lookupArgs = $lookup[0].arguments | ConvertTo-Json -Depth 8
if ($lookupArgs -notmatch "SeChangeNotifyPrivilege")
{
    throw "LookupPrivilegeValueW did not include stable privilege-name evidence: $lookupArgs"
}

$systemName = @($lookup[0].arguments | Where-Object { $_.name -eq "lpSystemName" } | Select-Object -First 1)
if ($systemName.Count -ne 1 -or $systemName[0].rawValue -notmatch "^0x0+$")
{
    throw "LookupPrivilegeValueW lpSystemName was not null: $($systemName[0] | ConvertTo-Json -Depth 8)"
}

$luidArg = @($lookup[0].arguments | Where-Object { $_.name -eq "lpLuid" } | Select-Object -First 1)
if ($luidArg.Count -ne 1 -or $luidArg[0].decodedValue -notmatch "LowPart=0x" -or $luidArg[0].decodedValue -notmatch "HighPart=0x")
{
    throw "LookupPrivilegeValueW did not include LUID numeric evidence: $($luidArg[0] | ConvertTo-Json -Depth 8)"
}

if (@($result.capturedEvents | Where-Object { $_.api -eq "AdjustTokenPrivileges" }).Count -ne 0)
{
    throw "Token query smoke captured AdjustTokenPrivileges, which is out of scope."
}

if (@($result.capturedEvents | Where-Object { $_.apiFamily -eq "service-control" }).Count -ne 0)
{
    throw "Token query smoke captured service-control events, which are out of scope."
}

$securityArgs = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "security" } | ForEach-Object { $_.arguments } | ConvertTo-Json -Depth 8)
if ($securityArgs -cmatch "TOKEN_PRIVILEGES|S-1-[0-9-]+|Password|Credential|PRIVATE KEY|BinaryPath|ServiceName|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Token query events appear to expose mutation, SID, credential, service, or byte-preview evidence: $securityArgs"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 2 token query smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -lt $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 2 advapi32 token query smoke passed: events=$($result.capturedEvents.Count) tokenApis=$($expected.Count) overheadAvgUs=$($result.hookOverheadAvgUs)"
