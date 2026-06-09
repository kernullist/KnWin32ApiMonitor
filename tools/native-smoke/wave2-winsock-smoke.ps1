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
    throw "Wave 2 Winsock capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

if ($result.transportDroppedEvents -ne 0)
{
    throw "Winsock healthy capture dropped transport events: $($result.transportDroppedEvents)"
}

$expected = @(
    @{ Api = "WSAStartup"; Category = "winsock_startup"; Args = @("wVersionRequested", "lpWSAData") },
    @{ Api = "WSACleanup"; Category = "winsock_cleanup"; Args = @() },
    @{ Api = "socket"; Category = "socket_create"; Args = @("af", "type", "protocol") },
    @{ Api = "closesocket"; Category = "socket_close"; Args = @("s") },
    @{ Api = "getaddrinfo"; Category = "socket_address_resolve"; Args = @("pNodeName", "pServiceName", "pHints", "ppResult") },
    @{ Api = "freeaddrinfo"; Category = "socket_address_free"; Args = @("pAddrInfo") },
    @{ Api = "WSAGetLastError"; Category = "winsock_error_query"; Args = @() }
)

foreach ($item in $expected)
{
    $event = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api } | Select-Object -First 1)
    if ($event.Count -ne 1)
    {
        throw "Wave 2 Winsock smoke did not capture $($item.Api)."
    }

    if ($event[0].module -ne "ws2_32.dll")
    {
        throw "$($item.Api) module mismatch: $($event[0].module)"
    }

    if ($event[0].apiFamily -ne "network" -or $event[0].apiCategory -ne $item.Category)
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

$getAddrInfo = @($result.capturedEvents | Where-Object { $_.api -eq "getaddrinfo" } | Select-Object -First 1)
$getAddrInfoArgs = $getAddrInfo[0].arguments | ConvertTo-Json -Depth 8
if ($getAddrInfoArgs -notmatch "localhost" -or $getAddrInfoArgs -notmatch '"80"')
{
    throw "getaddrinfo did not include localhost service evidence: $getAddrInfoArgs"
}

$socketEvent = @($result.capturedEvents | Where-Object { $_.api -eq "socket" } | Select-Object -First 1)
if ($socketEvent[0].returnValue -notmatch '^0x[0-9a-fA-F]+$')
{
    throw "socket returnValue is not a hex handle: $($socketEvent[0].returnValue)"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 2 Winsock smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -lt $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 2 Winsock smoke passed: events=$($result.capturedEvents.Count) winsockApis=$($expected.Count) overheadAvgUs=$($result.hookOverheadAvgUs)"
