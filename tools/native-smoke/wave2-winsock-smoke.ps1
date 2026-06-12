param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

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
$provider = @($ids.modules | Where-Object { $_.name -ieq "ws2_32.dll" } | Select-Object -First 1)
if ($provider.Count -ne 1 -or $provider[0].id -ne 8)
{
    throw "Generated provider module mismatch for ws2_32.dll: $($provider | ConvertTo-Json -Depth 4)"
}

$connectId = @($ids.apis | Where-Object { $_.module -ieq "ws2_32.dll" -and $_.name -eq "connect" } | Select-Object -First 1)
if ($connectId.Count -ne 1 -or $connectId[0].id -ne 63)
{
    throw "Generated ID mismatch for connect: $($connectId | ConvertTo-Json -Depth 4)"
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
    @{ Api = "connect"; Category = "socket_connect"; Args = @("s", "name", "namelen") },
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

$connectEvent = @($result.capturedEvents | Where-Object { $_.api -eq "connect" } | Select-Object -First 1)
if ($connectEvent.Count -ne 1)
{
    throw "Winsock connect event was not captured."
}

if ($connectEvent[0].returnValue -ne "0" -and $connectEvent[0].returnValue -ne "0 (0x00000000)")
{
    throw "Winsock connect did not return success: $($connectEvent[0].returnValue)"
}

if (-not [string]::IsNullOrEmpty($connectEvent[0].bufferPreview))
{
    throw "Winsock connect exposed bufferPreview: $($connectEvent[0] | ConvertTo-Json -Depth 8)"
}

$connectSocket = @($connectEvent[0].arguments | Where-Object { $_.name -eq "s" } | Select-Object -First 1)
if ($connectSocket.Count -ne 1 -or $connectSocket[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "Winsock connect did not include non-null socket handle evidence: $($connectSocket | ConvertTo-Json -Depth 8)"
}

$connectAddress = @($connectEvent[0].arguments | Where-Object { $_.name -eq "name" } | Select-Object -First 1)
if ($connectAddress.Count -ne 1 -or
    $connectAddress[0].decodeAlias -ne "sockaddr" -or
    $connectAddress[0].decodeStatus -ne "decoded" -or
    $connectAddress[0].rawValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $connectAddress[0].decodedValue -notmatch "^127\.0\.0\.1:[0-9]+$")
{
    throw "Winsock connect sockaddr evidence mismatch: $($connectAddress | ConvertTo-Json -Depth 8)"
}

$connectLength = @($connectEvent[0].arguments | Where-Object { $_.name -eq "namelen" } | Select-Object -First 1)
if ($connectLength.Count -ne 1 -or
    $connectLength[0].decodeAlias -ne "byte_count" -or
    ($connectLength[0].decodedValue -ne "16" -and $connectLength[0].decodedValue -notmatch "^16 "))
{
    throw "Winsock connect namelen evidence mismatch: $($connectLength | ConvertTo-Json -Depth 8)"
}

$connectPayload = $connectEvent[0] | ConvertTo-Json -Depth 12
if ($connectPayload -cmatch "socket_send|socket_recv|sendto|recvfrom|WSASend|WSARecv|WinHttp|InternetOpenUrl|HttpSend|Header|Cookie|Authorization|Password|Credential|Proxy|DNS|Adapter|RouteTable|CommandLine|Environment|TOKEN_|SecurityDescriptor|SID|ACL|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|Injection|BEGIN CERTIFICATE|PRIVATE KEY|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Winsock connect event appears to expose payload-heavy, credential, inventory, remote-memory, stack, injection, or byte-preview evidence: $connectPayload"
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
