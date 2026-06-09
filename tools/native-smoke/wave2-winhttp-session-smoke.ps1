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
    throw "Wave 2 WinHTTP capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

if ($result.transportDroppedEvents -ne 0)
{
    throw "WinHTTP healthy capture dropped transport events: $($result.transportDroppedEvents)"
}

$expected = @(
    @{ Api = "WinHttpOpen"; Category = "winhttp_session_open"; Args = @("pszAgentW", "dwAccessType", "pszProxyW", "pszProxyBypassW", "dwFlags") },
    @{ Api = "WinHttpCloseHandle"; Category = "winhttp_handle_close"; Args = @("hInternet") }
)

foreach ($item in $expected)
{
    $event = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api } | Select-Object -First 1)
    if ($event.Count -ne 1)
    {
        throw "Wave 2 WinHTTP smoke did not capture $($item.Api)."
    }

    if ($event[0].module -ne "winhttp.dll")
    {
        throw "$($item.Api) module mismatch: $($event[0].module)"
    }

    if ($event[0].apiFamily -ne "http" -or $event[0].apiCategory -ne $item.Category)
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

$openEvent = @($result.capturedEvents | Where-Object { $_.api -eq "WinHttpOpen" } | Select-Object -First 1)
$openArgs = $openEvent[0].arguments | ConvertTo-Json -Depth 8
if ($openArgs -notmatch "KNMonWinHttpSample/1.0")
{
    throw "WinHttpOpen did not include sample user-agent evidence: $openArgs"
}

if ($openArgs -notmatch "0x00000001")
{
    throw "WinHttpOpen did not include WINHTTP_ACCESS_TYPE_NO_PROXY evidence: $openArgs"
}

foreach ($argName in @("pszProxyW", "pszProxyBypassW"))
{
    $argument = @($openEvent[0].arguments | Where-Object { $_.name -eq $argName } | Select-Object -First 1)
    if ($argument.Count -ne 1)
    {
        throw "WinHttpOpen missing $argName."
    }

    if ($argument[0].rawValue -notmatch "^0x0+$")
    {
        throw "WinHttpOpen $argName was not null: $($argument[0] | ConvertTo-Json -Depth 8)"
    }
}

$winhttpArgs = @($result.capturedEvents | Where-Object { $_.module -eq "winhttp.dll" } | ForEach-Object { $_.arguments } | ConvertTo-Json -Depth 8)
if ($winhttpArgs -cmatch "https?://|Authorization|Cookie|Set-Cookie|POST|GET /|BEGIN CERTIFICATE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "WinHTTP events appear to expose URL/header/body/credential or byte-preview evidence: $winhttpArgs"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 2 WinHTTP smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -lt $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 2 WinHTTP session smoke passed: events=$($result.capturedEvents.Count) winhttpApis=$($expected.Count) overheadAvgUs=$($result.hookOverheadAvgUs)"
