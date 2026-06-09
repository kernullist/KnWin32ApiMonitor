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
    throw "Wave 2 WinINet capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

if ($result.transportDroppedEvents -ne 0)
{
    throw "WinINet healthy capture dropped transport events: $($result.transportDroppedEvents)"
}

$expected = @(
    @{ Api = "InternetOpenW"; Category = "wininet_session_open"; Args = @("lpszAgent", "dwAccessType", "lpszProxy", "lpszProxyBypass", "dwFlags") },
    @{ Api = "InternetCloseHandle"; Category = "wininet_handle_close"; Args = @("hInternet") }
)

foreach ($item in $expected)
{
    $event = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api } | Select-Object -First 1)
    if ($event.Count -ne 1)
    {
        throw "Wave 2 WinINet smoke did not capture $($item.Api)."
    }

    if ($event[0].module -ne "wininet.dll")
    {
        throw "$($item.Api) module mismatch: $($event[0].module)"
    }

    if ($event[0].apiFamily -ne "internet" -or $event[0].apiCategory -ne $item.Category)
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

$openEvent = @($result.capturedEvents | Where-Object { $_.api -eq "InternetOpenW" } | Select-Object -First 1)
$openArgs = $openEvent[0].arguments | ConvertTo-Json -Depth 8
if ($openArgs -notmatch "KNMonWinInetSample/1.0")
{
    throw "InternetOpenW did not include sample user-agent evidence: $openArgs"
}

if ($openArgs -notmatch "0x00000001")
{
    throw "InternetOpenW did not include INTERNET_OPEN_TYPE_DIRECT evidence: $openArgs"
}

foreach ($argName in @("lpszProxy", "lpszProxyBypass"))
{
    $argument = @($openEvent[0].arguments | Where-Object { $_.name -eq $argName } | Select-Object -First 1)
    if ($argument.Count -ne 1)
    {
        throw "InternetOpenW missing $argName."
    }

    if ($argument[0].rawValue -notmatch "^0x0+$")
    {
        throw "InternetOpenW $argName was not null: $($argument[0] | ConvertTo-Json -Depth 8)"
    }
}

$wininetArgs = @($result.capturedEvents | Where-Object { $_.module -eq "wininet.dll" } | ForEach-Object { $_.arguments } | ConvertTo-Json -Depth 8)
if ($wininetArgs -cmatch "https?://|Authorization|Cookie|Set-Cookie|POST|GET /|BEGIN CERTIFICATE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "WinINet events appear to expose URL/header/body/credential or byte-preview evidence: $wininetArgs"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 2 WinINet smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -lt $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 2 WinINet session smoke passed: events=$($result.capturedEvents.Count) wininetApis=$($expected.Count) overheadAvgUs=$($result.hookOverheadAvgUs)"
