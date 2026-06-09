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
    throw "Wave 2 bcrypt CNG capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

if ($result.transportDroppedEvents -ne 0)
{
    throw "bcrypt healthy capture dropped transport events: $($result.transportDroppedEvents)"
}

$expected = @(
    @{ Api = "BCryptOpenAlgorithmProvider"; Category = "cng_algorithm_open"; Args = @("phAlgorithm", "pszAlgId", "pszImplementation", "dwFlags") },
    @{ Api = "BCryptCloseAlgorithmProvider"; Category = "cng_algorithm_close"; Args = @("hAlgorithm", "dwFlags") },
    @{ Api = "BCryptGetProperty"; Category = "cng_property_get"; Args = @("hObject", "pszProperty", "pbOutput", "cbOutput", "pcbResult", "dwFlags") },
    @{ Api = "BCryptGenRandom"; Category = "cng_random"; Args = @("hAlgorithm", "pbBuffer", "cbBuffer", "dwFlags") }
)

foreach ($item in $expected)
{
    $event = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api } | Select-Object -First 1)
    if ($event.Count -ne 1)
    {
        throw "Wave 2 bcrypt smoke did not capture $($item.Api)."
    }

    if ($event[0].module -ne "bcrypt.dll")
    {
        throw "$($item.Api) module mismatch: $($event[0].module)"
    }

    if ($event[0].apiFamily -ne "crypto" -or $event[0].apiCategory -ne $item.Category)
    {
        throw "$($item.Api) metadata mismatch: family=$($event[0].apiFamily) category=$($event[0].apiCategory)"
    }

    if ($event[0].hookPolicy -ne "iat" -or $event[0].coverageStatus -ne "smoke_verified")
    {
        throw "$($item.Api) hook metadata mismatch: hook=$($event[0].hookPolicy) coverage=$($event[0].coverageStatus)"
    }

    if ($event[0].returnValue -ne "0x00000000")
    {
        throw "$($item.Api) return value mismatch: $($event[0].returnValue)"
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

$openEvent = @($result.capturedEvents | Where-Object { $_.api -eq "BCryptOpenAlgorithmProvider" } | Select-Object -First 1)
$openArgs = $openEvent[0].arguments | ConvertTo-Json -Depth 8
if ($openArgs -notmatch "RNG")
{
    throw "BCryptOpenAlgorithmProvider did not include RNG algorithm evidence: $openArgs"
}

$propertyEvent = @($result.capturedEvents | Where-Object { $_.api -eq "BCryptGetProperty" } | Select-Object -First 1)
$propertyArgs = $propertyEvent[0].arguments | ConvertTo-Json -Depth 8
if ($propertyArgs -notmatch "AlgorithmName" -or $propertyArgs -notmatch "RNG")
{
    throw "BCryptGetProperty did not include AlgorithmName/RNG evidence: $propertyArgs"
}

$randomEvent = @($result.capturedEvents | Where-Object { $_.api -eq "BCryptGenRandom" } | Select-Object -First 1)
if (-not [string]::IsNullOrEmpty($randomEvent[0].bufferPreview))
{
    throw "BCryptGenRandom exposed bufferPreview: $($randomEvent[0].bufferPreview)"
}

$randomBufferArg = @($randomEvent[0].arguments | Where-Object { $_.name -eq "pbBuffer" } | Select-Object -First 1)
if ($randomBufferArg.Count -ne 1)
{
    throw "BCryptGenRandom missing pbBuffer argument."
}

if ($randomBufferArg[0].decodedValue -ne $randomBufferArg[0].rawValue -or $randomBufferArg[0].postCallValue -ne $randomBufferArg[0].rawValue)
{
    throw "BCryptGenRandom exposed decoded buffer content: $($randomBufferArg[0] | ConvertTo-Json -Depth 8)"
}

$randomArgs = $randomEvent[0].arguments | ConvertTo-Json -Depth 8
if ($randomArgs -match "\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){3,}\b")
{
    throw "BCryptGenRandom appears to expose byte preview evidence: $randomArgs"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 2 bcrypt smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -lt $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 2 bcrypt CNG smoke passed: events=$($result.capturedEvents.Count) bcryptApis=$($expected.Count) overheadAvgUs=$($result.hookOverheadAvgUs)"
