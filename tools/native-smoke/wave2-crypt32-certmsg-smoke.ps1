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
    throw "Wave 2 crypt32 capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

if ($result.transportDroppedEvents -ne 0)
{
    throw "crypt32 healthy capture dropped transport events: $($result.transportDroppedEvents)"
}

$expected = @(
    @{ Api = "CertOpenStore"; Family = "certificate"; Category = "certificate_store_open"; Args = @("lpszStoreProvider", "dwEncodingType", "hCryptProv", "dwFlags", "pvPara") },
    @{ Api = "CertCloseStore"; Family = "certificate"; Category = "certificate_store_close"; Args = @("hCertStore", "dwFlags") },
    @{ Api = "CryptMsgOpenToDecode"; Family = "crypto-message"; Category = "crypt_message_open_decode"; Args = @("dwMsgEncodingType", "dwFlags", "dwMsgType", "hCryptProv", "pRecipientInfo", "pStreamInfo") },
    @{ Api = "CryptMsgClose"; Family = "crypto-message"; Category = "crypt_message_close"; Args = @("hCryptMsg") }
)

foreach ($item in $expected)
{
    $event = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api } | Select-Object -First 1)
    if ($event.Count -ne 1)
    {
        throw "Wave 2 crypt32 smoke did not capture $($item.Api)."
    }

    if ($event[0].module -ne "crypt32.dll")
    {
        throw "$($item.Api) module mismatch: $($event[0].module)"
    }

    if ($event[0].apiFamily -ne $item.Family -or $event[0].apiCategory -ne $item.Category)
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

$openEvent = @($result.capturedEvents | Where-Object { $_.api -eq "CertOpenStore" } | Select-Object -First 1)
$openArgs = $openEvent[0].arguments | ConvertTo-Json -Depth 8
if ($openArgs -notmatch "provider_id:2" -and $openArgs -notmatch "0x0+2")
{
    throw "CertOpenStore did not include memory provider evidence: $openArgs"
}

if ($openArgs -notmatch "0x00002000")
{
    throw "CertOpenStore did not include CERT_STORE_CREATE_NEW_FLAG evidence: $openArgs"
}

$messageOpen = @($result.capturedEvents | Where-Object { $_.api -eq "CryptMsgOpenToDecode" } | Select-Object -First 1)
$messageArgs = $messageOpen[0].arguments | ConvertTo-Json -Depth 8
if ($messageArgs -notmatch "0x00010001")
{
    throw "CryptMsgOpenToDecode did not include X509/PKCS7 encoding evidence: $messageArgs"
}

foreach ($argName in @("pRecipientInfo", "pStreamInfo"))
{
    $argument = @($messageOpen[0].arguments | Where-Object { $_.name -eq $argName } | Select-Object -First 1)
    if ($argument.Count -ne 1)
    {
        throw "CryptMsgOpenToDecode missing $argName."
    }

    if ($argument[0].rawValue -notmatch "^0x0+$")
    {
        throw "CryptMsgOpenToDecode $argName was not null: $($argument[0] | ConvertTo-Json -Depth 8)"
    }
}

$crypt32Args = @($result.capturedEvents | Where-Object { $_.module -eq "crypt32.dll" } | ForEach-Object { $_.arguments } | ConvertTo-Json -Depth 8)
if ($crypt32Args -match "BEGIN CERTIFICATE|PRIVATE KEY|plaintext|ciphertext|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "crypt32 events appear to expose blob or secret-bearing evidence: $crypt32Args"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 2 crypt32 smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -lt $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 2 crypt32 certificate/message smoke passed: events=$($result.capturedEvents.Count) crypt32Apis=$($expected.Count) overheadAvgUs=$($result.hookOverheadAvgUs)"
