param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe",
    [string]$DefinitionIdsPath = "generated\definition-ids.json"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $HelperPath))
{
    throw "Helper not found: $HelperPath"
}

if (-not (Test-Path -LiteralPath $DefinitionIdsPath))
{
    throw "Definition IDs not found: $DefinitionIdsPath"
}

$definitionIds = Get-Content -LiteralPath $DefinitionIdsPath -Raw | ConvertFrom-Json
$winHttpModule = @($definitionIds.modules | Where-Object { $_.name -eq "winhttp.dll" } | Select-Object -First 1)
if ($winHttpModule.Count -ne 1 -or $winHttpModule[0].id -ne 10)
{
    throw "winhttp.dll module ID mismatch."
}

$winHttpSetOptionId = @($definitionIds.apis | Where-Object { $_.module -eq "winhttp.dll" -and $_.name -eq "WinHttpSetOption" } | Select-Object -First 1)
if ($winHttpSetOptionId.Count -ne 1 -or $winHttpSetOptionId[0].id -ne 89)
{
    throw "WinHttpSetOption API ID mismatch."
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Wave 2 WinHTTP option capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

if ($result.transportDroppedEvents -ne 0)
{
    throw "WinHTTP option healthy capture dropped transport events: $($result.transportDroppedEvents)"
}

$optionEvent = @($result.capturedEvents | Where-Object { $_.api -eq "WinHttpSetOption" } | Select-Object -First 1)
if ($optionEvent.Count -ne 1)
{
    throw "Wave 2 WinHTTP option smoke did not capture WinHttpSetOption."
}

if ($optionEvent[0].module -ne "winhttp.dll")
{
    throw "WinHttpSetOption module mismatch: $($optionEvent[0].module)"
}

if ($optionEvent[0].apiFamily -ne "http" -or $optionEvent[0].apiCategory -ne "winhttp_option_set")
{
    throw "WinHttpSetOption metadata mismatch: family=$($optionEvent[0].apiFamily) category=$($optionEvent[0].apiCategory)"
}

if ($optionEvent[0].hookPolicy -ne "iat" -or $optionEvent[0].coverageStatus -ne "smoke_verified")
{
    throw "WinHttpSetOption hook metadata mismatch: hook=$($optionEvent[0].hookPolicy) coverage=$($optionEvent[0].coverageStatus)"
}

if (-not [string]::IsNullOrEmpty($optionEvent[0].bufferPreview))
{
    throw "WinHttpSetOption exposed bufferPreview: $($optionEvent[0].bufferPreview)"
}

if ([string]$optionEvent[0].returnValue -ne "1")
{
    throw "WinHttpSetOption did not return BOOL true: $($optionEvent[0].returnValue)"
}

$hInternet = @($optionEvent[0].arguments | Where-Object { $_.name -eq "hInternet" } | Select-Object -First 1)
if ($hInternet.Count -ne 1 -or $hInternet[0].rawValue -match "^0x0+$")
{
    throw "WinHttpSetOption missing non-null hInternet evidence."
}

$dwOption = @($optionEvent[0].arguments | Where-Object { $_.name -eq "dwOption" } | Select-Object -First 1)
if ($dwOption.Count -ne 1 -or $dwOption[0].decodedValue -notmatch "WINHTTP_OPTION_RECEIVE_TIMEOUT")
{
    throw "WinHttpSetOption option mismatch: $($dwOption[0] | ConvertTo-Json -Depth 8)"
}

$lpBuffer = @($optionEvent[0].arguments | Where-Object { $_.name -eq "lpBuffer" } | Select-Object -First 1)
if ($lpBuffer.Count -ne 1 -or $lpBuffer[0].rawValue -match "^0x0+$")
{
    throw "WinHttpSetOption missing non-null lpBuffer pointer evidence."
}

if ($lpBuffer[0].decodeStatus -ne "decoded" -or $lpBuffer[0].decodedValue -notmatch "value=5000")
{
    throw "WinHttpSetOption scalar option value mismatch: $($lpBuffer[0] | ConvertTo-Json -Depth 8)"
}

$dwBufferLength = @($optionEvent[0].arguments | Where-Object { $_.name -eq "dwBufferLength" } | Select-Object -First 1)
if ($dwBufferLength.Count -ne 1 -or $dwBufferLength[0].decodedValue -ne "4")
{
    throw "WinHttpSetOption buffer length mismatch: $($dwBufferLength[0] | ConvertTo-Json -Depth 8)"
}

$winHttpPayload = @($result.capturedEvents | Where-Object { $_.module -eq "winhttp.dll" } | ConvertTo-Json -Depth 10)
if ($winHttpPayload -cmatch "WinHttpConnect|WinHttpOpenRequest|WinHttpSendRequest|WinHttpReceiveResponse|WinHttpReadData|WinHttpWriteData|WinHttpQueryHeaders|InternetOpenUrl|HttpSend|send|recv|Authorization|Cookie|Set-Cookie|Password|Credential|Proxy-Authorization|https?://|GET /|POST|BEGIN CERTIFICATE|PRIVATE KEY|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|Injection|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "WinHTTP option events appear to expose forbidden payload evidence: $winHttpPayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 2 WinHTTP option smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -lt $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 2 WinHTTP option smoke passed: events=$($result.capturedEvents.Count) option=WINHTTP_OPTION_RECEIVE_TIMEOUT value=5000 restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
