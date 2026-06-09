param(
    [string]$BuildDir = "build\native-win32\Debug"
)

$ErrorActionPreference = "Stop"

$helperPath = Join-Path $BuildDir "knmon-native-helper.exe"
$requiredApis = @(
    "CreateFileW",
    "CreateFileA",
    "NtCreateFile",
    "ReadFile",
    "WriteFile",
    "CloseHandle",
    "GetProcAddress",
    "LdrGetProcedureAddress",
    "RegOpenKeyExW",
    "RegCreateKeyExW",
    "RegQueryValueExW",
    "RegSetValueExW",
    "RegDeleteValueW",
    "RegCloseKey",
    "OpenProcessToken",
    "LookupPrivilegeValueW",
    "BCryptOpenAlgorithmProvider",
    "BCryptCloseAlgorithmProvider",
    "BCryptGetProperty",
    "BCryptGenRandom",
    "CertOpenStore",
    "CertCloseStore",
    "CryptMsgOpenToDecode",
    "CryptMsgClose",
    "InternetOpenW",
    "InternetCloseHandle",
    "WinHttpOpen",
    "WinHttpCloseHandle",
    "RpcStringBindingComposeW",
    "RpcBindingFromStringBindingW",
    "RpcStringFreeW",
    "RpcBindingFree",
    "WSAStartup",
    "WSACleanup",
    "socket",
    "closesocket",
    "getaddrinfo",
    "freeaddrinfo",
    "WSAGetLastError"
)

if (-not (Test-Path -LiteralPath $helperPath))
{
    throw "x86 helper not found: $helperPath"
}

$result = & $helperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "x86 capture failed: $($result.operation): $($result.message)"
}

if ($result.architecture -ne "x86")
{
    throw "x86 capture result architecture mismatch: $($result.architecture)"
}

if (-not $result.handshake.received)
{
    throw "x86 capture did not receive HELLO."
}

if ($result.handshake.architecture -ne "x86")
{
    throw "x86 HELLO architecture mismatch: $($result.handshake.architecture)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "x86 capture did not use shared-memory transport: $($result.transportMode)"
}

if ($result.droppedEvents -ne 0)
{
    throw "x86 capture reported dropped events: $($result.droppedEvents)"
}

$apis = @($result.capturedEvents | ForEach-Object { $_.api } | Sort-Object -Unique)
foreach ($api in $requiredApis)
{
    if ($apis -notcontains $api)
    {
        throw "x86 capture missing API: $api"
    }
}

$ntEvents = @($result.capturedEvents | Where-Object { $_.api -eq "NtCreateFile" })
if ($ntEvents.Count -lt 1)
{
    throw "x86 capture did not include NtCreateFile."
}

$loaderEvents = @($result.capturedEvents | Where-Object { $_.api -eq "LoadLibraryW" })
if ($loaderEvents.Count -lt 1)
{
    throw "x86 capture did not include LoadLibraryW dynamic-load evidence."
}

$resolverEvents = @($result.capturedEvents | Where-Object { $_.api -in @("GetProcAddress", "LdrGetProcedureAddress") })
if ($resolverEvents.Count -lt 2)
{
    throw "x86 capture did not include both resolver API events."
}

$getProc = @($resolverEvents | Where-Object { $_.api -eq "GetProcAddress" } | Select-Object -First 1)
if ($getProc.Count -ne 1 -or $getProc[0].tags -notcontains "resolver" -or $getProc[0].tags -notcontains "dynamic_symbol_lookup")
{
    throw "x86 GetProcAddress resolver event is missing resolver tags."
}

$getProcArgs = ($getProc[0].arguments | ConvertTo-Json -Depth 8)
if ($getProcArgs -notmatch "KnMonDynamicProbe")
{
    throw "x86 GetProcAddress arguments did not include dynamic probe evidence: $getProcArgs"
}

$ldr = @($resolverEvents | Where-Object { $_.api -eq "LdrGetProcedureAddress" } | Select-Object -First 1)
if ($ldr.Count -ne 1 -or $ldr[0].tags -notcontains "resolver" -or $ldr[0].tags -notcontains "dynamic_symbol_lookup_nt")
{
    throw "x86 LdrGetProcedureAddress resolver event is missing resolver tags."
}

$ldrArgs = ($ldr[0].arguments | ConvertTo-Json -Depth 8)
if ($ldrArgs -notmatch "KnMonDynamicProbe")
{
    throw "x86 LdrGetProcedureAddress arguments did not include dynamic probe evidence: $ldrArgs"
}

$registryEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "registry" })
if ($registryEvents.Count -lt 6)
{
    throw "x86 capture did not include the selected registry API family slice."
}

$registryCreate = @($registryEvents | Where-Object { $_.api -eq "RegCreateKeyExW" } | Select-Object -First 1)
if ($registryCreate.Count -ne 1 -or $registryCreate[0].module -ne "advapi32.dll" -or $registryCreate[0].hookPolicy -ne "iat" -or $registryCreate[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 RegCreateKeyExW metadata mismatch."
}

$registryCreateArgs = ($registryCreate[0].arguments | ConvertTo-Json -Depth 8)
if ($registryCreateArgs -notmatch "KNMonApiMonitorSample")
{
    throw "x86 registry arguments did not include sample key evidence: $registryCreateArgs"
}

$registrySet = @($registryEvents | Where-Object { $_.api -eq "RegSetValueExW" } | Select-Object -First 1)
if ($registrySet.Count -ne 1)
{
    throw "x86 capture did not include RegSetValueExW."
}

$registrySetArgs = ($registrySet[0].arguments | ConvertTo-Json -Depth 8)
if ($registrySetArgs -notmatch "SampleValue")
{
    throw "x86 registry arguments did not include sample value evidence: $registrySetArgs"
}

$securityEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "security" })
if ($securityEvents.Count -lt 2)
{
    throw "x86 capture did not include the selected advapi32 token query API family slice."
}

$openToken = @($securityEvents | Where-Object { $_.api -eq "OpenProcessToken" } | Select-Object -First 1)
if ($openToken.Count -ne 1 -or $openToken[0].module -ne "advapi32.dll" -or $openToken[0].hookPolicy -ne "iat" -or $openToken[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 OpenProcessToken metadata mismatch."
}

$openTokenArgs = ($openToken[0].arguments | ConvertTo-Json -Depth 8)
if ($openTokenArgs -notmatch "0x00000008")
{
    throw "x86 OpenProcessToken arguments did not include TOKEN_QUERY evidence: $openTokenArgs"
}

$tokenHandle = @($openToken[0].arguments | Where-Object { $_.name -eq "TokenHandle" } | Select-Object -First 1)
if ($tokenHandle.Count -ne 1 -or $tokenHandle[0].postCallValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 OpenProcessToken did not include a non-null token handle value: $($tokenHandle[0] | ConvertTo-Json -Depth 8)"
}

$lookupPrivilege = @($securityEvents | Where-Object { $_.api -eq "LookupPrivilegeValueW" } | Select-Object -First 1)
if ($lookupPrivilege.Count -ne 1 -or $lookupPrivilege[0].module -ne "advapi32.dll" -or $lookupPrivilege[0].hookPolicy -ne "iat" -or $lookupPrivilege[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 LookupPrivilegeValueW metadata mismatch."
}

$lookupArgs = ($lookupPrivilege[0].arguments | ConvertTo-Json -Depth 8)
if ($lookupArgs -notmatch "SeChangeNotifyPrivilege")
{
    throw "x86 LookupPrivilegeValueW arguments did not include stable privilege evidence: $lookupArgs"
}

$systemName = @($lookupPrivilege[0].arguments | Where-Object { $_.name -eq "lpSystemName" } | Select-Object -First 1)
if ($systemName.Count -ne 1 -or $systemName[0].rawValue -notmatch "^0x0+$")
{
    throw "x86 LookupPrivilegeValueW lpSystemName was not null: $($systemName[0] | ConvertTo-Json -Depth 8)"
}

$luidArg = @($lookupPrivilege[0].arguments | Where-Object { $_.name -eq "lpLuid" } | Select-Object -First 1)
if ($luidArg.Count -ne 1 -or $luidArg[0].decodedValue -notmatch "LowPart=0x" -or $luidArg[0].decodedValue -notmatch "HighPart=0x")
{
    throw "x86 LookupPrivilegeValueW did not include LUID numeric evidence: $($luidArg[0] | ConvertTo-Json -Depth 8)"
}

if (@($result.capturedEvents | Where-Object { $_.api -eq "AdjustTokenPrivileges" }).Count -ne 0)
{
    throw "x86 token query capture unexpectedly included AdjustTokenPrivileges."
}

if (@($result.capturedEvents | Where-Object { $_.apiFamily -eq "service-control" }).Count -ne 0)
{
    throw "x86 token query capture unexpectedly included service-control events."
}

$securityArgs = @($securityEvents | ForEach-Object { $_.arguments } | ConvertTo-Json -Depth 8)
if ($securityArgs -cmatch "TOKEN_PRIVILEGES|S-1-[0-9-]+|Password|Credential|PRIVATE KEY|BinaryPath|ServiceName|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 token query events appear to expose mutation, SID, credential, service, or byte-preview evidence: $securityArgs"
}

$cryptoEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "crypto" })
if ($cryptoEvents.Count -lt 4)
{
    throw "x86 capture did not include the selected bcrypt CNG API family slice."
}

$bcryptOpen = @($cryptoEvents | Where-Object { $_.api -eq "BCryptOpenAlgorithmProvider" } | Select-Object -First 1)
if ($bcryptOpen.Count -ne 1 -or $bcryptOpen[0].module -ne "bcrypt.dll" -or $bcryptOpen[0].hookPolicy -ne "iat" -or $bcryptOpen[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 BCryptOpenAlgorithmProvider metadata mismatch."
}

$bcryptOpenArgs = ($bcryptOpen[0].arguments | ConvertTo-Json -Depth 8)
if ($bcryptOpenArgs -notmatch "RNG")
{
    throw "x86 bcrypt open arguments did not include RNG evidence: $bcryptOpenArgs"
}

$bcryptProperty = @($cryptoEvents | Where-Object { $_.api -eq "BCryptGetProperty" } | Select-Object -First 1)
if ($bcryptProperty.Count -ne 1)
{
    throw "x86 capture did not include BCryptGetProperty."
}

$bcryptPropertyArgs = ($bcryptProperty[0].arguments | ConvertTo-Json -Depth 8)
if ($bcryptPropertyArgs -notmatch "AlgorithmName" -or $bcryptPropertyArgs -notmatch "RNG")
{
    throw "x86 bcrypt property arguments did not include AlgorithmName/RNG evidence: $bcryptPropertyArgs"
}

$bcryptRandom = @($cryptoEvents | Where-Object { $_.api -eq "BCryptGenRandom" } | Select-Object -First 1)
if ($bcryptRandom.Count -ne 1 -or -not [string]::IsNullOrEmpty($bcryptRandom[0].bufferPreview))
{
    throw "x86 BCryptGenRandom exposed buffer preview or was not captured."
}

$certificateEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "certificate" })
if ($certificateEvents.Count -lt 2)
{
    throw "x86 capture did not include the selected crypt32 certificate API family slice."
}

$certOpen = @($certificateEvents | Where-Object { $_.api -eq "CertOpenStore" } | Select-Object -First 1)
if ($certOpen.Count -ne 1 -or $certOpen[0].module -ne "crypt32.dll" -or $certOpen[0].hookPolicy -ne "iat" -or $certOpen[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 CertOpenStore metadata mismatch."
}

$certOpenArgs = ($certOpen[0].arguments | ConvertTo-Json -Depth 8)
if (($certOpenArgs -notmatch "provider_id:2" -and $certOpenArgs -notmatch "0x0+2") -or $certOpenArgs -notmatch "0x00002000")
{
    throw "x86 CertOpenStore arguments did not include memory store evidence: $certOpenArgs"
}

$certClose = @($certificateEvents | Where-Object { $_.api -eq "CertCloseStore" } | Select-Object -First 1)
if ($certClose.Count -ne 1)
{
    throw "x86 capture did not include CertCloseStore."
}

$cryptoMessageEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "crypto-message" })
if ($cryptoMessageEvents.Count -lt 2)
{
    throw "x86 capture did not include the selected crypt32 message API family slice."
}

$messageOpen = @($cryptoMessageEvents | Where-Object { $_.api -eq "CryptMsgOpenToDecode" } | Select-Object -First 1)
if ($messageOpen.Count -ne 1 -or $messageOpen[0].module -ne "crypt32.dll" -or $messageOpen[0].hookPolicy -ne "iat" -or $messageOpen[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 CryptMsgOpenToDecode metadata mismatch."
}

$messageOpenArgs = ($messageOpen[0].arguments | ConvertTo-Json -Depth 8)
if ($messageOpenArgs -notmatch "0x00010001")
{
    throw "x86 CryptMsgOpenToDecode arguments did not include X509/PKCS7 evidence: $messageOpenArgs"
}

foreach ($argName in @("pRecipientInfo", "pStreamInfo"))
{
    $argument = @($messageOpen[0].arguments | Where-Object { $_.name -eq $argName } | Select-Object -First 1)
    if ($argument.Count -ne 1 -or $argument[0].rawValue -notmatch "^0x0+$")
    {
        throw "x86 CryptMsgOpenToDecode $argName was not null: $($argument[0] | ConvertTo-Json -Depth 8)"
    }
}

$messageClose = @($cryptoMessageEvents | Where-Object { $_.api -eq "CryptMsgClose" } | Select-Object -First 1)
if ($messageClose.Count -ne 1)
{
    throw "x86 capture did not include CryptMsgClose."
}

$crypt32Args = @($result.capturedEvents | Where-Object { $_.module -eq "crypt32.dll" } | ForEach-Object { $_.arguments } | ConvertTo-Json -Depth 8)
if ($crypt32Args -match "BEGIN CERTIFICATE|PRIVATE KEY|plaintext|ciphertext|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 crypt32 events appear to expose blob or secret-bearing evidence: $crypt32Args"
}

$httpEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "http" })
if ($httpEvents.Count -lt 2)
{
    throw "x86 capture did not include the selected WinHTTP session API family slice."
}

$winHttpOpen = @($httpEvents | Where-Object { $_.api -eq "WinHttpOpen" } | Select-Object -First 1)
if ($winHttpOpen.Count -ne 1 -or $winHttpOpen[0].module -ne "winhttp.dll" -or $winHttpOpen[0].hookPolicy -ne "iat" -or $winHttpOpen[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 WinHttpOpen metadata mismatch."
}

$winHttpOpenArgs = ($winHttpOpen[0].arguments | ConvertTo-Json -Depth 8)
if ($winHttpOpenArgs -notmatch "KNMonWinHttpSample/1.0" -or $winHttpOpenArgs -notmatch "0x00000001")
{
    throw "x86 WinHttpOpen arguments did not include sample no-proxy evidence: $winHttpOpenArgs"
}

foreach ($argName in @("pszProxyW", "pszProxyBypassW"))
{
    $argument = @($winHttpOpen[0].arguments | Where-Object { $_.name -eq $argName } | Select-Object -First 1)
    if ($argument.Count -ne 1 -or $argument[0].rawValue -notmatch "^0x0+$")
    {
        throw "x86 WinHttpOpen $argName was not null: $($argument[0] | ConvertTo-Json -Depth 8)"
    }
}

$winHttpClose = @($httpEvents | Where-Object { $_.api -eq "WinHttpCloseHandle" } | Select-Object -First 1)
if ($winHttpClose.Count -ne 1)
{
    throw "x86 capture did not include WinHttpCloseHandle."
}

$winHttpArgs = @($result.capturedEvents | Where-Object { $_.module -eq "winhttp.dll" } | ForEach-Object { $_.arguments } | ConvertTo-Json -Depth 8)
if ($winHttpArgs -cmatch "https?://|Authorization|Cookie|Set-Cookie|POST|GET /|BEGIN CERTIFICATE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 WinHTTP events appear to expose URL/header/body/credential or byte-preview evidence: $winHttpArgs"
}

$internetEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "internet" })
if ($internetEvents.Count -lt 2)
{
    throw "x86 capture did not include the selected WinINet session API family slice."
}

$winInetOpen = @($internetEvents | Where-Object { $_.api -eq "InternetOpenW" } | Select-Object -First 1)
if ($winInetOpen.Count -ne 1 -or $winInetOpen[0].module -ne "wininet.dll" -or $winInetOpen[0].hookPolicy -ne "iat" -or $winInetOpen[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 InternetOpenW metadata mismatch."
}

$winInetOpenArgs = ($winInetOpen[0].arguments | ConvertTo-Json -Depth 8)
if ($winInetOpenArgs -notmatch "KNMonWinInetSample/1.0" -or $winInetOpenArgs -notmatch "0x00000001")
{
    throw "x86 InternetOpenW arguments did not include sample direct-access evidence: $winInetOpenArgs"
}

foreach ($argName in @("lpszProxy", "lpszProxyBypass"))
{
    $argument = @($winInetOpen[0].arguments | Where-Object { $_.name -eq $argName } | Select-Object -First 1)
    if ($argument.Count -ne 1 -or $argument[0].rawValue -notmatch "^0x0+$")
    {
        throw "x86 InternetOpenW $argName was not null: $($argument[0] | ConvertTo-Json -Depth 8)"
    }
}

$winInetClose = @($internetEvents | Where-Object { $_.api -eq "InternetCloseHandle" } | Select-Object -First 1)
if ($winInetClose.Count -ne 1)
{
    throw "x86 capture did not include InternetCloseHandle."
}

$winInetArgs = @($result.capturedEvents | Where-Object { $_.module -eq "wininet.dll" } | ForEach-Object { $_.arguments } | ConvertTo-Json -Depth 8)
if ($winInetArgs -cmatch "https?://|Authorization|Cookie|Set-Cookie|POST|GET /|BEGIN CERTIFICATE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 WinINet events appear to expose URL/header/body/credential or byte-preview evidence: $winInetArgs"
}

$rpcEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "rpc" })
if ($rpcEvents.Count -lt 4)
{
    throw "x86 capture did not include the selected RPCRT4 binding API family slice."
}

$rpcCompose = @($rpcEvents | Where-Object { $_.api -eq "RpcStringBindingComposeW" } | Select-Object -First 1)
if ($rpcCompose.Count -ne 1 -or $rpcCompose[0].module -ne "rpcrt4.dll" -or $rpcCompose[0].hookPolicy -ne "iat" -or $rpcCompose[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 RpcStringBindingComposeW metadata mismatch."
}

$rpcComposeArgs = ($rpcCompose[0].arguments | ConvertTo-Json -Depth 8)
if ($rpcComposeArgs -notmatch "ncalrpc" -or $rpcComposeArgs -notmatch "KNMonRpcSample")
{
    throw "x86 RPC compose arguments did not include local binding evidence: $rpcComposeArgs"
}

$rpcStringFree = @($rpcEvents | Where-Object { $_.api -eq "RpcStringFreeW" } | Select-Object -First 1)
if ($rpcStringFree.Count -ne 1)
{
    throw "x86 capture did not include RpcStringFreeW."
}

$rpcStringFreeArgs = ($rpcStringFree[0].arguments | ConvertTo-Json -Depth 8)
if ($rpcStringFreeArgs -notmatch "ncalrpc" -or $rpcStringFreeArgs -notmatch "KNMonRpcSample")
{
    throw "x86 RPC string-free arguments did not include pre-free binding evidence: $rpcStringFreeArgs"
}

$dynamicSweep = @($result.agentMessages | Where-Object { $_.messageType -eq "iat_sweep" -and $_.reason -eq "dynamic_load" } | Select-Object -Last 1)
if ($dynamicSweep.Count -ne 1)
{
    throw "x86 capture did not include dynamic-load re-hook sweep evidence."
}

if ($dynamicSweep[0].patchedSlots -lt 1)
{
    throw "x86 dynamic-load sweep did not patch any new slots."
}

$ntEvent = $ntEvents[0]
if ($ntEvent.module -ne "ntdll.dll")
{
    throw "x86 NtCreateFile module mismatch: $($ntEvent.module)"
}

if ($ntEvent.returnValue -notmatch "^0x[0-9a-fA-F]{8}$")
{
    throw "x86 NtCreateFile returnValue is not NTSTATUS hex: $($ntEvent.returnValue)"
}

$stackEvidence = @($ntEvent.stack | Where-Object { $_ -eq "knmon-agent32.dll!IatHook" })
if ($stackEvidence.Count -ne 1)
{
    throw "x86 NtCreateFile stack did not include knmon-agent32.dll!IatHook."
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "x86 capture did not receive exactly one agent_shutdown event."
}

if ($shutdown[0].installedHooks -lt 6)
{
    throw "x86 unexpected installedHooks: $($shutdown[0].installedHooks)"
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks)
{
    throw "x86 unexpected restoredHooks: $($shutdown[0].restoredHooks)"
}

if ($shutdown[0].failedHooks -ne 0)
{
    throw "x86 capture reported failedHooks: $($shutdown[0].failedHooks)"
}

Write-Host "x86 capture smoke passed: apis=$($apis -join ',') ntStatus=$($ntEvent.returnValue) resolverEvents=$($resolverEvents.Count) restoredHooks=$($shutdown[0].restoredHooks)"
