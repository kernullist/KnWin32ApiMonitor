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
    "GetSystemMetrics",
    "GetDesktopWindow",
    "GetForegroundWindow",
    "GetWindowThreadProcessId",
    "CreateCompatibleDC",
    "GetDeviceCaps",
    "DeleteDC",
    "EnumProcessModules",
    "GetModuleInformation",
    "GetModuleBaseNameW",
    "GetModuleFileNameExW",
    "GetFileVersionInfoSizeW",
    "GetFileVersionInfoW",
    "VerQueryValueW",
    "SHGetKnownFolderPath",
    "SHGetSpecialFolderPathW",
    "CoInitializeEx",
    "CoUninitialize",
    "CoCreateGuid",
    "StringFromGUID2",
    "RoInitialize",
    "RoUninitialize",
    "RoGetApartmentIdentifier",
    "RpcStringBindingComposeW",
    "RpcBindingFromStringBindingW",
    "RpcStringFreeW",
    "RpcBindingFree",
    "UuidCreate",
    "UuidToStringW",
    "UuidFromStringW",
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
$winrtProviderModule = "api-ms-win-core-winrt-l1-1-0.dll"

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

$uiEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "ui" })
if ($uiEvents.Count -lt 4)
{
    throw "x86 capture did not include the selected User32 API family slice."
}

$systemMetric = @($uiEvents | Where-Object { $_.api -eq "GetSystemMetrics" } | Select-Object -First 1)
if ($systemMetric.Count -ne 1 -or $systemMetric[0].module -ne "user32.dll" -or $systemMetric[0].hookPolicy -ne "iat" -or $systemMetric[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 GetSystemMetrics metadata mismatch."
}

$metricArg = @($systemMetric[0].arguments | Where-Object { $_.name -eq "nIndex" } | Select-Object -First 1)
if ($metricArg.Count -ne 1 -or $metricArg[0].decodeAlias -ne "system_metric_index" -or $metricArg[0].decodedValue -notmatch "^-?[0-9]+$")
{
    throw "x86 GetSystemMetrics nIndex evidence mismatch: $($systemMetric[0] | ConvertTo-Json -Depth 8)"
}

$windowThread = @($uiEvents | Where-Object { $_.api -eq "GetWindowThreadProcessId" } | Select-Object -First 1)
if ($windowThread.Count -ne 1 -or $windowThread[0].module -ne "user32.dll" -or $windowThread[0].apiCategory -ne "window_thread_process_query")
{
    throw "x86 GetWindowThreadProcessId metadata mismatch."
}

$windowThreadArgs = ($windowThread[0].arguments | ConvertTo-Json -Depth 8)
if ($windowThreadArgs -notmatch "hwnd_handle" -or $windowThreadArgs -notmatch "dword_pointer")
{
    throw "x86 GetWindowThreadProcessId arguments did not include HWND/PID evidence: $windowThreadArgs"
}

$gdiEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "gdi" })
if ($gdiEvents.Count -lt 3)
{
    throw "x86 capture did not include the selected GDI32 API family slice."
}

$createDc = @($gdiEvents | Where-Object { $_.api -eq "CreateCompatibleDC" } | Select-Object -First 1)
if ($createDc.Count -ne 1 -or $createDc[0].module -ne "gdi32.dll" -or $createDc[0].hookPolicy -ne "iat" -or $createDc[0].coverageStatus -ne "smoke_verified" -or $createDc[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 CreateCompatibleDC metadata or handle evidence mismatch."
}

$deviceCaps = @($gdiEvents | Where-Object { $_.api -eq "GetDeviceCaps" } | Select-Object -First 1)
if ($deviceCaps.Count -ne 1 -or $deviceCaps[0].apiCategory -ne "gdi_device_cap_query")
{
    throw "x86 GetDeviceCaps metadata mismatch."
}

$deviceArgs = ($deviceCaps[0].arguments | ConvertTo-Json -Depth 8)
if ($deviceArgs -notmatch "hdc_handle" -or $deviceArgs -notmatch "device_cap_index")
{
    throw "x86 GetDeviceCaps arguments did not include HDC/index evidence: $deviceArgs"
}

$deleteDc = @($gdiEvents | Where-Object { $_.api -eq "DeleteDC" } | Select-Object -First 1)
if ($deleteDc.Count -ne 1 -or $deleteDc[0].returnValue -ne "1")
{
    throw "x86 DeleteDC did not report a successful handle close."
}

$uiGdiArgs = @($result.capturedEvents | Where-Object { $_.module -in @("user32.dll", "gdi32.dll") } | ForEach-Object { $_.arguments } | ConvertTo-Json -Depth 8)
if ($uiGdiArgs -cmatch "GetWindowText|WM_GETTEXT|Clipboard|CF_|Screenshot|ScreenCapture|DIB|Bitmap|Keyboard|Mouse|Password|Credential|Authorization|Cookie|BEGIN CERTIFICATE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 UI/GDI events appear to expose text, pixel, clipboard, input, credential, or byte-preview evidence: $uiGdiArgs"
}

$moduleEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "module" })
if ($moduleEvents.Count -lt 4)
{
    throw "x86 capture did not include the selected PSAPI module-query API family slice."
}

$enumModules = @($moduleEvents | Where-Object { $_.api -eq "EnumProcessModules" } | Select-Object -First 1)
if ($enumModules.Count -ne 1 -or $enumModules[0].module -ne "psapi.dll" -or $enumModules[0].hookPolicy -ne "iat" -or $enumModules[0].coverageStatus -ne "smoke_verified" -or $enumModules[0].returnValue -ne "1")
{
    throw "x86 EnumProcessModules metadata or return evidence mismatch."
}

$enumArgs = ($enumModules[0].arguments | ConvertTo-Json -Depth 8)
if ($enumArgs -notmatch "module_handle_array_pointer" -or $enumArgs -notmatch "firstModule=0x" -or $enumArgs -notmatch "dword_pointer")
{
    throw "x86 EnumProcessModules arguments did not include bounded module handle/count evidence: $enumArgs"
}

$moduleInfo = @($moduleEvents | Where-Object { $_.api -eq "GetModuleInformation" } | Select-Object -First 1)
if ($moduleInfo.Count -ne 1 -or $moduleInfo[0].module -ne "psapi.dll" -or $moduleInfo[0].apiCategory -ne "process_module_information" -or $moduleInfo[0].returnValue -ne "1")
{
    throw "x86 GetModuleInformation metadata or return evidence mismatch."
}

$moduleInfoArgs = ($moduleInfo[0].arguments | ConvertTo-Json -Depth 8)
if ($moduleInfoArgs -notmatch "module_info_pointer" -or $moduleInfoArgs -notmatch "base=0x" -or $moduleInfoArgs -notmatch "size=[1-9][0-9]*" -or $moduleInfoArgs -notmatch "entry=0x")
{
    throw "x86 GetModuleInformation arguments did not include MODULEINFO numeric evidence: $moduleInfoArgs"
}

$moduleBaseName = @($moduleEvents | Where-Object { $_.api -eq "GetModuleBaseNameW" } | Select-Object -First 1)
if ($moduleBaseName.Count -ne 1 -or $moduleBaseName[0].apiCategory -ne "process_module_base_name" -or $moduleBaseName[0].returnValue -notmatch "^[1-9][0-9]*$")
{
    throw "x86 GetModuleBaseNameW metadata or return evidence mismatch."
}

$moduleBaseNameArgs = ($moduleBaseName[0].arguments | ConvertTo-Json -Depth 8)
if ($moduleBaseNameArgs -notmatch "knmon-sample-fileio\.exe")
{
    throw "x86 GetModuleBaseNameW arguments did not include sample module name evidence: $moduleBaseNameArgs"
}

$moduleFileName = @($moduleEvents | Where-Object { $_.api -eq "GetModuleFileNameExW" } | Select-Object -First 1)
if ($moduleFileName.Count -ne 1 -or $moduleFileName[0].apiCategory -ne "process_module_file_name" -or $moduleFileName[0].returnValue -notmatch "^[1-9][0-9]*$")
{
    throw "x86 GetModuleFileNameExW metadata or return evidence mismatch."
}

$moduleFileNameArgs = ($moduleFileName[0].arguments | ConvertTo-Json -Depth 8)
if ($moduleFileNameArgs -notmatch "knmon-sample-fileio\.exe")
{
    throw "x86 GetModuleFileNameExW arguments did not include sample module path evidence: $moduleFileNameArgs"
}

$moduleArgs = @($moduleEvents | ForEach-Object { $_.arguments } | ConvertTo-Json -Depth 8)
if ($moduleArgs -cmatch "BEGIN CERTIFICATE|PRIVATE KEY|Authorization|Cookie|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|Authenticode|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 PSAPI module-query events appear to expose PE, module-memory, file-content, hash, signature, credential, or byte-preview evidence: $moduleArgs"
}

$resourceEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "resource" })
if ($resourceEvents.Count -lt 4)
{
    throw "x86 capture did not include the selected version resource API family slice."
}

$versionSize = @($resourceEvents | Where-Object { $_.api -eq "GetFileVersionInfoSizeW" } | Select-Object -First 1)
if ($versionSize.Count -ne 1 -or $versionSize[0].module -ne "version.dll" -or $versionSize[0].hookPolicy -ne "iat" -or $versionSize[0].coverageStatus -ne "smoke_verified" -or $versionSize[0].returnValue -notmatch "^[1-9][0-9]*$")
{
    throw "x86 GetFileVersionInfoSizeW metadata or return evidence mismatch."
}

$versionSizeArgs = ($versionSize[0].arguments | ConvertTo-Json -Depth 8)
if ($versionSizeArgs -notmatch "kernel32\.dll" -or $versionSizeArgs -notmatch "dword_pointer")
{
    throw "x86 GetFileVersionInfoSizeW arguments did not include path/handle evidence: $versionSizeArgs"
}

$versionLoad = @($resourceEvents | Where-Object { $_.api -eq "GetFileVersionInfoW" } | Select-Object -First 1)
if ($versionLoad.Count -ne 1 -or $versionLoad[0].module -ne "version.dll" -or $versionLoad[0].apiCategory -ne "version_info_load" -or $versionLoad[0].returnValue -ne "1")
{
    throw "x86 GetFileVersionInfoW metadata or return evidence mismatch."
}

$versionLoadArgs = ($versionLoad[0].arguments | ConvertTo-Json -Depth 8)
if ($versionLoadArgs -notmatch "kernel32\.dll" -or $versionLoadArgs -notmatch "version_info_buffer_pointer" -or $versionLoadArgs -notmatch "byte_count")
{
    throw "x86 GetFileVersionInfoW arguments did not include path/size/pointer evidence: $versionLoadArgs"
}

$versionQueries = @($resourceEvents | Where-Object { $_.api -eq "VerQueryValueW" })
if ($versionQueries.Count -lt 2)
{
    throw "x86 capture did not include root and translation VerQueryValueW evidence."
}

$rootVersionQuery = @($versionQueries | Where-Object {
    $subBlock = @($_.arguments | Where-Object { $_.name -eq "lpSubBlock" } | Select-Object -First 1)
    $subBlock.Count -eq 1 -and $subBlock[0].decodedValue -eq "\"
} | Select-Object -First 1)
if ($rootVersionQuery.Count -ne 1 -or $rootVersionQuery[0].returnValue -ne "1")
{
    throw "x86 VerQueryValueW root fixed-info evidence missing."
}

$rootValueArg = @($rootVersionQuery[0].arguments | Where-Object { $_.name -eq "lplpBuffer" } | Select-Object -First 1)
if ($rootValueArg.Count -ne 1 -or
    $rootValueArg[0].decodeAlias -ne "version_info_value_pointer" -or
    $rootValueArg[0].decodedValue -notmatch "sig=0xfeef04bd" -or
    $rootValueArg[0].decodedValue -notmatch "fileMS=0x[0-9a-fA-F]{8}" -or
    $rootValueArg[0].decodedValue -notmatch "prodMS=0x[0-9a-fA-F]{8}" -or
    $rootValueArg[0].decodedValue -notmatch "flags=0x[0-9a-fA-F]{8}" -or
    $rootValueArg[0].decodedValue -notmatch "type=0x[0-9a-fA-F]{8}")
{
    throw "x86 VerQueryValueW root did not include fixed-file-info numeric evidence: $($rootValueArg | ConvertTo-Json -Depth 8)"
}

$translationVersionQuery = @($versionQueries | Where-Object {
    $subBlock = @($_.arguments | Where-Object { $_.name -eq "lpSubBlock" } | Select-Object -First 1)
    $subBlock.Count -eq 1 -and $subBlock[0].decodedValue -eq "\VarFileInfo\Translation"
} | Select-Object -First 1)
if ($translationVersionQuery.Count -ne 1 -or $translationVersionQuery[0].returnValue -ne "1")
{
    throw "x86 VerQueryValueW translation evidence missing."
}

$translationValueArg = @($translationVersionQuery[0].arguments | Where-Object { $_.name -eq "lplpBuffer" } | Select-Object -First 1)
if ($translationValueArg.Count -ne 1 -or $translationValueArg[0].decodedValue -notmatch "translation=lang=0x[0-9a-fA-F]{4},codepage=0x[0-9a-fA-F]{4}")
{
    throw "x86 VerQueryValueW translation did not include language/codepage evidence: $($translationValueArg | ConvertTo-Json -Depth 8)"
}

$versionArgs = @($resourceEvents | ForEach-Object { $_.arguments } | ConvertTo-Json -Depth 8)
if ($versionArgs -cmatch "CompanyName|ProductName|FileDescription|OriginalFilename|StringFileInfo|VS_VERSION_INFO|BEGIN CERTIFICATE|PRIVATE KEY|Authorization|Cookie|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|Authenticode|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 version resource events appear to expose raw resource, PE, file-content, hash, signature, string-table, credential, or byte-preview evidence: $versionArgs"
}

$shellEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "shell" })
if ($shellEvents.Count -lt 8)
{
    throw "x86 capture did not include the selected Shell known-folder API family slice."
}

$knownFolderPath = @($shellEvents | Where-Object { $_.api -eq "SHGetKnownFolderPath" })
if ($knownFolderPath.Count -lt 4)
{
    throw "x86 capture did not include allowlisted and non-allowlisted SHGetKnownFolderPath evidence."
}

foreach ($event in $knownFolderPath)
{
    if ($event.module -ne "shell32.dll" -or $event.apiCategory -ne "known_folder_path_query" -or $event.hookPolicy -ne "iat" -or $event.coverageStatus -ne "smoke_verified")
    {
        throw "x86 SHGetKnownFolderPath metadata mismatch."
    }

    $knownArgs = ($event.arguments | ConvertTo-Json -Depth 8)
    if ($knownArgs -notmatch "known_folder_id_pointer" -or $knownArgs -notmatch "shell_folder_path_pointer_pointer")
    {
        throw "x86 SHGetKnownFolderPath arguments did not include GUID/path-pointer metadata: $knownArgs"
    }
}

$knownWindows = @($knownFolderPath | Where-Object {
    $arg = @($_.arguments | Where-Object { $_.name -eq "rfid" } | Select-Object -First 1)
    $arg.Count -eq 1 -and $arg[0].decodedValue -match "FOLDERID_Windows"
} | Select-Object -First 1)
$knownSystem = @($knownFolderPath | Where-Object {
    $arg = @($_.arguments | Where-Object { $_.name -eq "rfid" } | Select-Object -First 1)
    $arg.Count -eq 1 -and $arg[0].decodedValue -match "FOLDERID_System"
} | Select-Object -First 1)
$knownProgramFiles = @($knownFolderPath | Where-Object {
    $arg = @($_.arguments | Where-Object { $_.name -eq "rfid" } | Select-Object -First 1)
    $arg.Count -eq 1 -and $arg[0].decodedValue -match "FOLDERID_ProgramFiles"
} | Select-Object -First 1)
$knownFonts = @($knownFolderPath | Where-Object {
    $arg = @($_.arguments | Where-Object { $_.name -eq "rfid" } | Select-Object -First 1)
    $arg.Count -eq 1 -and $arg[0].decodedValue -match "FOLDERID_Fonts"
} | Select-Object -First 1)

if ($knownWindows.Count -ne 1 -or $knownSystem.Count -ne 1 -or $knownProgramFiles.Count -ne 1 -or $knownFonts.Count -ne 1)
{
    throw "x86 SHGetKnownFolderPath did not include all expected folder IDs."
}

$knownWindowsPath = @($knownWindows[0].arguments | Where-Object { $_.name -eq "ppszPath" } | Select-Object -First 1)
$knownSystemPath = @($knownSystem[0].arguments | Where-Object { $_.name -eq "ppszPath" } | Select-Object -First 1)
$knownProgramFilesPath = @($knownProgramFiles[0].arguments | Where-Object { $_.name -eq "ppszPath" } | Select-Object -First 1)
$knownFontsPath = @($knownFonts[0].arguments | Where-Object { $_.name -eq "ppszPath" } | Select-Object -First 1)

if ($knownWindowsPath.Count -ne 1 -or $knownWindowsPath[0].decodedValue -notmatch "(?i)status=decoded_safe_path;.*path=[A-Z]:\\WINDOWS$")
{
    throw "x86 FOLDERID_Windows did not include allowlisted path evidence: $($knownWindowsPath | ConvertTo-Json -Depth 8)"
}

if ($knownSystemPath.Count -ne 1 -or $knownSystemPath[0].decodedValue -notmatch "(?i)status=decoded_safe_path;.*path=[A-Z]:\\WINDOWS\\system32$")
{
    throw "x86 FOLDERID_System did not include allowlisted path evidence: $($knownSystemPath | ConvertTo-Json -Depth 8)"
}

if ($knownProgramFilesPath.Count -ne 1 -or $knownProgramFilesPath[0].decodedValue -notmatch "(?i)status=decoded_safe_path;.*path=[A-Z]:\\Program Files(?: \(x86\))?$")
{
    throw "x86 FOLDERID_ProgramFiles did not include allowlisted path evidence: $($knownProgramFilesPath | ConvertTo-Json -Depth 8)"
}

if ($knownFontsPath.Count -ne 1 -or $knownFontsPath[0].decodedValue -notmatch "status=non_allowlisted_no_path" -or $knownFontsPath[0].decodedValue -match "path=")
{
    throw "x86 FOLDERID_Fonts should not expose a returned path: $($knownFontsPath | ConvertTo-Json -Depth 8)"
}

$specialFolderPath = @($shellEvents | Where-Object { $_.api -eq "SHGetSpecialFolderPathW" })
if ($specialFolderPath.Count -lt 4)
{
    throw "x86 capture did not include allowlisted and non-allowlisted SHGetSpecialFolderPathW evidence."
}

foreach ($event in $specialFolderPath)
{
    if ($event.module -ne "shell32.dll" -or $event.apiCategory -ne "special_folder_path_query" -or $event.returnValue -ne "1" -or $event.hookPolicy -ne "iat" -or $event.coverageStatus -ne "smoke_verified")
    {
        throw "x86 SHGetSpecialFolderPathW metadata or return evidence mismatch."
    }

    $specialArgs = ($event.arguments | ConvertTo-Json -Depth 8)
    if ($specialArgs -notmatch "csidl_value" -or $specialArgs -notmatch "shell_folder_path_pointer" -or $specialArgs -notmatch '"fCreate"')
    {
        throw "x86 SHGetSpecialFolderPathW arguments did not include CSIDL/path metadata: $specialArgs"
    }
}

$specialWindows = @($specialFolderPath | Where-Object {
    $arg = @($_.arguments | Where-Object { $_.name -eq "csidl" } | Select-Object -First 1)
    $arg.Count -eq 1 -and $arg[0].decodedValue -match "CSIDL_WINDOWS"
} | Select-Object -First 1)
$specialSystem = @($specialFolderPath | Where-Object {
    $arg = @($_.arguments | Where-Object { $_.name -eq "csidl" } | Select-Object -First 1)
    $arg.Count -eq 1 -and $arg[0].decodedValue -match "CSIDL_SYSTEM"
} | Select-Object -First 1)
$specialProgramFiles = @($specialFolderPath | Where-Object {
    $arg = @($_.arguments | Where-Object { $_.name -eq "csidl" } | Select-Object -First 1)
    $arg.Count -eq 1 -and $arg[0].decodedValue -match "CSIDL_PROGRAM_FILES"
} | Select-Object -First 1)
$specialFonts = @($specialFolderPath | Where-Object {
    $arg = @($_.arguments | Where-Object { $_.name -eq "csidl" } | Select-Object -First 1)
    $arg.Count -eq 1 -and $arg[0].decodedValue -match "CSIDL_FONTS"
} | Select-Object -First 1)

if ($specialWindows.Count -ne 1 -or $specialSystem.Count -ne 1 -or $specialProgramFiles.Count -ne 1 -or $specialFonts.Count -ne 1)
{
    throw "x86 SHGetSpecialFolderPathW did not include all expected CSIDL values."
}

$specialWindowsPath = @($specialWindows[0].arguments | Where-Object { $_.name -eq "pszPath" } | Select-Object -First 1)
$specialSystemPath = @($specialSystem[0].arguments | Where-Object { $_.name -eq "pszPath" } | Select-Object -First 1)
$specialProgramFilesPath = @($specialProgramFiles[0].arguments | Where-Object { $_.name -eq "pszPath" } | Select-Object -First 1)
$specialFontsPath = @($specialFonts[0].arguments | Where-Object { $_.name -eq "pszPath" } | Select-Object -First 1)

if ($specialWindowsPath.Count -ne 1 -or $specialWindowsPath[0].decodedValue -notmatch "(?i)status=decoded_safe_path;.*path=[A-Z]:\\WINDOWS$")
{
    throw "x86 CSIDL_WINDOWS did not include allowlisted path evidence: $($specialWindowsPath | ConvertTo-Json -Depth 8)"
}

if ($specialSystemPath.Count -ne 1 -or $specialSystemPath[0].decodedValue -notmatch "(?i)status=decoded_safe_path;.*path=[A-Z]:\\WINDOWS\\system32$")
{
    throw "x86 CSIDL_SYSTEM did not include allowlisted path evidence: $($specialSystemPath | ConvertTo-Json -Depth 8)"
}

if ($specialProgramFilesPath.Count -ne 1 -or $specialProgramFilesPath[0].decodedValue -notmatch "(?i)status=decoded_safe_path;.*path=[A-Z]:\\Program Files(?: \(x86\))?$")
{
    throw "x86 CSIDL_PROGRAM_FILES did not include allowlisted path evidence: $($specialProgramFilesPath | ConvertTo-Json -Depth 8)"
}

if ($specialFontsPath.Count -ne 1 -or $specialFontsPath[0].decodedValue -notmatch "status=non_allowlisted_no_path" -or $specialFontsPath[0].decodedValue -match "path=")
{
    throw "x86 CSIDL_FONTS should not expose a returned path: $($specialFontsPath | ConvertTo-Json -Depth 8)"
}

$shellArgs = @($shellEvents | ForEach-Object { $_.arguments } | ConvertTo-Json -Depth 8)
if ($shellArgs -cmatch "Users\\\\|AppData|Downloads|Desktop|Documents|Recent|Startup|SendTo|OneDrive|ShellExecute|SHFileOperation|SHGetFileInfo|PIDL|ITEMIDLIST|PropertyStore|CommandLine|Environment|BEGIN CERTIFICATE|PRIVATE KEY|Authorization|Cookie|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 Shell events appear to expose user paths, shell payloads, credentials, PE/file/hash data, or byte-preview evidence: $shellArgs"
}

if ($shellArgs -cmatch "path=[^`"]*Fonts")
{
    throw "x86 non-allowlisted Font queries exposed a path: $shellArgs"
}

$comEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "com" })
if ($comEvents.Count -lt 7)
{
    throw "x86 capture did not include the selected OLE32 and COMBASE-backed WinRT lifecycle API family slices."
}

$coInitialize = @($comEvents | Where-Object { $_.api -eq "CoInitializeEx" } | Select-Object -First 1)
if ($coInitialize.Count -ne 1 -or
    $coInitialize[0].module -ne "ole32.dll" -or
    $coInitialize[0].apiCategory -ne "com_apartment_init" -or
    $coInitialize[0].hookPolicy -ne "iat" -or
    $coInitialize[0].coverageStatus -ne "smoke_verified" -or
    ($coInitialize[0].returnValue -ne "0x00000000" -and $coInitialize[0].returnValue -ne "0x00000001"))
{
    throw "x86 CoInitializeEx metadata or return evidence mismatch."
}

$coInitializeArgs = ($coInitialize[0].arguments | ConvertTo-Json -Depth 8)
if ($coInitializeArgs -notmatch "com_init_flags" -or $coInitializeArgs -notmatch "COINIT_MULTITHREADED")
{
    throw "x86 CoInitializeEx arguments did not include COM init flag evidence: $coInitializeArgs"
}

$coUninitialize = @($comEvents | Where-Object { $_.api -eq "CoUninitialize" } | Select-Object -First 1)
if ($coUninitialize.Count -ne 1 -or
    $coUninitialize[0].module -ne "ole32.dll" -or
    $coUninitialize[0].apiCategory -ne "com_apartment_uninit" -or
    $coUninitialize[0].returnValue -ne "void" -or
    @($coUninitialize[0].arguments).Count -ne 0)
{
    throw "x86 CoUninitialize should be lifecycle-only with no arguments."
}

$coCreateGuid = @($comEvents | Where-Object { $_.api -eq "CoCreateGuid" } | Select-Object -First 1)
if ($coCreateGuid.Count -ne 1 -or
    $coCreateGuid[0].module -ne "ole32.dll" -or
    $coCreateGuid[0].apiCategory -ne "com_guid_create" -or
    $coCreateGuid[0].returnValue -ne "0x00000000")
{
    throw "x86 CoCreateGuid metadata or return evidence mismatch."
}

$createdGuidArg = @($coCreateGuid[0].arguments | Where-Object { $_.name -eq "pguid" } | Select-Object -First 1)
if ($createdGuidArg.Count -ne 1 -or
    $createdGuidArg[0].decodeAlias -ne "guid_pointer" -or
    $createdGuidArg[0].decodedValue -notmatch "^GUID=\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
{
    throw "x86 CoCreateGuid did not include canonical GUID evidence: $($createdGuidArg | ConvertTo-Json -Depth 8)"
}

$stringFromGuid = @($comEvents | Where-Object { $_.api -eq "StringFromGUID2" } | Select-Object -First 1)
if ($stringFromGuid.Count -ne 1 -or
    $stringFromGuid[0].module -ne "ole32.dll" -or
    $stringFromGuid[0].apiCategory -ne "com_guid_string" -or
    $stringFromGuid[0].returnValue -notmatch "^[1-9][0-9]*$")
{
    throw "x86 StringFromGUID2 metadata or return evidence mismatch."
}

$stringGuidArg = @($stringFromGuid[0].arguments | Where-Object { $_.name -eq "rguid" } | Select-Object -First 1)
$guidStringArg = @($stringFromGuid[0].arguments | Where-Object { $_.name -eq "lpsz" } | Select-Object -First 1)
$guidStringSizeArg = @($stringFromGuid[0].arguments | Where-Object { $_.name -eq "cchMax" } | Select-Object -First 1)
if ($stringGuidArg.Count -ne 1 -or
    $stringGuidArg[0].decodeAlias -ne "guid_pointer" -or
    $stringGuidArg[0].decodedValue -notmatch "^GUID=\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
{
    throw "x86 StringFromGUID2 did not include input GUID evidence: $($stringGuidArg | ConvertTo-Json -Depth 8)"
}

if ($guidStringArg.Count -ne 1 -or
    $guidStringArg[0].decodeAlias -ne "guid_string_buffer_pointer" -or
    $guidStringArg[0].decodedValue -notmatch "^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
{
    throw "x86 StringFromGUID2 did not include bounded canonical output GUID string evidence: $($guidStringArg | ConvertTo-Json -Depth 8)"
}

if ($guidStringSizeArg.Count -ne 1 -or $guidStringSizeArg[0].decodedValue -ne "64")
{
    throw "x86 StringFromGUID2 used unexpected cchMax evidence: $($guidStringSizeArg | ConvertTo-Json -Depth 8)"
}

$createdGuid = $createdGuidArg[0].decodedValue -replace "^GUID=", ""
if ($createdGuid.ToLowerInvariant() -ne $guidStringArg[0].decodedValue.ToLowerInvariant())
{
    throw "x86 CoCreateGuid and StringFromGUID2 GUID evidence diverged."
}

$roInitialize = @($comEvents | Where-Object { $_.api -eq "RoInitialize" } | Select-Object -First 1)
if ($roInitialize.Count -ne 1 -or
    $roInitialize[0].module -ne $winrtProviderModule -or
    $roInitialize[0].apiCategory -ne "winrt_apartment_init" -or
    $roInitialize[0].hookPolicy -ne "iat" -or
    $roInitialize[0].coverageStatus -ne "smoke_verified" -or
    $roInitialize[0].returnValue -notmatch "^0x[0-7][0-9a-fA-F]{7}$")
{
    throw "x86 RoInitialize metadata or return evidence mismatch."
}

$roInitializeArg = @($roInitialize[0].arguments | Where-Object { $_.name -eq "initType" } | Select-Object -First 1)
if ($roInitializeArg.Count -ne 1 -or
    $roInitializeArg[0].decodeAlias -ne "ro_init_type" -or
    $roInitializeArg[0].decodedValue -notmatch "RO_INIT_MULTITHREADED" -or
    $roInitializeArg[0].rawValue -ne "0x00000001")
{
    throw "x86 RoInitialize did not include WinRT init type evidence: $($roInitializeArg | ConvertTo-Json -Depth 8)"
}

$roApartment = @($comEvents | Where-Object { $_.api -eq "RoGetApartmentIdentifier" } | Select-Object -First 1)
if ($roApartment.Count -ne 1 -or
    $roApartment[0].module -ne $winrtProviderModule -or
    $roApartment[0].apiCategory -ne "winrt_apartment_identifier" -or
    $roApartment[0].returnValue -notmatch "^0x[0-7][0-9a-fA-F]{7}$")
{
    throw "x86 RoGetApartmentIdentifier metadata or return evidence mismatch."
}

$roApartmentArg = @($roApartment[0].arguments | Where-Object { $_.name -eq "apartmentIdentifier" } | Select-Object -First 1)
if ($roApartmentArg.Count -ne 1 -or
    $roApartmentArg[0].decodeAlias -ne "uint64_pointer" -or
    $roApartmentArg[0].captureTiming -ne "post" -or
    $roApartmentArg[0].decodeStatus -ne "decoded" -or
    $roApartmentArg[0].rawValue -notmatch "^0x[0-9a-fA-F]+$" -or
    $roApartmentArg[0].postCallValue -notmatch "^\d+$" -or
    $roApartmentArg[0].decodedValue -notmatch "value=\d+")
{
    throw "x86 RoGetApartmentIdentifier did not include decoded UINT64 evidence: $($roApartmentArg | ConvertTo-Json -Depth 8)"
}

$roUninitialize = @($comEvents | Where-Object { $_.api -eq "RoUninitialize" } | Select-Object -First 1)
if ($roUninitialize.Count -ne 1 -or
    $roUninitialize[0].module -ne $winrtProviderModule -or
    $roUninitialize[0].apiCategory -ne "winrt_apartment_uninit" -or
    $roUninitialize[0].returnValue -ne "void" -or
    @($roUninitialize[0].arguments).Count -ne 0)
{
    throw "x86 RoUninitialize should be lifecycle-only with no arguments."
}

$winrtPayload = @($roInitialize[0], $roApartment[0], $roUninitialize[0]) | ConvertTo-Json -Depth 12
if ($winrtPayload -cmatch "RoGetActivationFactory|RoActivateInstance|RoRegisterActivationFactories|RoRevokeActivationFactories|WindowsCreateString|WindowsGetStringRawBuffer|HSTRING|RuntimeClass|ActivationFactory|IActivationFactory|IInspectable|IClassFactory|IUnknown|IDispatch|vtable|Vtbl|IMarshal|IStream|IStorage|IDataObject|Clipboard|DragDrop|Moniker|RunningObjectTable|ROT|RestrictedError|ErrorInfo|Users\\\\|AppData|Downloads|Desktop|Documents|CommandLine|Environment|Password|Credential|Token|SecurityDescriptor|Sid|Acl|BEGIN CERTIFICATE|PRIVATE KEY|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 COMBASE-backed WinRT events appear to expose activation, HSTRING, COM object, error-info, credential, path, PE/file/hash, or byte-preview evidence: $winrtPayload"
}

$comArgs = @($comEvents | ForEach-Object { $_.arguments } | ConvertTo-Json -Depth 8)
if ($comArgs -cmatch "CoCreateInstance|CoGetClassObject|CoGetObject|RoGetActivationFactory|RoActivateInstance|WindowsCreateString|WindowsGetStringRawBuffer|HSTRING|RuntimeClass|ActivationFactory|IActivationFactory|IInspectable|IClassFactory|IUnknown|IDispatch|vtable|Vtbl|IMarshal|IStream|IStorage|IDataObject|Clipboard|DragDrop|Moniker|RunningObjectTable|ROT|RestrictedError|ErrorInfo|ShellExecute|PIDL|ITEMIDLIST|Users\\\\|AppData|Downloads|Desktop|Documents|Recent|Startup|SendTo|CommandLine|Environment|BEGIN CERTIFICATE|PRIVATE KEY|Authorization|Cookie|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 COM lifecycle events appear to expose activation, HSTRING, object, marshaling, storage, user-path, credential, PE/file/hash, or byte-preview evidence: $comArgs"
}

$rpcEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "rpc" })
if ($rpcEvents.Count -lt 7)
{
    throw "x86 capture did not include the selected RPCRT4 binding and UUID API family slices."
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

$uuidCreate = @($rpcEvents | Where-Object { $_.api -eq "UuidCreate" } | Select-Object -First 1)
if ($uuidCreate.Count -ne 1 -or
    $uuidCreate[0].module -ne "rpcrt4.dll" -or
    $uuidCreate[0].apiCategory -ne "uuid_create" -or
    ($uuidCreate[0].returnValue -ne "0 (0x00000000)" -and $uuidCreate[0].returnValue -ne "1824 (0x00000720)") -or
    $uuidCreate[0].hookPolicy -ne "iat" -or
    $uuidCreate[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 UuidCreate metadata or return evidence mismatch."
}

$uuidCreateArg = @($uuidCreate[0].arguments | Where-Object { $_.name -eq "Uuid" } | Select-Object -First 1)
if ($uuidCreateArg.Count -ne 1 -or
    $uuidCreateArg[0].decodeAlias -ne "guid_pointer" -or
    $uuidCreateArg[0].captureTiming -ne "post" -or
    $uuidCreateArg[0].decodedValue -notmatch "^UUID=\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
{
    throw "x86 UuidCreate did not include canonical UUID evidence: $($uuidCreateArg | ConvertTo-Json -Depth 8)"
}

$uuidToString = @($rpcEvents | Where-Object { $_.api -eq "UuidToStringW" } | Select-Object -First 1)
if ($uuidToString.Count -ne 1 -or
    $uuidToString[0].module -ne "rpcrt4.dll" -or
    $uuidToString[0].apiCategory -ne "uuid_to_string" -or
    $uuidToString[0].returnValue -ne "0 (0x00000000)")
{
    throw "x86 UuidToStringW metadata or return evidence mismatch."
}

$uuidToStringInput = @($uuidToString[0].arguments | Where-Object { $_.name -eq "Uuid" } | Select-Object -First 1)
$uuidToStringOutput = @($uuidToString[0].arguments | Where-Object { $_.name -eq "StringUuid" } | Select-Object -First 1)
if ($uuidToStringInput.Count -ne 1 -or
    $uuidToStringInput[0].decodeAlias -ne "guid_pointer" -or
    $uuidToStringInput[0].decodedValue -notmatch "^UUID=\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
{
    throw "x86 UuidToStringW did not include input UUID evidence: $($uuidToStringInput | ConvertTo-Json -Depth 8)"
}

if ($uuidToStringOutput.Count -ne 1 -or
    $uuidToStringOutput[0].decodeAlias -ne "rpc_string_pointer" -or
    $uuidToStringOutput[0].captureTiming -ne "post" -or
    $uuidToStringOutput[0].decodedValue -notmatch "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
{
    throw "x86 UuidToStringW did not include bounded canonical UUID string evidence: $($uuidToStringOutput | ConvertTo-Json -Depth 8)"
}

$createdUuid = $uuidCreateArg[0].decodedValue -replace "^UUID=\{", "" -replace "\}$", ""
if ($createdUuid.ToLowerInvariant() -ne $uuidToStringOutput[0].decodedValue.ToLowerInvariant())
{
    throw "x86 UuidCreate and UuidToStringW UUID evidence diverged."
}

$uuidFromString = @($rpcEvents | Where-Object { $_.api -eq "UuidFromStringW" } | Select-Object -First 1)
if ($uuidFromString.Count -ne 1 -or
    $uuidFromString[0].module -ne "rpcrt4.dll" -or
    $uuidFromString[0].apiCategory -ne "uuid_from_string" -or
    $uuidFromString[0].returnValue -ne "0 (0x00000000)")
{
    throw "x86 UuidFromStringW metadata or return evidence mismatch."
}

$uuidFromStringInput = @($uuidFromString[0].arguments | Where-Object { $_.name -eq "StringUuid" } | Select-Object -First 1)
$uuidFromStringOutput = @($uuidFromString[0].arguments | Where-Object { $_.name -eq "Uuid" } | Select-Object -First 1)
if ($uuidFromStringInput.Count -ne 1 -or
    $uuidFromStringInput[0].decodeAlias -ne "utf16_string" -or
    $uuidFromStringInput[0].decodedValue -notmatch "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
{
    throw "x86 UuidFromStringW did not include canonical input string evidence: $($uuidFromStringInput | ConvertTo-Json -Depth 8)"
}

if ($uuidFromStringOutput.Count -ne 1 -or
    $uuidFromStringOutput[0].decodeAlias -ne "guid_pointer" -or
    $uuidFromStringOutput[0].captureTiming -ne "post" -or
    $uuidFromStringOutput[0].decodedValue -notmatch "^UUID=\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
{
    throw "x86 UuidFromStringW did not include output UUID evidence: $($uuidFromStringOutput | ConvertTo-Json -Depth 8)"
}

$parsedUuid = "UUID={$($uuidFromStringInput[0].decodedValue)}"
if ($parsedUuid.ToLowerInvariant() -ne $uuidFromStringOutput[0].decodedValue.ToLowerInvariant())
{
    throw "x86 UuidFromStringW input and output UUID evidence diverged."
}

$uuidStringFree = @($rpcEvents | Where-Object {
    $_.api -eq "RpcStringFreeW" -and (($_.arguments | ConvertTo-Json -Depth 8) -match "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
} | Select-Object -First 1)
if ($uuidStringFree.Count -ne 1)
{
    throw "x86 capture did not include RpcStringFreeW cleanup for UuidToStringW output."
}

$uuidPayload = @($uuidCreate[0], $uuidToString[0], $uuidFromString[0]) | ConvertTo-Json -Depth 12
if ($uuidPayload -cmatch "RpcMgmtEp|RpcBindingSetAuth|RpcBindingSetOption|Endpoint|Annotation|ServerPrinc|AuthIdentity|Authn|Authz|NetworkAddr|connect|send|recv|WinHttp|InternetOpenUrl|HttpSend|Authorization|Cookie|Password|Credential|Token|SecurityDescriptor|Sid|Acl|CoCreateInstance|CoGetClassObject|IClassFactory|IUnknown|IDispatch|vtable|Vtbl|IMarshal|IStream|IStorage|IDataObject|Clipboard|DragDrop|Moniker|RunningObjectTable|ROT|Users\\\\|AppData|Downloads|Desktop|Documents|CommandLine|Environment|BEGIN CERTIFICATE|PRIVATE KEY|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 RPCRT4 UUID helper events appear to expose endpoint, auth, network, COM, credential, path, PE/file/hash, or byte-preview evidence: $uuidPayload"
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
