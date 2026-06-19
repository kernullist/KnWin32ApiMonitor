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
    "VirtualAlloc",
    "VirtualFree",
    "VirtualProtect",
    "VirtualQuery",
    "CreateFileMappingW",
    "OpenFileMappingW",
    "MapViewOfFile",
    "UnmapViewOfFile",
    "GetCurrentProcess",
    "GetCurrentProcessId",
    "GetCurrentThread",
    "GetCurrentThreadId",
    "GetProcessId",
    "GetThreadId",
    "GetStdHandle",
    "GetFileType",
    "GetHandleInformation",
    "SetHandleInformation",
    "GetFileSizeEx",
    "GetFileTime",
    "GetFileInformationByHandle",
    "GetModuleHandleW",
    "GetModuleHandleExW",
    "GetModuleFileNameW",
    "FreeLibrary",
    "CreateThread",
    "OpenThread",
    "WaitForSingleObject",
    "GetExitCodeThread",
    "CreateEventW",
    "OpenEventW",
    "SetEvent",
    "ResetEvent",
    "WaitForSingleObjectEx",
    "CreateMutexW",
    "OpenMutexW",
    "ReleaseMutex",
    "CreateSemaphoreW",
    "OpenSemaphoreW",
    "ReleaseSemaphore",
    "WaitForMultipleObjectsEx",
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
    "WinHttpSetOption",
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
    "VariantClear",
    "SafeArrayDestroy",
    "DnsRecordListFree",
    "SymInitializeW",
    "SymCleanup",
    "RpcStringBindingComposeW",
    "RpcBindingFromStringBindingW",
    "RpcStringFreeW",
    "RpcBindingFree",
    "RpcBindingSetOption",
    "UuidCreate",
    "UuidToStringW",
    "UuidFromStringW",
    "WSAStartup",
    "WSACleanup",
    "socket",
    "closesocket",
    "connect",
    "getaddrinfo",
    "freeaddrinfo",
    "WSAGetLastError"
)

function ConvertFrom-DwordDecimalHex
{
    param(
        [string]$Value,
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^([0-9]+) \(0x[0-9a-fA-F]{8}\)$")
    {
        throw "$Name is not a DWORD decimal/hex value: $Value"
    }

    $parsed = [UInt64]$Matches[1]
    if ($parsed -eq 0 -or $parsed -gt [UInt32]::MaxValue)
    {
        throw "$Name is outside nonzero DWORD range: $Value"
    }

    return [UInt32]$parsed
}

function ConvertFrom-UInt64DecimalHex
{
    param(
        [string]$Value,
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^([0-9]+) \(0x[0-9a-fA-F]{16}\)$")
    {
        throw "$Name is not a UINT64 decimal/hex value: $Value"
    }

    return [UInt64]$Matches[1]
}

function Assert-PointerValue
{
    param(
        [string]$Value,
        [string]$Name,
        [bool]$AllowNull = $false
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^0x[0-9a-fA-F]+$")
    {
        throw "$Name is not a pointer value: $Value"
    }

    if (-not $AllowNull -and $Value -match "^0x0+$")
    {
        throw "$Name unexpectedly used a null pointer."
    }
}

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

$oleautEvents = @($result.capturedEvents | Where-Object { $_.module -eq "oleaut32.dll" -and $_.api -in @("VariantClear", "SafeArrayDestroy") })
if ($oleautEvents.Count -lt 2)
{
    throw "x86 capture did not include the selected OLEAUT32 lifecycle API slice."
}

$variantClear = @($oleautEvents | Where-Object { $_.api -eq "VariantClear" } | Select-Object -First 1)
if ($variantClear.Count -ne 1 -or
    $variantClear[0].apiFamily -ne "ole-automation" -or
    $variantClear[0].apiCategory -ne "variant_clear" -or
    $variantClear[0].hookPolicy -ne "iat" -or
    $variantClear[0].coverageStatus -ne "smoke_verified" -or
    $variantClear[0].returnValue -ne "0x00000000")
{
    throw "x86 VariantClear metadata or return evidence mismatch: $($variantClear | ConvertTo-Json -Depth 8)"
}

$variantPointer = @($variantClear[0].arguments | Where-Object { $_.name -eq "pvarg" } | Select-Object -First 1)
if ($variantPointer.Count -ne 1 -or $variantPointer[0].decodeAlias -ne "pointer")
{
    throw "x86 VariantClear pointer metadata mismatch: $($variantPointer | ConvertTo-Json -Depth 8)"
}
Assert-PointerValue -Value $variantPointer[0].decodedValue -Name "x86 VariantClear pvarg"

$safeArrayDestroy = @($oleautEvents | Where-Object { $_.api -eq "SafeArrayDestroy" } | Select-Object -First 1)
if ($safeArrayDestroy.Count -ne 1 -or
    $safeArrayDestroy[0].apiFamily -ne "ole-automation" -or
    $safeArrayDestroy[0].apiCategory -ne "safe_array_destroy" -or
    $safeArrayDestroy[0].hookPolicy -ne "iat" -or
    $safeArrayDestroy[0].coverageStatus -ne "smoke_verified" -or
    $safeArrayDestroy[0].returnValue -ne "0x00000000")
{
    throw "x86 SafeArrayDestroy metadata or return evidence mismatch: $($safeArrayDestroy | ConvertTo-Json -Depth 8)"
}

$safeArrayPointer = @($safeArrayDestroy[0].arguments | Where-Object { $_.name -eq "psa" } | Select-Object -First 1)
if ($safeArrayPointer.Count -ne 1 -or $safeArrayPointer[0].decodeAlias -ne "pointer")
{
    throw "x86 SafeArrayDestroy pointer metadata mismatch: $($safeArrayPointer | ConvertTo-Json -Depth 8)"
}
Assert-PointerValue -Value $safeArrayPointer[0].decodedValue -Name "x86 SafeArrayDestroy psa"

$oleautPayload = $oleautEvents | ConvertTo-Json -Depth 12
if ($oleautPayload -cmatch "SysAllocString|SysFreeString|VT_BSTR|BSTR|bstrString|SafeArrayAccessData|SafeArrayGetElement|SafeArrayPtrOfIndex|VariantChangeType|C:\\Users|AppData|ProgramData|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|StackWalk|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 OLEAUT32 events appear to expose BSTR, SAFEARRAY content, payload, stack, injection, credential, or byte-preview evidence: $oleautPayload"
}

$dnsRecordFree = @($result.capturedEvents | Where-Object { $_.module -eq "dnsapi.dll" -and $_.api -eq "DnsRecordListFree" } | Select-Object -First 1)
if ($dnsRecordFree.Count -ne 1 -or
    $dnsRecordFree[0].apiFamily -ne "dns" -or
    $dnsRecordFree[0].apiCategory -ne "dns_record_list_free" -or
    $dnsRecordFree[0].hookPolicy -ne "iat" -or
    $dnsRecordFree[0].coverageStatus -ne "smoke_verified" -or
    $dnsRecordFree[0].returnValue -ne "void")
{
    throw "x86 DnsRecordListFree metadata or return evidence mismatch: $($dnsRecordFree | ConvertTo-Json -Depth 8)"
}

if (-not [string]::IsNullOrEmpty($dnsRecordFree[0].bufferPreview))
{
    throw "x86 DnsRecordListFree exposed bufferPreview: $($dnsRecordFree[0] | ConvertTo-Json -Depth 8)"
}

$dnsRecordList = @($dnsRecordFree[0].arguments | Where-Object { $_.name -eq "pRecordList" } | Select-Object -First 1)
if ($dnsRecordList.Count -ne 1 -or
    $dnsRecordList[0].decodeAlias -ne "pointer" -or
    $dnsRecordList[0].rawValue -notmatch "^0x0+$" -or
    $dnsRecordList[0].decodedValue -notmatch "^0x0+$")
{
    throw "x86 DnsRecordListFree record-list pointer evidence mismatch: $($dnsRecordList | ConvertTo-Json -Depth 8)"
}

$dnsFreeType = @($dnsRecordFree[0].arguments | Where-Object { $_.name -eq "FreeType" } | Select-Object -First 1)
if ($dnsFreeType.Count -ne 1 -or
    $dnsFreeType[0].decodeAlias -ne "dword_value" -or
    $dnsFreeType[0].decodedValue -notmatch "^1( \(0x00000001\))?$")
{
    throw "x86 DnsRecordListFree FreeType evidence mismatch: $($dnsFreeType | ConvertTo-Json -Depth 8)"
}

$dnsPayload = $dnsRecordFree[0] | ConvertTo-Json -Depth 12
if ($dnsPayload -cmatch "DnsQuery|pszName|ppQueryResults|pReserved|DNS_RECORDW|DnsRecordSet|DnsExtract|DnsModify|[a-zA-Z0-9_-]+\.(com|net|org|local|test)|127\.0\.0\.1|Adapter|RouteTable|C:\\Users|AppData|ProgramData|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|StackWalk|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 DnsRecordListFree event appears to expose query, record, hostname, inventory, payload, stack, injection, credential, or byte-preview evidence: $dnsPayload"
}

$dbghelpEvents = @($result.capturedEvents | Where-Object { $_.module -eq "dbghelp.dll" -and $_.api -in @("SymInitializeW", "SymCleanup") })
if ($dbghelpEvents.Count -lt 2)
{
    throw "x86 capture did not include the selected DBGHELP symbol-session API slice."
}

$symInitialize = @($dbghelpEvents | Where-Object { $_.api -eq "SymInitializeW" } | Select-Object -First 1)
if ($symInitialize.Count -ne 1 -or
    $symInitialize[0].apiFamily -ne "symbols" -or
    $symInitialize[0].apiCategory -ne "symbol_session_initialize" -or
    $symInitialize[0].hookPolicy -ne "iat" -or
    $symInitialize[0].coverageStatus -ne "smoke_verified" -or
    $symInitialize[0].returnValue -ne "TRUE")
{
    throw "x86 SymInitializeW metadata or return evidence mismatch: $($symInitialize | ConvertTo-Json -Depth 8)"
}

$symInitProcess = @($symInitialize[0].arguments | Where-Object { $_.name -eq "hProcess" } | Select-Object -First 1)
if ($symInitProcess.Count -ne 1 -or $symInitProcess[0].decodeAlias -ne "handle")
{
    throw "x86 SymInitializeW process handle metadata mismatch: $($symInitProcess | ConvertTo-Json -Depth 8)"
}
Assert-PointerValue -Value $symInitProcess[0].decodedValue -Name "x86 SymInitializeW hProcess"

$symSearchPath = @($symInitialize[0].arguments | Where-Object { $_.name -eq "UserSearchPath" } | Select-Object -First 1)
if ($symSearchPath.Count -ne 1 -or
    $symSearchPath[0].decodeAlias -ne "pointer" -or
    $symSearchPath[0].rawValue -notmatch "^0x0+$" -or
    $symSearchPath[0].decodedValue -notmatch "^0x0+$")
{
    throw "x86 SymInitializeW search path was not null pointer-only evidence: $($symSearchPath | ConvertTo-Json -Depth 8)"
}

$symInvade = @($symInitialize[0].arguments | Where-Object { $_.name -eq "fInvadeProcess" } | Select-Object -First 1)
if ($symInvade.Count -ne 1 -or
    $symInvade[0].decodeAlias -ne "byte_count" -or
    $symInvade[0].decodedValue -ne "FALSE")
{
    throw "x86 SymInitializeW invade flag evidence mismatch: $($symInvade | ConvertTo-Json -Depth 8)"
}

$symCleanup = @($dbghelpEvents | Where-Object { $_.api -eq "SymCleanup" } | Select-Object -First 1)
if ($symCleanup.Count -ne 1 -or
    $symCleanup[0].apiFamily -ne "symbols" -or
    $symCleanup[0].apiCategory -ne "symbol_session_cleanup" -or
    $symCleanup[0].hookPolicy -ne "iat" -or
    $symCleanup[0].coverageStatus -ne "smoke_verified" -or
    $symCleanup[0].returnValue -ne "TRUE")
{
    throw "x86 SymCleanup metadata or return evidence mismatch: $($symCleanup | ConvertTo-Json -Depth 8)"
}

$symCleanupProcess = @($symCleanup[0].arguments | Where-Object { $_.name -eq "hProcess" } | Select-Object -First 1)
if ($symCleanupProcess.Count -ne 1 -or
    $symCleanupProcess[0].decodeAlias -ne "handle" -or
    $symCleanupProcess[0].decodedValue -ne $symInitProcess[0].decodedValue)
{
    throw "x86 SymCleanup process handle evidence mismatch: $($symCleanupProcess | ConvertTo-Json -Depth 8)"
}

$dbghelpPayload = $dbghelpEvents | ConvertTo-Json -Depth 12
if ($dbghelpPayload -cmatch "\.pdb|PDB|SymbolPath|SymEnum|SymFrom|SymLoad|LoadedModule|srv\*|symsrv|C:\\Users|AppData|ProgramData|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|StackWalk|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 DBGHELP events appear to expose symbol path, PDB, module, payload, stack, injection, credential, or byte-preview evidence: $dbghelpPayload"
}

$bindingSetOptionEvent = @($result.capturedEvents | Where-Object { $_.api -eq "RpcBindingSetOption" } | Select-Object -First 1)
if ($bindingSetOptionEvent.Count -ne 1)
{
    throw "x86 capture did not include RpcBindingSetOption."
}

if ($bindingSetOptionEvent[0].module -ne "rpcrt4.dll" -or
    $bindingSetOptionEvent[0].apiFamily -ne "rpc" -or
    $bindingSetOptionEvent[0].apiCategory -ne "rpc_binding_option_set" -or
    $bindingSetOptionEvent[0].hookPolicy -ne "iat" -or
    $bindingSetOptionEvent[0].coverageStatus -ne "smoke_verified" -or
    $bindingSetOptionEvent[0].returnValue -notmatch "^0 \(0x00000000\)$")
{
    throw "x86 RpcBindingSetOption metadata or return evidence mismatch: $($bindingSetOptionEvent | ConvertTo-Json -Depth 8)"
}

if (-not [string]::IsNullOrEmpty($bindingSetOptionEvent[0].bufferPreview))
{
    throw "x86 RpcBindingSetOption exposed bufferPreview: $($bindingSetOptionEvent | ConvertTo-Json -Depth 8)"
}

$bindingHandle = @($bindingSetOptionEvent[0].arguments | Where-Object { $_.name -eq "hBinding" } | Select-Object -First 1)
if ($bindingHandle.Count -ne 1 -or
    $bindingHandle[0].decodeAlias -ne "rpc_binding_handle" -or
    $bindingHandle[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 RpcBindingSetOption binding handle evidence mismatch: $($bindingHandle | ConvertTo-Json -Depth 8)"
}

$bindingOption = @($bindingSetOptionEvent[0].arguments | Where-Object { $_.name -eq "option" } | Select-Object -First 1)
if ($bindingOption.Count -ne 1 -or
    $bindingOption[0].decodeAlias -ne "byte_count" -or
    ($bindingOption[0].decodedValue -ne "12 (0x0000000C)" -and $bindingOption[0].decodedValue -ne "12"))
{
    throw "x86 RpcBindingSetOption option evidence mismatch: $($bindingOption | ConvertTo-Json -Depth 8)"
}

$bindingOptionValue = @($bindingSetOptionEvent[0].arguments | Where-Object { $_.name -eq "optionValue" } | Select-Object -First 1)
if ($bindingOptionValue.Count -ne 1 -or
    $bindingOptionValue[0].decodeAlias -ne "byte_count" -or
    $bindingOptionValue[0].decodedValue -ne "5000")
{
    throw "x86 RpcBindingSetOption optionValue evidence mismatch: $($bindingOptionValue | ConvertTo-Json -Depth 8)"
}

$bindingSetOptionPayload = $bindingSetOptionEvent[0] | ConvertTo-Json -Depth 12
if ($bindingSetOptionPayload -cmatch "RpcBindingSetAuthInfo|RpcMgmtEp|EndpointMapper|Annotation|ServerPrinc|AuthIdentity|Authn|Authz|Credential|Password|Token|SID|ACL|SecurityDescriptor|send|recv|WinHttp|InternetOpenUrl|HttpSend|Cookie|Authorization|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|Injection|BEGIN CERTIFICATE|PRIVATE KEY|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 RpcBindingSetOption event appears to expose forbidden auth, endpoint, credential, payload, remote-memory, stack, injection, or byte-preview evidence: $bindingSetOptionPayload"
}

$connectEvent = @($result.capturedEvents | Where-Object { $_.api -eq "connect" } | Select-Object -First 1)
if ($connectEvent.Count -ne 1)
{
    throw "x86 capture did not include Winsock connect."
}

if ($connectEvent[0].module -ne "ws2_32.dll" -or
    $connectEvent[0].apiFamily -ne "network" -or
    $connectEvent[0].apiCategory -ne "socket_connect" -or
    $connectEvent[0].hookPolicy -ne "iat" -or
    $connectEvent[0].coverageStatus -ne "smoke_verified" -or
    ($connectEvent[0].returnValue -ne "0" -and $connectEvent[0].returnValue -ne "0 (0x00000000)"))
{
    throw "x86 Winsock connect metadata or return evidence mismatch: $($connectEvent | ConvertTo-Json -Depth 8)"
}

if (-not [string]::IsNullOrEmpty($connectEvent[0].bufferPreview))
{
    throw "x86 Winsock connect exposed bufferPreview: $($connectEvent | ConvertTo-Json -Depth 8)"
}

$connectSocket = @($connectEvent[0].arguments | Where-Object { $_.name -eq "s" } | Select-Object -First 1)
if ($connectSocket.Count -ne 1 -or
    $connectSocket[0].decodeAlias -ne "socket_handle" -or
    $connectSocket[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 Winsock connect socket evidence mismatch: $($connectSocket | ConvertTo-Json -Depth 8)"
}

$connectAddress = @($connectEvent[0].arguments | Where-Object { $_.name -eq "name" } | Select-Object -First 1)
if ($connectAddress.Count -ne 1 -or
    $connectAddress[0].decodeAlias -ne "sockaddr" -or
    $connectAddress[0].decodeStatus -ne "decoded" -or
    $connectAddress[0].rawValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $connectAddress[0].decodedValue -notmatch "^127\.0\.0\.1:[0-9]+$")
{
    throw "x86 Winsock connect sockaddr evidence mismatch: $($connectAddress | ConvertTo-Json -Depth 8)"
}

$connectLength = @($connectEvent[0].arguments | Where-Object { $_.name -eq "namelen" } | Select-Object -First 1)
if ($connectLength.Count -ne 1 -or
    $connectLength[0].decodeAlias -ne "byte_count" -or
    ($connectLength[0].decodedValue -ne "16" -and $connectLength[0].decodedValue -notmatch "^16 "))
{
    throw "x86 Winsock connect namelen evidence mismatch: $($connectLength | ConvertTo-Json -Depth 8)"
}

$connectPayload = $connectEvent[0] | ConvertTo-Json -Depth 12
if ($connectPayload -cmatch "socket_send|socket_recv|sendto|recvfrom|WSASend|WSARecv|WinHttp|InternetOpenUrl|HttpSend|Header|Cookie|Authorization|Password|Credential|Proxy|DNS|Adapter|RouteTable|CommandLine|Environment|TOKEN_|SecurityDescriptor|SID|ACL|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|Injection|BEGIN CERTIFICATE|PRIVATE KEY|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 Winsock connect event appears to expose payload-heavy, credential, inventory, remote-memory, stack, injection, or byte-preview evidence: $connectPayload"
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
if ($httpEvents.Count -lt 3)
{
    throw "x86 capture did not include the selected WinHTTP session and option API family slice."
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

$winHttpSetOption = @($httpEvents | Where-Object { $_.api -eq "WinHttpSetOption" } | Select-Object -First 1)
if ($winHttpSetOption.Count -ne 1 -or $winHttpSetOption[0].module -ne "winhttp.dll" -or $winHttpSetOption[0].apiCategory -ne "winhttp_option_set" -or $winHttpSetOption[0].hookPolicy -ne "iat" -or $winHttpSetOption[0].coverageStatus -ne "smoke_verified")
{
    throw "x86 WinHttpSetOption metadata mismatch."
}

if ([string]$winHttpSetOption[0].returnValue -ne "1")
{
    throw "x86 WinHttpSetOption did not return BOOL true: $($winHttpSetOption[0].returnValue)"
}

$winHttpSetOptionHandle = @($winHttpSetOption[0].arguments | Where-Object { $_.name -eq "hInternet" } | Select-Object -First 1)
if ($winHttpSetOptionHandle.Count -ne 1 -or $winHttpSetOptionHandle[0].rawValue -match "^0x0+$")
{
    throw "x86 WinHttpSetOption missing non-null hInternet evidence."
}

$winHttpSetOptionOption = @($winHttpSetOption[0].arguments | Where-Object { $_.name -eq "dwOption" } | Select-Object -First 1)
if ($winHttpSetOptionOption.Count -ne 1 -or $winHttpSetOptionOption[0].decodedValue -notmatch "WINHTTP_OPTION_RECEIVE_TIMEOUT")
{
    throw "x86 WinHttpSetOption option mismatch: $($winHttpSetOptionOption[0] | ConvertTo-Json -Depth 8)"
}

$winHttpSetOptionBuffer = @($winHttpSetOption[0].arguments | Where-Object { $_.name -eq "lpBuffer" } | Select-Object -First 1)
if ($winHttpSetOptionBuffer.Count -ne 1 -or $winHttpSetOptionBuffer[0].rawValue -match "^0x0+$")
{
    throw "x86 WinHttpSetOption missing non-null lpBuffer pointer evidence."
}

if ($winHttpSetOptionBuffer[0].decodeStatus -ne "decoded" -or $winHttpSetOptionBuffer[0].decodedValue -notmatch "value=5000")
{
    throw "x86 WinHttpSetOption scalar option value mismatch: $($winHttpSetOptionBuffer[0] | ConvertTo-Json -Depth 8)"
}

$winHttpSetOptionLength = @($winHttpSetOption[0].arguments | Where-Object { $_.name -eq "dwBufferLength" } | Select-Object -First 1)
if ($winHttpSetOptionLength.Count -ne 1 -or $winHttpSetOptionLength[0].decodedValue -ne "4")
{
    throw "x86 WinHttpSetOption buffer length mismatch: $($winHttpSetOptionLength[0] | ConvertTo-Json -Depth 8)"
}

$winHttpPayload = @($result.capturedEvents | Where-Object { $_.module -eq "winhttp.dll" } | ConvertTo-Json -Depth 10)
if ($winHttpPayload -cmatch "WinHttpConnect|WinHttpOpenRequest|WinHttpSendRequest|WinHttpReceiveResponse|WinHttpReadData|WinHttpWriteData|WinHttpQueryHeaders|InternetOpenUrl|HttpSend|send|recv|Authorization|Cookie|Set-Cookie|Password|Credential|Proxy-Authorization|https?://|POST|GET /|BEGIN CERTIFICATE|PRIVATE KEY|CommandLine|Environment|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|GetThreadContext|SetThreadContext|CallStack|StackTrace|Injection|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 WinHTTP events appear to expose forbidden payload evidence: $winHttpPayload"
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

$memoryEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "memory" })
$memoryProtectionApis = @(
    "VirtualAlloc",
    "VirtualFree",
    "VirtualProtect",
    "VirtualQuery"
)
$memoryProtectionEvents = @($memoryEvents | Where-Object { $memoryProtectionApis -contains $_.api })
if ($memoryProtectionEvents.Count -lt $memoryProtectionApis.Count)
{
    throw "x86 capture did not include the selected KERNEL32 memory protection API slice."
}

$virtualAlloc = @($memoryProtectionEvents | Where-Object { $_.api -eq "VirtualAlloc" } | Select-Object -First 1)
if ($virtualAlloc.Count -ne 1 -or
    $virtualAlloc[0].module -ne "kernel32.dll" -or
    $virtualAlloc[0].apiCategory -ne "memory_allocate" -or
    $virtualAlloc[0].hookPolicy -ne "iat" -or
    $virtualAlloc[0].coverageStatus -ne "smoke_verified" -or
    $virtualAlloc[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 VirtualAlloc metadata or return evidence mismatch."
}

$virtualAllocArgs = ($virtualAlloc[0].arguments | ConvertTo-Json -Depth 8)
if ($virtualAllocArgs -notmatch "memory_allocation_type" -or
    $virtualAllocArgs -notmatch "memory_protection_flags" -or
    $virtualAllocArgs -notmatch "MEM_COMMIT" -or
    $virtualAllocArgs -notmatch "MEM_RESERVE" -or
    $virtualAllocArgs -notmatch "PAGE_READWRITE" -or
    $virtualAllocArgs -notmatch '"decodedValue":\s*"12288"')
{
    throw "x86 VirtualAlloc arguments did not include expected allocation metadata: $virtualAllocArgs"
}

$virtualProtect = @($memoryProtectionEvents | Where-Object { $_.api -eq "VirtualProtect" } | Select-Object -First 1)
if ($virtualProtect.Count -ne 1 -or
    $virtualProtect[0].module -ne "kernel32.dll" -or
    $virtualProtect[0].apiCategory -ne "memory_protect" -or
    $virtualProtect[0].returnValue -ne "TRUE")
{
    throw "x86 VirtualProtect metadata or return evidence mismatch."
}

$newProtectArg = @($virtualProtect[0].arguments | Where-Object { $_.name -eq "flNewProtect" } | Select-Object -First 1)
$oldProtectArg = @($virtualProtect[0].arguments | Where-Object { $_.name -eq "lpflOldProtect" } | Select-Object -First 1)
if ($newProtectArg.Count -ne 1 -or
    $newProtectArg[0].decodeAlias -ne "memory_protection_flags" -or
    $newProtectArg[0].decodedValue -notmatch "PAGE_READONLY" -or
    $oldProtectArg.Count -ne 1 -or
    $oldProtectArg[0].decodeAlias -ne "dword_pointer" -or
    $oldProtectArg[0].captureTiming -ne "post" -or
    $oldProtectArg[0].decodeStatus -ne "decoded" -or
    $oldProtectArg[0].postCallValue -ne "0x00000004" -or
    $oldProtectArg[0].decodedValue -notmatch "PAGE_READWRITE")
{
    throw "x86 VirtualProtect did not include expected protection transition metadata: $($virtualProtect[0].arguments | ConvertTo-Json -Depth 8)"
}

$virtualQuery = @($memoryProtectionEvents | Where-Object { $_.api -eq "VirtualQuery" } | Select-Object -First 1)
if ($virtualQuery.Count -ne 1 -or
    $virtualQuery[0].module -ne "kernel32.dll" -or
    $virtualQuery[0].apiCategory -ne "memory_query" -or
    $virtualQuery[0].returnValue -notmatch "^[1-9][0-9]*$")
{
    throw "x86 VirtualQuery metadata or return evidence mismatch."
}

$queryBufferArg = @($virtualQuery[0].arguments | Where-Object { $_.name -eq "lpBuffer" } | Select-Object -First 1)
if ($queryBufferArg.Count -ne 1 -or
    $queryBufferArg[0].decodeAlias -ne "memory_basic_information_pointer" -or
    $queryBufferArg[0].captureTiming -ne "post" -or
    $queryBufferArg[0].decodeStatus -ne "decoded" -or
    $queryBufferArg[0].decodedValue -notmatch "base=0x" -or
    $queryBufferArg[0].decodedValue -notmatch "allocationBase=0x" -or
    $queryBufferArg[0].decodedValue -notmatch "regionSize=[1-9][0-9]*" -or
    $queryBufferArg[0].decodedValue -notmatch "MEM_COMMIT" -or
    $queryBufferArg[0].decodedValue -notmatch "PAGE_READONLY" -or
    $queryBufferArg[0].decodedValue -notmatch "MEM_PRIVATE")
{
    throw "x86 VirtualQuery did not include decoded MEMORY_BASIC_INFORMATION metadata: $($queryBufferArg | ConvertTo-Json -Depth 8)"
}

$virtualFree = @($memoryProtectionEvents | Where-Object { $_.api -eq "VirtualFree" } | Select-Object -First 1)
if ($virtualFree.Count -ne 1 -or
    $virtualFree[0].module -ne "kernel32.dll" -or
    $virtualFree[0].apiCategory -ne "memory_free" -or
    $virtualFree[0].returnValue -ne "TRUE")
{
    throw "x86 VirtualFree metadata or return evidence mismatch."
}

$freeTypeArg = @($virtualFree[0].arguments | Where-Object { $_.name -eq "dwFreeType" } | Select-Object -First 1)
if ($freeTypeArg.Count -ne 1 -or
    $freeTypeArg[0].decodeAlias -ne "memory_free_type" -or
    $freeTypeArg[0].decodedValue -notmatch "MEM_RELEASE")
{
    throw "x86 VirtualFree did not include expected free metadata: $($freeTypeArg | ConvertTo-Json -Depth 8)"
}

$memoryPayload = $memoryProtectionEvents | ConvertTo-Json -Depth 12
if ($memoryPayload -cmatch "VirtualAllocEx|VirtualFreeEx|VirtualProtectEx|ReadProcessMemory|WriteProcessMemory|CreateRemoteThread|QueueUserAPC|NtMapViewOfSection|MapViewOfFile|SECTION_|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 KERNEL32 memory events appear to expose remote-memory, injection, file/PE/hash, credential, or byte-preview evidence: $memoryPayload"
}

$fileMappingApis = @(
    "CreateFileMappingW",
    "OpenFileMappingW",
    "MapViewOfFile",
    "UnmapViewOfFile"
)

$fileMappingEvents = @($result.capturedEvents | Where-Object { $fileMappingApis -contains $_.api })
if ($fileMappingEvents.Count -lt $fileMappingApis.Count)
{
    throw "x86 capture did not include the selected KERNEL32 file-mapping API slice."
}

$createMapping = @($fileMappingEvents | Where-Object { $_.api -eq "CreateFileMappingW" } | Select-Object -First 1)
if ($createMapping.Count -ne 1 -or
    $createMapping[0].module -ne "kernel32.dll" -or
    $createMapping[0].apiCategory -ne "file_mapping_create" -or
    $createMapping[0].hookPolicy -ne "iat" -or
    $createMapping[0].coverageStatus -ne "smoke_verified" -or
    $createMapping[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 CreateFileMappingW metadata or return evidence mismatch."
}

$createMappingFileArg = @($createMapping[0].arguments | Where-Object { $_.name -eq "hFile" } | Select-Object -First 1)
$createMappingAttributesArg = @($createMapping[0].arguments | Where-Object { $_.name -eq "lpFileMappingAttributes" } | Select-Object -First 1)
$createMappingProtectArg = @($createMapping[0].arguments | Where-Object { $_.name -eq "flProtect" } | Select-Object -First 1)
$createMappingHighArg = @($createMapping[0].arguments | Where-Object { $_.name -eq "dwMaximumSizeHigh" } | Select-Object -First 1)
$createMappingLowArg = @($createMapping[0].arguments | Where-Object { $_.name -eq "dwMaximumSizeLow" } | Select-Object -First 1)
$createMappingNameArg = @($createMapping[0].arguments | Where-Object { $_.name -eq "lpName" } | Select-Object -First 1)
if ($createMappingFileArg.Count -ne 1 -or
    $createMappingFileArg[0].decodeAlias -ne "handle" -or
    $createMappingFileArg[0].decodedValue -notmatch "^0x[fF]+$" -or
    $createMappingAttributesArg.Count -ne 1 -or
    $createMappingAttributesArg[0].decodeAlias -ne "pointer" -or
    $createMappingAttributesArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]+$" -or
    $createMappingProtectArg.Count -ne 1 -or
    $createMappingProtectArg[0].decodeAlias -ne "file_mapping_protection_flags" -or
    $createMappingProtectArg[0].decodedValue -notmatch "PAGE_READWRITE" -or
    $createMappingHighArg.Count -ne 1 -or
    $createMappingHighArg[0].decodeAlias -ne "file_mapping_size_high" -or
    $createMappingHighArg[0].decodedValue -notmatch "^0" -or
    $createMappingLowArg.Count -ne 1 -or
    $createMappingLowArg[0].decodeAlias -ne "file_mapping_size_low" -or
    $createMappingLowArg[0].decodedValue -notmatch "4096" -or
    $createMappingLowArg[0].decodedValue -notmatch "0x00001000" -or
    $createMappingNameArg.Count -ne 1 -or
    $createMappingNameArg[0].decodeAlias -ne "file_mapping_name_pointer" -or
    $createMappingNameArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 CreateFileMappingW did not include expected mapping create metadata: $($createMapping[0].arguments | ConvertTo-Json -Depth 8)"
}

$openMapping = @($fileMappingEvents | Where-Object { $_.api -eq "OpenFileMappingW" } | Select-Object -First 1)
if ($openMapping.Count -ne 1 -or
    $openMapping[0].module -ne "kernel32.dll" -or
    $openMapping[0].apiCategory -ne "file_mapping_open" -or
    $openMapping[0].hookPolicy -ne "iat" -or
    $openMapping[0].coverageStatus -ne "smoke_verified" -or
    $openMapping[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 OpenFileMappingW metadata or return evidence mismatch."
}

$openMappingAccessArg = @($openMapping[0].arguments | Where-Object { $_.name -eq "dwDesiredAccess" } | Select-Object -First 1)
$openMappingInheritArg = @($openMapping[0].arguments | Where-Object { $_.name -eq "bInheritHandle" } | Select-Object -First 1)
$openMappingNameArg = @($openMapping[0].arguments | Where-Object { $_.name -eq "lpName" } | Select-Object -First 1)
if ($openMappingAccessArg.Count -ne 1 -or
    $openMappingAccessArg[0].decodeAlias -ne "file_mapping_access_flags" -or
    $openMappingAccessArg[0].decodedValue -notmatch "FILE_MAP_READ" -or
    $openMappingAccessArg[0].decodedValue -notmatch "FILE_MAP_WRITE" -or
    $openMappingInheritArg.Count -ne 1 -or
    $openMappingInheritArg[0].decodeAlias -ne "dword_value" -or
    $openMappingInheritArg[0].decodedValue -ne "FALSE" -or
    $openMappingNameArg.Count -ne 1 -or
    $openMappingNameArg[0].decodeAlias -ne "file_mapping_name_pointer" -or
    $openMappingNameArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 OpenFileMappingW did not include expected mapping open metadata: $($openMapping[0].arguments | ConvertTo-Json -Depth 8)"
}

$mapView = @($fileMappingEvents | Where-Object { $_.api -eq "MapViewOfFile" } | Select-Object -First 1)
if ($mapView.Count -ne 1 -or
    $mapView[0].module -ne "kernel32.dll" -or
    $mapView[0].apiCategory -ne "file_mapping_map_view" -or
    $mapView[0].hookPolicy -ne "iat" -or
    $mapView[0].coverageStatus -ne "smoke_verified" -or
    $mapView[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 MapViewOfFile metadata or return evidence mismatch."
}

$mapViewHandleArg = @($mapView[0].arguments | Where-Object { $_.name -eq "hFileMappingObject" } | Select-Object -First 1)
$mapViewAccessArg = @($mapView[0].arguments | Where-Object { $_.name -eq "dwDesiredAccess" } | Select-Object -First 1)
$mapViewOffsetHighArg = @($mapView[0].arguments | Where-Object { $_.name -eq "dwFileOffsetHigh" } | Select-Object -First 1)
$mapViewOffsetLowArg = @($mapView[0].arguments | Where-Object { $_.name -eq "dwFileOffsetLow" } | Select-Object -First 1)
$mapViewSizeArg = @($mapView[0].arguments | Where-Object { $_.name -eq "dwNumberOfBytesToMap" } | Select-Object -First 1)
if ($mapViewHandleArg.Count -ne 1 -or
    $mapViewHandleArg[0].decodeAlias -ne "handle" -or
    $mapViewHandleArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $mapViewAccessArg.Count -ne 1 -or
    $mapViewAccessArg[0].decodeAlias -ne "file_mapping_access_flags" -or
    $mapViewAccessArg[0].decodedValue -notmatch "FILE_MAP_WRITE" -or
    $mapViewOffsetHighArg.Count -ne 1 -or
    $mapViewOffsetHighArg[0].decodeAlias -ne "file_mapping_offset_high" -or
    $mapViewOffsetHighArg[0].decodedValue -notmatch "^0" -or
    $mapViewOffsetLowArg.Count -ne 1 -or
    $mapViewOffsetLowArg[0].decodeAlias -ne "file_mapping_offset_low" -or
    $mapViewOffsetLowArg[0].decodedValue -notmatch "^0" -or
    $mapViewSizeArg.Count -ne 1 -or
    $mapViewSizeArg[0].decodeAlias -ne "file_mapping_view_size" -or
    $mapViewSizeArg[0].decodedValue -ne "4096")
{
    throw "x86 MapViewOfFile did not include expected view metadata: $($mapView[0].arguments | ConvertTo-Json -Depth 8)"
}

$unmapView = @($fileMappingEvents | Where-Object { $_.api -eq "UnmapViewOfFile" } | Select-Object -First 1)
if ($unmapView.Count -ne 1 -or
    $unmapView[0].module -ne "kernel32.dll" -or
    $unmapView[0].apiCategory -ne "file_mapping_unmap_view" -or
    $unmapView[0].returnValue -ne "TRUE")
{
    throw "x86 UnmapViewOfFile metadata or return evidence mismatch."
}

$unmapViewBaseArg = @($unmapView[0].arguments | Where-Object { $_.name -eq "lpBaseAddress" } | Select-Object -First 1)
if ($unmapViewBaseArg.Count -ne 1 -or
    $unmapViewBaseArg[0].decodeAlias -ne "mapped_view_pointer" -or
    $unmapViewBaseArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 UnmapViewOfFile did not include expected base pointer metadata: $($unmapView[0].arguments | ConvertTo-Json -Depth 8)"
}

foreach ($fileMappingEvent in $fileMappingEvents)
{
    if (-not [string]::IsNullOrEmpty($fileMappingEvent.bufferPreview))
    {
        throw "x86 file-mapping event exposed bufferPreview: $($fileMappingEvent | ConvertTo-Json -Depth 8)"
    }
}

$fileMappingPayload = $fileMappingEvents | ConvertTo-Json -Depth 12
if ($fileMappingPayload -cmatch "KnMonFileMappingProbe|Global\\|Local\\|BaseNamedObjects|ObjectName|ObjectDirectory|ObjectManager|SecurityDescriptor|SECURITY_DESCRIPTOR|SID|ACL|TOKEN_|Privilege|Integrity|DuplicateHandle|NtMapViewOfSection|VirtualAllocEx|VirtualFreeEx|VirtualProtectEx|ReadProcessMemory|WriteProcessMemory|CreateRemoteThread|QueueUserAPC|NtQueueApcThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|TerminateThread|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 KERNEL32 file-mapping events appear to expose mapping-name, namespace, mapped memory, security, stack, injection, PE/file/hash, credential, or byte-preview evidence: $fileMappingPayload"
}

$identityApis = @(
    "GetCurrentProcess",
    "GetCurrentProcessId",
    "GetCurrentThread",
    "GetCurrentThreadId",
    "GetProcessId",
    "GetThreadId"
)

$identityEvents = @($result.capturedEvents | Where-Object { $identityApis -contains $_.api })
if ($identityEvents.Count -lt $identityApis.Count)
{
    throw "x86 capture did not include the selected KERNEL32 process/thread identity API slice."
}

$identityExpected = @(
    @{ Api = "GetCurrentProcess"; Family = "process"; Category = "process_identity"; Args = @() },
    @{ Api = "GetCurrentProcessId"; Family = "process"; Category = "process_identity"; Args = @() },
    @{ Api = "GetCurrentThread"; Family = "process"; Category = "thread_identity"; Args = @() },
    @{ Api = "GetCurrentThreadId"; Family = "process"; Category = "thread_identity"; Args = @() },
    @{ Api = "GetProcessId"; Family = "process"; Category = "process_identity"; Args = @(
        @{ Name = "Process"; Alias = "process_handle_value"; Timing = "pre" }
    ) },
    @{ Api = "GetThreadId"; Family = "process"; Category = "thread_identity"; Args = @(
        @{ Name = "Thread"; Alias = "thread_handle_value"; Timing = "pre" }
    ) }
)

foreach ($expectedIdentity in $identityExpected)
{
    $event = @($identityEvents | Where-Object { $_.api -eq $expectedIdentity.Api } | Select-Object -First 1)
    if ($event.Count -ne 1 -or
        $event[0].module -ne "kernel32.dll" -or
        $event[0].apiFamily -ne $expectedIdentity.Family -or
        $event[0].apiCategory -ne $expectedIdentity.Category -or
        $event[0].hookPolicy -ne "iat" -or
        $event[0].coverageStatus -ne "smoke_verified" -or
        $null -eq $event[0].durationUs -or
        $event[0].durationUs -lt 0)
    {
        throw "x86 $($expectedIdentity.Api) identity metadata mismatch: $($event | ConvertTo-Json -Depth 8)"
    }

    if (-not [string]::IsNullOrEmpty($event[0].bufferPreview))
    {
        throw "x86 $($expectedIdentity.Api) exposed bufferPreview: $($event[0] | ConvertTo-Json -Depth 8)"
    }

    if ($expectedIdentity.Args.Count -eq 0 -and @($event[0].arguments).Count -ne 0)
    {
        throw "x86 $($expectedIdentity.Api) unexpectedly captured arguments: $($event[0].arguments | ConvertTo-Json -Depth 8)"
    }

    foreach ($expectedArg in $expectedIdentity.Args)
    {
        $argument = @($event[0].arguments | Where-Object { $_.name -eq $expectedArg.Name } | Select-Object -First 1)
        if ($argument.Count -ne 1 -or
            $argument[0].decodeAlias -ne $expectedArg.Alias -or
            $argument[0].captureTiming -ne $expectedArg.Timing)
        {
            throw "x86 $($expectedIdentity.Api) $($expectedArg.Name) metadata mismatch: $($argument | ConvertTo-Json -Depth 8)"
        }
    }
}

$currentProcess = @($identityEvents | Where-Object { $_.api -eq "GetCurrentProcess" } | Select-Object -First 1)
if ($currentProcess.Count -ne 1 -or $currentProcess[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 GetCurrentProcess return evidence mismatch: $($currentProcess | ConvertTo-Json -Depth 8)"
}

$currentProcessIds = @($identityEvents |
    Where-Object { $_.api -eq "GetCurrentProcessId" } |
    ForEach-Object { ConvertFrom-DwordDecimalHex -Value $_.returnValue -Name "x86 GetCurrentProcessId returnValue" })
if ($currentProcessIds.Count -lt 1)
{
    throw "x86 GetCurrentProcessId returned no current PID values."
}

$processId = @($identityEvents | Where-Object { $_.api -eq "GetProcessId" } | Select-Object -First 1)
$handleProcessId = ConvertFrom-DwordDecimalHex -Value $processId[0].returnValue -Name "x86 GetProcessId returnValue"
if ($currentProcessIds -notcontains $handleProcessId)
{
    throw "x86 GetProcessId did not match captured current PID values: handle=$handleProcessId current=$($currentProcessIds -join ',')"
}

$processHandle = @($processId[0].arguments | Where-Object { $_.name -eq "Process" } | Select-Object -First 1)
if ($processHandle.Count -ne 1 -or $processHandle[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 GetProcessId did not capture a process handle value: $($processHandle | ConvertTo-Json -Depth 8)"
}

$currentThread = @($identityEvents | Where-Object { $_.api -eq "GetCurrentThread" } | Select-Object -First 1)
if ($currentThread.Count -ne 1 -or $currentThread[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 GetCurrentThread return evidence mismatch: $($currentThread | ConvertTo-Json -Depth 8)"
}

$currentThreadIds = @($identityEvents |
    Where-Object { $_.api -eq "GetCurrentThreadId" } |
    ForEach-Object { ConvertFrom-DwordDecimalHex -Value $_.returnValue -Name "x86 GetCurrentThreadId returnValue" })
if ($currentThreadIds.Count -lt 1)
{
    throw "x86 GetCurrentThreadId returned no current TID values."
}

$threadId = @($identityEvents | Where-Object { $_.api -eq "GetThreadId" } | Select-Object -First 1)
$handleThreadId = ConvertFrom-DwordDecimalHex -Value $threadId[0].returnValue -Name "x86 GetThreadId returnValue"
if ($currentThreadIds -notcontains $handleThreadId)
{
    throw "x86 GetThreadId did not match captured current TID values: handle=$handleThreadId current=$($currentThreadIds -join ',')"
}

$threadHandle = @($threadId[0].arguments | Where-Object { $_.name -eq "Thread" } | Select-Object -First 1)
if ($threadHandle.Count -ne 1 -or $threadHandle[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 GetThreadId did not capture a thread handle value: $($threadHandle | ConvertTo-Json -Depth 8)"
}

$identityPayload = $identityEvents | ConvertTo-Json -Depth 12
if ($identityPayload -cmatch "CommandLine|Environment|GetEnvironment|TOKEN_|TokenPrivileges|LookupAccount|SecurityDescriptor|SECURITY_DESCRIPTOR|\bSID\b|\bACL\b|Process32First|Process32Next|CreateToolhelp32Snapshot|EnumProcesses|OpenProcess|CreateProcessW|TerminateProcess|DuplicateHandle|OpenThread|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|VirtualFreeEx|VirtualProtectEx|CreateRemoteThread|QueueUserAPC|NtQueueApcThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 KERNEL32 process/thread identity events appear to expose command-line, environment, token, security, enumeration, remote-memory, remote-thread, stack, injection, PE/file/hash, credential, or byte-preview evidence: $identityPayload"
}

$handleApis = @(
    "GetStdHandle",
    "GetFileType",
    "GetHandleInformation",
    "SetHandleInformation"
)

$handleEvents = @($result.capturedEvents | Where-Object { $handleApis -contains $_.api })
if ($handleEvents.Count -lt $handleApis.Count)
{
    throw "x86 capture did not include the selected KERNEL32 handle metadata API slice."
}

$handleExpected = @(
    @{ Api = "GetStdHandle"; Family = "handle"; Category = "standard_handle"; Args = @(
        @{ Name = "nStdHandle"; Alias = "std_handle_selector"; Timing = "pre" }
    ) },
    @{ Api = "GetFileType"; Family = "handle"; Category = "handle_metadata"; Args = @(
        @{ Name = "hFile"; Alias = "handle"; Timing = "pre" }
    ) },
    @{ Api = "GetHandleInformation"; Family = "handle"; Category = "handle_metadata"; Args = @(
        @{ Name = "hObject"; Alias = "handle"; Timing = "pre" },
        @{ Name = "lpdwFlags"; Alias = "handle_information_flags_pointer"; Timing = "post" }
    ) },
    @{ Api = "SetHandleInformation"; Family = "handle"; Category = "handle_metadata"; Args = @(
        @{ Name = "hObject"; Alias = "handle"; Timing = "pre" },
        @{ Name = "dwMask"; Alias = "handle_information_mask"; Timing = "pre" },
        @{ Name = "dwFlags"; Alias = "handle_information_flags"; Timing = "pre" }
    ) }
)

foreach ($expectedHandle in $handleExpected)
{
    $event = @($handleEvents | Where-Object { $_.api -eq $expectedHandle.Api } | Select-Object -First 1)
    if ($event.Count -ne 1 -or
        $event[0].module -ne "kernel32.dll" -or
        $event[0].apiFamily -ne $expectedHandle.Family -or
        $event[0].apiCategory -ne $expectedHandle.Category -or
        $event[0].hookPolicy -ne "iat" -or
        $event[0].coverageStatus -ne "smoke_verified" -or
        $null -eq $event[0].durationUs -or
        $event[0].durationUs -lt 0)
    {
        throw "x86 $($expectedHandle.Api) handle metadata mismatch: $($event | ConvertTo-Json -Depth 8)"
    }

    if (-not [string]::IsNullOrEmpty($event[0].bufferPreview))
    {
        throw "x86 $($expectedHandle.Api) exposed bufferPreview: $($event[0] | ConvertTo-Json -Depth 8)"
    }

    foreach ($expectedArg in $expectedHandle.Args)
    {
        $argument = @($event[0].arguments | Where-Object { $_.name -eq $expectedArg.Name } | Select-Object -First 1)
        if ($argument.Count -ne 1 -or
            $argument[0].decodeAlias -ne $expectedArg.Alias -or
            $argument[0].captureTiming -ne $expectedArg.Timing)
        {
            throw "x86 $($expectedHandle.Api) $($expectedArg.Name) metadata mismatch: $($argument | ConvertTo-Json -Depth 8)"
        }
    }
}

$stdHandle = @($handleEvents | Where-Object { $_.api -eq "GetStdHandle" } | Select-Object -First 1)
if ($stdHandle.Count -ne 1 -or $stdHandle[0].returnValue -notmatch "^0x[0-9a-fA-F]+$")
{
    throw "x86 GetStdHandle return evidence mismatch: $($stdHandle | ConvertTo-Json -Depth 8)"
}

$stdSelector = @($stdHandle[0].arguments | Where-Object { $_.name -eq "nStdHandle" } | Select-Object -First 1)
if ($stdSelector.Count -ne 1 -or $stdSelector[0].decodedValue -notmatch "STD_OUTPUT_HANDLE")
{
    throw "x86 GetStdHandle did not capture STD_OUTPUT_HANDLE selector: $($stdSelector | ConvertTo-Json -Depth 8)"
}

$fileType = @($handleEvents | Where-Object { $_.api -eq "GetFileType" } | Select-Object -First 1)
if ($fileType.Count -ne 1 -or $fileType[0].returnValue -notmatch "FILE_TYPE_DISK")
{
    throw "x86 GetFileType did not return FILE_TYPE_DISK: $($fileType | ConvertTo-Json -Depth 8)"
}

$fileTypeHandle = @($fileType[0].arguments | Where-Object { $_.name -eq "hFile" } | Select-Object -First 1)
if ($fileTypeHandle.Count -ne 1 -or $fileTypeHandle[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 GetFileType did not capture a file handle: $($fileTypeHandle | ConvertTo-Json -Depth 8)"
}

$getHandleInfoEvents = @($handleEvents | Where-Object { $_.api -eq "GetHandleInformation" })
if ($getHandleInfoEvents.Count -lt 2)
{
    throw "x86 expected at least two GetHandleInformation events, got $($getHandleInfoEvents.Count)."
}

foreach ($event in $getHandleInfoEvents)
{
    if ($event.returnValue -ne "TRUE")
    {
        throw "x86 GetHandleInformation did not succeed: $($event | ConvertTo-Json -Depth 8)"
    }

    $handleArg = @($event.arguments | Where-Object { $_.name -eq "hObject" } | Select-Object -First 1)
    $flagsArg = @($event.arguments | Where-Object { $_.name -eq "lpdwFlags" } | Select-Object -First 1)
    if ($handleArg.Count -ne 1 -or
        $handleArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
        $flagsArg.Count -ne 1 -or
        $flagsArg[0].rawValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
        $flagsArg[0].decodeStatus -ne "decoded" -or
        $flagsArg[0].decodedValue -notmatch "0x[0-9a-fA-F]{8}")
    {
        throw "x86 GetHandleInformation handle/flags evidence mismatch: $($event | ConvertTo-Json -Depth 8)"
    }
}

$setHandleInfo = @($handleEvents | Where-Object { $_.api -eq "SetHandleInformation" } | Select-Object -First 1)
if ($setHandleInfo.Count -ne 1 -or $setHandleInfo[0].returnValue -ne "TRUE")
{
    throw "x86 SetHandleInformation did not succeed: $($setHandleInfo | ConvertTo-Json -Depth 8)"
}

$setHandle = @($setHandleInfo[0].arguments | Where-Object { $_.name -eq "hObject" } | Select-Object -First 1)
$mask = @($setHandleInfo[0].arguments | Where-Object { $_.name -eq "dwMask" } | Select-Object -First 1)
$flags = @($setHandleInfo[0].arguments | Where-Object { $_.name -eq "dwFlags" } | Select-Object -First 1)
if ($setHandle.Count -ne 1 -or
    $setHandle[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $mask.Count -ne 1 -or
    $mask[0].decodedValue -notmatch "HANDLE_FLAG_INHERIT" -or
    $flags.Count -ne 1 -or
    $flags[0].decodedValue -notmatch "none")
{
    throw "x86 SetHandleInformation metadata mismatch: $($setHandleInfo | ConvertTo-Json -Depth 8)"
}

$handlePayload = $handleEvents | ConvertTo-Json -Depth 12
if ($handlePayload -cmatch "ObjectName|ObjectType|NtQueryObject|SystemHandle|SystemExtendedHandle|DuplicateHandle|SecurityDescriptor|SECURITY_DESCRIPTOR|\bSID\b|\bACL\b|TOKEN_|TokenPrivileges|LookupAccount|CommandLine|Environment|GetEnvironment|Process32First|Process32Next|CreateToolhelp32Snapshot|EnumProcesses|OpenProcess|CreateProcessW|TerminateProcess|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|VirtualFreeEx|VirtualProtectEx|CreateRemoteThread|QueueUserAPC|NtQueueApcThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 KERNEL32 handle metadata events appear to expose object-name, security, duplication, payload, command-line, environment, remote-memory, remote-thread, stack, injection, PE/file/hash, credential, or byte-preview evidence: $handlePayload"
}

$fileMetadataApis = @(
    "GetFileSizeEx",
    "GetFileTime",
    "GetFileInformationByHandle"
)

$fileMetadataEvents = @($result.capturedEvents | Where-Object { $fileMetadataApis -contains $_.api })
if ($fileMetadataEvents.Count -lt $fileMetadataApis.Count)
{
    throw "x86 capture did not include the selected KERNEL32 file metadata API slice."
}

$fileMetadataExpected = @(
    @{ Api = "GetFileSizeEx"; Family = "file"; Category = "file_size_query"; Args = @(
        @{ Name = "hFile"; Alias = "handle"; Timing = "pre" },
        @{ Name = "lpFileSize"; Alias = "file_size_pointer"; Timing = "post" }
    ) },
    @{ Api = "GetFileTime"; Family = "file"; Category = "file_time_query"; Args = @(
        @{ Name = "hFile"; Alias = "handle"; Timing = "pre" },
        @{ Name = "lpCreationTime"; Alias = "file_time_pointer"; Timing = "post" },
        @{ Name = "lpLastAccessTime"; Alias = "file_time_pointer"; Timing = "post" },
        @{ Name = "lpLastWriteTime"; Alias = "file_time_pointer"; Timing = "post" }
    ) },
    @{ Api = "GetFileInformationByHandle"; Family = "file"; Category = "file_information_query"; Args = @(
        @{ Name = "hFile"; Alias = "handle"; Timing = "pre" },
        @{ Name = "lpFileInformation"; Alias = "by_handle_file_information_pointer"; Timing = "post" }
    ) }
)

foreach ($expectedFileMetadata in $fileMetadataExpected)
{
    $event = @($fileMetadataEvents | Where-Object { $_.api -eq $expectedFileMetadata.Api } | Select-Object -First 1)
    if ($event.Count -ne 1 -or
        $event[0].module -ne "kernel32.dll" -or
        $event[0].apiFamily -ne $expectedFileMetadata.Family -or
        $event[0].apiCategory -ne $expectedFileMetadata.Category -or
        $event[0].hookPolicy -ne "iat" -or
        $event[0].coverageStatus -ne "smoke_verified" -or
        $null -eq $event[0].durationUs -or
        $event[0].durationUs -lt 0)
    {
        throw "x86 $($expectedFileMetadata.Api) file metadata mismatch: $($event | ConvertTo-Json -Depth 8)"
    }

    if (-not [string]::IsNullOrEmpty($event[0].bufferPreview))
    {
        throw "x86 $($expectedFileMetadata.Api) exposed bufferPreview: $($event[0] | ConvertTo-Json -Depth 8)"
    }

    foreach ($expectedArg in $expectedFileMetadata.Args)
    {
        $argument = @($event[0].arguments | Where-Object { $_.name -eq $expectedArg.Name } | Select-Object -First 1)
        if ($argument.Count -ne 1 -or
            $argument[0].decodeAlias -ne $expectedArg.Alias -or
            $argument[0].captureTiming -ne $expectedArg.Timing)
        {
            throw "x86 $($expectedFileMetadata.Api) $($expectedArg.Name) metadata mismatch: $($argument | ConvertTo-Json -Depth 8)"
        }
    }
}

$fileSizeEx = @($fileMetadataEvents | Where-Object { $_.api -eq "GetFileSizeEx" } | Select-Object -First 1)
if ($fileSizeEx.Count -ne 1 -or $fileSizeEx[0].returnValue -ne "TRUE")
{
    throw "x86 GetFileSizeEx did not succeed: $($fileSizeEx | ConvertTo-Json -Depth 8)"
}

$fileSizeHandle = @($fileSizeEx[0].arguments | Where-Object { $_.name -eq "hFile" } | Select-Object -First 1)
$fileSizePointer = @($fileSizeEx[0].arguments | Where-Object { $_.name -eq "lpFileSize" } | Select-Object -First 1)
if ($fileSizeHandle.Count -ne 1 -or
    $fileSizeHandle[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $fileSizePointer.Count -ne 1 -or
    $fileSizePointer[0].rawValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $fileSizePointer[0].decodeStatus -ne "decoded")
{
    throw "x86 GetFileSizeEx handle/size evidence mismatch: $($fileSizeEx | ConvertTo-Json -Depth 8)"
}

$fileSizeValue = ConvertFrom-UInt64DecimalHex -Value $fileSizePointer[0].decodedValue -Name "x86 GetFileSizeEx lpFileSize decodedValue"

$fileTime = @($fileMetadataEvents | Where-Object { $_.api -eq "GetFileTime" } | Select-Object -First 1)
if ($fileTime.Count -ne 1 -or $fileTime[0].returnValue -ne "TRUE")
{
    throw "x86 GetFileTime did not succeed: $($fileTime | ConvertTo-Json -Depth 8)"
}

$fileTimeHandle = @($fileTime[0].arguments | Where-Object { $_.name -eq "hFile" } | Select-Object -First 1)
if ($fileTimeHandle.Count -ne 1 -or $fileTimeHandle[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 GetFileTime did not capture a file handle: $($fileTime | ConvertTo-Json -Depth 8)"
}

foreach ($timeArgumentName in @("lpCreationTime", "lpLastAccessTime", "lpLastWriteTime"))
{
    $timeArgument = @($fileTime[0].arguments | Where-Object { $_.name -eq $timeArgumentName } | Select-Object -First 1)
    if ($timeArgument.Count -ne 1 -or
        $timeArgument[0].rawValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
        $timeArgument[0].decodeStatus -ne "decoded" -or
        $timeArgument[0].decodedValue -notmatch "^[0-9]+$")
    {
        throw "x86 GetFileTime $timeArgumentName evidence mismatch: $($timeArgument | ConvertTo-Json -Depth 8)"
    }
}

$fileInfo = @($fileMetadataEvents | Where-Object { $_.api -eq "GetFileInformationByHandle" } | Select-Object -First 1)
if ($fileInfo.Count -ne 1 -or $fileInfo[0].returnValue -ne "TRUE")
{
    throw "x86 GetFileInformationByHandle did not succeed: $($fileInfo | ConvertTo-Json -Depth 8)"
}

$fileInfoHandle = @($fileInfo[0].arguments | Where-Object { $_.name -eq "hFile" } | Select-Object -First 1)
$fileInfoPointer = @($fileInfo[0].arguments | Where-Object { $_.name -eq "lpFileInformation" } | Select-Object -First 1)
if ($fileInfoHandle.Count -ne 1 -or
    $fileInfoHandle[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $fileInfoPointer.Count -ne 1 -or
    $fileInfoPointer[0].rawValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $fileInfoPointer[0].decodeStatus -ne "decoded")
{
    throw "x86 GetFileInformationByHandle handle/info evidence mismatch: $($fileInfo | ConvertTo-Json -Depth 8)"
}

$fileInfoSizeMatch = [regex]::Match($fileInfoPointer[0].decodedValue, "nFileSize=([0-9]+) \(0x[0-9a-fA-F]{16}\)")
if ($fileInfoPointer[0].decodedValue -notmatch "dwFileAttributes=0x[0-9a-fA-F]{8}" -or
    $fileInfoPointer[0].decodedValue -notmatch "dwVolumeSerialNumber=[0-9]+ \(0x[0-9a-fA-F]{8}\)" -or
    -not $fileInfoSizeMatch.Success -or
    $fileInfoPointer[0].decodedValue -notmatch "nNumberOfLinks=[0-9]+ \(0x[0-9a-fA-F]{8}\)" -or
    $fileInfoPointer[0].decodedValue -notmatch "nFileIndex=[0-9]+ \(0x[0-9a-fA-F]{16}\)" -or
    $fileInfoPointer[0].decodedValue -notmatch "ftCreationTime=[0-9]+" -or
    $fileInfoPointer[0].decodedValue -notmatch "ftLastAccessTime=[0-9]+" -or
    $fileInfoPointer[0].decodedValue -notmatch "ftLastWriteTime=[0-9]+")
{
    throw "x86 GetFileInformationByHandle scalar metadata missing: $($fileInfoPointer | ConvertTo-Json -Depth 8)"
}

$fileInfoSize = [UInt64]$fileInfoSizeMatch.Groups[1].Value
if ($fileSizeValue -ne $fileInfoSize)
{
    throw "x86 file size mismatch between GetFileSizeEx and GetFileInformationByHandle: sizeEx=$fileSizeValue info=$fileInfoSize"
}

$fileMetadataPayload = $fileMetadataEvents | ConvertTo-Json -Depth 12
if ($fileMetadataPayload -cmatch "GetFinalPathNameByHandle|GetFileInformationByHandleEx|FileNameInfo|FileStreamInfo|FileIdInfo|FileIdBothDirectoryInfo|FindFirstFile|FindNextFile|DirectoryListing|ObjectName|ObjectType|NtQueryObject|SystemHandle|SystemExtendedHandle|DuplicateHandle|SecurityDescriptor|SECURITY_DESCRIPTOR|\bSID\b|\bACL\b|TOKEN_|TokenPrivileges|LookupAccount|CommandLine|Environment|GetEnvironment|Process32First|Process32Next|CreateToolhelp32Snapshot|EnumProcesses|OpenProcess|CreateProcessW|TerminateProcess|ReadFile|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|VirtualFreeEx|VirtualProtectEx|CreateRemoteThread|QueueUserAPC|NtQueueApcThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Disassembly|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 KERNEL32 file metadata events appear to expose path/name/content, object-name, security, duplication, command-line, environment, remote-memory, remote-thread, stack, injection, PE/file/hash, credential, or byte-preview evidence: $fileMetadataPayload"
}

$moduleApis = @(
    "GetModuleHandleW",
    "GetModuleHandleExW",
    "GetModuleFileNameW",
    "FreeLibrary"
)

$moduleEvents = @($result.capturedEvents | Where-Object { $moduleApis -contains $_.api })
if ($moduleEvents.Count -lt $moduleApis.Count)
{
    throw "x86 capture did not include the selected KERNEL32 module lifecycle API slice."
}

$moduleExpected = @(
    @{ Api = "GetModuleHandleW"; Family = "module"; Category = "module_lookup"; Args = @(
        @{ Name = "lpModuleName"; Alias = "module_lookup_name"; Timing = "pre" }
    ) },
    @{ Api = "GetModuleHandleExW"; Family = "module"; Category = "module_lookup"; Args = @(
        @{ Name = "dwFlags"; Alias = "get_module_handle_ex_flags"; Timing = "pre" },
        @{ Name = "lpModuleName"; Alias = "module_lookup_name"; Timing = "pre" },
        @{ Name = "phModule"; Alias = "module_handle_pointer"; Timing = "post" }
    ) },
    @{ Api = "GetModuleFileNameW"; Family = "module"; Category = "module_path"; Args = @(
        @{ Name = "hModule"; Alias = "module_handle"; Timing = "pre" },
        @{ Name = "lpFilename"; Alias = "module_file_name_buffer_pointer"; Timing = "post" },
        @{ Name = "nSize"; Alias = "byte_count"; Timing = "pre" }
    ) },
    @{ Api = "FreeLibrary"; Family = "module"; Category = "module_lifecycle"; Args = @(
        @{ Name = "hLibModule"; Alias = "module_handle"; Timing = "pre" }
    ) }
)

foreach ($expectedModule in $moduleExpected)
{
    $events = @($moduleEvents | Where-Object { $_.api -eq $expectedModule.Api })
    if ($events.Count -lt 1)
    {
        throw "x86 capture did not include $($expectedModule.Api)."
    }

    foreach ($event in $events)
    {
        if ($event.module -ne "kernel32.dll" -or
            $event.apiFamily -ne $expectedModule.Family -or
            $event.apiCategory -ne $expectedModule.Category -or
            $event.hookPolicy -ne "iat" -or
            $event.coverageStatus -ne "smoke_verified" -or
            $null -eq $event.durationUs -or
            $event.durationUs -lt 0)
        {
            throw "x86 $($expectedModule.Api) module lifecycle metadata mismatch: $($event | ConvertTo-Json -Depth 8)"
        }

        if (-not [string]::IsNullOrEmpty($event.bufferPreview))
        {
            throw "x86 $($expectedModule.Api) exposed bufferPreview: $($event | ConvertTo-Json -Depth 8)"
        }

        foreach ($expectedArg in $expectedModule.Args)
        {
            $argument = @($event.arguments | Where-Object { $_.name -eq $expectedArg.Name } | Select-Object -First 1)
            if ($argument.Count -ne 1 -or
                $argument[0].decodeAlias -ne $expectedArg.Alias -or
                $argument[0].captureTiming -ne $expectedArg.Timing)
            {
                throw "x86 $($expectedModule.Api) $($expectedArg.Name) metadata mismatch: $($argument | ConvertTo-Json -Depth 8)"
            }
        }
    }
}

$moduleHandle = @($moduleEvents | Where-Object {
    $argument = @($_.arguments | Where-Object { $_.name -eq "lpModuleName" } | Select-Object -First 1)
    $_.api -eq "GetModuleHandleW" -and $argument.Count -eq 1 -and $argument[0].decodedValue -ieq "version.dll"
} | Select-Object -First 1)
if ($moduleHandle.Count -ne 1 -or $moduleHandle[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 GetModuleHandleW did not capture version.dll lookup: $($moduleHandle | ConvertTo-Json -Depth 8)"
}

$moduleHandleEx = @($moduleEvents | Where-Object {
    $argument = @($_.arguments | Where-Object { $_.name -eq "lpModuleName" } | Select-Object -First 1)
    $_.api -eq "GetModuleHandleExW" -and $argument.Count -eq 1 -and $argument[0].decodedValue -ieq "version.dll"
} | Select-Object -First 1)
if ($moduleHandleEx.Count -ne 1 -or $moduleHandleEx[0].returnValue -ne "TRUE")
{
    throw "x86 GetModuleHandleExW did not capture successful version.dll lookup: $($moduleHandleEx | ConvertTo-Json -Depth 8)"
}

$moduleFlags = @($moduleHandleEx[0].arguments | Where-Object { $_.name -eq "dwFlags" } | Select-Object -First 1)
$modulePointer = @($moduleHandleEx[0].arguments | Where-Object { $_.name -eq "phModule" } | Select-Object -First 1)
if ($moduleFlags.Count -ne 1 -or
    $moduleFlags[0].decodedValue -notmatch "GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT" -or
    $modulePointer.Count -ne 1 -or
    $modulePointer[0].rawValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $modulePointer[0].decodeStatus -ne "decoded" -or
    $modulePointer[0].decodedValue -ne $moduleHandle[0].returnValue)
{
    throw "x86 GetModuleHandleExW handle evidence mismatch: $($moduleHandleEx | ConvertTo-Json -Depth 8)"
}

$moduleFileName = @($moduleEvents | Where-Object {
    $argument = @($_.arguments | Where-Object { $_.name -eq "hModule" } | Select-Object -First 1)
    $_.api -eq "GetModuleFileNameW" -and $argument.Count -eq 1 -and $argument[0].decodedValue -eq $moduleHandle[0].returnValue
} | Select-Object -First 1)
if ($moduleFileName.Count -ne 1 -or $moduleFileName[0].returnValue -notmatch "^[1-9][0-9]* \(0x[0-9a-fA-F]{8}\)$")
{
    throw "x86 GetModuleFileNameW did not capture positive version.dll path length: $($moduleFileName | ConvertTo-Json -Depth 8)"
}

$fileName = @($moduleFileName[0].arguments | Where-Object { $_.name -eq "lpFilename" } | Select-Object -First 1)
$fileNameSize = @($moduleFileName[0].arguments | Where-Object { $_.name -eq "nSize" } | Select-Object -First 1)
if ($fileName.Count -ne 1 -or
    $fileName[0].rawValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $fileName[0].decodeStatus -ne "decoded" -or
    $fileName[0].decodedValue -notmatch "(?i)version\.dll" -or
    $fileNameSize.Count -ne 1 -or
    $fileNameSize[0].decodedValue -notmatch "^260 ")
{
    throw "x86 GetModuleFileNameW path evidence mismatch: $($moduleFileName | ConvertTo-Json -Depth 8)"
}

$freeLibrary = @($moduleEvents | Where-Object {
    $argument = @($_.arguments | Where-Object { $_.name -eq "hLibModule" } | Select-Object -First 1)
    $_.api -eq "FreeLibrary" -and $argument.Count -eq 1 -and $argument[0].decodedValue -eq $moduleHandle[0].returnValue
} | Select-Object -First 1)
if ($freeLibrary.Count -ne 1 -or $freeLibrary[0].returnValue -ne "TRUE")
{
    throw "x86 FreeLibrary did not release the deterministic version.dll handle: $($freeLibrary | ConvertTo-Json -Depth 8)"
}

$modulePayload = $moduleEvents | ConvertTo-Json -Depth 12
if ($modulePayload -cmatch "IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SectionHeader|CodeBytes|Disassembly|SHA256|SHA1|MD5|Authenticode|WinVerifyTrust|CertVerify|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b|CreateToolhelp32Snapshot|Module32First|Module32Next|EnumProcesses|PEB|LDR_DATA_TABLE_ENTRY|InLoadOrderModuleList|CommandLine|Environment|GetEnvironment|TOKEN_|TokenPrivileges|LookupAccount|SecurityDescriptor|SECURITY_DESCRIPTOR|\bSID\b|\bACL\b|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|VirtualFreeEx|VirtualProtectEx|CreateRemoteThread|QueueUserAPC|NtQueueApcThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential")
{
    throw "x86 KERNEL32 module lifecycle events appear to expose module-memory, PE/hash/signature, enumeration, command-line, environment, token/security, remote-memory, remote-thread, stack, injection, credential, or byte-preview evidence: $modulePayload"
}

$threadEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "thread" })
if ($threadEvents.Count -lt 4)
{
    throw "x86 capture did not include the selected KERNEL32 thread lifecycle API slice."
}

$openThread = @($threadEvents | Where-Object { $_.api -eq "OpenThread" } | Select-Object -First 1)
if ($openThread.Count -ne 1 -or
    $openThread[0].module -ne "kernel32.dll" -or
    $openThread[0].apiCategory -ne "thread_open" -or
    $openThread[0].hookPolicy -ne "iat" -or
    $openThread[0].coverageStatus -ne "smoke_verified" -or
    $openThread[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 OpenThread metadata or return evidence mismatch."
}

$desiredAccessArg = @($openThread[0].arguments | Where-Object { $_.name -eq "dwDesiredAccess" } | Select-Object -First 1)
$inheritHandleArg = @($openThread[0].arguments | Where-Object { $_.name -eq "bInheritHandle" } | Select-Object -First 1)
$threadIdArg = @($openThread[0].arguments | Where-Object { $_.name -eq "dwThreadId" } | Select-Object -First 1)
if ($desiredAccessArg.Count -ne 1 -or
    $desiredAccessArg[0].decodeAlias -ne "thread_access_flags" -or
    $desiredAccessArg[0].decodedValue -notmatch "THREAD_QUERY_LIMITED_INFORMATION" -or
    $desiredAccessArg[0].decodedValue -notmatch "SYNCHRONIZE" -or
    $inheritHandleArg.Count -ne 1 -or
    $inheritHandleArg[0].decodeAlias -ne "dword_value" -or
    $inheritHandleArg[0].decodedValue -ne "FALSE" -or
    $threadIdArg.Count -ne 1 -or
    $threadIdArg[0].decodeAlias -ne "dword_value" -or
    $threadIdArg[0].postCallValue -notmatch "^[1-9][0-9]*$")
{
    throw "x86 OpenThread did not include expected thread access metadata: $($openThread[0].arguments | ConvertTo-Json -Depth 8)"
}

$threadId = $threadIdArg[0].postCallValue
$createThread = @($threadEvents | Where-Object {
    if ($_.api -ne "CreateThread")
    {
        $false
    }
    else
    {
        $argument = @($_.arguments | Where-Object { $_.name -eq "lpThreadId" } | Select-Object -First 1)
        $argument.Count -eq 1 -and $argument[0].postCallValue -eq $threadId
    }
} | Select-Object -First 1)
if ($createThread.Count -ne 1 -or
    $createThread[0].module -ne "kernel32.dll" -or
    $createThread[0].apiCategory -ne "thread_create" -or
    $createThread[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 CreateThread metadata or return evidence mismatch for thread ID $threadId."
}

$threadAttributesArg = @($createThread[0].arguments | Where-Object { $_.name -eq "lpThreadAttributes" } | Select-Object -First 1)
$stackSizeArg = @($createThread[0].arguments | Where-Object { $_.name -eq "dwStackSize" } | Select-Object -First 1)
$startAddressArg = @($createThread[0].arguments | Where-Object { $_.name -eq "lpStartAddress" } | Select-Object -First 1)
$parameterArg = @($createThread[0].arguments | Where-Object { $_.name -eq "lpParameter" } | Select-Object -First 1)
$creationFlagsArg = @($createThread[0].arguments | Where-Object { $_.name -eq "dwCreationFlags" } | Select-Object -First 1)
$threadIdOutArg = @($createThread[0].arguments | Where-Object { $_.name -eq "lpThreadId" } | Select-Object -First 1)
if ($threadAttributesArg.Count -ne 1 -or
    $threadAttributesArg[0].decodeAlias -ne "security_attributes" -or
    $stackSizeArg.Count -ne 1 -or
    $stackSizeArg[0].decodeAlias -ne "byte_count" -or
    $startAddressArg.Count -ne 1 -or
    $startAddressArg[0].decodeAlias -ne "thread_start_routine_pointer" -or
    $startAddressArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $parameterArg.Count -ne 1 -or
    $parameterArg[0].decodeAlias -ne "pointer" -or
    $parameterArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $creationFlagsArg.Count -ne 1 -or
    $creationFlagsArg[0].decodeAlias -ne "thread_creation_flags" -or
    $creationFlagsArg[0].decodedValue -notmatch "none" -or
    $threadIdOutArg.Count -ne 1 -or
    $threadIdOutArg[0].decodeAlias -ne "thread_id_pointer" -or
    $threadIdOutArg[0].captureTiming -ne "post" -or
    $threadIdOutArg[0].decodeStatus -ne "decoded" -or
    $threadIdOutArg[0].postCallValue -ne $threadId -or
    $threadIdOutArg[0].decodedValue -notmatch "value=$threadId")
{
    throw "x86 CreateThread did not include expected thread creation metadata: $($createThread[0].arguments | ConvertTo-Json -Depth 8)"
}

$waitThread = @($threadEvents | Where-Object {
    if ($_.api -ne "WaitForSingleObject" -or $_.returnValue -notmatch "WAIT_OBJECT_0")
    {
        $false
    }
    else
    {
        $argument = @($_.arguments | Where-Object { $_.name -eq "hHandle" } | Select-Object -First 1)
        $argument.Count -eq 1 -and $argument[0].rawValue -eq $createThread[0].returnValue
    }
} | Select-Object -First 1)
if ($waitThread.Count -ne 1 -or
    $waitThread[0].module -ne "kernel32.dll" -or
    $waitThread[0].apiCategory -ne "thread_wait")
{
    throw "x86 WaitForSingleObject metadata or handle evidence mismatch."
}

$waitHandleArg = @($waitThread[0].arguments | Where-Object { $_.name -eq "hHandle" } | Select-Object -First 1)
$timeoutArg = @($waitThread[0].arguments | Where-Object { $_.name -eq "dwMilliseconds" } | Select-Object -First 1)
if ($waitHandleArg.Count -ne 1 -or
    $waitHandleArg[0].decodeAlias -ne "handle" -or
    $timeoutArg.Count -ne 1 -or
    $timeoutArg[0].decodeAlias -ne "wait_timeout_ms" -or
    $timeoutArg[0].decodedValue -notmatch "INFINITE")
{
    throw "x86 WaitForSingleObject did not include expected wait metadata: $($waitThread[0].arguments | ConvertTo-Json -Depth 8)"
}

$exitThread = @($threadEvents | Where-Object {
    if ($_.api -ne "GetExitCodeThread" -or $_.returnValue -ne "TRUE")
    {
        $false
    }
    else
    {
        $handleArgument = @($_.arguments | Where-Object { $_.name -eq "hThread" } | Select-Object -First 1)
        $exitArgument = @($_.arguments | Where-Object { $_.name -eq "lpExitCode" } | Select-Object -First 1)
        $handleArgument.Count -eq 1 -and
            $exitArgument.Count -eq 1 -and
            $handleArgument[0].rawValue -eq $createThread[0].returnValue -and
            $exitArgument[0].postCallValue -eq "42"
    }
} | Select-Object -First 1)
if ($exitThread.Count -ne 1 -or
    $exitThread[0].module -ne "kernel32.dll" -or
    $exitThread[0].apiCategory -ne "thread_exit_code")
{
    throw "x86 GetExitCodeThread metadata or return evidence mismatch."
}

$exitHandleArg = @($exitThread[0].arguments | Where-Object { $_.name -eq "hThread" } | Select-Object -First 1)
$exitCodeArg = @($exitThread[0].arguments | Where-Object { $_.name -eq "lpExitCode" } | Select-Object -First 1)
if ($exitHandleArg.Count -ne 1 -or
    $exitHandleArg[0].decodeAlias -ne "handle" -or
    $exitCodeArg.Count -ne 1 -or
    $exitCodeArg[0].decodeAlias -ne "thread_exit_code_pointer" -or
    $exitCodeArg[0].captureTiming -ne "post" -or
    $exitCodeArg[0].decodeStatus -ne "decoded" -or
    $exitCodeArg[0].postCallValue -ne "42" -or
    $exitCodeArg[0].decodedValue -notmatch "value=42" -or
    $exitCodeArg[0].decodedValue -notmatch "0x0000002a")
{
    throw "x86 GetExitCodeThread did not include decoded exit-code metadata: $($exitThread[0].arguments | ConvertTo-Json -Depth 8)"
}

foreach ($threadEvent in $threadEvents)
{
    if (-not [string]::IsNullOrEmpty($threadEvent.bufferPreview))
    {
        throw "x86 thread lifecycle event exposed bufferPreview: $($threadEvent | ConvertTo-Json -Depth 8)"
    }
}

$threadPayload = $threadEvents | ConvertTo-Json -Depth 12
if ($threadPayload -cmatch "CreateRemoteThread|QueueUserAPC|NtQueueApcThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|TerminateThread|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Disassembly|VirtualAllocEx|WriteProcessMemory|ReadProcessMemory|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 KERNEL32 thread lifecycle events appear to expose remote-thread, APC, context, stack, injection, PE/file/hash, credential, or byte-preview evidence: $threadPayload"
}

$syncEvents = @($result.capturedEvents | Where-Object { $_.apiFamily -eq "synchronization" })
if ($syncEvents.Count -lt 5)
{
    throw "x86 capture did not include the selected KERNEL32 event synchronization API slice."
}

$createEvent = @($syncEvents | Where-Object { $_.api -eq "CreateEventW" } | Select-Object -First 1)
if ($createEvent.Count -ne 1 -or
    $createEvent[0].module -ne "kernel32.dll" -or
    $createEvent[0].apiCategory -ne "event_create" -or
    $createEvent[0].hookPolicy -ne "iat" -or
    $createEvent[0].coverageStatus -ne "smoke_verified" -or
    $createEvent[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 CreateEventW metadata or return evidence mismatch."
}

$createEventAttributesArg = @($createEvent[0].arguments | Where-Object { $_.name -eq "lpEventAttributes" } | Select-Object -First 1)
$manualResetArg = @($createEvent[0].arguments | Where-Object { $_.name -eq "bManualReset" } | Select-Object -First 1)
$initialStateArg = @($createEvent[0].arguments | Where-Object { $_.name -eq "bInitialState" } | Select-Object -First 1)
$createNameArg = @($createEvent[0].arguments | Where-Object { $_.name -eq "lpName" } | Select-Object -First 1)
if ($createEventAttributesArg.Count -ne 1 -or
    $createEventAttributesArg[0].decodeAlias -ne "pointer" -or
    $createEventAttributesArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]+$" -or
    $manualResetArg.Count -ne 1 -or
    $manualResetArg[0].decodeAlias -ne "event_manual_reset_bool" -or
    $manualResetArg[0].decodedValue -ne "TRUE" -or
    $initialStateArg.Count -ne 1 -or
    $initialStateArg[0].decodeAlias -ne "event_initial_state_bool" -or
    $initialStateArg[0].decodedValue -ne "FALSE" -or
    $createNameArg.Count -ne 1 -or
    $createNameArg[0].decodeAlias -ne "event_name_pointer" -or
    $createNameArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 CreateEventW did not include expected event create metadata: $($createEvent[0].arguments | ConvertTo-Json -Depth 8)"
}

$openEvent = @($syncEvents | Where-Object { $_.api -eq "OpenEventW" } | Select-Object -First 1)
if ($openEvent.Count -ne 1 -or
    $openEvent[0].module -ne "kernel32.dll" -or
    $openEvent[0].apiCategory -ne "event_open" -or
    $openEvent[0].hookPolicy -ne "iat" -or
    $openEvent[0].coverageStatus -ne "smoke_verified" -or
    $openEvent[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 OpenEventW metadata or return evidence mismatch."
}

$eventAccessArg = @($openEvent[0].arguments | Where-Object { $_.name -eq "dwDesiredAccess" } | Select-Object -First 1)
$eventInheritArg = @($openEvent[0].arguments | Where-Object { $_.name -eq "bInheritHandle" } | Select-Object -First 1)
$openNameArg = @($openEvent[0].arguments | Where-Object { $_.name -eq "lpName" } | Select-Object -First 1)
if ($eventAccessArg.Count -ne 1 -or
    $eventAccessArg[0].decodeAlias -ne "event_access_flags" -or
    $eventAccessArg[0].decodedValue -notmatch "EVENT_MODIFY_STATE" -or
    $eventAccessArg[0].decodedValue -notmatch "SYNCHRONIZE" -or
    $eventInheritArg.Count -ne 1 -or
    $eventInheritArg[0].decodeAlias -ne "dword_value" -or
    $eventInheritArg[0].decodedValue -ne "FALSE" -or
    $openNameArg.Count -ne 1 -or
    $openNameArg[0].decodeAlias -ne "event_name_pointer" -or
    $openNameArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 OpenEventW did not include expected event open metadata: $($openEvent[0].arguments | ConvertTo-Json -Depth 8)"
}

$setEvent = @($syncEvents | Where-Object { $_.api -eq "SetEvent" } | Select-Object -First 1)
if ($setEvent.Count -ne 1 -or
    $setEvent[0].module -ne "kernel32.dll" -or
    $setEvent[0].apiCategory -ne "event_set" -or
    $setEvent[0].returnValue -ne "TRUE")
{
    throw "x86 SetEvent metadata or return evidence mismatch."
}

$setEventHandleArg = @($setEvent[0].arguments | Where-Object { $_.name -eq "hEvent" } | Select-Object -First 1)
if ($setEventHandleArg.Count -ne 1 -or
    $setEventHandleArg[0].decodeAlias -ne "handle" -or
    $setEventHandleArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 SetEvent did not include expected handle metadata: $($setEvent[0].arguments | ConvertTo-Json -Depth 8)"
}

$waitEvent = @($syncEvents | Where-Object { $_.api -eq "WaitForSingleObjectEx" -and $_.returnValue -match "WAIT_OBJECT_0" } | Select-Object -First 1)
if ($waitEvent.Count -ne 1 -or
    $waitEvent[0].module -ne "kernel32.dll" -or
    $waitEvent[0].apiCategory -ne "event_wait")
{
    throw "x86 WaitForSingleObjectEx metadata or return evidence mismatch."
}

$waitEventHandleArg = @($waitEvent[0].arguments | Where-Object { $_.name -eq "hHandle" } | Select-Object -First 1)
$waitEventTimeoutArg = @($waitEvent[0].arguments | Where-Object { $_.name -eq "dwMilliseconds" } | Select-Object -First 1)
$waitEventAlertableArg = @($waitEvent[0].arguments | Where-Object { $_.name -eq "bAlertable" } | Select-Object -First 1)
if ($waitEventHandleArg.Count -ne 1 -or
    $waitEventHandleArg[0].decodeAlias -ne "handle" -or
    $waitEventHandleArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $waitEventTimeoutArg.Count -ne 1 -or
    $waitEventTimeoutArg[0].decodeAlias -ne "wait_timeout_ms" -or
    $waitEventTimeoutArg[0].decodedValue -notmatch "1000" -or
    $waitEventTimeoutArg[0].decodedValue -notmatch "0x000003e8" -or
    $waitEventAlertableArg.Count -ne 1 -or
    $waitEventAlertableArg[0].decodeAlias -ne "wait_alertable_bool" -or
    $waitEventAlertableArg[0].decodedValue -ne "FALSE")
{
    throw "x86 WaitForSingleObjectEx did not include expected wait metadata: $($waitEvent[0].arguments | ConvertTo-Json -Depth 8)"
}

$resetEvent = @($syncEvents | Where-Object { $_.api -eq "ResetEvent" } | Select-Object -First 1)
if ($resetEvent.Count -ne 1 -or
    $resetEvent[0].module -ne "kernel32.dll" -or
    $resetEvent[0].apiCategory -ne "event_reset" -or
    $resetEvent[0].returnValue -ne "TRUE")
{
    throw "x86 ResetEvent metadata or return evidence mismatch."
}

$resetEventHandleArg = @($resetEvent[0].arguments | Where-Object { $_.name -eq "hEvent" } | Select-Object -First 1)
if ($resetEventHandleArg.Count -ne 1 -or
    $resetEventHandleArg[0].decodeAlias -ne "handle" -or
    $resetEventHandleArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 ResetEvent did not include expected handle metadata: $($resetEvent[0].arguments | ConvertTo-Json -Depth 8)"
}

foreach ($syncEvent in $syncEvents)
{
    if (-not [string]::IsNullOrEmpty($syncEvent.bufferPreview))
    {
        throw "x86 event synchronization event exposed bufferPreview: $($syncEvent | ConvertTo-Json -Depth 8)"
    }
}

$syncPayload = $syncEvents | ConvertTo-Json -Depth 12
if ($syncPayload -cmatch "KnMonEventProbe|Global\\|Local\\|BaseNamedObjects|ObjectName|ObjectDirectory|ObjectManager|SecurityDescriptor|SECURITY_DESCRIPTOR|SID|ACL|TOKEN_|Privilege|Integrity|DuplicateHandle|WaitChain|WCT|Apc|APC|QueueUserAPC|NtQueueApcThread|CreateRemoteThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|TerminateThread|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Disassembly|VirtualAllocEx|WriteProcessMemory|ReadProcessMemory|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 KERNEL32 event synchronization events appear to expose event-name, namespace, security, wait-chain, APC, context, stack, injection, PE/file/hash, credential, or byte-preview evidence: $syncPayload"
}

$mutexSemaphoreApis = @(
    "CreateMutexW",
    "OpenMutexW",
    "ReleaseMutex",
    "CreateSemaphoreW",
    "OpenSemaphoreW",
    "ReleaseSemaphore",
    "WaitForMultipleObjectsEx"
)

$mutexSemaphoreEvents = @($result.capturedEvents | Where-Object { $mutexSemaphoreApis -contains $_.api })
if ($mutexSemaphoreEvents.Count -lt $mutexSemaphoreApis.Count)
{
    throw "x86 capture did not include the selected KERNEL32 mutex/semaphore API slice."
}

$createMutex = @($mutexSemaphoreEvents | Where-Object { $_.api -eq "CreateMutexW" } | Select-Object -First 1)
if ($createMutex.Count -ne 1 -or
    $createMutex[0].module -ne "kernel32.dll" -or
    $createMutex[0].apiCategory -ne "mutex_create" -or
    $createMutex[0].hookPolicy -ne "iat" -or
    $createMutex[0].coverageStatus -ne "smoke_verified" -or
    $createMutex[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 CreateMutexW metadata or return evidence mismatch."
}

$createMutexAttributesArg = @($createMutex[0].arguments | Where-Object { $_.name -eq "lpMutexAttributes" } | Select-Object -First 1)
$initialOwnerArg = @($createMutex[0].arguments | Where-Object { $_.name -eq "bInitialOwner" } | Select-Object -First 1)
$createMutexNameArg = @($createMutex[0].arguments | Where-Object { $_.name -eq "lpName" } | Select-Object -First 1)
if ($createMutexAttributesArg.Count -ne 1 -or
    $createMutexAttributesArg[0].decodeAlias -ne "pointer" -or
    $createMutexAttributesArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]+$" -or
    $initialOwnerArg.Count -ne 1 -or
    $initialOwnerArg[0].decodeAlias -ne "mutex_initial_owner_bool" -or
    $initialOwnerArg[0].decodedValue -ne "FALSE" -or
    $createMutexNameArg.Count -ne 1 -or
    $createMutexNameArg[0].decodeAlias -ne "sync_object_name_pointer" -or
    $createMutexNameArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 CreateMutexW did not include expected mutex create metadata: $($createMutex[0].arguments | ConvertTo-Json -Depth 8)"
}

$openMutex = @($mutexSemaphoreEvents | Where-Object { $_.api -eq "OpenMutexW" } | Select-Object -First 1)
if ($openMutex.Count -ne 1 -or
    $openMutex[0].module -ne "kernel32.dll" -or
    $openMutex[0].apiCategory -ne "mutex_open" -or
    $openMutex[0].hookPolicy -ne "iat" -or
    $openMutex[0].coverageStatus -ne "smoke_verified" -or
    $openMutex[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 OpenMutexW metadata or return evidence mismatch."
}

$mutexAccessArg = @($openMutex[0].arguments | Where-Object { $_.name -eq "dwDesiredAccess" } | Select-Object -First 1)
$mutexInheritArg = @($openMutex[0].arguments | Where-Object { $_.name -eq "bInheritHandle" } | Select-Object -First 1)
$openMutexNameArg = @($openMutex[0].arguments | Where-Object { $_.name -eq "lpName" } | Select-Object -First 1)
if ($mutexAccessArg.Count -ne 1 -or
    $mutexAccessArg[0].decodeAlias -ne "mutex_access_flags" -or
    $mutexAccessArg[0].decodedValue -notmatch "MUTEX_MODIFY_STATE" -or
    $mutexAccessArg[0].decodedValue -notmatch "SYNCHRONIZE" -or
    $mutexInheritArg.Count -ne 1 -or
    $mutexInheritArg[0].decodeAlias -ne "dword_value" -or
    $mutexInheritArg[0].decodedValue -ne "FALSE" -or
    $openMutexNameArg.Count -ne 1 -or
    $openMutexNameArg[0].decodeAlias -ne "sync_object_name_pointer" -or
    $openMutexNameArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 OpenMutexW did not include expected mutex open metadata: $($openMutex[0].arguments | ConvertTo-Json -Depth 8)"
}

$releaseMutex = @($mutexSemaphoreEvents | Where-Object { $_.api -eq "ReleaseMutex" } | Select-Object -First 1)
if ($releaseMutex.Count -ne 1 -or
    $releaseMutex[0].module -ne "kernel32.dll" -or
    $releaseMutex[0].apiCategory -ne "mutex_release" -or
    $releaseMutex[0].returnValue -ne "TRUE")
{
    throw "x86 ReleaseMutex metadata or return evidence mismatch."
}

$releaseMutexHandleArg = @($releaseMutex[0].arguments | Where-Object { $_.name -eq "hMutex" } | Select-Object -First 1)
if ($releaseMutexHandleArg.Count -ne 1 -or
    $releaseMutexHandleArg[0].decodeAlias -ne "handle" -or
    $releaseMutexHandleArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 ReleaseMutex did not include expected handle metadata: $($releaseMutex[0].arguments | ConvertTo-Json -Depth 8)"
}

$createSemaphore = @($mutexSemaphoreEvents | Where-Object { $_.api -eq "CreateSemaphoreW" } | Select-Object -First 1)
if ($createSemaphore.Count -ne 1 -or
    $createSemaphore[0].module -ne "kernel32.dll" -or
    $createSemaphore[0].apiCategory -ne "semaphore_create" -or
    $createSemaphore[0].hookPolicy -ne "iat" -or
    $createSemaphore[0].coverageStatus -ne "smoke_verified" -or
    $createSemaphore[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 CreateSemaphoreW metadata or return evidence mismatch."
}

$createSemaphoreAttributesArg = @($createSemaphore[0].arguments | Where-Object { $_.name -eq "lpSemaphoreAttributes" } | Select-Object -First 1)
$initialCountArg = @($createSemaphore[0].arguments | Where-Object { $_.name -eq "lInitialCount" } | Select-Object -First 1)
$maximumCountArg = @($createSemaphore[0].arguments | Where-Object { $_.name -eq "lMaximumCount" } | Select-Object -First 1)
$createSemaphoreNameArg = @($createSemaphore[0].arguments | Where-Object { $_.name -eq "lpName" } | Select-Object -First 1)
if ($createSemaphoreAttributesArg.Count -ne 1 -or
    $createSemaphoreAttributesArg[0].decodeAlias -ne "pointer" -or
    $createSemaphoreAttributesArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]+$" -or
    $initialCountArg.Count -ne 1 -or
    $initialCountArg[0].decodeAlias -ne "semaphore_count_value" -or
    $initialCountArg[0].decodedValue -ne "0" -or
    $maximumCountArg.Count -ne 1 -or
    $maximumCountArg[0].decodeAlias -ne "semaphore_count_value" -or
    $maximumCountArg[0].decodedValue -ne "1" -or
    $createSemaphoreNameArg.Count -ne 1 -or
    $createSemaphoreNameArg[0].decodeAlias -ne "sync_object_name_pointer" -or
    $createSemaphoreNameArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 CreateSemaphoreW did not include expected semaphore create metadata: $($createSemaphore[0].arguments | ConvertTo-Json -Depth 8)"
}

$openSemaphore = @($mutexSemaphoreEvents | Where-Object { $_.api -eq "OpenSemaphoreW" } | Select-Object -First 1)
if ($openSemaphore.Count -ne 1 -or
    $openSemaphore[0].module -ne "kernel32.dll" -or
    $openSemaphore[0].apiCategory -ne "semaphore_open" -or
    $openSemaphore[0].hookPolicy -ne "iat" -or
    $openSemaphore[0].coverageStatus -ne "smoke_verified" -or
    $openSemaphore[0].returnValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 OpenSemaphoreW metadata or return evidence mismatch."
}

$semaphoreAccessArg = @($openSemaphore[0].arguments | Where-Object { $_.name -eq "dwDesiredAccess" } | Select-Object -First 1)
$semaphoreInheritArg = @($openSemaphore[0].arguments | Where-Object { $_.name -eq "bInheritHandle" } | Select-Object -First 1)
$openSemaphoreNameArg = @($openSemaphore[0].arguments | Where-Object { $_.name -eq "lpName" } | Select-Object -First 1)
if ($semaphoreAccessArg.Count -ne 1 -or
    $semaphoreAccessArg[0].decodeAlias -ne "semaphore_access_flags" -or
    $semaphoreAccessArg[0].decodedValue -notmatch "SEMAPHORE_MODIFY_STATE" -or
    $semaphoreAccessArg[0].decodedValue -notmatch "SYNCHRONIZE" -or
    $semaphoreInheritArg.Count -ne 1 -or
    $semaphoreInheritArg[0].decodeAlias -ne "dword_value" -or
    $semaphoreInheritArg[0].decodedValue -ne "FALSE" -or
    $openSemaphoreNameArg.Count -ne 1 -or
    $openSemaphoreNameArg[0].decodeAlias -ne "sync_object_name_pointer" -or
    $openSemaphoreNameArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$")
{
    throw "x86 OpenSemaphoreW did not include expected semaphore open metadata: $($openSemaphore[0].arguments | ConvertTo-Json -Depth 8)"
}

$releaseSemaphore = @($mutexSemaphoreEvents | Where-Object { $_.api -eq "ReleaseSemaphore" } | Select-Object -First 1)
if ($releaseSemaphore.Count -ne 1 -or
    $releaseSemaphore[0].module -ne "kernel32.dll" -or
    $releaseSemaphore[0].apiCategory -ne "semaphore_release" -or
    $releaseSemaphore[0].returnValue -ne "TRUE")
{
    throw "x86 ReleaseSemaphore metadata or return evidence mismatch."
}

$releaseSemaphoreHandleArg = @($releaseSemaphore[0].arguments | Where-Object { $_.name -eq "hSemaphore" } | Select-Object -First 1)
$releaseCountArg = @($releaseSemaphore[0].arguments | Where-Object { $_.name -eq "lReleaseCount" } | Select-Object -First 1)
$previousCountArg = @($releaseSemaphore[0].arguments | Where-Object { $_.name -eq "lpPreviousCount" } | Select-Object -First 1)
if ($releaseSemaphoreHandleArg.Count -ne 1 -or
    $releaseSemaphoreHandleArg[0].decodeAlias -ne "handle" -or
    $releaseSemaphoreHandleArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $releaseCountArg.Count -ne 1 -or
    $releaseCountArg[0].decodeAlias -ne "semaphore_count_value" -or
    $releaseCountArg[0].decodedValue -ne "1" -or
    $previousCountArg.Count -ne 1 -or
    $previousCountArg[0].decodeAlias -ne "semaphore_previous_count_pointer" -or
    $previousCountArg[0].captureTiming -ne "post" -or
    $previousCountArg[0].decodeStatus -ne "decoded" -or
    $previousCountArg[0].postCallValue -ne "0" -or
    $previousCountArg[0].decodedValue -notmatch "value=0")
{
    throw "x86 ReleaseSemaphore did not include expected semaphore release metadata: $($releaseSemaphore[0].arguments | ConvertTo-Json -Depth 8)"
}

$multiWait = @($mutexSemaphoreEvents | Where-Object { $_.api -eq "WaitForMultipleObjectsEx" -and $_.returnValue -match "WAIT_OBJECT_0" } | Select-Object -First 1)
if ($multiWait.Count -ne 1 -or
    $multiWait[0].module -ne "kernel32.dll" -or
    $multiWait[0].apiCategory -ne "multi_wait")
{
    throw "x86 WaitForMultipleObjectsEx metadata or return evidence mismatch."
}

$waitCountArg = @($multiWait[0].arguments | Where-Object { $_.name -eq "nCount" } | Select-Object -First 1)
$waitHandlesArg = @($multiWait[0].arguments | Where-Object { $_.name -eq "lpHandles" } | Select-Object -First 1)
$waitAllArg = @($multiWait[0].arguments | Where-Object { $_.name -eq "bWaitAll" } | Select-Object -First 1)
$multiWaitTimeoutArg = @($multiWait[0].arguments | Where-Object { $_.name -eq "dwMilliseconds" } | Select-Object -First 1)
$multiWaitAlertableArg = @($multiWait[0].arguments | Where-Object { $_.name -eq "bAlertable" } | Select-Object -First 1)
if ($waitCountArg.Count -ne 1 -or
    $waitCountArg[0].decodeAlias -ne "dword_value" -or
    $waitCountArg[0].decodedValue -ne "1" -or
    $waitHandlesArg.Count -ne 1 -or
    $waitHandlesArg[0].decodeAlias -ne "wait_handle_array_pointer" -or
    $waitHandlesArg[0].decodedValue -notmatch "^0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*$" -or
    $waitAllArg.Count -ne 1 -or
    $waitAllArg[0].decodeAlias -ne "wait_all_bool" -or
    $waitAllArg[0].decodedValue -ne "FALSE" -or
    $multiWaitTimeoutArg.Count -ne 1 -or
    $multiWaitTimeoutArg[0].decodeAlias -ne "wait_timeout_ms" -or
    $multiWaitTimeoutArg[0].decodedValue -notmatch "1000" -or
    $multiWaitTimeoutArg[0].decodedValue -notmatch "0x000003e8" -or
    $multiWaitAlertableArg.Count -ne 1 -or
    $multiWaitAlertableArg[0].decodeAlias -ne "wait_alertable_bool" -or
    $multiWaitAlertableArg[0].decodedValue -ne "FALSE")
{
    throw "x86 WaitForMultipleObjectsEx did not include expected multi-wait metadata: $($multiWait[0].arguments | ConvertTo-Json -Depth 8)"
}

foreach ($mutexSemaphoreEvent in $mutexSemaphoreEvents)
{
    if (-not [string]::IsNullOrEmpty($mutexSemaphoreEvent.bufferPreview))
    {
        throw "x86 mutex/semaphore event exposed bufferPreview: $($mutexSemaphoreEvent | ConvertTo-Json -Depth 8)"
    }
}

$mutexSemaphorePayload = $mutexSemaphoreEvents | ConvertTo-Json -Depth 12
if ($mutexSemaphorePayload -cmatch "KnMonMutexProbe|KnMonSemaphoreProbe|Global\\|Local\\|BaseNamedObjects|ObjectName|ObjectDirectory|ObjectManager|SecurityDescriptor|SECURITY_DESCRIPTOR|SID|ACL|TOKEN_|Privilege|Integrity|DuplicateHandle|WaitChain|WCT|Apc|APC|QueueUserAPC|NtQueueApcThread|CreateRemoteThread|SuspendThread|ResumeThread|GetThreadContext|SetThreadContext|TerminateThread|CONTEXT|Eip|Rip|Rsp|CallStack|StackTrace|StackWalk|StackFrame|Disassembly|VirtualAllocEx|WriteProcessMemory|ReadProcessMemory|Injection|Shellcode|BEGIN CERTIFICATE|PRIVATE KEY|Password|Credential|IMAGE_DOS_HEADER|IMAGE_NT_HEADERS|ImportDirectory|ExportDirectory|ResourceDirectory|Relocation|DebugDirectory|SHA256|SHA1|MD5|MZ.{0,8}PE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "x86 KERNEL32 mutex/semaphore events appear to expose object-name, namespace, security, handle-array, wait-chain, APC, context, stack, injection, PE/file/hash, credential, or byte-preview evidence: $mutexSemaphorePayload"
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

$dynamicSweeps = @($result.agentMessages | Where-Object { $_.messageType -eq "iat_sweep" -and $_.reason -eq "dynamic_load" })
if ($dynamicSweeps.Count -lt 1)
{
    throw "x86 capture did not include dynamic-load re-hook sweep evidence."
}

$patchedDynamicSweep = @($dynamicSweeps | Where-Object { $_.patchedSlots -ge 1 } | Select-Object -First 1)
if ($patchedDynamicSweep.Count -ne 1)
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
