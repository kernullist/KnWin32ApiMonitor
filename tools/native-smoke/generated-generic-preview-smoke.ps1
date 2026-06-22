param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

function Assert-True
{
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition)
    {
        throw $Message
    }
}

function Assert-PreviewEvent
{
    param(
        [object]$Result,
        [string]$Api,
        [string]$Module,
        [string]$Kind,
        [string]$DecodeClass,
        [string]$ValueKind = "string",
        [string]$ArgumentName,
        [string]$ArgumentType,
        [int]$ArgumentIndex,
        [string]$ExpectedValue,
        [string]$ExpectedPattern = "",
        [string]$ExpectedDecodeStatus = "decoded"
    )

    $event = @($Result.capturedEvents | Where-Object { $_.api -eq $Api -and $_.module -eq $Module } | Select-Object -First 1)
    Assert-True ($event.Count -eq 1) "Generated preview smoke did not capture $Module!$Api."
    Assert-True (@("generated_generic", "generic_decoded") -contains $event[0].coverageStatus) "$Api coverage mismatch: $($event[0].coverageStatus)"
    Assert-True (@("generated-abi", "devices-safe") -contains $event[0].hookProfile) "$Api hook profile mismatch: $($event[0].hookProfile)"
    Assert-True ($null -ne $event[0].genericPreview) "$Api generic preview missing."
    Assert-True ($null -ne $event[0].genericPreviews) "$Api generic previews array missing."

    $preview = @($event[0].genericPreviews | Where-Object { $_.argumentIndex -eq $ArgumentIndex } | Select-Object -First 1)
    Assert-True ($preview.Count -eq 1) "$Api preview for argument $ArgumentIndex missing."
    Assert-True ($preview[0].kind -eq $Kind) "$Api preview kind mismatch: $($preview[0].kind)"
    Assert-True ($preview[0].decodeStatus -eq $ExpectedDecodeStatus) "$Api preview decode status mismatch: $($preview[0].decodeStatus)"
    if ($ExpectedPattern.Length -gt 0)
    {
        Assert-True ($preview[0].value -match $ExpectedPattern) "$Api preview value mismatch: $($preview[0].value)"
    }
    else
    {
        Assert-True ($preview[0].value -eq $ExpectedValue) "$Api preview value mismatch: $($preview[0].value)"
    }

    $argument = @($event[0].arguments | Where-Object { $_.index -eq $ArgumentIndex } | Select-Object -First 1)
    Assert-True ($argument.Count -eq 1) "$Api argument $ArgumentIndex missing."
    Assert-True ($argument[0].name -eq $ArgumentName) "$Api argument name mismatch: $($argument[0].name)"
    Assert-True ($argument[0].type -eq $ArgumentType) "$Api argument type mismatch: $($argument[0].type)"
    if ($ExpectedPattern.Length -gt 0)
    {
        Assert-True ($argument[0].decodedValue -match $ExpectedPattern) "$Api decoded value mismatch: $($argument[0].decodedValue)"
    }
    else
    {
        Assert-True ($argument[0].decodedValue -eq $ExpectedValue) "$Api decoded value mismatch: $($argument[0].decodedValue)"
    }
    Assert-True ($argument[0].decodeStatus -eq $ExpectedDecodeStatus) "$Api argument decode status mismatch: $($argument[0].decodeStatus)"
    Assert-True ($argument[0].valueKind -eq $ValueKind) "$Api value kind mismatch: $($argument[0].valueKind)"
    Assert-True ($argument[0].decodeClass -eq $DecodeClass) "$Api decode class mismatch: $($argument[0].decodeClass)"
    Assert-True ($argument[0].payloadPolicy -eq "target_memory") "$Api payload policy mismatch: $($argument[0].payloadPolicy)"
    Assert-True ($argument[0].targetMemoryRead -eq $true) "$Api target memory flag mismatch: $($argument[0].targetMemoryRead)"
}

Assert-True (Test-Path -LiteralPath $HelperPath) "Helper not found: $HelperPath"

$selection = "kernel32.dll!GetFileAttributesW;kernelbase.dll!GetFileAttributesW;shlwapi.dll!PathFileExistsA;kernelbase.dll!PathFileExistsA;shlwapi.dll!PathCombineA;kernelbase.dll!PathCombineA;shlwapi.dll!HashData;kernelbase.dll!HashData;ntdll.dll!RtlComputeCrc32;crypt32.dll!CertCompareIntegerBlob;advapi32.dll!CryptGenRandom;netapi32.dll!NetApiBufferSize;netapi32.dll!NetApiBufferFree;ntdll.dll!NtNotifyChangeMultipleKeys;advapi32.dll!EventRegister;advapi32.dll!GetNamedSecurityInfoW;advapi32.dll!RegGetValueW;oleaut32.dll!VarBstrCmp;api-ms-win-core-winrt-string-l1-1-0.dll!WindowsGetStringRawBuffer;webservices.dll!WsAddErrorString;webservices.dll!WsXmlStringEquals;ntdll.dll!RtlGUIDFromString;ntdll.dll!RtlInitAnsiString;ntdll.dll!RtlInitUTF8String;ntdll.dll!RtlUnicodeStringToOemString;user32.dll!MonitorFromRect;user32.dll!MapWindowPoints;kernel32.dll!SystemTimeToFileTime;ntdll.dll!RtlSecondsSince1970ToTime"
$result = $null
for ($attempt = 1; $attempt -le 3; ++$attempt)
{
    $candidate = & $HelperPath capture-sample --api-selection $selection --generated-preview-probe --timeout-ms 30000 | ConvertFrom-Json
    if ($candidate.success -and @($candidate.capturedEvents).Count -ge 3)
    {
        $result = $candidate
        break
    }

    $result = $candidate
    Start-Sleep -Milliseconds 500
}

Assert-True $result.success "Generated preview capture failed: $($result.operation): $($result.message)"
Assert-True ($result.apiSelection -eq $selection) "Generated preview capture did not echo api selection."
Assert-True (@($result.capturedEvents).Count -ge 3) "Generated preview capture returned too few events."

Assert-PreviewEvent `
    -Result $result `
    -Api "GetFileAttributesW" `
    -Module "kernel32.dll" `
    -Kind "utf16_string" `
    -DecodeClass "utf16_string" `
    -ValueKind "string" `
    -ArgumentName "lpFileName" `
    -ArgumentType "PWSTR" `
    -ArgumentIndex 0 `
    -ExpectedValue "C:\Windows"

Assert-PreviewEvent `
    -Result $result `
    -Api "PathFileExistsA" `
    -Module "shlwapi.dll" `
    -Kind "ansi_string" `
    -DecodeClass "ansi_string" `
    -ValueKind "string" `
    -ArgumentName "pszPath" `
    -ArgumentType "PSTR" `
    -ArgumentIndex 0 `
    -ExpectedValue "C:\Windows"

$pathCombineEvent = @($result.capturedEvents | Where-Object { $_.api -eq "PathCombineA" -and $_.module -eq "shlwapi.dll" } | Select-Object -First 1)
Assert-True ($pathCombineEvent.Count -eq 1) "Generated preview smoke did not capture shlwapi.dll!PathCombineA."
Assert-True (@($pathCombineEvent[0].genericPreviews).Count -ge 3) "PathCombineA did not capture multiple generated previews."
Assert-True ($pathCombineEvent[0].genericPreview.argumentIndex -eq 0) "PathCombineA compatibility preview should point to post-call output string."

Assert-PreviewEvent `
    -Result $result `
    -Api "PathCombineA" `
    -Module "shlwapi.dll" `
    -Kind "ansi_string" `
    -DecodeClass "ansi_string" `
    -ValueKind "string" `
    -ArgumentName "pszDest" `
    -ArgumentType "PSTR" `
    -ArgumentIndex 0 `
    -ExpectedValue "C:\Windows\System32"

Assert-PreviewEvent `
    -Result $result `
    -Api "PathCombineA" `
    -Module "shlwapi.dll" `
    -Kind "ansi_string" `
    -DecodeClass "ansi_string" `
    -ValueKind "string" `
    -ArgumentName "pszDir" `
    -ArgumentType "PSTR" `
    -ArgumentIndex 1 `
    -ExpectedValue "C:\Windows"

Assert-PreviewEvent `
    -Result $result `
    -Api "PathCombineA" `
    -Module "shlwapi.dll" `
    -Kind "ansi_string" `
    -DecodeClass "ansi_string" `
    -ValueKind "string" `
    -ArgumentName "pszFile" `
    -ArgumentType "PSTR" `
    -ArgumentIndex 2 `
    -ExpectedValue "System32"

Assert-PreviewEvent `
    -Result $result `
    -Api "HashData" `
    -Module "shlwapi.dll" `
    -Kind "buffer" `
    -DecodeClass "buffer" `
    -ValueKind "buffer" `
    -ArgumentName "pbData" `
    -ArgumentType "BYTE*" `
    -ArgumentIndex 0 `
    -ExpectedValue "hex=4b4e4d4f4e2d425546464552;len=12"

Assert-PreviewEvent `
    -Result $result `
    -Api "RtlComputeCrc32" `
    -Module "ntdll.dll" `
    -Kind "buffer" `
    -DecodeClass "buffer" `
    -ValueKind "buffer" `
    -ArgumentName "Buffer" `
    -ArgumentType "PVOID" `
    -ArgumentIndex 1 `
    -ExpectedValue "hex=4b4e4d4f4e2d425546464552;len=12"

Assert-PreviewEvent `
    -Result $result `
    -Api "CertCompareIntegerBlob" `
    -Module "crypt32.dll" `
    -Kind "buffer" `
    -DecodeClass "buffer" `
    -ValueKind "buffer" `
    -ArgumentName "pInt1" `
    -ArgumentType "CRYPT_INTEGER_BLOB*" `
    -ArgumentIndex 0 `
    -ExpectedValue "hex=4b4e4d4f4e2d43525950542d424c4f42;len=16"

Assert-PreviewEvent `
    -Result $result `
    -Api "CertCompareIntegerBlob" `
    -Module "crypt32.dll" `
    -Kind "buffer" `
    -DecodeClass "buffer" `
    -ValueKind "buffer" `
    -ArgumentName "pInt2" `
    -ArgumentType "CRYPT_INTEGER_BLOB*" `
    -ArgumentIndex 1 `
    -ExpectedValue "hex=4b4e4d4f4e2d43525950542d424c4f42;len=16"

Assert-PreviewEvent `
    -Result $result `
    -Api "CryptGenRandom" `
    -Module "advapi32.dll" `
    -Kind "buffer" `
    -DecodeClass "buffer" `
    -ValueKind "buffer" `
    -ArgumentName "pbBuffer" `
    -ArgumentType "BYTE*" `
    -ArgumentIndex 2 `
    -ExpectedValue "" `
    -ExpectedPattern "^hex=[0-9a-f]{24};len=12$"

Assert-PreviewEvent `
    -Result $result `
    -Api "NetApiBufferSize" `
    -Module "netapi32.dll" `
    -Kind "buffer" `
    -DecodeClass "buffer" `
    -ValueKind "buffer" `
    -ArgumentName "Buffer" `
    -ArgumentType "void*" `
    -ArgumentIndex 0 `
    -ExpectedValue "hex=4b4e4d4f4e2d4e45544150492d425546;len=16"

Assert-PreviewEvent `
    -Result $result `
    -Api "NetApiBufferFree" `
    -Module "netapi32.dll" `
    -Kind "buffer" `
    -DecodeClass "buffer" `
    -ValueKind "buffer" `
    -ArgumentName "Buffer" `
    -ArgumentType "void*" `
    -ArgumentIndex 0 `
    -ExpectedValue "hex=4b4e4d4f4e2d4e45544150492d425546;len=16"

Assert-PreviewEvent `
    -Result $result `
    -Api "NtNotifyChangeMultipleKeys" `
    -Module "ntdll.dll" `
    -Kind "utf16_string_struct" `
    -DecodeClass "object_attributes" `
    -ValueKind "object" `
    -ArgumentName "SubordinateObjects" `
    -ArgumentType "OBJECT_ATTRIBUTES" `
    -ArgumentIndex 2 `
    -ExpectedValue "\Registry\Machine\Software\KNMON-OA"

Assert-PreviewEvent `
    -Result $result `
    -Api "EventRegister" `
    -Module "advapi32.dll" `
    -Kind "guid" `
    -DecodeClass "guid" `
    -ValueKind "object" `
    -ArgumentName "ProviderId" `
    -ArgumentType "System.Guid*" `
    -ArgumentIndex 0 `
    -ExpectedValue "{8f5f52c1-6f56-4c0d-9c1d-3bde8a7f0001}"

Assert-PreviewEvent `
    -Result $result `
    -Api "EventRegister" `
    -Module "advapi32.dll" `
    -Kind "scalar_pointer" `
    -DecodeClass "scalar_pointer" `
    -ValueKind "pointer" `
    -ArgumentName "RegHandle" `
    -ArgumentType "REGHANDLE*" `
    -ArgumentIndex 3 `
    -ExpectedValue "" `
    -ExpectedPattern "^0x[0-9a-f]{16}$"

Assert-PreviewEvent `
    -Result $result `
    -Api "GetNamedSecurityInfoW" `
    -Module "advapi32.dll" `
    -Kind "pointer_indirect" `
    -DecodeClass "pointer_pointer" `
    -ValueKind "pointer" `
    -ArgumentName "ppDacl" `
    -ArgumentType "ACL**" `
    -ArgumentIndex 5 `
    -ExpectedValue "" `
    -ExpectedPattern "^pointee=0x[0-9a-f]{16}$"

Assert-PreviewEvent `
    -Result $result `
    -Api "RegGetValueW" `
    -Module "advapi32.dll" `
    -Kind "buffer" `
    -DecodeClass "buffer" `
    -ValueKind "buffer" `
    -ArgumentName "pvData" `
    -ArgumentType "void*" `
    -ArgumentIndex 5 `
    -ExpectedValue "" `
    -ExpectedPattern "^hex=43003a005c00[0-9a-f]+;len=[0-9]+$" `
    -ExpectedDecodeStatus "truncated"

Assert-PreviewEvent `
    -Result $result `
    -Api "VarBstrCmp" `
    -Module "oleaut32.dll" `
    -Kind "bstr" `
    -DecodeClass "utf16_string" `
    -ValueKind "string" `
    -ArgumentName "bstrLeft" `
    -ArgumentType "BSTR" `
    -ArgumentIndex 0 `
    -ExpectedValue "KNMonBstrPreview"

Assert-PreviewEvent `
    -Result $result `
    -Api "VarBstrCmp" `
    -Module "oleaut32.dll" `
    -Kind "bstr" `
    -DecodeClass "utf16_string" `
    -ValueKind "string" `
    -ArgumentName "bstrRight" `
    -ArgumentType "BSTR" `
    -ArgumentIndex 1 `
    -ExpectedValue "KNMonBstrPreview"

Assert-PreviewEvent `
    -Result $result `
    -Api "WindowsGetStringRawBuffer" `
    -Module "api-ms-win-core-winrt-string-l1-1-0.dll" `
    -Kind "hstring" `
    -DecodeClass "utf16_string" `
    -ValueKind "string" `
    -ArgumentName "string" `
    -ArgumentType "HSTRING" `
    -ArgumentIndex 0 `
    -ExpectedValue "knmon-hstring"

Assert-PreviewEvent `
    -Result $result `
    -Api "WsAddErrorString" `
    -Module "webservices.dll" `
    -Kind "utf16_string_struct" `
    -DecodeClass "utf16_string" `
    -ValueKind "string" `
    -ArgumentName "string" `
    -ArgumentType "WS_STRING*" `
    -ArgumentIndex 1 `
    -ExpectedValue "KNMonWsString"

Assert-PreviewEvent `
    -Result $result `
    -Api "WsXmlStringEquals" `
    -Module "webservices.dll" `
    -Kind "ansi_string_struct" `
    -DecodeClass "ansi_string" `
    -ValueKind "string" `
    -ArgumentName "string1" `
    -ArgumentType "WS_XML_STRING*" `
    -ArgumentIndex 0 `
    -ExpectedValue "KNMonXmlString"

Assert-PreviewEvent `
    -Result $result `
    -Api "WsXmlStringEquals" `
    -Module "webservices.dll" `
    -Kind "ansi_string_struct" `
    -DecodeClass "ansi_string" `
    -ValueKind "string" `
    -ArgumentName "string2" `
    -ArgumentType "WS_XML_STRING*" `
    -ArgumentIndex 1 `
    -ExpectedValue "KNMonXmlString"

Assert-PreviewEvent `
    -Result $result `
    -Api "RtlGUIDFromString" `
    -Module "ntdll.dll" `
    -Kind "utf16_string_struct" `
    -DecodeClass "utf16_string" `
    -ValueKind "string" `
    -ArgumentName "GuidString" `
    -ArgumentType "PCUNICODE_STRING" `
    -ArgumentIndex 0 `
    -ExpectedValue "{8f5f52c1-6f56-4c0d-9c1d-3bde8a7f0001}"

Assert-PreviewEvent `
    -Result $result `
    -Api "RtlGUIDFromString" `
    -Module "ntdll.dll" `
    -Kind "guid" `
    -DecodeClass "guid" `
    -ValueKind "object" `
    -ArgumentName "Guid" `
    -ArgumentType "PGUID" `
    -ArgumentIndex 1 `
    -ExpectedValue "{8f5f52c1-6f56-4c0d-9c1d-3bde8a7f0001}"

Assert-PreviewEvent `
    -Result $result `
    -Api "RtlInitAnsiString" `
    -Module "ntdll.dll" `
    -Kind "ansi_string_struct" `
    -DecodeClass "ansi_string" `
    -ValueKind "string" `
    -ArgumentName "DestinationString" `
    -ArgumentType "PANSI_STRING" `
    -ArgumentIndex 0 `
    -ExpectedValue "KNMON-ANSI-STRUCT"

Assert-PreviewEvent `
    -Result $result `
    -Api "RtlInitAnsiString" `
    -Module "ntdll.dll" `
    -Kind "ansi_string" `
    -DecodeClass "ansi_string" `
    -ValueKind "string" `
    -ArgumentName "SourceString" `
    -ArgumentType "PCSTR" `
    -ArgumentIndex 1 `
    -ExpectedValue "KNMON-ANSI-STRUCT"

Assert-PreviewEvent `
    -Result $result `
    -Api "RtlInitUTF8String" `
    -Module "ntdll.dll" `
    -Kind "ansi_string_struct" `
    -DecodeClass "ansi_string" `
    -ValueKind "string" `
    -ArgumentName "DestinationString" `
    -ArgumentType "PUTF8_STRING" `
    -ArgumentIndex 0 `
    -ExpectedValue "KNMON-UTF8-STRUCT"

Assert-PreviewEvent `
    -Result $result `
    -Api "RtlInitUTF8String" `
    -Module "ntdll.dll" `
    -Kind "ansi_string" `
    -DecodeClass "ansi_string" `
    -ValueKind "string" `
    -ArgumentName "SourceString" `
    -ArgumentType "PCSZ" `
    -ArgumentIndex 1 `
    -ExpectedValue "KNMON-UTF8-STRUCT"

Assert-PreviewEvent `
    -Result $result `
    -Api "RtlUnicodeStringToOemString" `
    -Module "ntdll.dll" `
    -Kind "ansi_string_struct" `
    -DecodeClass "ansi_string" `
    -ValueKind "string" `
    -ArgumentName "DestinationString" `
    -ArgumentType "POEM_STRING" `
    -ArgumentIndex 0 `
    -ExpectedValue "KNMON-OEM-STRUCT"

Assert-PreviewEvent `
    -Result $result `
    -Api "RtlUnicodeStringToOemString" `
    -Module "ntdll.dll" `
    -Kind "utf16_string_struct" `
    -DecodeClass "utf16_string" `
    -ValueKind "string" `
    -ArgumentName "SourceString" `
    -ArgumentType "PCUNICODE_STRING" `
    -ArgumentIndex 1 `
    -ExpectedValue "KNMON-OEM-STRUCT"

Assert-PreviewEvent `
    -Result $result `
    -Api "MonitorFromRect" `
    -Module "user32.dll" `
    -Kind "rect" `
    -DecodeClass "rect" `
    -ValueKind "object" `
    -ArgumentName "lprc" `
    -ArgumentType "RECT*" `
    -ArgumentIndex 0 `
    -ExpectedValue "left=0;top=0;right=640;bottom=480"

Assert-PreviewEvent `
    -Result $result `
    -Api "MapWindowPoints" `
    -Module "user32.dll" `
    -Kind "point" `
    -DecodeClass "point" `
    -ValueKind "object" `
    -ArgumentName "lpPoints" `
    -ArgumentType "POINT*" `
    -ArgumentIndex 2 `
    -ExpectedValue "x=11;y=22"

Assert-PreviewEvent `
    -Result $result `
    -Api "SystemTimeToFileTime" `
    -Module "kernel32.dll" `
    -Kind "systemtime" `
    -DecodeClass "systemtime" `
    -ValueKind "object" `
    -ArgumentName "lpSystemTime" `
    -ArgumentType "SYSTEMTIME*" `
    -ArgumentIndex 0 `
    -ExpectedValue "2024-01-02T03:04:05.006"

Assert-PreviewEvent `
    -Result $result `
    -Api "SystemTimeToFileTime" `
    -Module "kernel32.dll" `
    -Kind "filetime" `
    -DecodeClass "filetime" `
    -ValueKind "object" `
    -ArgumentName "lpFileTime" `
    -ArgumentType "FILETIME*" `
    -ArgumentIndex 1 `
    -ExpectedValue "" `
    -ExpectedPattern "^ticks=0x[0-9a-f]{16}$"

Assert-PreviewEvent `
    -Result $result `
    -Api "RtlSecondsSince1970ToTime" `
    -Module "ntdll.dll" `
    -Kind "large_integer" `
    -DecodeClass "large_integer" `
    -ValueKind "object" `
    -ArgumentName "Time" `
    -ArgumentType "PLARGE_INTEGER" `
    -ArgumentIndex 1 `
    -ExpectedValue "" `
    -ExpectedPattern "^value=[0-9]+;hex=0x[0-9a-f]{16}$"

Write-Host "Generated generic preview smoke passed: events=$(@($result.capturedEvents).Count)"
