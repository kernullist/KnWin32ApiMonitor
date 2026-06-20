#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#ifndef PSAPI_VERSION
#define PSAPI_VERSION 1
#endif
#include <psapi.h>
#include <bcrypt.h>
#include <dbghelp.h>
#include <objbase.h>
#include <oleauto.h>
#include <rpc.h>
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <security.h>
#include <roapi.h>
#include <winstring.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <windns.h>
#include <setupapi.h>
#include <devguid.h>
#include <userenv.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <winver.h>
#include <winhttp.h>
#include <wininet.h>
#include <winternl.h>
#include <winuser.h>
#include <wingdi.h>
#include <shlwapi.h>

#include <array>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef RPC_S_UUID_LOCAL_ONLY
#define RPC_S_UUID_LOCAL_ONLY 1824L
#endif

#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif

#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

extern "C" NTSYSAPI NTSTATUS NTAPI LdrGetProcedureAddress(
    HMODULE ModuleHandle,
    PANSI_STRING FunctionName,
    ULONG Ordinal,
    PVOID* FunctionAddress);

namespace
{
constexpr GUID SampleFolderIdWindows = { 0xf38bf404, 0x1d43, 0x42f2, { 0x93, 0x05, 0x67, 0xde, 0x0b, 0x28, 0xfc, 0x23 } };
constexpr GUID SampleFolderIdSystem = { 0x1ac14e77, 0x02e7, 0x4e5d, { 0xb7, 0x44, 0x2e, 0xb1, 0xae, 0x51, 0x98, 0xb7 } };
constexpr GUID SampleFolderIdProgramFiles = { 0x905e63b6, 0xc1bf, 0x494e, { 0xb2, 0x9c, 0x65, 0xb7, 0x32, 0xd3, 0xd2, 0x1a } };
constexpr GUID SampleFolderIdFonts = { 0xfd228cb7, 0xae11, 0x4ae3, { 0x86, 0x4c, 0x16, 0xf3, 0x91, 0x0a, 0xb8, 0xfe } };

std::wstring BuildSamplePath()
{
    std::array<wchar_t, MAX_PATH> tempPath = {};
    std::wstring result;

    do
    {
        const DWORD length = GetTempPathW(static_cast<DWORD>(tempPath.size()), tempPath.data());
        if (length == 0 || length >= tempPath.size())
        {
            result = L".\\knmon-fileio-sample.dat";
            break;
        }

        result.assign(tempPath.data(), length);
        result += L"knmon-fileio-sample.dat";
    }
    while (false);

    return result;
}

std::wstring BuildNtPath(const std::wstring& dosPath)
{
    return L"\\??\\" + dosPath;
}

std::string HexNtStatus(NTSTATUS status)
{
    std::ostringstream stream;
    stream << "0x"
           << std::hex
           << std::setfill('0')
           << std::setw(8)
           << static_cast<unsigned long>(status);
    return stream.str();
}

std::string HexHResult(HRESULT result)
{
    std::ostringstream stream;
    stream << "0x"
           << std::hex
           << std::setfill('0')
           << std::setw(8)
           << static_cast<unsigned long>(static_cast<unsigned int>(result));
    return stream.str();
}

bool HasOption(int argc, wchar_t** argv, const wchar_t* name)
{
    bool found = false;

    for (int index = 1; index < argc; ++index)
    {
        if (std::wstring(argv[index]) == name)
        {
            found = true;
            break;
        }
    }

    return found;
}

int GetIntOption(int argc, wchar_t** argv, const wchar_t* name, int fallback)
{
    int value = fallback;

    for (int index = 1; index + 1 < argc; ++index)
    {
        if (std::wstring(argv[index]) == name)
        {
            wchar_t* end = nullptr;
            const long parsed = wcstol(argv[index + 1], &end, 10);
            if (end != argv[index + 1] && end != nullptr && *end == L'\0')
            {
                value = static_cast<int>(parsed);
            }
            break;
        }
    }

    return value;
}

std::wstring GetStringOption(int argc, wchar_t** argv, const wchar_t* name, const wchar_t* fallback)
{
    std::wstring value = fallback == nullptr ? L"" : fallback;

    for (int index = 1; index + 1 < argc; ++index)
    {
        if (std::wstring(argv[index]) == name)
        {
            value = argv[index + 1];
            break;
        }
    }

    return value;
}

void LogLastError(const char* operation)
{
    std::cout << operation << " failed with " << GetLastError() << "\n";
}

void LogRegistryStatus(const char* operation, LSTATUS status)
{
    std::cout << operation << " failed with " << status << "\n";
}

bool RunNtCreateFileProbe(const std::wstring& path)
{
    bool success = false;
    HANDLE ntHandle = nullptr;
    IO_STATUS_BLOCK ioStatus = {};
    const std::wstring ntPath = BuildNtPath(path);
    UNICODE_STRING objectName = {};
    OBJECT_ATTRIBUTES objectAttributes = {};

    do
    {
        objectName.Buffer = const_cast<PWSTR>(ntPath.c_str());
        objectName.Length = static_cast<USHORT>(ntPath.size() * sizeof(wchar_t));
        objectName.MaximumLength = objectName.Length + sizeof(wchar_t);

        objectAttributes.Length = sizeof(objectAttributes);
        objectAttributes.ObjectName = &objectName;
        objectAttributes.Attributes = OBJ_CASE_INSENSITIVE;

        const NTSTATUS status = NtCreateFile(
            &ntHandle,
            GENERIC_READ,
            &objectAttributes,
            &ioStatus,
            nullptr,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            nullptr,
            0);

        std::cout << "ntcreatefile status=" << HexNtStatus(status) << "\n";

        if (!NT_SUCCESS(status))
        {
            break;
        }

        success = true;
    }
    while (false);

    if (ntHandle != nullptr)
    {
        CloseHandle(ntHandle);
    }

    return success;
}

bool RunDynamicLoadProbe()
{
    bool success = false;
    HMODULE module = nullptr;

    do
    {
        module = LoadLibraryW(L"knmon-dynamic-probe.dll");
        if (module == nullptr)
        {
            LogLastError("LoadLibraryW(knmon-dynamic-probe.dll)");
            break;
        }

        using ProbeFn = DWORD(*)();
        auto probe = reinterpret_cast<ProbeFn>(GetProcAddress(module, "KnMonDynamicProbe"));
        if (probe == nullptr)
        {
            LogLastError("GetProcAddress(KnMonDynamicProbe)");
            break;
        }

        const char ldrProbeName[] = "KnMonDynamicProbe";
        ANSI_STRING ldrName = {};
        ldrName.Buffer = const_cast<PSTR>(ldrProbeName);
        ldrName.Length = static_cast<USHORT>(std::strlen(ldrProbeName));
        ldrName.MaximumLength = static_cast<USHORT>(ldrName.Length + 1);
        PVOID ldrProbe = nullptr;
        const NTSTATUS ldrStatus = LdrGetProcedureAddress(module, &ldrName, 0, &ldrProbe);
        std::cout << "ldrgetprocedureaddress status=" << HexNtStatus(ldrStatus) << "\n";
        if (!NT_SUCCESS(ldrStatus) || ldrProbe == nullptr)
        {
            break;
        }

        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32 == nullptr)
        {
            LogLastError("GetModuleHandleW(kernel32.dll)");
            break;
        }

        using ProcessIdFn = DWORD(WINAPI*)();
        auto resolvedGetCurrentProcessId = reinterpret_cast<ProcessIdFn>(GetProcAddress(kernel32, "GetCurrentProcessId"));
        if (resolvedGetCurrentProcessId == nullptr)
        {
            LogLastError("GetProcAddress(GetCurrentProcessId)");
            break;
        }

        const char ldrProcessIdName[] = "GetCurrentProcessId";
        ANSI_STRING ldrProcessId = {};
        ldrProcessId.Buffer = const_cast<PSTR>(ldrProcessIdName);
        ldrProcessId.Length = static_cast<USHORT>(std::strlen(ldrProcessIdName));
        ldrProcessId.MaximumLength = static_cast<USHORT>(ldrProcessId.Length + 1);
        PVOID ldrProcessIdAddress = nullptr;
        const NTSTATUS ldrProcessIdStatus = LdrGetProcedureAddress(kernel32, &ldrProcessId, 0, &ldrProcessIdAddress);
        std::cout << "ldrgetprocedureaddress GetCurrentProcessId status=" << HexNtStatus(ldrProcessIdStatus) << "\n";
        if (!NT_SUCCESS(ldrProcessIdStatus) || ldrProcessIdAddress == nullptr)
        {
            break;
        }

        auto ldrGetCurrentProcessId = reinterpret_cast<ProcessIdFn>(ldrProcessIdAddress);
        const DWORD importedPid = GetCurrentProcessId();
        const DWORD resolvedPid = resolvedGetCurrentProcessId();
        const DWORD ldrResolvedPid = ldrGetCurrentProcessId();
        if (resolvedPid != importedPid || ldrResolvedPid != importedPid)
        {
            break;
        }

        const DWORD probeResult = probe();
        std::cout << "dynamic probe result=" << probeResult << "\n";
        if (probeResult != 0)
        {
            break;
        }

        success = true;
    }
    while (false);

    if (module != nullptr)
    {
        FreeLibrary(module);
    }

    return success;
}

bool RunRegistryProbe()
{
    bool success = false;
    HKEY key = nullptr;
    HKEY openedKey = nullptr;
    DWORD disposition = 0;
    DWORD valueType = 0;
    DWORD queryBytes = 0;
    const wchar_t* sampleKey = L"Software\\KNMonApiMonitorSample";
    const wchar_t* valueName = L"SampleValue";
    const std::wstring valueData = L"KNMon registry sample value";
    std::array<wchar_t, 128> queryBuffer = {};

    do
    {
        LSTATUS status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            sampleKey,
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE,
            nullptr,
            &key,
            &disposition);

        if (status != ERROR_SUCCESS)
        {
            LogRegistryStatus("RegCreateKeyExW", status);
            break;
        }

        const DWORD valueBytes = static_cast<DWORD>((valueData.size() + 1) * sizeof(wchar_t));
        status = RegSetValueExW(
            key,
            valueName,
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(valueData.c_str()),
            valueBytes);

        if (status != ERROR_SUCCESS)
        {
            LogRegistryStatus("RegSetValueExW", status);
            break;
        }

        queryBytes = static_cast<DWORD>(queryBuffer.size() * sizeof(wchar_t));
        status = RegQueryValueExW(
            key,
            valueName,
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(queryBuffer.data()),
            &queryBytes);

        if (status != ERROR_SUCCESS)
        {
            LogRegistryStatus("RegQueryValueExW(create handle)", status);
            break;
        }

        status = RegCloseKey(key);
        key = nullptr;
        if (status != ERROR_SUCCESS)
        {
            LogRegistryStatus("RegCloseKey(create handle)", status);
            break;
        }

        status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            sampleKey,
            0,
            KEY_READ | KEY_WRITE,
            &openedKey);

        if (status != ERROR_SUCCESS)
        {
            LogRegistryStatus("RegOpenKeyExW", status);
            break;
        }

        queryBuffer.fill(L'\0');
        valueType = 0;
        queryBytes = static_cast<DWORD>(queryBuffer.size() * sizeof(wchar_t));
        status = RegQueryValueExW(
            openedKey,
            valueName,
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(queryBuffer.data()),
            &queryBytes);

        if (status != ERROR_SUCCESS)
        {
            LogRegistryStatus("RegQueryValueExW(open handle)", status);
            break;
        }

        status = RegDeleteValueW(openedKey, valueName);
        if (status != ERROR_SUCCESS)
        {
            LogRegistryStatus("RegDeleteValueW", status);
            break;
        }

        status = RegCloseKey(openedKey);
        openedKey = nullptr;
        if (status != ERROR_SUCCESS)
        {
            LogRegistryStatus("RegCloseKey(open handle)", status);
            break;
        }

        std::cout << "registry roundtrip disposition=" << disposition << " type=" << valueType << " bytes=" << queryBytes << "\n";
        success = true;
    }
    while (false);

    if (openedKey != nullptr)
    {
        RegCloseKey(openedKey);
    }

    if (key != nullptr)
    {
        RegCloseKey(key);
    }

    const LSTATUS cleanupStatus = RegDeleteKeyW(HKEY_CURRENT_USER, sampleKey);
    if (success && cleanupStatus != ERROR_SUCCESS && cleanupStatus != ERROR_FILE_NOT_FOUND)
    {
        LogRegistryStatus("RegDeleteKeyW(cleanup)", cleanupStatus);
        success = false;
    }

    return success;
}

bool RunTokenQueryProbe()
{
    bool success = false;
    HANDLE token = nullptr;
    LUID luid = {};

    do
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        {
            LogLastError("OpenProcessToken");
            break;
        }

        if (!LookupPrivilegeValueW(nullptr, L"SeChangeNotifyPrivilege", &luid))
        {
            LogLastError("LookupPrivilegeValueW");
            break;
        }

        std::cout << "token query roundtrip access=" << TOKEN_QUERY
                  << " privilege=SeChangeNotifyPrivilege"
                  << " luid_low=" << luid.LowPart
                  << " luid_high=" << luid.HighPart
                  << "\n";
        success = true;
    }
    while (false);

    if (token != nullptr)
    {
        if (!CloseHandle(token))
        {
            LogLastError("CloseHandle(token)");
            success = false;
        }
    }

    return success;
}

bool RunRpcBindingProbe()
{
    bool success = false;
    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE binding = nullptr;
    auto* protocolSequence = reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc"));
    auto* endpoint = reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"KNMonRpcSample"));

    do
    {
        RPC_STATUS status = RpcStringBindingComposeW(
            nullptr,
            protocolSequence,
            nullptr,
            endpoint,
            nullptr,
            &stringBinding);

        if (status != RPC_S_OK)
        {
            std::cout << "RpcStringBindingComposeW failed with " << status << "\n";
            break;
        }

        status = RpcBindingFromStringBindingW(stringBinding, &binding);
        if (status != RPC_S_OK)
        {
            std::cout << "RpcBindingFromStringBindingW failed with " << status << "\n";
            break;
        }

        status = RpcBindingSetOption(binding, RPC_C_OPT_CALL_TIMEOUT, 5000);
        if (status != RPC_S_OK)
        {
            std::cout << "RpcBindingSetOption failed with " << status << "\n";
            break;
        }

        status = RpcBindingFree(&binding);
        if (status != RPC_S_OK)
        {
            std::cout << "RpcBindingFree failed with " << status << "\n";
            break;
        }

        status = RpcStringFreeW(&stringBinding);
        if (status != RPC_S_OK)
        {
            std::cout << "RpcStringFreeW failed with " << status << "\n";
            break;
        }

        std::cout << "rpc binding roundtrip endpoint=KNMonRpcSample\n";
        success = true;
    }
    while (false);

    if (binding != nullptr)
    {
        const RPC_STATUS cleanupStatus = RpcBindingFree(&binding);
        if (cleanupStatus != RPC_S_OK)
        {
            std::cout << "RpcBindingFree(cleanup) failed with " << cleanupStatus << "\n";
            success = false;
        }
    }

    if (stringBinding != nullptr)
    {
        const RPC_STATUS cleanupStatus = RpcStringFreeW(&stringBinding);
        if (cleanupStatus != RPC_S_OK)
        {
            std::cout << "RpcStringFreeW(cleanup) failed with " << cleanupStatus << "\n";
            success = false;
        }
    }

    return success;
}

bool RpcStatusProducedUuid(RPC_STATUS status)
{
    return status == RPC_S_OK || status == RPC_S_UUID_LOCAL_ONLY;
}

bool RunRpcUuidProbe()
{
    bool success = false;
    UUID createdUuid = {};
    UUID parsedUuid = {};
    RPC_WSTR uuidString = nullptr;
    auto* parseInput = reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"12345678-1234-5678-9abc-def012345678"));

    do
    {
        RPC_STATUS status = UuidCreate(&createdUuid);
        if (!RpcStatusProducedUuid(status))
        {
            std::cout << "UuidCreate failed with " << status << "\n";
            break;
        }

        const RPC_STATUS createStatus = status;
        status = UuidToStringW(&createdUuid, &uuidString);
        if (status != RPC_S_OK)
        {
            std::cout << "UuidToStringW failed with " << status << "\n";
            break;
        }

        status = UuidFromStringW(parseInput, &parsedUuid);
        if (status != RPC_S_OK)
        {
            std::cout << "UuidFromStringW failed with " << status << "\n";
            break;
        }

        std::cout << "rpc uuid helper roundtrip create_status=" << createStatus << "\n";
        success = true;
    }
    while (false);

    if (uuidString != nullptr)
    {
        const RPC_STATUS cleanupStatus = RpcStringFreeW(&uuidString);
        if (cleanupStatus != RPC_S_OK)
        {
            std::cout << "RpcStringFreeW(uuid cleanup) failed with " << cleanupStatus << "\n";
            success = false;
        }
    }

    return success;
}

bool RunBcryptProbe()
{
    bool success = false;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    std::array<UCHAR, 128> propertyBuffer = {};
    ULONG propertyBytes = 0;
    std::array<UCHAR, 16> randomBuffer = {};

    do
    {
        NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_RNG_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(status))
        {
            std::cout << "BCryptOpenAlgorithmProvider failed with " << HexNtStatus(status) << "\n";
            break;
        }

        status = BCryptGetProperty(
            algorithm,
            BCRYPT_ALGORITHM_NAME,
            propertyBuffer.data(),
            static_cast<ULONG>(propertyBuffer.size()),
            &propertyBytes,
            0);

        if (!NT_SUCCESS(status))
        {
            std::cout << "BCryptGetProperty failed with " << HexNtStatus(status) << "\n";
            break;
        }

        status = BCryptGenRandom(algorithm, randomBuffer.data(), static_cast<ULONG>(randomBuffer.size()), 0);
        if (!NT_SUCCESS(status))
        {
            std::cout << "BCryptGenRandom failed with " << HexNtStatus(status) << "\n";
            break;
        }

        const NTSTATUS destroyKeyStatus = BCryptDestroyKey(nullptr);
        std::cout << "bcrypt key destroy invalid-handle probe status=" << HexNtStatus(destroyKeyStatus) << "\n";

        status = BCryptCloseAlgorithmProvider(algorithm, 0);
        algorithm = nullptr;
        if (!NT_SUCCESS(status))
        {
            std::cout << "BCryptCloseAlgorithmProvider failed with " << HexNtStatus(status) << "\n";
            break;
        }

        std::cout << "bcrypt cng roundtrip property_bytes=" << propertyBytes << " random_bytes=" << randomBuffer.size() << "\n";
        success = true;
    }
    while (false);

    if (algorithm != nullptr)
    {
        const NTSTATUS cleanupStatus = BCryptCloseAlgorithmProvider(algorithm, 0);
        if (!NT_SUCCESS(cleanupStatus))
        {
            std::cout << "BCryptCloseAlgorithmProvider(cleanup) failed with " << HexNtStatus(cleanupStatus) << "\n";
            success = false;
        }
    }

    SecureZeroMemory(randomBuffer.data(), randomBuffer.size());
    return success;
}

bool RunCrypt32Probe()
{
    bool success = false;
    HCERTSTORE store = nullptr;
    HCRYPTMSG message = nullptr;

    do
    {
        store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr);
        if (store == nullptr)
        {
            LogLastError("CertOpenStore");
            break;
        }

        if (!CertCloseStore(store, 0))
        {
            LogLastError("CertCloseStore");
            break;
        }

        store = nullptr;
        message = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, nullptr, nullptr);
        if (message == nullptr)
        {
            LogLastError("CryptMsgOpenToDecode");
            break;
        }

        if (!CryptMsgClose(message))
        {
            LogLastError("CryptMsgClose");
            break;
        }

        message = nullptr;
        std::cout << "crypt32 handle roundtrip store=memory msg_encoding=" << (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING) << "\n";
        success = true;
    }
    while (false);

    if (message != nullptr)
    {
        if (!CryptMsgClose(message))
        {
            LogLastError("CryptMsgClose(cleanup)");
            success = false;
        }
    }

    if (store != nullptr)
    {
        if (!CertCloseStore(store, CERT_CLOSE_STORE_CHECK_FLAG))
        {
            LogLastError("CertCloseStore(cleanup)");
            success = false;
        }
    }

    return success;
}

bool RunWinHttpProbe()
{
    bool success = false;
    HINTERNET session = nullptr;

    do
    {
        session = WinHttpOpen(
            L"KNMonWinHttpSample/1.0",
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);

        if (session == nullptr)
        {
            LogLastError("WinHttpOpen");
            break;
        }

        DWORD timeoutMs = 5000;
        if (!WinHttpSetOption(session, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeoutMs, sizeof(timeoutMs)))
        {
            LogLastError("WinHttpSetOption");
            break;
        }

        if (!WinHttpCloseHandle(session))
        {
            LogLastError("WinHttpCloseHandle");
            break;
        }

        session = nullptr;
        std::cout << "winhttp session roundtrip access_type=" << WINHTTP_ACCESS_TYPE_NO_PROXY << "\n";
        success = true;
    }
    while (false);

    if (session != nullptr)
    {
        if (!WinHttpCloseHandle(session))
        {
            LogLastError("WinHttpCloseHandle(cleanup)");
            success = false;
        }
    }

    return success;
}

bool RunWinInetProbe()
{
    bool success = false;
    HINTERNET session = nullptr;

    do
    {
        session = InternetOpenW(
            L"KNMonWinInetSample/1.0",
            INTERNET_OPEN_TYPE_DIRECT,
            nullptr,
            nullptr,
            0);

        if (session == nullptr)
        {
            LogLastError("InternetOpenW");
            break;
        }

        if (!InternetCloseHandle(session))
        {
            LogLastError("InternetCloseHandle");
            break;
        }

        session = nullptr;
        std::cout << "wininet session roundtrip access_type=" << INTERNET_OPEN_TYPE_DIRECT << "\n";
        success = true;
    }
    while (false);

    if (session != nullptr)
    {
        if (!InternetCloseHandle(session))
        {
            LogLastError("InternetCloseHandle(cleanup)");
            success = false;
        }
    }

    return success;
}

bool RunUserGdiProbe()
{
    bool success = false;
    HDC compatibleDc = nullptr;

    do
    {
        const int screenWidth = GetSystemMetrics(SM_CXSCREEN);
        const int screenHeight = GetSystemMetrics(SM_CYSCREEN);
        HWND desktopWindow = GetDesktopWindow();
        HWND foregroundWindow = GetForegroundWindow();
        HWND queryWindow = foregroundWindow != nullptr ? foregroundWindow : desktopWindow;
        DWORD windowProcessId = 0;
        const DWORD windowThreadId = GetWindowThreadProcessId(queryWindow, &windowProcessId);

        compatibleDc = CreateCompatibleDC(nullptr);
        if (compatibleDc == nullptr)
        {
            LogLastError("CreateCompatibleDC");
            break;
        }

        const int planes = GetDeviceCaps(compatibleDc, PLANES);
        const int bitsPerPixel = GetDeviceCaps(compatibleDc, BITSPIXEL);

        if (!DeleteDC(compatibleDc))
        {
            LogLastError("DeleteDC");
            break;
        }

        compatibleDc = nullptr;
        std::cout << "user32/gdi32 metadata roundtrip metrics=" << screenWidth << "x" << screenHeight
                  << " window_tid=" << windowThreadId
                  << " window_pid=" << windowProcessId
                  << " planes=" << planes
                  << " bits_per_pixel=" << bitsPerPixel << "\n";
        success = true;
    }
    while (false);

    if (compatibleDc != nullptr)
    {
        if (!DeleteDC(compatibleDc))
        {
            LogLastError("DeleteDC(cleanup)");
            success = false;
        }
    }

    return success;
}

bool RunPsapiModuleQueryProbe()
{
    bool success = false;
    std::array<HMODULE, 8> modules = {};
    MODULEINFO moduleInfo = {};
    std::array<wchar_t, MAX_PATH> baseName = {};
    std::array<wchar_t, MAX_PATH * 2> modulePath = {};
    DWORD neededBytes = 0;
    HANDLE process = GetCurrentProcess();

    do
    {
        const DWORD requestedBytes = static_cast<DWORD>(modules.size() * sizeof(HMODULE));
        if (!EnumProcessModules(process, modules.data(), requestedBytes, &neededBytes))
        {
            LogLastError("EnumProcessModules");
            break;
        }

        if (neededBytes < sizeof(HMODULE) || modules[0] == nullptr)
        {
            std::cout << "EnumProcessModules returned no module evidence\n";
            break;
        }

        HMODULE selectedModule = modules[0];
        if (!GetModuleInformation(process, selectedModule, &moduleInfo, sizeof(moduleInfo)))
        {
            LogLastError("GetModuleInformation");
            break;
        }

        const DWORD baseNameChars = GetModuleBaseNameW(
            process,
            selectedModule,
            baseName.data(),
            static_cast<DWORD>(baseName.size()));
        if (baseNameChars == 0)
        {
            LogLastError("GetModuleBaseNameW");
            break;
        }

        const DWORD pathChars = GetModuleFileNameExW(
            process,
            selectedModule,
            modulePath.data(),
            static_cast<DWORD>(modulePath.size()));
        if (pathChars == 0)
        {
            LogLastError("GetModuleFileNameExW");
            break;
        }

        std::cout << "psapi module query roundtrip modules_bytes=" << neededBytes
                  << " image_size=" << moduleInfo.SizeOfImage
                  << " base_chars=" << baseNameChars
                  << " path_chars=" << pathChars << "\n";
        success = true;
    }
    while (false);

    return success;
}

std::wstring BuildVersionProbePath()
{
    std::array<wchar_t, MAX_PATH> systemDirectory = {};
    std::wstring result;

    do
    {
        const UINT length = GetSystemDirectoryW(systemDirectory.data(), static_cast<UINT>(systemDirectory.size()));
        if (length == 0 || length >= systemDirectory.size())
        {
            result = L"C:\\Windows\\System32\\kernel32.dll";
            break;
        }

        result.assign(systemDirectory.data(), length);
        if (!result.empty() && result.back() != L'\\')
        {
            result += L"\\";
        }

        result += L"kernel32.dll";
    }
    while (false);

    return result;
}

bool RunVersionResourceProbe()
{
    bool success = false;
    static constexpr DWORD MaxVersionInfoBytes = 64 * 1024;
    std::array<BYTE, MaxVersionInfoBytes> versionInfo = {};
    std::wstring versionPath = BuildVersionProbePath();
    DWORD versionHandle = 0;

    do
    {
        const DWORD versionBytes = GetFileVersionInfoSizeW(versionPath.c_str(), &versionHandle);
        if (versionBytes == 0)
        {
            LogLastError("GetFileVersionInfoSizeW");
            break;
        }

        if (versionBytes > versionInfo.size())
        {
            std::cout << "version resource too large bytes=" << versionBytes << "\n";
            break;
        }

        if (!GetFileVersionInfoW(versionPath.c_str(), versionHandle, versionBytes, versionInfo.data()))
        {
            LogLastError("GetFileVersionInfoW");
            break;
        }

        LPVOID fixedValue = nullptr;
        UINT fixedLength = 0;
        if (!VerQueryValueW(versionInfo.data(), L"\\", &fixedValue, &fixedLength))
        {
            LogLastError("VerQueryValueW(root)");
            break;
        }

        auto* fixedInfo = static_cast<VS_FIXEDFILEINFO*>(fixedValue);
        if (fixedInfo == nullptr || fixedLength < sizeof(VS_FIXEDFILEINFO) || fixedInfo->dwSignature != VS_FFI_SIGNATURE)
        {
            std::cout << "version fixed info evidence invalid\n";
            break;
        }

        LPVOID translationValue = nullptr;
        UINT translationLength = 0;
        if (!VerQueryValueW(versionInfo.data(), L"\\VarFileInfo\\Translation", &translationValue, &translationLength))
        {
            LogLastError("VerQueryValueW(translation)");
            break;
        }

        std::cout << "version resource roundtrip bytes=" << versionBytes
                  << " file_version_ms=0x" << std::hex << fixedInfo->dwFileVersionMS
                  << " file_version_ls=0x" << fixedInfo->dwFileVersionLS
                  << " type=0x" << fixedInfo->dwFileType
                  << std::dec
                  << " translation_bytes=" << translationLength << "\n";
        success = true;
    }
    while (false);

    return success;
}

bool QueryKnownFolderPath(REFKNOWNFOLDERID folderId, const char* label, bool requirePath)
{
    bool success = false;
    PWSTR folderPath = nullptr;

    do
    {
        const HRESULT result = SHGetKnownFolderPath(folderId, 0, nullptr, &folderPath);
        if (FAILED(result))
        {
            std::cout << "SHGetKnownFolderPath(" << label << ") failed with " << HexHResult(result) << "\n";
            break;
        }

        if (folderPath == nullptr)
        {
            std::cout << "SHGetKnownFolderPath(" << label << ") returned null path\n";
            break;
        }

        if (requirePath && std::wcslen(folderPath) == 0)
        {
            std::cout << "SHGetKnownFolderPath(" << label << ") returned empty path\n";
            break;
        }

        success = true;
    }
    while (false);

    if (folderPath != nullptr)
    {
        CoTaskMemFree(folderPath);
    }

    return success;
}

bool QuerySpecialFolderPath(int csidl, const char* label, bool requirePath)
{
    bool success = false;
    std::array<wchar_t, MAX_PATH> folderPath = {};

    do
    {
        if (!SHGetSpecialFolderPathW(nullptr, folderPath.data(), csidl, FALSE))
        {
            const std::string operation = std::string("SHGetSpecialFolderPathW(") + label + ")";
            LogLastError(operation.c_str());
            break;
        }

        if (requirePath && folderPath[0] == L'\0')
        {
            std::cout << "SHGetSpecialFolderPathW(" << label << ") returned empty path\n";
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

bool RunShellKnownFolderProbe()
{
    bool success = false;

    do
    {
        if (!QueryKnownFolderPath(SampleFolderIdWindows, "Windows", true))
        {
            break;
        }

        if (!QueryKnownFolderPath(SampleFolderIdSystem, "System", true))
        {
            break;
        }

        if (!QueryKnownFolderPath(SampleFolderIdProgramFiles, "ProgramFiles", true))
        {
            break;
        }

        if (!QueryKnownFolderPath(SampleFolderIdFonts, "Fonts", true))
        {
            break;
        }

        if (!QuerySpecialFolderPath(CSIDL_WINDOWS, "Windows", true))
        {
            break;
        }

        if (!QuerySpecialFolderPath(CSIDL_SYSTEM, "System", true))
        {
            break;
        }

        if (!QuerySpecialFolderPath(CSIDL_PROGRAM_FILES, "ProgramFiles", true))
        {
            break;
        }

        if (!QuerySpecialFolderPath(CSIDL_FONTS, "Fonts", true))
        {
            break;
        }

        std::cout << "shell known folder roundtrip known=4 special=4\n";
        success = true;
    }
    while (false);

    return success;
}

DWORD WINAPI Ole32ComLifecycleThreadProc(LPVOID)
{
    bool success = false;
    bool initialized = false;
    GUID guid = {};
    std::array<wchar_t, 64> guidString = {};

    do
    {
        const HRESULT initResult = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(initResult))
        {
            std::cout << "CoInitializeEx failed with " << HexHResult(initResult) << "\n";
            break;
        }

        initialized = true;

        const HRESULT guidResult = CoCreateGuid(&guid);
        if (FAILED(guidResult))
        {
            std::cout << "CoCreateGuid failed with " << HexHResult(guidResult) << "\n";
            break;
        }

        const int guidChars = StringFromGUID2(guid, guidString.data(), static_cast<int>(guidString.size()));
        if (guidChars <= 0)
        {
            std::cout << "StringFromGUID2 failed chars=" << guidChars << "\n";
            break;
        }

        std::cout << "ole32 com lifecycle roundtrip chars=" << guidChars
                  << " init=" << HexHResult(initResult) << "\n";
        success = true;
    }
    while (false);

    if (initialized)
    {
        CoUninitialize();
    }

    return success ? 0 : 1;
}

bool RunOle32ComLifecycleProbe()
{
    bool success = false;
    HANDLE threadHandle = nullptr;

    do
    {
        threadHandle = CreateThread(nullptr, 0, Ole32ComLifecycleThreadProc, nullptr, 0, nullptr);
        if (threadHandle == nullptr)
        {
            LogLastError("CreateThread(ole32)");
            break;
        }

        const DWORD waitResult = WaitForSingleObject(threadHandle, INFINITE);
        if (waitResult != WAIT_OBJECT_0)
        {
            LogLastError("WaitForSingleObject(ole32)");
            break;
        }

        DWORD exitCode = 1;
        if (!GetExitCodeThread(threadHandle, &exitCode))
        {
            LogLastError("GetExitCodeThread(ole32)");
            break;
        }

        success = exitCode == 0;
    }
    while (false);

    if (threadHandle != nullptr)
    {
        CloseHandle(threadHandle);
    }

    return success;
}

bool RunOleAutomationLifecycleProbe()
{
    bool success = false;
    BSTR bstr = nullptr;
    SAFEARRAY* safeArray = nullptr;

    do
    {
        bstr = SysAllocString(L"KNMonBstrProbe");
        if (bstr == nullptr)
        {
            std::cout << "SysAllocString failed\n";
            break;
        }

        SysFreeString(bstr);
        bstr = nullptr;

        VARIANT variant = {};
        VariantInit(&variant);
        variant.vt = VT_I4;
        variant.lVal = 42;

        HRESULT result = VariantClear(&variant);
        if (FAILED(result))
        {
            std::cout << "VariantClear failed with " << HexHResult(result) << "\n";
            break;
        }

        safeArray = SafeArrayCreateVector(VT_UI1, 0, 4);
        if (safeArray == nullptr)
        {
            std::cout << "SafeArrayCreateVector failed\n";
            break;
        }

        result = SafeArrayDestroy(safeArray);
        safeArray = nullptr;
        if (FAILED(result))
        {
            std::cout << "SafeArrayDestroy failed with " << HexHResult(result) << "\n";
            break;
        }

        std::cout << "oleaut32 BSTR, variant, and safe array lifecycle completed\n";
        success = true;
    }
    while (false);

    if (bstr != nullptr)
    {
        SysFreeString(bstr);
    }

    if (safeArray != nullptr)
    {
        SafeArrayDestroy(safeArray);
    }

    return success;
}

bool RunSecur32CredentialFreeProbe()
{
    bool success = false;
    bool credentialAcquired = false;
    CredHandle credential = {};
    TimeStamp expiry = {};
    wchar_t packageName[] = L"Negotiate";

    do
    {
        SECURITY_STATUS status = AcquireCredentialsHandleW(
            nullptr,
            packageName,
            SECPKG_CRED_OUTBOUND,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            &credential,
            &expiry);
        if (status != SEC_E_OK)
        {
            std::cout << "AcquireCredentialsHandleW failed with " << HexHResult(status) << "\n";
            break;
        }

        credentialAcquired = true;
        status = FreeCredentialsHandle(&credential);
        if (status != SEC_E_OK)
        {
            std::cout << "FreeCredentialsHandle failed with " << HexHResult(status) << "\n";
            break;
        }

        credentialAcquired = false;
        CtxtHandle context = {};
        status = DeleteSecurityContext(&context);
        std::cout << "secur32 context delete invalid-handle probe status=" << HexHResult(status) << "\n";

        std::cout << "secur32 credential free lifecycle completed\n";
        success = true;
    }
    while (false);

    if (credentialAcquired)
    {
        const SECURITY_STATUS cleanupStatus = FreeCredentialsHandle(&credential);
        if (cleanupStatus != SEC_E_OK)
        {
            std::cout << "FreeCredentialsHandle(cleanup) failed with " << HexHResult(cleanupStatus) << "\n";
        }
    }

    return success;
}

bool RunDnsRecordLifecycleProbe()
{
    DnsRecordListFree(nullptr, DnsFreeRecordList);
    std::cout << "dnsapi record list free lifecycle completed\n";
    return true;
}

bool RunSetupApiDeviceInfoSetLifecycleProbe()
{
    bool success = false;
    HDEVINFO deviceInfoSet = INVALID_HANDLE_VALUE;

    do
    {
        deviceInfoSet = SetupDiCreateDeviceInfoList(nullptr, nullptr);
        if (deviceInfoSet == INVALID_HANDLE_VALUE)
        {
            LogLastError("SetupDiCreateDeviceInfoList");
            break;
        }

        if (!SetupDiDestroyDeviceInfoList(deviceInfoSet))
        {
            LogLastError("SetupDiDestroyDeviceInfoList");
            break;
        }

        deviceInfoSet = INVALID_HANDLE_VALUE;
        std::cout << "setupapi device info set lifecycle completed\n";
        success = true;
    }
    while (false);

    if (deviceInfoSet != INVALID_HANDLE_VALUE)
    {
        if (!SetupDiDestroyDeviceInfoList(deviceInfoSet))
        {
            LogLastError("SetupDiDestroyDeviceInfoList(cleanup)");
            success = false;
        }
    }

    return success;
}

bool RunUserenvEnvironmentBlockLifecycleProbe()
{
    bool success = false;
    LPVOID environment = nullptr;

    do
    {
        if (!CreateEnvironmentBlock(&environment, nullptr, FALSE))
        {
            LogLastError("CreateEnvironmentBlock");
            break;
        }

        if (environment == nullptr)
        {
            std::cout << "CreateEnvironmentBlock returned null environment\n";
            break;
        }

        if (!DestroyEnvironmentBlock(environment))
        {
            LogLastError("DestroyEnvironmentBlock");
            break;
        }

        environment = nullptr;
        std::cout << "userenv environment block lifecycle completed\n";
        success = true;
    }
    while (false);

    if (environment != nullptr)
    {
        if (!DestroyEnvironmentBlock(environment))
        {
            LogLastError("DestroyEnvironmentBlock(cleanup)");
            success = false;
        }
    }

    return success;
}

bool RunIphlpapiAdapterAddressesProbe()
{
    bool success = false;
    ULONG size = 0;
    const ULONG flags =
        GAA_FLAG_SKIP_UNICAST |
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_FRIENDLY_NAME;

    do
    {
        ULONG status = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &size);
        if (status == ERROR_NO_DATA)
        {
            std::cout << "GetAdaptersAddresses returned no adapter data\n";
            success = true;
            break;
        }

        if (status != ERROR_BUFFER_OVERFLOW && status != ERROR_SUCCESS)
        {
            std::cout << "GetAdaptersAddresses size query failed with " << status << "\n";
            break;
        }

        if (size == 0)
        {
            std::cout << "GetAdaptersAddresses returned zero required size\n";
            break;
        }

        if (size > 256U * 1024U)
        {
            std::cout << "GetAdaptersAddresses required size too large: " << size << "\n";
            break;
        }

        std::vector<unsigned char> buffer(size);
        PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        status = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addresses, &size);
        if (status != ERROR_SUCCESS && status != ERROR_NO_DATA)
        {
            std::cout << "GetAdaptersAddresses failed with " << status << "\n";
            break;
        }

        std::cout << "iphlpapi adapter address size query completed size=" << size << "\n";
        success = true;
    }
    while (false);

    return success;
}

bool RunIphlpapiInterfaceEntryQueryProbe()
{
    bool success = false;
    MIB_IF_TABLE2* table = nullptr;

    do
    {
        NETIO_STATUS status = GetIfTable2(&table);
        if (status != NO_ERROR)
        {
            std::cout << "GetIfTable2 failed with " << status << "\n";
            break;
        }

        if (table == nullptr || table->NumEntries == 0)
        {
            std::cout << "GetIfTable2 returned no interfaces\n";
            break;
        }

        MIB_IF_ROW2 row = table->Table[0];
        status = GetIfEntry2(&row);
        if (status != NO_ERROR)
        {
            std::cout << "GetIfEntry2 failed with " << status << "\n";
            break;
        }

        std::cout << "iphlpapi interface entry query completed\n";
        success = true;
    }
    while (false);

    if (table != nullptr)
    {
        FreeMibTable(table);
    }

    return success;
}

DWORD WINAPI CombaseWinRtLifecycleThreadProc(LPVOID)
{
    bool success = false;
    bool initialized = false;
    UINT64 apartmentId = 0;

    do
    {
        const HRESULT initResult = RoInitialize(RO_INIT_MULTITHREADED);
        if (FAILED(initResult))
        {
            std::cout << "RoInitialize failed with " << HexHResult(initResult) << "\n";
            break;
        }

        initialized = true;

        const HRESULT apartmentResult = RoGetApartmentIdentifier(&apartmentId);
        if (FAILED(apartmentResult))
        {
            std::cout << "RoGetApartmentIdentifier failed with " << HexHResult(apartmentResult) << "\n";
            break;
        }

        std::cout << "combase winrt lifecycle roundtrip apartment_id=" << apartmentId
                  << " init=" << HexHResult(initResult) << "\n";
        success = true;
    }
    while (false);

    if (initialized)
    {
        RoUninitialize();
    }

    return success ? 0 : 1;
}

bool RunCombaseWinRtLifecycleProbe()
{
    bool success = false;
    HANDLE threadHandle = nullptr;

    do
    {
        threadHandle = CreateThread(nullptr, 0, CombaseWinRtLifecycleThreadProc, nullptr, 0, nullptr);
        if (threadHandle == nullptr)
        {
            LogLastError("CreateThread(winrt)");
            break;
        }

        const DWORD waitResult = WaitForSingleObject(threadHandle, INFINITE);
        if (waitResult != WAIT_OBJECT_0)
        {
            LogLastError("WaitForSingleObject(winrt)");
            break;
        }

        DWORD exitCode = 1;
        if (!GetExitCodeThread(threadHandle, &exitCode))
        {
            LogLastError("GetExitCodeThread(winrt)");
            break;
        }

        success = exitCode == 0;
    }
    while (false);

    if (threadHandle != nullptr)
    {
        CloseHandle(threadHandle);
    }

    return success;
}

bool RunMemoryProtectionProbe()
{
    bool success = false;
    void* region = nullptr;

    do
    {
        constexpr SIZE_T AllocationSize = 0x3000;
        constexpr SIZE_T ProtectSize = 0x1000;

        region = VirtualAlloc(nullptr, AllocationSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (region == nullptr)
        {
            LogLastError("VirtualAlloc(memory)");
            break;
        }

        volatile unsigned char* bytes = static_cast<volatile unsigned char*>(region);
        bytes[0] = 0x41;

        DWORD oldProtect = 0;
        if (!VirtualProtect(region, ProtectSize, PAGE_READONLY, &oldProtect))
        {
            LogLastError("VirtualProtect(memory)");
            break;
        }

        MEMORY_BASIC_INFORMATION info = {};
        const SIZE_T querySize = VirtualQuery(region, &info, sizeof(info));
        if (querySize == 0)
        {
            LogLastError("VirtualQuery(memory)");
            break;
        }

        std::cout << "memory protection roundtrip size=" << AllocationSize
                  << " query=" << querySize << "\n";
        success = true;
    }
    while (false);

    if (region != nullptr)
    {
        if (!VirtualFree(region, 0, MEM_RELEASE))
        {
            LogLastError("VirtualFree(memory)");
            success = false;
        }
    }

    return success;
}

bool RunFileMappingProbe()
{
    bool success = false;
    HANDLE createdMapping = nullptr;
    HANDLE openedMapping = nullptr;
    void* view = nullptr;
    const std::wstring mappingName = L"Local\\KnMonFileMappingProbe_" + std::to_wstring(GetCurrentProcessId());

    do
    {
        constexpr DWORD MappingSize = 4096;

        createdMapping = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            nullptr,
            PAGE_READWRITE,
            0,
            MappingSize,
            mappingName.c_str());

        if (createdMapping == nullptr)
        {
            LogLastError("CreateFileMappingW(mapping)");
            break;
        }

        openedMapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, mappingName.c_str());
        if (openedMapping == nullptr)
        {
            LogLastError("OpenFileMappingW(mapping)");
            break;
        }

        view = MapViewOfFile(openedMapping, FILE_MAP_WRITE, 0, 0, MappingSize);
        if (view == nullptr)
        {
            LogLastError("MapViewOfFile(mapping)");
            break;
        }

        volatile unsigned char* bytes = static_cast<volatile unsigned char*>(view);
        bytes[0] = 0x4D;

        if (!UnmapViewOfFile(view))
        {
            LogLastError("UnmapViewOfFile(mapping)");
            break;
        }

        view = nullptr;
        std::cout << "file mapping roundtrip size=" << MappingSize << "\n";
        success = true;
    }
    while (false);

    if (view != nullptr)
    {
        if (!UnmapViewOfFile(view))
        {
            LogLastError("UnmapViewOfFile(cleanup)");
            success = false;
        }
    }

    if (openedMapping != nullptr)
    {
        CloseHandle(openedMapping);
    }

    if (createdMapping != nullptr)
    {
        CloseHandle(createdMapping);
    }

    return success;
}

bool RunProcessThreadIdentityProbe()
{
    bool success = false;

    do
    {
        HANDLE currentProcess = GetCurrentProcess();
        const DWORD currentProcessId = GetCurrentProcessId();
        const DWORD processIdFromHandle = GetProcessId(currentProcess);
        HANDLE currentThread = GetCurrentThread();
        const DWORD currentThreadId = GetCurrentThreadId();
        const DWORD threadIdFromHandle = GetThreadId(currentThread);

        if (currentProcess == nullptr)
        {
            std::cout << "GetCurrentProcess returned null\n";
            break;
        }

        if (currentThread == nullptr)
        {
            std::cout << "GetCurrentThread returned null\n";
            break;
        }

        if (currentProcessId == 0 || processIdFromHandle == 0 || currentProcessId != processIdFromHandle)
        {
            std::cout << "process identity mismatch current=" << currentProcessId
                      << " handle=" << processIdFromHandle << "\n";
            break;
        }

        if (currentThreadId == 0 || threadIdFromHandle == 0 || currentThreadId != threadIdFromHandle)
        {
            std::cout << "thread identity mismatch current=" << currentThreadId
                      << " handle=" << threadIdFromHandle << "\n";
            break;
        }

        std::cout << "process/thread identity pid=" << currentProcessId
                  << " tid=" << currentThreadId << "\n";
        success = true;
    }
    while (false);

    return success;
}

bool RunHandleMetadataProbe()
{
    bool success = false;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    const std::wstring path = BuildSamplePath();

    do
    {
        fileHandle = CreateFileW(
            path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            LogLastError("CreateFileW(handle-metadata)");
            break;
        }

        HANDLE stdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        (void)stdOutput;

        const DWORD fileType = GetFileType(fileHandle);
        if (fileType != FILE_TYPE_DISK)
        {
            std::cout << "GetFileType(handle-metadata) returned 0x"
                      << std::hex << fileType << std::dec << "\n";
            break;
        }

        DWORD flags = 0;
        if (!GetHandleInformation(fileHandle, &flags))
        {
            LogLastError("GetHandleInformation(handle-metadata)");
            break;
        }

        if (!SetHandleInformation(fileHandle, HANDLE_FLAG_INHERIT, 0))
        {
            LogLastError("SetHandleInformation(handle-metadata)");
            break;
        }

        DWORD updatedFlags = 0;
        if (!GetHandleInformation(fileHandle, &updatedFlags))
        {
            LogLastError("GetHandleInformation(handle-metadata-after-set)");
            break;
        }

        if ((updatedFlags & HANDLE_FLAG_INHERIT) != 0)
        {
            std::cout << "handle inherit flag remained set\n";
            break;
        }

        std::cout << "handle metadata flags=0x"
                  << std::hex << updatedFlags << std::dec << "\n";
        success = true;
    }
    while (false);

    if (fileHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(fileHandle);
    }

    return success;
}

bool RunFileMetadataProbe()
{
    bool success = false;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    const std::wstring path = BuildSamplePath();
    constexpr char metadataBytes[] = "knmon file metadata sample\n";
    constexpr DWORD expectedBytes = static_cast<DWORD>(sizeof(metadataBytes) - 1);

    do
    {
        fileHandle = CreateFileW(
            path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            LogLastError("CreateFileW(file-metadata)");
            break;
        }

        DWORD bytesWritten = 0;
        if (!WriteFile(fileHandle, metadataBytes, expectedBytes, &bytesWritten, nullptr) ||
            bytesWritten != expectedBytes)
        {
            LogLastError("WriteFile(file-metadata)");
            break;
        }

        LARGE_INTEGER fileSize = {};
        if (!GetFileSizeEx(fileHandle, &fileSize))
        {
            LogLastError("GetFileSizeEx(file-metadata)");
            break;
        }

        if (fileSize.QuadPart != expectedBytes)
        {
            std::cout << "GetFileSizeEx(file-metadata) size mismatch "
                      << fileSize.QuadPart << " expected=" << expectedBytes << "\n";
            break;
        }

        FILETIME creationTime = {};
        FILETIME lastAccessTime = {};
        FILETIME lastWriteTime = {};
        if (!GetFileTime(fileHandle, &creationTime, &lastAccessTime, &lastWriteTime))
        {
            LogLastError("GetFileTime(file-metadata)");
            break;
        }

        BY_HANDLE_FILE_INFORMATION fileInformation = {};
        if (!GetFileInformationByHandle(fileHandle, &fileInformation))
        {
            LogLastError("GetFileInformationByHandle(file-metadata)");
            break;
        }

        const ULONGLONG infoSize =
            (static_cast<ULONGLONG>(fileInformation.nFileSizeHigh) << 32) |
            static_cast<ULONGLONG>(fileInformation.nFileSizeLow);
        if (infoSize != expectedBytes)
        {
            std::cout << "GetFileInformationByHandle(file-metadata) size mismatch "
                      << infoSize << " expected=" << expectedBytes << "\n";
            break;
        }

        if ((fileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            std::cout << "GetFileInformationByHandle(file-metadata) returned directory attribute\n";
            break;
        }

        if (fileInformation.nNumberOfLinks == 0)
        {
            std::cout << "GetFileInformationByHandle(file-metadata) link count was zero\n";
            break;
        }

        std::cout << "file metadata size=" << fileSize.QuadPart
                  << " links=" << fileInformation.nNumberOfLinks << "\n";
        success = true;
    }
    while (false);

    if (fileHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(fileHandle);
    }

    return success;
}

bool RunShlwapiPathExistsProbe()
{
    if (!PathFileExistsW(L"C:\\Windows"))
    {
        LogLastError("PathFileExistsW");
        return false;
    }

    std::cout << "shlwapi path exists query completed\n";
    return true;
}

bool RunDbgHelpSymbolSessionProbe()
{
    bool success = false;
    const HANDLE process = GetCurrentProcess();

    do
    {
        if (!SymInitializeW(process, nullptr, FALSE))
        {
            LogLastError("SymInitializeW(symbol-session)");
            break;
        }

        if (!SymCleanup(process))
        {
            LogLastError("SymCleanup(symbol-session)");
            break;
        }

        std::cout << "dbghelp symbol session initialized and cleaned\n";
        success = true;
    }
    while (false);

    return success;
}

bool RunModuleLifecycleProbe()
{
    bool success = false;
    HMODULE loadedModule = nullptr;

    do
    {
        loadedModule = LoadLibraryW(L"version.dll");
        if (loadedModule == nullptr)
        {
            LogLastError("LoadLibraryW(module-lifecycle)");
            break;
        }

        HMODULE moduleFromHandle = GetModuleHandleW(L"version.dll");
        if (moduleFromHandle == nullptr)
        {
            LogLastError("GetModuleHandleW(module-lifecycle)");
            break;
        }

        HMODULE moduleFromEx = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"version.dll", &moduleFromEx))
        {
            LogLastError("GetModuleHandleExW(module-lifecycle)");
            break;
        }

        if (moduleFromHandle != loadedModule || moduleFromEx != loadedModule)
        {
            std::cout << "module handle mismatch\n";
            break;
        }

        std::array<wchar_t, MAX_PATH> modulePath = {};
        const DWORD pathChars = GetModuleFileNameW(loadedModule, modulePath.data(), static_cast<DWORD>(modulePath.size()));
        if (pathChars == 0 || pathChars >= modulePath.size())
        {
            LogLastError("GetModuleFileNameW(module-lifecycle)");
            break;
        }

        const wchar_t* moduleName = std::wcsrchr(modulePath.data(), L'\\');
        moduleName = moduleName == nullptr ? modulePath.data() : moduleName + 1;
        if (_wcsicmp(moduleName, L"version.dll") != 0)
        {
            std::wcout << L"unexpected module lifecycle path=" << modulePath.data() << L"\n";
            break;
        }

        std::cout << "module lifecycle path chars=" << pathChars << "\n";
        success = true;
    }
    while (false);

    if (loadedModule != nullptr)
    {
        if (!FreeLibrary(loadedModule))
        {
            LogLastError("FreeLibrary(module-lifecycle)");
            success = false;
        }
    }

    return success;
}

DWORD WINAPI ThreadLifecycleProbeThreadProc(LPVOID parameter)
{
    DWORD* value = static_cast<DWORD*>(parameter);
    if (value != nullptr)
    {
        *value = 0x2A;
    }

    return 0x2A;
}

bool RunThreadLifecycleProbe()
{
    bool success = false;
    HANDLE threadHandle = nullptr;
    HANDLE openedThread = nullptr;
    DWORD threadId = 0;
    DWORD exitCode = 0;
    DWORD threadValue = 0;

    do
    {
        threadHandle = CreateThread(nullptr, 0, ThreadLifecycleProbeThreadProc, &threadValue, 0, &threadId);
        if (threadHandle == nullptr)
        {
            LogLastError("CreateThread(thread)");
            break;
        }

        if (threadId == 0)
        {
            std::cout << "CreateThread returned zero thread id\n";
            break;
        }

        openedThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, threadId);
        if (openedThread == nullptr)
        {
            LogLastError("OpenThread(thread)");
            break;
        }

        const DWORD waitResult = WaitForSingleObject(threadHandle, INFINITE);
        if (waitResult != WAIT_OBJECT_0)
        {
            std::cout << "WaitForSingleObject(thread) returned 0x"
                      << std::hex << waitResult << std::dec << "\n";
            break;
        }

        if (!GetExitCodeThread(threadHandle, &exitCode))
        {
            LogLastError("GetExitCodeThread(thread)");
            break;
        }

        if (exitCode != 0x2A || threadValue != 0x2A)
        {
            std::cout << "thread lifecycle mismatch exit=0x"
                      << std::hex << exitCode
                      << " value=0x" << threadValue
                      << std::dec << "\n";
            break;
        }

        std::cout << "thread lifecycle roundtrip tid=" << threadId
                  << " exit=0x" << std::hex << exitCode << std::dec << "\n";
        success = true;
    }
    while (false);

    if (openedThread != nullptr)
    {
        CloseHandle(openedThread);
    }

    if (threadHandle != nullptr)
    {
        CloseHandle(threadHandle);
    }

    return success;
}

bool RunEventSynchronizationProbe()
{
    bool success = false;
    HANDLE createdEvent = nullptr;
    HANDLE openedEvent = nullptr;
    const std::wstring eventName = L"Local\\KnMonEventProbe_" + std::to_wstring(GetCurrentProcessId());

    do
    {
        createdEvent = CreateEventW(nullptr, TRUE, FALSE, eventName.c_str());
        if (createdEvent == nullptr)
        {
            LogLastError("CreateEventW(event)");
            break;
        }

        openedEvent = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, eventName.c_str());
        if (openedEvent == nullptr)
        {
            LogLastError("OpenEventW(event)");
            break;
        }

        if (!SetEvent(openedEvent))
        {
            LogLastError("SetEvent(event)");
            break;
        }

        const DWORD waitResult = WaitForSingleObjectEx(createdEvent, 1000, FALSE);
        if (waitResult != WAIT_OBJECT_0)
        {
            std::cout << "WaitForSingleObjectEx(event) returned 0x"
                      << std::hex << waitResult << std::dec << "\n";
            break;
        }

        if (!ResetEvent(createdEvent))
        {
            LogLastError("ResetEvent(event)");
            break;
        }

        std::cout << "event synchronization roundtrip wait=0x"
                  << std::hex << waitResult << std::dec << "\n";
        success = true;
    }
    while (false);

    if (openedEvent != nullptr)
    {
        CloseHandle(openedEvent);
    }

    if (createdEvent != nullptr)
    {
        CloseHandle(createdEvent);
    }

    return success;
}

bool RunMutexSemaphoreProbe()
{
    bool success = false;
    HANDLE createdMutex = nullptr;
    HANDLE openedMutex = nullptr;
    HANDLE createdSemaphore = nullptr;
    HANDLE openedSemaphore = nullptr;
    LONG previousSemaphoreCount = -1;
    const std::wstring mutexName = L"Local\\KnMonMutexProbe_" + std::to_wstring(GetCurrentProcessId());
    const std::wstring semaphoreName = L"Local\\KnMonSemaphoreProbe_" + std::to_wstring(GetCurrentProcessId());

    do
    {
        createdMutex = CreateMutexW(nullptr, FALSE, mutexName.c_str());
        if (createdMutex == nullptr)
        {
            LogLastError("CreateMutexW(mutex)");
            break;
        }

        openedMutex = OpenMutexW(MUTEX_MODIFY_STATE | SYNCHRONIZE, FALSE, mutexName.c_str());
        if (openedMutex == nullptr)
        {
            LogLastError("OpenMutexW(mutex)");
            break;
        }

        const DWORD mutexWait = WaitForSingleObject(openedMutex, 1000);
        if (mutexWait != WAIT_OBJECT_0)
        {
            std::cout << "WaitForSingleObject(mutex) returned 0x"
                      << std::hex << mutexWait << std::dec << "\n";
            break;
        }

        if (!ReleaseMutex(openedMutex))
        {
            LogLastError("ReleaseMutex(mutex)");
            break;
        }

        createdSemaphore = CreateSemaphoreW(nullptr, 0, 1, semaphoreName.c_str());
        if (createdSemaphore == nullptr)
        {
            LogLastError("CreateSemaphoreW(semaphore)");
            break;
        }

        openedSemaphore = OpenSemaphoreW(SEMAPHORE_MODIFY_STATE | SYNCHRONIZE, FALSE, semaphoreName.c_str());
        if (openedSemaphore == nullptr)
        {
            LogLastError("OpenSemaphoreW(semaphore)");
            break;
        }

        if (!ReleaseSemaphore(openedSemaphore, 1, &previousSemaphoreCount))
        {
            LogLastError("ReleaseSemaphore(semaphore)");
            break;
        }

        if (previousSemaphoreCount != 0)
        {
            std::cout << "ReleaseSemaphore previous count mismatch: "
                      << previousSemaphoreCount << "\n";
            break;
        }

        const HANDLE waitHandles[] = { createdSemaphore };
        const DWORD semaphoreWait = WaitForMultipleObjectsEx(1, waitHandles, FALSE, 1000, FALSE);
        if (semaphoreWait != WAIT_OBJECT_0)
        {
            std::cout << "WaitForMultipleObjectsEx(semaphore) returned 0x"
                      << std::hex << semaphoreWait << std::dec << "\n";
            break;
        }

        std::cout << "mutex semaphore roundtrip mutexWait=0x"
                  << std::hex << mutexWait
                  << " semaphoreWait=0x" << semaphoreWait
                  << std::dec << "\n";
        success = true;
    }
    while (false);

    if (openedSemaphore != nullptr)
    {
        CloseHandle(openedSemaphore);
    }

    if (createdSemaphore != nullptr)
    {
        CloseHandle(createdSemaphore);
    }

    if (openedMutex != nullptr)
    {
        CloseHandle(openedMutex);
    }

    if (createdMutex != nullptr)
    {
        CloseHandle(createdMutex);
    }

    return success;
}

bool RunWinsockProbe()
{
    bool success = false;
    bool started = false;
    WSADATA wsaData = {};
    ADDRINFOA hints = {};
    PADDRINFOA results = nullptr;
    SOCKET socketHandle = INVALID_SOCKET;
    SOCKET listenerSocket = INVALID_SOCKET;
    SOCKET acceptedSocket = INVALID_SOCKET;

    do
    {
        const int startupResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (startupResult != 0)
        {
            std::cout << "WSAStartup failed with " << startupResult << "\n";
            break;
        }

        started = true;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        const int addressResult = getaddrinfo("localhost", "80", &hints, &results);
        if (addressResult != 0)
        {
            std::cout << "getaddrinfo failed with " << addressResult << "\n";
            break;
        }

        socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socketHandle == INVALID_SOCKET)
        {
            std::cout << "socket failed with " << WSAGetLastError() << "\n";
            break;
        }

        listenerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenerSocket == INVALID_SOCKET)
        {
            std::cout << "listener socket failed with " << WSAGetLastError() << "\n";
            break;
        }

        sockaddr_in listenerAddress = {};
        listenerAddress.sin_family = AF_INET;
        listenerAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        listenerAddress.sin_port = 0;

        if (bind(listenerSocket, reinterpret_cast<const sockaddr*>(&listenerAddress), sizeof(listenerAddress)) == SOCKET_ERROR)
        {
            std::cout << "bind failed with " << WSAGetLastError() << "\n";
            break;
        }

        int listenerAddressLength = sizeof(listenerAddress);
        if (getsockname(listenerSocket, reinterpret_cast<sockaddr*>(&listenerAddress), &listenerAddressLength) == SOCKET_ERROR)
        {
            std::cout << "getsockname failed with " << WSAGetLastError() << "\n";
            break;
        }

        if (listen(listenerSocket, 1) == SOCKET_ERROR)
        {
            std::cout << "listen failed with " << WSAGetLastError() << "\n";
            break;
        }

        if (connect(socketHandle, reinterpret_cast<const sockaddr*>(&listenerAddress), listenerAddressLength) == SOCKET_ERROR)
        {
            std::cout << "connect failed with " << WSAGetLastError() << "\n";
            break;
        }

        acceptedSocket = accept(listenerSocket, nullptr, nullptr);
        if (acceptedSocket == INVALID_SOCKET)
        {
            std::cout << "accept failed with " << WSAGetLastError() << "\n";
            break;
        }

        std::cout << "winsock connect port=" << ntohs(listenerAddress.sin_port) << "\n";

        const int lastError = WSAGetLastError();
        std::cout << "winsock probe last_error=" << lastError << "\n";
        success = true;
    }
    while (false);

    if (acceptedSocket != INVALID_SOCKET)
    {
        const int closeResult = closesocket(acceptedSocket);
        acceptedSocket = INVALID_SOCKET;
        if (closeResult == SOCKET_ERROR)
        {
            std::cout << "accepted closesocket failed with " << WSAGetLastError() << "\n";
            success = false;
        }
    }

    if (socketHandle != INVALID_SOCKET)
    {
        const int closeResult = closesocket(socketHandle);
        socketHandle = INVALID_SOCKET;
        if (closeResult == SOCKET_ERROR)
        {
            std::cout << "closesocket failed with " << WSAGetLastError() << "\n";
            success = false;
        }
    }

    if (listenerSocket != INVALID_SOCKET)
    {
        const int closeResult = closesocket(listenerSocket);
        listenerSocket = INVALID_SOCKET;
        if (closeResult == SOCKET_ERROR)
        {
            std::cout << "listener closesocket failed with " << WSAGetLastError() << "\n";
            success = false;
        }
    }

    if (results != nullptr)
    {
        freeaddrinfo(results);
        results = nullptr;
    }

    if (started)
    {
        const int cleanupResult = WSACleanup();
        if (cleanupResult != 0)
        {
            std::cout << "WSACleanup failed with " << WSAGetLastError() << "\n";
            success = false;
        }
    }

    return success;
}

bool RunAttachFileIoProbe(int iteration)
{
    bool success = false;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    HANDLE ansiHandle = INVALID_HANDLE_VALUE;
    const std::wstring path = BuildSamplePath();
    char ansiPath[MAX_PATH] = {};
    char tempPath[MAX_PATH] = {};
    const char payload[] = "KNMon attach File I/O payload\n";
    std::array<char, 128> readBuffer = {};

    do
    {
        fileHandle = CreateFileW(
            path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            LogLastError("CreateFileW(attach)");
            break;
        }

        DWORD bytesWritten = 0;
        if (!WriteFile(fileHandle, payload, static_cast<DWORD>(sizeof(payload) - 1), &bytesWritten, nullptr))
        {
            LogLastError("WriteFile(attach)");
            break;
        }

        if (SetFilePointer(fileHandle, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
        {
            LogLastError("SetFilePointer(attach)");
            break;
        }

        DWORD bytesRead = 0;
        if (!ReadFile(fileHandle, readBuffer.data(), static_cast<DWORD>(readBuffer.size() - 1), &bytesRead, nullptr))
        {
            LogLastError("ReadFile(attach)");
            break;
        }

        if (!CloseHandle(fileHandle))
        {
            fileHandle = INVALID_HANDLE_VALUE;
            LogLastError("CloseHandle(attach)");
            break;
        }
        fileHandle = INVALID_HANDLE_VALUE;

        if (!RunNtCreateFileProbe(path))
        {
            break;
        }

        const DWORD tempLength = GetTempPathA(static_cast<DWORD>(sizeof(tempPath)), tempPath);
        if (tempLength == 0 || tempLength >= sizeof(tempPath))
        {
            strcpy_s(ansiPath, ".\\knmon-fileio-attach-sample-a.dat");
        }
        else
        {
            strcpy_s(ansiPath, tempPath);
            strcat_s(ansiPath, "knmon-fileio-attach-sample-a.dat");
        }

        ansiHandle = CreateFileA(
            ansiPath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (ansiHandle == INVALID_HANDLE_VALUE)
        {
            LogLastError("CreateFileA(attach)");
            break;
        }

        if (!CloseHandle(ansiHandle))
        {
            ansiHandle = INVALID_HANDLE_VALUE;
            LogLastError("CloseHandle(attach ansi)");
            break;
        }
        ansiHandle = INVALID_HANDLE_VALUE;

        DeleteFileW(path.c_str());
        DeleteFileA(ansiPath);
        std::cout << "attach loop iteration=" << iteration << " bytes_written=" << bytesWritten << " bytes_read=" << bytesRead << "\n";
        success = true;
    }
    while (false);

    if (ansiHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(ansiHandle);
    }

    if (fileHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(fileHandle);
    }

    DeleteFileW(path.c_str());
    if (ansiPath[0] != '\0')
    {
        DeleteFileA(ansiPath);
    }

    return success;
}

int RunAttachLoop(int iterations, int delayMs)
{
    int exitCode = 1;

    if (iterations < 1)
    {
        iterations = 1;
    }

    if (delayMs < 1)
    {
        delayMs = 1;
    }

    do
    {
        std::cout << "knmon-sample-fileio attach-loop-ready pid=" << GetCurrentProcessId() << "\n" << std::flush;
        Sleep(static_cast<DWORD>(delayMs));

        for (int iteration = 0; iteration < iterations; ++iteration)
        {
            if (!RunAttachFileIoProbe(iteration))
            {
                break;
            }

            Sleep(static_cast<DWORD>(delayMs));
        }

        exitCode = 0;
    }
    while (false);

    std::cout << "knmon-sample-fileio attach-loop-exiting code=" << exitCode << "\n";
    return exitCode;
}

std::wstring GetExecutablePath()
{
    std::array<wchar_t, MAX_PATH * 4> path = {};
    std::wstring result;

    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length > 0 && length < path.size())
    {
        result.assign(path.data(), length);
    }

    return result;
}

int RunSpawnChildLoop(int childCount, int childIterations, int delayMs, const std::wstring& requestedChildPath)
{
    int exitCode = 1;
    std::vector<HANDLE> childHandles;
    const std::wstring currentExecutablePath = GetExecutablePath();
    const std::wstring childExecutablePath = requestedChildPath.empty() ? currentExecutablePath : requestedChildPath;

    if (childCount < 1)
    {
        childCount = 1;
    }

    if (childCount > 4)
    {
        childCount = 4;
    }

    if (childIterations < 1)
    {
        childIterations = 1;
    }

    if (delayMs < 1)
    {
        delayMs = 1;
    }

    do
    {
        if (childExecutablePath.empty())
        {
            LogLastError("GetModuleFileNameW");
            break;
        }

        std::cout << "knmon-sample-fileio tree-root-ready pid=" << GetCurrentProcessId() << "\n" << std::flush;
        Sleep(static_cast<DWORD>(delayMs));

        for (int index = 0; index < childCount; ++index)
        {
            std::wstring commandLine = L"\"";
            commandLine += childExecutablePath;
            commandLine += L"\" --attach-loop --iterations ";
            commandLine += std::to_wstring(childIterations);
            commandLine += L" --delay-ms ";
            commandLine += std::to_wstring(delayMs);

            std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
            mutableCommandLine.push_back(L'\0');

            STARTUPINFOW startupInfo = {};
            PROCESS_INFORMATION processInfo = {};
            startupInfo.cb = sizeof(startupInfo);

            const BOOL created = CreateProcessW(
                childExecutablePath.c_str(),
                mutableCommandLine.data(),
                nullptr,
                nullptr,
                FALSE,
                CREATE_NO_WINDOW,
                nullptr,
                nullptr,
                &startupInfo,
                &processInfo);

            if (!created)
            {
                LogLastError("CreateProcessW(child)");
                break;
            }

            if (processInfo.hThread != nullptr)
            {
                CloseHandle(processInfo.hThread);
            }

            childHandles.push_back(processInfo.hProcess);
            std::cout << "knmon-sample-fileio child-started pid=" << processInfo.dwProcessId << "\n" << std::flush;
            Sleep(static_cast<DWORD>(delayMs));
        }

        if (static_cast<int>(childHandles.size()) != childCount)
        {
            break;
        }

        exitCode = 0;
        for (HANDLE childHandle : childHandles)
        {
            const DWORD waitResult = WaitForSingleObject(childHandle, INFINITE);
            DWORD childExitCode = 1;
            if (waitResult != WAIT_OBJECT_0 || !GetExitCodeProcess(childHandle, &childExitCode) || childExitCode != 0)
            {
                exitCode = 1;
            }
        }
    }
    while (false);

    for (HANDLE childHandle : childHandles)
    {
        if (childHandle != nullptr)
        {
            CloseHandle(childHandle);
        }
    }

    std::cout << "knmon-sample-fileio tree-root-exiting code=" << exitCode << "\n" << std::flush;
    return exitCode;
}

bool RunTier1SystemProbe()
{
    SYSTEMTIME systemTime = {};
    GetSystemTime(&systemTime);
    std::cout << "tier1 system probe year=" << systemTime.wYear << "\n";
    return systemTime.wYear >= 2024;
}

bool RunTier1DevicesProbe()
{
    std::array<wchar_t, 64> className = {};
    DWORD requiredSize = 0;
    const BOOL ok = SetupDiClassNameFromGuidW(
        &GUID_DEVCLASS_DISKDRIVE,
        className.data(),
        static_cast<DWORD>(className.size()),
        &requiredSize);
    std::cout << "tier1 devices probe ok=" << ok << " required=" << requiredSize << "\n";
    return ok != FALSE;
}

bool RunTier1UiProbe()
{
    POINT point = {};
    const BOOL ok = GetCursorPos(&point);
    std::cout << "tier1 ui probe ok=" << ok << "\n";
    return true;
}

bool RunTier1NetworkManagementProbe()
{
    MIB_IPSTATS statistics = {};
    const DWORD status = GetIpStatistics(&statistics);
    std::cout << "tier1 network-management probe status=" << status << "\n";
    return status == NO_ERROR;
}

bool RunTier1GraphicsProbe()
{
    HGDIOBJ object = GetStockObject(WHITE_BRUSH);
    std::cout << "tier1 graphics probe object=" << object << "\n";
    return object != nullptr;
}

bool RunTier2ApiSetProbe()
{
    bool success = false;
    HSTRING value = nullptr;

    do
    {
        const HRESULT createResult = WindowsCreateString(L"knmon", 5, &value);
        if (FAILED(createResult))
        {
            std::cout << "WindowsCreateString failed with " << HexHResult(createResult) << "\n";
            break;
        }

        const UINT32 length = WindowsGetStringLen(value);
        std::cout << "tier2 api-set probe length=" << length << "\n";
        if (length != 5)
        {
            break;
        }

        success = true;
    }
    while (false);

    if (value != nullptr)
    {
        const HRESULT deleteResult = WindowsDeleteString(value);
        if (FAILED(deleteResult))
        {
            std::cout << "WindowsDeleteString failed with " << HexHResult(deleteResult) << "\n";
            success = false;
        }
    }

    return success;
}

bool RunTier2MissingMetadataProbe()
{
    const BOOL result = RevertToSelf();
    const DWORD lastError = GetLastError();
    std::cout << "tier2 missing-metadata probe revert=" << result << "\n";
    if (!result)
    {
        std::cout << "RevertToSelf failed with " << lastError << "\n";
    }

    return result != FALSE;
}

int RunFileIo(bool slow)
{
    int exitCode = 1;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    const std::wstring path = BuildSamplePath();
    const char payload[] = "KNMon sample File I/O payload\n";
    std::array<char, 128> readBuffer = {};

    do
    {
        std::cout << "knmon-sample-fileio starting\n";

        if (slow)
        {
            Sleep(500);
        }

        if (!RunTier1SystemProbe())
        {
            break;
        }

        if (!RunTier1DevicesProbe())
        {
            break;
        }

        if (!RunTier1UiProbe())
        {
            break;
        }

        if (!RunTier1NetworkManagementProbe())
        {
            break;
        }

        if (!RunTier1GraphicsProbe())
        {
            break;
        }

        if (!RunTier2ApiSetProbe())
        {
            break;
        }

        if (!RunTier2MissingMetadataProbe())
        {
            break;
        }

        fileHandle = CreateFileW(
            path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            LogLastError("CreateFileW");
            break;
        }

        DWORD bytesWritten = 0;
        if (!WriteFile(fileHandle, payload, static_cast<DWORD>(sizeof(payload) - 1), &bytesWritten, nullptr))
        {
            LogLastError("WriteFile");
            break;
        }

        if (SetFilePointer(fileHandle, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
        {
            LogLastError("SetFilePointer");
            break;
        }

        DWORD bytesRead = 0;
        if (!ReadFile(fileHandle, readBuffer.data(), static_cast<DWORD>(readBuffer.size() - 1), &bytesRead, nullptr))
        {
            LogLastError("ReadFile");
            break;
        }

        std::cout << "file roundtrip bytes_written=" << bytesWritten << " bytes_read=" << bytesRead << "\n";

        CloseHandle(fileHandle);
        fileHandle = INVALID_HANDLE_VALUE;

        if (!RunNtCreateFileProbe(path))
        {
            break;
        }

        if (!RunDynamicLoadProbe())
        {
            break;
        }

        if (!RunRegistryProbe())
        {
            break;
        }

        if (!RunTokenQueryProbe())
        {
            break;
        }

        if (!RunRpcBindingProbe())
        {
            break;
        }

        if (!RunRpcUuidProbe())
        {
            break;
        }

        if (!RunBcryptProbe())
        {
            break;
        }

        if (!RunCrypt32Probe())
        {
            break;
        }

        if (!RunWinHttpProbe())
        {
            break;
        }

        if (!RunWinInetProbe())
        {
            break;
        }

        if (!RunUserGdiProbe())
        {
            break;
        }

        if (!RunPsapiModuleQueryProbe())
        {
            break;
        }

        if (!RunVersionResourceProbe())
        {
            break;
        }

        if (!RunOle32ComLifecycleProbe())
        {
            break;
        }

        if (!RunOleAutomationLifecycleProbe())
        {
            break;
        }

        if (!RunSecur32CredentialFreeProbe())
        {
            break;
        }

        if (!RunDnsRecordLifecycleProbe())
        {
            break;
        }

        if (!RunSetupApiDeviceInfoSetLifecycleProbe())
        {
            break;
        }

        if (!RunUserenvEnvironmentBlockLifecycleProbe())
        {
            break;
        }

        if (!RunIphlpapiAdapterAddressesProbe())
        {
            break;
        }

        if (!RunIphlpapiInterfaceEntryQueryProbe())
        {
            break;
        }

        if (!RunShlwapiPathExistsProbe())
        {
            break;
        }

        if (!RunCombaseWinRtLifecycleProbe())
        {
            break;
        }

        if (!RunMemoryProtectionProbe())
        {
            break;
        }

        if (!RunFileMappingProbe())
        {
            break;
        }

        if (!RunHandleMetadataProbe())
        {
            break;
        }

        if (!RunFileMetadataProbe())
        {
            break;
        }

        if (!RunDbgHelpSymbolSessionProbe())
        {
            break;
        }

        if (!RunModuleLifecycleProbe())
        {
            break;
        }

        if (!RunProcessThreadIdentityProbe())
        {
            break;
        }

        if (!RunThreadLifecycleProbe())
        {
            break;
        }

        if (!RunEventSynchronizationProbe())
        {
            break;
        }

        if (!RunMutexSemaphoreProbe())
        {
            break;
        }

        if (!RunShellKnownFolderProbe())
        {
            break;
        }

        if (!RunWinsockProbe())
        {
            break;
        }

        HANDLE missingHandle = CreateFileW(
            L"C:\\Windows\\System32\\drivers\\etc\\knmon-missing-file-do-not-create.dat",
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (missingHandle == INVALID_HANDLE_VALUE)
        {
            std::cout << "expected missing file error=" << GetLastError() << "\n";
        }
        else
        {
            CloseHandle(missingHandle);
        }

        HANDLE missingAnsiHandle = CreateFileA(
            "C:\\Windows\\System32\\drivers\\etc\\knmon-missing-file-do-not-create-a.dat",
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (missingAnsiHandle == INVALID_HANDLE_VALUE)
        {
            std::cout << "expected missing ansi file error=" << GetLastError() << "\n";
        }
        else
        {
            CloseHandle(missingAnsiHandle);
        }

        if (slow)
        {
            Sleep(1500);
        }

        DeleteFileW(path.c_str());
        exitCode = 0;
    }
    while (false);

    if (fileHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(fileHandle);
    }

    std::cout << "knmon-sample-fileio exiting code=" << exitCode << "\n";
    return exitCode;
}
}

int wmain(int argc, wchar_t** argv)
{
    if (HasOption(argc, argv, L"--attach-loop"))
    {
        return RunAttachLoop(
            GetIntOption(argc, argv, L"--iterations", 16),
            GetIntOption(argc, argv, L"--delay-ms", 250));
    }

    if (HasOption(argc, argv, L"--spawn-child-loop"))
    {
        return RunSpawnChildLoop(
            GetIntOption(argc, argv, L"--children", 1),
            GetIntOption(argc, argv, L"--child-iterations", 24),
            GetIntOption(argc, argv, L"--delay-ms", 150),
            GetStringOption(argc, argv, L"--child-path", L""));
    }

    return RunFileIo(HasOption(argc, argv, L"--slow"));
}
