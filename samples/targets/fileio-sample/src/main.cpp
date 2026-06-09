#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <rpc.h>
#include <winternl.h>

#include <array>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
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

bool HasSlowOption(int argc, wchar_t** argv)
{
    bool slow = false;

    for (int index = 1; index < argc; ++index)
    {
        if (std::wstring(argv[index]) == L"--slow")
        {
            slow = true;
            break;
        }
    }

    return slow;
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

bool RunWinsockProbe()
{
    bool success = false;
    bool started = false;
    WSADATA wsaData = {};
    ADDRINFOA hints = {};
    PADDRINFOA results = nullptr;
    SOCKET socketHandle = INVALID_SOCKET;

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

        const int lastError = WSAGetLastError();
        std::cout << "winsock probe last_error=" << lastError << "\n";
        success = true;
    }
    while (false);

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

        if (!RunRpcBindingProbe())
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
    return RunFileIo(HasSlowOption(argc, argv));
}
