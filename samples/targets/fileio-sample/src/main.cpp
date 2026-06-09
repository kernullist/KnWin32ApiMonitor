#include <Windows.h>
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
