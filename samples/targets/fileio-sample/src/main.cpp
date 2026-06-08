#include <Windows.h>

#include <array>
#include <iostream>
#include <string>

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
