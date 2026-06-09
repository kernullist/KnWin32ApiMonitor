#include <Windows.h>

#include <array>
#include <string>

namespace
{
std::wstring BuildProbePath()
{
    std::array<wchar_t, MAX_PATH> tempPath = {};
    std::wstring result;

    do
    {
        const DWORD length = GetTempPathW(static_cast<DWORD>(tempPath.size()), tempPath.data());
        if (length == 0 || length >= tempPath.size())
        {
            result = L".\\knmon-dynamic-probe.dat";
            break;
        }

        result.assign(tempPath.data(), length);
        result += L"knmon-dynamic-probe.dat";
    }
    while (false);

    return result;
}
}

extern "C" __declspec(dllexport) DWORD KnMonDynamicProbe()
{
    DWORD result = 1;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    const std::wstring path = BuildProbePath();
    const char payload[] = "KNMon dynamic probe payload\n";

    do
    {
        fileHandle = CreateFileW(
            path.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            break;
        }

        DWORD bytesWritten = 0;
        if (!WriteFile(fileHandle, payload, static_cast<DWORD>(sizeof(payload) - 1), &bytesWritten, nullptr))
        {
            break;
        }

        result = 0;
    }
    while (false);

    if (fileHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(fileHandle);
    }

    DeleteFileW(path.c_str());
    return result;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    (void)module;
    (void)reason;
    (void)reserved;
    return TRUE;
}
