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

extern "C" __declspec(dllexport) DWORD KnMonDynamicProbeWaitForIat()
{
    const HMODULE agent = GetModuleHandleW(sizeof(void*) == 8 ? L"knmon-agent64.dll" : L"knmon-agent32.dll");
    const ULONGLONG deadline = GetTickCount64() + 5000;
    bool observed = false;
    do
    {
        HMODULE owner = nullptr;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            reinterpret_cast<LPCWSTR>(&CreateFileW), &owner))
        {
            observed = agent != nullptr && owner == agent;
            FreeLibrary(owner);
        }
        if (observed)
        {
            break;
        }
        Sleep(5);
    }
    while (GetTickCount64() < deadline);
    return observed ? 0 : ERROR_TIMEOUT;
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
