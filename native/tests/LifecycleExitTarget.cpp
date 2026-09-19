#include <Windows.h>

#include <iostream>
#include <cwchar>

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2 && argc != 3)
    {
        return 1;
    }
    HMODULE agent = LoadLibraryW(argv[1]);
    if (argc == 3)
    {
        auto testRace = agent == nullptr ? nullptr : reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(agent, "KnMonTestStopRace"));
        if (testRace == nullptr)
        {
            return 4;
        }
        const DWORD result = testRace(std::wcscmp(argv[2], L"commit") == 0 ? reinterpret_cast<void*>(1) : nullptr);
        std::cout << "Agent stop race result: " << result << "\n";
        return static_cast<int>(result);
    }
    auto holdLocks = agent == nullptr ? nullptr : reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(agent, "KnMonTestHoldTeardownLocks"));
    if (holdLocks == nullptr)
    {
        return 2;
    }
    HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE thread = ready == nullptr ? nullptr : CreateThread(nullptr, 0, holdLocks, ready, 0, nullptr);
    if (thread == nullptr || WaitForSingleObject(ready, 5000) != WAIT_OBJECT_0)
    {
        return 3;
    }
    std::cout << "Process exit with abandoned agent hook and pipe locks.\n";
    ExitProcess(0);
}
