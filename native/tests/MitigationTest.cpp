#include <Windows.h>
#include <array>
#include <cstdio>
#include <string>

extern "C" __declspec(noinline) int AllowedProbe()
{
    return 73;
}

extern "C" __declspec(noinline) __declspec(guard(suppress)) int SuppressedProbe()
{
    return 97;
}

namespace
{
using Probe = int(*)();

bool RunProbe(const wchar_t* mode, DWORD expectedExit)
{
    bool passed = false;
    std::array<wchar_t, 32768> path = {};
    PROCESS_INFORMATION process = {};
    do
    {
        const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0 || length >= path.size())
        {
            break;
        }
        std::wstring command = L"\"" + std::wstring(path.data()) + L"\" " + mode;
        STARTUPINFOW startup = {};
        startup.cb = sizeof(startup);
        if (!CreateProcessW(path.data(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startup, &process))
        {
            break;
        }
        DWORD exitCode = 0;
        passed = WaitForSingleObject(process.hProcess, 5000) == WAIT_OBJECT_0 &&
            GetExitCodeProcess(process.hProcess, &exitCode) && exitCode == expectedExit;
        if (!passed)
        {
            std::fprintf(stderr, "Mitigation probe failed: expected=%08lx actual=%08lx\n", expectedExit, exitCode);
        }
    }
    while (false);
    if (process.hProcess != nullptr)
    {
        if (WaitForSingleObject(process.hProcess, 0) != WAIT_OBJECT_0)
        {
            TerminateProcess(process.hProcess, 99);
            WaitForSingleObject(process.hProcess, 5000);
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    return passed;
}
}

int wmain(int argc, wchar_t** argv)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc == 2 && wcscmp(argv[1], L"--cig-target") == 0)
    {
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = {};
        policy.MicrosoftSignedOnly = 1;
        if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &policy, sizeof(policy)))
        {
            std::fprintf(stderr, "CIG policy could not be enabled: %lu\n", GetLastError());
            return 1;
        }
        std::puts("cig-target-ready");
        std::fflush(stdout);
        const int command = std::getchar();
        if (GetModuleHandleW(L"knmon-agent64.dll") != nullptr || GetModuleHandleW(L"knmon-agent32.dll") != nullptr)
        {
            return 5;
        }
        return command == 'q' ? 0 : 2;
    }
    if (argc == 2 && (wcscmp(argv[1], L"--allowed") == 0 || wcscmp(argv[1], L"--suppressed") == 0))
    {
        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY policy = {};
        if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &policy, sizeof(policy)) ||
            !policy.EnableControlFlowGuard)
        {
            return 3;
        }
        // Volatile prevents optimization from turning the negative probe into a direct call.
        Probe volatile probe = wcscmp(argv[1], L"--allowed") == 0 ? AllowedProbe : SuppressedProbe;
        return probe() == 73 ? 0 : 4;
    }
    const bool passed = RunProbe(L"--allowed", 0) && RunProbe(L"--suppressed", 0xc0000409);
    if (passed)
    {
        std::puts("CFG accepts the valid target and terminates the suppressed indirect call.");
    }
    return passed ? 0 : 1;
}
