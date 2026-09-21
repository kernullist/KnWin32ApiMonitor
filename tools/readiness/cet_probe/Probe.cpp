#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <string>
#include <vector>

extern "C" int KnMonCetAllowedReturn();
extern "C" int KnMonCetMismatchedReturn();

namespace
{
class Handle
{
public:
    HANDLE Value = nullptr;
    Handle() = default;
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle()
    {
        Reset();
    }
    void Reset()
    {
        if (Value != nullptr && Value != INVALID_HANDLE_VALUE)
        {
            CloseHandle(Value);
        }
        Value = nullptr;
    }
};

struct ExceptionRecord
{
    DWORD Code = 0;
    DWORD FirstChance = 0;
    DWORD ThreadId = 0;
    std::vector<ULONG_PTR> Parameters;
};

struct Observation
{
    const char* Name = nullptr;
    const char* ErrorStage = "none";
    DWORD Error = 0;
    DWORD ProcessId = 0;
    DWORD ThreadId = 0;
    ULONGLONG CreationTime = 0;
    ULONGLONG RequestedPolicy = 0;
    DWORD ParentPolicyFlags = 0;
    bool ParentPolicyRead = false;
    DWORD ParentPolicyError = 0;
    bool ObservedExit = false;
    bool ExitCodeRead = false;
    DWORD ExitCode = 0;
    DWORD DebugExitCode = 0;
    DWORD DebugEvents = 0;
    bool ForcedCleanup = false;
    bool CleanupSucceeded = false;
    bool JobAssigned = false;
    bool JobAccountingRead = false;
    DWORD JobActiveProcesses = 0;
    std::string Output;
    std::vector<ExceptionRecord> Exceptions;
};

void PrintString(const std::string& value)
{
    std::putchar('"');
    for (const unsigned char character : value)
    {
        if (character == '"' || character == '\\')
        {
            std::putchar('\\');
            std::putchar(character);
        }
        else if (character < 32 || character > 126)
        {
            std::printf("\\u%04x", static_cast<unsigned int>(character));
        }
        else
        {
            std::putchar(character);
        }
    }
    std::putchar('"');
}

bool DrainOutput(HANDLE pipe, std::string& output)
{
    bool success = false;
    do
    {
        DWORD available = 0;
        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr))
        {
            success = GetLastError() == ERROR_BROKEN_PIPE;
            break;
        }
        if (available == 0)
        {
            success = true;
            break;
        }
        if (output.size() >= 65536)
        {
            SetLastError(ERROR_BUFFER_OVERFLOW);
            break;
        }
        std::array<char, 4096> bytes = {};
        DWORD count = 0;
        const DWORD capacity = static_cast<DWORD>(65536 - output.size());
        const DWORD requested = (std::min)((std::min)(available, capacity), static_cast<DWORD>(bytes.size()));
        if (!ReadFile(pipe, bytes.data(), requested, &count, nullptr))
        {
            break;
        }
        if (count == 0)
        {
            SetLastError(ERROR_INVALID_DATA);
            break;
        }
        output.append(bytes.data(), count);
    }
    while (true);
    return success;
}

void CloseDebugFile(const DEBUG_EVENT& event)
{
    HANDLE file = nullptr;
    if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
    {
        file = event.u.CreateProcessInfo.hFile;
    }
    else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
    {
        file = event.u.LoadDll.hFile;
    }
    if (file != nullptr && file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
    // Debug-event process/thread handles are closed by Windows after exit continuation.
}

Observation Observe(const wchar_t* executable, bool strict, bool mismatch, const wchar_t* control = nullptr)
{
    Observation result;
    result.Name = strict ? (mismatch ? "strict-mismatch" : "strict-valid") : (mismatch ? "off-mismatch" : "off-valid");
    if (control != nullptr)
    {
        result.Name = wcscmp(control, L"wait") == 0 ? "timeout-control" : "output-control";
    }
    result.RequestedPolicy = strict ? PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_STRICT_MODE :
        PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_ALWAYS_OFF;
    Handle job;
    Handle reader;
    Handle writer;
    Handle input;
    Handle process;
    Handle thread;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = nullptr;
    std::array<DWORD64, 2> mitigation = {0, result.RequestedPolicy};
    std::array<HANDLE, 2> inherited = {};
    bool initialized = false;
    bool debugConnected = false;
    bool breakpointSeen = false;
    do
    {
        result.ErrorStage = "job";
        job.Value = CreateJobObjectW(nullptr, nullptr);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (job.Value == nullptr || !SetInformationJobObject(job.Value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        {
            result.Error = GetLastError();
            break;
        }
        result.ErrorStage = "pipe";
        SECURITY_ATTRIBUTES security = {sizeof(security), nullptr, TRUE};
        if (!CreatePipe(&reader.Value, &writer.Value, &security, 65536) ||
            !SetHandleInformation(reader.Value, HANDLE_FLAG_INHERIT, 0))
        {
            result.Error = GetLastError();
            break;
        }
        input.Value = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr);
        if (input.Value == INVALID_HANDLE_VALUE)
        {
            result.Error = GetLastError();
            break;
        }
        result.ErrorStage = "attributes";
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, 2, 0, &size);
        attributes = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, size));
        if (attributes == nullptr)
        {
            result.Error = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }
        if (!InitializeProcThreadAttributeList(attributes, 2, 0, &size))
        {
            result.Error = GetLastError();
            break;
        }
        initialized = true;
        inherited = {writer.Value, input.Value};
        if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, mitigation.data(), sizeof(mitigation), nullptr, nullptr) ||
            !UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(), sizeof(inherited), nullptr, nullptr))
        {
            result.Error = GetLastError();
            break;
        }
        STARTUPINFOEXW startup = {};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        startup.StartupInfo.wShowWindow = SW_HIDE;
        startup.StartupInfo.hStdInput = input.Value;
        startup.StartupInfo.hStdOutput = writer.Value;
        startup.StartupInfo.hStdError = writer.Value;
        startup.lpAttributeList = attributes;
        std::wstring command = L"\"" + std::wstring(executable) + L"\" --child ";
        command += strict ? L"strict " : L"off ";
        command += control != nullptr ? control : (mismatch ? L"mismatch" : L"valid");
        PROCESS_INFORMATION created = {};
        result.ErrorStage = "create";
        if (!CreateProcessW(executable, command.data(), nullptr, nullptr, TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW | DEBUG_ONLY_THIS_PROCESS,
            nullptr, nullptr, &startup.StartupInfo, &created))
        {
            result.Error = GetLastError();
            break;
        }
        process.Value = created.hProcess;
        thread.Value = created.hThread;
        result.ProcessId = created.dwProcessId;
        result.ThreadId = created.dwThreadId;
        debugConnected = true;
        writer.Reset();
        result.ErrorStage = "debug-exit-policy";
        if (!DebugSetProcessKillOnExit(TRUE))
        {
            result.Error = GetLastError();
            break;
        }
        result.ErrorStage = "ownership";
        FILETIME creation = {}, exit = {}, kernel = {}, user = {};
        if (!AssignProcessToJobObject(job.Value, process.Value) ||
            !GetProcessTimes(process.Value, &creation, &exit, &kernel, &user))
        {
            result.Error = GetLastError();
            break;
        }
        BOOL assigned = FALSE;
        if (!IsProcessInJob(process.Value, job.Value, &assigned) || !assigned)
        {
            result.Error = ERROR_INVALID_DATA;
            break;
        }
        result.JobAssigned = true;
        result.CreationTime = (static_cast<ULONGLONG>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
        result.ErrorStage = "resume";
        if (ResumeThread(thread.Value) == static_cast<DWORD>(-1))
        {
            result.Error = GetLastError();
            break;
        }
        result.ErrorStage = "debug";
        const ULONGLONG deadline = GetTickCount64() + (control != nullptr ? 2000 : 10000);
        while (!result.ObservedExit && result.Error == 0)
        {
            if (GetTickCount64() >= deadline || result.DebugEvents >= 4096)
            {
                result.Error = ERROR_TIMEOUT;
                break;
            }
            if (!DrainOutput(reader.Value, result.Output))
            {
                result.Error = GetLastError();
                break;
            }
            DEBUG_EVENT event = {};
            if (!WaitForDebugEvent(&event, 50))
            {
                const DWORD error = GetLastError();
                if (error != ERROR_SEM_TIMEOUT)
                {
                    result.Error = error;
                }
                continue;
            }
            ++result.DebugEvents;
            CloseDebugFile(event);
            DWORD continuation = DBG_CONTINUE;
            if (event.dwProcessId != result.ProcessId)
            {
                result.Error = ERROR_INVALID_DATA;
            }
            if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
            {
                const auto& exception = event.u.Exception.ExceptionRecord;
                if (result.Exceptions.size() >= 32 || exception.NumberParameters > EXCEPTION_MAXIMUM_PARAMETERS)
                {
                    result.Error = ERROR_BUFFER_OVERFLOW;
                }
                else
                {
                    result.Exceptions.push_back({exception.ExceptionCode, event.u.Exception.dwFirstChance, event.dwThreadId,
                        {exception.ExceptionInformation, exception.ExceptionInformation + exception.NumberParameters}});
                }
                continuation = DBG_EXCEPTION_NOT_HANDLED;
                if (!breakpointSeen && exception.ExceptionCode == EXCEPTION_BREAKPOINT && event.u.Exception.dwFirstChance != 0)
                {
                    breakpointSeen = true;
                    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY policy = {};
                    result.ParentPolicyRead = GetProcessMitigationPolicy(process.Value, ProcessUserShadowStackPolicy, &policy, sizeof(policy)) != FALSE;
                    result.ParentPolicyFlags = policy.Flags;
                    result.ParentPolicyError = result.ParentPolicyRead ? 0 : GetLastError();
                    continuation = DBG_CONTINUE;
                }
            }
            if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            {
                result.ObservedExit = true;
                result.DebugExitCode = event.u.ExitProcess.dwExitCode;
            }
            if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation))
            {
                result.Error = GetLastError();
            }
            else if (result.ObservedExit)
            {
                debugConnected = false;
            }
        }
        if (result.Error == 0 && !DrainOutput(reader.Value, result.Output))
        {
            result.Error = GetLastError();
        }
        if (result.Error == 0)
        {
            result.ErrorStage = "none";
        }
    }
    while (false);
    if (process.Value != nullptr)
    {
        if (!result.ObservedExit || result.Error != 0)
        {
            result.ForcedCleanup = true;
            TerminateProcess(process.Value, 99);
        }
        if (debugConnected)
        {
            DebugActiveProcessStop(result.ProcessId);
        }
        result.CleanupSucceeded = WaitForSingleObject(process.Value, 5000) == WAIT_OBJECT_0;
        result.ExitCodeRead = GetExitCodeProcess(process.Value, &result.ExitCode) != FALSE;
    }
    else
    {
        result.CleanupSucceeded = true;
    }
    if (job.Value != nullptr)
    {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting = {};
        result.JobAccountingRead = QueryInformationJobObject(job.Value, JobObjectBasicAccountingInformation,
            &accounting, sizeof(accounting), nullptr) != FALSE;
        const ULONGLONG naturalDeadline = GetTickCount64() + 2000;
        while (result.JobAccountingRead && accounting.ActiveProcesses != 0 && GetTickCount64() < naturalDeadline)
        {
            Sleep(10);
            result.JobAccountingRead = QueryInformationJobObject(job.Value, JobObjectBasicAccountingInformation,
                &accounting, sizeof(accounting), nullptr) != FALSE;
        }
        if (result.JobAccountingRead && accounting.ActiveProcesses != 0)
        {
            result.ForcedCleanup = true;
            TerminateJobObject(job.Value, 99);
            const ULONGLONG deadline = GetTickCount64() + 2000;
            do
            {
                Sleep(10);
                result.JobAccountingRead = QueryInformationJobObject(job.Value, JobObjectBasicAccountingInformation,
                    &accounting, sizeof(accounting), nullptr) != FALSE;
            }
            while (result.JobAccountingRead && accounting.ActiveProcesses != 0 && GetTickCount64() < deadline);
        }
        result.JobActiveProcesses = accounting.ActiveProcesses;
        result.CleanupSucceeded = result.CleanupSucceeded && result.JobAccountingRead && accounting.ActiveProcesses == 0;
    }
    if (initialized)
    {
        DeleteProcThreadAttributeList(attributes);
    }
    if (attributes != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, attributes);
    }
    return result;
}

void PrintObservation(const Observation& value)
{
    std::printf("{\"name\":\"%s\",\"errorStage\":\"%s\",\"error\":%lu,\"processId\":%lu,\"threadId\":%lu,\"creationTime100ns\":\"%llu\","
        "\"requestedPolicy\":%llu,\"parentPolicyRead\":%s,\"parentPolicyFlags\":%lu,\"parentPolicyError\":%lu,"
        "\"observedExit\":%s,\"exitCodeRead\":%s,\"exitCode\":%lu,\"debugExitCode\":%lu,\"debugEvents\":%lu,"
        "\"forcedCleanup\":%s,\"cleanupSucceeded\":%s,\"jobAssigned\":%s,\"jobAccountingRead\":%s,\"jobActiveProcesses\":%lu,\"output\":",
        value.Name, value.ErrorStage, value.Error, value.ProcessId, value.ThreadId, value.CreationTime, value.RequestedPolicy,
        value.ParentPolicyRead ? "true" : "false", value.ParentPolicyFlags, value.ParentPolicyError,
        value.ObservedExit ? "true" : "false", value.ExitCodeRead ? "true" : "false", value.ExitCode,
        value.DebugExitCode, value.DebugEvents, value.ForcedCleanup ? "true" : "false", value.CleanupSucceeded ? "true" : "false",
        value.JobAssigned ? "true" : "false", value.JobAccountingRead ? "true" : "false", value.JobActiveProcesses);
    PrintString(value.Output);
    std::printf(",\"exceptions\":[");
    for (size_t index = 0; index < value.Exceptions.size(); ++index)
    {
        const auto& exception = value.Exceptions[index];
        std::printf("%s{\"code\":%lu,\"firstChance\":%lu,\"threadId\":%lu,\"parameters\":[", index == 0 ? "" : ",",
            exception.Code, exception.FirstChance, exception.ThreadId);
        for (size_t parameter = 0; parameter < exception.Parameters.size(); ++parameter)
        {
            std::printf("%s%llu", parameter == 0 ? "" : ",", static_cast<ULONGLONG>(exception.Parameters[parameter]));
        }
        std::printf("]}");
    }
    std::printf("]}");
}
}

int wmain(int argc, wchar_t** argv)
{
    int result = 1;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    do
    {
        if (argc == 4 && wcscmp(argv[1], L"--child") == 0 &&
            (wcscmp(argv[2], L"strict") == 0 || wcscmp(argv[2], L"off") == 0) &&
            (wcscmp(argv[3], L"mismatch") == 0 || wcscmp(argv[3], L"valid") == 0 ||
             wcscmp(argv[3], L"wait") == 0 || wcscmp(argv[3], L"flood") == 0))
        {
            const bool strict = wcscmp(argv[2], L"strict") == 0;
            const bool mismatch = wcscmp(argv[3], L"mismatch") == 0;
            PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY policy = {};
            const bool queried = GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy, &policy, sizeof(policy)) != FALSE;
            const DWORD error = queried ? 0 : GetLastError();
            std::printf("{\"phase\":\"before\",\"processId\":%lu,\"threadId\":%lu,\"queried\":%s,\"flags\":%lu,\"error\":%lu,\"strict\":%s,\"mismatch\":%s}\n",
                GetCurrentProcessId(), GetCurrentThreadId(), queried ? "true" : "false", policy.Flags, error,
                strict ? "true" : "false", mismatch ? "true" : "false");
            std::fflush(stdout);
            if (!queried || (strict ? (!policy.EnableUserShadowStack || !policy.EnableUserShadowStackStrictMode || policy.AuditUserShadowStack) :
                (policy.EnableUserShadowStack || policy.EnableUserShadowStackStrictMode)))
            {
                result = 77;
                break;
            }
            if (wcscmp(argv[3], L"wait") == 0)
            {
                Sleep(INFINITE);
            }
            if (wcscmp(argv[3], L"flood") == 0)
            {
                const std::string flood(100000, 'x');
                std::fwrite(flood.data(), 1, flood.size(), stdout);
                std::fflush(stdout);
                Sleep(INFINITE);
            }
            const int returned = mismatch ? KnMonCetMismatchedReturn() : KnMonCetAllowedReturn();
            std::printf("{\"phase\":\"after\",\"returned\":%d}\n", returned);
            result = returned == 73 ? 0 : 3;
            break;
        }
        const wchar_t* control = nullptr;
        if (argc == 2 && wcscmp(argv[1], L"--timeout-control") == 0)
        {
            control = L"wait";
        }
        else if (argc == 2 && wcscmp(argv[1], L"--output-control") == 0)
        {
            control = L"flood";
        }
        else if (argc != 1)
        {
            break;
        }
        std::array<wchar_t, 32768> executable = {};
        const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        if (length == 0 || length >= executable.size())
        {
            break;
        }
        std::printf("{\"schemaVersion\":1,\"kind\":\"%s\",\"architecture\":\"x64\",\"cases\":[",
            control == nullptr ? "observed" : "cleanup-control");
        for (int index = 0; index < (control == nullptr ? 4 : 1); ++index)
        {
            if (index != 0)
            {
                std::putchar(',');
            }
            PrintObservation(Observe(executable.data(), index >= 2, (index % 2) != 0, control));
        }
        std::printf("]}\n");
        result = std::ferror(stdout) == 0 ? 0 : 1;
    }
    while (false);
    return result;
}
