#include <knmon/core/Controller.h>

#include <Windows.h>
#include <TlHelp32.h>

#include <array>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace knmon
{
namespace
{
std::string WideToUtf8(const wchar_t* value)
{
    std::string result;

    do
    {
        if (value == nullptr)
        {
            break;
        }

        const int required = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
        if (required <= 1)
        {
            break;
        }

        result.resize(static_cast<std::size_t>(required - 1));
        const int converted = WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), required, nullptr, nullptr);
        if (converted <= 0)
        {
            result.clear();
            break;
        }
    }
    while (false);

    return result;
}

std::wstring Utf8ToWide(const std::string& value)
{
    std::wstring result;

    do
    {
        if (value.empty())
        {
            break;
        }

        const int required = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
        if (required <= 1)
        {
            break;
        }

        result.resize(static_cast<std::size_t>(required - 1));
        const int converted = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, result.data(), required);
        if (converted <= 0)
        {
            result.clear();
            break;
        }
    }
    while (false);

    return result;
}

std::string FormatWindowsError(DWORD errorCode)
{
    std::string result;
    LPWSTR message = nullptr;

    do
    {
        const DWORD length = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            0,
            reinterpret_cast<LPWSTR>(&message),
            0,
            nullptr);

        if (length == 0 || message == nullptr)
        {
            std::ostringstream stream;
            stream << "Windows error " << errorCode;
            result = stream.str();
            break;
        }

        result = WideToUtf8(message);
        while (!result.empty() && (result.back() == '\r' || result.back() == '\n' || result.back() == ' '))
        {
            result.pop_back();
        }
    }
    while (false);

    if (message != nullptr)
    {
        LocalFree(message);
    }

    return result;
}

std::string NowUtc()
{
    SYSTEMTIME time = {};
    GetSystemTime(&time);

    std::ostringstream stream;
    stream << std::setfill('0')
           << std::setw(4) << time.wYear << "-"
           << std::setw(2) << time.wMonth << "-"
           << std::setw(2) << time.wDay << "T"
           << std::setw(2) << time.wHour << ":"
           << std::setw(2) << time.wMinute << ":"
           << std::setw(2) << time.wSecond << "."
           << std::setw(3) << time.wMilliseconds << "Z";
    return stream.str();
}

std::string QueryProcessImagePath(DWORD processId)
{
    std::string result;
    HANDLE processHandle = nullptr;

    do
    {
        processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (processHandle == nullptr)
        {
            break;
        }

        wchar_t path[MAX_PATH * 8] = {};
        DWORD size = static_cast<DWORD>(std::size(path));
        if (!QueryFullProcessImageNameW(processHandle, 0, path, &size))
        {
            break;
        }

        result = WideToUtf8(path);
    }
    while (false);

    if (processHandle != nullptr)
    {
        CloseHandle(processHandle);
    }

    return result;
}

std::string QueryProcessArchitecture(DWORD processId)
{
    std::string result = "unknown";
    HANDLE processHandle = nullptr;

    do
    {
        processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (processHandle == nullptr)
        {
            break;
        }

        BOOL isWow64 = FALSE;
        if (!IsWow64Process(processHandle, &isWow64))
        {
            break;
        }

#if defined(_WIN64)
        if (isWow64)
        {
            result = "x86";
        }
        else
        {
            result = "x64";
        }
#else
        result = isWow64 ? "x86-wow64" : "x86";
#endif
    }
    while (false);

    if (processHandle != nullptr)
    {
        CloseHandle(processHandle);
    }

    return result;
}

bool FileExists(const std::string& path)
{
    bool exists = false;

    do
    {
        if (path.empty())
        {
            break;
        }

        const auto attributes = GetFileAttributesW(Utf8ToWide(path).c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            break;
        }

        exists = (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }
    while (false);

    return exists;
}

void AddAudit(
    KnMonLaunchResult& result,
    const std::string& eventType,
    const std::string& operation,
    const std::string& message,
    DWORD errorCode = 0,
    const std::string& subsystem = "knmon-core")
{
    KnMonAuditEvent event;
    event.OperationId = result.OperationId;
    event.EventType = eventType;
    event.TimestampUtc = NowUtc();
    event.Subsystem = subsystem;
    event.Operation = operation;
    event.Win32ErrorCode = errorCode;
    event.NtStatus = "0x00000000";
    event.Message = message;
    result.AuditEvents.push_back(event);
}

void SetResultError(
    KnMonLaunchResult& result,
    DWORD errorCode,
    const std::string& subsystem,
    const std::string& operation,
    const std::string& message)
{
    result.Success = false;
    result.Win32ErrorCode = errorCode;
    result.Subsystem = subsystem;
    result.Operation = operation;
    result.Message = message;
    AddAudit(result, operation, operation, message, errorCode, subsystem);
}

std::wstring QuoteArgument(const std::wstring& value)
{
    std::wstring result = L"\"";
    result += value;
    result += L"\"";
    return result;
}

class EnvironmentOverride
{
public:
    EnvironmentOverride(const wchar_t* name, const std::wstring& value) :
        m_name(name)
    {
        wchar_t buffer[32768] = {};
        const DWORD length = GetEnvironmentVariableW(m_name.c_str(), buffer, static_cast<DWORD>(std::size(buffer)));
        if (length > 0 && length < std::size(buffer))
        {
            m_hadOriginal = true;
            m_original.assign(buffer, length);
        }

        SetEnvironmentVariableW(m_name.c_str(), value.c_str());
    }

    ~EnvironmentOverride()
    {
        if (m_hadOriginal)
        {
            SetEnvironmentVariableW(m_name.c_str(), m_original.c_str());
        }
        else
        {
            SetEnvironmentVariableW(m_name.c_str(), nullptr);
        }
    }

private:
    std::wstring m_name;
    std::wstring m_original;
    bool m_hadOriginal = false;
};

bool WaitForPipeConnection(HANDLE pipeHandle, DWORD timeoutMs, DWORD* errorCode)
{
    bool connected = false;
    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    do
    {
        if (overlapped.hEvent == nullptr)
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        if (ConnectNamedPipe(pipeHandle, &overlapped))
        {
            connected = true;
            break;
        }

        const DWORD connectError = GetLastError();
        if (connectError == ERROR_PIPE_CONNECTED)
        {
            connected = true;
            break;
        }

        if (connectError != ERROR_IO_PENDING)
        {
            if (errorCode != nullptr)
            {
                *errorCode = connectError;
            }
            break;
        }

        const DWORD waitResult = WaitForSingleObject(overlapped.hEvent, timeoutMs);
        if (waitResult != WAIT_OBJECT_0)
        {
            CancelIo(pipeHandle);
            if (errorCode != nullptr)
            {
                *errorCode = waitResult == WAIT_TIMEOUT ? WAIT_TIMEOUT : GetLastError();
            }
            break;
        }

        DWORD bytes = 0;
        if (!GetOverlappedResult(pipeHandle, &overlapped, &bytes, FALSE))
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        connected = true;
    }
    while (false);

    if (overlapped.hEvent != nullptr)
    {
        CloseHandle(overlapped.hEvent);
    }

    return connected;
}

bool ReadPipeMessage(HANDLE pipeHandle, DWORD timeoutMs, std::string* payload, DWORD* errorCode)
{
    bool received = false;
    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::array<char, 4096> buffer = {};

    do
    {
        if (payload != nullptr)
        {
            payload->clear();
        }

        if (overlapped.hEvent == nullptr)
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        DWORD bytesRead = 0;
        if (!ReadFile(pipeHandle, buffer.data(), static_cast<DWORD>(buffer.size() - 1), &bytesRead, &overlapped))
        {
            const DWORD readError = GetLastError();
            if (readError != ERROR_IO_PENDING)
            {
                if (errorCode != nullptr)
                {
                    *errorCode = readError;
                }
                break;
            }

            const DWORD waitResult = WaitForSingleObject(overlapped.hEvent, timeoutMs);
            if (waitResult != WAIT_OBJECT_0)
            {
                CancelIo(pipeHandle);
                if (errorCode != nullptr)
                {
                    *errorCode = waitResult == WAIT_TIMEOUT ? WAIT_TIMEOUT : GetLastError();
                }
                break;
            }

            if (!GetOverlappedResult(pipeHandle, &overlapped, &bytesRead, FALSE))
            {
                if (errorCode != nullptr)
                {
                    *errorCode = GetLastError();
                }
                break;
            }
        }

        buffer[bytesRead] = '\0';
        if (payload != nullptr)
        {
            payload->assign(buffer.data(), bytesRead);
        }
        received = true;
    }
    while (false);

    if (overlapped.hEvent != nullptr)
    {
        CloseHandle(overlapped.hEvent);
    }

    return received;
}

KnMonAgentHandshake BuildHandshake(const KnMonLaunchResult& result, const std::string& rawPayload)
{
    KnMonAgentHandshake handshake;
    handshake.Received = true;
    handshake.SchemaVersion = "0.1.0";
    handshake.OperationId = result.OperationId;
    handshake.ProcessId = result.TargetProcessId;
    handshake.ThreadId = result.TargetThreadId;
    handshake.Architecture = result.Architecture;
    handshake.AgentVersion = "0.1.0";
    handshake.Message = "Agent HELLO received.";
    handshake.RawPayload = rawPayload;
    return handshake;
}

KnMonError NotImplementedError(const std::string& operation)
{
    KnMonError error;
    error.Code = ERROR_CALL_NOT_IMPLEMENTED;
    error.Subsystem = "knmon-core";
    error.Operation = operation;
    error.Message = "Operation is defined by the controller contract but is not implemented in the safe native-capture foundation.";
    return error;
}
}

std::vector<KnMonTargetProcess> Controller::EnumerateTargets(KnMonError* error) const
{
    std::vector<KnMonTargetProcess> processes;
    HANDLE snapshot = INVALID_HANDLE_VALUE;

    do
    {
        if (error != nullptr)
        {
            *error = {};
        }

        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                error->Code = GetLastError();
                error->Subsystem = "win32";
                error->Operation = "CreateToolhelp32Snapshot";
                error->Message = FormatWindowsError(error->Code);
            }
            break;
        }

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);

        if (!Process32FirstW(snapshot, &entry))
        {
            if (error != nullptr)
            {
                error->Code = GetLastError();
                error->Subsystem = "win32";
                error->Operation = "Process32FirstW";
                error->Message = FormatWindowsError(error->Code);
            }
            break;
        }

        do
        {
            KnMonTargetProcess target;
            target.ProcessId = entry.th32ProcessID;
            target.ParentProcessId = entry.th32ParentProcessID;
            target.HasParentProcessId = true;
            target.ImageName = WideToUtf8(entry.szExeFile);
            target.ImagePath = QueryProcessImagePath(entry.th32ProcessID);
            target.Architecture = QueryProcessArchitecture(entry.th32ProcessID);
            target.Status = target.ImagePath.empty() ? "limited" : "available";

            if (target.ProcessId == 0 || target.ProcessId == 4)
            {
                target.Status = "unsupported";
            }

            processes.push_back(target);
        }
        while (Process32NextW(snapshot, &entry));
    }
    while (false);

    if (snapshot != INVALID_HANDLE_VALUE)
    {
        CloseHandle(snapshot);
    }

    return processes;
}

KnMonLaunchResult Controller::LaunchWithEarlyBirdApc(const KnMonLaunchRequest& request) const
{
    KnMonLaunchResult result;
    result.OperationId = request.OperationId.empty() ? "manual-operation" : request.OperationId;
    result.TargetPath = request.TargetPath;
    result.AgentPath = request.AgentPath;
    result.Architecture = "x64";
    result.InjectionMethod = "early-bird APC";

    PROCESS_INFORMATION processInfo = {};
    STARTUPINFOW startupInfo = {};
    startupInfo.cb = sizeof(startupInfo);
    HANDLE pipeHandle = INVALID_HANDLE_VALUE;
    void* remoteDllPath = nullptr;
    bool processCreated = false;
    bool processResumed = false;

    do
    {
#if !defined(_WIN64)
        SetResultError(result, ERROR_NOT_SUPPORTED, "knmon-core", "architecture_check", "The first early-bird path requires an x64 helper build.");
        break;
#endif

        if (request.InjectionMethod != KnMonInjectionMethod::EarlyBirdApc)
        {
            SetResultError(result, ERROR_NOT_SUPPORTED, "knmon-core", "injection_method_check", "Only early-bird APC injection is supported in this goal.");
            break;
        }

        if (!FileExists(request.TargetPath))
        {
            SetResultError(result, ERROR_FILE_NOT_FOUND, "knmon-core", "target_path_check", "Target executable does not exist.");
            break;
        }

        if (!FileExists(request.AgentPath))
        {
            SetResultError(result, ERROR_FILE_NOT_FOUND, "knmon-core", "agent_path_check", "Agent DLL does not exist.");
            break;
        }

        AddAudit(result, "launch_requested", "launch_requested", "Controlled early-bird launch requested.");

        const std::wstring pipeName = L"\\\\.\\pipe\\knmon_agent_" + Utf8ToWide(result.OperationId);
        pipeHandle = CreateNamedPipeW(
            pipeName.c_str(),
            PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            4096,
            4096,
            request.TimeoutMs,
            nullptr);

        if (pipeHandle == INVALID_HANDLE_VALUE)
        {
            SetResultError(result, GetLastError(), "win32", "CreateNamedPipeW", "Failed to create agent handshake pipe.");
            break;
        }

        AddAudit(result, "handshake_pipe_created", "CreateNamedPipeW", WideToUtf8(pipeName.c_str()));

        const std::wstring targetPath = Utf8ToWide(request.TargetPath);
        const std::wstring agentPath = Utf8ToWide(request.AgentPath);
        const std::wstring workingDirectory = request.WorkingDirectory.empty() ? std::filesystem::path(targetPath).parent_path().wstring() : Utf8ToWide(request.WorkingDirectory);
        std::wstring commandLine = QuoteArgument(targetPath);
        commandLine += L" --slow";
        std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
        mutableCommandLine.push_back(L'\0');

        EnvironmentOverride pipeEnv(L"KNMON_AGENT_PIPE", pipeName);
        EnvironmentOverride operationEnv(L"KNMON_OPERATION_ID", Utf8ToWide(result.OperationId));

        if (!CreateProcessW(
            targetPath.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            nullptr,
            workingDirectory.empty() ? nullptr : workingDirectory.c_str(),
            &startupInfo,
            &processInfo))
        {
            SetResultError(result, GetLastError(), "win32", "CreateProcessW", "Failed to create controlled target process suspended.");
            break;
        }

        processCreated = true;
        result.TargetProcessId = processInfo.dwProcessId;
        result.TargetThreadId = processInfo.dwThreadId;
        AddAudit(result, "process_created_suspended", "CreateProcessW", "Controlled target process created suspended.");

        const std::uint64_t remoteSize = static_cast<std::uint64_t>((agentPath.size() + 1) * sizeof(wchar_t));
        remoteDllPath = VirtualAllocEx(processInfo.hProcess, nullptr, static_cast<SIZE_T>(remoteSize), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (remoteDllPath == nullptr)
        {
            SetResultError(result, GetLastError(), "win32", "VirtualAllocEx", "Failed to allocate remote agent path buffer.");
            break;
        }

        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(processInfo.hProcess, remoteDllPath, agentPath.c_str(), static_cast<SIZE_T>(remoteSize), &bytesWritten))
        {
            SetResultError(result, GetLastError(), "win32", "WriteProcessMemory", "Failed to write agent path into target process.");
            break;
        }

        AddAudit(result, "agent_path_written", "WriteProcessMemory", "Agent DLL path written into target process.");

        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32 == nullptr)
        {
            SetResultError(result, GetLastError(), "win32", "GetModuleHandleW", "Failed to resolve kernel32.dll.");
            break;
        }

        FARPROC loadLibrary = GetProcAddress(kernel32, "LoadLibraryW");
        if (loadLibrary == nullptr)
        {
            SetResultError(result, GetLastError(), "win32", "GetProcAddress", "Failed to resolve LoadLibraryW.");
            break;
        }

        if (QueueUserAPC(reinterpret_cast<PAPCFUNC>(loadLibrary), processInfo.hThread, reinterpret_cast<ULONG_PTR>(remoteDllPath)) == 0)
        {
            SetResultError(result, GetLastError(), "win32", "QueueUserAPC", "Failed to queue early-bird APC.");
            break;
        }

        AddAudit(result, "early_bird_apc_queued", "QueueUserAPC", "Early-bird LoadLibraryW APC queued on the suspended primary thread.");

        if (ResumeThread(processInfo.hThread) == static_cast<DWORD>(-1))
        {
            SetResultError(result, GetLastError(), "win32", "ResumeThread", "Failed to resume target primary thread.");
            break;
        }

        processResumed = true;
        AddAudit(result, "primary_thread_resumed", "ResumeThread", "Target primary thread resumed.");

        DWORD pipeError = 0;
        if (!WaitForPipeConnection(pipeHandle, request.TimeoutMs, &pipeError))
        {
            SetResultError(result, pipeError, "win32", "agent_handshake_connect", "Agent handshake pipe connection timed out or failed.");
            AddAudit(result, "handshake_timeout", "agent_handshake_connect", "No agent connection was received before timeout.", pipeError, "win32");
            break;
        }

        std::string payload;
        if (!ReadPipeMessage(pipeHandle, request.TimeoutMs, &payload, &pipeError))
        {
            SetResultError(result, pipeError, "win32", "agent_handshake_read", "Agent handshake payload timed out or failed.");
            AddAudit(result, "handshake_timeout", "agent_handshake_read", "No agent HELLO payload was received before timeout.", pipeError, "win32");
            break;
        }

        result.Handshake = BuildHandshake(result, payload);
        result.Success = true;
        result.Win32ErrorCode = 0;
        result.Subsystem = "knmon-core";
        result.Operation = "launch_sample_early_bird";
        result.Message = "Controlled early-bird agent load completed and HELLO was received.";
        AddAudit(result, "agent_hello_received", "agent_handshake_read", payload);
    }
    while (false);

    if (remoteDllPath != nullptr && processInfo.hProcess != nullptr)
    {
        if (VirtualFreeEx(processInfo.hProcess, remoteDllPath, 0, MEM_RELEASE))
        {
            AddAudit(result, "remote_buffer_released", "VirtualFreeEx", "Remote agent path buffer released.");
        }
        else
        {
            AddAudit(result, "cleanup_partial_failure", "VirtualFreeEx", "Remote agent path buffer cleanup failed.", GetLastError(), "win32");
        }
    }

    if (processCreated && !processResumed && processInfo.hProcess != nullptr)
    {
        TerminateProcess(processInfo.hProcess, 1);
        AddAudit(result, "cleanup_completed", "TerminateProcess", "Suspended target was terminated because launch failed before resume.");
    }
    else
    {
        AddAudit(result, "cleanup_completed", "handle_cleanup", "Controller handle cleanup completed.");
    }

    if (pipeHandle != INVALID_HANDLE_VALUE)
    {
        DisconnectNamedPipe(pipeHandle);
        CloseHandle(pipeHandle);
    }

    if (processInfo.hThread != nullptr)
    {
        CloseHandle(processInfo.hThread);
    }

    if (processInfo.hProcess != nullptr)
    {
        CloseHandle(processInfo.hProcess);
    }

    return result;
}

KnMonError Controller::LaunchTarget(const std::string& imagePath) const
{
    (void)imagePath;
    return NotImplementedError("launch");
}

KnMonError Controller::AttachToTarget(std::uint32_t processId) const
{
    (void)processId;
    return NotImplementedError("attach");
}

KnMonError Controller::DetachFromTarget(std::uint32_t processId) const
{
    (void)processId;
    return NotImplementedError("detach");
}

KnMonError Controller::StartCapture(std::uint32_t processId) const
{
    (void)processId;
    return NotImplementedError("start_capture");
}

KnMonError Controller::StopCapture(std::uint32_t processId) const
{
    (void)processId;
    return NotImplementedError("stop_capture");
}
}
