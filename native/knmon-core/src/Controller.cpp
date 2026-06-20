#include <knmon/core/Controller.h>

#include <knmon/common/AttachConfig.h>
#include <knmon/common/GeneratedApiMetadata.h>
#include <knmon/collector/SharedTransportReader.h>

#include <Windows.h>
#include <winhttp.h>
#include <TlHelp32.h>

#include <array>
#include <algorithm>
#include <cwchar>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace knmon
{
namespace
{
constexpr std::uint64_t ExpectedFileIoHookCount = 6;

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

std::string JsonEscape(const std::string& value)
{
    std::ostringstream stream;

    for (const char ch : value)
    {
        const unsigned char byte = static_cast<unsigned char>(ch);
        switch (ch)
        {
        case '\\':
            stream << "\\\\";
            break;
        case '"':
            stream << "\\\"";
            break;
        case '\n':
            stream << "\\n";
            break;
        case '\r':
            stream << "\\r";
            break;
        case '\t':
            stream << "\\t";
            break;
        default:
            if (byte < 0x20)
            {
                const char* hex = "0123456789abcdef";
                stream << "\\u00" << hex[(byte >> 4) & 0x0f] << hex[byte & 0x0f];
            }
            else
            {
                stream << ch;
            }
            break;
        }
    }

    return stream.str();
}

std::string Q(const std::string& value)
{
    return "\"" + JsonEscape(value) + "\"";
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

KnMonAgentArchitecture NativeHelperArchitecture()
{
#if defined(_WIN64)
    return KnMonAgentArchitecture::X64;
#else
    return KnMonAgentArchitecture::X86;
#endif
}

std::string ArchitectureName(KnMonAgentArchitecture architecture)
{
    std::string name = "unknown";

    switch (architecture)
    {
    case KnMonAgentArchitecture::X86:
        name = "x86";
        break;
    case KnMonAgentArchitecture::X64:
        name = "x64";
        break;
    default:
        break;
    }

    return name;
}

KnMonAgentArchitecture RequestedArchitectureOrNative(KnMonAgentArchitecture requested)
{
    KnMonAgentArchitecture architecture = requested;

    if (architecture == KnMonAgentArchitecture::Unknown)
    {
        architecture = NativeHelperArchitecture();
    }

    return architecture;
}

KnMonAgentArchitecture ArchitectureFromMachine(WORD machine)
{
    KnMonAgentArchitecture architecture = KnMonAgentArchitecture::Unknown;

    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        architecture = KnMonAgentArchitecture::X86;
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        architecture = KnMonAgentArchitecture::X64;
        break;
    default:
        break;
    }

    return architecture;
}

struct BinaryArchitectureResult
{
    bool Success = false;
    KnMonAgentArchitecture Architecture = KnMonAgentArchitecture::Unknown;
    DWORD ErrorCode = 0;
    std::string Operation;
    std::string Message;
};

void AddAudit(
    KnMonLaunchResult& result,
    const std::string& eventType,
    const std::string& operation,
    const std::string& message,
    DWORD errorCode = 0,
    const std::string& subsystem = "knmon-core");

void AddAudit(
    KnMonCaptureResult& result,
    const std::string& eventType,
    const std::string& operation,
    const std::string& message,
    DWORD errorCode = 0,
    const std::string& subsystem = "knmon-core");

void AddAudit(
    KnMonProcessTreeResult& result,
    const std::string& eventType,
    const std::string& operation,
    const std::string& message,
    DWORD errorCode = 0,
    const std::string& subsystem = "knmon-core");

void SetResultError(
    KnMonCaptureResult& result,
    DWORD errorCode,
    const std::string& subsystem,
    const std::string& operation,
    const std::string& message);

void SetResultError(
    KnMonProcessTreeResult& result,
    DWORD errorCode,
    const std::string& subsystem,
    const std::string& operation,
    const std::string& message);

bool IsMissingFileError(DWORD errorCode)
{
    return errorCode == ERROR_FILE_NOT_FOUND || errorCode == ERROR_PATH_NOT_FOUND;
}

std::string BinaryOpenFailureOperation(DWORD errorCode, const std::string& label)
{
    std::string operation;

    if (IsMissingFileError(errorCode))
    {
        operation = "missing_" + label;
    }
    else if (errorCode == ERROR_ACCESS_DENIED)
    {
        operation = "access_denied";
    }
    else
    {
        operation = label + "_open_failed";
    }

    return operation;
}

BinaryArchitectureResult QueryBinaryArchitecture(const std::string& path, const std::string& label)
{
    BinaryArchitectureResult result;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;

    do
    {
        if (path.empty())
        {
            result.ErrorCode = ERROR_FILE_NOT_FOUND;
            result.Operation = "missing_" + label;
            result.Message = label + " path is empty.";
            break;
        }

        const std::wstring widePath = Utf8ToWide(path);
        fileHandle = CreateFileW(
            widePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            result.ErrorCode = GetLastError();
            result.Operation = BinaryOpenFailureOperation(result.ErrorCode, label);
            result.Message = "Failed to open " + label + " binary for architecture preflight: " + FormatWindowsError(result.ErrorCode);
            break;
        }

        IMAGE_DOS_HEADER dosHeader = {};
        DWORD bytesRead = 0;
        if (!ReadFile(fileHandle, &dosHeader, sizeof(dosHeader), &bytesRead, nullptr) || bytesRead != sizeof(dosHeader))
        {
            result.ErrorCode = ERROR_BAD_EXE_FORMAT;
            result.Operation = "unsupported_architecture";
            result.Message = "Failed to read " + label + " DOS header for architecture preflight.";
            break;
        }

        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        {
            result.ErrorCode = ERROR_BAD_EXE_FORMAT;
            result.Operation = "unsupported_architecture";
            result.Message = label + " is not a PE image.";
            break;
        }

        LARGE_INTEGER offset = {};
        offset.QuadPart = dosHeader.e_lfanew;
        if (!SetFilePointerEx(fileHandle, offset, nullptr, FILE_BEGIN))
        {
            result.ErrorCode = GetLastError();
            result.Operation = "unsupported_architecture";
            result.Message = "Failed to seek to " + label + " NT headers for architecture preflight.";
            break;
        }

        DWORD signature = 0;
        if (!ReadFile(fileHandle, &signature, sizeof(signature), &bytesRead, nullptr) || bytesRead != sizeof(signature) || signature != IMAGE_NT_SIGNATURE)
        {
            result.ErrorCode = ERROR_BAD_EXE_FORMAT;
            result.Operation = "unsupported_architecture";
            result.Message = label + " NT header signature is invalid.";
            break;
        }

        IMAGE_FILE_HEADER fileHeader = {};
        if (!ReadFile(fileHandle, &fileHeader, sizeof(fileHeader), &bytesRead, nullptr) || bytesRead != sizeof(fileHeader))
        {
            result.ErrorCode = ERROR_BAD_EXE_FORMAT;
            result.Operation = "unsupported_architecture";
            result.Message = "Failed to read " + label + " file header for architecture preflight.";
            break;
        }

        result.Architecture = ArchitectureFromMachine(fileHeader.Machine);
        if (result.Architecture == KnMonAgentArchitecture::Unknown)
        {
            std::ostringstream stream;
            stream << label << " uses unsupported PE machine 0x" << std::hex << std::setw(4) << std::setfill('0') << fileHeader.Machine << ".";
            result.ErrorCode = ERROR_NOT_SUPPORTED;
            result.Operation = "unsupported_architecture";
            result.Message = stream.str();
            break;
        }

        result.Success = true;
        result.ErrorCode = 0;
        result.Operation = "architecture_detected";
        result.Message = label + " architecture is " + ArchitectureName(result.Architecture) + ".";
    }
    while (false);

    if (fileHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(fileHandle);
    }

    return result;
}

struct ProcessSnapshotInfo
{
    bool Found = false;
    DWORD ProcessId = 0;
    DWORD ParentProcessId = 0;
    std::string ImageName;
};

struct ProcessArchitectureResult
{
    bool Success = false;
    KnMonAgentArchitecture Architecture = KnMonAgentArchitecture::Unknown;
    DWORD ErrorCode = 0;
    std::string Operation;
    std::string Message;
};

struct AttachPreflightResult
{
    bool Success = false;
    HANDLE ProcessHandle = nullptr;
    std::string TargetPath;
    std::string TargetImageName;
    DWORD ParentProcessId = 0;
    KnMonAgentArchitecture TargetArchitecture = KnMonAgentArchitecture::Unknown;
};

std::uint64_t FileTimeToUInt64(const FILETIME& fileTime)
{
    ULARGE_INTEGER value = {};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return value.QuadPart;
}

bool QueryProcessCreationTime(HANDLE processHandle, std::uint64_t* creationTime, DWORD* errorCode)
{
    bool queried = false;

    do
    {
        if (creationTime != nullptr)
        {
            *creationTime = 0;
        }

        if (errorCode != nullptr)
        {
            *errorCode = 0;
        }

        if (processHandle == nullptr)
        {
            if (errorCode != nullptr)
            {
                *errorCode = ERROR_INVALID_HANDLE;
            }
            break;
        }

        FILETIME created = {};
        FILETIME exited = {};
        FILETIME kernel = {};
        FILETIME user = {};
        if (!GetProcessTimes(processHandle, &created, &exited, &kernel, &user))
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        if (creationTime != nullptr)
        {
            *creationTime = FileTimeToUInt64(created);
        }
        queried = true;
    }
    while (false);

    return queried;
}

bool IsProcessHandleExited(HANDLE processHandle)
{
    bool exited = false;

    if (processHandle != nullptr)
    {
        exited = WaitForSingleObject(processHandle, 0) == WAIT_OBJECT_0;
    }

    return exited;
}

bool FindProcessSnapshotInfo(DWORD processId, ProcessSnapshotInfo* info, DWORD* errorCode)
{
    bool found = false;
    HANDLE snapshot = INVALID_HANDLE_VALUE;

    do
    {
        if (info != nullptr)
        {
            *info = {};
        }

        if (errorCode != nullptr)
        {
            *errorCode = 0;
        }

        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (!Process32FirstW(snapshot, &entry))
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        do
        {
            if (entry.th32ProcessID == processId)
            {
                if (info != nullptr)
                {
                    info->Found = true;
                    info->ProcessId = entry.th32ProcessID;
                    info->ParentProcessId = entry.th32ParentProcessID;
                    info->ImageName = WideToUtf8(entry.szExeFile);
                }

                found = true;
                break;
            }
        }
        while (Process32NextW(snapshot, &entry));
    }
    while (false);

    if (snapshot != INVALID_HANDLE_VALUE)
    {
        CloseHandle(snapshot);
    }

    return found;
}

ProcessArchitectureResult QueryProcessArchitectureFromHandle(HANDLE processHandle)
{
    ProcessArchitectureResult result;

    do
    {
        if (processHandle == nullptr)
        {
            result.ErrorCode = ERROR_INVALID_HANDLE;
            result.Operation = "target_process_open";
            result.Message = "Target process handle is invalid.";
            break;
        }

        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
        auto isWow64Process2 = kernel32 == nullptr ? nullptr : reinterpret_cast<IsWow64Process2Fn>(GetProcAddress(kernel32, "IsWow64Process2"));
        if (isWow64Process2 != nullptr)
        {
            USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            if (!isWow64Process2(processHandle, &processMachine, &nativeMachine))
            {
                result.ErrorCode = GetLastError();
                result.Operation = "target_architecture";
                result.Message = "IsWow64Process2 failed during attach preflight: " + FormatWindowsError(result.ErrorCode);
                break;
            }

            const WORD selectedMachine = processMachine == IMAGE_FILE_MACHINE_UNKNOWN ? nativeMachine : processMachine;
            result.Architecture = ArchitectureFromMachine(selectedMachine);
            if (result.Architecture == KnMonAgentArchitecture::Unknown)
            {
                result.ErrorCode = ERROR_NOT_SUPPORTED;
                result.Operation = "unsupported_architecture";
                result.Message = "Target process architecture is not supported.";
                break;
            }
        }
        else
        {
            BOOL isWow64 = FALSE;
            if (!IsWow64Process(processHandle, &isWow64))
            {
                result.ErrorCode = GetLastError();
                result.Operation = "target_architecture";
                result.Message = "IsWow64Process failed during attach preflight: " + FormatWindowsError(result.ErrorCode);
                break;
            }

#if defined(_WIN64)
            result.Architecture = isWow64 ? KnMonAgentArchitecture::X86 : KnMonAgentArchitecture::X64;
#else
            result.Architecture = KnMonAgentArchitecture::X86;
#endif
        }

        result.Success = true;
        result.ErrorCode = 0;
        result.Operation = "target_architecture";
        result.Message = "Target process architecture is " + ArchitectureName(result.Architecture) + ".";
    }
    while (false);

    return result;
}

bool QueryProcessProtection(HANDLE processHandle, bool* protectedProcess)
{
    bool queried = false;

    do
    {
        if (protectedProcess != nullptr)
        {
            *protectedProcess = false;
        }

        if (processHandle == nullptr)
        {
            break;
        }

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            break;
        }

        using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto ntQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (ntQueryInformationProcess == nullptr)
        {
            break;
        }

        struct ProcessProtectionInfo
        {
            UCHAR Level;
        };

        ProcessProtectionInfo protection = {};
        const LONG status = ntQueryInformationProcess(processHandle, 61, &protection, sizeof(protection), nullptr);
        if (status < 0)
        {
            break;
        }

        if (protectedProcess != nullptr)
        {
            *protectedProcess = protection.Level != 0;
        }

        queried = true;
    }
    while (false);

    return queried;
}

struct ProcessSignaturePolicyInfo
{
    bool Queried = false;
    bool MicrosoftSignedOnly = false;
    bool StoreSignedOnly = false;
    DWORD ErrorCode = 0;
    std::string Message;
};

ProcessSignaturePolicyInfo QueryProcessSignaturePolicy(HANDLE processHandle)
{
    ProcessSignaturePolicyInfo result;

    do
    {
        if (processHandle == nullptr)
        {
            result.ErrorCode = ERROR_INVALID_HANDLE;
            result.Message = "Target process handle is invalid.";
            break;
        }

        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32 == nullptr)
        {
            result.ErrorCode = GetLastError();
            result.Message = "kernel32.dll is not available for mitigation policy query.";
            break;
        }

        using GetProcessMitigationPolicyFn = BOOL(WINAPI*)(HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
        auto getProcessMitigationPolicy = reinterpret_cast<GetProcessMitigationPolicyFn>(GetProcAddress(kernel32, "GetProcessMitigationPolicy"));
        if (getProcessMitigationPolicy == nullptr)
        {
            result.ErrorCode = ERROR_PROC_NOT_FOUND;
            result.Message = "GetProcessMitigationPolicy is not available on this host.";
            break;
        }

        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = {};
        if (!getProcessMitigationPolicy(processHandle, ProcessSignaturePolicy, &policy, sizeof(policy)))
        {
            result.ErrorCode = GetLastError();
            result.Message = "GetProcessMitigationPolicy(ProcessSignaturePolicy) failed: " + FormatWindowsError(result.ErrorCode);
            break;
        }

        result.Queried = true;
        result.MicrosoftSignedOnly = policy.MicrosoftSignedOnly != 0;
        result.StoreSignedOnly = policy.StoreSignedOnly != 0;

        std::ostringstream stream;
        stream << "Process signature policy: MicrosoftSignedOnly=" << (result.MicrosoftSignedOnly ? "true" : "false")
               << " StoreSignedOnly=" << (result.StoreSignedOnly ? "true" : "false") << ".";
        result.Message = stream.str();
    }
    while (false);

    return result;
}

void SetAttachPreflightError(
    KnMonCaptureResult& result,
    DWORD errorCode,
    const std::string& operation,
    const std::string& message)
{
    SetResultError(result, errorCode, "knmon-core", operation, message);
    AddAudit(result, "attach_preflight_failed", operation, message, errorCode, "knmon-core");
}

AttachPreflightResult RunAttachPreflight(
    KnMonCaptureResult& result,
    const KnMonAttachRequest& request,
    KnMonAgentArchitecture requestedArchitecture)
{
    AttachPreflightResult preflight;
    HANDLE queryHandle = nullptr;

    do
    {
        AddAudit(result, "attach_preflight_started", "attach_preflight", "Running same-bitness attach preflight.");

        if (request.ProcessId == 0 || request.ProcessId == 4)
        {
            SetAttachPreflightError(result, ERROR_NOT_SUPPORTED, "missing_target_process", "System idle and system process PIDs are not supported attach targets.");
            break;
        }

        if (request.ProcessId == GetCurrentProcessId())
        {
            SetAttachPreflightError(result, ERROR_NOT_SUPPORTED, "missing_target_process", "The helper process cannot attach to itself.");
            break;
        }

        ProcessSnapshotInfo snapshotInfo;
        DWORD snapshotError = 0;
        if (!FindProcessSnapshotInfo(request.ProcessId, &snapshotInfo, &snapshotError))
        {
            HANDLE staleProcessHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, request.ProcessId);
            if (staleProcessHandle != nullptr)
            {
                if (IsProcessHandleExited(staleProcessHandle))
                {
                    CloseHandle(staleProcessHandle);
                    SetAttachPreflightError(result, ERROR_PROCESS_ABORTED, "target_exited_before_mutation", "Target process exited before attach preflight could acquire a live snapshot.");
                    break;
                }

                CloseHandle(staleProcessHandle);
            }

            const DWORD errorCode = snapshotError == 0 ? ERROR_INVALID_PARAMETER : snapshotError;
            SetAttachPreflightError(result, errorCode, "missing_target_process", "Target process was not found in the process snapshot.");
            break;
        }

        const KnMonAgentArchitecture helperArchitecture = NativeHelperArchitecture();
        if (requestedArchitecture == KnMonAgentArchitecture::Unknown || helperArchitecture == KnMonAgentArchitecture::Unknown)
        {
            SetAttachPreflightError(result, ERROR_NOT_SUPPORTED, "unsupported_architecture", "Requested or helper architecture is unknown.");
            break;
        }

        if (requestedArchitecture != helperArchitecture)
        {
            const std::string message = "Requested architecture " + ArchitectureName(requestedArchitecture) + " does not match helper architecture " + ArchitectureName(helperArchitecture) + ". Cross-bitness attach is not supported.";
            SetAttachPreflightError(result, ERROR_NOT_SUPPORTED, "helper_target_mismatch", message);
            break;
        }

        BinaryArchitectureResult agentArchitecture = QueryBinaryArchitecture(request.AgentPath, "agent");
        if (!agentArchitecture.Success)
        {
            SetAttachPreflightError(result, agentArchitecture.ErrorCode, agentArchitecture.Operation, agentArchitecture.Message);
            break;
        }

        if (agentArchitecture.Architecture != requestedArchitecture)
        {
            const std::string message = "Agent architecture " + ArchitectureName(agentArchitecture.Architecture) + " does not match helper/target architecture " + ArchitectureName(requestedArchitecture) + ".";
            SetAttachPreflightError(result, ERROR_NOT_SUPPORTED, "helper_agent_mismatch", message);
            break;
        }

        queryHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, request.ProcessId);
        if (queryHandle == nullptr)
        {
            const DWORD errorCode = GetLastError();
            const std::string operation = errorCode == ERROR_ACCESS_DENIED ? "access_denied" : "target_process_open";
            SetAttachPreflightError(result, errorCode, operation, "Failed to open target process for query: " + FormatWindowsError(errorCode));
            break;
        }

        if (IsProcessHandleExited(queryHandle))
        {
            SetAttachPreflightError(result, ERROR_PROCESS_ABORTED, "target_exited_before_mutation", "Target process exited before attach preflight completed.");
            break;
        }

        std::uint64_t queryCreationTime = 0;
        DWORD creationTimeError = 0;
        if (!QueryProcessCreationTime(queryHandle, &queryCreationTime, &creationTimeError))
        {
            const DWORD errorCode = creationTimeError == 0 ? ERROR_INVALID_PARAMETER : creationTimeError;
            SetAttachPreflightError(result, errorCode, "target_identity_query", "Failed to query target process creation time before attach mutation: " + FormatWindowsError(errorCode));
            break;
        }

        ProcessArchitectureResult targetArchitecture = QueryProcessArchitectureFromHandle(queryHandle);
        if (!targetArchitecture.Success)
        {
            SetAttachPreflightError(result, targetArchitecture.ErrorCode, targetArchitecture.Operation, targetArchitecture.Message);
            break;
        }

        if (targetArchitecture.Architecture != requestedArchitecture)
        {
            const std::string message = "Target architecture " + ArchitectureName(targetArchitecture.Architecture) + " does not match helper architecture " + ArchitectureName(requestedArchitecture) + ". Cross-bitness attach is not supported.";
            SetAttachPreflightError(result, ERROR_NOT_SUPPORTED, "helper_target_mismatch", message);
            break;
        }

        bool protectedProcess = false;
        if (QueryProcessProtection(queryHandle, &protectedProcess) && protectedProcess)
        {
            SetAttachPreflightError(result, ERROR_ACCESS_DENIED, "protected_process", "Target process reports a protected-process protection level.");
            break;
        }

        ProcessSignaturePolicyInfo signaturePolicy = QueryProcessSignaturePolicy(queryHandle);
        if (signaturePolicy.Queried)
        {
            AddAudit(result, "attach_mitigation_policy_checked", "GetProcessMitigationPolicy", signaturePolicy.Message);

            if (signaturePolicy.MicrosoftSignedOnly || signaturePolicy.StoreSignedOnly)
            {
                SetAttachPreflightError(result, ERROR_ACCESS_DENIED, "mitigation_policy_conflict", "Target process signature mitigation policy blocks loading the unsigned KNMon agent DLL.");
                break;
            }
        }
        else
        {
            const DWORD mitigationError = signaturePolicy.ErrorCode == 0 ? ERROR_NOT_SUPPORTED : signaturePolicy.ErrorCode;
            AddAudit(result, "attach_mitigation_policy_unavailable", "GetProcessMitigationPolicy", signaturePolicy.Message, mitigationError, "win32");
        }

        CloseHandle(queryHandle);
        queryHandle = nullptr;

        constexpr DWORD desiredAccess =
            PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_QUERY_INFORMATION |
            PROCESS_CREATE_THREAD |
            PROCESS_VM_OPERATION |
            PROCESS_VM_READ |
            PROCESS_VM_WRITE |
            SYNCHRONIZE;

        HANDLE processHandle = OpenProcess(desiredAccess, FALSE, request.ProcessId);
        if (processHandle == nullptr)
        {
            const DWORD errorCode = GetLastError();
            const std::string operation = errorCode == ERROR_ACCESS_DENIED ? "access_denied" : "target_process_open";
            SetAttachPreflightError(result, errorCode, operation, "Failed to open target process for attach mutation: " + FormatWindowsError(errorCode));
            break;
        }

        if (IsProcessHandleExited(processHandle))
        {
            CloseHandle(processHandle);
            SetAttachPreflightError(result, ERROR_PROCESS_ABORTED, "target_exited_before_mutation", "Target process exited before remote attach mutation.");
            break;
        }

        std::uint64_t attachCreationTime = 0;
        if (!QueryProcessCreationTime(processHandle, &attachCreationTime, &creationTimeError))
        {
            const DWORD errorCode = creationTimeError == 0 ? ERROR_INVALID_PARAMETER : creationTimeError;
            CloseHandle(processHandle);
            SetAttachPreflightError(result, errorCode, "target_identity_query", "Failed to re-query target process creation time before attach mutation: " + FormatWindowsError(errorCode));
            break;
        }

        if (queryCreationTime != attachCreationTime)
        {
            CloseHandle(processHandle);
            SetAttachPreflightError(result, ERROR_PROCESS_ABORTED, "target_identity_changed", "Target process identity changed before attach mutation; PID reuse is not accepted.");
            break;
        }

        preflight.Success = true;
        preflight.ProcessHandle = processHandle;
        preflight.TargetPath = QueryProcessImagePath(request.ProcessId);
        preflight.TargetImageName = snapshotInfo.ImageName;
        preflight.ParentProcessId = snapshotInfo.ParentProcessId;
        preflight.TargetArchitecture = targetArchitecture.Architecture;
        AddAudit(result, "target_process_opened", "OpenProcess", "Target process opened for bounded same-bitness attach.");
        AddAudit(result, "attach_preflight_passed", "attach_preflight", "Same-bitness running-process attach preflight passed.");
    }
    while (false);

    if (queryHandle != nullptr)
    {
        CloseHandle(queryHandle);
    }

    return preflight;
}

std::string ChildPolicyName(KnMonChildPolicy policy)
{
    std::string name = "observe";

    if (policy == KnMonChildPolicy::AttachSupported)
    {
        name = "attach-supported";
    }

    return name;
}

std::string ProcessEligibilityName(KnMonProcessEligibility eligibility)
{
    std::string name = "unsupported";

    switch (eligibility)
    {
    case KnMonProcessEligibility::Eligible:
        name = "eligible";
        break;
    case KnMonProcessEligibility::Missing:
        name = "missing";
        break;
    case KnMonProcessEligibility::Exited:
        name = "exited";
        break;
    case KnMonProcessEligibility::UnknownArchitecture:
        name = "unknown_architecture";
        break;
    case KnMonProcessEligibility::HelperTargetMismatch:
        name = "helper_target_mismatch";
        break;
    case KnMonProcessEligibility::AccessDenied:
        name = "access_denied";
        break;
    case KnMonProcessEligibility::ProtectedProcess:
        name = "protected_process";
        break;
    case KnMonProcessEligibility::Unsupported:
    default:
        name = "unsupported";
        break;
    }

    return name;
}

std::string ProcessPolicyDecisionName(KnMonProcessPolicyDecision decision)
{
    std::string name = "unsupported";

    switch (decision)
    {
    case KnMonProcessPolicyDecision::ObserveOnly:
        name = "observe_only";
        break;
    case KnMonProcessPolicyDecision::AttachAllowed:
        name = "attach_allowed";
        break;
    case KnMonProcessPolicyDecision::AttachSkipped:
        name = "attach_skipped";
        break;
    case KnMonProcessPolicyDecision::AttachFailed:
        name = "attach_failed";
        break;
    case KnMonProcessPolicyDecision::Unsupported:
    default:
        name = "unsupported";
        break;
    }

    return name;
}

bool IsRepositorySampleImage(const std::string& imageName)
{
    return _stricmp(imageName.c_str(), "knmon-sample-fileio.exe") == 0;
}

bool CollectProcessSnapshot(std::vector<ProcessSnapshotInfo>* processes, DWORD* errorCode)
{
    bool collected = false;
    HANDLE snapshot = INVALID_HANDLE_VALUE;

    do
    {
        if (processes != nullptr)
        {
            processes->clear();
        }

        if (errorCode != nullptr)
        {
            *errorCode = 0;
        }

        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (!Process32FirstW(snapshot, &entry))
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        do
        {
            ProcessSnapshotInfo info;
            info.Found = true;
            info.ProcessId = entry.th32ProcessID;
            info.ParentProcessId = entry.th32ParentProcessID;
            info.ImageName = WideToUtf8(entry.szExeFile);
            if (processes != nullptr)
            {
                processes->push_back(info);
            }
        }
        while (Process32NextW(snapshot, &entry));

        collected = true;
    }
    while (false);

    if (snapshot != INVALID_HANDLE_VALUE)
    {
        CloseHandle(snapshot);
    }

    return collected;
}

const ProcessSnapshotInfo* FindSnapshotProcess(const std::vector<ProcessSnapshotInfo>& processes, DWORD processId)
{
    const ProcessSnapshotInfo* found = nullptr;

    for (const auto& process : processes)
    {
        if (process.ProcessId == processId)
        {
            found = &process;
            break;
        }
    }

    return found;
}

KnMonProcessTreeNode* FindProcessTreeNode(std::vector<KnMonProcessTreeNode>& nodes, DWORD processId)
{
    KnMonProcessTreeNode* found = nullptr;

    for (auto& node : nodes)
    {
        if (node.ProcessId == processId)
        {
            found = &node;
            break;
        }
    }

    return found;
}

bool ProcessTreeHasNode(const std::vector<KnMonProcessTreeNode>& nodes, DWORD processId)
{
    bool found = false;

    for (const auto& node : nodes)
    {
        if (node.ProcessId == processId)
        {
            found = true;
            break;
        }
    }

    return found;
}

KnMonChildPolicyDecision EvaluateChildPolicy(
    KnMonProcessTreeResult& result,
    KnMonProcessTreeNode& node,
    const KnMonProcessTreeRequest& request)
{
    KnMonChildPolicyDecision decision;
    decision.ProcessId = node.ProcessId;
    decision.ParentProcessId = node.ParentProcessId;
    decision.ImageName = node.ImageName;
    decision.Decision = ProcessPolicyDecisionName(KnMonProcessPolicyDecision::AttachSkipped);
    decision.Reason = "Child process has not been evaluated.";

    HANDLE processHandle = nullptr;

    do
    {
        if (!node.IsAlive || node.Exited)
        {
            node.EligibilityStatus = ProcessEligibilityName(KnMonProcessEligibility::Exited);
            decision.EligibilityStatus = node.EligibilityStatus;
            decision.Decision = ProcessPolicyDecisionName(KnMonProcessPolicyDecision::AttachSkipped);
            decision.Reason = "Child process exited before policy evaluation.";
            break;
        }

        if (!IsRepositorySampleImage(node.ImageName))
        {
            node.EligibilityStatus = ProcessEligibilityName(KnMonProcessEligibility::Unsupported);
            decision.EligibilityStatus = node.EligibilityStatus;
            decision.Decision = ProcessPolicyDecisionName(KnMonProcessPolicyDecision::Unsupported);
            decision.Reason = "Only repository sample children are eligible for Phase 11B child attach policy.";
            break;
        }

        processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, node.ProcessId);
        if (processHandle == nullptr)
        {
            const DWORD errorCode = GetLastError();
            node.EligibilityStatus = ProcessEligibilityName(errorCode == ERROR_ACCESS_DENIED ? KnMonProcessEligibility::AccessDenied : KnMonProcessEligibility::Missing);
            decision.EligibilityStatus = node.EligibilityStatus;
            decision.Decision = ProcessPolicyDecisionName(KnMonProcessPolicyDecision::AttachSkipped);
            decision.Reason = "Failed to open child process for policy query: " + FormatWindowsError(errorCode);
            break;
        }

        ProcessArchitectureResult architecture = QueryProcessArchitectureFromHandle(processHandle);
        if (!architecture.Success)
        {
            node.EligibilityStatus = ProcessEligibilityName(KnMonProcessEligibility::UnknownArchitecture);
            decision.EligibilityStatus = node.EligibilityStatus;
            decision.Decision = ProcessPolicyDecisionName(KnMonProcessPolicyDecision::AttachSkipped);
            decision.Reason = architecture.Message;
            break;
        }

        node.Architecture = ArchitectureName(architecture.Architecture);
        decision.Architecture = node.Architecture;

        const KnMonAgentArchitecture helperArchitecture = NativeHelperArchitecture();
        if (helperArchitecture == KnMonAgentArchitecture::Unknown || architecture.Architecture == KnMonAgentArchitecture::Unknown)
        {
            node.EligibilityStatus = ProcessEligibilityName(KnMonProcessEligibility::UnknownArchitecture);
            decision.EligibilityStatus = node.EligibilityStatus;
            decision.Decision = ProcessPolicyDecisionName(KnMonProcessPolicyDecision::AttachSkipped);
            decision.Reason = "Helper or child architecture is unknown.";
            break;
        }

        if (helperArchitecture != architecture.Architecture)
        {
            node.EligibilityStatus = ProcessEligibilityName(KnMonProcessEligibility::HelperTargetMismatch);
            decision.EligibilityStatus = node.EligibilityStatus;
            decision.Decision = ProcessPolicyDecisionName(KnMonProcessPolicyDecision::AttachSkipped);
            decision.Reason = "Child architecture does not match helper architecture.";
            break;
        }

        bool protectedProcess = false;
        if (QueryProcessProtection(processHandle, &protectedProcess) && protectedProcess)
        {
            node.EligibilityStatus = ProcessEligibilityName(KnMonProcessEligibility::ProtectedProcess);
            decision.EligibilityStatus = node.EligibilityStatus;
            decision.Decision = ProcessPolicyDecisionName(KnMonProcessPolicyDecision::AttachSkipped);
            decision.Reason = "Child process reports a protected-process protection level.";
            break;
        }

        BinaryArchitectureResult agentArchitecture = QueryBinaryArchitecture(request.AgentPath, "agent");
        if (!agentArchitecture.Success)
        {
            node.EligibilityStatus = ProcessEligibilityName(agentArchitecture.Operation == "missing_agent" ? KnMonProcessEligibility::Missing : KnMonProcessEligibility::Unsupported);
            decision.EligibilityStatus = node.EligibilityStatus;
            decision.Decision = ProcessPolicyDecisionName(KnMonProcessPolicyDecision::AttachSkipped);
            decision.Reason = agentArchitecture.Message;
            break;
        }

        if (agentArchitecture.Architecture != architecture.Architecture)
        {
            node.EligibilityStatus = ProcessEligibilityName(KnMonProcessEligibility::HelperTargetMismatch);
            decision.EligibilityStatus = node.EligibilityStatus;
            decision.Decision = ProcessPolicyDecisionName(KnMonProcessPolicyDecision::AttachSkipped);
            decision.Reason = "Agent architecture does not match child architecture.";
            break;
        }

        node.EligibilityStatus = ProcessEligibilityName(KnMonProcessEligibility::Eligible);
        decision.EligibilityStatus = node.EligibilityStatus;
        decision.Decision = request.ChildPolicy == KnMonChildPolicy::Observe
            ? ProcessPolicyDecisionName(KnMonProcessPolicyDecision::ObserveOnly)
            : ProcessPolicyDecisionName(KnMonProcessPolicyDecision::AttachAllowed);
        decision.Reason = request.ChildPolicy == KnMonChildPolicy::Observe
            ? "Observe policy classified the child as attachable without mutation."
            : "Attach-supported policy allows Phase 11A attach for this child.";
    }
    while (false);

    if (processHandle != nullptr)
    {
        CloseHandle(processHandle);
    }

    node.PolicyDecision = decision.Decision;
    node.Message = decision.Reason;

    AddAudit(
        result,
        "child_policy_evaluated",
        "child_policy",
        "Child pid " + std::to_string(node.ProcessId) + " eligibility=" + decision.EligibilityStatus + " decision=" + decision.Decision + ".");

    return decision;
}

bool CopyWideBounded(wchar_t* destination, std::size_t count, const std::wstring& value)
{
    bool copied = false;

    do
    {
        if (destination == nullptr || count == 0 || value.size() + 1 > count)
        {
            break;
        }

        std::wmemset(destination, 0, count);
        std::wmemcpy(destination, value.c_str(), value.size());
        copied = true;
    }
    while (false);

    return copied;
}

bool ResolveLoadedModuleExportRva(HMODULE moduleHandle, const char* exportName, std::uintptr_t* rva)
{
    bool resolved = false;

    do
    {
        if (moduleHandle == nullptr || exportName == nullptr || rva == nullptr)
        {
            break;
        }

        FARPROC exportAddress = GetProcAddress(moduleHandle, exportName);
        if (exportAddress == nullptr)
        {
            break;
        }

        *rva = reinterpret_cast<std::uintptr_t>(exportAddress) - reinterpret_cast<std::uintptr_t>(moduleHandle);
        resolved = true;
    }
    while (false);

    return resolved;
}

bool ResolveImageExportRva(const std::wstring& imagePath, const char* exportName, std::uintptr_t* rva, DWORD* errorCode)
{
    bool resolved = false;
    HMODULE moduleHandle = nullptr;

    do
    {
        if (errorCode != nullptr)
        {
            *errorCode = 0;
        }

        moduleHandle = LoadLibraryExW(imagePath.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (moduleHandle == nullptr)
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        if (!ResolveLoadedModuleExportRva(moduleHandle, exportName, rva))
        {
            if (errorCode != nullptr)
            {
                *errorCode = ERROR_PROC_NOT_FOUND;
            }
            break;
        }

        resolved = true;
    }
    while (false);

    if (moduleHandle != nullptr)
    {
        FreeLibrary(moduleHandle);
    }

    return resolved;
}

struct RemoteModuleInfo
{
    std::uintptr_t Base = 0;
    std::wstring Path;
    std::wstring Name;
};

struct CancellationContext
{
    HANDLE EventHandle = nullptr;
    std::string EventName;
};

bool OpenCancellationContext(const std::string& eventName, CancellationContext* context, DWORD* errorCode)
{
    bool opened = false;

    do
    {
        if (context != nullptr)
        {
            context->EventHandle = nullptr;
            context->EventName = eventName;
        }

        if (errorCode != nullptr)
        {
            *errorCode = 0;
        }

        if (eventName.empty())
        {
            opened = true;
            break;
        }

        const std::wstring wideName = Utf8ToWide(eventName);
        if (wideName.empty())
        {
            if (errorCode != nullptr)
            {
                *errorCode = ERROR_INVALID_PARAMETER;
            }
            break;
        }

        HANDLE eventHandle = CreateEventW(nullptr, TRUE, FALSE, wideName.c_str());
        if (eventHandle == nullptr)
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        if (context != nullptr)
        {
            context->EventHandle = eventHandle;
        }
        else
        {
            CloseHandle(eventHandle);
        }

        opened = true;
    }
    while (false);

    return opened;
}

void CloseCancellationContext(CancellationContext& context)
{
    if (context.EventHandle != nullptr)
    {
        CloseHandle(context.EventHandle);
        context.EventHandle = nullptr;
    }
}

bool IsCancellationRequested(const CancellationContext& context)
{
    bool requested = false;

    if (context.EventHandle != nullptr)
    {
        requested = WaitForSingleObject(context.EventHandle, 0) == WAIT_OBJECT_0;
    }

    return requested;
}

bool FindRemoteModuleInfo(DWORD processId, const std::wstring& moduleName, RemoteModuleInfo* moduleInfo, DWORD* errorCode)
{
    bool found = false;
    HANDLE snapshot = INVALID_HANDLE_VALUE;

    do
    {
        if (moduleInfo != nullptr)
        {
            *moduleInfo = {};
        }

        if (errorCode != nullptr)
        {
            *errorCode = 0;
        }

        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        MODULEENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (!Module32FirstW(snapshot, &entry))
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        do
        {
            if (_wcsicmp(entry.szModule, moduleName.c_str()) == 0)
            {
                if (moduleInfo != nullptr)
                {
                    moduleInfo->Base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
                    moduleInfo->Path = entry.szExePath;
                    moduleInfo->Name = entry.szModule;
                }

                found = true;
                break;
            }
        }
        while (Module32NextW(snapshot, &entry));
    }
    while (false);

    if (snapshot != INVALID_HANDLE_VALUE)
    {
        CloseHandle(snapshot);
    }

    return found;
}

bool FindRemoteModuleBase(DWORD processId, const std::wstring& moduleName, std::uintptr_t* moduleBase, DWORD* errorCode)
{
    RemoteModuleInfo moduleInfo;
    const bool found = FindRemoteModuleInfo(processId, moduleName, &moduleInfo, errorCode);

    if (moduleBase != nullptr)
    {
        *moduleBase = found ? moduleInfo.Base : 0;
    }

    return found;
}

bool WaitRemoteThread(
    HANDLE processHandle,
    void* remoteAddress,
    void* remoteParameter,
    DWORD timeoutMs,
    DWORD* exitCode,
    DWORD* errorCode)
{
    bool completed = false;
    HANDLE threadHandle = nullptr;

    do
    {
        if (exitCode != nullptr)
        {
            *exitCode = 0;
        }

        if (errorCode != nullptr)
        {
            *errorCode = 0;
        }

        threadHandle = CreateRemoteThread(
            processHandle,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteAddress),
            remoteParameter,
            0,
            nullptr);

        if (threadHandle == nullptr)
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        const DWORD waitResult = WaitForSingleObject(threadHandle, timeoutMs);
        if (waitResult != WAIT_OBJECT_0)
        {
            if (errorCode != nullptr)
            {
                *errorCode = waitResult == WAIT_TIMEOUT ? WAIT_TIMEOUT : GetLastError();
            }
            break;
        }

        DWORD remoteExitCode = 0;
        if (!GetExitCodeThread(threadHandle, &remoteExitCode))
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        if (exitCode != nullptr)
        {
            *exitCode = remoteExitCode;
        }

        completed = true;
    }
    while (false);

    if (threadHandle != nullptr)
    {
        CloseHandle(threadHandle);
    }

    return completed;
}

std::string AgentControlStatusName(std::uint32_t status)
{
    std::string name = "unknown";

    switch (static_cast<KnMonAgentControlStatus>(status))
    {
    case KnMonAgentControlStatus::Success:
        name = "success";
        break;
    case KnMonAgentControlStatus::InvalidConfig:
        name = "invalid_config";
        break;
    case KnMonAgentControlStatus::UnsupportedAbi:
        name = "unsupported_abi";
        break;
    case KnMonAgentControlStatus::AlreadyRunning:
        name = "already_running";
        break;
    case KnMonAgentControlStatus::WorkerStartFailed:
        name = "worker_start_failed";
        break;
    case KnMonAgentControlStatus::NotRunning:
        name = "not_running";
        break;
    case KnMonAgentControlStatus::InvalidState:
        name = "invalid_state";
        break;
    default:
        break;
    }

    return name;
}

std::string AgentLifecycleStateName(std::uint32_t state)
{
    std::string name = "unknown";

    switch (static_cast<KnMonAgentLifecycleState>(state))
    {
    case KnMonAgentLifecycleState::Starting:
        name = "starting";
        break;
    case KnMonAgentLifecycleState::Running:
        name = "running";
        break;
    case KnMonAgentLifecycleState::Stopping:
        name = "stopping";
        break;
    case KnMonAgentLifecycleState::Disabled:
        name = "disabled";
        break;
    case KnMonAgentLifecycleState::Failed:
        name = "failed";
        break;
    default:
        break;
    }

    return name;
}

bool QueryRemoteAgentState(
    HANDLE processHandle,
    void* remoteQueryAddress,
    DWORD timeoutMs,
    KnMonAgentStateV1* state,
    DWORD* controlStatus,
    DWORD* errorCode,
    std::string* message)
{
    bool queried = false;
    void* remoteState = nullptr;

    do
    {
        if (controlStatus != nullptr)
        {
            *controlStatus = 0;
        }

        if (errorCode != nullptr)
        {
            *errorCode = 0;
        }

        if (message != nullptr)
        {
            message->clear();
        }

        if (processHandle == nullptr || remoteQueryAddress == nullptr || state == nullptr)
        {
            if (errorCode != nullptr)
            {
                *errorCode = ERROR_INVALID_PARAMETER;
            }
            break;
        }

        KnMonAgentStateV1 requestState;
        requestState.StructSize = static_cast<std::uint16_t>(sizeof(requestState));

        remoteState = VirtualAllocEx(processHandle, nullptr, sizeof(requestState), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (remoteState == nullptr)
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(processHandle, remoteState, &requestState, sizeof(requestState), &bytesWritten) || bytesWritten != sizeof(requestState))
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        DWORD remoteExitCode = 0;
        DWORD remoteError = 0;
        if (!WaitRemoteThread(processHandle, remoteQueryAddress, remoteState, timeoutMs, &remoteExitCode, &remoteError))
        {
            if (errorCode != nullptr)
            {
                *errorCode = remoteError == 0 ? ERROR_TIMEOUT : remoteError;
            }
            break;
        }

        if (controlStatus != nullptr)
        {
            *controlStatus = remoteExitCode;
        }

        if (remoteExitCode != static_cast<DWORD>(KnMonAgentControlStatus::Success))
        {
            if (message != nullptr)
            {
                *message = "KnMonAgentQueryState returned " + AgentControlStatusName(remoteExitCode) + ".";
            }
            break;
        }

        KnMonAgentStateV1 localState;
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(processHandle, remoteState, &localState, sizeof(localState), &bytesRead) || bytesRead != sizeof(localState))
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        if (
            localState.Magic != KnMonAgentStateMagic ||
            localState.AbiVersion != KnMonAgentStateAbiVersion ||
            localState.StructSize < sizeof(KnMonAgentStateV1))
        {
            if (errorCode != nullptr)
            {
                *errorCode = ERROR_INVALID_DATA;
            }

            if (message != nullptr)
            {
                *message = "Loaded agent state ABI validation failed.";
            }
            break;
        }

        *state = localState;
        queried = true;
    }
    while (false);

    if (remoteState != nullptr)
    {
        VirtualFreeEx(processHandle, remoteState, 0, MEM_RELEASE);
    }

    return queried;
}

void AddAudit(
    KnMonLaunchResult& result,
    const std::string& eventType,
    const std::string& operation,
    const std::string& message,
    DWORD errorCode,
    const std::string& subsystem)
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

void AddAudit(
    KnMonCaptureResult& result,
    const std::string& eventType,
    const std::string& operation,
    const std::string& message,
    DWORD errorCode,
    const std::string& subsystem)
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

void AddAudit(
    KnMonProcessTreeResult& result,
    const std::string& eventType,
    const std::string& operation,
    const std::string& message,
    DWORD errorCode,
    const std::string& subsystem)
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

void SetResultError(
    KnMonCaptureResult& result,
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

void SetResultError(
    KnMonProcessTreeResult& result,
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

void SetPreflightError(
    KnMonLaunchResult& result,
    DWORD errorCode,
    const std::string& operation,
    const std::string& message)
{
    SetResultError(result, errorCode, "knmon-core", operation, message);
    AddAudit(result, "preflight_failed", operation, message, errorCode, "knmon-core");
}

void SetPreflightError(
    KnMonCaptureResult& result,
    DWORD errorCode,
    const std::string& operation,
    const std::string& message)
{
    SetResultError(result, errorCode, "knmon-core", operation, message);
    AddAudit(result, "preflight_failed", operation, message, errorCode, "knmon-core");
}

template <typename TResult>
bool RunSameBitnessPreflight(
    TResult& result,
    KnMonAgentArchitecture requestedArchitecture,
    const std::string& targetPath,
    const std::string& agentPath)
{
    bool passed = false;

    do
    {
        const KnMonAgentArchitecture helperArchitecture = NativeHelperArchitecture();
        if (requestedArchitecture == KnMonAgentArchitecture::Unknown)
        {
            SetPreflightError(result, ERROR_NOT_SUPPORTED, "unsupported_architecture", "Requested architecture is unknown.");
            break;
        }

        if (helperArchitecture == KnMonAgentArchitecture::Unknown)
        {
            SetPreflightError(result, ERROR_NOT_SUPPORTED, "unsupported_architecture", "Helper build architecture is unknown.");
            break;
        }

        if (requestedArchitecture != helperArchitecture)
        {
            const std::string message = "Requested architecture " + ArchitectureName(requestedArchitecture) + " does not match helper architecture " + ArchitectureName(helperArchitecture) + ". Cross-bitness injection is not supported.";
            SetPreflightError(result, ERROR_NOT_SUPPORTED, "unsupported_architecture", message);
            break;
        }

        BinaryArchitectureResult targetArchitecture = QueryBinaryArchitecture(targetPath, "target");
        if (!targetArchitecture.Success)
        {
            SetPreflightError(result, targetArchitecture.ErrorCode, targetArchitecture.Operation, targetArchitecture.Message);
            break;
        }

        BinaryArchitectureResult agentArchitecture = QueryBinaryArchitecture(agentPath, "agent");
        if (!agentArchitecture.Success)
        {
            SetPreflightError(result, agentArchitecture.ErrorCode, agentArchitecture.Operation, agentArchitecture.Message);
            break;
        }

        if (targetArchitecture.Architecture != requestedArchitecture)
        {
            const std::string message = "Target architecture " + ArchitectureName(targetArchitecture.Architecture) + " does not match requested same-bitness architecture " + ArchitectureName(requestedArchitecture) + ".";
            SetPreflightError(result, ERROR_NOT_SUPPORTED, "unsupported_architecture", message);
            break;
        }

        if (agentArchitecture.Architecture != requestedArchitecture)
        {
            const std::string message = "Agent architecture " + ArchitectureName(agentArchitecture.Architecture) + " does not match requested same-bitness architecture " + ArchitectureName(requestedArchitecture) + ".";
            SetPreflightError(result, ERROR_NOT_SUPPORTED, "helper_agent_mismatch", message);
            break;
        }

        const std::string message = "Same-bitness preflight passed: helper=" + ArchitectureName(helperArchitecture) + " target=" + ArchitectureName(targetArchitecture.Architecture) + " agent=" + ArchitectureName(agentArchitecture.Architecture) + ".";
        AddAudit(result, "preflight_passed", "same_bitness_preflight", message);
        passed = true;
    }
    while (false);

    return passed;
}

bool ValidateHandshakeEvidence(
    KnMonLaunchResult& result,
    KnMonAgentArchitecture expectedArchitecture)
{
    bool valid = false;

    do
    {
        if (result.Handshake.OperationId != result.OperationId)
        {
            const std::string message = "Agent HELLO operation id mismatch: expected " + result.OperationId + " but received " + result.Handshake.OperationId + ".";
            SetResultError(result, ERROR_INVALID_DATA, "knmon-core", "handshake_operation_mismatch", message);
            break;
        }

        if (result.Handshake.Architecture != ArchitectureName(expectedArchitecture))
        {
            const std::string message = "Agent HELLO architecture mismatch: expected " + ArchitectureName(expectedArchitecture) + " but received " + result.Handshake.Architecture + ".";
            SetResultError(result, ERROR_INVALID_DATA, "knmon-core", "handshake_architecture_mismatch", message);
            break;
        }

        if (result.Handshake.SchemaVersion.empty())
        {
            SetResultError(result, ERROR_INVALID_DATA, "knmon-core", "handshake_schema_missing", "Agent HELLO schemaVersion is missing.");
            break;
        }

        AddAudit(result, "handshake_validated", "agent_handshake_read", "Agent HELLO operation id, schema, and architecture were validated.");
        valid = true;
    }
    while (false);

    return valid;
}

bool ValidateHandshakeEvidence(
    KnMonCaptureResult& result,
    KnMonAgentArchitecture expectedArchitecture)
{
    bool valid = false;

    do
    {
        if (result.Handshake.OperationId != result.OperationId)
        {
            const std::string message = "Agent HELLO operation id mismatch: expected " + result.OperationId + " but received " + result.Handshake.OperationId + ".";
            SetResultError(result, ERROR_INVALID_DATA, "knmon-core", "handshake_operation_mismatch", message);
            break;
        }

        if (result.Handshake.Architecture != ArchitectureName(expectedArchitecture))
        {
            const std::string message = "Agent HELLO architecture mismatch: expected " + ArchitectureName(expectedArchitecture) + " but received " + result.Handshake.Architecture + ".";
            SetResultError(result, ERROR_INVALID_DATA, "knmon-core", "handshake_architecture_mismatch", message);
            break;
        }

        if (result.Handshake.SchemaVersion.empty())
        {
            SetResultError(result, ERROR_INVALID_DATA, "knmon-core", "handshake_schema_missing", "Agent HELLO schemaVersion is missing.");
            break;
        }

        AddAudit(result, "handshake_validated", "agent_event_read", "Agent HELLO operation id, schema, and architecture were validated.");
        valid = true;
    }
    while (false);

    return valid;
}

std::uint64_t ExtractJsonUInt64(const std::string& payload, const std::string& key);
KnMonAgentMessage BuildAgentMessage(const KnMonCaptureResult& result, const std::string& rawPayload);

std::string FileNameFromPath(const std::string& path)
{
    std::string result = path;
    const std::size_t slash = result.find_last_of("\\/");
    if (slash != std::string::npos && slash + 1 < result.size())
    {
        result = result.substr(slash + 1);
    }

    return result;
}

std::string HexFixed(std::uint64_t value, int width)
{
    std::ostringstream stream;
    stream << "0x"
           << std::hex
           << std::setfill('0')
           << std::setw(width)
           << value;
    return stream.str();
}

std::string HexPointerValue(std::uint64_t value, const std::string& architecture)
{
    return HexFixed(value, architecture == "x86" ? 8 : 16);
}

std::string HexDwordValue(std::uint32_t value)
{
    return HexFixed(value, 8);
}

std::string WinHttpOptionText(std::uint32_t value)
{
    std::ostringstream stream;
    stream << HexDwordValue(value);

    switch (value)
    {
    case WINHTTP_OPTION_RESOLVE_TIMEOUT:
        stream << " (WINHTTP_OPTION_RESOLVE_TIMEOUT)";
        break;
    case WINHTTP_OPTION_CONNECT_TIMEOUT:
        stream << " (WINHTTP_OPTION_CONNECT_TIMEOUT)";
        break;
    case WINHTTP_OPTION_SEND_TIMEOUT:
        stream << " (WINHTTP_OPTION_SEND_TIMEOUT)";
        break;
    case WINHTTP_OPTION_RECEIVE_TIMEOUT:
        stream << " (WINHTTP_OPTION_RECEIVE_TIMEOUT)";
        break;
    case WINHTTP_OPTION_CONNECT_RETRIES:
        stream << " (WINHTTP_OPTION_CONNECT_RETRIES)";
        break;
    default:
        break;
    }

    return stream.str();
}

std::string LStatusValue(std::uint64_t value)
{
    const std::uint32_t code = static_cast<std::uint32_t>(value);
    return std::to_string(code) + " (" + HexDwordValue(code) + ")";
}

std::string RpcStatusValue(std::uint64_t value)
{
    const std::uint32_t code = static_cast<std::uint32_t>(value);
    return std::to_string(code) + " (" + HexDwordValue(code) + ")";
}

std::string HexNtStatusValue(std::uint32_t value)
{
    return HexFixed(value, 8);
}

std::string HexHResultValue(std::uint32_t value)
{
    return HexFixed(value, 8);
}

std::string ShellFolderPathStatusName(std::uint32_t value)
{
    std::string result = "none";

    switch (value)
    {
    case 1:
        result = "decoded_safe_path";
        break;
    case 2:
        result = "non_allowlisted_no_path";
        break;
    case 3:
        result = "decode_failed";
        break;
    default:
        break;
    }

    return result;
}

std::string ComInitFlagsText(std::uint32_t value)
{
    std::ostringstream stream;
    std::uint32_t remaining = value;
    bool hasName = false;

    stream << HexDwordValue(value);
    stream << " (";

    if (value == 0)
    {
        stream << "COINIT_MULTITHREADED";
        hasName = true;
    }
    else
    {
        if ((value & 0x00000002U) != 0)
        {
            stream << "COINIT_APARTMENTTHREADED";
            remaining &= ~0x00000002U;
            hasName = true;
        }

        if ((value & 0x00000004U) != 0)
        {
            if (hasName)
            {
                stream << "|";
            }

            stream << "COINIT_DISABLE_OLE1DDE";
            remaining &= ~0x00000004U;
            hasName = true;
        }

        if ((value & 0x00000008U) != 0)
        {
            if (hasName)
            {
                stream << "|";
            }

            stream << "COINIT_SPEED_OVER_MEMORY";
            remaining &= ~0x00000008U;
            hasName = true;
        }

        if (remaining != 0)
        {
            if (hasName)
            {
                stream << "|";
            }

            stream << "unknown=" << HexDwordValue(remaining);
            hasName = true;
        }
    }

    if (!hasName)
    {
        stream << "none";
    }

    stream << ")";
    return stream.str();
}

std::string RoInitTypeText(std::uint32_t value)
{
    std::ostringstream stream;

    stream << HexDwordValue(value);
    stream << " (";

    switch (value)
    {
    case 0:
        stream << "RO_INIT_SINGLETHREADED";
        break;
    case 1:
        stream << "RO_INIT_MULTITHREADED";
        break;
    default:
        stream << "unknown";
        break;
    }

    stream << ")";
    return stream.str();
}

struct FlagName
{
    std::uint32_t Mask;
    const char* Name;
};

std::string FlagMaskText(std::uint32_t value, const FlagName* flags, std::size_t count)
{
    std::ostringstream stream;
    std::uint32_t remaining = value;
    bool hasName = false;

    stream << HexDwordValue(value);
    stream << " (";

    for (std::size_t index = 0; index < count; ++index)
    {
        if (flags[index].Mask != 0 && (remaining & flags[index].Mask) == flags[index].Mask)
        {
            if (hasName)
            {
                stream << "|";
            }

            stream << flags[index].Name;
            remaining &= ~flags[index].Mask;
            hasName = true;
        }
    }

    if (remaining != 0)
    {
        if (hasName)
        {
            stream << "|";
        }

        stream << "unknown=" << HexDwordValue(remaining);
        hasName = true;
    }

    if (!hasName)
    {
        stream << "none";
    }

    stream << ")";
    return stream.str();
}

std::string MemoryAllocationTypeText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00001000U, "MEM_COMMIT" },
        { 0x00002000U, "MEM_RESERVE" },
        { 0x00080000U, "MEM_RESET" },
        { 0x00100000U, "MEM_TOP_DOWN" },
        { 0x00200000U, "MEM_WRITE_WATCH" },
        { 0x00400000U, "MEM_PHYSICAL" },
        { 0x01000000U, "MEM_RESET_UNDO" },
        { 0x20000000U, "MEM_LARGE_PAGES" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string MemoryFreeTypeText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00004000U, "MEM_DECOMMIT" },
        { 0x00008000U, "MEM_RELEASE" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string MemoryProtectionFlagsText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00000001U, "PAGE_NOACCESS" },
        { 0x00000002U, "PAGE_READONLY" },
        { 0x00000004U, "PAGE_READWRITE" },
        { 0x00000008U, "PAGE_WRITECOPY" },
        { 0x00000010U, "PAGE_EXECUTE" },
        { 0x00000020U, "PAGE_EXECUTE_READ" },
        { 0x00000040U, "PAGE_EXECUTE_READWRITE" },
        { 0x00000080U, "PAGE_EXECUTE_WRITECOPY" },
        { 0x00000100U, "PAGE_GUARD" },
        { 0x00000200U, "PAGE_NOCACHE" },
        { 0x00000400U, "PAGE_WRITECOMBINE" },
        { 0x40000000U, "PAGE_TARGETS_INVALID" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string FileMappingProtectionFlagsText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00000002U, "PAGE_READONLY" },
        { 0x00000004U, "PAGE_READWRITE" },
        { 0x00000008U, "PAGE_WRITECOPY" },
        { 0x00000020U, "PAGE_EXECUTE_READ" },
        { 0x00000040U, "PAGE_EXECUTE_READWRITE" },
        { 0x00000080U, "PAGE_EXECUTE_WRITECOPY" },
        { 0x04000000U, "SEC_RESERVE" },
        { 0x08000000U, "SEC_COMMIT" },
        { 0x10000000U, "SEC_NOCACHE" },
        { 0x80000000U, "SEC_LARGE_PAGES" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string FileMappingAccessFlagsText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00000001U, "FILE_MAP_COPY" },
        { 0x00000002U, "FILE_MAP_WRITE" },
        { 0x00000004U, "FILE_MAP_READ" },
        { 0x00000020U, "FILE_MAP_EXECUTE" },
        { 0x000f001fU, "FILE_MAP_ALL_ACCESS" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string MemoryStateText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00001000U, "MEM_COMMIT" },
        { 0x00002000U, "MEM_RESERVE" },
        { 0x00010000U, "MEM_FREE" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string MemoryTypeText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00020000U, "MEM_PRIVATE" },
        { 0x00040000U, "MEM_MAPPED" },
        { 0x01000000U, "MEM_IMAGE" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string DwordDecimalHexText(std::uint32_t value)
{
    return std::to_string(value) + " (" + HexDwordValue(value) + ")";
}

std::string UInt64DecimalHexText(std::uint64_t value)
{
    return std::to_string(value) + " (" + HexFixed(value, 16) + ")";
}

std::string StdHandleText(std::uint32_t value)
{
    const char* name = nullptr;
    switch (value)
    {
    case 0xFFFFFFF6U:
        name = "STD_INPUT_HANDLE";
        break;
    case 0xFFFFFFF5U:
        name = "STD_OUTPUT_HANDLE";
        break;
    case 0xFFFFFFF4U:
        name = "STD_ERROR_HANDLE";
        break;
    default:
        break;
    }

    if (name == nullptr)
    {
        return DwordDecimalHexText(value);
    }

    return HexDwordValue(value) + " (" + name + ")";
}

std::string FileTypeText(std::uint32_t value)
{
    const std::uint32_t baseType = value & 0x000000ffU;
    const bool remote = (value & 0x00008000U) != 0;
    const std::uint32_t remaining = value & ~(0x000000ffU | 0x00008000U);
    const char* baseName = nullptr;

    switch (baseType)
    {
    case 0x00000000U:
        baseName = "FILE_TYPE_UNKNOWN";
        break;
    case 0x00000001U:
        baseName = "FILE_TYPE_DISK";
        break;
    case 0x00000002U:
        baseName = "FILE_TYPE_CHAR";
        break;
    case 0x00000003U:
        baseName = "FILE_TYPE_PIPE";
        break;
    default:
        break;
    }

    std::ostringstream stream;
    stream << HexDwordValue(value) << " (";
    bool hasName = false;
    if (baseName != nullptr)
    {
        stream << baseName;
        hasName = true;
    }
    else
    {
        stream << "base=" << HexDwordValue(baseType);
        hasName = true;
    }

    if (remote)
    {
        stream << "|FILE_TYPE_REMOTE";
    }

    if (remaining != 0)
    {
        if (hasName)
        {
            stream << "|";
        }

        stream << "unknown=" << HexDwordValue(remaining);
    }

    stream << ")";
    return stream.str();
}

std::string FileAttributesText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00000001U, "FILE_ATTRIBUTE_READONLY" },
        { 0x00000002U, "FILE_ATTRIBUTE_HIDDEN" },
        { 0x00000004U, "FILE_ATTRIBUTE_SYSTEM" },
        { 0x00000010U, "FILE_ATTRIBUTE_DIRECTORY" },
        { 0x00000020U, "FILE_ATTRIBUTE_ARCHIVE" },
        { 0x00000040U, "FILE_ATTRIBUTE_DEVICE" },
        { 0x00000080U, "FILE_ATTRIBUTE_NORMAL" },
        { 0x00000100U, "FILE_ATTRIBUTE_TEMPORARY" },
        { 0x00000400U, "FILE_ATTRIBUTE_REPARSE_POINT" },
        { 0x00000800U, "FILE_ATTRIBUTE_COMPRESSED" },
        { 0x00001000U, "FILE_ATTRIBUTE_OFFLINE" },
        { 0x00002000U, "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED" },
        { 0x00004000U, "FILE_ATTRIBUTE_ENCRYPTED" },
        { 0x00008000U, "FILE_ATTRIBUTE_INTEGRITY_STREAM" },
        { 0x00020000U, "FILE_ATTRIBUTE_NO_SCRUB_DATA" },
        { 0x00040000U, "FILE_ATTRIBUTE_EA" },
        { 0x00080000U, "FILE_ATTRIBUTE_PINNED" },
        { 0x00100000U, "FILE_ATTRIBUTE_UNPINNED" },
        { 0x00400000U, "FILE_ATTRIBUTE_RECALL_ON_OPEN" },
        { 0x00800000U, "FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string HandleInformationFlagsText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00000001U, "HANDLE_FLAG_INHERIT" },
        { 0x00000002U, "HANDLE_FLAG_PROTECT_FROM_CLOSE" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string GetModuleHandleExFlagsText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00000001U, "GET_MODULE_HANDLE_EX_FLAG_PIN" },
        { 0x00000002U, "GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT" },
        { 0x00000004U, "GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string BoolText(std::uint32_t value)
{
    return value == 0 ? "FALSE" : "TRUE";
}

std::string ThreadAccessFlagsText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00000001U, "THREAD_TERMINATE" },
        { 0x00000002U, "THREAD_SUSPEND_RESUME" },
        { 0x00000008U, "THREAD_GET_CONTEXT" },
        { 0x00000010U, "THREAD_SET_CONTEXT" },
        { 0x00000020U, "THREAD_SET_INFORMATION" },
        { 0x00000040U, "THREAD_QUERY_INFORMATION" },
        { 0x00000080U, "THREAD_SET_THREAD_TOKEN" },
        { 0x00000100U, "THREAD_IMPERSONATE" },
        { 0x00000200U, "THREAD_DIRECT_IMPERSONATION" },
        { 0x00000400U, "THREAD_SET_LIMITED_INFORMATION" },
        { 0x00000800U, "THREAD_QUERY_LIMITED_INFORMATION" },
        { 0x00010000U, "DELETE" },
        { 0x00020000U, "READ_CONTROL" },
        { 0x00040000U, "WRITE_DAC" },
        { 0x00080000U, "WRITE_OWNER" },
        { 0x00100000U, "SYNCHRONIZE" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string ThreadCreationFlagsText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00000004U, "CREATE_SUSPENDED" },
        { 0x00010000U, "STACK_SIZE_PARAM_IS_A_RESERVATION" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string EventAccessFlagsText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00000002U, "EVENT_MODIFY_STATE" },
        { 0x00010000U, "DELETE" },
        { 0x00020000U, "READ_CONTROL" },
        { 0x00040000U, "WRITE_DAC" },
        { 0x00080000U, "WRITE_OWNER" },
        { 0x00100000U, "SYNCHRONIZE" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string MutexAccessFlagsText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00000001U, "MUTEX_MODIFY_STATE" },
        { 0x00010000U, "DELETE" },
        { 0x00020000U, "READ_CONTROL" },
        { 0x00040000U, "WRITE_DAC" },
        { 0x00080000U, "WRITE_OWNER" },
        { 0x00100000U, "SYNCHRONIZE" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string SemaphoreAccessFlagsText(std::uint32_t value)
{
    static constexpr FlagName Flags[] =
    {
        { 0x00000002U, "SEMAPHORE_MODIFY_STATE" },
        { 0x00010000U, "DELETE" },
        { 0x00020000U, "READ_CONTROL" },
        { 0x00040000U, "WRITE_DAC" },
        { 0x00080000U, "WRITE_OWNER" },
        { 0x00100000U, "SYNCHRONIZE" },
    };

    return FlagMaskText(value, Flags, sizeof(Flags) / sizeof(Flags[0]));
}

std::string WaitTimeoutText(std::uint32_t value)
{
    if (value == 0xFFFFFFFFU)
    {
        return HexDwordValue(value) + " (INFINITE)";
    }

    return DwordDecimalHexText(value);
}

std::string WaitResultText(std::uint32_t value)
{
    std::ostringstream stream;

    stream << HexDwordValue(value);
    stream << " (";

    switch (value)
    {
    case 0x00000000U:
        stream << "WAIT_OBJECT_0";
        break;
    case 0x00000080U:
        stream << "WAIT_ABANDONED";
        break;
    case 0x00000102U:
        stream << "WAIT_TIMEOUT";
        break;
    case 0xFFFFFFFFU:
        stream << "WAIT_FAILED";
        break;
    default:
        stream << "unknown";
        break;
    }

    stream << ")";
    return stream.str();
}

std::string MultiWaitResultText(std::uint32_t value, std::uint32_t count)
{
    std::ostringstream stream;

    stream << HexDwordValue(value);
    stream << " (";

    if (count > 0 && value < count)
    {
        stream << "WAIT_OBJECT_0";
        if (value > 0)
        {
            stream << "+" << value;
        }
    }
    else if (count > 0 && value >= 0x00000080U && value < 0x00000080U + count)
    {
        const std::uint32_t index = value - 0x00000080U;
        stream << "WAIT_ABANDONED";
        if (index > 0)
        {
            stream << "+" << index;
        }
    }
    else
    {
        switch (value)
        {
        case 0x00000102U:
            stream << "WAIT_TIMEOUT";
            break;
        case 0xFFFFFFFFU:
            stream << "WAIT_FAILED";
            break;
        default:
            stream << "unknown";
            break;
        }
    }

    stream << ")";
    return stream.str();
}

std::string SignedIntValue(std::uint64_t value)
{
    return std::to_string(static_cast<std::int32_t>(static_cast<std::uint32_t>(value)));
}

std::string SignedIntValue32(std::uint32_t value)
{
    return std::to_string(static_cast<std::int32_t>(value));
}

std::string AddrInfoHintText(std::uint32_t family, std::uint32_t sockType, std::uint32_t protocol)
{
    std::ostringstream stream;
    stream << "family=" << SignedIntValue32(family)
           << ",type=" << SignedIntValue32(sockType)
           << ",protocol=" << SignedIntValue32(protocol);
    return stream.str();
}

std::string DecodeStatusName(std::uint32_t value)
{
    std::string result = "decoded";

    switch (static_cast<KnMonDecodeStatus>(value))
    {
    case KnMonDecodeStatus::Decoded:
        result = "decoded";
        break;
    case KnMonDecodeStatus::Partial:
        result = "partial";
        break;
    case KnMonDecodeStatus::InvalidPointer:
        result = "invalid_pointer";
        break;
    case KnMonDecodeStatus::UnreadableMemory:
        result = "unreadable_memory";
        break;
    case KnMonDecodeStatus::DefinitionMissing:
        result = "definition_missing";
        break;
    case KnMonDecodeStatus::Truncated:
        result = "truncated";
        break;
    default:
        result = "decoded";
        break;
    }

    return result;
}

std::string MemoryBasicInformationText(const KnMonCaptureResult& result, const KnMonTransportRecord& record)
{
    std::ostringstream stream;

    stream << "status=" << DecodeStatusName(record.Values32[0]);
    if (static_cast<KnMonDecodeStatus>(record.Values32[0]) == KnMonDecodeStatus::Decoded)
    {
        stream << ";base=" << HexPointerValue(record.Values64[3], result.Architecture)
               << ";allocationBase=" << HexPointerValue(record.Values64[4], result.Architecture)
               << ";allocationProtect=" << MemoryProtectionFlagsText(record.Values32[1])
               << ";regionSize=" << record.Values64[5]
               << ";state=" << MemoryStateText(record.Values32[2])
               << ";protect=" << MemoryProtectionFlagsText(record.Values32[3])
               << ";type=" << MemoryTypeText(record.Values32[4]);
    }

    return stream.str();
}

std::string TransportApiName(std::uint16_t apiId)
{
    std::string result = "Unknown";

    const KnMonGeneratedApiMetadata* metadata = FindGeneratedApiMetadata(apiId);
    if (metadata != nullptr)
    {
        result = std::string(metadata->Name);
    }

    return result;
}

std::string TransportModuleName(std::uint16_t moduleId)
{
    std::string result = "unknown.dll";

    const KnMonGeneratedModuleMetadata* metadata = FindGeneratedModuleMetadata(moduleId);
    if (metadata != nullptr)
    {
        result = std::string(metadata->Name);
    }

    return result;
}

std::string MetadataValue(std::string_view value, const std::string& fallback)
{
    std::string result = fallback;

    if (!value.empty())
    {
        result = std::string(value);
    }

    return result;
}

std::string TransportText(const char* text, std::uint32_t length, std::size_t capacity)
{
    std::string result;

    do
    {
        if (text == nullptr || capacity == 0)
        {
            break;
        }

        std::size_t actualLength = 0;
        if (length > 0 && length < capacity)
        {
            actualLength = length;
        }
        else
        {
            while (actualLength < capacity && text[actualLength] != '\0')
            {
                ++actualLength;
            }
        }

        result.assign(text, actualLength);
    }
    while (false);

    return result;
}

std::string ArgumentJson(
    int index,
    const std::string& type,
    const std::string& name,
    const std::string& direction,
    const std::string& preCallValue,
    const std::string& postCallValue,
    const std::string& decodedValue,
    const std::string& decodeStatus = "decoded",
    const std::string& decodeAlias = "",
    const std::string& captureTiming = "")
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"index\":" << index << ",";
    stream << "\"type\":" << Q(type) << ",";
    stream << "\"name\":" << Q(name) << ",";
    stream << "\"direction\":" << Q(direction) << ",";
    stream << "\"rawValue\":" << Q(preCallValue) << ",";
    stream << "\"preCallValue\":" << Q(preCallValue) << ",";
    stream << "\"postCallValue\":" << Q(postCallValue) << ",";
    stream << "\"decodedValue\":" << Q(decodedValue) << ",";
    stream << "\"decodeStatus\":" << Q(decodeStatus);
    if (!decodeAlias.empty())
    {
        stream << ",\"decodeAlias\":" << Q(decodeAlias);
    }
    if (!captureTiming.empty())
    {
        stream << ",\"captureTiming\":" << Q(captureTiming);
    }
    stream << "}";
    return stream.str();
}

std::string ArgumentJsonFromMetadata(
    std::uint16_t apiId,
    int index,
    const std::string& fallbackType,
    const std::string& fallbackName,
    const std::string& fallbackDirection,
    const std::string& preCallValue,
    const std::string& postCallValue,
    const std::string& decodedValue,
    const std::string& decodeStatus = "decoded")
{
    const KnMonGeneratedParameterMetadata* metadata = FindGeneratedParameterMetadata(apiId, static_cast<std::uint16_t>(index));
    const std::string type = metadata == nullptr ? fallbackType : MetadataValue(metadata->Type, fallbackType);
    const std::string name = metadata == nullptr ? fallbackName : MetadataValue(metadata->Name, fallbackName);
    const std::string direction = metadata == nullptr ? fallbackDirection : MetadataValue(metadata->Direction, fallbackDirection);
    const std::string decodeAlias = metadata == nullptr ? "" : std::string(metadata->Decode);
    const std::string captureTiming = metadata == nullptr ? "" : std::string(metadata->CaptureTiming);

    return ArgumentJson(index, type, name, direction, preCallValue, postCallValue, decodedValue, decodeStatus, decodeAlias, captureTiming);
}

std::string ApiCallPayload(
    const KnMonCaptureResult& result,
    const KnMonTransportRecord& record,
    const std::string& returnValue,
    const std::string& argumentsJson,
    const std::string& bufferPreview,
    const std::string& categoryTag = "",
    const std::string& detailTag = "")
{
    const KnMonGeneratedApiMetadata* metadata = FindGeneratedApiMetadata(record.ApiId);
    const std::string apiName = TransportApiName(record.ApiId);
    const std::string moduleName = TransportModuleName(record.ModuleId);
    const std::string apiFamily = metadata == nullptr ? "uncategorized" : MetadataValue(metadata->Family, "uncategorized");
    const std::string apiCategory = metadata == nullptr ? "uncategorized" : MetadataValue(metadata->Category, "uncategorized");
    const std::string apiRisk = metadata == nullptr ? "medium" : MetadataValue(metadata->Risk, "medium");
    const std::string hookPolicy = metadata == nullptr ? "unknown" : MetadataValue(metadata->HookPolicy, "unknown");
    const std::string coverageStatus = metadata == nullptr ? "unknown" : MetadataValue(metadata->CoverageStatus, "unknown");
    const std::string resolvedCategoryTag = categoryTag.empty() ? apiFamily : categoryTag;
    const std::string resolvedDetailTag = detailTag.empty() ? apiCategory : detailTag;
    const std::string agentName = FileNameFromPath(result.AgentPath);
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"messageType\":\"api_call\",";
    stream << "\"operationId\":" << Q(result.OperationId) << ",";
    stream << "\"pid\":" << record.ProcessId << ",";
    stream << "\"tid\":" << record.ThreadId << ",";
    stream << "\"timestampUtc\":" << Q(NowUtc()) << ",";
    stream << "\"sequence\":" << record.Sequence << ",";
    stream << "\"api\":" << Q(apiName) << ",";
    stream << "\"module\":" << Q(moduleName) << ",";
    stream << "\"process\":\"knmon-sample-fileio.exe\",";
    stream << "\"apiFamily\":" << Q(apiFamily) << ",";
    stream << "\"apiCategory\":" << Q(apiCategory) << ",";
    stream << "\"apiRisk\":" << Q(apiRisk) << ",";
    stream << "\"hookPolicy\":" << Q(hookPolicy) << ",";
    stream << "\"coverageStatus\":" << Q(coverageStatus) << ",";
    stream << "\"returnValue\":" << Q(returnValue) << ",";
    stream << "\"lastErrorCode\":" << record.LastErrorCode << ",";
    stream << "\"lastErrorMessage\":" << Q(record.LastErrorCode == 0 ? "success" : FormatWindowsError(record.LastErrorCode)) << ",";
    stream << "\"durationUs\":" << record.DurationUs << ",";
    stream << "\"arguments\":[" << argumentsJson << "],";
    stream << "\"tags\":[\"native-capture\"," << Q(resolvedCategoryTag);
    if (!resolvedDetailTag.empty() && resolvedDetailTag != resolvedCategoryTag)
    {
        stream << "," << Q(resolvedDetailTag);
    }
    if (resolvedCategoryTag == "file-io")
    {
        stream << "," << Q("file");
    }
    stream << ",\"hook\",\"shared-memory\"],";
    stream << "\"stack\":[" << Q(agentName + "!IatHook") << "," << Q(moduleName + "!" + apiName) << "],";
    stream << "\"bufferPreview\":" << Q(bufferPreview);
    stream << "}";
    return stream.str();
}

bool IsGenericInventoryRecord(const KnMonTransportRecord& record)
{
    return (record.Flags & KnMonTransportRecordFlagGenericInventory) != 0;
}

std::string MetadataTokenValue(const std::string& text, const std::string& key, const std::string& fallback)
{
    std::string result = fallback;
    std::size_t start = 0;

    while (start <= text.size())
    {
        std::size_t end = text.find(';', start);
        if (end == std::string::npos)
        {
            end = text.size();
        }

        const std::string token = text.substr(start, end - start);
        const std::size_t separator = token.find('=');
        if (separator != std::string::npos && token.substr(0, separator) == key)
        {
            result = token.substr(separator + 1);
            break;
        }

        if (end == text.size())
        {
            break;
        }

        start = end + 1;
    }

    return result;
}

struct GenericArgumentSchema
{
    std::string Name = "arg0";
    std::string Type = "PVOID";
    std::string Direction = "in";
    std::string DecodeHint = "pointer";
};

GenericArgumentSchema ParseGenericArgumentSchema(const std::string& text)
{
    GenericArgumentSchema schema;
    std::array<std::string*, 4> fields =
    {{
        &schema.Name,
        &schema.Type,
        &schema.Direction,
        &schema.DecodeHint
    }};
    std::size_t start = 0;
    std::size_t fieldIndex = 0;

    while (fieldIndex < fields.size() && start <= text.size())
    {
        std::size_t end = text.find('|', start);
        if (end == std::string::npos)
        {
            end = text.size();
        }

        *fields[fieldIndex] = text.substr(start, end - start);
        ++fieldIndex;

        if (end == text.size())
        {
            break;
        }

        start = end + 1;
    }

    if (schema.Name.empty())
    {
        schema.Name = "arg0";
    }

    if (schema.Type.empty())
    {
        schema.Type = "PVOID";
    }

    if (schema.Direction.empty())
    {
        schema.Direction = "in";
    }

    if (schema.DecodeHint.empty())
    {
        schema.DecodeHint = "pointer";
    }

    return schema;
}

std::string GenericReturnValueText(const KnMonCaptureResult& result, const KnMonTransportRecord& record)
{
    std::string value = "void";

    switch (record.Values32[2])
    {
    case 1:
        value = record.ReturnValue == 0 ? "FALSE" : "TRUE";
        break;
    case 2:
        value = DwordDecimalHexText(static_cast<std::uint32_t>(record.ReturnValue));
        break;
    case 3:
        value = HexPointerValue(record.ReturnValue, result.Architecture);
        break;
    case 0:
    default:
        value = "void";
        break;
    }

    return value;
}

std::string GenericTransportApiPayload(
    const KnMonCaptureResult& result,
    const KnMonTransportRecord& record,
    const std::string& text0,
    const std::string& text1,
    const std::string& text2)
{
    const std::string apiName = text0.empty() ? TransportApiName(record.ApiId) : text0;
    const std::string moduleName = TransportModuleName(record.ModuleId);
    const std::string apiFamily = MetadataTokenValue(text1, "family", "tier1");
    const std::string apiCategory = MetadataTokenValue(text1, "category", "tier1/generic");
    const std::string profile = MetadataTokenValue(text1, "profile", "tier1");
    const std::string inventoryKey = MetadataTokenValue(text1, "inventoryKey", moduleName + "!" + apiName);
    const GenericArgumentSchema schema = ParseGenericArgumentSchema(text2);
    const bool scalarArgument = schema.DecodeHint == "raw" || schema.DecodeHint == "scalar" || schema.DecodeHint == "object";
    const std::string argumentValue = scalarArgument ?
        DwordDecimalHexText(static_cast<std::uint32_t>(record.Values64[0])) :
        HexPointerValue(record.Values64[0], result.Architecture);
    const std::string decoded = scalarArgument ? argumentValue : (schema.DecodeHint + ";pointer=" + argumentValue);
    const std::string agentName = FileNameFromPath(result.AgentPath);
    std::ostringstream args;
    args << ArgumentJson(
        0,
        schema.Type,
        schema.Name,
        schema.Direction,
        argumentValue,
        argumentValue,
        decoded,
        DecodeStatusName(record.Values32[1]),
        "generic_pointer",
        "pre_post");

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"messageType\":\"api_call\",";
    stream << "\"operationId\":" << Q(result.OperationId) << ",";
    stream << "\"pid\":" << record.ProcessId << ",";
    stream << "\"tid\":" << record.ThreadId << ",";
    stream << "\"timestampUtc\":" << Q(NowUtc()) << ",";
    stream << "\"sequence\":" << record.Sequence << ",";
    stream << "\"api\":" << Q(apiName) << ",";
    stream << "\"module\":" << Q(moduleName) << ",";
    stream << "\"process\":\"knmon-sample-fileio.exe\",";
    stream << "\"apiFamily\":" << Q(apiFamily) << ",";
    stream << "\"apiCategory\":" << Q(apiCategory) << ",";
    stream << "\"apiRisk\":\"medium\",";
    stream << "\"hookPolicy\":\"tier1_generic_iat\",";
    stream << "\"coverageStatus\":\"generic_decoded\",";
    stream << "\"inventoryKey\":" << Q(inventoryKey) << ",";
    stream << "\"tier1Profile\":" << Q(profile) << ",";
    stream << "\"returnValue\":" << Q(GenericReturnValueText(result, record)) << ",";
    stream << "\"lastErrorCode\":" << record.LastErrorCode << ",";
    stream << "\"lastErrorMessage\":" << Q(record.LastErrorCode == 0 ? "success" : FormatWindowsError(record.LastErrorCode)) << ",";
    stream << "\"durationUs\":" << record.DurationUs << ",";
    stream << "\"arguments\":[" << args.str() << "],";
    stream << "\"tags\":[\"native-capture\",\"tier1\",\"generic\"," << Q(profile) << "," << Q(apiFamily) << ",\"hook\",\"shared-memory\"],";
    stream << "\"stack\":[" << Q(agentName + "!IatHook") << "," << Q(moduleName + "!" + apiName) << "],";
    stream << "\"bufferPreview\":\"\"";
    stream << "}";
    return stream.str();
}

std::string BuildTransportApiPayload(const KnMonCaptureResult& result, const KnMonTransportRecord& record)
{
    std::string payload;
    const std::string text0 = TransportText(record.Text0, record.Text0Length, sizeof(record.Text0));
    const std::string text1 = TransportText(record.Text1, record.Text1Length, sizeof(record.Text1));
    const std::string text2 = TransportText(record.Text2, record.Text2Length, sizeof(record.Text2));
    std::ostringstream args;

    if (IsGenericInventoryRecord(record))
    {
        return GenericTransportApiPayload(result, record, text0, text1, text2);
    }

    switch (static_cast<KnMonTransportApiId>(record.ApiId))
    {
    case KnMonTransportApiId::CreateFileW:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCWSTR", "lpFileName", "in", text0, text0, text0) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwDesiredAccess", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "dwShareMode", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "DWORD", "dwCreationDisposition", "in", HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::CreateFileA:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCSTR", "lpFileName", "in", text0, text0, text0) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwDesiredAccess", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "dwShareMode", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "DWORD", "dwCreationDisposition", "in", HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::ReadFile:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hFile", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPVOID", "lpBuffer", "out", HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "nNumberOfBytesToRead", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), std::to_string(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "LPDWORD", "lpNumberOfBytesRead", "out", "0x00000000", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), text0);
        break;
    case KnMonTransportApiId::WriteFile:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hFile", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPCVOID", "lpBuffer", "in", HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), text0) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "nNumberOfBytesToWrite", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), std::to_string(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "LPDWORD", "lpNumberOfBytesWritten", "out", "0x00000000", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), text0);
        break;
    case KnMonTransportApiId::CloseHandle:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hObject", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    case KnMonTransportApiId::VirtualAlloc:
    {
        const std::string addressPointer = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPVOID", "lpAddress", "in", addressPointer, addressPointer, addressPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "SIZE_T", "dwSize", "in", std::to_string(record.Values64[1]), std::to_string(record.Values64[1]), std::to_string(record.Values64[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "flAllocationType", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), MemoryAllocationTypeText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "DWORD", "flProtect", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), MemoryProtectionFlagsText(record.Values32[1]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::VirtualFree:
    {
        const std::string addressPointer = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPVOID", "lpAddress", "in", addressPointer, addressPointer, addressPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "SIZE_T", "dwSize", "in", std::to_string(record.Values64[1]), std::to_string(record.Values64[1]), std::to_string(record.Values64[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "dwFreeType", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), MemoryFreeTypeText(record.Values32[0]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::VirtualProtect:
    {
        const std::string addressPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string oldProtectPointer = HexPointerValue(record.Values64[2], result.Architecture);
        const std::string oldProtectValue = HexDwordValue(record.Values32[2]);
        const bool oldProtectDecoded = static_cast<KnMonDecodeStatus>(record.Values32[1]) == KnMonDecodeStatus::Decoded;
        const std::string oldProtectPost = oldProtectDecoded ? oldProtectValue : oldProtectPointer;
        const std::string oldProtectDecodedValue = oldProtectDecoded ?
            MemoryProtectionFlagsText(record.Values32[2]) :
            (DecodeStatusName(record.Values32[1]) + ";pointer=" + oldProtectPointer);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPVOID", "lpAddress", "in", addressPointer, addressPointer, addressPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "SIZE_T", "dwSize", "in", std::to_string(record.Values64[1]), std::to_string(record.Values64[1]), std::to_string(record.Values64[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "flNewProtect", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), MemoryProtectionFlagsText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "PDWORD", "lpflOldProtect", "out", oldProtectPointer, oldProtectPost, oldProtectDecodedValue, DecodeStatusName(record.Values32[1]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::VirtualQuery:
    {
        const std::string addressPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string bufferPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string bufferValue = MemoryBasicInformationText(result, record);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCVOID", "lpAddress", "in", addressPointer, addressPointer, addressPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "PMEMORY_BASIC_INFORMATION", "lpBuffer", "out", bufferPointer, bufferValue, bufferValue, DecodeStatusName(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "SIZE_T", "dwLength", "in", std::to_string(record.Values64[2]), std::to_string(record.Values64[2]), std::to_string(record.Values64[2]));
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::CreateFileMappingW:
    {
        const std::string fileHandle = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string attributesPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string namePointer = HexPointerValue(record.Values64[2], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hFile", "in", fileHandle, fileHandle, fileHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPSECURITY_ATTRIBUTES", "lpFileMappingAttributes", "in", attributesPointer, attributesPointer, attributesPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "flProtect", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), FileMappingProtectionFlagsText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "DWORD", "dwMaximumSizeHigh", "in", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]), DwordDecimalHexText(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "DWORD", "dwMaximumSizeLow", "in", std::to_string(record.Values32[2]), std::to_string(record.Values32[2]), DwordDecimalHexText(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 5, "LPCWSTR", "lpName", "in", namePointer, namePointer, namePointer);
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::OpenFileMappingW:
    {
        const std::string namePointer = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "DWORD", "dwDesiredAccess", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), FileMappingAccessFlagsText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "BOOL", "bInheritHandle", "in", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]), BoolText(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPCWSTR", "lpName", "in", namePointer, namePointer, namePointer);
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::MapViewOfFile:
    {
        const std::string mappingHandle = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hFileMappingObject", "in", mappingHandle, mappingHandle, mappingHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwDesiredAccess", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), FileMappingAccessFlagsText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "dwFileOffsetHigh", "in", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]), DwordDecimalHexText(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "DWORD", "dwFileOffsetLow", "in", std::to_string(record.Values32[2]), std::to_string(record.Values32[2]), DwordDecimalHexText(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "SIZE_T", "dwNumberOfBytesToMap", "in", std::to_string(record.Values64[1]), std::to_string(record.Values64[1]), std::to_string(record.Values64[1]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::UnmapViewOfFile:
    {
        const std::string baseAddress = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCVOID", "lpBaseAddress", "in", baseAddress, baseAddress, baseAddress);
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetCurrentProcess:
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::GetCurrentProcessId:
        payload = ApiCallPayload(result, record, DwordDecimalHexText(static_cast<std::uint32_t>(record.ReturnValue)), args.str(), "");
        break;
    case KnMonTransportApiId::GetCurrentThread:
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::GetCurrentThreadId:
        payload = ApiCallPayload(result, record, DwordDecimalHexText(static_cast<std::uint32_t>(record.ReturnValue)), args.str(), "");
        break;
    case KnMonTransportApiId::GetProcessId:
    {
        const std::string processHandle = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string processIdValue = DwordDecimalHexText(static_cast<std::uint32_t>(record.ReturnValue));
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "Process", "in", processHandle, processHandle, processHandle);
        payload = ApiCallPayload(result, record, processIdValue, args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetThreadId:
    {
        const std::string threadHandle = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string threadIdValue = DwordDecimalHexText(static_cast<std::uint32_t>(record.ReturnValue));
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "Thread", "in", threadHandle, threadHandle, threadHandle);
        payload = ApiCallPayload(result, record, threadIdValue, args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetStdHandle:
    {
        const std::string stdHandleValue = StdHandleText(record.Values32[0]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "DWORD", "nStdHandle", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), stdHandleValue);
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetFileType:
    {
        const std::string fileHandle = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string fileTypeValue = FileTypeText(static_cast<std::uint32_t>(record.ReturnValue));
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hFile", "in", fileHandle, fileHandle, fileHandle);
        payload = ApiCallPayload(result, record, fileTypeValue, args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetHandleInformation:
    {
        const std::string objectHandle = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string flagsPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const bool flagsDecoded = static_cast<KnMonDecodeStatus>(record.Values32[0]) == KnMonDecodeStatus::Decoded;
        const std::string flagsValue = HexDwordValue(record.Values32[1]);
        const std::string flagsPost = flagsDecoded ? flagsValue : flagsPointer;
        const std::string flagsDecodedValue = flagsDecoded ?
            HandleInformationFlagsText(record.Values32[1]) :
            (DecodeStatusName(record.Values32[0]) + ";pointer=" + flagsPointer);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hObject", "in", objectHandle, objectHandle, objectHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPDWORD", "lpdwFlags", "out", flagsPointer, flagsPost, flagsDecodedValue, DecodeStatusName(record.Values32[0]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::SetHandleInformation:
    {
        const std::string objectHandle = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hObject", "in", objectHandle, objectHandle, objectHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwMask", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HandleInformationFlagsText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "dwFlags", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HandleInformationFlagsText(record.Values32[1]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetFileSizeEx:
    {
        const std::string fileHandle = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string fileSizePointer = HexPointerValue(record.Values64[1], result.Architecture);
        const bool sizeDecoded = static_cast<KnMonDecodeStatus>(record.Values32[0]) == KnMonDecodeStatus::Decoded;
        const std::string fileSizeValue = UInt64DecimalHexText(record.Values64[2]);
        const std::string fileSizePost = sizeDecoded ? fileSizeValue : fileSizePointer;
        const std::string fileSizeDecodedValue = sizeDecoded ?
            fileSizeValue :
            (DecodeStatusName(record.Values32[0]) + ";pointer=" + fileSizePointer);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hFile", "in", fileHandle, fileHandle, fileHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "PLARGE_INTEGER", "lpFileSize", "out", fileSizePointer, fileSizePost, fileSizeDecodedValue, DecodeStatusName(record.Values32[0]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetFileTime:
    {
        const std::string fileHandle = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string creationTimePointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string lastAccessTimePointer = HexPointerValue(record.Values64[2], result.Architecture);
        const std::string lastWriteTimePointer = HexPointerValue(record.Values64[3], result.Architecture);
        const bool creationTimeDecoded = static_cast<KnMonDecodeStatus>(record.Values32[0]) == KnMonDecodeStatus::Decoded;
        const bool lastAccessTimeDecoded = static_cast<KnMonDecodeStatus>(record.Values32[1]) == KnMonDecodeStatus::Decoded;
        const bool lastWriteTimeDecoded = static_cast<KnMonDecodeStatus>(record.Values32[2]) == KnMonDecodeStatus::Decoded;
        const std::string creationTimeValue = std::to_string(record.Values64[4]);
        const std::string lastAccessTimeValue = std::to_string(record.Values64[5]);
        const std::string lastWriteTimeValue = std::to_string(record.Values64[6]);
        const std::string creationTimePost = creationTimeDecoded ? creationTimeValue : creationTimePointer;
        const std::string lastAccessTimePost = lastAccessTimeDecoded ? lastAccessTimeValue : lastAccessTimePointer;
        const std::string lastWriteTimePost = lastWriteTimeDecoded ? lastWriteTimeValue : lastWriteTimePointer;
        const std::string creationTimeDecodedValue = creationTimeDecoded ?
            creationTimeValue :
            (DecodeStatusName(record.Values32[0]) + ";pointer=" + creationTimePointer);
        const std::string lastAccessTimeDecodedValue = lastAccessTimeDecoded ?
            lastAccessTimeValue :
            (DecodeStatusName(record.Values32[1]) + ";pointer=" + lastAccessTimePointer);
        const std::string lastWriteTimeDecodedValue = lastWriteTimeDecoded ?
            lastWriteTimeValue :
            (DecodeStatusName(record.Values32[2]) + ";pointer=" + lastWriteTimePointer);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hFile", "in", fileHandle, fileHandle, fileHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPFILETIME", "lpCreationTime", "out", creationTimePointer, creationTimePost, creationTimeDecodedValue, DecodeStatusName(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPFILETIME", "lpLastAccessTime", "out", lastAccessTimePointer, lastAccessTimePost, lastAccessTimeDecodedValue, DecodeStatusName(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "LPFILETIME", "lpLastWriteTime", "out", lastWriteTimePointer, lastWriteTimePost, lastWriteTimeDecodedValue, DecodeStatusName(record.Values32[2]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetFileInformationByHandle:
    {
        const std::string fileHandle = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string infoPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const bool infoDecoded = static_cast<KnMonDecodeStatus>(record.Values32[0]) == KnMonDecodeStatus::Decoded;
        std::ostringstream infoDecodedStream;
        infoDecodedStream << "dwFileAttributes=" << FileAttributesText(record.Values32[1])
                          << ";dwVolumeSerialNumber=" << DwordDecimalHexText(record.Values32[2])
                          << ";nFileSize=" << UInt64DecimalHexText(record.Values64[2])
                          << ";nNumberOfLinks=" << DwordDecimalHexText(record.Values32[3])
                          << ";nFileIndex=" << UInt64DecimalHexText(record.Values64[3])
                          << ";ftCreationTime=" << record.Values64[4]
                          << ";ftLastAccessTime=" << record.Values64[5]
                          << ";ftLastWriteTime=" << record.Values64[6];
        const std::string infoDecodedValue = infoDecoded ?
            infoDecodedStream.str() :
            (DecodeStatusName(record.Values32[0]) + ";pointer=" + infoPointer);
        const std::string infoPost = infoDecoded ? infoDecodedStream.str() : infoPointer;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hFile", "in", fileHandle, fileHandle, fileHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPBY_HANDLE_FILE_INFORMATION", "lpFileInformation", "out", infoPointer, infoPost, infoDecodedValue, DecodeStatusName(record.Values32[0]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetModuleHandleW:
    {
        const std::string moduleNamePointer = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCWSTR", "lpModuleName", "in", moduleNamePointer, text0, text0, DecodeStatusName(record.Values32[0]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetModuleHandleExW:
    {
        const bool fromAddress = (record.Values32[0] & 0x00000004U) != 0;
        const std::string moduleNamePointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string moduleNameValue = fromAddress ? moduleNamePointer : text0;
        const std::string modulePointer = HexPointerValue(record.Values64[1], result.Architecture);
        const bool moduleDecoded = static_cast<KnMonDecodeStatus>(record.Values32[2]) == KnMonDecodeStatus::Decoded;
        const std::string modulePost = moduleDecoded ? HexPointerValue(record.Values64[2], result.Architecture) : modulePointer;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "DWORD", "dwFlags", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), GetModuleHandleExFlagsText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPCWSTR", "lpModuleName", "in", moduleNamePointer, moduleNameValue, moduleNameValue, DecodeStatusName(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "HMODULE*", "phModule", "out", modulePointer, modulePost, modulePost, DecodeStatusName(record.Values32[2]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetModuleFileNameW:
    {
        const std::string moduleHandle = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string fileNamePointer = HexPointerValue(record.Values64[1], result.Architecture);
        const bool fileNameDecoded = static_cast<KnMonDecodeStatus>(record.Values32[1]) == KnMonDecodeStatus::Decoded ||
            static_cast<KnMonDecodeStatus>(record.Values32[1]) == KnMonDecodeStatus::Truncated ||
            static_cast<KnMonDecodeStatus>(record.Values32[1]) == KnMonDecodeStatus::Partial;
        const std::string fileNamePost = fileNameDecoded ? text0 : fileNamePointer;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HMODULE", "hModule", "in", moduleHandle, moduleHandle, moduleHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPWSTR", "lpFilename", "out", fileNamePointer, fileNamePost, fileNamePost, DecodeStatusName(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "nSize", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), DwordDecimalHexText(record.Values32[0]));
        payload = ApiCallPayload(result, record, DwordDecimalHexText(static_cast<std::uint32_t>(record.ReturnValue)), args.str(), "");
        break;
    }
    case KnMonTransportApiId::FreeLibrary:
    {
        const std::string moduleHandle = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HMODULE", "hLibModule", "in", moduleHandle, moduleHandle, moduleHandle);
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::CreateThread:
    {
        const std::string attributesPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string startPointer = HexPointerValue(record.Values64[2], result.Architecture);
        const std::string parameterPointer = HexPointerValue(record.Values64[3], result.Architecture);
        const std::string threadIdPointer = HexPointerValue(record.Values64[4], result.Architecture);
        const bool threadIdDecoded = static_cast<KnMonDecodeStatus>(record.Values32[1]) == KnMonDecodeStatus::Decoded;
        const std::string threadIdValue = DwordDecimalHexText(record.Values32[2]);
        const std::string threadIdPost = threadIdDecoded ? std::to_string(record.Values32[2]) : threadIdPointer;
        const std::string threadIdDecodedValue = threadIdDecoded ?
            ("value=" + threadIdValue) :
            (DecodeStatusName(record.Values32[1]) + ";pointer=" + threadIdPointer);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPSECURITY_ATTRIBUTES", "lpThreadAttributes", "in", attributesPointer, attributesPointer, attributesPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "SIZE_T", "dwStackSize", "in", std::to_string(record.Values64[1]), std::to_string(record.Values64[1]), std::to_string(record.Values64[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPTHREAD_START_ROUTINE", "lpStartAddress", "in", startPointer, startPointer, startPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "LPVOID", "lpParameter", "in", parameterPointer, parameterPointer, parameterPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "DWORD", "dwCreationFlags", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), ThreadCreationFlagsText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 5, "LPDWORD", "lpThreadId", "out", threadIdPointer, threadIdPost, threadIdDecodedValue, DecodeStatusName(record.Values32[1]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::OpenThread:
    {
        const std::string threadIdValue = DwordDecimalHexText(record.Values32[2]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "DWORD", "dwDesiredAccess", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), ThreadAccessFlagsText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "BOOL", "bInheritHandle", "in", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]), BoolText(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "dwThreadId", "in", std::to_string(record.Values32[2]), std::to_string(record.Values32[2]), threadIdValue);
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::WaitForSingleObject:
    {
        const std::string handlePointer = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hHandle", "in", handlePointer, handlePointer, handlePointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwMilliseconds", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), WaitTimeoutText(record.Values32[0]));
        payload = ApiCallPayload(result, record, WaitResultText(static_cast<std::uint32_t>(record.ReturnValue)), args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetExitCodeThread:
    {
        const std::string threadPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string exitCodePointer = HexPointerValue(record.Values64[1], result.Architecture);
        const bool exitCodeDecoded = static_cast<KnMonDecodeStatus>(record.Values32[0]) == KnMonDecodeStatus::Decoded;
        const std::string exitCodeValue = DwordDecimalHexText(record.Values32[1]);
        const std::string exitCodePost = exitCodeDecoded ? std::to_string(record.Values32[1]) : exitCodePointer;
        const std::string exitCodeDecodedValue = exitCodeDecoded ?
            ("value=" + exitCodeValue) :
            (DecodeStatusName(record.Values32[0]) + ";pointer=" + exitCodePointer);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hThread", "in", threadPointer, threadPointer, threadPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPDWORD", "lpExitCode", "out", exitCodePointer, exitCodePost, exitCodeDecodedValue, DecodeStatusName(record.Values32[0]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::CreateEventW:
    {
        const std::string attributesPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string namePointer = HexPointerValue(record.Values64[1], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPSECURITY_ATTRIBUTES", "lpEventAttributes", "in", attributesPointer, attributesPointer, attributesPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "BOOL", "bManualReset", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), BoolText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "BOOL", "bInitialState", "in", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]), BoolText(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "LPCWSTR", "lpName", "in", namePointer, namePointer, namePointer);
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::OpenEventW:
    {
        const std::string namePointer = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "DWORD", "dwDesiredAccess", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), EventAccessFlagsText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "BOOL", "bInheritHandle", "in", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]), BoolText(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPCWSTR", "lpName", "in", namePointer, namePointer, namePointer);
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::SetEvent:
    {
        const std::string eventHandle = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hEvent", "in", eventHandle, eventHandle, eventHandle);
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::ResetEvent:
    {
        const std::string eventHandle = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hEvent", "in", eventHandle, eventHandle, eventHandle);
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::WaitForSingleObjectEx:
    {
        const std::string handlePointer = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hHandle", "in", handlePointer, handlePointer, handlePointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwMilliseconds", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), WaitTimeoutText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "BOOL", "bAlertable", "in", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]), BoolText(record.Values32[1]));
        payload = ApiCallPayload(result, record, WaitResultText(static_cast<std::uint32_t>(record.ReturnValue)), args.str(), "");
        break;
    }
    case KnMonTransportApiId::CreateMutexW:
    {
        const std::string attributesPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string namePointer = HexPointerValue(record.Values64[1], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPSECURITY_ATTRIBUTES", "lpMutexAttributes", "in", attributesPointer, attributesPointer, attributesPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "BOOL", "bInitialOwner", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), BoolText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPCWSTR", "lpName", "in", namePointer, namePointer, namePointer);
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::OpenMutexW:
    {
        const std::string namePointer = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "DWORD", "dwDesiredAccess", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), MutexAccessFlagsText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "BOOL", "bInheritHandle", "in", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]), BoolText(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPCWSTR", "lpName", "in", namePointer, namePointer, namePointer);
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::ReleaseMutex:
    {
        const std::string mutexHandle = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hMutex", "in", mutexHandle, mutexHandle, mutexHandle);
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::CreateSemaphoreW:
    {
        const std::string attributesPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string namePointer = HexPointerValue(record.Values64[1], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPSECURITY_ATTRIBUTES", "lpSemaphoreAttributes", "in", attributesPointer, attributesPointer, attributesPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LONG", "lInitialCount", "in", SignedIntValue32(record.Values32[0]), SignedIntValue32(record.Values32[0]), SignedIntValue32(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LONG", "lMaximumCount", "in", SignedIntValue32(record.Values32[1]), SignedIntValue32(record.Values32[1]), SignedIntValue32(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "LPCWSTR", "lpName", "in", namePointer, namePointer, namePointer);
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::OpenSemaphoreW:
    {
        const std::string namePointer = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "DWORD", "dwDesiredAccess", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), SemaphoreAccessFlagsText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "BOOL", "bInheritHandle", "in", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]), BoolText(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPCWSTR", "lpName", "in", namePointer, namePointer, namePointer);
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::ReleaseSemaphore:
    {
        const std::string semaphoreHandle = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string previousCountPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const bool previousCountDecoded = static_cast<KnMonDecodeStatus>(record.Values32[1]) == KnMonDecodeStatus::Decoded;
        const std::string previousCountValue = SignedIntValue32(record.Values32[2]);
        const std::string previousCountPost = previousCountDecoded ? previousCountValue : previousCountPointer;
        const std::string previousCountDecodedValue = previousCountDecoded ?
            ("value=" + previousCountValue) :
            (DecodeStatusName(record.Values32[1]) + ";pointer=" + previousCountPointer);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hSemaphore", "in", semaphoreHandle, semaphoreHandle, semaphoreHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LONG", "lReleaseCount", "in", SignedIntValue32(record.Values32[0]), SignedIntValue32(record.Values32[0]), SignedIntValue32(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPLONG", "lpPreviousCount", "out", previousCountPointer, previousCountPost, previousCountDecodedValue, DecodeStatusName(record.Values32[1]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::WaitForMultipleObjectsEx:
    {
        const std::string handlesPointer = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "DWORD", "nCount", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), std::to_string(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "const HANDLE*", "lpHandles", "in", handlesPointer, handlesPointer, handlesPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "BOOL", "bWaitAll", "in", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]), BoolText(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "DWORD", "dwMilliseconds", "in", HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2]), WaitTimeoutText(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "BOOL", "bAlertable", "in", std::to_string(record.Values32[3]), std::to_string(record.Values32[3]), BoolText(record.Values32[3]));
        payload = ApiCallPayload(result, record, MultiWaitResultText(static_cast<std::uint32_t>(record.ReturnValue), record.Values32[0]), args.str(), "");
        break;
    }
    case KnMonTransportApiId::NtCreateFile:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "PHANDLE", "FileHandle", "out", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "ACCESS_MASK", "DesiredAccess", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "POBJECT_ATTRIBUTES", "ObjectAttributes", "in", HexPointerValue(record.Values64[2], result.Architecture), HexPointerValue(record.Values64[2], result.Architecture), text0, DecodeStatusName(record.Values32[6])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "PIO_STATUS_BLOCK", "IoStatusBlock", "out", HexPointerValue(record.Values64[3], result.Architecture), text1, text1, DecodeStatusName(record.Values32[7])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "PLARGE_INTEGER", "AllocationSize", "in", HexPointerValue(record.Values64[4], result.Architecture), HexPointerValue(record.Values64[4], result.Architecture), HexPointerValue(record.Values64[4], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 5, "ULONG", "FileAttributes", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 6, "ULONG", "ShareAccess", "in", HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 7, "ULONG", "CreateDisposition", "in", HexDwordValue(record.Values32[3]), HexDwordValue(record.Values32[3]), HexDwordValue(record.Values32[3])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 8, "ULONG", "CreateOptions", "in", HexDwordValue(record.Values32[4]), HexDwordValue(record.Values32[4]), HexDwordValue(record.Values32[4])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 9, "PVOID", "EaBuffer", "in", HexPointerValue(record.Values64[5], result.Architecture), HexPointerValue(record.Values64[5], result.Architecture), HexPointerValue(record.Values64[5], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 10, "ULONG", "EaLength", "in", std::to_string(record.Values32[5]), std::to_string(record.Values32[5]), std::to_string(record.Values32[5]));
        payload = ApiCallPayload(result, record, HexNtStatusValue(record.ReturnCode), args.str(), "");
        break;
    case KnMonTransportApiId::LoadLibraryW:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCWSTR", "lpLibFileName", "in", text0, text0, text0);
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::LoadLibraryA:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCSTR", "lpLibFileName", "in", text0, text0, text0);
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::LoadLibraryExW:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCWSTR", "lpLibFileName", "in", text0, text0, text0) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "HANDLE", "hFile", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "dwFlags", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::LoadLibraryExA:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCSTR", "lpLibFileName", "in", text0, text0, text0) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "HANDLE", "hFile", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "dwFlags", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::LdrLoadDll:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "PWSTR", "PathToFile", "in", text0, text0, text0) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "ULONG", "Flags", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "PUNICODE_STRING", "ModuleFileName", "in", text1, text1, text1, DecodeStatusName(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "PHANDLE", "ModuleHandle", "out", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture));
        payload = ApiCallPayload(result, record, HexNtStatusValue(record.ReturnCode), args.str(), "");
        break;
    case KnMonTransportApiId::GetProcAddress:
    {
        const bool procByOrdinal = record.Values32[0] != 0;
        const std::string procRaw = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string procDecoded = procByOrdinal ? ("ordinal:" + std::to_string(record.Values32[1])) : text0;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HMODULE", "hModule", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPCSTR", "lpProcName", "in", procRaw, procRaw, procDecoded, DecodeStatusName(record.Values32[2]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::LdrGetProcedureAddress:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HMODULE", "ModuleHandle", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "PANSI_STRING", "FunctionName", "in", HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), text0, DecodeStatusName(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "WORD", "Ordinal", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), std::to_string(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "PVOID*", "FunctionAddress", "out", HexPointerValue(record.Values64[2], result.Architecture), HexPointerValue(record.Values64[3], result.Architecture), HexPointerValue(record.Values64[3], result.Architecture));
        payload = ApiCallPayload(result, record, HexNtStatusValue(record.ReturnCode), args.str(), "");
        break;
    case KnMonTransportApiId::RegOpenKeyExW:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HKEY", "hKey", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPCWSTR", "lpSubKey", "in", text0, text0, text0, DecodeStatusName(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "ulOptions", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "REGSAM", "samDesired", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "PHKEY", "phkResult", "out", HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[2], result.Architecture), HexPointerValue(record.Values64[2], result.Architecture));
        payload = ApiCallPayload(result, record, LStatusValue(record.ReturnValue), args.str(), "");
        break;
    case KnMonTransportApiId::RegCreateKeyExW:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HKEY", "hKey", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPCWSTR", "lpSubKey", "in", text0, text0, text0, DecodeStatusName(record.Values32[4])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "Reserved", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "LPWSTR", "lpClass", "in", text1, text1, text1, DecodeStatusName(record.Values32[5])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "DWORD", "dwOptions", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 5, "REGSAM", "samDesired", "in", HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 6, "LPSECURITY_ATTRIBUTES", "lpSecurityAttributes", "in", HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 7, "PHKEY", "phkResult", "out", HexPointerValue(record.Values64[2], result.Architecture), HexPointerValue(record.Values64[3], result.Architecture), HexPointerValue(record.Values64[3], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 8, "LPDWORD", "lpdwDisposition", "out", HexPointerValue(record.Values64[4], result.Architecture), std::to_string(record.Values32[3]), std::to_string(record.Values32[3]));
        payload = ApiCallPayload(result, record, LStatusValue(record.ReturnValue), args.str(), "");
        break;
    case KnMonTransportApiId::RegQueryValueExW:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HKEY", "hKey", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPCWSTR", "lpValueName", "in", text0, text0, text0, DecodeStatusName(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPDWORD", "lpReserved", "in", HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "LPDWORD", "lpType", "out", HexPointerValue(record.Values64[2], result.Architecture), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "LPBYTE", "lpData", "out", HexPointerValue(record.Values64[3], result.Architecture), HexPointerValue(record.Values64[3], result.Architecture), text1.empty() ? HexPointerValue(record.Values64[3], result.Architecture) : text1, DecodeStatusName(record.Values32[3])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 5, "LPDWORD", "lpcbData", "inout", HexPointerValue(record.Values64[4], result.Architecture), std::to_string(record.Values32[1]), std::to_string(record.Values32[1]));
        payload = ApiCallPayload(result, record, LStatusValue(record.ReturnValue), args.str(), text1);
        break;
    case KnMonTransportApiId::RegSetValueExW:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HKEY", "hKey", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPCWSTR", "lpValueName", "in", text0, text0, text0, DecodeStatusName(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "Reserved", "in", HexDwordValue(static_cast<std::uint32_t>(record.Values64[1])), HexDwordValue(static_cast<std::uint32_t>(record.Values64[1])), HexDwordValue(static_cast<std::uint32_t>(record.Values64[1]))) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "DWORD", "dwType", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "const BYTE*", "lpData", "in", HexPointerValue(record.Values64[2], result.Architecture), HexPointerValue(record.Values64[2], result.Architecture), text1.empty() ? HexPointerValue(record.Values64[2], result.Architecture) : text1, DecodeStatusName(record.Values32[3])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 5, "DWORD", "cbData", "in", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]), std::to_string(record.Values32[1]));
        payload = ApiCallPayload(result, record, LStatusValue(record.ReturnValue), args.str(), text1);
        break;
    case KnMonTransportApiId::RegDeleteValueW:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HKEY", "hKey", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPCWSTR", "lpValueName", "in", text0, text0, text0, DecodeStatusName(record.Values32[0]));
        payload = ApiCallPayload(result, record, LStatusValue(record.ReturnValue), args.str(), "");
        break;
    case KnMonTransportApiId::RegCloseKey:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HKEY", "hKey", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture));
        payload = ApiCallPayload(result, record, LStatusValue(record.ReturnValue), args.str(), "");
        break;
    case KnMonTransportApiId::OpenProcessToken:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "ProcessHandle", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "DesiredAccess", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "PHANDLE", "TokenHandle", "out", HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[2], result.Architecture), HexPointerValue(record.Values64[2], result.Architecture));
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    case KnMonTransportApiId::LookupPrivilegeValueW:
    {
        const std::string systemNamePointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string namePointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string luidPointer = HexPointerValue(record.Values64[2], result.Architecture);
        const std::string luidValue = "LowPart=" + HexDwordValue(record.Values32[2]) + " HighPart=" + HexDwordValue(record.Values32[3]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCWSTR", "lpSystemName", "in", systemNamePointer, systemNamePointer, text0.empty() ? systemNamePointer : text0, DecodeStatusName(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPCWSTR", "lpName", "in", namePointer, namePointer, text1.empty() ? namePointer : text1, DecodeStatusName(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "PLUID", "lpLuid", "out", luidPointer, luidValue, luidValue);
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::BCryptOpenAlgorithmProvider:
    {
        const std::string algorithmPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string algorithmHandle = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string algorithmIdPointer = HexPointerValue(record.Values64[2], result.Architecture);
        const std::string implementationPointer = HexPointerValue(record.Values64[3], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "BCRYPT_ALG_HANDLE*", "phAlgorithm", "out", algorithmPointer, algorithmHandle, algorithmHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPCWSTR", "pszAlgId", "in", algorithmIdPointer, algorithmIdPointer, text0.empty() ? algorithmIdPointer : text0, DecodeStatusName(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPCWSTR", "pszImplementation", "in", implementationPointer, implementationPointer, text1.empty() ? implementationPointer : text1, DecodeStatusName(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "ULONG", "dwFlags", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]));
        payload = ApiCallPayload(result, record, HexNtStatusValue(record.ReturnCode), args.str(), "");
        break;
    }
    case KnMonTransportApiId::BCryptCloseAlgorithmProvider:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "BCRYPT_ALG_HANDLE", "hAlgorithm", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "ULONG", "dwFlags", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]));
        payload = ApiCallPayload(result, record, HexNtStatusValue(record.ReturnCode), args.str(), "");
        break;
    case KnMonTransportApiId::BCryptGetProperty:
    {
        const std::string objectHandle = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string propertyPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string outputPointer = HexPointerValue(record.Values64[2], result.Architecture);
        const std::string resultBytesPointer = HexPointerValue(record.Values64[3], result.Architecture);
        const std::string propertyDecoded = text0.empty() ? propertyPointer : text0;
        const std::string outputDecoded = text1.empty() ? outputPointer : text1;
        const std::string resultBytes = std::to_string(record.Values32[2]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "BCRYPT_HANDLE", "hObject", "in", objectHandle, objectHandle, objectHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPCWSTR", "pszProperty", "in", propertyPointer, propertyPointer, propertyDecoded, DecodeStatusName(record.Values32[3])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "PUCHAR", "pbOutput", "out", outputPointer, outputDecoded, outputDecoded, DecodeStatusName(record.Values32[4])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "ULONG", "cbOutput", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), std::to_string(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "ULONG*", "pcbResult", "out", resultBytesPointer, resultBytes, resultBytes) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 5, "ULONG", "dwFlags", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]));
        payload = ApiCallPayload(result, record, HexNtStatusValue(record.ReturnCode), args.str(), "");
        break;
    }
    case KnMonTransportApiId::BCryptGenRandom:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "BCRYPT_ALG_HANDLE", "hAlgorithm", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "PUCHAR", "pbBuffer", "out", HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "ULONG", "cbBuffer", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), std::to_string(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "ULONG", "dwFlags", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]));
        payload = ApiCallPayload(result, record, HexNtStatusValue(record.ReturnCode), args.str(), "");
        break;
    case KnMonTransportApiId::CertOpenStore:
    {
        const std::string providerPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string providerDecoded = text0.empty() ? providerPointer : text0;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCSTR", "lpszStoreProvider", "in", providerPointer, providerPointer, providerDecoded, DecodeStatusName(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwEncodingType", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "HCRYPTPROV_LEGACY", "hCryptProv", "in", HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "DWORD", "dwFlags", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "const void*", "pvPara", "in", HexPointerValue(record.Values64[2], result.Architecture), HexPointerValue(record.Values64[2], result.Architecture), HexPointerValue(record.Values64[2], result.Architecture));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::CertCloseStore:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HCERTSTORE", "hCertStore", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwFlags", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]));
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    case KnMonTransportApiId::CryptMsgOpenToDecode:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "DWORD", "dwMsgEncodingType", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwFlags", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "dwMsgType", "in", HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "HCRYPTPROV_LEGACY", "hCryptProv", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "PCERT_INFO", "pRecipientInfo", "in", HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 5, "PCMSG_STREAM_INFO", "pStreamInfo", "in", HexPointerValue(record.Values64[2], result.Architecture), HexPointerValue(record.Values64[2], result.Architecture), HexPointerValue(record.Values64[2], result.Architecture));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::CryptMsgClose:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HCRYPTMSG", "hCryptMsg", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture));
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    case KnMonTransportApiId::InternetOpenW:
    {
        const std::string agentPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string proxyPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string proxyBypassPointer = HexPointerValue(record.Values64[2], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCWSTR", "lpszAgent", "in", agentPointer, agentPointer, text0.empty() ? agentPointer : text0, DecodeStatusName(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwAccessType", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPCWSTR", "lpszProxy", "in", proxyPointer, proxyPointer, text1.empty() ? proxyPointer : text1, DecodeStatusName(record.Values32[3])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "LPCWSTR", "lpszProxyBypass", "in", proxyBypassPointer, proxyBypassPointer, text2.empty() ? proxyBypassPointer : text2, DecodeStatusName(record.Values32[4])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "DWORD", "dwFlags", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::InternetCloseHandle:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HINTERNET", "hInternet", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture));
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    case KnMonTransportApiId::WinHttpOpen:
    {
        const std::string agentPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string proxyPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string proxyBypassPointer = HexPointerValue(record.Values64[2], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCWSTR", "pszAgentW", "in", agentPointer, agentPointer, text0.empty() ? agentPointer : text0, DecodeStatusName(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwAccessType", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPCWSTR", "pszProxyW", "in", proxyPointer, proxyPointer, text1.empty() ? proxyPointer : text1, DecodeStatusName(record.Values32[3])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "LPCWSTR", "pszProxyBypassW", "in", proxyBypassPointer, proxyBypassPointer, text2.empty() ? proxyBypassPointer : text2, DecodeStatusName(record.Values32[4])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "DWORD", "dwFlags", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    }
    case KnMonTransportApiId::WinHttpCloseHandle:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HINTERNET", "hInternet", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture));
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    case KnMonTransportApiId::WinHttpSetOption:
    {
        const std::string internetHandle = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string bufferPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const bool optionDecoded = static_cast<KnMonDecodeStatus>(record.Values32[2]) == KnMonDecodeStatus::Decoded;
        const std::string optionValue = std::to_string(record.Values64[2]);
        const std::string bufferDecoded = optionDecoded ?
            ("status=decoded;value=" + optionValue) :
            (DecodeStatusName(record.Values32[2]) + ";pointer=" + bufferPointer);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HINTERNET", "hInternet", "in", internetHandle, internetHandle, internetHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwOption", "in", WinHttpOptionText(record.Values32[0]), WinHttpOptionText(record.Values32[0]), WinHttpOptionText(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPVOID", "lpBuffer", "in", bufferPointer, bufferPointer, bufferDecoded, DecodeStatusName(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "DWORD", "dwBufferLength", "in", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]), std::to_string(record.Values32[1]));
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetSystemMetrics:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "int", "nIndex", "in", SignedIntValue32(record.Values32[0]), SignedIntValue32(record.Values32[0]), SignedIntValue32(record.Values32[0]));
        payload = ApiCallPayload(result, record, SignedIntValue(record.ReturnValue), args.str(), "");
        break;
    case KnMonTransportApiId::GetDesktopWindow:
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::GetForegroundWindow:
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::GetWindowThreadProcessId:
    {
        const std::string window = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string processIdPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string processIdValue = record.Values32[1] == 0 ? processIdPointer : std::to_string(record.Values32[0]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HWND", "hWnd", "in", window, window, window) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPDWORD", "lpdwProcessId", "out", processIdPointer, processIdValue, processIdValue);
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::CreateCompatibleDC:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HDC", "hdc", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::GetDeviceCaps:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HDC", "hdc", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "int", "index", "in", SignedIntValue32(record.Values32[0]), SignedIntValue32(record.Values32[0]), SignedIntValue32(record.Values32[0]));
        payload = ApiCallPayload(result, record, SignedIntValue(record.ReturnValue), args.str(), "");
        break;
    case KnMonTransportApiId::DeleteDC:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HDC", "hdc", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture));
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    case KnMonTransportApiId::EnumProcessModules:
    {
        const std::string process = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string moduleArrayPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string neededBytesPointer = HexPointerValue(record.Values64[2], result.Architecture);
        const std::string firstModule = HexPointerValue(record.Values64[3], result.Architecture);
        const std::string moduleArrayDecoded = record.Values32[3] == 0 ? moduleArrayPointer : "firstModule=" + firstModule;
        const std::string neededBytes = record.Values32[2] == 0 ? neededBytesPointer : std::to_string(record.Values32[1]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hProcess", "in", process, process, process) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "HMODULE*", "lphModule", "out", moduleArrayPointer, moduleArrayDecoded, moduleArrayDecoded) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "cb", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), std::to_string(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "LPDWORD", "lpcbNeeded", "out", neededBytesPointer, neededBytes, neededBytes);
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetModuleInformation:
    {
        const std::string process = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string module = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string moduleInfoPointer = HexPointerValue(record.Values64[2], result.Architecture);
        std::string moduleInfoDecoded = moduleInfoPointer;
        if (record.Values32[2] != 0)
        {
            std::ostringstream decoded;
            decoded << "base=" << HexPointerValue(record.Values64[3], result.Architecture)
                    << ",size=" << record.Values32[1]
                    << ",entry=" << HexPointerValue(record.Values64[4], result.Architecture);
            moduleInfoDecoded = decoded.str();
        }

        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hProcess", "in", process, process, process) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "HMODULE", "hModule", "in", module, module, module) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPMODULEINFO", "lpmodinfo", "out", moduleInfoPointer, moduleInfoDecoded, moduleInfoDecoded) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "DWORD", "cb", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), std::to_string(record.Values32[0]));
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetModuleBaseNameW:
    {
        const std::string process = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string module = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string baseNamePointer = HexPointerValue(record.Values64[2], result.Architecture);
        const std::string baseName = text0.empty() ? baseNamePointer : text0;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hProcess", "in", process, process, process) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "HMODULE", "hModule", "in", module, module, module) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPWSTR", "lpBaseName", "out", baseNamePointer, baseName, baseName, DecodeStatusName(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "DWORD", "nSize", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), std::to_string(record.Values32[0]));
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetModuleFileNameExW:
    {
        const std::string process = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string module = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string fileNamePointer = HexPointerValue(record.Values64[2], result.Architecture);
        const std::string fileName = text0.empty() ? fileNamePointer : text0;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hProcess", "in", process, process, process) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "HMODULE", "hModule", "in", module, module, module) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPWSTR", "lpFilename", "out", fileNamePointer, fileName, fileName, DecodeStatusName(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "DWORD", "nSize", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), std::to_string(record.Values32[0]));
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetFileVersionInfoSizeW:
    {
        const std::string fileNamePointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string handlePointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string fileName = text0.empty() ? fileNamePointer : text0;
        const std::string handleValue = record.Values32[1] == 0 ? handlePointer : std::to_string(record.Values32[0]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCWSTR", "lptstrFilename", "in", fileNamePointer, fileNamePointer, fileName, DecodeStatusName(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPDWORD", "lpdwHandle", "out", handlePointer, handleValue, handleValue);
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetFileVersionInfoW:
    {
        const std::string fileNamePointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string dataPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string fileName = text0.empty() ? fileNamePointer : text0;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCWSTR", "lptstrFilename", "in", fileNamePointer, fileNamePointer, fileName, DecodeStatusName(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwHandle", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "DWORD", "dwLen", "in", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]), std::to_string(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "LPVOID", "lpData", "out", dataPointer, dataPointer, dataPointer);
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::VerQueryValueW:
    {
        const std::string blockPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string subBlockPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string valuePointerPointer = HexPointerValue(record.Values64[2], result.Architecture);
        const std::string lengthPointer = HexPointerValue(record.Values64[3], result.Architecture);
        const std::string valuePointer = HexPointerValue(record.Values64[4], result.Architecture);
        const std::string subBlock = text0.empty() ? subBlockPointer : text0;
        std::string valueDecoded = record.Values32[4] == 0 ? valuePointerPointer : valuePointer;
        if (record.Values32[3] == 1)
        {
            valueDecoded = valuePointer + ";" + text1;
            if (!text2.empty())
            {
                valueDecoded += ";" + text2;
            }
        }
        else if (record.Values32[3] == 2)
        {
            valueDecoded = valuePointer + ";" + text1;
        }

        const std::string lengthValue = record.Values32[1] == 0 ? lengthPointer : std::to_string(record.Values32[0]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPCVOID", "pBlock", "in", blockPointer, blockPointer, blockPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPCWSTR", "lpSubBlock", "in", subBlockPointer, subBlockPointer, subBlock, DecodeStatusName(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "LPVOID*", "lplpBuffer", "out", valuePointerPointer, valuePointer, valueDecoded) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "PUINT", "puLen", "out", lengthPointer, lengthValue, lengthValue);
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::SHGetKnownFolderPath:
    {
        const std::string knownFolderPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string tokenHandle = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string pathPointerPointer = HexPointerValue(record.Values64[2], result.Architecture);
        const std::string pathPointer = HexPointerValue(record.Values64[3], result.Architecture);
        const std::string knownFolder = text0.empty() ? knownFolderPointer : text0;
        const std::string status = ShellFolderPathStatusName(record.Values32[2]);
        std::string pathDecoded = "status=" + status + ";pointer=" + pathPointer;
        if (record.Values32[2] == 1 && !text1.empty())
        {
            pathDecoded += ";path=" + text1;
        }

        args << ArgumentJsonFromMetadata(record.ApiId, 0, "REFKNOWNFOLDERID", "rfid", "in", knownFolderPointer, knownFolderPointer, knownFolder, DecodeStatusName(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwFlags", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "HANDLE", "hToken", "in", tokenHandle, tokenHandle, tokenHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "PWSTR*", "ppszPath", "out", pathPointerPointer, pathPointer, pathDecoded, DecodeStatusName(record.Values32[3]));
        payload = ApiCallPayload(result, record, HexHResultValue(record.ReturnCode), args.str(), "");
        break;
    }
    case KnMonTransportApiId::SHGetSpecialFolderPathW:
    {
        const std::string windowHandle = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string pathPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string csidlRaw = SignedIntValue32(record.Values32[0]);
        const std::string csidlDecoded = text0.empty() ? csidlRaw : text0;
        const std::string createValue = record.Values32[1] == 0 ? "FALSE" : "TRUE";
        const std::string status = ShellFolderPathStatusName(record.Values32[3]);
        std::string pathDecoded = "status=" + status + ";pointer=" + pathPointer;
        if (record.Values32[3] == 1 && !text1.empty())
        {
            pathDecoded += ";path=" + text1;
        }

        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HWND", "hwnd", "in", windowHandle, windowHandle, windowHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPWSTR", "pszPath", "out", pathPointer, pathPointer, pathDecoded, DecodeStatusName(record.Values32[4])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "int", "csidl", "in", csidlRaw, csidlRaw, csidlDecoded) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "BOOL", "fCreate", "in", createValue, createValue, createValue);
        payload = ApiCallPayload(result, record, std::to_string(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::CoInitializeEx:
    {
        const std::string reservedPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string initFlags = ComInitFlagsText(record.Values32[0]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPVOID", "pvReserved", "in", reservedPointer, reservedPointer, reservedPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DWORD", "dwCoInit", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), initFlags);
        payload = ApiCallPayload(result, record, HexHResultValue(record.ReturnCode), args.str(), "");
        break;
    }
    case KnMonTransportApiId::CoUninitialize:
        payload = ApiCallPayload(result, record, "void", args.str(), "");
        break;
    case KnMonTransportApiId::CoCreateGuid:
    {
        const std::string guidPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string guidValue = text0.empty() ? guidPointer : text0;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "GUID*", "pguid", "out", guidPointer, guidPointer, guidValue, DecodeStatusName(record.Values32[0]));
        payload = ApiCallPayload(result, record, HexHResultValue(record.ReturnCode), args.str(), "");
        break;
    }
    case KnMonTransportApiId::StringFromGUID2:
    {
        const std::string guidPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string stringPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string guidValue = text0.empty() ? guidPointer : text0;
        const std::string stringValue = text1.empty() ? stringPointer : text1;
        const std::string cchMax = SignedIntValue32(record.Values32[0]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "REFGUID", "rguid", "in", guidPointer, guidPointer, guidValue, DecodeStatusName(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPOLESTR", "lpsz", "out", stringPointer, stringPointer, stringValue, DecodeStatusName(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "int", "cchMax", "in", cchMax, cchMax, cchMax);
        payload = ApiCallPayload(result, record, SignedIntValue(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::RoInitialize:
    {
        const std::string initTypeRaw = HexDwordValue(record.Values32[0]);
        const std::string initTypeDecoded = RoInitTypeText(record.Values32[0]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "RO_INIT_TYPE", "initType", "in", initTypeRaw, initTypeRaw, initTypeDecoded);
        payload = ApiCallPayload(result, record, HexHResultValue(record.ReturnCode), args.str(), "");
        break;
    }
    case KnMonTransportApiId::RoUninitialize:
        payload = ApiCallPayload(result, record, "void", args.str(), "");
        break;
    case KnMonTransportApiId::RoGetApartmentIdentifier:
    {
        const std::string identifierPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string identifierValue = std::to_string(record.Values64[1]);
        const std::string identifierDecoded = DecodeStatusName(record.Values32[0]) + ";value=" + identifierValue;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "UINT64*", "apartmentIdentifier", "out", identifierPointer, identifierValue, identifierDecoded, DecodeStatusName(record.Values32[0]));
        payload = ApiCallPayload(result, record, HexHResultValue(record.ReturnCode), args.str(), "");
        break;
    }
    case KnMonTransportApiId::VariantClear:
    {
        const std::string variantPointer = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "VARIANTARG*", "pvarg", "inout", variantPointer, variantPointer, variantPointer);
        payload = ApiCallPayload(result, record, HexHResultValue(record.ReturnCode), args.str(), "");
        break;
    }
    case KnMonTransportApiId::SafeArrayDestroy:
    {
        const std::string safeArrayPointer = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "SAFEARRAY*", "psa", "in", safeArrayPointer, safeArrayPointer, safeArrayPointer);
        payload = ApiCallPayload(result, record, HexHResultValue(record.ReturnCode), args.str(), "");
        break;
    }
    case KnMonTransportApiId::DnsRecordListFree:
    {
        const std::string recordListPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string freeTypeValue = DwordDecimalHexText(record.Values32[0]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "PDNS_RECORD", "pRecordList", "in", recordListPointer, recordListPointer, recordListPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "DNS_FREE_TYPE", "FreeType", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), freeTypeValue);
        payload = ApiCallPayload(result, record, "void", args.str(), "");
        break;
    }
    case KnMonTransportApiId::SetupDiDestroyDeviceInfoList:
    {
        const std::string deviceInfoSet = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HDEVINFO", "DeviceInfoSet", "in", deviceInfoSet, deviceInfoSet, deviceInfoSet);
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::DestroyEnvironmentBlock:
    {
        const std::string environment = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "LPVOID", "lpEnvironment", "in", environment, environment, environment);
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetIfEntry2:
    {
        const std::string row = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "PMIB_IF_ROW2", "Row", "inout", row, row, row);
        payload = ApiCallPayload(result, record, DwordDecimalHexText(record.ReturnCode), args.str(), "");
        break;
    }
    case KnMonTransportApiId::SymInitializeW:
    {
        const std::string processHandle = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string searchPathPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string invadeProcess = std::to_string(record.Values32[0]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hProcess", "in", processHandle, processHandle, processHandle) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "PCWSTR", "UserSearchPath", "in", searchPathPointer, searchPathPointer, searchPathPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "BOOL", "fInvadeProcess", "in", invadeProcess, invadeProcess, BoolText(record.Values32[0]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::SymCleanup:
    {
        const std::string processHandle = HexPointerValue(record.Values64[0], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "HANDLE", "hProcess", "in", processHandle, processHandle, processHandle);
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    }
    case KnMonTransportApiId::RpcStringBindingComposeW:
    {
        const std::string objUuidPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string protSeqPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string networkAddrPointer = HexPointerValue(record.Values64[2], result.Architecture);
        const std::string endpointPointer = HexPointerValue(record.Values64[3], result.Architecture);
        const std::string optionsPointer = HexPointerValue(record.Values64[4], result.Architecture);
        const std::string stringBindingPointer = HexPointerValue(record.Values64[5], result.Architecture);
        const std::string composedBindingPointer = HexPointerValue(record.Values64[6], result.Architecture);
        const std::string composedBinding = text0.empty() ? composedBindingPointer : text0;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "RPC_WSTR", "ObjUuid", "in", objUuidPointer, objUuidPointer, objUuidPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "RPC_WSTR", "ProtSeq", "in", protSeqPointer, protSeqPointer, text1.empty() ? protSeqPointer : text1, DecodeStatusName(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "RPC_WSTR", "NetworkAddr", "in", networkAddrPointer, networkAddrPointer, networkAddrPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "RPC_WSTR", "Endpoint", "in", endpointPointer, endpointPointer, text2.empty() ? endpointPointer : text2, DecodeStatusName(record.Values32[2])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 4, "RPC_WSTR", "Options", "in", optionsPointer, optionsPointer, optionsPointer) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 5, "RPC_WSTR*", "StringBinding", "out", stringBindingPointer, composedBinding, composedBinding, DecodeStatusName(record.Values32[0]));
        payload = ApiCallPayload(result, record, RpcStatusValue(record.ReturnValue), args.str(), text0);
        break;
    }
    case KnMonTransportApiId::RpcBindingFromStringBindingW:
    {
        const std::string stringBindingPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string bindingPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string bindingValue = HexPointerValue(record.Values64[2], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "RPC_WSTR", "StringBinding", "in", stringBindingPointer, stringBindingPointer, text0.empty() ? stringBindingPointer : text0, DecodeStatusName(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "RPC_BINDING_HANDLE*", "Binding", "out", bindingPointer, bindingValue, bindingValue);
        payload = ApiCallPayload(result, record, RpcStatusValue(record.ReturnValue), args.str(), text0);
        break;
    }
    case KnMonTransportApiId::RpcStringFreeW:
    {
        const std::string stringPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string preStringPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string postStringPointer = HexPointerValue(record.Values64[2], result.Architecture);
        const std::string preString = text0.empty() ? preStringPointer : text0;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "RPC_WSTR*", "String", "inout", stringPointer, postStringPointer, preString, DecodeStatusName(record.Values32[0]));
        payload = ApiCallPayload(result, record, RpcStatusValue(record.ReturnValue), args.str(), text0);
        break;
    }
    case KnMonTransportApiId::RpcBindingFree:
    {
        const std::string bindingPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string preBinding = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string postBinding = HexPointerValue(record.Values64[2], result.Architecture);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "RPC_BINDING_HANDLE*", "Binding", "inout", bindingPointer, postBinding, preBinding);
        payload = ApiCallPayload(result, record, RpcStatusValue(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::RpcBindingSetOption:
    {
        const std::string bindingValue = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string optionValue = std::to_string(record.Values32[0]);
        const std::string optionValueDecoded = DwordDecimalHexText(record.Values32[0]);
        const std::string scalarValue = std::to_string(record.Values64[1]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "RPC_BINDING_HANDLE", "hBinding", "in", bindingValue, bindingValue, bindingValue) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "unsigned long", "option", "in", optionValue, optionValue, optionValueDecoded) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "ULONG_PTR", "optionValue", "in", scalarValue, scalarValue, scalarValue);
        payload = ApiCallPayload(result, record, RpcStatusValue(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::UuidCreate:
    {
        const std::string uuidPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string uuidValue = text0.empty() ? uuidPointer : text0;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "UUID*", "Uuid", "out", uuidPointer, uuidPointer, uuidValue, DecodeStatusName(record.Values32[0]));
        payload = ApiCallPayload(result, record, RpcStatusValue(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::UuidToStringW:
    {
        const std::string uuidPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string stringUuidPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string returnedStringPointer = HexPointerValue(record.Values64[2], result.Architecture);
        const std::string uuidValue = text0.empty() ? uuidPointer : text0;
        const std::string stringValue = text1.empty() ? returnedStringPointer : text1;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "UUID*", "Uuid", "in", uuidPointer, uuidPointer, uuidValue, DecodeStatusName(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "RPC_WSTR*", "StringUuid", "out", stringUuidPointer, returnedStringPointer, stringValue, DecodeStatusName(record.Values32[1]));
        payload = ApiCallPayload(result, record, RpcStatusValue(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::UuidFromStringW:
    {
        const std::string stringUuidPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string uuidPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string stringValue = text0.empty() ? stringUuidPointer : text0;
        const std::string uuidValue = text1.empty() ? uuidPointer : text1;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "RPC_WSTR", "StringUuid", "in", stringUuidPointer, stringUuidPointer, stringValue, DecodeStatusName(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "UUID*", "Uuid", "out", uuidPointer, uuidPointer, uuidValue, DecodeStatusName(record.Values32[1]));
        payload = ApiCallPayload(result, record, RpcStatusValue(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::WSAStartup:
    {
        const std::string dataPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string dataDecoded = text0.empty() ? dataPointer : (text1.empty() ? text0 : (text0 + " | " + text1));
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "WORD", "wVersionRequested", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "LPWSADATA", "lpWSAData", "out", dataPointer, dataPointer, dataDecoded);
        payload = ApiCallPayload(result, record, SignedIntValue(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::WSACleanup:
        payload = ApiCallPayload(result, record, SignedIntValue(record.ReturnValue), args.str(), "");
        break;
    case KnMonTransportApiId::Socket:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "int", "af", "in", SignedIntValue32(record.Values32[0]), SignedIntValue32(record.Values32[0]), SignedIntValue32(record.Values32[0])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "int", "type", "in", SignedIntValue32(record.Values32[1]), SignedIntValue32(record.Values32[1]), SignedIntValue32(record.Values32[1])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "int", "protocol", "in", SignedIntValue32(record.Values32[2]), SignedIntValue32(record.Values32[2]), SignedIntValue32(record.Values32[2]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::Closesocket:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "SOCKET", "s", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture));
        payload = ApiCallPayload(result, record, SignedIntValue(record.ReturnValue), args.str(), "");
        break;
    case KnMonTransportApiId::Connect:
    {
        const std::string socketValue = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string addressPointer = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string addressDecoded = text0.empty() ?
            (DecodeStatusName(record.Values32[4]) + ";family=" + SignedIntValue32(record.Values32[1])) :
            text0;
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "SOCKET", "s", "in", socketValue, socketValue, socketValue) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "const sockaddr*", "name", "in", addressPointer, addressPointer, addressDecoded, DecodeStatusName(record.Values32[4])) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "int", "namelen", "in", SignedIntValue32(record.Values32[0]), SignedIntValue32(record.Values32[0]), SignedIntValue32(record.Values32[0]));
        payload = ApiCallPayload(result, record, SignedIntValue(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::GetAddrInfo:
    {
        const std::string hintsPointer = HexPointerValue(record.Values64[0], result.Architecture);
        const std::string hintsDecoded = record.Values64[0] == 0 ? hintsPointer : AddrInfoHintText(record.Values32[0], record.Values32[1], record.Values32[2]);
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "PCSTR", "pNodeName", "in", text0, text0, text0) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 1, "PCSTR", "pServiceName", "in", text1, text1, text1) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 2, "const ADDRINFOA*", "pHints", "in", hintsPointer, hintsPointer, hintsDecoded) << ",";
        args << ArgumentJsonFromMetadata(record.ApiId, 3, "PADDRINFOA*", "ppResult", "out", HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[2], result.Architecture), HexPointerValue(record.Values64[2], result.Architecture));
        payload = ApiCallPayload(result, record, SignedIntValue(record.ReturnValue), args.str(), "");
        break;
    }
    case KnMonTransportApiId::FreeAddrInfo:
        args << ArgumentJsonFromMetadata(record.ApiId, 0, "PADDRINFOA", "pAddrInfo", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture));
        payload = ApiCallPayload(result, record, "void", args.str(), "");
        break;
    case KnMonTransportApiId::WSAGetLastError:
        payload = ApiCallPayload(result, record, SignedIntValue(record.ReturnValue), args.str(), "");
        break;
    default:
        break;
    }

    return payload;
}

std::uint32_t TransportCapacityFromEnvironment()
{
    std::uint32_t capacity = KnMonTransportDefaultCapacity;
    std::array<wchar_t, 32> buffer = {};
    const DWORD length = GetEnvironmentVariableW(L"KNMON_TRANSPORT_CAPACITY", buffer.data(), static_cast<DWORD>(buffer.size()));

    if (length > 0 && length < buffer.size())
    {
        wchar_t* end = nullptr;
        const unsigned long parsed = wcstoul(buffer.data(), &end, 10);
        if (parsed > 0)
        {
            capacity = static_cast<std::uint32_t>(std::clamp<unsigned long>(parsed, KnMonTransportMinCapacity, KnMonTransportMaxCapacity));
        }
    }

    return capacity;
}

std::wstring TransportMappingName(const std::string& operationId)
{
    std::wstring result = L"Local\\KNMonTransport_";
    for (const char ch : operationId)
    {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_')
        {
            result.push_back(static_cast<wchar_t>(ch));
        }
        else
        {
            result.push_back(L'_');
        }
    }

    return result;
}

struct SharedTransportSession
{
    HANDLE MappingHandle = nullptr;
    KnMonTransportHeader* Header = nullptr;
    KnMonTransportRecord* Records = nullptr;
    std::wstring MappingName;
    std::string OperationId;
    KnMonAgentArchitecture Architecture = KnMonAgentArchitecture::Unknown;
    std::uint32_t Capacity = 0;
    std::uint64_t MappingSize = 0;
};

void CloseSharedTransport(SharedTransportSession& transport)
{
    if (transport.Header != nullptr)
    {
        UnmapViewOfFile(transport.Header);
        transport.Header = nullptr;
        transport.Records = nullptr;
    }

    if (transport.MappingHandle != nullptr)
    {
        CloseHandle(transport.MappingHandle);
        transport.MappingHandle = nullptr;
    }

    transport.Capacity = 0;
    transport.MappingSize = 0;
    transport.MappingName.clear();
    transport.OperationId.clear();
    transport.Architecture = KnMonAgentArchitecture::Unknown;
}

bool CreateSharedTransport(
    SharedTransportSession& transport,
    const std::string& operationId,
    KnMonAgentArchitecture architecture,
    DWORD* errorCode)
{
    bool created = false;

    do
    {
        CloseSharedTransport(transport);
        transport.Capacity = TransportCapacityFromEnvironment();
        transport.OperationId = operationId;
        transport.Architecture = architecture;
        transport.MappingName = TransportMappingName(operationId);
        transport.MappingSize = sizeof(KnMonTransportHeader) + (static_cast<std::uint64_t>(transport.Capacity) * sizeof(KnMonTransportRecord));
        transport.MappingHandle = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            nullptr,
            PAGE_READWRITE,
            static_cast<DWORD>((transport.MappingSize >> 32) & 0xffffffffULL),
            static_cast<DWORD>(transport.MappingSize & 0xffffffffULL),
            transport.MappingName.c_str());
        if (transport.MappingHandle == nullptr)
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        transport.Header = static_cast<KnMonTransportHeader*>(MapViewOfFile(transport.MappingHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0));
        if (transport.Header == nullptr)
        {
            if (errorCode != nullptr)
            {
                *errorCode = GetLastError();
            }
            break;
        }

        std::memset(transport.Header, 0, static_cast<std::size_t>(transport.MappingSize));
        transport.Header->Magic = KnMonTransportMagic;
        transport.Header->AbiVersion = KnMonTransportAbiVersion;
        transport.Header->HeaderSize = sizeof(KnMonTransportHeader);
        transport.Header->Architecture = static_cast<std::uint32_t>(architecture);
        transport.Header->Capacity = transport.Capacity;
        transport.Header->RecordSize = sizeof(KnMonTransportRecord);
        transport.Header->Flags = 0;
        const std::wstring wideOperationId = Utf8ToWide(operationId);
        wcsncpy_s(transport.Header->OperationId, wideOperationId.c_str(), _TRUNCATE);
        transport.Records = reinterpret_cast<KnMonTransportRecord*>(reinterpret_cast<unsigned char*>(transport.Header) + sizeof(KnMonTransportHeader));
        for (std::uint32_t index = 0; index < transport.Capacity; ++index)
        {
            transport.Records[index].Sequence = -1;
            transport.Records[index].State = static_cast<std::int32_t>(KnMonTransportRecordState::Free);
            transport.Records[index].RecordSize = sizeof(KnMonTransportRecord);
        }

        created = true;
        if (errorCode != nullptr)
        {
            *errorCode = 0;
        }
    }
    while (false);

    if (!created)
    {
        CloseSharedTransport(transport);
    }

    return created;
}

SharedTransportReader MakeSharedTransportReader(const SharedTransportSession& transport, std::uint32_t maxRecordsPerDrain = 0)
{
    SharedTransportReaderConfig config;
    config.ExpectedArchitecture = static_cast<std::uint32_t>(transport.Architecture);
    config.ExpectedOperationId = transport.OperationId;
    config.MaxRecordsPerDrain = maxRecordsPerDrain;

    return SharedTransportReader(transport.Header, transport.Records, config);
}

void ApplyTransportMetrics(KnMonCaptureResult& result, const SharedTransportDrainResult& drainResult)
{
    result.TransportMode = "shared-memory";
    result.TransportCapacity = drainResult.Capacity;
    result.TransportRecordsProduced = drainResult.RecordsProduced;
    result.TransportRecordsConsumed = drainResult.RecordsConsumed;
    result.TransportDroppedEvents = drainResult.RecordsDropped;
    result.TransportHighWaterMark = drainResult.HighWaterMark;
    result.LastTransportSequence = drainResult.RecordsConsumed;
    result.RecordsStreamed = drainResult.RecordsConsumed;
    result.DroppedEvents = std::max(result.DroppedEvents, result.TransportDroppedEvents);
}

void UpdateTransportMetrics(KnMonCaptureResult& result, const SharedTransportSession& transport)
{
    SharedTransportReader reader = MakeSharedTransportReader(transport);
    ApplyTransportMetrics(result, reader.SnapshotMetrics());
}

void RecordHookOverhead(KnMonCaptureResult& result, std::uint64_t overheadUs)
{
    const std::uint64_t nextCount = static_cast<std::uint64_t>(result.CapturedEvents.size()) + 1;

    if (nextCount == 1)
    {
        result.HookOverheadMinUs = overheadUs;
        result.HookOverheadAvgUs = overheadUs;
        result.HookOverheadMaxUs = overheadUs;
        return;
    }

    result.HookOverheadMinUs = std::min(result.HookOverheadMinUs, overheadUs);
    result.HookOverheadMaxUs = std::max(result.HookOverheadMaxUs, overheadUs);
    result.HookOverheadAvgUs = ((result.HookOverheadAvgUs * (nextCount - 1)) + overheadUs) / nextCount;
}

void DrainSharedTransport(
    KnMonCaptureResult& result,
    SharedTransportSession& transport,
    const KnMonCaptureStreamCallbacks* streamCallbacks,
    std::uint64_t* batchSequence)
{
    if (transport.Header == nullptr || transport.Records == nullptr || transport.Capacity == 0)
    {
        return;
    }

    const std::uint32_t maxRecordsPerDrain = streamCallbacks == nullptr ? 0 : streamCallbacks->MaxRecordsPerBatch;
    std::vector<KnMonAgentMessage> batchEvents;
    std::uint64_t firstRecordSequence = 0;
    std::uint64_t lastRecordSequence = 0;

    SharedTransportReader reader = MakeSharedTransportReader(transport, maxRecordsPerDrain);
    SharedTransportDrainResult drainResult = reader.DrainAvailable([&](const KnMonTransportRecord& record)
    {
        const std::string payload = BuildTransportApiPayload(result, record);
        if (!payload.empty())
        {
            RecordHookOverhead(result, record.HookOverheadUs);
            KnMonAgentMessage message = BuildAgentMessage(result, payload);
            result.AgentMessages.push_back(message);
            result.CapturedEvents.push_back(message);
            AddAudit(result, "api_call_received", "shared_memory_transport_read", message.RawPayload);

            if (batchEvents.empty())
            {
                firstRecordSequence = static_cast<std::uint64_t>(record.Sequence);
            }

            lastRecordSequence = static_cast<std::uint64_t>(record.Sequence);
            batchEvents.push_back(message);
        }

        return true;
    });

    if (!drainResult.HeaderValid)
    {
        AddAudit(result, "transport_reader_invalid", "shared_memory_transport_read", drainResult.ErrorMessage, ERROR_INVALID_DATA, "knmon-collector");
    }

    ApplyTransportMetrics(result, drainResult);

    if (
        streamCallbacks != nullptr &&
        streamCallbacks->OnTraceBatch &&
        batchSequence != nullptr &&
        !batchEvents.empty())
    {
        ++(*batchSequence);

        KnMonTraceBatch batch;
        batch.SessionId = result.SessionId;
        batch.OperationId = result.OperationId;
        batch.BatchSequence = *batchSequence;
        batch.FirstRecordSequence = firstRecordSequence;
        batch.LastRecordSequence = lastRecordSequence;
        batch.EventCount = static_cast<std::uint64_t>(batchEvents.size());
        batch.DroppedEvents = result.TransportDroppedEvents;
        batch.RecordsStreamed = result.RecordsStreamed;
        batch.HostDroppedBatches = 0;
        batch.Events = batchEvents;
        (void)streamCallbacks->OnTraceBatch(batch);
    }
}

void DrainSharedTransport(KnMonCaptureResult& result, SharedTransportSession& transport)
{
    DrainSharedTransport(result, transport, nullptr, nullptr);
}

void EmitCaptureStreamSessionFrame(
    const KnMonCaptureStreamCallbacks* streamCallbacks,
    const std::string& frameType,
    KnMonCaptureResult& result)
{
    if (streamCallbacks != nullptr && streamCallbacks->OnSessionFrame)
    {
        result.UpdatedUtc = NowUtc();
        streamCallbacks->OnSessionFrame(frameType, result);
    }
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
    std::array<char, 16384> buffer = {};

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

std::string ExtractJsonString(const std::string& payload, const std::string& key);
std::uint64_t ExtractJsonUInt64(const std::string& payload, const std::string& key);

KnMonAgentHandshake BuildHandshake(const KnMonLaunchResult& result, const std::string& rawPayload)
{
    KnMonAgentHandshake handshake;
    handshake.Received = true;
    handshake.SchemaVersion = ExtractJsonString(rawPayload, "schemaVersion");
    if (handshake.SchemaVersion.empty())
    {
        handshake.SchemaVersion = "0.1.0";
    }

    handshake.OperationId = ExtractJsonString(rawPayload, "operationId");
    if (handshake.OperationId.empty())
    {
        handshake.OperationId = result.OperationId;
    }

    handshake.ProcessId = static_cast<std::uint32_t>(ExtractJsonUInt64(rawPayload, "pid"));
    if (handshake.ProcessId == 0)
    {
        handshake.ProcessId = result.TargetProcessId;
    }

    handshake.ThreadId = static_cast<std::uint32_t>(ExtractJsonUInt64(rawPayload, "tid"));
    if (handshake.ThreadId == 0)
    {
        handshake.ThreadId = result.TargetThreadId;
    }

    handshake.Architecture = ExtractJsonString(rawPayload, "architecture");
    if (handshake.Architecture.empty())
    {
        handshake.Architecture = result.Architecture;
    }

    handshake.AgentVersion = ExtractJsonString(rawPayload, "agentVersion");
    if (handshake.AgentVersion.empty())
    {
        handshake.AgentVersion = "0.1.0";
    }

    handshake.Message = "Agent HELLO received.";
    handshake.RawPayload = rawPayload;
    return handshake;
}

KnMonAgentHandshake BuildHandshake(const KnMonCaptureResult& result, const std::string& rawPayload)
{
    KnMonAgentHandshake handshake;
    handshake.Received = true;
    handshake.SchemaVersion = ExtractJsonString(rawPayload, "schemaVersion");
    if (handshake.SchemaVersion.empty())
    {
        handshake.SchemaVersion = "0.1.0";
    }

    handshake.OperationId = ExtractJsonString(rawPayload, "operationId");
    if (handshake.OperationId.empty())
    {
        handshake.OperationId = result.OperationId;
    }

    handshake.ProcessId = static_cast<std::uint32_t>(ExtractJsonUInt64(rawPayload, "pid"));
    if (handshake.ProcessId == 0)
    {
        handshake.ProcessId = result.TargetProcessId;
    }

    handshake.ThreadId = static_cast<std::uint32_t>(ExtractJsonUInt64(rawPayload, "tid"));
    if (handshake.ThreadId == 0)
    {
        handshake.ThreadId = result.TargetThreadId;
    }

    handshake.Architecture = ExtractJsonString(rawPayload, "architecture");
    if (handshake.Architecture.empty())
    {
        handshake.Architecture = result.Architecture;
    }

    handshake.AgentVersion = ExtractJsonString(rawPayload, "agentVersion");
    if (handshake.AgentVersion.empty())
    {
        handshake.AgentVersion = "0.1.0";
    }

    handshake.Message = "Agent HELLO received.";
    handshake.RawPayload = rawPayload;
    return handshake;
}

bool PayloadContains(const std::string& payload, const std::string& marker)
{
    return payload.find(marker) != std::string::npos;
}

std::string ExtractJsonString(const std::string& payload, const std::string& key)
{
    std::string result;

    do
    {
        const std::string quotedKey = "\"" + key + "\"";
        std::size_t position = payload.find(quotedKey);
        if (position == std::string::npos)
        {
            break;
        }

        position = payload.find(':', position + quotedKey.size());
        if (position == std::string::npos)
        {
            break;
        }

        position = payload.find('"', position + 1);
        if (position == std::string::npos)
        {
            break;
        }

        ++position;
        std::ostringstream stream;
        bool escaped = false;
        for (; position < payload.size(); ++position)
        {
            const char ch = payload[position];
            if (escaped)
            {
                switch (ch)
                {
                case '"':
                    stream << '"';
                    break;
                case '\\':
                    stream << '\\';
                    break;
                case 'n':
                    stream << '\n';
                    break;
                case 'r':
                    stream << '\r';
                    break;
                case 't':
                    stream << '\t';
                    break;
                default:
                    stream << ch;
                    break;
                }
                escaped = false;
                continue;
            }

            if (ch == '\\')
            {
                escaped = true;
                continue;
            }

            if (ch == '"')
            {
                break;
            }

            stream << ch;
        }

        result = stream.str();
    }
    while (false);

    return result;
}

std::uint64_t ExtractJsonUInt64(const std::string& payload, const std::string& key)
{
    std::uint64_t result = 0;

    do
    {
        const std::string quotedKey = "\"" + key + "\"";
        std::size_t position = payload.find(quotedKey);
        if (position == std::string::npos)
        {
            break;
        }

        position = payload.find(':', position + quotedKey.size());
        if (position == std::string::npos)
        {
            break;
        }

        ++position;
        while (position < payload.size() && payload[position] == ' ')
        {
            ++position;
        }

        std::uint64_t value = 0;
        bool sawDigit = false;
        for (; position < payload.size(); ++position)
        {
            const char ch = payload[position];
            if (ch < '0' || ch > '9')
            {
                break;
            }

            sawDigit = true;
            value = (value * 10) + static_cast<std::uint64_t>(ch - '0');
        }

        if (sawDigit)
        {
            result = value;
        }
    }
    while (false);

    return result;
}

KnMonAgentMessage BuildAgentMessage(const KnMonCaptureResult& result, const std::string& rawPayload)
{
    KnMonAgentMessage message;
    message.SchemaVersion = ExtractJsonString(rawPayload, "schemaVersion");
    if (message.SchemaVersion.empty())
    {
        message.SchemaVersion = "0.1.0";
    }

    message.MessageType = ExtractJsonString(rawPayload, "messageType");
    message.OperationId = ExtractJsonString(rawPayload, "operationId");
    if (message.OperationId.empty())
    {
        message.OperationId = result.OperationId;
    }

    message.ProcessId = static_cast<std::uint32_t>(ExtractJsonUInt64(rawPayload, "pid"));
    message.ThreadId = static_cast<std::uint32_t>(ExtractJsonUInt64(rawPayload, "tid"));
    message.TimestampUtc = ExtractJsonString(rawPayload, "timestampUtc");
    message.Sequence = ExtractJsonUInt64(rawPayload, "sequence");
    message.RawPayload = rawPayload;
    return message;
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
    const KnMonAgentArchitecture requestedArchitecture = RequestedArchitectureOrNative(request.Architecture);
    result.OperationId = request.OperationId.empty() ? "manual-operation" : request.OperationId;
    result.TargetPath = request.TargetPath;
    result.AgentPath = request.AgentPath;
    result.Architecture = ArchitectureName(requestedArchitecture);
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
        if (request.InjectionMethod != KnMonInjectionMethod::EarlyBirdApc)
        {
            SetResultError(result, ERROR_NOT_SUPPORTED, "knmon-core", "injection_method_check", "Only early-bird APC injection is supported in this goal.");
            break;
        }

        if (!RunSameBitnessPreflight(result, requestedArchitecture, request.TargetPath, request.AgentPath))
        {
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
            SetResultError(result, GetLastError(), "win32", "loader_failed", "Failed to resolve kernel32.dll before queuing LoadLibraryW.");
            break;
        }

        FARPROC loadLibrary = GetProcAddress(kernel32, "LoadLibraryW");
        if (loadLibrary == nullptr)
        {
            SetResultError(result, GetLastError(), "win32", "loader_failed", "Failed to resolve LoadLibraryW before queuing early-bird APC.");
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
            if (processInfo.hProcess != nullptr && WaitForSingleObject(processInfo.hProcess, 0) == WAIT_OBJECT_0)
            {
                DWORD exitCode = 0;
                GetExitCodeProcess(processInfo.hProcess, &exitCode);
                const DWORD errorCode = exitCode == 0 ? ERROR_PROCESS_ABORTED : exitCode;
                std::ostringstream stream;
                stream << "Target exited before agent HELLO connection. exitCode=" << exitCode;
                SetResultError(result, errorCode, "win32", "target_exited_early", stream.str());
                AddAudit(result, "target_exited_early", "agent_handshake_connect", stream.str(), errorCode, "win32");
            }
            else
            {
                SetResultError(result, pipeError, "win32", "handshake_timeout", "Agent handshake pipe connection timed out or failed.");
                AddAudit(result, "handshake_timeout", "agent_handshake_connect", "No agent connection was received before timeout.", pipeError, "win32");
            }
            break;
        }

        std::string payload;
        if (!ReadPipeMessage(pipeHandle, request.TimeoutMs, &payload, &pipeError))
        {
            SetResultError(result, pipeError, "win32", "handshake_timeout", "Agent handshake payload timed out or failed.");
            AddAudit(result, "handshake_timeout", "agent_handshake_read", "No agent HELLO payload was received before timeout.", pipeError, "win32");
            break;
        }

        result.Handshake = BuildHandshake(result, payload);
        if (!ValidateHandshakeEvidence(result, requestedArchitecture))
        {
            break;
        }

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

KnMonCaptureResult Controller::LaunchCapture(const KnMonLaunchRequest& request) const
{
    return LaunchCapture(request, nullptr);
}

KnMonCaptureResult Controller::LaunchCapture(const KnMonLaunchRequest& request, const KnMonCaptureStreamCallbacks* streamCallbacks) const
{
    KnMonCaptureResult result;
    const KnMonAgentArchitecture requestedArchitecture = RequestedArchitectureOrNative(request.Architecture);
    result.OperationId = request.OperationId.empty() ? "manual-operation" : request.OperationId;
    result.SessionId = request.SessionId;
    result.SessionState = request.SessionId.empty() ? "" : "running";
    result.SessionKind = request.SessionKind.empty() ? "launch_capture" : request.SessionKind;
    result.OwnerProcessId = request.OwnerProcessId;
    result.HelperProcessId = request.HelperProcessId;
    result.StartedUtc = request.StartedUtc;
    result.UpdatedUtc = NowUtc();
    result.CancellationEventName = request.CancellationEventName;
    result.TargetPath = request.TargetPath;
    result.AgentPath = request.AgentPath;
    result.Architecture = ArchitectureName(requestedArchitecture);
    result.CaptureMode = "bounded-native-launch";
    result.InjectionMethod = "early-bird APC";
    result.DetachPolicy = "self-disable-no-unload";
    result.AgentAbiVersion = KnMonAgentStateAbiVersion;
    result.OperationState = "running";

    PROCESS_INFORMATION processInfo = {};
    STARTUPINFOW startupInfo = {};
    startupInfo.cb = sizeof(startupInfo);
    HANDLE pipeHandle = INVALID_HANDLE_VALUE;
    SharedTransportSession transport;
    void* remoteDllPath = nullptr;
    std::uintptr_t remoteStopAddress = 0;
    bool processCreated = false;
    bool processResumed = false;
    bool targetExited = false;
    bool fatalError = false;
    bool hookInstallFailed = false;
    bool stopRequested = false;
    bool agentShutdownReceived = false;
    bool cancellationLogged = false;
    std::uint64_t hookInstalledCount = 0;
    std::uint64_t shutdownInstalledHooks = 0;
    std::uint64_t shutdownRestoredHooks = 0;
    std::uint64_t shutdownFailedHooks = 0;
    std::string shutdownReason;
    CancellationContext cancellationContext;
    std::uint64_t streamBatchSequence = 0;

    auto consumePayload = [&](const std::string& payload)
    {
        KnMonAgentMessage message = BuildAgentMessage(result, payload);
        result.AgentMessages.push_back(message);

        if (message.MessageType == "agent_hello" || PayloadContains(payload, "\"eventType\":\"agent_hello_received\""))
        {
            result.Handshake = BuildHandshake(result, payload);
            AddAudit(result, "agent_hello_received", "agent_event_read", payload);
        }
        else if (message.MessageType == "hook_installed")
        {
            ++hookInstalledCount;
            AddAudit(result, "hook_installed", "agent_event_read", payload);
        }
        else if (message.MessageType == "hook_install_failed")
        {
            hookInstallFailed = true;
            AddAudit(result, "hook_install_failed", "agent_event_read", payload, ERROR_HOOK_NOT_INSTALLED);
        }
        else if (message.MessageType == "api_call")
        {
            result.CapturedEvents.push_back(message);
            AddAudit(result, "api_call_received", "agent_event_read", message.RawPayload);
        }
        else if (message.MessageType == "dropped_events")
        {
            result.DroppedEvents = ExtractJsonUInt64(payload, "droppedCount");
            AddAudit(result, "dropped_events_reported", "agent_event_read", payload);
        }
        else if (message.MessageType == "agent_shutdown")
        {
            agentShutdownReceived = true;
            shutdownReason = ExtractJsonString(payload, "reason");
            shutdownInstalledHooks = ExtractJsonUInt64(payload, "installedHooks");
            shutdownRestoredHooks = ExtractJsonUInt64(payload, "restoredHooks");
            shutdownFailedHooks = ExtractJsonUInt64(payload, "failedHooks");
            result.DroppedEvents = ExtractJsonUInt64(payload, "droppedCount");
            result.SessionShutdownEvidence = payload;
            AddAudit(result, "agent_shutdown", "agent_event_read", payload);
            if (shutdownRestoredHooks >= shutdownInstalledHooks && shutdownFailedHooks == 0)
            {
                AddAudit(result, "agent_self_disabled", "agent_shutdown", payload);
            }
            else
            {
                AddAudit(result, "launch_cleanup_incomplete", "agent_shutdown", payload, ERROR_HOOK_NOT_INSTALLED);
            }
        }
        else
        {
            AddAudit(result, "agent_message_received", "agent_event_read", payload);
        }
    };

    auto observeCancellation = [&](const std::string& stage) -> bool
    {
        bool observed = false;

        if (IsCancellationRequested(cancellationContext))
        {
            result.CancelRequested = true;
            result.CancelObserved = true;
            result.CancelStage = stage;
            if (result.OperationState != "stopping_agent" && result.OperationState != "draining")
            {
                result.OperationState = "cancel_requested";
            }

            if (!cancellationLogged)
            {
                AddAudit(result, "operation_cancel_requested", stage, "Cancellation was requested for this launch capture operation.");
                cancellationLogged = true;
            }

            observed = true;
        }

        return observed;
    };

    do
    {
        DWORD cancellationError = 0;
        if (!OpenCancellationContext(request.CancellationEventName, &cancellationContext, &cancellationError))
        {
            SetResultError(result, cancellationError == 0 ? ERROR_INVALID_PARAMETER : cancellationError, "win32", "operation_cancellation_setup", "Failed to create launch cancellation event.");
            fatalError = true;
            break;
        }

        if (request.InjectionMethod != KnMonInjectionMethod::EarlyBirdApc)
        {
            SetResultError(result, ERROR_NOT_SUPPORTED, "knmon-core", "injection_method_check", "Only early-bird APC injection is supported by launch-capture.");
            fatalError = true;
            break;
        }

        if (observeCancellation("launch_preflight"))
        {
            SetResultError(result, ERROR_CANCELLED, "knmon-core", "operation_cancelled", "Launch capture was cancelled before process creation.");
            result.OperationState = "cancelled";
            fatalError = true;
            break;
        }

        if (!RunSameBitnessPreflight(result, requestedArchitecture, request.TargetPath, request.AgentPath))
        {
            fatalError = true;
            break;
        }

        AddAudit(result, "launch_capture_requested", "launch_capture", "Controlled early-bird launch capture requested.");

        const std::wstring pipeName = L"\\\\.\\pipe\\knmon_agent_" + Utf8ToWide(result.OperationId);
        pipeHandle = CreateNamedPipeW(
            pipeName.c_str(),
            PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            65536,
            65536,
            request.TimeoutMs,
            nullptr);

        if (pipeHandle == INVALID_HANDLE_VALUE)
        {
            SetResultError(result, GetLastError(), "win32", "CreateNamedPipeW", "Failed to create launch agent event pipe.");
            fatalError = true;
            break;
        }

        AddAudit(result, "event_pipe_created", "CreateNamedPipeW", WideToUtf8(pipeName.c_str()));

        DWORD transportError = 0;
        if (!CreateSharedTransport(transport, result.OperationId, requestedArchitecture, &transportError))
        {
            SetResultError(result, transportError, "win32", "shared_memory_transport_create", "Failed to create launch shared-memory event transport.");
            AddAudit(result, "transport_setup_failed", "shared_memory_transport_create", "Launch shared-memory event transport setup failed.", transportError, "win32");
            fatalError = true;
            break;
        }

        UpdateTransportMetrics(result, transport);
        AddAudit(result, "launch_transport_created", "CreateFileMappingW", "Launch shared-memory event transport created.");

        const std::wstring targetPath = Utf8ToWide(request.TargetPath);
        const std::wstring agentPath = Utf8ToWide(request.AgentPath);
        const std::wstring agentModuleName = std::filesystem::path(agentPath).filename().wstring();
        const std::wstring workingDirectory = request.WorkingDirectory.empty() ? std::filesystem::path(targetPath).parent_path().wstring() : Utf8ToWide(request.WorkingDirectory);
        std::wstring commandLine = QuoteArgument(targetPath);
        std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
        mutableCommandLine.push_back(L'\0');

        EnvironmentOverride pipeEnv(L"KNMON_AGENT_PIPE", pipeName);
        EnvironmentOverride operationEnv(L"KNMON_OPERATION_ID", Utf8ToWide(result.OperationId));
        EnvironmentOverride modeEnv(L"KNMON_CAPTURE_MODE", L"launch");
        EnvironmentOverride transportEnv(L"KNMON_TRANSPORT_NAME", transport.MappingName);
        EnvironmentOverride transportRequiredEnv(L"KNMON_TRANSPORT_REQUIRED", L"1");

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
            SetResultError(result, GetLastError(), "win32", "CreateProcessW", "Failed to create target process suspended for launch capture.");
            fatalError = true;
            break;
        }

        processCreated = true;
        result.TargetProcessId = processInfo.dwProcessId;
        result.TargetThreadId = processInfo.dwThreadId;
        AddAudit(result, "process_created_suspended", "CreateProcessW", "Target process created suspended for early-bird launch capture.");
        EmitCaptureStreamSessionFrame(streamCallbacks, "session_state", result);

        const std::uint64_t remoteSize = static_cast<std::uint64_t>((agentPath.size() + 1) * sizeof(wchar_t));
        remoteDllPath = VirtualAllocEx(processInfo.hProcess, nullptr, static_cast<SIZE_T>(remoteSize), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (remoteDllPath == nullptr)
        {
            SetResultError(result, GetLastError(), "win32", "VirtualAllocEx", "Failed to allocate remote agent path buffer.");
            fatalError = true;
            break;
        }

        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(processInfo.hProcess, remoteDllPath, agentPath.c_str(), static_cast<SIZE_T>(remoteSize), &bytesWritten))
        {
            SetResultError(result, GetLastError(), "win32", "WriteProcessMemory", "Failed to write agent path into target process.");
            fatalError = true;
            break;
        }

        AddAudit(result, "agent_path_written", "WriteProcessMemory", "Agent DLL path written into target process.");

        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32 == nullptr)
        {
            SetResultError(result, GetLastError(), "win32", "loader_failed", "Failed to resolve kernel32.dll before queuing LoadLibraryW.");
            fatalError = true;
            break;
        }

        FARPROC loadLibrary = GetProcAddress(kernel32, "LoadLibraryW");
        if (loadLibrary == nullptr)
        {
            SetResultError(result, GetLastError(), "win32", "loader_failed", "Failed to resolve LoadLibraryW before queuing early-bird APC.");
            fatalError = true;
            break;
        }

        if (QueueUserAPC(reinterpret_cast<PAPCFUNC>(loadLibrary), processInfo.hThread, reinterpret_cast<ULONG_PTR>(remoteDllPath)) == 0)
        {
            SetResultError(result, GetLastError(), "win32", "QueueUserAPC", "Failed to queue early-bird APC.");
            fatalError = true;
            break;
        }

        AddAudit(result, "early_bird_apc_queued", "QueueUserAPC", "Early-bird LoadLibraryW APC queued on the suspended primary thread.");

        if (ResumeThread(processInfo.hThread) == static_cast<DWORD>(-1))
        {
            SetResultError(result, GetLastError(), "win32", "ResumeThread", "Failed to resume target primary thread.");
            fatalError = true;
            break;
        }

        processResumed = true;
        AddAudit(result, "primary_thread_resumed", "ResumeThread", "Target primary thread resumed.");

        DWORD pipeError = 0;
        if (!WaitForPipeConnection(pipeHandle, request.TimeoutMs, &pipeError))
        {
            if (processInfo.hProcess != nullptr && WaitForSingleObject(processInfo.hProcess, 0) == WAIT_OBJECT_0)
            {
                DWORD exitCode = 0;
                GetExitCodeProcess(processInfo.hProcess, &exitCode);
                const DWORD errorCode = exitCode == 0 ? ERROR_PROCESS_ABORTED : exitCode;
                std::ostringstream stream;
                stream << "Target exited before launch agent event pipe connection. exitCode=" << exitCode;
                SetResultError(result, errorCode, "win32", "target_exited_early", stream.str());
                AddAudit(result, "target_exited_early", "agent_pipe_connect", stream.str(), errorCode, "win32");
            }
            else
            {
                SetResultError(result, pipeError, "win32", "handshake_timeout", "Launch agent event pipe connection timed out or failed.");
                AddAudit(result, "handshake_timeout", "agent_pipe_connect", "No agent connection was received before timeout.", pipeError, "win32");
            }

            fatalError = true;
            break;
        }

        AddAudit(result, "agent_pipe_connected", "agent_pipe_connect", "Launch agent event pipe connected.");
        AddAudit(result, "launch_capture_started", "launch_capture", "Bounded early-bird launch capture started.");

        const ULONGLONG captureDeadline = GetTickCount64() + static_cast<ULONGLONG>(request.DurationMs);
        while (GetTickCount64() < captureDeadline)
        {
            if (observeCancellation("launch_capture"))
            {
                break;
            }

            DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);

            std::string payload;
            pipeError = 0;
            if (ReadPipeMessage(pipeHandle, 100, &payload, &pipeError))
            {
                consumePayload(payload);
                DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);
                continue;
            }

            DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);
            if (pipeError == ERROR_BROKEN_PIPE || pipeError == ERROR_HANDLE_EOF || pipeError == ERROR_NO_DATA)
            {
                AddAudit(result, agentShutdownReceived ? "pipe_closed_after_shutdown" : "pipe_closed_without_shutdown", "agent_event_read", "Launch agent event pipe closed.", pipeError, "win32");
                break;
            }

            if (pipeError != WAIT_TIMEOUT)
            {
                SetResultError(result, pipeError, "win32", "agent_event_read", "Launch agent event stream read failed.");
                fatalError = true;
                break;
            }

            if (WaitForSingleObject(processInfo.hProcess, 0) == WAIT_OBJECT_0)
            {
                targetExited = true;
                AddAudit(result, "target_exited", "launch_capture", "Target exited before launch capture duration elapsed.");
                break;
            }
        }

        if (fatalError)
        {
            break;
        }

        DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);
        UpdateTransportMetrics(result, transport);
        if (result.CancelObserved)
        {
            AddAudit(result, "launch_capture_cancelled", "launch_capture", "Bounded launch capture cancellation observed; cleanup follows.");
            result.OperationState = "stopping_agent";
            result.SessionState = result.SessionId.empty() ? result.SessionState : "stopping_agent";
        }
        else
        {
            AddAudit(result, "launch_capture_window_completed", "launch_capture", "Bounded launch capture window completed.");
            result.OperationState = "stopping_agent";
            result.SessionState = result.SessionId.empty() ? result.SessionState : "stopping_agent";
        }

        EmitCaptureStreamSessionFrame(streamCallbacks, "session_stopping", result);

        if (!targetExited && WaitForSingleObject(processInfo.hProcess, 0) == WAIT_OBJECT_0)
        {
            targetExited = true;
            AddAudit(result, "target_exited", "launch_cleanup", "Target exited before explicit launch cleanup was requested.");
        }

        if (!targetExited)
        {
            std::uintptr_t remoteAgentBase = 0;
            DWORD moduleError = 0;
            for (int attempt = 0; attempt < 20 && remoteAgentBase == 0; ++attempt)
            {
                if (FindRemoteModuleBase(processInfo.dwProcessId, agentModuleName, &remoteAgentBase, &moduleError))
                {
                    break;
                }

                Sleep(50);
            }

            if (remoteAgentBase == 0)
            {
                SetResultError(result, moduleError == 0 ? ERROR_MOD_NOT_FOUND : moduleError, "win32", "remote_agent_missing", "Agent module was not visible in the target before launch cleanup.");
                fatalError = true;
                break;
            }

            std::uintptr_t stopRva = 0;
            DWORD remoteError = 0;
            if (!ResolveImageExportRva(agentPath, "KnMonAgentStop", &stopRva, &remoteError))
            {
                SetResultError(result, remoteError == 0 ? ERROR_PROC_NOT_FOUND : remoteError, "win32", "remote_export_missing", "Failed to resolve KnMonAgentStop export RVA.");
                fatalError = true;
                break;
            }

            remoteStopAddress = remoteAgentBase + stopRva;
            DWORD remoteExitCode = 0;
            AddAudit(result, "agent_stop_requested", "CreateRemoteThread", "Requesting launch agent self-disable.");
            stopRequested = true;
            if (!WaitRemoteThread(processInfo.hProcess, reinterpret_cast<void*>(remoteStopAddress), nullptr, request.TimeoutMs, &remoteExitCode, &remoteError))
            {
                SetResultError(result, remoteError, "win32", "agent_stop_timeout", "Remote KnMonAgentStop thread failed or timed out.");
                fatalError = true;
                break;
            }

            if (remoteExitCode != static_cast<DWORD>(KnMonAgentControlStatus::Success))
            {
                std::ostringstream stream;
                stream << "KnMonAgentStop returned status " << remoteExitCode << ".";
                SetResultError(result, remoteExitCode, "knmon-agent", "detach_incomplete", stream.str());
                fatalError = true;
                break;
            }

            const ULONGLONG shutdownDeadline = GetTickCount64() + static_cast<ULONGLONG>(request.TimeoutMs);
            result.OperationState = "draining";
            result.SessionState = result.SessionId.empty() ? result.SessionState : "draining";
            while (!agentShutdownReceived && GetTickCount64() < shutdownDeadline)
            {
                DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);

                std::string payload;
                pipeError = 0;
                if (ReadPipeMessage(pipeHandle, 100, &payload, &pipeError))
                {
                    consumePayload(payload);
                    DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);
                    continue;
                }

                DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);
                if (pipeError == ERROR_BROKEN_PIPE || pipeError == ERROR_HANDLE_EOF || pipeError == ERROR_NO_DATA)
                {
                    AddAudit(result, agentShutdownReceived ? "pipe_closed_after_shutdown" : "pipe_closed_without_shutdown", "agent_event_read", "Launch agent event pipe closed.", pipeError, "win32");
                    break;
                }

                if (pipeError != WAIT_TIMEOUT)
                {
                    SetResultError(result, pipeError, "win32", "agent_event_read", "Launch agent shutdown read failed.");
                    fatalError = true;
                    break;
                }
            }
        }

        DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);
        UpdateTransportMetrics(result, transport);

        if (fatalError)
        {
            break;
        }

        if (!result.Handshake.Received)
        {
            SetResultError(result, WAIT_TIMEOUT, "knmon-core", "agent_hello_required", "Launch agent HELLO was not received.");
            fatalError = true;
            break;
        }

        if (!ValidateHandshakeEvidence(result, requestedArchitecture))
        {
            fatalError = true;
            break;
        }

        if (hookInstallFailed)
        {
            SetResultError(result, ERROR_HOOK_NOT_INSTALLED, "knmon-core", "hook_install_required", "One or more selected hooks could not be installed.");
            fatalError = true;
            break;
        }

        if (hookInstalledCount < ExpectedFileIoHookCount)
        {
            SetResultError(result, ERROR_HOOK_NOT_INSTALLED, "knmon-core", "hook_install_count_required", "Launch capture did not report the required stable File I/O hooks.");
            fatalError = true;
            break;
        }

        if (!targetExited && !agentShutdownReceived)
        {
            SetResultError(result, WAIT_TIMEOUT, "knmon-core", "agent_shutdown_required", "Launch agent shutdown lifecycle event was not received.");
            fatalError = true;
            break;
        }

        if (agentShutdownReceived && (shutdownRestoredHooks < shutdownInstalledHooks || shutdownFailedHooks != 0))
        {
            SetResultError(result, ERROR_HOOK_NOT_INSTALLED, "knmon-core", "hook_uninstall_required", "Launch self-disable did not restore all installed hooks.");
            fatalError = true;
            break;
        }

        if (!shutdownReason.empty() && shutdownReason != "self_disable" && shutdownReason != "process_detach")
        {
            AddAudit(result, "detach_policy_note", "agent_shutdown", "Launch shutdown reason was " + shutdownReason + ".");
        }

        result.AgentCleanupAttempted = stopRequested;
        result.AgentCleanupSucceeded = stopRequested ? agentShutdownReceived && shutdownRestoredHooks >= shutdownInstalledHooks && shutdownFailedHooks == 0 : targetExited;

        if (result.CancelObserved)
        {
            if (!result.AgentCleanupSucceeded && !targetExited)
            {
                result.OperationState = "cleanup_failed";
                SetResultError(result, ERROR_CANCELLED, "knmon-core", "cleanup_failed", "Launch capture cancellation cleanup did not prove self-disable.");
                fatalError = true;
                break;
            }

            result.Success = false;
            result.Win32ErrorCode = ERROR_CANCELLED;
            result.NtStatus = "0x00000000";
            result.Subsystem = "knmon-core";
            result.Operation = "operation_cancelled";
            result.OperationState = "cancelled";
            result.SessionState = result.SessionId.empty() ? result.SessionState : "stopped";
            result.StoppedUtc = NowUtc();
            result.Message = "Launch capture cancelled after cleanup.";
            break;
        }

        result.Success = true;
        result.Win32ErrorCode = 0;
        result.Subsystem = "knmon-core";
        result.Operation = "launch_capture";
        result.OperationState = "completed";
        result.SessionState = result.SessionId.empty() ? result.SessionState : "stopped";
        result.StoppedUtc = NowUtc();
        result.Message = "Controlled early-bird launch capture completed.";
        AddAudit(result, "launch_capture_completed", "launch_capture", "Bounded early-bird launch capture completed.");
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
        AddAudit(result, "cleanup_completed", "handle_cleanup", "Launch controller handle cleanup completed.");
    }

    if (pipeHandle != INVALID_HANDLE_VALUE)
    {
        DisconnectNamedPipe(pipeHandle);
        CloseHandle(pipeHandle);
    }

    DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);
    UpdateTransportMetrics(result, transport);
    CloseSharedTransport(transport);

    if (processInfo.hThread != nullptr)
    {
        CloseHandle(processInfo.hThread);
    }

    if (processInfo.hProcess != nullptr)
    {
        CloseHandle(processInfo.hProcess);
    }

    CloseCancellationContext(cancellationContext);

    if (result.Operation.empty())
    {
        result.Operation = fatalError ? "launch_capture_failed" : "launch_capture";
    }

    if (result.Message.empty())
    {
        result.Message = fatalError ? "Controlled early-bird launch capture failed." : "Controlled early-bird launch capture finished.";
    }

    if (result.OperationState.empty() || (result.OperationState == "running" && !result.Success))
    {
        result.OperationState = fatalError ? "failed" : "completed";
    }

    if (!result.SessionId.empty())
    {
        result.UpdatedUtc = NowUtc();
        if (result.SessionState.empty() || result.SessionState == "running" || result.SessionState == "stopping_agent" || result.SessionState == "draining")
        {
            result.SessionState = result.Success ? "stopped" : "failed";
        }

        if (result.StoppedUtc.empty() && (result.SessionState == "stopped" || result.SessionState == "failed"))
        {
            result.StoppedUtc = result.UpdatedUtc;
        }
    }

    return result;
}

KnMonCaptureResult Controller::CaptureSampleFileIo(const KnMonLaunchRequest& request) const
{
    KnMonCaptureResult result;
    const KnMonAgentArchitecture requestedArchitecture = RequestedArchitectureOrNative(request.Architecture);
    result.OperationId = request.OperationId.empty() ? "manual-operation" : request.OperationId;
    result.TargetPath = request.TargetPath;
    result.AgentPath = request.AgentPath;
    result.Architecture = ArchitectureName(requestedArchitecture);
    result.InjectionMethod = "early-bird APC";

    PROCESS_INFORMATION processInfo = {};
    STARTUPINFOW startupInfo = {};
    startupInfo.cb = sizeof(startupInfo);
    HANDLE pipeHandle = INVALID_HANDLE_VALUE;
    SharedTransportSession transport;
    void* remoteDllPath = nullptr;
    bool processCreated = false;
    bool processResumed = false;
    bool fatalError = false;

    do
    {
        if (request.InjectionMethod != KnMonInjectionMethod::EarlyBirdApc)
        {
            SetResultError(result, ERROR_NOT_SUPPORTED, "knmon-core", "injection_method_check", "Only early-bird APC injection is supported in this goal.");
            fatalError = true;
            break;
        }

        if (!RunSameBitnessPreflight(result, requestedArchitecture, request.TargetPath, request.AgentPath))
        {
            fatalError = true;
            break;
        }

        AddAudit(result, "capture_requested", "capture_requested", "Controlled File I/O capture requested.");

        const std::wstring pipeName = L"\\\\.\\pipe\\knmon_agent_" + Utf8ToWide(result.OperationId);
        pipeHandle = CreateNamedPipeW(
            pipeName.c_str(),
            PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            65536,
            65536,
            request.TimeoutMs,
            nullptr);

        if (pipeHandle == INVALID_HANDLE_VALUE)
        {
            SetResultError(result, GetLastError(), "win32", "CreateNamedPipeW", "Failed to create agent event pipe.");
            fatalError = true;
            break;
        }

        AddAudit(result, "event_pipe_created", "CreateNamedPipeW", WideToUtf8(pipeName.c_str()));

        DWORD transportError = 0;
        if (!CreateSharedTransport(transport, result.OperationId, requestedArchitecture, &transportError))
        {
            SetResultError(result, transportError, "win32", "shared_memory_transport_create", "Failed to create shared-memory event transport.");
            AddAudit(result, "transport_setup_failed", "shared_memory_transport_create", "Shared-memory event transport setup failed.", transportError, "win32");
            fatalError = true;
            break;
        }

        UpdateTransportMetrics(result, transport);
        AddAudit(result, "transport_created", "CreateFileMappingW", "Shared-memory event transport created.");

        const std::wstring targetPath = Utf8ToWide(request.TargetPath);
        const std::wstring agentPath = Utf8ToWide(request.AgentPath);
        const std::wstring workingDirectory = request.WorkingDirectory.empty() ? std::filesystem::path(targetPath).parent_path().wstring() : Utf8ToWide(request.WorkingDirectory);
        std::wstring commandLine = QuoteArgument(targetPath);
        commandLine += L" --slow";
        std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
        mutableCommandLine.push_back(L'\0');

        EnvironmentOverride pipeEnv(L"KNMON_AGENT_PIPE", pipeName);
        EnvironmentOverride operationEnv(L"KNMON_OPERATION_ID", Utf8ToWide(result.OperationId));
        EnvironmentOverride modeEnv(L"KNMON_CAPTURE_MODE", L"fileio");
        EnvironmentOverride transportEnv(L"KNMON_TRANSPORT_NAME", transport.MappingName);
        EnvironmentOverride transportRequiredEnv(L"KNMON_TRANSPORT_REQUIRED", L"1");

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
            fatalError = true;
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
            fatalError = true;
            break;
        }

        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(processInfo.hProcess, remoteDllPath, agentPath.c_str(), static_cast<SIZE_T>(remoteSize), &bytesWritten))
        {
            SetResultError(result, GetLastError(), "win32", "WriteProcessMemory", "Failed to write agent path into target process.");
            fatalError = true;
            break;
        }

        AddAudit(result, "agent_path_written", "WriteProcessMemory", "Agent DLL path written into target process.");

        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32 == nullptr)
        {
            SetResultError(result, GetLastError(), "win32", "loader_failed", "Failed to resolve kernel32.dll before queuing LoadLibraryW.");
            fatalError = true;
            break;
        }

        FARPROC loadLibrary = GetProcAddress(kernel32, "LoadLibraryW");
        if (loadLibrary == nullptr)
        {
            SetResultError(result, GetLastError(), "win32", "loader_failed", "Failed to resolve LoadLibraryW before queuing early-bird APC.");
            fatalError = true;
            break;
        }

        if (QueueUserAPC(reinterpret_cast<PAPCFUNC>(loadLibrary), processInfo.hThread, reinterpret_cast<ULONG_PTR>(remoteDllPath)) == 0)
        {
            SetResultError(result, GetLastError(), "win32", "QueueUserAPC", "Failed to queue early-bird APC.");
            fatalError = true;
            break;
        }

        AddAudit(result, "early_bird_apc_queued", "QueueUserAPC", "Early-bird LoadLibraryW APC queued on the suspended primary thread.");

        if (ResumeThread(processInfo.hThread) == static_cast<DWORD>(-1))
        {
            SetResultError(result, GetLastError(), "win32", "ResumeThread", "Failed to resume target primary thread.");
            fatalError = true;
            break;
        }

        processResumed = true;
        AddAudit(result, "primary_thread_resumed", "ResumeThread", "Target primary thread resumed.");

        DWORD pipeError = 0;
        if (!WaitForPipeConnection(pipeHandle, request.TimeoutMs, &pipeError))
        {
            if (processInfo.hProcess != nullptr && WaitForSingleObject(processInfo.hProcess, 0) == WAIT_OBJECT_0)
            {
                DWORD exitCode = 0;
                GetExitCodeProcess(processInfo.hProcess, &exitCode);
                const DWORD errorCode = exitCode == 0 ? ERROR_PROCESS_ABORTED : exitCode;
                std::ostringstream stream;
                stream << "Target exited before agent event pipe connection. exitCode=" << exitCode;
                SetResultError(result, errorCode, "win32", "target_exited_early", stream.str());
                AddAudit(result, "target_exited_early", "agent_pipe_connect", stream.str(), errorCode, "win32");
            }
            else
            {
                SetResultError(result, pipeError, "win32", "handshake_timeout", "Agent event pipe connection timed out or failed.");
                AddAudit(result, "handshake_timeout", "agent_pipe_connect", "No agent connection was received before timeout.", pipeError, "win32");
            }
            fatalError = true;
            break;
        }

        AddAudit(result, "agent_pipe_connected", "agent_pipe_connect", "Agent event pipe connected.");

        const ULONGLONG captureDeadline = GetTickCount64() + static_cast<ULONGLONG>(request.TimeoutMs) + 8000ULL;
        bool captureEnded = false;
        bool hookInstallFailed = false;
        bool agentShutdownReceived = false;
        std::uint64_t hookInstalledCount = 0;
        std::uint64_t shutdownInstalledHooks = 0;
        std::uint64_t shutdownRestoredHooks = 0;
        std::uint64_t shutdownFailedHooks = 0;
        std::string shutdownReason;

        while (!captureEnded)
        {
            std::string payload;
            pipeError = 0;
            DrainSharedTransport(result, transport);

            if (ReadPipeMessage(pipeHandle, 2500, &payload, &pipeError))
            {
                KnMonAgentMessage message = BuildAgentMessage(result, payload);
                result.AgentMessages.push_back(message);

                if (message.MessageType == "agent_hello" || PayloadContains(payload, "\"eventType\":\"agent_hello_received\""))
                {
                    result.Handshake = BuildHandshake(result, payload);
                    AddAudit(result, "agent_hello_received", "agent_event_read", payload);
                }
                else if (message.MessageType == "hook_installed")
                {
                    ++hookInstalledCount;
                    AddAudit(result, "hook_installed", "agent_event_read", payload);
                }
                else if (message.MessageType == "hook_install_failed")
                {
                    hookInstallFailed = true;
                    AddAudit(result, "hook_install_failed", "agent_event_read", payload, ERROR_HOOK_NOT_INSTALLED);
                }
                else if (message.MessageType == "api_call")
                {
                    result.CapturedEvents.push_back(message);
                    AddAudit(result, "api_call_received", "agent_event_read", message.RawPayload);
                }
                else if (message.MessageType == "dropped_events")
                {
                    result.DroppedEvents = ExtractJsonUInt64(payload, "droppedCount");
                    AddAudit(result, "dropped_events_reported", "agent_event_read", payload);
                }
                else if (message.MessageType == "agent_shutdown")
                {
                    agentShutdownReceived = true;
                    shutdownReason = ExtractJsonString(payload, "reason");
                    shutdownInstalledHooks = ExtractJsonUInt64(payload, "installedHooks");
                    shutdownRestoredHooks = ExtractJsonUInt64(payload, "restoredHooks");
                    shutdownFailedHooks = ExtractJsonUInt64(payload, "failedHooks");
                    result.DroppedEvents = ExtractJsonUInt64(payload, "droppedCount");
                    AddAudit(result, "agent_shutdown", "agent_event_read", payload);
                    if (shutdownReason == "process_detach" && shutdownRestoredHooks >= shutdownInstalledHooks && shutdownFailedHooks == 0)
                    {
                        AddAudit(result, "hook_uninstall_complete", "agent_shutdown", "Installed hooks were restored during process detach.");
                    }
                    else
                    {
                        AddAudit(result, "agent_self_disabled", "agent_shutdown", payload, shutdownFailedHooks == 0 ? 0 : ERROR_HOOK_NOT_INSTALLED);
                    }
                    captureEnded = true;
                }
                else
                {
                    AddAudit(result, "agent_message_received", "agent_event_read", payload);
                }

                DrainSharedTransport(result, transport);
                continue;
            }

            DrainSharedTransport(result, transport);

            if (pipeError == ERROR_BROKEN_PIPE || pipeError == ERROR_HANDLE_EOF || pipeError == ERROR_NO_DATA)
            {
                AddAudit(result, agentShutdownReceived ? "pipe_closed_after_shutdown" : "pipe_closed_without_shutdown", "agent_event_read", "Agent event pipe closed.", pipeError, "win32");
                captureEnded = true;
                break;
            }

            if (pipeError == WAIT_TIMEOUT)
            {
                const DWORD processWait = WaitForSingleObject(processInfo.hProcess, 0);
                if (processWait == WAIT_OBJECT_0)
                {
                    DrainSharedTransport(result, transport);
                    captureEnded = true;
                    break;
                }

                if (GetTickCount64() >= captureDeadline)
                {
                    SetResultError(result, WAIT_TIMEOUT, "win32", "agent_event_idle_timeout", "Agent event stream did not finish before the bounded capture timeout.");
                    fatalError = true;
                    break;
                }

                continue;
            }

            SetResultError(result, pipeError, "win32", "agent_event_read", "Agent event stream read failed.");
            fatalError = true;
            break;
        }

        if (fatalError)
        {
            break;
        }

        DrainSharedTransport(result, transport);
        UpdateTransportMetrics(result, transport);

        if (hookInstalledCount >= ExpectedFileIoHookCount)
        {
            AddAudit(result, "hook_install_complete", "agent_event_read", "All selected File I/O hooks reported installed.");
        }

        if (agentShutdownReceived)
        {
            AddAudit(result, "pipe_closed_after_shutdown", "agent_shutdown", "Agent shutdown was received; controller pipe cleanup follows.");
        }

        if (!result.Handshake.Received)
        {
            SetResultError(result, WAIT_TIMEOUT, "knmon-core", "agent_hello_required", "Agent HELLO was not received before capture completed.");
            fatalError = true;
            break;
        }

        if (!ValidateHandshakeEvidence(result, requestedArchitecture))
        {
            fatalError = true;
            break;
        }

        if (hookInstallFailed)
        {
            SetResultError(result, ERROR_HOOK_NOT_INSTALLED, "knmon-core", "hook_install_required", "One or more selected File I/O hooks could not be installed.");
            fatalError = true;
            break;
        }

        if (hookInstalledCount < ExpectedFileIoHookCount)
        {
            SetResultError(result, ERROR_HOOK_NOT_INSTALLED, "knmon-core", "hook_install_count_required", "Not all selected File I/O hooks reported installed.");
            fatalError = true;
            break;
        }

        if (result.CapturedEvents.empty())
        {
            SetResultError(result, ERROR_NO_DATA, "knmon-core", "api_call_required", "No real File I/O api_call events were captured from the sample target.");
            fatalError = true;
            break;
        }

        if (!agentShutdownReceived)
        {
            SetResultError(result, ERROR_NO_DATA, "knmon-core", "agent_shutdown_required", "Agent shutdown lifecycle event was not received before capture completed.");
            fatalError = true;
            break;
        }

        if (shutdownRestoredHooks < shutdownInstalledHooks || shutdownFailedHooks != 0)
        {
            SetResultError(result, ERROR_HOOK_NOT_INSTALLED, "knmon-core", "hook_uninstall_required", "One or more installed hooks were not restored cleanly.");
            fatalError = true;
            break;
        }

        result.Success = true;
        result.Win32ErrorCode = 0;
        result.Subsystem = "knmon-core";
        result.Operation = "capture_sample_fileio";
        result.Message = "Controlled File I/O capture completed with real agent api_call events.";
        AddAudit(result, "capture_completed", "capture_sample_fileio", "Bounded controlled File I/O capture completed.");
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
        AddAudit(result, "cleanup_completed", "TerminateProcess", "Suspended target was terminated because capture failed before resume.");
    }
    else if (processCreated && fatalError && processInfo.hProcess != nullptr && WaitForSingleObject(processInfo.hProcess, 0) == WAIT_TIMEOUT)
    {
        TerminateProcess(processInfo.hProcess, 1);
        AddAudit(result, "cleanup_completed", "TerminateProcess", "Controlled target was terminated after capture failure.");
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

    DrainSharedTransport(result, transport);
    UpdateTransportMetrics(result, transport);
    CloseSharedTransport(transport);

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

KnMonCaptureResult Controller::AttachCapture(const KnMonAttachRequest& request) const
{
    return AttachCapture(request, nullptr);
}

KnMonCaptureResult Controller::AttachCapture(const KnMonAttachRequest& request, const KnMonCaptureStreamCallbacks* streamCallbacks) const
{
    KnMonCaptureResult result;
    const KnMonAgentArchitecture requestedArchitecture = RequestedArchitectureOrNative(request.Architecture);
    result.OperationId = request.OperationId.empty() ? "manual-operation" : request.OperationId;
    result.SessionId = request.SessionId;
    result.SessionState = request.SessionId.empty() ? "" : "running";
    result.SessionKind = request.SessionKind.empty() ? "attach_capture" : request.SessionKind;
    result.OwnerProcessId = request.OwnerProcessId;
    result.HelperProcessId = request.HelperProcessId;
    result.StartedUtc = request.StartedUtc;
    result.UpdatedUtc = NowUtc();
    result.CancellationEventName = request.CancellationEventName;
    result.AgentPath = request.AgentPath;
    result.AttachProcessId = request.ProcessId;
    result.TargetProcessId = request.ProcessId;
    result.Architecture = ArchitectureName(requestedArchitecture);
    result.CaptureMode = "bounded-native-attach";
    result.InjectionMethod = "remote LoadLibraryW";
    result.DetachPolicy = "self-disable-no-unload";
    result.AttachState = "not_loaded";
    result.AttachStrategy = "load_library_initialize";
    result.AgentAbiVersion = KnMonAgentStateAbiVersion;
    result.OperationState = "running";

    HANDLE pipeHandle = INVALID_HANDLE_VALUE;
    HANDLE processHandle = nullptr;
    SharedTransportSession transport;
    void* remoteDllPath = nullptr;
    void* remoteConfig = nullptr;
    std::uintptr_t remoteAgentBase = 0;
    std::uintptr_t remoteStopAddress = 0;
    bool useLoadedAgent = false;
    bool fatalError = false;
    bool agentInitialized = false;
    bool stopRequested = false;
    bool agentShutdownReceived = false;
    bool cancellationLogged = false;
    std::uint64_t hookInstalledCount = 0;
    std::uint64_t shutdownInstalledHooks = 0;
    std::uint64_t shutdownRestoredHooks = 0;
    std::uint64_t shutdownFailedHooks = 0;
    std::string shutdownReason;
    CancellationContext cancellationContext;
    std::uint64_t streamBatchSequence = 0;

    auto consumePayload = [&](const std::string& payload)
    {
        KnMonAgentMessage message = BuildAgentMessage(result, payload);
        result.AgentMessages.push_back(message);

        if (message.MessageType == "agent_hello" || PayloadContains(payload, "\"eventType\":\"agent_hello_received\""))
        {
            result.Handshake = BuildHandshake(result, payload);
            AddAudit(result, "agent_hello_received", "agent_event_read", payload);
        }
        else if (message.MessageType == "hook_installed")
        {
            ++hookInstalledCount;
            AddAudit(result, "hook_installed", "agent_event_read", payload);
        }
        else if (message.MessageType == "hook_install_failed")
        {
            AddAudit(result, "hook_install_failed", "agent_event_read", payload, ERROR_HOOK_NOT_INSTALLED);
        }
        else if (message.MessageType == "api_call")
        {
            result.CapturedEvents.push_back(message);
            AddAudit(result, "api_call_received", "agent_event_read", message.RawPayload);
        }
        else if (message.MessageType == "dropped_events")
        {
            result.DroppedEvents = ExtractJsonUInt64(payload, "droppedCount");
            AddAudit(result, "dropped_events_reported", "agent_event_read", payload);
        }
        else if (message.MessageType == "agent_shutdown")
        {
            agentShutdownReceived = true;
            shutdownReason = ExtractJsonString(payload, "reason");
            shutdownInstalledHooks = ExtractJsonUInt64(payload, "installedHooks");
            shutdownRestoredHooks = ExtractJsonUInt64(payload, "restoredHooks");
            shutdownFailedHooks = ExtractJsonUInt64(payload, "failedHooks");
            result.DroppedEvents = ExtractJsonUInt64(payload, "droppedCount");
            result.SessionShutdownEvidence = payload;
            AddAudit(result, "agent_shutdown", "agent_event_read", payload);
            if (shutdownRestoredHooks >= shutdownInstalledHooks && shutdownFailedHooks == 0)
            {
                AddAudit(result, "agent_self_disabled", "agent_shutdown", payload);
            }
            else
            {
                AddAudit(result, "detach_incomplete", "agent_shutdown", payload, ERROR_HOOK_NOT_INSTALLED);
            }
        }
        else
        {
            AddAudit(result, "agent_message_received", "agent_event_read", payload);
        }
    };

    auto observeCancellation = [&](const std::string& stage) -> bool
    {
        bool observed = false;

        if (IsCancellationRequested(cancellationContext))
        {
            result.CancelRequested = true;
            result.CancelObserved = true;
            result.CancelStage = stage;
            if (result.OperationState != "stopping_agent" && result.OperationState != "draining")
            {
                result.OperationState = "cancel_requested";
            }

            if (!cancellationLogged)
            {
                AddAudit(result, "operation_cancel_requested", stage, "Cancellation was requested for this bounded attach operation.");
                cancellationLogged = true;
            }

            observed = true;
        }

        return observed;
    };

    do
    {
        DWORD cancellationError = 0;
        if (!OpenCancellationContext(request.CancellationEventName, &cancellationContext, &cancellationError))
        {
            SetResultError(result, cancellationError == 0 ? ERROR_INVALID_PARAMETER : cancellationError, "win32", "operation_cancellation_setup", "Failed to create attach cancellation event.");
            fatalError = true;
            break;
        }

        if (!request.CancellationEventName.empty())
        {
            AddAudit(result, "operation_cancellation_ready", "CreateEventW", "Attach cancellation event is ready.");
        }

        if (observeCancellation("attach_preflight"))
        {
            SetResultError(result, ERROR_CANCELLED, "knmon-core", "operation_cancelled", "Attach capture was cancelled before remote mutation.");
            result.OperationState = "cancelled";
            fatalError = true;
            break;
        }

        if (request.InjectionMethod != KnMonInjectionMethod::RemoteLoadLibrary)
        {
            SetResultError(result, ERROR_NOT_SUPPORTED, "knmon-core", "injection_method_check", "Only remote LoadLibraryW attach is supported by attach-capture.");
            fatalError = true;
            break;
        }

        AttachPreflightResult preflight = RunAttachPreflight(result, request, requestedArchitecture);
        if (!preflight.Success)
        {
            fatalError = true;
            break;
        }

        processHandle = preflight.ProcessHandle;
        result.TargetPath = preflight.TargetPath.empty() ? preflight.TargetImageName : preflight.TargetPath;

        const std::wstring agentPath = Utf8ToWide(request.AgentPath);
        const std::wstring agentModuleName = std::filesystem::path(agentPath).filename().wstring();
        RemoteModuleInfo loadedAgentModule;
        DWORD moduleError = 0;
        if (FindRemoteModuleInfo(request.ProcessId, agentModuleName, &loadedAgentModule, &moduleError))
        {
            result.LoadedAgentDetected = true;
            result.LoadedAgentModuleBase = static_cast<std::uint64_t>(loadedAgentModule.Base);
            result.LoadedAgentPath = WideToUtf8(loadedAgentModule.Path.c_str());
            AddAudit(result, "loaded_agent_detected", "module_snapshot", "Expected agent DLL is already loaded in the target process.");

            std::uintptr_t queryStateRva = 0;
            DWORD queryExportError = 0;
            if (!ResolveImageExportRva(agentPath, "KnMonAgentQueryState", &queryStateRva, &queryExportError))
            {
                result.AttachState = "loaded_incompatible";
                result.AttachStrategy = "reject_incompatible";
                SetResultError(result, queryExportError == 0 ? ERROR_PROC_NOT_FOUND : queryExportError, "win32", "loaded_agent_incompatible", "Loaded agent does not export KnMonAgentQueryState.");
                fatalError = true;
                break;
            }

            KnMonAgentStateV1 agentState;
            DWORD controlStatus = 0;
            DWORD queryError = 0;
            std::string queryMessage;
            if (!QueryRemoteAgentState(processHandle, reinterpret_cast<void*>(loadedAgentModule.Base + queryStateRva), request.TimeoutMs, &agentState, &controlStatus, &queryError, &queryMessage))
            {
                result.AgentControlStatus = controlStatus;
                result.AttachState = controlStatus == static_cast<DWORD>(KnMonAgentControlStatus::UnsupportedAbi) ? "loaded_incompatible" : "loaded_unknown";
                result.AttachStrategy = controlStatus == static_cast<DWORD>(KnMonAgentControlStatus::UnsupportedAbi) ? "reject_incompatible" : "reject_unknown";
                SetResultError(result, queryError == 0 ? controlStatus : queryError, "knmon-agent", "loaded_agent_state_query", queryMessage.empty() ? "Loaded agent state query failed." : queryMessage);
                fatalError = true;
                break;
            }

            result.AgentControlStatus = controlStatus;
            result.AgentAbiVersion = agentState.AttachConfigAbiVersion;
            const bool resettable = (agentState.Flags & KnMonAgentStateFlagResettable) != 0;
            const bool active = (agentState.Flags & KnMonAgentStateFlagActive) != 0;
            const bool busy = (agentState.Flags & KnMonAgentStateFlagBusy) != 0;
            result.StaleAgentOperationId = WideToUtf8(agentState.OperationId);
            result.StaleAgentState = AgentLifecycleStateName(agentState.LifecycleState);
            std::ostringstream stateMessage;
            stateMessage << "Loaded agent state lifecycle=" << AgentLifecycleStateName(agentState.LifecycleState)
                         << " resettable=" << (resettable ? "true" : "false")
                         << " active=" << (active ? "true" : "false")
                         << " busy=" << (busy ? "true" : "false")
                         << " operationId=" << (result.StaleAgentOperationId.empty() ? "<empty>" : result.StaleAgentOperationId) << ".";
            AddAudit(result, "loaded_agent_state_queried", "KnMonAgentQueryState", stateMessage.str());

            if (agentState.LifecycleState == static_cast<std::uint32_t>(KnMonAgentLifecycleState::Disabled) && resettable)
            {
                result.AttachState = "loaded_disabled";
                result.AttachStrategy = "loaded_agent_reinitialize";
                remoteAgentBase = loadedAgentModule.Base;
                useLoadedAgent = true;
                AddAudit(result, "attach_strategy_selected", "loaded_agent_reinitialize", "Reusing already-loaded self-disabled agent without another LoadLibraryW call.");
            }
            else if (active)
            {
                result.AttachState = "loaded_active";
                result.AttachStrategy = "reject_already_active";
                SetResultError(result, ERROR_BUSY, "knmon-agent", "already_instrumented", "Loaded agent is already active in the target process.");
                fatalError = true;
                break;
            }
            else if (busy)
            {
                result.AttachState = "loaded_busy";
                result.AttachStrategy = "reject_already_active";
                SetResultError(result, ERROR_BUSY, "knmon-agent", "already_instrumented", "Loaded agent is busy and cannot start another bounded attach.");
                fatalError = true;
                break;
            }
            else
            {
                result.AttachState = "loaded_incompatible";
                result.AttachStrategy = "reject_incompatible";
                SetResultError(result, ERROR_INVALID_DATA, "knmon-agent", "loaded_agent_incompatible", "Loaded agent is not in a resettable self-disabled state.");
                fatalError = true;
                break;
            }
        }
        else if (moduleError != 0)
        {
            result.AttachState = "loaded_unknown";
            result.AttachStrategy = "reject_unknown";
            SetResultError(result, moduleError, "win32", "loaded_agent_scan_failed", "Failed to inspect target modules for loaded agent state.");
            fatalError = true;
            break;
        }
        else
        {
            AddAudit(result, "loaded_agent_not_found", "module_snapshot", "Expected agent DLL is not loaded; first attach will use LoadLibraryW.");
        }

        if (observeCancellation("attach_before_transport"))
        {
            SetResultError(result, ERROR_CANCELLED, "knmon-core", "operation_cancelled", "Attach capture was cancelled before transport setup.");
            result.OperationState = "cancelled";
            fatalError = true;
            break;
        }

        const std::wstring pipeName = L"\\\\.\\pipe\\knmon_agent_" + Utf8ToWide(result.OperationId);
        pipeHandle = CreateNamedPipeW(
            pipeName.c_str(),
            PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            65536,
            65536,
            request.TimeoutMs,
            nullptr);

        if (pipeHandle == INVALID_HANDLE_VALUE)
        {
            SetResultError(result, GetLastError(), "win32", "CreateNamedPipeW", "Failed to create attach agent event pipe.");
            fatalError = true;
            break;
        }

        AddAudit(result, "event_pipe_created", "CreateNamedPipeW", WideToUtf8(pipeName.c_str()));

        DWORD transportError = 0;
        if (!CreateSharedTransport(transport, result.OperationId, requestedArchitecture, &transportError))
        {
            SetResultError(result, transportError, "win32", "shared_memory_transport_create", "Failed to create attach shared-memory event transport.");
            AddAudit(result, "transport_setup_failed", "shared_memory_transport_create", "Attach shared-memory event transport setup failed.", transportError, "win32");
            fatalError = true;
            break;
        }

        UpdateTransportMetrics(result, transport);
        AddAudit(result, "attach_transport_created", "CreateFileMappingW", "Attach shared-memory event transport created.");

        const std::uint64_t remotePathSize = static_cast<std::uint64_t>((agentPath.size() + 1) * sizeof(wchar_t));
        if (!useLoadedAgent)
        {
            remoteDllPath = VirtualAllocEx(processHandle, nullptr, static_cast<SIZE_T>(remotePathSize), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (remoteDllPath == nullptr)
            {
                SetResultError(result, GetLastError(), "win32", "remote_allocation_failed", "Failed to allocate remote agent path buffer.");
                fatalError = true;
                break;
            }

            AddAudit(result, "remote_agent_path_allocated", "VirtualAllocEx", "Remote agent path buffer allocated.");

            SIZE_T bytesWritten = 0;
            if (!WriteProcessMemory(processHandle, remoteDllPath, agentPath.c_str(), static_cast<SIZE_T>(remotePathSize), &bytesWritten))
            {
                SetResultError(result, GetLastError(), "win32", "remote_write_failed", "Failed to write agent path into target process.");
                fatalError = true;
                break;
            }

            AddAudit(result, "remote_agent_path_written", "WriteProcessMemory", "Agent DLL path written into target process.");
        }

        KnMonAttachConfigV1 attachConfig;
        attachConfig.StructSize = static_cast<std::uint16_t>(sizeof(attachConfig));
        if (
            !CopyWideBounded(attachConfig.OperationId, std::size(attachConfig.OperationId), Utf8ToWide(result.OperationId)) ||
            !CopyWideBounded(attachConfig.PipeName, std::size(attachConfig.PipeName), pipeName) ||
            !CopyWideBounded(attachConfig.TransportName, std::size(attachConfig.TransportName), transport.MappingName))
        {
            SetResultError(result, ERROR_INVALID_PARAMETER, "knmon-core", "remote_initialize_failed", "Attach config strings exceed fixed ABI buffers.");
            fatalError = true;
            break;
        }

        remoteConfig = VirtualAllocEx(processHandle, nullptr, sizeof(attachConfig), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (remoteConfig == nullptr)
        {
            SetResultError(result, GetLastError(), "win32", "remote_allocation_failed", "Failed to allocate remote attach config buffer.");
            fatalError = true;
            break;
        }

        AddAudit(result, "remote_config_allocated", "VirtualAllocEx", "Remote attach config buffer allocated.");

        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(processHandle, remoteConfig, &attachConfig, sizeof(attachConfig), &bytesWritten))
        {
            SetResultError(result, GetLastError(), "win32", "remote_write_failed", "Failed to write attach config into target process.");
            fatalError = true;
            break;
        }

        AddAudit(result, "remote_config_written", "WriteProcessMemory", "Attach config written into target process.");

        DWORD remoteExitCode = 0;
        DWORD remoteError = 0;
        if (observeCancellation("attach_before_remote_load"))
        {
            SetResultError(result, ERROR_CANCELLED, "knmon-core", "operation_cancelled", "Attach capture was cancelled before remote agent load.");
            result.OperationState = "cancelled";
            fatalError = true;
            break;
        }

        if (!useLoadedAgent)
        {
            std::uintptr_t remoteKernel32Base = 0;
            moduleError = 0;
            if (!FindRemoteModuleBase(request.ProcessId, L"kernel32.dll", &remoteKernel32Base, &moduleError))
            {
                SetResultError(result, moduleError == 0 ? ERROR_MOD_NOT_FOUND : moduleError, "win32", "remote_loadlibrary_failed", "Failed to find remote kernel32.dll module base.");
                fatalError = true;
                break;
            }

            HMODULE localKernel32 = GetModuleHandleW(L"kernel32.dll");
            std::uintptr_t loadLibraryRva = 0;
            if (!ResolveLoadedModuleExportRva(localKernel32, "LoadLibraryW", &loadLibraryRva))
            {
                SetResultError(result, GetLastError(), "win32", "remote_loadlibrary_failed", "Failed to resolve local LoadLibraryW RVA.");
                fatalError = true;
                break;
            }

            void* remoteLoadLibrary = reinterpret_cast<void*>(remoteKernel32Base + loadLibraryRva);
            AddAudit(result, "remote_loadlibrary_started", "CreateRemoteThread", "Remote LoadLibraryW thread starting.");
            if (!WaitRemoteThread(processHandle, remoteLoadLibrary, remoteDllPath, request.TimeoutMs, &remoteExitCode, &remoteError))
            {
                SetResultError(result, remoteError, "win32", "remote_loadlibrary_failed", "Remote LoadLibraryW thread failed or timed out.");
                fatalError = true;
                break;
            }

            AddAudit(result, "remote_loadlibrary_completed", "CreateRemoteThread", "Remote LoadLibraryW thread completed.");

            for (int attempt = 0; attempt < 20 && remoteAgentBase == 0; ++attempt)
            {
                if (FindRemoteModuleBase(request.ProcessId, agentModuleName, &remoteAgentBase, &moduleError))
                {
                    break;
                }

                Sleep(50);
            }

            if (remoteAgentBase == 0)
            {
                SetResultError(result, moduleError == 0 ? ERROR_MOD_NOT_FOUND : moduleError, "win32", "remote_loadlibrary_failed", "Agent module was not visible in the target after LoadLibraryW.");
                fatalError = true;
                break;
            }

            result.AttachState = "not_loaded";
            result.AttachStrategy = "load_library_initialize";
            AddAudit(result, "attach_strategy_selected", "load_library_initialize", "Agent was loaded with remote LoadLibraryW before initialization.");
        }
        else if (remoteAgentBase == 0)
        {
            result.AttachState = "loaded_unknown";
            result.AttachStrategy = "reject_unknown";
            SetResultError(result, ERROR_MOD_NOT_FOUND, "win32", "loaded_agent_missing_base", "Loaded-agent reattach selected without a remote module base.");
            fatalError = true;
            break;
        }

        if (observeCancellation("attach_before_initialize"))
        {
            AddAudit(result, "operation_cancel_deferred", "attach_before_initialize", "Cancellation was observed after agent DLL load; initialization will continue so self-disable cleanup can run.");
        }

        std::uintptr_t initializeRva = 0;
        if (!ResolveImageExportRva(agentPath, "KnMonAgentInitialize", &initializeRva, &remoteError))
        {
            SetResultError(result, remoteError == 0 ? ERROR_PROC_NOT_FOUND : remoteError, "win32", "remote_export_missing", "Failed to resolve KnMonAgentInitialize export RVA.");
            fatalError = true;
            break;
        }

        std::uintptr_t stopRva = 0;
        if (!ResolveImageExportRva(agentPath, "KnMonAgentStop", &stopRva, &remoteError))
        {
            SetResultError(result, remoteError == 0 ? ERROR_PROC_NOT_FOUND : remoteError, "win32", "remote_export_missing", "Failed to resolve KnMonAgentStop export RVA.");
            fatalError = true;
            break;
        }

        void* remoteInitialize = reinterpret_cast<void*>(remoteAgentBase + initializeRva);
        remoteStopAddress = remoteAgentBase + stopRva;

        AddAudit(result, "remote_agent_initialize_started", "CreateRemoteThread", "Remote KnMonAgentInitialize thread starting.");
        if (!WaitRemoteThread(processHandle, remoteInitialize, remoteConfig, request.TimeoutMs, &remoteExitCode, &remoteError))
        {
            SetResultError(result, remoteError, "win32", "remote_initialize_failed", "Remote KnMonAgentInitialize thread failed or timed out.");
            fatalError = true;
            break;
        }

        result.AgentControlStatus = remoteExitCode;
        if (remoteExitCode != static_cast<DWORD>(KnMonAgentControlStatus::Success))
        {
            std::ostringstream stream;
            stream << "KnMonAgentInitialize returned " << AgentControlStatusName(remoteExitCode) << " (" << remoteExitCode << ").";
            SetResultError(result, remoteExitCode, "knmon-agent", "remote_initialize_failed", stream.str());
            fatalError = true;
            break;
        }

        agentInitialized = true;
        AddAudit(result, "remote_agent_initialize_completed", "CreateRemoteThread", "Remote KnMonAgentInitialize completed.");
        (void)observeCancellation("attach_after_initialize");

        DWORD pipeError = 0;
        if (!WaitForPipeConnection(pipeHandle, request.TimeoutMs, &pipeError))
        {
            if (WaitForSingleObject(processHandle, 0) == WAIT_OBJECT_0)
            {
                DWORD exitCode = 0;
                GetExitCodeProcess(processHandle, &exitCode);
                std::ostringstream stream;
                stream << "Target exited before attach agent event pipe connection. exitCode=" << exitCode;
                SetResultError(result, exitCode == 0 ? ERROR_PROCESS_ABORTED : exitCode, "win32", "target_exited_early", stream.str());
            }
            else
            {
                SetResultError(result, pipeError, "win32", "handshake_timeout", "Attach agent event pipe connection timed out or failed.");
            }

            fatalError = true;
            break;
        }

        AddAudit(result, "agent_pipe_connected", "agent_pipe_connect", "Attach agent event pipe connected.");
        AddAudit(result, "attach_capture_started", "attach_capture", "Bounded attach capture started.");

        const ULONGLONG captureDeadline = GetTickCount64() + static_cast<ULONGLONG>(request.DurationMs);
        while (GetTickCount64() < captureDeadline)
        {
            if (observeCancellation("attach_capture"))
            {
                break;
            }

            DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);

            std::string payload;
            pipeError = 0;
            if (ReadPipeMessage(pipeHandle, 100, &payload, &pipeError))
            {
                consumePayload(payload);
                DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);
                continue;
            }

            DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);
            if (pipeError == ERROR_BROKEN_PIPE || pipeError == ERROR_HANDLE_EOF || pipeError == ERROR_NO_DATA)
            {
                AddAudit(result, "pipe_closed_without_shutdown", "agent_event_read", "Attach agent event pipe closed before explicit stop.", pipeError, "win32");
                break;
            }

            if (pipeError != WAIT_TIMEOUT)
            {
                SetResultError(result, pipeError, "win32", "agent_event_read", "Attach agent event stream read failed.");
                fatalError = true;
                break;
            }

            if (WaitForSingleObject(processHandle, 0) == WAIT_OBJECT_0)
            {
                AddAudit(result, "target_exited_early", "attach_capture", "Target exited before attach duration elapsed.");
                break;
            }
        }

        if (fatalError)
        {
            break;
        }

        DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);
        UpdateTransportMetrics(result, transport);
        if (result.CancelObserved)
        {
            AddAudit(result, "attach_capture_cancelled", "attach_capture", "Bounded attach capture cancellation observed; requesting self-disable cleanup.");
            result.OperationState = "stopping_agent";
            result.SessionState = result.SessionId.empty() ? result.SessionState : "stopping_agent";
        }
        else
        {
            AddAudit(result, "attach_capture_completed", "attach_capture", "Bounded attach capture window completed.");
            result.OperationState = "stopping_agent";
            result.SessionState = result.SessionId.empty() ? result.SessionState : "stopping_agent";
        }

        EmitCaptureStreamSessionFrame(streamCallbacks, "session_stopping", result);

        if (remoteStopAddress == 0)
        {
            SetResultError(result, ERROR_PROC_NOT_FOUND, "win32", "remote_export_missing", "Remote stop export address is missing.");
            fatalError = true;
            break;
        }

        AddAudit(result, "agent_stop_requested", "CreateRemoteThread", "Requesting attach agent self-disable.");
        stopRequested = true;
        if (!WaitRemoteThread(processHandle, reinterpret_cast<void*>(remoteStopAddress), nullptr, request.TimeoutMs, &remoteExitCode, &remoteError))
        {
            SetResultError(result, remoteError, "win32", "agent_stop_timeout", "Remote KnMonAgentStop thread failed or timed out.");
            fatalError = true;
            break;
        }

        if (remoteExitCode != static_cast<DWORD>(KnMonAgentControlStatus::Success))
        {
            std::ostringstream stream;
            stream << "KnMonAgentStop returned status " << remoteExitCode << ".";
            SetResultError(result, remoteExitCode, "knmon-agent", "detach_incomplete", stream.str());
            fatalError = true;
            break;
        }

        const ULONGLONG shutdownDeadline = GetTickCount64() + static_cast<ULONGLONG>(request.TimeoutMs);
        result.OperationState = result.CancelObserved ? "draining" : result.OperationState;
        while (!agentShutdownReceived && GetTickCount64() < shutdownDeadline)
        {
            DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);

            std::string payload;
            pipeError = 0;
            if (ReadPipeMessage(pipeHandle, 100, &payload, &pipeError))
            {
                consumePayload(payload);
                DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);
                continue;
            }

            DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);
            if (pipeError == ERROR_BROKEN_PIPE || pipeError == ERROR_HANDLE_EOF || pipeError == ERROR_NO_DATA)
            {
                AddAudit(result, agentShutdownReceived ? "pipe_closed_after_shutdown" : "pipe_closed_without_shutdown", "agent_event_read", "Attach agent event pipe closed.", pipeError, "win32");
                break;
            }

            if (pipeError != WAIT_TIMEOUT)
            {
                SetResultError(result, pipeError, "win32", "agent_event_read", "Attach agent shutdown read failed.");
                fatalError = true;
                break;
            }
        }

        DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);
        UpdateTransportMetrics(result, transport);

        if (fatalError)
        {
            break;
        }

        if (result.CancelObserved)
        {
            result.AgentCleanupAttempted = true;
            result.AgentCleanupSucceeded = agentShutdownReceived && shutdownRestoredHooks >= shutdownInstalledHooks && shutdownFailedHooks == 0;
            if (!result.AgentCleanupSucceeded)
            {
                result.OperationState = "cleanup_failed";
                SetResultError(result, ERROR_CANCELLED, "knmon-core", "cleanup_failed", "Attach capture cancellation cleanup did not prove self-disable.");
                fatalError = true;
                break;
            }

            result.Success = false;
            result.Win32ErrorCode = ERROR_CANCELLED;
            result.NtStatus = "0x00000000";
            result.Subsystem = "knmon-core";
            result.Operation = "operation_cancelled";
            result.OperationState = "cancelled";
            result.SessionState = result.SessionId.empty() ? result.SessionState : "stopped";
            result.StoppedUtc = NowUtc();
            result.Message = "Attach capture cancelled after agent self-disable cleanup.";
            break;
        }

        if (!result.Handshake.Received)
        {
            SetResultError(result, WAIT_TIMEOUT, "knmon-core", "agent_hello_required", "Attach agent HELLO was not received.");
            fatalError = true;
            break;
        }

        if (!ValidateHandshakeEvidence(result, requestedArchitecture))
        {
            fatalError = true;
            break;
        }

        if (hookInstalledCount < ExpectedFileIoHookCount)
        {
            SetResultError(result, ERROR_HOOK_NOT_INSTALLED, "knmon-core", "hook_install_count_required", "Attach did not report the required stable File I/O hooks.");
            fatalError = true;
            break;
        }

        if (result.CapturedEvents.empty())
        {
            SetResultError(result, ERROR_NO_DATA, "knmon-core", "api_call_required", "Attach capture did not receive API events.");
            fatalError = true;
            break;
        }

        if (!agentShutdownReceived)
        {
            SetResultError(result, WAIT_TIMEOUT, "knmon-core", "agent_shutdown_required", "Attach agent shutdown lifecycle event was not received.");
            fatalError = true;
            break;
        }

        if (shutdownRestoredHooks < shutdownInstalledHooks || shutdownFailedHooks != 0)
        {
            SetResultError(result, ERROR_HOOK_NOT_INSTALLED, "knmon-core", "hook_uninstall_required", "Attach self-disable did not restore all installed hooks.");
            fatalError = true;
            break;
        }

        if (shutdownReason != "self_disable")
        {
            AddAudit(result, "detach_policy_note", "agent_shutdown", "Attach shutdown reason was " + shutdownReason + ".");
        }

        result.Success = true;
        result.Win32ErrorCode = 0;
        result.Subsystem = "knmon-core";
        result.Operation = "attach_capture";
        result.OperationState = "completed";
        result.SessionState = result.SessionId.empty() ? result.SessionState : "stopped";
        result.StoppedUtc = NowUtc();
        result.Message = "Controlled running-process attach capture completed with self-disable detach evidence.";
    }
    while (false);

    if (agentInitialized && !stopRequested && !agentShutdownReceived && processHandle != nullptr && remoteStopAddress != 0)
    {
        DWORD stopExitCode = 0;
        DWORD stopError = 0;
        result.AgentCleanupAttempted = true;
        AddAudit(result, "agent_stop_requested", "CreateRemoteThread", "Requesting attach agent self-disable during cleanup.");
        if (!WaitRemoteThread(processHandle, reinterpret_cast<void*>(remoteStopAddress), nullptr, request.TimeoutMs, &stopExitCode, &stopError))
        {
            AddAudit(result, "agent_stop_timeout", "CreateRemoteThread", "Cleanup stop request failed or timed out.", stopError, "win32");
        }
        else
        {
            if (stopExitCode == static_cast<DWORD>(KnMonAgentControlStatus::Success))
            {
                result.AgentCleanupSucceeded = true;
            }
        }
    }

    if (remoteConfig != nullptr && processHandle != nullptr)
    {
        if (VirtualFreeEx(processHandle, remoteConfig, 0, MEM_RELEASE))
        {
            AddAudit(result, "remote_buffer_released", "VirtualFreeEx", "Remote attach config buffer released.");
        }
        else
        {
            AddAudit(result, "cleanup_partial_failure", "VirtualFreeEx", "Remote attach config buffer cleanup failed.", GetLastError(), "win32");
        }
    }

    if (remoteDllPath != nullptr && processHandle != nullptr)
    {
        if (VirtualFreeEx(processHandle, remoteDllPath, 0, MEM_RELEASE))
        {
            AddAudit(result, "remote_buffer_released", "VirtualFreeEx", "Remote agent path buffer released.");
        }
        else
        {
            AddAudit(result, "cleanup_partial_failure", "VirtualFreeEx", "Remote agent path buffer cleanup failed.", GetLastError(), "win32");
        }
    }

    if (pipeHandle != INVALID_HANDLE_VALUE)
    {
        DisconnectNamedPipe(pipeHandle);
        CloseHandle(pipeHandle);
    }

    DrainSharedTransport(result, transport, streamCallbacks, &streamBatchSequence);
    UpdateTransportMetrics(result, transport);
    CloseSharedTransport(transport);

    if (processHandle != nullptr)
    {
        CloseHandle(processHandle);
    }

    CloseCancellationContext(cancellationContext);
    AddAudit(result, "attach_cleanup_completed", "handle_cleanup", "Attach controller cleanup completed.");

    if (result.Operation.empty())
    {
        result.Operation = fatalError ? "attach_capture_failed" : "attach_capture";
    }

    if (result.Message.empty())
    {
        result.Message = fatalError ? "Controlled running-process attach capture failed." : "Controlled running-process attach capture finished.";
    }

    if (result.OperationState.empty() || (result.OperationState == "running" && !result.Success))
    {
        result.OperationState = fatalError ? "failed" : "completed";
    }

    if (!result.SessionId.empty())
    {
        result.UpdatedUtc = NowUtc();
        if (result.SessionState.empty() || result.SessionState == "running")
        {
            result.SessionState = result.Success ? "stopped" : "failed";
        }

        if (result.StoppedUtc.empty() && (result.SessionState == "stopped" || result.SessionState == "failed"))
        {
            result.StoppedUtc = result.UpdatedUtc;
        }
    }

    return result;
}

KnMonProcessTreeResult Controller::SuperviseProcessTree(const KnMonProcessTreeRequest& request) const
{
    KnMonProcessTreeResult result;
    result.OperationId = request.OperationId.empty() ? "manual-operation" : request.OperationId;
    result.SessionId = request.SessionId;
    result.SessionState = request.SessionId.empty() ? "" : "running";
    result.SessionKind = request.SessionKind.empty() ? "process_tree_supervision" : request.SessionKind;
    result.OwnerProcessId = request.OwnerProcessId;
    result.HelperProcessId = request.HelperProcessId;
    result.StartedUtc = request.StartedUtc;
    result.UpdatedUtc = NowUtc();
    result.CancellationEventName = request.CancellationEventName;
    result.RootProcessId = request.RootProcessId;
    result.DurationMs = request.DurationMs == 0 ? 3000 : request.DurationMs;
    result.ChildPolicy = ChildPolicyName(request.ChildPolicy);
    result.NtStatus = "0x00000000";
    result.OperationState = "running";

    bool fatalError = false;
    bool cancellationLogged = false;
    std::vector<DWORD> evaluatedChildren;
    const KnMonAgentArchitecture requestedArchitecture = RequestedArchitectureOrNative(request.Architecture);
    const DWORD pollIntervalMs = request.PollIntervalMs < 10 ? 10 : request.PollIntervalMs;
    CancellationContext cancellationContext;

    auto observeCancellation = [&](const std::string& stage) -> bool
    {
        bool observed = false;

        if (IsCancellationRequested(cancellationContext))
        {
            result.CancelRequested = true;
            result.CancelObserved = true;
            result.CancelStage = stage;
            result.OperationState = "cancel_requested";

            if (!cancellationLogged)
            {
                AddAudit(result, "operation_cancel_requested", stage, "Cancellation was requested for this process-tree supervision operation.");
                cancellationLogged = true;
            }

            observed = true;
        }

        return observed;
    };

    auto hasEvaluatedChild = [&evaluatedChildren](DWORD processId) -> bool
    {
        bool found = false;

        for (const DWORD evaluatedProcessId : evaluatedChildren)
        {
            if (evaluatedProcessId == processId)
            {
                found = true;
                break;
            }
        }

        return found;
    };

    auto markExitedNodes = [&result](const std::vector<ProcessSnapshotInfo>& snapshot, const std::string& timestamp)
    {
        for (auto& node : result.ProcessNodes)
        {
            if (node.IsAlive && FindSnapshotProcess(snapshot, node.ProcessId) == nullptr)
            {
                node.IsAlive = false;
                node.Exited = true;
                node.LastSeenUtc = timestamp;
                if (!node.IsRoot)
                {
                    AddAudit(result, "child_process_exited", "process_snapshot", "Child pid " + std::to_string(node.ProcessId) + " is no longer present in the process snapshot.");
                }
            }
        }
    };

    auto addNode = [&result](const ProcessSnapshotInfo& process, bool isRoot, const std::string& timestamp) -> KnMonProcessTreeNode*
    {
        KnMonProcessTreeNode node;
        node.ProcessId = process.ProcessId;
        node.ParentProcessId = process.ParentProcessId;
        node.IsRoot = isRoot;
        node.ImageName = process.ImageName;
        node.ImagePath = QueryProcessImagePath(process.ProcessId);
        node.Architecture = QueryProcessArchitecture(process.ProcessId);
        node.FirstSeenUtc = timestamp;
        node.LastSeenUtc = timestamp;
        node.IsAlive = true;
        node.Exited = false;
        node.EligibilityStatus = isRoot ? ProcessEligibilityName(KnMonProcessEligibility::Eligible) : ProcessEligibilityName(KnMonProcessEligibility::Unsupported);
        node.PolicyDecision = isRoot ? ProcessPolicyDecisionName(KnMonProcessPolicyDecision::ObserveOnly) : ProcessPolicyDecisionName(KnMonProcessPolicyDecision::AttachSkipped);
        node.Message = isRoot ? "Root process validated for bounded supervision." : "Child process discovered and pending policy evaluation.";
        result.ProcessNodes.push_back(node);
        return &result.ProcessNodes.back();
    };

    auto evaluateAndMaybeAttach = [this, &result, &request, &evaluatedChildren, &observeCancellation](KnMonProcessTreeNode& node)
    {
        KnMonChildPolicyDecision decision = EvaluateChildPolicy(result, node, request);

        if (observeCancellation("process_tree_before_child_attach"))
        {
            decision.Decision = ProcessPolicyDecisionName(KnMonProcessPolicyDecision::AttachSkipped);
            decision.Reason = "Child attach skipped because cancellation was requested.";
            node.PolicyDecision = decision.Decision;
            node.Message = decision.Reason;
        }
        else
        {
            if (request.ChildPolicy == KnMonChildPolicy::AttachSupported && decision.Decision == ProcessPolicyDecisionName(KnMonProcessPolicyDecision::AttachAllowed))
            {
                decision.MutationAttempted = true;
                AddAudit(result, "child_attach_started", "attach_capture", "Starting Phase 11A attach for child pid " + std::to_string(node.ProcessId) + ".");

                KnMonAttachRequest attachRequest;
                attachRequest.OperationId = result.OperationId + "-child-" + std::to_string(node.ProcessId);
                attachRequest.ProcessId = node.ProcessId;
                attachRequest.AgentPath = request.AgentPath;
                attachRequest.TimeoutMs = request.TimeoutMs;
                attachRequest.DurationMs = request.DurationMs < 1500 ? request.DurationMs : 1500;
                attachRequest.Architecture = request.Architecture;
                attachRequest.InjectionMethod = KnMonInjectionMethod::RemoteLoadLibrary;
                attachRequest.CancellationEventName = request.CancellationEventName;

                KnMonCaptureResult attachResult = AttachCapture(attachRequest);
                if (attachResult.CancelObserved)
                {
                    result.CancelRequested = true;
                    result.CancelObserved = true;
                    result.CancelStage = "process_tree_child_attach";
                    result.OperationState = "cancel_requested";
                }

                decision.AttachSucceeded = attachResult.Success;
                if (attachResult.Success)
                {
                    decision.Reason = "Child attach completed through Phase 11A self-disable path.";
                    AddAudit(result, "child_attach_completed", "attach_capture", "Child pid " + std::to_string(node.ProcessId) + " attach completed.");
                }
                else
                {
                    decision.Decision = ProcessPolicyDecisionName(KnMonProcessPolicyDecision::AttachFailed);
                    decision.Reason = "Child attach failed: " + attachResult.Operation + ": " + attachResult.Message;
                    AddAudit(result, "child_attach_failed", "attach_capture", decision.Reason, attachResult.Win32ErrorCode);
                    AddAudit(result, "child_attach_completed", "attach_capture", "Child pid " + std::to_string(node.ProcessId) + " attach completed with failure.", attachResult.Win32ErrorCode);
                }

                node.PolicyDecision = decision.Decision;
                node.Message = decision.Reason;
                result.ChildAttachResults.push_back(attachResult);
            }
        }

        result.PolicyDecisions.push_back(decision);
        evaluatedChildren.push_back(node.ProcessId);
    };

    do
    {
        DWORD cancellationError = 0;
        if (!OpenCancellationContext(request.CancellationEventName, &cancellationContext, &cancellationError))
        {
            SetResultError(result, cancellationError == 0 ? ERROR_INVALID_PARAMETER : cancellationError, "win32", "operation_cancellation_setup", "Failed to create process-tree cancellation event.");
            fatalError = true;
            break;
        }

        if (!request.CancellationEventName.empty())
        {
            AddAudit(result, "operation_cancellation_ready", "CreateEventW", "Process-tree cancellation event is ready.");
        }

        AddAudit(result, "process_tree_supervision_started", "supervise_tree", "Starting bounded process-tree supervision.");

        if (observeCancellation("process_tree_preflight"))
        {
            SetResultError(result, ERROR_CANCELLED, "knmon-core", "operation_cancelled", "Process-tree supervision was cancelled before mutation.");
            result.OperationState = "cancelled";
            fatalError = true;
            break;
        }

        if (request.RootProcessId == 0 || request.RootProcessId == 4)
        {
            SetResultError(result, ERROR_NOT_SUPPORTED, "knmon-core", "missing_root_process", "System idle and system process PIDs are not supported supervision roots.");
            fatalError = true;
            break;
        }

        if (request.RootProcessId == GetCurrentProcessId())
        {
            SetResultError(result, ERROR_NOT_SUPPORTED, "knmon-core", "missing_root_process", "The helper process cannot supervise itself as root.");
            fatalError = true;
            break;
        }

        if (requestedArchitecture == KnMonAgentArchitecture::Unknown)
        {
            SetResultError(result, ERROR_NOT_SUPPORTED, "knmon-core", "unsupported_architecture", "Requested or helper architecture is unknown.");
            fatalError = true;
            break;
        }

        std::vector<ProcessSnapshotInfo> snapshot;
        DWORD snapshotError = 0;
        if (!CollectProcessSnapshot(&snapshot, &snapshotError))
        {
            SetResultError(result, snapshotError == 0 ? ERROR_GEN_FAILURE : snapshotError, "win32", "snapshot_failed", "Failed to take initial process snapshot.");
            fatalError = true;
            break;
        }

        AddAudit(result, "process_snapshot_taken", "CreateToolhelp32Snapshot", "Initial process snapshot captured.");

        const ProcessSnapshotInfo* rootSnapshot = FindSnapshotProcess(snapshot, request.RootProcessId);
        if (rootSnapshot == nullptr)
        {
            SetResultError(result, ERROR_INVALID_PARAMETER, "knmon-core", "missing_root_process", "Root process was not found in the process snapshot.");
            fatalError = true;
            break;
        }

        HANDLE rootHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, request.RootProcessId);
        if (rootHandle == nullptr)
        {
            const DWORD errorCode = GetLastError();
            SetResultError(result, errorCode, "win32", errorCode == ERROR_ACCESS_DENIED ? "access_denied" : "missing_root_process", "Failed to open root process for query: " + FormatWindowsError(errorCode));
            fatalError = true;
            break;
        }

        ProcessArchitectureResult rootArchitecture = QueryProcessArchitectureFromHandle(rootHandle);
        CloseHandle(rootHandle);
        rootHandle = nullptr;

        if (!rootArchitecture.Success)
        {
            SetResultError(result, rootArchitecture.ErrorCode, "knmon-core", rootArchitecture.Operation, rootArchitecture.Message);
            fatalError = true;
            break;
        }

        if (rootArchitecture.Architecture != requestedArchitecture)
        {
            SetResultError(result, ERROR_NOT_SUPPORTED, "knmon-core", "helper_target_mismatch", "Root architecture does not match helper architecture.");
            fatalError = true;
            break;
        }

        const std::string firstSeenUtc = NowUtc();
        KnMonProcessTreeNode* rootNode = addNode(*rootSnapshot, true, firstSeenUtc);
        if (rootNode != nullptr)
        {
            rootNode->Architecture = ArchitectureName(rootArchitecture.Architecture);
        }

        AddAudit(result, "root_process_validated", "supervise_tree", "Root process validated for bounded process-tree supervision.");

        const ULONGLONG startTick = GetTickCount64();
        while (GetTickCount64() - startTick < result.DurationMs)
        {
            if (observeCancellation("process_tree_poll"))
            {
                break;
            }

            std::vector<ProcessSnapshotInfo> currentSnapshot;
            DWORD currentSnapshotError = 0;
            if (!CollectProcessSnapshot(&currentSnapshot, &currentSnapshotError))
            {
                SetResultError(result, currentSnapshotError == 0 ? ERROR_GEN_FAILURE : currentSnapshotError, "win32", "snapshot_failed", "Failed to take process supervision snapshot.");
                fatalError = true;
                break;
            }

            AddAudit(result, "process_snapshot_taken", "CreateToolhelp32Snapshot", "Process supervision snapshot captured.");

            const std::string snapshotTime = NowUtc();
            if (FindSnapshotProcess(currentSnapshot, request.RootProcessId) == nullptr)
            {
                markExitedNodes(currentSnapshot, snapshotTime);
                SetResultError(result, ERROR_PROCESS_ABORTED, "knmon-core", "root_exited_early", "Root process exited before supervision duration elapsed.");
                fatalError = true;
                break;
            }

            bool addedNode = true;
            while (addedNode)
            {
                addedNode = false;
                for (const auto& process : currentSnapshot)
                {
                    if (process.ProcessId == request.RootProcessId || ProcessTreeHasNode(result.ProcessNodes, process.ProcessId))
                    {
                        continue;
                    }

                    if (!ProcessTreeHasNode(result.ProcessNodes, process.ParentProcessId))
                    {
                        continue;
                    }

                    if (observeCancellation("process_tree_before_child_discovery"))
                    {
                        addedNode = false;
                        break;
                    }

                    KnMonProcessTreeNode* childNode = addNode(process, false, snapshotTime);
                    if (childNode != nullptr)
                    {
                        AddAudit(result, "child_process_discovered", "process_snapshot", "Discovered child pid " + std::to_string(childNode->ProcessId) + " parent=" + std::to_string(childNode->ParentProcessId) + ".");
                        if (!hasEvaluatedChild(childNode->ProcessId))
                        {
                            evaluateAndMaybeAttach(*childNode);
                        }
                    }

                    addedNode = true;
                }
            }

            for (auto& node : result.ProcessNodes)
            {
                const ProcessSnapshotInfo* process = FindSnapshotProcess(currentSnapshot, node.ProcessId);
                if (process != nullptr)
                {
                    node.IsAlive = true;
                    node.LastSeenUtc = snapshotTime;
                    if (node.ImagePath.empty())
                    {
                        node.ImagePath = QueryProcessImagePath(node.ProcessId);
                    }
                }
            }

            markExitedNodes(currentSnapshot, snapshotTime);

            const ULONGLONG elapsed = GetTickCount64() - startTick;
            if (elapsed >= result.DurationMs)
            {
                break;
            }

            const DWORD remaining = static_cast<DWORD>(result.DurationMs - elapsed);
            const DWORD sleepMs = remaining < pollIntervalMs ? remaining : pollIntervalMs;
            if (cancellationContext.EventHandle != nullptr)
            {
                const DWORD waitResult = WaitForSingleObject(cancellationContext.EventHandle, sleepMs);
                if (waitResult == WAIT_OBJECT_0)
                {
                    (void)observeCancellation("process_tree_sleep");
                }
            }
            else
            {
                Sleep(sleepMs);
            }
        }

        if (fatalError)
        {
            break;
        }

        if (result.CancelObserved)
        {
            result.Success = false;
            result.Win32ErrorCode = ERROR_CANCELLED;
            result.NtStatus = "0x00000000";
            result.Subsystem = "knmon-core";
            result.Operation = "operation_cancelled";
            result.OperationState = "cancelled";
            result.SessionState = result.SessionId.empty() ? result.SessionState : "stopped";
            result.StoppedUtc = NowUtc();
            result.Message = "Process-tree supervision cancelled before the bounded window completed.";
            break;
        }

        std::vector<ProcessSnapshotInfo> finalSnapshot;
        DWORD finalSnapshotError = 0;
        if (CollectProcessSnapshot(&finalSnapshot, &finalSnapshotError))
        {
            markExitedNodes(finalSnapshot, NowUtc());
        }

        std::size_t childCount = 0;
        for (const auto& node : result.ProcessNodes)
        {
            if (!node.IsRoot)
            {
                childCount += 1;
            }
        }

        if (childCount == 0)
        {
            SetResultError(result, ERROR_NOT_FOUND, "knmon-core", "child_policy_failed", "No child process was discovered under the requested root.");
            fatalError = true;
            break;
        }

        result.Success = true;
        result.Win32ErrorCode = 0;
        result.Subsystem = "knmon-core";
        result.Operation = "supervise_tree";
        result.OperationState = "completed";
        result.SessionState = result.SessionId.empty() ? result.SessionState : "stopped";
        result.StoppedUtc = NowUtc();
        result.Message = "Process-tree supervision completed.";
        AddAudit(result, "process_tree_supervision_completed", "supervise_tree", "Process-tree supervision completed.");
    }
    while (false);

    CloseCancellationContext(cancellationContext);

    if (result.CancelObserved && result.Operation == "operation_cancelled")
    {
        AddAudit(result, "process_tree_supervision_cancelled", "operation_cancelled", result.Message, result.Win32ErrorCode, "knmon-core");
    }
    else
    {
        if (!result.Success)
        {
            AddAudit(result, "process_tree_supervision_failed", result.Operation.empty() ? "supervise_tree" : result.Operation, result.Message.empty() ? "Process-tree supervision failed." : result.Message, result.Win32ErrorCode, result.Subsystem.empty() ? "knmon-core" : result.Subsystem);
        }
    }

    if (result.Message.empty())
    {
        result.Message = fatalError ? "Process-tree supervision failed." : "Process-tree supervision finished.";
    }

    if (result.OperationState.empty() || (result.OperationState == "running" && !result.Success))
    {
        result.OperationState = fatalError ? "failed" : "completed";
    }

    if (!result.SessionId.empty())
    {
        result.UpdatedUtc = NowUtc();
        if (result.SessionState.empty() || result.SessionState == "running")
        {
            result.SessionState = result.Success ? "stopped" : "failed";
        }

        if (result.StoppedUtc.empty() && (result.SessionState == "stopped" || result.SessionState == "failed"))
        {
            result.StoppedUtc = result.UpdatedUtc;
        }
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
