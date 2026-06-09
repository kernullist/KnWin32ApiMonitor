#include <knmon/core/Controller.h>

#include <Windows.h>
#include <TlHelp32.h>

#include <array>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
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

void AddAudit(
    KnMonCaptureResult& result,
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

std::string HexNtStatusValue(std::uint32_t value)
{
    return HexFixed(value, 8);
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

std::string TransportApiName(std::uint16_t apiId)
{
    std::string result = "Unknown";

    switch (static_cast<KnMonTransportApiId>(apiId))
    {
    case KnMonTransportApiId::CreateFileW:
        result = "CreateFileW";
        break;
    case KnMonTransportApiId::CreateFileA:
        result = "CreateFileA";
        break;
    case KnMonTransportApiId::NtCreateFile:
        result = "NtCreateFile";
        break;
    case KnMonTransportApiId::ReadFile:
        result = "ReadFile";
        break;
    case KnMonTransportApiId::WriteFile:
        result = "WriteFile";
        break;
    case KnMonTransportApiId::CloseHandle:
        result = "CloseHandle";
        break;
    case KnMonTransportApiId::LoadLibraryW:
        result = "LoadLibraryW";
        break;
    case KnMonTransportApiId::LoadLibraryA:
        result = "LoadLibraryA";
        break;
    case KnMonTransportApiId::LoadLibraryExW:
        result = "LoadLibraryExW";
        break;
    case KnMonTransportApiId::LoadLibraryExA:
        result = "LoadLibraryExA";
        break;
    case KnMonTransportApiId::LdrLoadDll:
        result = "LdrLoadDll";
        break;
    case KnMonTransportApiId::GetProcAddress:
        result = "GetProcAddress";
        break;
    case KnMonTransportApiId::LdrGetProcedureAddress:
        result = "LdrGetProcedureAddress";
        break;
    default:
        break;
    }

    return result;
}

std::string TransportModuleName(std::uint16_t moduleId)
{
    std::string result = "unknown.dll";

    switch (static_cast<KnMonTransportModuleId>(moduleId))
    {
    case KnMonTransportModuleId::Kernel32:
        result = "kernel32.dll";
        break;
    case KnMonTransportModuleId::Ntdll:
        result = "ntdll.dll";
        break;
    case KnMonTransportModuleId::KernelBase:
        result = "kernelbase.dll";
        break;
    default:
        break;
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
    const std::string& decodeStatus = "decoded")
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
    stream << "}";
    return stream.str();
}

std::string ApiCallPayload(
    const KnMonCaptureResult& result,
    const KnMonTransportRecord& record,
    const std::string& returnValue,
    const std::string& argumentsJson,
    const std::string& bufferPreview,
    const std::string& categoryTag = "file",
    const std::string& detailTag = "")
{
    const std::string apiName = TransportApiName(record.ApiId);
    const std::string moduleName = TransportModuleName(record.ModuleId);
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
    stream << "\"returnValue\":" << Q(returnValue) << ",";
    stream << "\"lastErrorCode\":" << record.LastErrorCode << ",";
    stream << "\"lastErrorMessage\":" << Q(record.LastErrorCode == 0 ? "success" : FormatWindowsError(record.LastErrorCode)) << ",";
    stream << "\"durationUs\":" << record.DurationUs << ",";
    stream << "\"arguments\":[" << argumentsJson << "],";
    stream << "\"tags\":[\"native-capture\"," << Q(categoryTag);
    if (!detailTag.empty())
    {
        stream << "," << Q(detailTag);
    }
    stream << ",\"hook\",\"shared-memory\"],";
    stream << "\"stack\":[" << Q(agentName + "!IatHook") << "," << Q(moduleName + "!" + apiName) << "],";
    stream << "\"bufferPreview\":" << Q(bufferPreview);
    stream << "}";
    return stream.str();
}

std::string BuildTransportApiPayload(const KnMonCaptureResult& result, const KnMonTransportRecord& record)
{
    std::string payload;
    const std::string text0 = TransportText(record.Text0, record.Text0Length, sizeof(record.Text0));
    const std::string text1 = TransportText(record.Text1, record.Text1Length, sizeof(record.Text1));
    std::ostringstream args;

    switch (static_cast<KnMonTransportApiId>(record.ApiId))
    {
    case KnMonTransportApiId::CreateFileW:
        args << ArgumentJson(0, "LPCWSTR", "lpFileName", "in", text0, text0, text0) << ",";
        args << ArgumentJson(1, "DWORD", "dwDesiredAccess", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJson(2, "DWORD", "dwShareMode", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1])) << ",";
        args << ArgumentJson(3, "DWORD", "dwCreationDisposition", "in", HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::CreateFileA:
        args << ArgumentJson(0, "LPCSTR", "lpFileName", "in", text0, text0, text0) << ",";
        args << ArgumentJson(1, "DWORD", "dwDesiredAccess", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJson(2, "DWORD", "dwShareMode", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1])) << ",";
        args << ArgumentJson(3, "DWORD", "dwCreationDisposition", "in", HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "");
        break;
    case KnMonTransportApiId::ReadFile:
        args << ArgumentJson(0, "HANDLE", "hFile", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJson(1, "LPVOID", "lpBuffer", "out", HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture)) << ",";
        args << ArgumentJson(2, "DWORD", "nNumberOfBytesToRead", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), std::to_string(record.Values32[0])) << ",";
        args << ArgumentJson(3, "LPDWORD", "lpNumberOfBytesRead", "out", "0x00000000", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), text0);
        break;
    case KnMonTransportApiId::WriteFile:
        args << ArgumentJson(0, "HANDLE", "hFile", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJson(1, "LPCVOID", "lpBuffer", "in", HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), text0) << ",";
        args << ArgumentJson(2, "DWORD", "nNumberOfBytesToWrite", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), std::to_string(record.Values32[0])) << ",";
        args << ArgumentJson(3, "LPDWORD", "lpNumberOfBytesWritten", "out", "0x00000000", std::to_string(record.Values32[1]), std::to_string(record.Values32[1]));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), text0);
        break;
    case KnMonTransportApiId::CloseHandle:
        args << ArgumentJson(0, "HANDLE", "hObject", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture));
        payload = ApiCallPayload(result, record, record.ReturnValue == 0 ? "FALSE" : "TRUE", args.str(), "");
        break;
    case KnMonTransportApiId::NtCreateFile:
        args << ArgumentJson(0, "PHANDLE", "FileHandle", "out", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture)) << ",";
        args << ArgumentJson(1, "ACCESS_MASK", "DesiredAccess", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJson(2, "POBJECT_ATTRIBUTES", "ObjectAttributes", "in", HexPointerValue(record.Values64[2], result.Architecture), HexPointerValue(record.Values64[2], result.Architecture), text0, DecodeStatusName(record.Values32[6])) << ",";
        args << ArgumentJson(3, "PIO_STATUS_BLOCK", "IoStatusBlock", "out", HexPointerValue(record.Values64[3], result.Architecture), text1, text1, DecodeStatusName(record.Values32[7])) << ",";
        args << ArgumentJson(4, "PLARGE_INTEGER", "AllocationSize", "in", HexPointerValue(record.Values64[4], result.Architecture), HexPointerValue(record.Values64[4], result.Architecture), HexPointerValue(record.Values64[4], result.Architecture)) << ",";
        args << ArgumentJson(5, "ULONG", "FileAttributes", "in", HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1]), HexDwordValue(record.Values32[1])) << ",";
        args << ArgumentJson(6, "ULONG", "ShareAccess", "in", HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2]), HexDwordValue(record.Values32[2])) << ",";
        args << ArgumentJson(7, "ULONG", "CreateDisposition", "in", HexDwordValue(record.Values32[3]), HexDwordValue(record.Values32[3]), HexDwordValue(record.Values32[3])) << ",";
        args << ArgumentJson(8, "ULONG", "CreateOptions", "in", HexDwordValue(record.Values32[4]), HexDwordValue(record.Values32[4]), HexDwordValue(record.Values32[4])) << ",";
        args << ArgumentJson(9, "PVOID", "EaBuffer", "in", HexPointerValue(record.Values64[5], result.Architecture), HexPointerValue(record.Values64[5], result.Architecture), HexPointerValue(record.Values64[5], result.Architecture)) << ",";
        args << ArgumentJson(10, "ULONG", "EaLength", "in", std::to_string(record.Values32[5]), std::to_string(record.Values32[5]), std::to_string(record.Values32[5]));
        payload = ApiCallPayload(result, record, HexNtStatusValue(record.ReturnCode), args.str(), "");
        break;
    case KnMonTransportApiId::LoadLibraryW:
        args << ArgumentJson(0, "LPCWSTR", "lpLibFileName", "in", text0, text0, text0);
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "", "loader");
        break;
    case KnMonTransportApiId::LoadLibraryA:
        args << ArgumentJson(0, "LPCSTR", "lpLibFileName", "in", text0, text0, text0);
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "", "loader");
        break;
    case KnMonTransportApiId::LoadLibraryExW:
        args << ArgumentJson(0, "LPCWSTR", "lpLibFileName", "in", text0, text0, text0) << ",";
        args << ArgumentJson(1, "HANDLE", "hFile", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJson(2, "DWORD", "dwFlags", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "", "loader");
        break;
    case KnMonTransportApiId::LoadLibraryExA:
        args << ArgumentJson(0, "LPCSTR", "lpLibFileName", "in", text0, text0, text0) << ",";
        args << ArgumentJson(1, "HANDLE", "hFile", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJson(2, "DWORD", "dwFlags", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "", "loader");
        break;
    case KnMonTransportApiId::LdrLoadDll:
        args << ArgumentJson(0, "PWSTR", "PathToFile", "in", text0, text0, text0) << ",";
        args << ArgumentJson(1, "ULONG", "Flags", "in", HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0]), HexDwordValue(record.Values32[0])) << ",";
        args << ArgumentJson(2, "PUNICODE_STRING", "ModuleFileName", "in", text1, text1, text1, DecodeStatusName(record.Values32[1])) << ",";
        args << ArgumentJson(3, "PHANDLE", "ModuleHandle", "out", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture));
        payload = ApiCallPayload(result, record, HexNtStatusValue(record.ReturnCode), args.str(), "", "loader");
        break;
    case KnMonTransportApiId::GetProcAddress:
    {
        const bool procByOrdinal = record.Values32[0] != 0;
        const std::string procRaw = HexPointerValue(record.Values64[1], result.Architecture);
        const std::string procDecoded = procByOrdinal ? ("ordinal:" + std::to_string(record.Values32[1])) : text0;
        args << ArgumentJson(0, "HMODULE", "hModule", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJson(1, "LPCSTR", "lpProcName", "in", procRaw, procRaw, procDecoded, DecodeStatusName(record.Values32[2]));
        payload = ApiCallPayload(result, record, HexPointerValue(record.ReturnValue, result.Architecture), args.str(), "", "resolver", "dynamic_symbol_lookup");
        break;
    }
    case KnMonTransportApiId::LdrGetProcedureAddress:
        args << ArgumentJson(0, "HMODULE", "ModuleHandle", "in", HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture), HexPointerValue(record.Values64[0], result.Architecture)) << ",";
        args << ArgumentJson(1, "PANSI_STRING", "FunctionName", "in", HexPointerValue(record.Values64[1], result.Architecture), HexPointerValue(record.Values64[1], result.Architecture), text0, DecodeStatusName(record.Values32[1])) << ",";
        args << ArgumentJson(2, "WORD", "Ordinal", "in", std::to_string(record.Values32[0]), std::to_string(record.Values32[0]), std::to_string(record.Values32[0])) << ",";
        args << ArgumentJson(3, "PVOID*", "FunctionAddress", "out", HexPointerValue(record.Values64[2], result.Architecture), HexPointerValue(record.Values64[3], result.Architecture), HexPointerValue(record.Values64[3], result.Architecture));
        payload = ApiCallPayload(result, record, HexNtStatusValue(record.ReturnCode), args.str(), "", "resolver", "dynamic_symbol_lookup_nt");
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

std::uint64_t NonNegativeCounter(std::int64_t value)
{
    return value < 0 ? 0 : static_cast<std::uint64_t>(value);
}

std::int64_t ReadTransportCounter(volatile std::int64_t* value)
{
    std::int64_t result = 0;

    if (value != nullptr)
    {
        result = InterlockedCompareExchange64(value, 0, 0);
    }

    return result;
}

void UpdateTransportMetrics(KnMonCaptureResult& result, const SharedTransportSession& transport)
{
    result.TransportMode = "shared-memory";
    result.TransportCapacity = transport.Capacity;

    if (transport.Header != nullptr)
    {
        result.TransportRecordsProduced = NonNegativeCounter(ReadTransportCounter(&transport.Header->ProducerSequence));
        result.TransportRecordsConsumed = NonNegativeCounter(ReadTransportCounter(&transport.Header->ConsumerSequence));
        result.TransportDroppedEvents = NonNegativeCounter(ReadTransportCounter(&transport.Header->DroppedEvents));
        result.TransportHighWaterMark = NonNegativeCounter(ReadTransportCounter(&transport.Header->HighWaterMark));
        result.DroppedEvents = std::max(result.DroppedEvents, result.TransportDroppedEvents);
    }
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

void DrainSharedTransport(KnMonCaptureResult& result, SharedTransportSession& transport)
{
    if (transport.Header == nullptr || transport.Records == nullptr || transport.Capacity == 0)
    {
        return;
    }

    for (;;)
    {
        const std::int64_t consumer = ReadTransportCounter(&transport.Header->ConsumerSequence);
        const std::int64_t producer = ReadTransportCounter(&transport.Header->ProducerSequence);
        if (consumer >= producer)
        {
            break;
        }

        KnMonTransportRecord& record = transport.Records[consumer % transport.Capacity];
        if (
            record.Sequence != consumer ||
            record.State != static_cast<std::int32_t>(KnMonTransportRecordState::Committed))
        {
            break;
        }

        const std::string payload = BuildTransportApiPayload(result, record);
        if (!payload.empty())
        {
            RecordHookOverhead(result, record.HookOverheadUs);
            KnMonAgentMessage message = BuildAgentMessage(result, payload);
            result.AgentMessages.push_back(message);
            result.CapturedEvents.push_back(message);
            AddAudit(result, "api_call_received", "shared_memory_transport_read", message.RawPayload);
        }

        record.State = static_cast<std::int32_t>(KnMonTransportRecordState::Free);
        record.Sequence = -1;
        MemoryBarrier();
        InterlockedExchange64(&transport.Header->ConsumerSequence, consumer + 1);
    }

    UpdateTransportMetrics(result, transport);
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
