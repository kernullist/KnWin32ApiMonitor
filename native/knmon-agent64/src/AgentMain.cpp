#include <Windows.h>
#include <winternl.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace
{
constexpr const wchar_t* AgentVersion = L"0.2.0";
constexpr std::size_t MaxBufferPreviewBytes = 16;
constexpr std::size_t MaxNtObjectNameBytes = 512;

using CreateFileWFn = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using CreateFileAFn = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using ReadFileFn = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
using WriteFileFn = BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
using CloseHandleFn = BOOL(WINAPI*)(HANDLE);
using NtCreateFileFn = NTSTATUS(NTAPI*)(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK,
    PLARGE_INTEGER,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    PVOID,
    ULONG);
using RtlNtStatusToDosErrorFn = ULONG(WINAPI*)(NTSTATUS);

HANDLE g_pipeHandle = INVALID_HANDLE_VALUE;
SRWLOCK g_pipeLock = SRWLOCK_INIT;
volatile LONG64 g_sequence = 0;
volatile LONG64 g_droppedEvents = 0;
thread_local bool g_inHook = false;

CreateFileWFn g_originalCreateFileW = nullptr;
CreateFileAFn g_originalCreateFileA = nullptr;
ReadFileFn g_originalReadFile = nullptr;
WriteFileFn g_originalWriteFile = nullptr;
CloseHandleFn g_originalCloseHandle = nullptr;
NtCreateFileFn g_originalNtCreateFile = nullptr;
std::wstring g_operationId;

enum class AgentLifecycleState : LONG
{
    Starting = 0,
    Running = 1,
    Stopping = 2,
    Disabled = 3,
    Failed = 4,
};

struct HookRecord
{
    const char* ApiName = "";
    const char* ModuleName = "";
    ULONG_PTR* ThunkAddress = nullptr;
    void* OriginalFunction = nullptr;
    void* ReplacementFunction = nullptr;
    bool Installed = false;
    bool Restored = false;
    bool Failed = false;
};

struct HookLifecycleCounts
{
    int InstalledHooks = 0;
    int RestoredHooks = 0;
    int FailedHooks = 0;
};

constexpr std::size_t MaxHookRecords = 16;
std::array<HookRecord, MaxHookRecords> g_hookRecords = {};
std::size_t g_hookRecordCount = 0;
SRWLOCK g_hookLock = SRWLOCK_INIT;
volatile LONG g_lifecycleState = static_cast<LONG>(AgentLifecycleState::Starting);
volatile LONG g_hooksEnabled = 0;
volatile LONG g_failedHooks = 0;

void SetLifecycleState(AgentLifecycleState state)
{
    InterlockedExchange(&g_lifecycleState, static_cast<LONG>(state));
}

AgentLifecycleState GetLifecycleState()
{
    return static_cast<AgentLifecycleState>(InterlockedCompareExchange(&g_lifecycleState, 0, 0));
}

bool HooksEnabled()
{
    return InterlockedCompareExchange(&g_hooksEnabled, 0, 0) != 0 && GetLifecycleState() == AgentLifecycleState::Running;
}

const char* LifecycleStateName(AgentLifecycleState state)
{
    const char* name = "unknown";

    switch (state)
    {
    case AgentLifecycleState::Starting:
        name = "starting";
        break;
    case AgentLifecycleState::Running:
        name = "running";
        break;
    case AgentLifecycleState::Stopping:
        name = "stopping";
        break;
    case AgentLifecycleState::Disabled:
        name = "disabled";
        break;
    case AgentLifecycleState::Failed:
        name = "failed";
        break;
    default:
        break;
    }

    return name;
}

class HookReentryGuard
{
public:
    HookReentryGuard()
    {
        g_inHook = true;
    }

    ~HookReentryGuard()
    {
        g_inHook = false;
    }
};

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

std::wstring ReadEnv(const wchar_t* name)
{
    std::wstring result;
    std::array<wchar_t, 2048> buffer = {};
    const DWORD length = GetEnvironmentVariableW(name, buffer.data(), static_cast<DWORD>(buffer.size()));

    if (length > 0 && length < buffer.size())
    {
        result.assign(buffer.data(), length);
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

std::string FormatWindowsError(DWORD errorCode)
{
    std::string result;
    LPWSTR message = nullptr;

    do
    {
        if (errorCode == 0)
        {
            result = "success";
            break;
        }

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

std::string HexPointer(const void* value)
{
    std::ostringstream stream;
    stream << "0x"
           << std::hex
           << std::setfill('0')
           << std::setw(static_cast<int>(sizeof(void*) * 2))
           << reinterpret_cast<std::uintptr_t>(value);
    return stream.str();
}

std::string HexDword(DWORD value)
{
    std::ostringstream stream;
    stream << "0x"
           << std::hex
           << std::setfill('0')
           << std::setw(8)
           << value;
    return stream.str();
}

std::string HexNtStatus(NTSTATUS status)
{
    std::ostringstream stream;
    stream << "0x"
           << std::hex
           << std::setfill('0')
           << std::setw(8)
           << static_cast<std::uint32_t>(status);
    return stream.str();
}

std::string HexUlongPtr(ULONG_PTR value)
{
    std::ostringstream stream;
    stream << "0x"
           << std::hex
           << std::setfill('0')
           << std::setw(static_cast<int>(sizeof(void*) * 2))
           << static_cast<std::uintptr_t>(value);
    return stream.str();
}

std::string BufferPreview(const void* buffer, DWORD length)
{
    std::ostringstream stream;

    do
    {
        if (buffer == nullptr || length == 0)
        {
            break;
        }

        const auto* bytes = static_cast<const unsigned char*>(buffer);
        const DWORD captured = length < MaxBufferPreviewBytes ? length : static_cast<DWORD>(MaxBufferPreviewBytes);

        for (DWORD index = 0; index < captured; ++index)
        {
            if (index != 0)
            {
                stream << " ";
            }

            stream << std::hex
                   << std::setfill('0')
                   << std::setw(2)
                   << static_cast<unsigned int>(bytes[index]);
        }
    }
    while (false);

    return stream.str();
}

struct DecodeResult
{
    std::string Value;
    const char* Status = "decoded";
};

template <typename T>
bool ReadCurrentProcessValue(const T* address, T* value)
{
    bool read = false;

    do
    {
        if (address == nullptr || value == nullptr)
        {
            break;
        }

        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), address, value, sizeof(T), &bytesRead))
        {
            break;
        }

        read = bytesRead == sizeof(T);
    }
    while (false);

    return read;
}

DecodeResult DecodeUnicodeString(const UNICODE_STRING* value)
{
    DecodeResult result;

    do
    {
        if (value == nullptr)
        {
            result.Status = "invalid_pointer";
            break;
        }

        UNICODE_STRING local = {};
        if (!ReadCurrentProcessValue(value, &local))
        {
            result.Status = "unreadable_memory";
            break;
        }

        if (local.Buffer == nullptr || local.Length == 0)
        {
            break;
        }

        std::size_t capturedBytes = local.Length;
        if (capturedBytes > MaxNtObjectNameBytes)
        {
            capturedBytes = MaxNtObjectNameBytes;
            result.Status = "truncated";
        }

        capturedBytes -= capturedBytes % sizeof(wchar_t);
        if (capturedBytes == 0)
        {
            result.Status = "unreadable_memory";
            break;
        }

        std::vector<wchar_t> buffer(capturedBytes / sizeof(wchar_t) + 1);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), local.Buffer, buffer.data(), capturedBytes, &bytesRead) || bytesRead == 0)
        {
            result.Value = HexPointer(local.Buffer);
            result.Status = "unreadable_memory";
            break;
        }

        bytesRead -= bytesRead % sizeof(wchar_t);
        buffer[bytesRead / sizeof(wchar_t)] = L'\0';
        result.Value = WideToUtf8(buffer.data());
    }
    while (false);

    return result;
}

DecodeResult DecodeObjectAttributesObjectName(const OBJECT_ATTRIBUTES* objectAttributes)
{
    DecodeResult result;

    do
    {
        if (objectAttributes == nullptr)
        {
            result.Value = "";
            result.Status = "invalid_pointer";
            break;
        }

        OBJECT_ATTRIBUTES local = {};
        if (!ReadCurrentProcessValue(objectAttributes, &local))
        {
            result.Value = HexPointer(objectAttributes);
            result.Status = "unreadable_memory";
            break;
        }

        DecodeResult objectName = DecodeUnicodeString(local.ObjectName);
        result.Value = objectName.Value.empty() ? HexPointer(local.ObjectName) : objectName.Value;
        result.Status = objectName.Status;
    }
    while (false);

    return result;
}

DecodeResult DecodeIoStatusBlock(const IO_STATUS_BLOCK* ioStatusBlock)
{
    DecodeResult result;

    do
    {
        if (ioStatusBlock == nullptr)
        {
            result.Status = "invalid_pointer";
            break;
        }

        IO_STATUS_BLOCK local = {};
        if (!ReadCurrentProcessValue(ioStatusBlock, &local))
        {
            result.Value = HexPointer(ioStatusBlock);
            result.Status = "unreadable_memory";
            break;
        }

        std::ostringstream stream;
        stream << "Status=" << HexNtStatus(local.Status) << ",Information=" << HexUlongPtr(local.Information);
        result.Value = stream.str();
    }
    while (false);

    return result;
}

std::string ReadHandlePointer(PHANDLE handlePointer)
{
    std::string result = HexPointer(handlePointer);

    do
    {
        HANDLE value = nullptr;
        if (!ReadCurrentProcessValue(handlePointer, &value))
        {
            break;
        }

        result = HexPointer(value);
    }
    while (false);

    return result;
}

DWORD NtStatusToDosError(NTSTATUS status)
{
    DWORD result = 0;

    do
    {
        if (NT_SUCCESS(status))
        {
            break;
        }

        HMODULE module = GetModuleHandleW(L"ntdll.dll");
        if (module == nullptr)
        {
            result = ERROR_MR_MID_NOT_FOUND;
            break;
        }

        auto rtlNtStatusToDosError = reinterpret_cast<RtlNtStatusToDosErrorFn>(GetProcAddress(module, "RtlNtStatusToDosError"));
        if (rtlNtStatusToDosError == nullptr)
        {
            result = ERROR_MR_MID_NOT_FOUND;
            break;
        }

        result = rtlNtStatusToDosError(status);
    }
    while (false);

    return result;
}

std::uint64_t DurationUs(const LARGE_INTEGER& start, const LARGE_INTEGER& end)
{
    LARGE_INTEGER frequency = {};
    QueryPerformanceFrequency(&frequency);
    if (frequency.QuadPart == 0)
    {
        return 0;
    }

    return static_cast<std::uint64_t>(((end.QuadPart - start.QuadPart) * 1000000LL) / frequency.QuadPart);
}

LONG64 NextSequence()
{
    return InterlockedIncrement64(&g_sequence);
}

std::string MessagePrefix(const char* messageType, LONG64 sequence)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"messageType\":" << Q(messageType) << ",";
    stream << "\"operationId\":" << Q(WideToUtf8(g_operationId.c_str())) << ",";
    stream << "\"pid\":" << GetCurrentProcessId() << ",";
    stream << "\"tid\":" << GetCurrentThreadId() << ",";
    stream << "\"timestampUtc\":" << Q(NowUtc()) << ",";
    stream << "\"sequence\":" << sequence;
    return stream.str();
}

bool SendJson(const std::string& payload)
{
    bool sent = false;

    AcquireSRWLockExclusive(&g_pipeLock);
    do
    {
        if (g_pipeHandle == INVALID_HANDLE_VALUE)
        {
            break;
        }

        DWORD bytesWritten = 0;
        if (!WriteFile(g_pipeHandle, payload.data(), static_cast<DWORD>(payload.size()), &bytesWritten, nullptr))
        {
            break;
        }

        FlushFileBuffers(g_pipeHandle);
        sent = bytesWritten == payload.size();
    }
    while (false);
    ReleaseSRWLockExclusive(&g_pipeLock);

    if (!sent)
    {
        InterlockedIncrement64(&g_droppedEvents);
    }

    return sent;
}

void SendHello()
{
    const LONG64 sequence = NextSequence();
    std::ostringstream stream;
    stream << MessagePrefix("agent_hello", sequence) << ",";
    stream << "\"architecture\":\"x64\",";
    stream << "\"agentVersion\":" << Q(WideToUtf8(AgentVersion)) << ",";
    stream << "\"message\":\"KNMon x64 agent loaded by controlled early-bird APC\"";
    stream << "}";
    SendJson(stream.str());
}

void SendHookStatus(const char* moduleName, const char* apiName, bool installed, const std::string& message)
{
    const LONG64 sequence = NextSequence();
    std::ostringstream stream;
    stream << MessagePrefix(installed ? "hook_installed" : "hook_install_failed", sequence) << ",";
    stream << "\"api\":" << Q(apiName) << ",";
    stream << "\"module\":" << Q(moduleName) << ",";
    stream << "\"hookMethod\":\"iat\",";
    stream << "\"message\":" << Q(message);
    stream << "}";
    SendJson(stream.str());
}

void SendDroppedEvents()
{
    const LONG64 sequence = NextSequence();
    std::ostringstream stream;
    stream << MessagePrefix("dropped_events", sequence) << ",";
    stream << "\"droppedCount\":" << static_cast<LONG64>(g_droppedEvents) << ",";
    stream << "\"message\":\"Current agent dropped event counter\"";
    stream << "}";
    SendJson(stream.str());
}

HookLifecycleCounts SnapshotHookCounts()
{
    HookLifecycleCounts counts;

    AcquireSRWLockShared(&g_hookLock);
    for (std::size_t index = 0; index < g_hookRecordCount; ++index)
    {
        const HookRecord& record = g_hookRecords[index];
        if (record.Installed)
        {
            ++counts.InstalledHooks;
        }

        if (record.Restored)
        {
            ++counts.RestoredHooks;
        }

        if (record.Failed)
        {
            ++counts.FailedHooks;
        }
    }
    ReleaseSRWLockShared(&g_hookLock);

    counts.FailedHooks += static_cast<int>(InterlockedCompareExchange(&g_failedHooks, 0, 0));
    return counts;
}

void SendAgentShutdown(const char* reason, const HookLifecycleCounts& counts)
{
    const LONG64 sequence = NextSequence();
    std::ostringstream stream;
    stream << MessagePrefix("agent_shutdown", sequence) << ",";
    stream << "\"reason\":" << Q(reason == nullptr ? "unknown" : reason) << ",";
    stream << "\"lifecycleState\":" << Q(LifecycleStateName(GetLifecycleState())) << ",";
    stream << "\"installedHooks\":" << counts.InstalledHooks << ",";
    stream << "\"restoredHooks\":" << counts.RestoredHooks << ",";
    stream << "\"failedHooks\":" << counts.FailedHooks << ",";
    stream << "\"droppedCount\":" << static_cast<LONG64>(g_droppedEvents) << ",";
    stream << "\"message\":\"Agent lifecycle shutdown completed.\"";
    stream << "}";
    SendJson(stream.str());
}

std::string ArgumentJsonWithStatus(
    int index,
    const char* type,
    const char* name,
    const char* direction,
    const std::string& preCallValue,
    const std::string& postCallValue,
    const std::string& decodedValue,
    const char* decodeStatus);

std::string ArgumentJson(
    int index,
    const char* type,
    const char* name,
    const char* direction,
    const std::string& preCallValue,
    const std::string& postCallValue,
    const std::string& decodedValue)
{
    return ArgumentJsonWithStatus(index, type, name, direction, preCallValue, postCallValue, decodedValue, "decoded");
}

std::string ArgumentJsonWithStatus(
    int index,
    const char* type,
    const char* name,
    const char* direction,
    const std::string& preCallValue,
    const std::string& postCallValue,
    const std::string& decodedValue,
    const char* decodeStatus)
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
    stream << "\"decodeStatus\":" << Q(decodeStatus == nullptr ? "decoded" : decodeStatus);
    stream << "}";
    return stream.str();
}

void SendApiCall(
    const char* moduleName,
    const char* apiName,
    const std::string& returnValue,
    DWORD errorCode,
    std::uint64_t durationUs,
    const std::string& argumentsJson,
    const std::string& bufferPreview)
{
    const LONG64 sequence = NextSequence();
    std::ostringstream stream;
    stream << MessagePrefix("api_call", sequence) << ",";
    stream << "\"api\":" << Q(apiName) << ",";
    stream << "\"module\":" << Q(moduleName) << ",";
    stream << "\"process\":\"knmon-sample-fileio.exe\",";
    stream << "\"returnValue\":" << Q(returnValue) << ",";
    stream << "\"lastErrorCode\":" << errorCode << ",";
    stream << "\"lastErrorMessage\":" << Q(errorCode == 0 ? "success" : FormatWindowsError(errorCode)) << ",";
    stream << "\"durationUs\":" << durationUs << ",";
    stream << "\"arguments\":[" << argumentsJson << "],";
    stream << "\"tags\":[\"native-capture\",\"file\",\"hook\"],";
    stream << "\"stack\":[\"knmon-agent64.dll!IatHook\"," << Q(std::string(moduleName) + "!" + apiName) << "],";
    stream << "\"bufferPreview\":" << Q(bufferPreview);
    stream << "}";
    SendJson(stream.str());
}

void* ResolveExport(const char* moduleName, const char* name)
{
    void* result = nullptr;

    do
    {
        HMODULE module = GetModuleHandleA(moduleName);
        if (module == nullptr)
        {
            break;
        }

        result = reinterpret_cast<void*>(GetProcAddress(module, name));
    }
    while (false);

    return result;
}

bool AppendHookRecordNoLock(
    const char* moduleName,
    const char* apiName,
    ULONG_PTR* thunkAddress,
    void* originalFunction,
    void* replacementFunction)
{
    bool appended = false;

    do
    {
        if (g_hookRecordCount >= g_hookRecords.size())
        {
            break;
        }

        HookRecord& record = g_hookRecords[g_hookRecordCount];
        record.ApiName = apiName;
        record.ModuleName = moduleName;
        record.ThunkAddress = thunkAddress;
        record.OriginalFunction = originalFunction;
        record.ReplacementFunction = replacementFunction;
        record.Installed = true;
        record.Restored = false;
        record.Failed = false;
        ++g_hookRecordCount;
        appended = true;
    }
    while (false);

    return appended;
}

bool PatchImport(const char* moduleName, const char* functionName, void* replacement, void** original)
{
    bool patched = false;

    do
    {
        HMODULE mainModule = GetModuleHandleW(nullptr);
        if (mainModule == nullptr)
        {
            break;
        }

        auto* base = reinterpret_cast<std::uint8_t*>(mainModule);
        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            break;
        }

        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            break;
        }

        const IMAGE_DATA_DIRECTORY& importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDirectory.VirtualAddress == 0)
        {
            break;
        }

        auto* importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importDirectory.VirtualAddress);
        for (; importDescriptor->Name != 0; ++importDescriptor)
        {
            const char* importedModuleName = reinterpret_cast<const char*>(base + importDescriptor->Name);
            if (_stricmp(importedModuleName, moduleName) != 0)
            {
                continue;
            }

            auto* originalThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + importDescriptor->OriginalFirstThunk);
            auto* firstThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + importDescriptor->FirstThunk);

            if (importDescriptor->OriginalFirstThunk == 0)
            {
                originalThunk = firstThunk;
            }

            for (; originalThunk->u1.AddressOfData != 0; ++originalThunk, ++firstThunk)
            {
                if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal))
                {
                    continue;
                }

                auto* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + originalThunk->u1.AddressOfData);
                if (std::strcmp(reinterpret_cast<const char*>(importByName->Name), functionName) != 0)
                {
                    continue;
                }

                DWORD oldProtect = 0;
                if (!VirtualProtect(&firstThunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect))
                {
                    continue;
                }

                if (original != nullptr && *original == nullptr)
                {
                    *original = reinterpret_cast<void*>(firstThunk->u1.Function);
                }

                void* originalFunction = reinterpret_cast<void*>(firstThunk->u1.Function);
                firstThunk->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
                FlushInstructionCache(GetCurrentProcess(), &firstThunk->u1.Function, sizeof(void*));

                DWORD ignored = 0;
                VirtualProtect(&firstThunk->u1.Function, sizeof(void*), oldProtect, &ignored);
                if (AppendHookRecordNoLock(moduleName, functionName, &firstThunk->u1.Function, originalFunction, replacement))
                {
                    patched = true;
                }
                else
                {
                    firstThunk->u1.Function = reinterpret_cast<ULONG_PTR>(originalFunction);
                    FlushInstructionCache(GetCurrentProcess(), &firstThunk->u1.Function, sizeof(void*));
                    InterlockedIncrement(&g_failedHooks);
                }
            }
        }
    }
    while (false);

    return patched;
}

HookLifecycleCounts UninstallHooks()
{
    HookLifecycleCounts counts;

    InterlockedExchange(&g_hooksEnabled, 0);
    AcquireSRWLockExclusive(&g_hookLock);
    for (std::size_t index = 0; index < g_hookRecordCount; ++index)
    {
        HookRecord& record = g_hookRecords[index];
        if (!record.Installed || record.Restored || record.ThunkAddress == nullptr || record.OriginalFunction == nullptr)
        {
            if (record.Installed)
            {
                ++counts.InstalledHooks;
            }

            if (record.Restored)
            {
                ++counts.RestoredHooks;
            }

            if (record.Failed)
            {
                ++counts.FailedHooks;
            }
            continue;
        }

        ++counts.InstalledHooks;

        DWORD oldProtect = 0;
        if (!VirtualProtect(record.ThunkAddress, sizeof(void*), PAGE_READWRITE, &oldProtect))
        {
            record.Failed = true;
            ++counts.FailedHooks;
            continue;
        }

        if (*record.ThunkAddress == reinterpret_cast<ULONG_PTR>(record.ReplacementFunction))
        {
            *record.ThunkAddress = reinterpret_cast<ULONG_PTR>(record.OriginalFunction);
            FlushInstructionCache(GetCurrentProcess(), record.ThunkAddress, sizeof(void*));
            record.Restored = true;
            ++counts.RestoredHooks;
        }
        else
        {
            record.Restored = true;
            ++counts.RestoredHooks;
        }

        DWORD ignored = 0;
        if (!VirtualProtect(record.ThunkAddress, sizeof(void*), oldProtect, &ignored))
        {
            record.Failed = true;
            ++counts.FailedHooks;
        }
    }
    ReleaseSRWLockExclusive(&g_hookLock);

    counts.FailedHooks += static_cast<int>(InterlockedCompareExchange(&g_failedHooks, 0, 0));
    return counts;
}

HANDLE WINAPI HookedCreateFileW(
    LPCWSTR fileName,
    DWORD desiredAccess,
    DWORD shareMode,
    LPSECURITY_ATTRIBUTES securityAttributes,
    DWORD creationDisposition,
    DWORD flagsAndAttributes,
    HANDLE templateFile)
{
    if (g_inHook || !HooksEnabled() || g_originalCreateFileW == nullptr)
    {
        if (g_originalCreateFileW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }

        return g_originalCreateFileW(fileName, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalCreateFileW(fileName, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const bool failed = result == INVALID_HANDLE_VALUE;
    const DWORD eventError = failed ? lastError : 0;
    const std::string path = WideToUtf8(fileName);
    std::ostringstream args;
    args << ArgumentJson(0, "LPCWSTR", "lpFileName", "in", path, path, path) << ",";
    args << ArgumentJson(1, "DWORD", "dwDesiredAccess", "in", HexDword(desiredAccess), HexDword(desiredAccess), HexDword(desiredAccess)) << ",";
    args << ArgumentJson(2, "DWORD", "dwShareMode", "in", HexDword(shareMode), HexDword(shareMode), HexDword(shareMode)) << ",";
    args << ArgumentJson(3, "DWORD", "dwCreationDisposition", "in", HexDword(creationDisposition), HexDword(creationDisposition), HexDword(creationDisposition));
    if (HooksEnabled())
    {
        SendApiCall("kernel32.dll", "CreateFileW", HexPointer(result), eventError, DurationUs(start, end), args.str(), "");
    }

    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookedCreateFileA(
    LPCSTR fileName,
    DWORD desiredAccess,
    DWORD shareMode,
    LPSECURITY_ATTRIBUTES securityAttributes,
    DWORD creationDisposition,
    DWORD flagsAndAttributes,
    HANDLE templateFile)
{
    if (g_inHook || !HooksEnabled() || g_originalCreateFileA == nullptr)
    {
        if (g_originalCreateFileA == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }

        return g_originalCreateFileA(fileName, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalCreateFileA(fileName, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const bool failed = result == INVALID_HANDLE_VALUE;
    const DWORD eventError = failed ? lastError : 0;
    const std::string path = fileName == nullptr ? "" : fileName;
    std::ostringstream args;
    args << ArgumentJson(0, "LPCSTR", "lpFileName", "in", path, path, path) << ",";
    args << ArgumentJson(1, "DWORD", "dwDesiredAccess", "in", HexDword(desiredAccess), HexDword(desiredAccess), HexDword(desiredAccess)) << ",";
    args << ArgumentJson(2, "DWORD", "dwShareMode", "in", HexDword(shareMode), HexDword(shareMode), HexDword(shareMode)) << ",";
    args << ArgumentJson(3, "DWORD", "dwCreationDisposition", "in", HexDword(creationDisposition), HexDword(creationDisposition), HexDword(creationDisposition));
    if (HooksEnabled())
    {
        SendApiCall("kernel32.dll", "CreateFileA", HexPointer(result), eventError, DurationUs(start, end), args.str(), "");
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedReadFile(HANDLE file, LPVOID buffer, DWORD bytesToRead, LPDWORD bytesRead, LPOVERLAPPED overlapped)
{
    if (g_inHook || !HooksEnabled() || g_originalReadFile == nullptr)
    {
        if (g_originalReadFile == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalReadFile(file, buffer, bytesToRead, bytesRead, overlapped);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalReadFile(file, buffer, bytesToRead, bytesRead, overlapped);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD actualBytes = bytesRead == nullptr ? 0 : *bytesRead;
    const DWORD eventError = result ? 0 : lastError;
    std::ostringstream args;
    args << ArgumentJson(0, "HANDLE", "hFile", "in", HexPointer(file), HexPointer(file), HexPointer(file)) << ",";
    args << ArgumentJson(1, "LPVOID", "lpBuffer", "out", HexPointer(buffer), HexPointer(buffer), HexPointer(buffer)) << ",";
    args << ArgumentJson(2, "DWORD", "nNumberOfBytesToRead", "in", std::to_string(bytesToRead), std::to_string(bytesToRead), std::to_string(bytesToRead)) << ",";
    args << ArgumentJson(3, "LPDWORD", "lpNumberOfBytesRead", "out", HexPointer(bytesRead), std::to_string(actualBytes), std::to_string(actualBytes));
    if (HooksEnabled())
    {
        SendApiCall("kernel32.dll", "ReadFile", result ? "TRUE" : "FALSE", eventError, DurationUs(start, end), args.str(), result ? BufferPreview(buffer, actualBytes) : "");
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedWriteFile(HANDLE file, LPCVOID buffer, DWORD bytesToWrite, LPDWORD bytesWritten, LPOVERLAPPED overlapped)
{
    if (g_inHook || !HooksEnabled() || g_originalWriteFile == nullptr)
    {
        if (g_originalWriteFile == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalWriteFile(file, buffer, bytesToWrite, bytesWritten, overlapped);
    }

    HookReentryGuard guard;
    const std::string preview = BufferPreview(buffer, bytesToWrite);
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalWriteFile(file, buffer, bytesToWrite, bytesWritten, overlapped);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD actualBytes = bytesWritten == nullptr ? 0 : *bytesWritten;
    const DWORD eventError = result ? 0 : lastError;
    std::ostringstream args;
    args << ArgumentJson(0, "HANDLE", "hFile", "in", HexPointer(file), HexPointer(file), HexPointer(file)) << ",";
    args << ArgumentJson(1, "LPCVOID", "lpBuffer", "in", HexPointer(buffer), HexPointer(buffer), preview) << ",";
    args << ArgumentJson(2, "DWORD", "nNumberOfBytesToWrite", "in", std::to_string(bytesToWrite), std::to_string(bytesToWrite), std::to_string(bytesToWrite)) << ",";
    args << ArgumentJson(3, "LPDWORD", "lpNumberOfBytesWritten", "out", HexPointer(bytesWritten), std::to_string(actualBytes), std::to_string(actualBytes));
    if (HooksEnabled())
    {
        SendApiCall("kernel32.dll", "WriteFile", result ? "TRUE" : "FALSE", eventError, DurationUs(start, end), args.str(), preview);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedCloseHandle(HANDLE handle)
{
    if (g_inHook || !HooksEnabled() || g_originalCloseHandle == nullptr)
    {
        if (g_originalCloseHandle == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalCloseHandle(handle);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalCloseHandle(handle);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result ? 0 : lastError;
    std::ostringstream args;
    args << ArgumentJson(0, "HANDLE", "hObject", "in", HexPointer(handle), HexPointer(handle), HexPointer(handle));
    if (HooksEnabled())
    {
        SendApiCall("kernel32.dll", "CloseHandle", result ? "TRUE" : "FALSE", eventError, DurationUs(start, end), args.str(), "");
    }

    SetLastError(lastError);
    return result;
}

NTSTATUS NTAPI HookedNtCreateFile(
    PHANDLE fileHandle,
    ACCESS_MASK desiredAccess,
    POBJECT_ATTRIBUTES objectAttributes,
    PIO_STATUS_BLOCK ioStatusBlock,
    PLARGE_INTEGER allocationSize,
    ULONG fileAttributes,
    ULONG shareAccess,
    ULONG createDisposition,
    ULONG createOptions,
    PVOID eaBuffer,
    ULONG eaLength)
{
    if (g_inHook || !HooksEnabled() || g_originalNtCreateFile == nullptr)
    {
        if (g_originalNtCreateFile == nullptr)
        {
            return static_cast<NTSTATUS>(0xC000007AL);
        }

        return g_originalNtCreateFile(
            fileHandle,
            desiredAccess,
            objectAttributes,
            ioStatusBlock,
            allocationSize,
            fileAttributes,
            shareAccess,
            createDisposition,
            createOptions,
            eaBuffer,
            eaLength);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    NTSTATUS status = g_originalNtCreateFile(
        fileHandle,
        desiredAccess,
        objectAttributes,
        ioStatusBlock,
        allocationSize,
        fileAttributes,
        shareAccess,
        createDisposition,
        createOptions,
        eaBuffer,
        eaLength);
    QueryPerformanceCounter(&end);

    const DWORD eventError = NtStatusToDosError(status);
    const DecodeResult objectName = DecodeObjectAttributesObjectName(objectAttributes);
    const DecodeResult ioStatus = DecodeIoStatusBlock(ioStatusBlock);
    const std::string fileHandlePointer = HexPointer(fileHandle);
    const std::string fileHandleValue = NT_SUCCESS(status) ? ReadHandlePointer(fileHandle) : fileHandlePointer;
    const std::string objectDecoded = objectName.Value.empty() ? HexPointer(objectAttributes) : objectName.Value;
    const std::string ioStatusDecoded = ioStatus.Value.empty() ? HexPointer(ioStatusBlock) : ioStatus.Value;

    std::ostringstream args;
    args << ArgumentJson(0, "PHANDLE", "FileHandle", "out", fileHandlePointer, fileHandleValue, fileHandleValue) << ",";
    args << ArgumentJson(1, "ACCESS_MASK", "DesiredAccess", "in", HexDword(desiredAccess), HexDword(desiredAccess), HexDword(desiredAccess)) << ",";
    args << ArgumentJsonWithStatus(2, "POBJECT_ATTRIBUTES", "ObjectAttributes", "in", HexPointer(objectAttributes), HexPointer(objectAttributes), objectDecoded, objectName.Status) << ",";
    args << ArgumentJsonWithStatus(3, "PIO_STATUS_BLOCK", "IoStatusBlock", "out", HexPointer(ioStatusBlock), ioStatusDecoded, ioStatusDecoded, ioStatus.Status) << ",";
    args << ArgumentJson(4, "PLARGE_INTEGER", "AllocationSize", "in", HexPointer(allocationSize), HexPointer(allocationSize), HexPointer(allocationSize)) << ",";
    args << ArgumentJson(5, "ULONG", "FileAttributes", "in", HexDword(fileAttributes), HexDword(fileAttributes), HexDword(fileAttributes)) << ",";
    args << ArgumentJson(6, "ULONG", "ShareAccess", "in", HexDword(shareAccess), HexDword(shareAccess), HexDword(shareAccess)) << ",";
    args << ArgumentJson(7, "ULONG", "CreateDisposition", "in", HexDword(createDisposition), HexDword(createDisposition), HexDword(createDisposition)) << ",";
    args << ArgumentJson(8, "ULONG", "CreateOptions", "in", HexDword(createOptions), HexDword(createOptions), HexDword(createOptions)) << ",";
    args << ArgumentJson(9, "PVOID", "EaBuffer", "in", HexPointer(eaBuffer), HexPointer(eaBuffer), HexPointer(eaBuffer)) << ",";
    args << ArgumentJson(10, "ULONG", "EaLength", "in", std::to_string(eaLength), std::to_string(eaLength), std::to_string(eaLength));

    if (HooksEnabled())
    {
        SendApiCall("ntdll.dll", "NtCreateFile", HexNtStatus(status), eventError, DurationUs(start, end), args.str(), "");
    }

    return status;
}

bool InstallHook(const char* moduleName, const char* apiName, void* replacement, void** original)
{
    bool installed = false;

    do
    {
        if (original != nullptr && *original == nullptr)
        {
            *original = ResolveExport(moduleName, apiName);
        }

        AcquireSRWLockExclusive(&g_hookLock);
        installed = PatchImport(moduleName, apiName, replacement, original);
        ReleaseSRWLockExclusive(&g_hookLock);
    }
    while (false);

    if (!installed)
    {
        InterlockedIncrement(&g_failedHooks);
    }

    SendHookStatus(moduleName, apiName, installed, installed ? "IAT hook installed in controlled sample target." : "IAT entry was not found in controlled sample target.");
    return installed;
}

bool InstallHooks()
{
    bool allInstalled = true;

    allInstalled = InstallHook("kernel32.dll", "CreateFileW", reinterpret_cast<void*>(HookedCreateFileW), reinterpret_cast<void**>(&g_originalCreateFileW)) && allInstalled;
    allInstalled = InstallHook("kernel32.dll", "CreateFileA", reinterpret_cast<void*>(HookedCreateFileA), reinterpret_cast<void**>(&g_originalCreateFileA)) && allInstalled;
    allInstalled = InstallHook("kernel32.dll", "ReadFile", reinterpret_cast<void*>(HookedReadFile), reinterpret_cast<void**>(&g_originalReadFile)) && allInstalled;
    allInstalled = InstallHook("kernel32.dll", "WriteFile", reinterpret_cast<void*>(HookedWriteFile), reinterpret_cast<void**>(&g_originalWriteFile)) && allInstalled;
    allInstalled = InstallHook("kernel32.dll", "CloseHandle", reinterpret_cast<void*>(HookedCloseHandle), reinterpret_cast<void**>(&g_originalCloseHandle)) && allInstalled;
    allInstalled = InstallHook("ntdll.dll", "NtCreateFile", reinterpret_cast<void*>(HookedNtCreateFile), reinterpret_cast<void**>(&g_originalNtCreateFile)) && allInstalled;

    if (allInstalled)
    {
        SetLifecycleState(AgentLifecycleState::Running);
        InterlockedExchange(&g_hooksEnabled, 1);
    }

    return allInstalled;
}

void CloseAgentPipe()
{
    AcquireSRWLockExclusive(&g_pipeLock);
    if (g_pipeHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_pipeHandle);
        g_pipeHandle = INVALID_HANDLE_VALUE;
    }
    ReleaseSRWLockExclusive(&g_pipeLock);
}

void ShutdownAgent(const char* reason, AgentLifecycleState finalState)
{
    const AgentLifecycleState previousState = GetLifecycleState();
    if (previousState == AgentLifecycleState::Stopping || previousState == AgentLifecycleState::Disabled || previousState == AgentLifecycleState::Failed)
    {
        return;
    }

    SetLifecycleState(AgentLifecycleState::Stopping);
    HookLifecycleCounts counts = UninstallHooks();
    SetLifecycleState(finalState);
    SendAgentShutdown(reason, counts);
    CloseAgentPipe();
}

DWORD WINAPI AgentWorker(void*)
{
    const std::wstring pipeName = ReadEnv(L"KNMON_AGENT_PIPE");
    g_operationId = ReadEnv(L"KNMON_OPERATION_ID");

    do
    {
        if (pipeName.empty())
        {
            break;
        }

        HANDLE pipeHandle = INVALID_HANDLE_VALUE;
        for (int attempt = 0; attempt < 50; ++attempt)
        {
            pipeHandle = CreateFileW(
                pipeName.c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (pipeHandle != INVALID_HANDLE_VALUE)
            {
                break;
            }

            if (GetLastError() != ERROR_PIPE_BUSY)
            {
                Sleep(50);
            }
            else
            {
                WaitNamedPipeW(pipeName.c_str(), 100);
            }
        }

        if (pipeHandle == INVALID_HANDLE_VALUE)
        {
            break;
        }

        AcquireSRWLockExclusive(&g_pipeLock);
        g_pipeHandle = pipeHandle;
        ReleaseSRWLockExclusive(&g_pipeLock);

        SendHello();

        if (!InstallHooks())
        {
            SendDroppedEvents();
            ShutdownAgent("hook_install_failed", AgentLifecycleState::Failed);
            break;
        }

        SendDroppedEvents();
    }
    while (false);

    return 0;
}
}

extern "C" __declspec(dllexport) DWORD KnMonAgentVersion()
{
    return 0x00020000;
}

BOOL APIENTRY DllMain(HMODULE moduleHandle, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(moduleHandle);
        HANDLE threadHandle = CreateThread(nullptr, 0, AgentWorker, nullptr, 0, nullptr);
        if (threadHandle != nullptr)
        {
            CloseHandle(threadHandle);
        }
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        ShutdownAgent("process_detach", AgentLifecycleState::Disabled);
    }

    return TRUE;
}
