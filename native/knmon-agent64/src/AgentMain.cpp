#include <knmon/common/Protocol.h>

#include <Windows.h>
#include <winternl.h>

#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <intrin.h>
#include <sstream>
#include <string>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef KNMON_AGENT_ARCHITECTURE
#define KNMON_AGENT_ARCHITECTURE "unknown"
#endif

#ifndef KNMON_AGENT_DLL_NAME
#define KNMON_AGENT_DLL_NAME "knmon-agent.dll"
#endif

#ifndef KNMON_AGENT_HELLO_MESSAGE
#define KNMON_AGENT_HELLO_MESSAGE "KNMon agent loaded by controlled early-bird APC"
#endif

namespace
{
constexpr const wchar_t* AgentVersion = L"0.2.0";
constexpr std::size_t MaxBufferPreviewBytes = 16;
constexpr std::size_t MaxNtObjectNameBytes = 512;

struct KnMonPebLdrData
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct KnMonLdrDataTableEntry
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

struct KnMonPeb
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    KnMonPebLdrData* Ldr;
};

using CreateFileWFn = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using CreateFileAFn = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using ReadFileFn = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
using WriteFileFn = BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
using CloseHandleFn = BOOL(WINAPI*)(HANDLE);
using LoadLibraryWFn = HMODULE(WINAPI*)(LPCWSTR);
using LoadLibraryAFn = HMODULE(WINAPI*)(LPCSTR);
using LoadLibraryExWFn = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
using LoadLibraryExAFn = HMODULE(WINAPI*)(LPCSTR, HANDLE, DWORD);
using GetProcAddressFn = FARPROC(WINAPI*)(HMODULE, LPCSTR);
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
using LdrLoadDllFn = NTSTATUS(NTAPI*)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
using LdrGetProcedureAddressFn = NTSTATUS(NTAPI*)(HMODULE, PANSI_STRING, ULONG, PVOID*);
using RtlNtStatusToDosErrorFn = ULONG(WINAPI*)(NTSTATUS);

HMODULE g_agentModule = nullptr;
HANDLE g_pipeHandle = INVALID_HANDLE_VALUE;
HANDLE g_transportMapping = nullptr;
knmon::KnMonTransportHeader* g_transportHeader = nullptr;
knmon::KnMonTransportRecord* g_transportRecords = nullptr;
std::uint32_t g_transportCapacity = 0;
SRWLOCK g_pipeLock = SRWLOCK_INIT;
volatile LONG64 g_sequence = 0;
volatile LONG64 g_droppedEvents = 0;
thread_local bool g_inHook = false;

CreateFileWFn g_originalCreateFileW = nullptr;
CreateFileAFn g_originalCreateFileA = nullptr;
ReadFileFn g_originalReadFile = nullptr;
WriteFileFn g_originalWriteFile = nullptr;
CloseHandleFn g_originalCloseHandle = nullptr;
LoadLibraryWFn g_originalLoadLibraryW = nullptr;
LoadLibraryAFn g_originalLoadLibraryA = nullptr;
LoadLibraryExWFn g_originalLoadLibraryExW = nullptr;
LoadLibraryExAFn g_originalLoadLibraryExA = nullptr;
GetProcAddressFn g_originalGetProcAddress = nullptr;
NtCreateFileFn g_originalNtCreateFile = nullptr;
LdrLoadDllFn g_originalLdrLoadDll = nullptr;
LdrGetProcedureAddressFn g_originalLdrGetProcedureAddress = nullptr;
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
    char ApiName[64] = {};
    char ImportModuleName[64] = {};
    char OwnerModuleName[128] = {};
    HMODULE OwnerModule = nullptr;
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

struct ModuleInfo
{
    HMODULE Base = nullptr;
    std::uint32_t SizeOfImage = 0;
    char Name[128] = {};
    char FullPath[512] = {};
    bool IsAgent = false;
    bool IsSystem = false;
    bool HasImports = false;
    bool Eligible = false;
};

struct SweepStats
{
    std::uint32_t ScannedModules = 0;
    std::uint32_t EligibleModules = 0;
    std::uint32_t SkippedModules = 0;
    std::uint32_t ModulesWithPatches = 0;
    std::uint32_t PatchedSlots = 0;
    std::uint32_t DuplicateSlots = 0;
    std::uint32_t FailedSlots = 0;
};

struct HookDefinition
{
    const char* ImportModuleName = "";
    const char* ApiName = "";
    void* ReplacementFunction = nullptr;
    void** OriginalFunction = nullptr;
    bool Required = false;
    bool ReportStatus = false;
    bool LoaderApi = false;
    std::uint32_t LastPatchedSlots = 0;
};

constexpr std::size_t MaxHookRecords = 1024;
constexpr std::size_t MaxModuleRecords = 256;
constexpr std::size_t HookDefinitionCount = 13;
constexpr std::size_t MaxResolverNameBytes = 512;
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

bool EnvEnabled(const wchar_t* name)
{
    const std::wstring value = ReadEnv(name);
    return value == L"1" || value == L"true" || value == L"TRUE";
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

void CopyAsciiText(char* destination, std::uint32_t* length, std::size_t capacity, const char* source)
{
    std::uint32_t copied = 0;

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            break;
        }

        destination[0] = '\0';
        if (source == nullptr)
        {
            break;
        }

        while (copied + 1 < capacity && source[copied] != '\0')
        {
            destination[copied] = source[copied];
            ++copied;
        }

        destination[copied] = '\0';
    }
    while (false);

    if (length != nullptr)
    {
        *length = copied;
    }
}

void CopyWideText(char* destination, std::uint32_t* length, std::size_t capacity, const wchar_t* source)
{
    std::uint32_t copied = 0;

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            break;
        }

        destination[0] = '\0';
        if (source == nullptr)
        {
            break;
        }

        const int converted = WideCharToMultiByte(CP_UTF8, 0, source, -1, destination, static_cast<int>(capacity), nullptr, nullptr);
        if (converted <= 0)
        {
            break;
        }

        copied = static_cast<std::uint32_t>(converted - 1);
    }
    while (false);

    if (length != nullptr)
    {
        *length = copied;
    }
}

void CopyWideCountText(char* destination, std::size_t capacity, const wchar_t* source, std::size_t charCount)
{
    do
    {
        if (destination == nullptr || capacity == 0)
        {
            break;
        }

        destination[0] = '\0';
        if (source == nullptr || charCount == 0)
        {
            break;
        }

        const std::size_t boundedChars = charCount < 511 ? charCount : 511;
        std::array<wchar_t, 512> buffer = {};
        for (std::size_t index = 0; index < boundedChars; ++index)
        {
            buffer[index] = source[index];
        }

        buffer[boundedChars] = L'\0';
        CopyWideText(destination, nullptr, capacity, buffer.data());
    }
    while (false);
}

void LowerAsciiInPlace(char* value)
{
    if (value == nullptr)
    {
        return;
    }

    for (std::size_t index = 0; value[index] != '\0'; ++index)
    {
        if (value[index] >= 'A' && value[index] <= 'Z')
        {
            value[index] = static_cast<char>(value[index] - 'A' + 'a');
        }
    }
}

const char* FileNameFromPathText(const char* path)
{
    const char* result = path;

    if (path != nullptr)
    {
        for (const char* current = path; *current != '\0'; ++current)
        {
            if (*current == '\\' || *current == '/')
            {
                result = current + 1;
            }
        }
    }

    return result == nullptr ? "" : result;
}

bool TextContains(const char* value, const char* pattern)
{
    bool contains = false;

    do
    {
        if (value == nullptr || pattern == nullptr)
        {
            break;
        }

        if (std::strstr(value, pattern) != nullptr)
        {
            contains = true;
        }
    }
    while (false);

    return contains;
}

bool IsWindowsSystemModule(const ModuleInfo& module)
{
    bool systemModule = false;

    if (
        TextContains(module.FullPath, "\\windows\\system32\\") ||
        TextContains(module.FullPath, "\\windows\\syswow64\\") ||
        std::strcmp(module.Name, "ntdll.dll") == 0 ||
        std::strcmp(module.Name, "kernel32.dll") == 0 ||
        std::strcmp(module.Name, "kernelbase.dll") == 0)
    {
        systemModule = true;
    }

    return systemModule;
}

void CopyHexPointerText(char* destination, std::uint32_t* length, std::size_t capacity, const void* value)
{
    int written = 0;

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            break;
        }

        destination[0] = '\0';
        written = std::snprintf(
            destination,
            capacity,
            sizeof(void*) == 8 ? "0x%016llx" : "0x%08llx",
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(value)));
        if (written < 0)
        {
            written = 0;
            destination[0] = '\0';
        }
    }
    while (false);

    if (length != nullptr)
    {
        *length = static_cast<std::uint32_t>(written < 0 ? 0 : written);
    }
}

void CopyBufferPreviewText(char* destination, std::uint32_t* length, std::size_t capacity, const void* buffer, DWORD bytes)
{
    std::uint32_t copied = 0;
    static constexpr char Hex[] = "0123456789abcdef";

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            break;
        }

        destination[0] = '\0';
        if (buffer == nullptr || bytes == 0)
        {
            break;
        }

        const auto* source = static_cast<const unsigned char*>(buffer);
        const DWORD captured = bytes < MaxBufferPreviewBytes ? bytes : static_cast<DWORD>(MaxBufferPreviewBytes);
        for (DWORD index = 0; index < captured; ++index)
        {
            if (copied + 3 >= capacity)
            {
                break;
            }

            if (index != 0)
            {
                destination[copied] = ' ';
                ++copied;
            }

            destination[copied] = Hex[(source[index] >> 4) & 0x0f];
            ++copied;
            destination[copied] = Hex[source[index] & 0x0f];
            ++copied;
        }

        destination[copied] = '\0';
    }
    while (false);

    if (length != nullptr)
    {
        *length = copied;
    }
}

bool IsOrdinalProcName(LPCSTR procName)
{
    const std::uintptr_t value = reinterpret_cast<std::uintptr_t>(procName);
    return value != 0 && (value >> 16) == 0;
}

std::uint32_t CopyAnsiPointerText(char* destination, std::uint32_t* length, std::size_t capacity, const char* source)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
    std::uint32_t copied = 0;
    bool terminated = false;

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
            break;
        }

        destination[0] = '\0';
        if (source == nullptr)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            break;
        }

        while (copied + 1 < capacity)
        {
            char ch = '\0';
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), source + copied, &ch, sizeof(ch), &bytesRead) || bytesRead != sizeof(ch))
            {
                status = copied == 0 ?
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory) :
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);
                break;
            }

            if (ch == '\0')
            {
                terminated = true;
                break;
            }

            destination[copied] = ch;
            ++copied;
        }

        destination[copied] = '\0';
        if (!terminated && status == static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded))
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
        }
    }
    while (false);

    if (length != nullptr)
    {
        *length = copied;
    }

    return status;
}

template <typename T>
bool ReadCurrentProcessValue(const T* address, T* value);

std::uint64_t DurationUs(const LARGE_INTEGER& start, const LARGE_INTEGER& end);

std::uint32_t CopyAnsiStringText(char* destination, std::uint32_t* length, std::size_t capacity, const ANSI_STRING* value)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
    std::uint32_t copied = 0;

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
            break;
        }

        destination[0] = '\0';
        if (value == nullptr)
        {
            break;
        }

        ANSI_STRING local = {};
        if (!ReadCurrentProcessValue(value, &local))
        {
            CopyHexPointerText(destination, length, capacity, value);
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            break;
        }

        if (local.Buffer == nullptr || local.Length == 0)
        {
            break;
        }

        std::size_t capturedBytes = local.Length;
        if (capturedBytes > MaxResolverNameBytes)
        {
            capturedBytes = MaxResolverNameBytes;
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
        }

        if (capturedBytes + 1 > capacity)
        {
            capturedBytes = capacity - 1;
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
        }

        if (capturedBytes == 0)
        {
            break;
        }

        std::array<char, MaxResolverNameBytes + 1> localBuffer = {};
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), local.Buffer, localBuffer.data(), capturedBytes, &bytesRead) || bytesRead == 0)
        {
            CopyHexPointerText(destination, length, capacity, local.Buffer);
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            break;
        }

        copied = static_cast<std::uint32_t>(bytesRead < capturedBytes ? bytesRead : capturedBytes);
        for (std::uint32_t index = 0; index < copied; ++index)
        {
            destination[index] = localBuffer[index];
        }
        destination[copied] = '\0';

        if (bytesRead < local.Length && status == static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded))
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);
        }
    }
    while (false);

    if (length != nullptr && status != static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory))
    {
        *length = copied;
    }

    return status;
}

std::uint32_t CopyUnicodeStringText(char* destination, std::uint32_t* length, std::size_t capacity, const UNICODE_STRING* value)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
            break;
        }

        destination[0] = '\0';
        if (value == nullptr)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            break;
        }

        UNICODE_STRING local = {};
        if (!ReadCurrentProcessValue(value, &local))
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
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
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
        }

        capturedBytes -= capturedBytes % sizeof(wchar_t);
        if (capturedBytes == 0)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            break;
        }

        std::array<wchar_t, (MaxNtObjectNameBytes / sizeof(wchar_t)) + 1> localBuffer = {};
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), local.Buffer, localBuffer.data(), capturedBytes, &bytesRead) || bytesRead == 0)
        {
            CopyHexPointerText(destination, length, capacity, local.Buffer);
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            break;
        }

        bytesRead -= bytesRead % sizeof(wchar_t);
        localBuffer[bytesRead / sizeof(wchar_t)] = L'\0';
        CopyWideText(destination, length, capacity, localBuffer.data());
    }
    while (false);

    return status;
}

std::uint32_t CopyObjectAttributesName(char* destination, std::uint32_t* length, std::size_t capacity, const OBJECT_ATTRIBUTES* objectAttributes)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);

    do
    {
        if (objectAttributes == nullptr)
        {
            CopyAsciiText(destination, length, capacity, "");
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            break;
        }

        OBJECT_ATTRIBUTES local = {};
        if (!ReadCurrentProcessValue(objectAttributes, &local))
        {
            CopyHexPointerText(destination, length, capacity, objectAttributes);
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            break;
        }

        status = CopyUnicodeStringText(destination, length, capacity, local.ObjectName);
        if (destination != nullptr && destination[0] == '\0')
        {
            CopyHexPointerText(destination, length, capacity, local.ObjectName);
        }
    }
    while (false);

    return status;
}

std::uint32_t CopyIoStatusBlockText(char* destination, std::uint32_t* length, std::size_t capacity, const IO_STATUS_BLOCK* ioStatusBlock)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);

    do
    {
        if (ioStatusBlock == nullptr)
        {
            CopyAsciiText(destination, length, capacity, "");
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            break;
        }

        IO_STATUS_BLOCK local = {};
        if (!ReadCurrentProcessValue(ioStatusBlock, &local))
        {
            CopyHexPointerText(destination, length, capacity, ioStatusBlock);
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            break;
        }

        char buffer[96] = {};
        std::snprintf(
            buffer,
            sizeof(buffer),
            sizeof(void*) == 8 ? "Status=0x%08lx,Information=0x%016llx" : "Status=0x%08lx,Information=0x%08llx",
            static_cast<unsigned long>(static_cast<std::uint32_t>(local.Status)),
            static_cast<unsigned long long>(static_cast<std::uintptr_t>(local.Information)));
        CopyAsciiText(destination, length, capacity, buffer);
    }
    while (false);

    return status;
}

void CountDroppedTransportEvent()
{
    InterlockedIncrement64(&g_droppedEvents);
    if (g_transportHeader != nullptr)
    {
        InterlockedIncrement64(&g_transportHeader->DroppedEvents);
    }
}

void UpdateTransportHighWaterMark(std::int64_t depth)
{
    if (g_transportHeader == nullptr)
    {
        return;
    }

    for (;;)
    {
        const std::int64_t current = InterlockedCompareExchange64(&g_transportHeader->HighWaterMark, 0, 0);
        if (depth <= current)
        {
            break;
        }

        if (InterlockedCompareExchange64(&g_transportHeader->HighWaterMark, depth, current) == current)
        {
            break;
        }
    }
}

knmon::KnMonTransportRecord* ReserveTransportRecord()
{
    knmon::KnMonTransportRecord* record = nullptr;

    do
    {
        if (g_transportHeader == nullptr || g_transportRecords == nullptr || g_transportCapacity == 0)
        {
            CountDroppedTransportEvent();
            break;
        }

        for (;;)
        {
            const std::int64_t producer = InterlockedCompareExchange64(&g_transportHeader->ProducerSequence, 0, 0);
            const std::int64_t consumer = InterlockedCompareExchange64(&g_transportHeader->ConsumerSequence, 0, 0);
            const std::int64_t depth = producer - consumer;
            if (depth >= static_cast<std::int64_t>(g_transportCapacity))
            {
                CountDroppedTransportEvent();
                break;
            }

            if (InterlockedCompareExchange64(&g_transportHeader->ProducerSequence, producer + 1, producer) == producer)
            {
                UpdateTransportHighWaterMark(depth + 1);
                record = &g_transportRecords[producer % g_transportCapacity];
                if (InterlockedCompareExchange(
                        reinterpret_cast<volatile LONG*>(&record->State),
                        static_cast<LONG>(knmon::KnMonTransportRecordState::Writing),
                        static_cast<LONG>(knmon::KnMonTransportRecordState::Free)) != static_cast<LONG>(knmon::KnMonTransportRecordState::Free))
                {
                    record = nullptr;
                    CountDroppedTransportEvent();
                    break;
                }

                std::memset(record, 0, sizeof(*record));
                record->State = static_cast<LONG>(knmon::KnMonTransportRecordState::Writing);
                record->Sequence = producer;
                record->RecordSize = sizeof(knmon::KnMonTransportRecord);
                record->EventKind = static_cast<std::uint16_t>(knmon::KnMonTransportEventKind::ApiCall);
                record->ProcessId = GetCurrentProcessId();
                record->ThreadId = GetCurrentThreadId();
                break;
            }
        }
    }
    while (false);

    return record;
}

void CommitTransportRecord(knmon::KnMonTransportRecord* record, const LARGE_INTEGER& overheadStart)
{
    if (record != nullptr)
    {
        LARGE_INTEGER overheadEnd = {};
        QueryPerformanceCounter(&overheadEnd);
        record->HookOverheadUs = DurationUs(overheadStart, overheadEnd);
        MemoryBarrier();
        InterlockedExchange(reinterpret_cast<volatile LONG*>(&record->State), static_cast<LONG>(knmon::KnMonTransportRecordState::Committed));
    }
}

std::uint16_t ModuleId(const char* moduleName)
{
    std::uint16_t result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Unknown);

    if (std::strcmp(moduleName, "kernel32.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Kernel32);
    }
    else if (std::strcmp(moduleName, "ntdll.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Ntdll);
    }
    else if (std::strcmp(moduleName, "kernelbase.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::KernelBase);
    }

    return result;
}

bool OpenTransport(const std::wstring& mappingName)
{
    bool opened = false;

    do
    {
        if (mappingName.empty())
        {
            break;
        }

        g_transportMapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, mappingName.c_str());
        if (g_transportMapping == nullptr)
        {
            break;
        }

        auto* header = static_cast<knmon::KnMonTransportHeader*>(MapViewOfFile(g_transportMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0));
        if (header == nullptr)
        {
            break;
        }

        if (
            header->Magic != knmon::KnMonTransportMagic ||
            header->AbiVersion != knmon::KnMonTransportAbiVersion ||
            header->RecordSize != sizeof(knmon::KnMonTransportRecord) ||
            header->Capacity < knmon::KnMonTransportMinCapacity)
        {
            UnmapViewOfFile(header);
            break;
        }

        g_transportHeader = header;
        g_transportRecords = reinterpret_cast<knmon::KnMonTransportRecord*>(reinterpret_cast<unsigned char*>(header) + sizeof(knmon::KnMonTransportHeader));
        g_transportCapacity = header->Capacity;
        opened = true;
    }
    while (false);

    if (!opened)
    {
        if (g_transportHeader != nullptr)
        {
            UnmapViewOfFile(g_transportHeader);
            g_transportHeader = nullptr;
            g_transportRecords = nullptr;
            g_transportCapacity = 0;
        }

        if (g_transportMapping != nullptr)
        {
            CloseHandle(g_transportMapping);
            g_transportMapping = nullptr;
        }
    }

    return opened;
}

void CloseTransport()
{
    if (g_transportHeader != nullptr)
    {
        UnmapViewOfFile(g_transportHeader);
        g_transportHeader = nullptr;
        g_transportRecords = nullptr;
        g_transportCapacity = 0;
    }

    if (g_transportMapping != nullptr)
    {
        CloseHandle(g_transportMapping);
        g_transportMapping = nullptr;
    }
}

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
    stream << "\"architecture\":" << Q(KNMON_AGENT_ARCHITECTURE) << ",";
    stream << "\"agentVersion\":" << Q(WideToUtf8(AgentVersion)) << ",";
    stream << "\"message\":" << Q(KNMON_AGENT_HELLO_MESSAGE);
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

void SendModuleInventoryStatus(const SweepStats& stats)
{
    const LONG64 sequence = NextSequence();
    std::ostringstream stream;
    stream << MessagePrefix("module_inventory", sequence) << ",";
    stream << "\"scannedModules\":" << stats.ScannedModules << ",";
    stream << "\"eligibleModules\":" << stats.EligibleModules << ",";
    stream << "\"skippedModules\":" << stats.SkippedModules << ",";
    stream << "\"message\":\"Module inventory captured from PEB loader list.\"";
    stream << "}";
    SendJson(stream.str());
}

void SendIatSweepStatus(const char* reason, const SweepStats& stats)
{
    const LONG64 sequence = NextSequence();
    std::ostringstream stream;
    stream << MessagePrefix("iat_sweep", sequence) << ",";
    stream << "\"reason\":" << Q(reason == nullptr ? "unknown" : reason) << ",";
    stream << "\"scannedModules\":" << stats.ScannedModules << ",";
    stream << "\"eligibleModules\":" << stats.EligibleModules << ",";
    stream << "\"skippedModules\":" << stats.SkippedModules << ",";
    stream << "\"patchedModules\":" << stats.ModulesWithPatches << ",";
    stream << "\"patchedSlots\":" << stats.PatchedSlots << ",";
    stream << "\"duplicateSlots\":" << stats.DuplicateSlots << ",";
    stream << "\"failedSlots\":" << stats.FailedSlots << ",";
    stream << "\"message\":\"Loaded-module IAT sweep completed.\"";
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

void FillTransportCommon(
    knmon::KnMonTransportRecord* record,
    knmon::KnMonTransportApiId apiId,
    const char* moduleName,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    DWORD errorCode)
{
    if (record != nullptr)
    {
        record->ApiId = static_cast<std::uint16_t>(apiId);
        record->ModuleId = ModuleId(moduleName);
        record->StartQpc = static_cast<std::uint64_t>(start.QuadPart);
        record->EndQpc = static_cast<std::uint64_t>(end.QuadPart);
        record->DurationUs = DurationUs(start, end);
        record->LastErrorCode = errorCode;
    }
}

void EmitCreateFileWEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCWSTR fileName,
    DWORD desiredAccess,
    DWORD shareMode,
    DWORD creationDisposition)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CreateFileW, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values32[0] = desiredAccess;
        record->Values32[1] = shareMode;
        record->Values32[2] = creationDisposition;
        CopyWideText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCreateFileAEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCSTR fileName,
    DWORD desiredAccess,
    DWORD shareMode,
    DWORD creationDisposition)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CreateFileA, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values32[0] = desiredAccess;
        record->Values32[1] = shareMode;
        record->Values32[2] = creationDisposition;
        CopyAsciiText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitReadFileEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE file,
    LPVOID buffer,
    DWORD bytesToRead,
    DWORD bytesRead)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::ReadFile, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result ? 1 : 0;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(file));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(buffer));
        record->Values32[0] = bytesToRead;
        record->Values32[1] = bytesRead;
        CopyBufferPreviewText(record->Text0, &record->Text0Length, sizeof(record->Text0), result ? buffer : nullptr, bytesRead);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitWriteFileEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE file,
    LPCVOID buffer,
    DWORD bytesToWrite,
    DWORD bytesWritten)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::WriteFile, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result ? 1 : 0;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(file));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(buffer));
        record->Values32[0] = bytesToWrite;
        record->Values32[1] = bytesWritten;
        CopyBufferPreviewText(record->Text0, &record->Text0Length, sizeof(record->Text0), buffer, bytesToWrite);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCloseHandleEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE handle)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CloseHandle, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result ? 1 : 0;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(handle));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitNtCreateFileEvent(
    NTSTATUS status,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
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
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::NtCreateFile, "ntdll.dll", start, end, errorCode);
        record->ReturnCode = static_cast<std::uint32_t>(status);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(fileHandle));
        HANDLE localHandle = nullptr;
        if (NT_SUCCESS(status) && ReadCurrentProcessValue(fileHandle, &localHandle))
        {
            record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(localHandle));
        }
        else
        {
            record->Values64[1] = record->Values64[0];
        }
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(objectAttributes));
        record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(ioStatusBlock));
        record->Values64[4] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(allocationSize));
        record->Values64[5] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(eaBuffer));
        record->Values32[0] = desiredAccess;
        record->Values32[1] = fileAttributes;
        record->Values32[2] = shareAccess;
        record->Values32[3] = createDisposition;
        record->Values32[4] = createOptions;
        record->Values32[5] = eaLength;
        record->Values32[6] = CopyObjectAttributesName(record->Text0, &record->Text0Length, sizeof(record->Text0), objectAttributes);
        record->Values32[7] = CopyIoStatusBlockText(record->Text1, &record->Text1Length, sizeof(record->Text1), ioStatusBlock);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitLoadLibraryWEvent(
    HMODULE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCWSTR fileName)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::LoadLibraryW, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        CopyWideText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitLoadLibraryAEvent(
    HMODULE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCSTR fileName)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::LoadLibraryA, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        CopyAsciiText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitLoadLibraryExWEvent(
    HMODULE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCWSTR fileName,
    HANDLE file,
    DWORD flags)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::LoadLibraryExW, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(file));
        record->Values32[0] = flags;
        CopyWideText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitLoadLibraryExAEvent(
    HMODULE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCSTR fileName,
    HANDLE file,
    DWORD flags)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::LoadLibraryExA, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(file));
        record->Values32[0] = flags;
        CopyAsciiText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitLdrLoadDllEvent(
    NTSTATUS status,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    PWSTR pathToFile,
    ULONG flags,
    PUNICODE_STRING moduleFileName,
    PHANDLE moduleHandle)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::LdrLoadDll, "ntdll.dll", start, end, errorCode);
        record->ReturnCode = static_cast<std::uint32_t>(status);
        record->Values32[0] = flags;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(moduleHandle));
        HANDLE loadedModule = nullptr;
        if (NT_SUCCESS(status) && ReadCurrentProcessValue(moduleHandle, &loadedModule))
        {
            record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(loadedModule));
        }
        CopyWideText(record->Text0, &record->Text0Length, sizeof(record->Text0), pathToFile);
        record->Values32[1] = CopyUnicodeStringText(record->Text1, &record->Text1Length, sizeof(record->Text1), moduleFileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetProcAddressEvent(
    FARPROC result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HMODULE module,
    LPCSTR procName)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetProcAddress, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(module));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(procName));

        const bool ordinal = IsOrdinalProcName(procName);
        record->Values32[0] = ordinal ? 1 : 0;
        if (ordinal)
        {
            record->Values32[1] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(procName) & 0xffffu);
            char ordinalText[32] = {};
            std::snprintf(ordinalText, sizeof(ordinalText), "ordinal:%lu", static_cast<unsigned long>(record->Values32[1]));
            CopyAsciiText(record->Text0, &record->Text0Length, sizeof(record->Text0), ordinalText);
            record->Values32[2] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
        }
        else
        {
            record->Values32[2] = CopyAnsiPointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), procName);
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitLdrGetProcedureAddressEvent(
    NTSTATUS status,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HMODULE module,
    PANSI_STRING functionName,
    ULONG ordinal,
    PVOID* functionAddress)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::LdrGetProcedureAddress, "ntdll.dll", start, end, errorCode);
        record->ReturnCode = static_cast<std::uint32_t>(status);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(module));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(functionName));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(functionAddress));
        record->Values32[0] = ordinal;
        record->Values32[1] = CopyAnsiStringText(record->Text0, &record->Text0Length, sizeof(record->Text0), functionName);

        PVOID resolvedAddress = nullptr;
        if (NT_SUCCESS(status) && ReadCurrentProcessValue(functionAddress, &resolvedAddress))
        {
            record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(resolvedAddress));
        }

        CommitTransportRecord(record, overheadStart);
    }
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

KnMonPeb* CurrentPeb()
{
#if defined(_M_X64)
    return reinterpret_cast<KnMonPeb*>(__readgsqword(0x60));
#elif defined(_M_IX86)
    return reinterpret_cast<KnMonPeb*>(__readfsdword(0x30));
#else
    return nullptr;
#endif
}

bool ImageRangeContains(const std::uint8_t* base, std::uint32_t size, const void* address, std::size_t bytes)
{
    bool contains = false;

    do
    {
        if (base == nullptr || address == nullptr || size == 0)
        {
            break;
        }

        const auto* current = static_cast<const std::uint8_t*>(address);
        if (current < base)
        {
            break;
        }

        const std::uintptr_t offset = static_cast<std::uintptr_t>(current - base);
        if (offset > size)
        {
            break;
        }

        contains = bytes <= (static_cast<std::size_t>(size) - static_cast<std::size_t>(offset));
    }
    while (false);

    return contains;
}

template <typename T>
T* ImageRvaToPointer(std::uint8_t* base, std::uint32_t size, DWORD rva, std::size_t minBytes = sizeof(T))
{
    T* result = nullptr;

    do
    {
        if (base == nullptr || rva == 0 || rva >= size)
        {
            break;
        }

        auto* pointer = reinterpret_cast<T*>(base + rva);
        if (!ImageRangeContains(base, size, pointer, minBytes))
        {
            break;
        }

        result = pointer;
    }
    while (false);

    return result;
}

bool ReadImageImportDirectory(HMODULE module, std::uint32_t size, IMAGE_IMPORT_DESCRIPTOR** imports)
{
    bool present = false;

    do
    {
        if (module == nullptr || imports == nullptr)
        {
            break;
        }

        *imports = nullptr;
        auto* base = reinterpret_cast<std::uint8_t*>(module);
        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (!ImageRangeContains(base, size, dosHeader, sizeof(*dosHeader)) || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            break;
        }

        if (dosHeader->e_lfanew <= 0 || static_cast<std::uint32_t>(dosHeader->e_lfanew) >= size)
        {
            break;
        }

        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
        if (!ImageRangeContains(base, size, ntHeaders, sizeof(*ntHeaders)) || ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            break;
        }

        const IMAGE_DATA_DIRECTORY& importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDirectory.VirtualAddress == 0 || importDirectory.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR))
        {
            break;
        }

        auto* importDescriptor = ImageRvaToPointer<IMAGE_IMPORT_DESCRIPTOR>(
            base,
            size,
            importDirectory.VirtualAddress,
            sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (importDescriptor == nullptr)
        {
            break;
        }

        *imports = importDescriptor;
        present = true;
    }
    while (false);

    return present;
}

bool ModuleHasImports(HMODULE module, std::uint32_t size)
{
    IMAGE_IMPORT_DESCRIPTOR* imports = nullptr;
    return ReadImageImportDirectory(module, size, &imports);
}

std::size_t CaptureModuleSnapshot(std::array<ModuleInfo, MaxModuleRecords>& modules, SweepStats* stats)
{
    std::size_t count = 0;

    do
    {
        KnMonPeb* peb = CurrentPeb();
        if (peb == nullptr || peb->Ldr == nullptr)
        {
            break;
        }

        LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
        LIST_ENTRY* current = head->Flink;
        while (current != nullptr && current != head && count < modules.size())
        {
            auto* entry = CONTAINING_RECORD(current, KnMonLdrDataTableEntry, InMemoryOrderLinks);
            current = current->Flink;

            if (entry == nullptr || entry->DllBase == nullptr)
            {
                continue;
            }

            ModuleInfo& module = modules[count];
            module = {};
            module.Base = static_cast<HMODULE>(entry->DllBase);
            module.SizeOfImage = entry->SizeOfImage;
            CopyWideCountText(module.FullPath, sizeof(module.FullPath), entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(wchar_t));
            CopyWideCountText(module.Name, sizeof(module.Name), entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(wchar_t));
            if (module.Name[0] == '\0')
            {
                CopyAsciiText(module.Name, nullptr, sizeof(module.Name), FileNameFromPathText(module.FullPath));
            }

            LowerAsciiInPlace(module.Name);
            LowerAsciiInPlace(module.FullPath);
            module.IsAgent = module.Base == g_agentModule || std::strcmp(module.Name, KNMON_AGENT_DLL_NAME) == 0;
            module.IsSystem = IsWindowsSystemModule(module);
            module.HasImports = ModuleHasImports(module.Base, module.SizeOfImage);
            module.Eligible = !module.IsAgent && !module.IsSystem && module.HasImports;

            if (stats != nullptr)
            {
                ++stats->ScannedModules;
                if (module.Eligible)
                {
                    ++stats->EligibleModules;
                }
                else
                {
                    ++stats->SkippedModules;
                }
            }

            ++count;
        }
    }
    while (false);

    return count;
}

HookRecord* FindHookRecordByThunkNoLock(ULONG_PTR* thunkAddress)
{
    HookRecord* result = nullptr;

    if (thunkAddress != nullptr)
    {
        for (std::size_t index = 0; index < g_hookRecordCount; ++index)
        {
            if (g_hookRecords[index].ThunkAddress == thunkAddress)
            {
                result = &g_hookRecords[index];
                break;
            }
        }
    }

    return result;
}

bool AppendHookRecordNoLock(
    const ModuleInfo& ownerModule,
    const char* importModuleName,
    const char* apiName,
    ULONG_PTR* thunkAddress,
    void* originalFunction,
    void* replacementFunction,
    bool* duplicate)
{
    bool appended = false;

    do
    {
        if (duplicate != nullptr)
        {
            *duplicate = false;
        }

        if (FindHookRecordByThunkNoLock(thunkAddress) != nullptr)
        {
            if (duplicate != nullptr)
            {
                *duplicate = true;
            }
            break;
        }

        if (g_hookRecordCount >= g_hookRecords.size())
        {
            break;
        }

        HookRecord& record = g_hookRecords[g_hookRecordCount];
        CopyAsciiText(record.ApiName, nullptr, sizeof(record.ApiName), apiName);
        CopyAsciiText(record.ImportModuleName, nullptr, sizeof(record.ImportModuleName), importModuleName);
        CopyAsciiText(record.OwnerModuleName, nullptr, sizeof(record.OwnerModuleName), ownerModule.Name);
        record.OwnerModule = ownerModule.Base;
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

HANDLE WINAPI HookedCreateFileW(LPCWSTR fileName, DWORD desiredAccess, DWORD shareMode, LPSECURITY_ATTRIBUTES securityAttributes, DWORD creationDisposition, DWORD flagsAndAttributes, HANDLE templateFile);
HANDLE WINAPI HookedCreateFileA(LPCSTR fileName, DWORD desiredAccess, DWORD shareMode, LPSECURITY_ATTRIBUTES securityAttributes, DWORD creationDisposition, DWORD flagsAndAttributes, HANDLE templateFile);
BOOL WINAPI HookedReadFile(HANDLE file, LPVOID buffer, DWORD bytesToRead, LPDWORD bytesRead, LPOVERLAPPED overlapped);
BOOL WINAPI HookedWriteFile(HANDLE file, LPCVOID buffer, DWORD bytesToWrite, LPDWORD bytesWritten, LPOVERLAPPED overlapped);
BOOL WINAPI HookedCloseHandle(HANDLE handle);
HMODULE WINAPI HookedLoadLibraryW(LPCWSTR fileName);
HMODULE WINAPI HookedLoadLibraryA(LPCSTR fileName);
HMODULE WINAPI HookedLoadLibraryExW(LPCWSTR fileName, HANDLE file, DWORD flags);
HMODULE WINAPI HookedLoadLibraryExA(LPCSTR fileName, HANDLE file, DWORD flags);
FARPROC WINAPI HookedGetProcAddress(HMODULE module, LPCSTR procName);
NTSTATUS NTAPI HookedNtCreateFile(PHANDLE fileHandle, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, PIO_STATUS_BLOCK ioStatusBlock, PLARGE_INTEGER allocationSize, ULONG fileAttributes, ULONG shareAccess, ULONG createDisposition, ULONG createOptions, PVOID eaBuffer, ULONG eaLength);
NTSTATUS NTAPI HookedLdrLoadDll(PWSTR pathToFile, ULONG flags, PUNICODE_STRING moduleFileName, PHANDLE moduleHandle);
NTSTATUS NTAPI HookedLdrGetProcedureAddress(HMODULE module, PANSI_STRING functionName, ULONG ordinal, PVOID* functionAddress);

std::array<HookDefinition, HookDefinitionCount> BuildHookDefinitions()
{
    return {
        HookDefinition { "kernel32.dll", "CreateFileW", reinterpret_cast<void*>(HookedCreateFileW), reinterpret_cast<void**>(&g_originalCreateFileW), true, true, false, 0 },
        HookDefinition { "kernel32.dll", "CreateFileA", reinterpret_cast<void*>(HookedCreateFileA), reinterpret_cast<void**>(&g_originalCreateFileA), true, true, false, 0 },
        HookDefinition { "kernel32.dll", "ReadFile", reinterpret_cast<void*>(HookedReadFile), reinterpret_cast<void**>(&g_originalReadFile), true, true, false, 0 },
        HookDefinition { "kernel32.dll", "WriteFile", reinterpret_cast<void*>(HookedWriteFile), reinterpret_cast<void**>(&g_originalWriteFile), true, true, false, 0 },
        HookDefinition { "kernel32.dll", "CloseHandle", reinterpret_cast<void*>(HookedCloseHandle), reinterpret_cast<void**>(&g_originalCloseHandle), true, true, false, 0 },
        HookDefinition { "ntdll.dll", "NtCreateFile", reinterpret_cast<void*>(HookedNtCreateFile), reinterpret_cast<void**>(&g_originalNtCreateFile), true, true, false, 0 },
        HookDefinition { "kernel32.dll", "LoadLibraryW", reinterpret_cast<void*>(HookedLoadLibraryW), reinterpret_cast<void**>(&g_originalLoadLibraryW), false, true, true, 0 },
        HookDefinition { "kernel32.dll", "LoadLibraryA", reinterpret_cast<void*>(HookedLoadLibraryA), reinterpret_cast<void**>(&g_originalLoadLibraryA), false, true, true, 0 },
        HookDefinition { "kernel32.dll", "LoadLibraryExW", reinterpret_cast<void*>(HookedLoadLibraryExW), reinterpret_cast<void**>(&g_originalLoadLibraryExW), false, true, true, 0 },
        HookDefinition { "kernel32.dll", "LoadLibraryExA", reinterpret_cast<void*>(HookedLoadLibraryExA), reinterpret_cast<void**>(&g_originalLoadLibraryExA), false, true, true, 0 },
        HookDefinition { "ntdll.dll", "LdrLoadDll", reinterpret_cast<void*>(HookedLdrLoadDll), reinterpret_cast<void**>(&g_originalLdrLoadDll), false, true, true, 0 },
        HookDefinition { "kernel32.dll", "GetProcAddress", reinterpret_cast<void*>(HookedGetProcAddress), reinterpret_cast<void**>(&g_originalGetProcAddress), false, true, false, 0 },
        HookDefinition { "ntdll.dll", "LdrGetProcedureAddress", reinterpret_cast<void*>(HookedLdrGetProcedureAddress), reinterpret_cast<void**>(&g_originalLdrGetProcedureAddress), false, true, false, 0 },
    };
}

bool ImportNameMatches(std::uint8_t* base, std::uint32_t size, IMAGE_THUNK_DATA* originalThunk, const char* functionName)
{
    bool matches = false;

    do
    {
        if (base == nullptr || originalThunk == nullptr || functionName == nullptr)
        {
            break;
        }

        if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal))
        {
            break;
        }

        auto* importByName = ImageRvaToPointer<IMAGE_IMPORT_BY_NAME>(
            base,
            size,
            static_cast<DWORD>(originalThunk->u1.AddressOfData),
            sizeof(WORD) + 1);
        if (importByName == nullptr)
        {
            break;
        }

        if (std::strcmp(reinterpret_cast<const char*>(importByName->Name), functionName) == 0)
        {
            matches = true;
        }
    }
    while (false);

    return matches;
}

void PatchImportInModule(ModuleInfo& module, HookDefinition& definition, SweepStats& stats)
{
    do
    {
        if (!module.Eligible || definition.ImportModuleName == nullptr || definition.ApiName == nullptr || definition.ReplacementFunction == nullptr)
        {
            break;
        }

        if (definition.OriginalFunction == nullptr || *definition.OriginalFunction == nullptr)
        {
            break;
        }

        auto* base = reinterpret_cast<std::uint8_t*>(module.Base);
        IMAGE_IMPORT_DESCRIPTOR* importDescriptor = nullptr;
        if (!ReadImageImportDirectory(module.Base, module.SizeOfImage, &importDescriptor))
        {
            break;
        }

        for (; importDescriptor->Name != 0; ++importDescriptor)
        {
            const char* importedModuleName = ImageRvaToPointer<char>(base, module.SizeOfImage, importDescriptor->Name, 1);
            if (importedModuleName == nullptr || _stricmp(importedModuleName, definition.ImportModuleName) != 0)
            {
                continue;
            }

            auto* firstThunk = ImageRvaToPointer<IMAGE_THUNK_DATA>(base, module.SizeOfImage, importDescriptor->FirstThunk);
            if (firstThunk == nullptr)
            {
                continue;
            }

            auto* originalThunk = ImageRvaToPointer<IMAGE_THUNK_DATA>(base, module.SizeOfImage, importDescriptor->OriginalFirstThunk);
            if (importDescriptor->OriginalFirstThunk == 0)
            {
                originalThunk = firstThunk;
            }

            if (originalThunk == nullptr)
            {
                continue;
            }

            for (
                std::size_t thunkIndex = 0;
                ImageRangeContains(base, module.SizeOfImage, &originalThunk[thunkIndex], sizeof(IMAGE_THUNK_DATA)) &&
                    ImageRangeContains(base, module.SizeOfImage, &firstThunk[thunkIndex], sizeof(IMAGE_THUNK_DATA)) &&
                    originalThunk[thunkIndex].u1.AddressOfData != 0;
                ++thunkIndex)
            {
                if (!ImportNameMatches(base, module.SizeOfImage, &originalThunk[thunkIndex], definition.ApiName))
                {
                    continue;
                }

                auto* thunkAddress = reinterpret_cast<ULONG_PTR*>(&firstThunk[thunkIndex].u1.Function);
                if (FindHookRecordByThunkNoLock(thunkAddress) != nullptr || *thunkAddress == reinterpret_cast<ULONG_PTR>(definition.ReplacementFunction))
                {
                    ++stats.DuplicateSlots;
                    continue;
                }

                void* originalFunction = reinterpret_cast<void*>(*thunkAddress);
                DWORD oldProtect = 0;
                if (!VirtualProtect(thunkAddress, sizeof(void*), PAGE_READWRITE, &oldProtect))
                {
                    ++stats.FailedSlots;
                    continue;
                }

                *thunkAddress = reinterpret_cast<ULONG_PTR>(definition.ReplacementFunction);
                FlushInstructionCache(GetCurrentProcess(), thunkAddress, sizeof(void*));

                DWORD ignored = 0;
                VirtualProtect(thunkAddress, sizeof(void*), oldProtect, &ignored);

                bool duplicate = false;
                if (AppendHookRecordNoLock(module, definition.ImportModuleName, definition.ApiName, thunkAddress, originalFunction, definition.ReplacementFunction, &duplicate))
                {
                    ++definition.LastPatchedSlots;
                    ++stats.PatchedSlots;
                }
                else
                {
                    if (VirtualProtect(thunkAddress, sizeof(void*), PAGE_READWRITE, &oldProtect))
                    {
                        *thunkAddress = reinterpret_cast<ULONG_PTR>(originalFunction);
                        FlushInstructionCache(GetCurrentProcess(), thunkAddress, sizeof(void*));
                        VirtualProtect(thunkAddress, sizeof(void*), oldProtect, &ignored);
                    }

                    if (duplicate)
                    {
                        ++stats.DuplicateSlots;
                    }
                    else
                    {
                        ++stats.FailedSlots;
                        InterlockedIncrement(&g_failedHooks);
                    }
                }
            }
        }
    }
    while (false);
}

void ResolveHookDefinitions(std::array<HookDefinition, HookDefinitionCount>& definitions)
{
    for (HookDefinition& definition : definitions)
    {
        if (definition.OriginalFunction != nullptr && *definition.OriginalFunction == nullptr)
        {
            *definition.OriginalFunction = ResolveExport(definition.ImportModuleName, definition.ApiName);
        }
    }
}

bool AddressBelongsToLoadedModule(const void* address)
{
    bool loaded = false;
    HMODULE module = nullptr;

    if (address != nullptr)
    {
        loaded = GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(address),
            &module) != FALSE;
    }

    return loaded;
}

bool SweepLoadedModules(const char* reason, bool reportHookStatus, SweepStats* outStats)
{
    bool requiredCoverage = true;
    SweepStats stats = {};
    std::array<ModuleInfo, MaxModuleRecords> modules = {};
    std::array<HookDefinition, HookDefinitionCount> definitions = BuildHookDefinitions();
    ResolveHookDefinitions(definitions);
    const std::size_t moduleCount = CaptureModuleSnapshot(modules, &stats);

    AcquireSRWLockExclusive(&g_hookLock);
    for (std::size_t moduleIndex = 0; moduleIndex < moduleCount; ++moduleIndex)
    {
        ModuleInfo& module = modules[moduleIndex];
        const std::uint32_t patchedBefore = stats.PatchedSlots;

        for (HookDefinition& definition : definitions)
        {
            PatchImportInModule(module, definition, stats);
        }

        if (stats.PatchedSlots > patchedBefore)
        {
            ++stats.ModulesWithPatches;
        }
    }
    ReleaseSRWLockExclusive(&g_hookLock);

    if (reportHookStatus)
    {
        SendModuleInventoryStatus(stats);
    }

    SendIatSweepStatus(reason, stats);

    for (HookDefinition& definition : definitions)
    {
        if (reportHookStatus && definition.Required && definition.LastPatchedSlots == 0)
        {
            requiredCoverage = false;
            InterlockedIncrement(&g_failedHooks);
        }

        if (reportHookStatus && definition.ReportStatus)
        {
            if (definition.LastPatchedSlots > 0)
            {
                std::ostringstream message;
                message << "Loaded-module IAT sweep patched " << definition.LastPatchedSlots << " import slot(s).";
                SendHookStatus(definition.ImportModuleName, definition.ApiName, true, message.str());
            }
            else if (definition.Required)
            {
                SendHookStatus(definition.ImportModuleName, definition.ApiName, false, "Required IAT entry was not found in eligible loaded modules.");
            }
        }
    }

    if (outStats != nullptr)
    {
        *outStats = stats;
    }

    return requiredCoverage;
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

        if (!AddressBelongsToLoadedModule(record.ThunkAddress))
        {
            record.Restored = true;
            ++counts.RestoredHooks;
            continue;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect(record.ThunkAddress, sizeof(void*), PAGE_READWRITE, &oldProtect))
        {
            if (!AddressBelongsToLoadedModule(record.ThunkAddress))
            {
                record.Restored = true;
                ++counts.RestoredHooks;
                continue;
            }

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
    if (HooksEnabled())
    {
        EmitCreateFileWEvent(result, eventError, start, end, fileName, desiredAccess, shareMode, creationDisposition);
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
    if (HooksEnabled())
    {
        EmitCreateFileAEvent(result, eventError, start, end, fileName, desiredAccess, shareMode, creationDisposition);
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
    if (HooksEnabled())
    {
        EmitReadFileEvent(result, eventError, start, end, file, buffer, bytesToRead, actualBytes);
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
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalWriteFile(file, buffer, bytesToWrite, bytesWritten, overlapped);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD actualBytes = bytesWritten == nullptr ? 0 : *bytesWritten;
    const DWORD eventError = result ? 0 : lastError;
    if (HooksEnabled())
    {
        EmitWriteFileEvent(result, eventError, start, end, file, buffer, bytesToWrite, actualBytes);
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
    if (HooksEnabled())
    {
        EmitCloseHandleEvent(result, eventError, start, end, handle);
    }

    SetLastError(lastError);
    return result;
}

HMODULE WINAPI HookedLoadLibraryW(LPCWSTR fileName)
{
    if (g_inHook || !HooksEnabled() || g_originalLoadLibraryW == nullptr)
    {
        if (g_originalLoadLibraryW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalLoadLibraryW(fileName);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HMODULE result = g_originalLoadLibraryW(fileName);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitLoadLibraryWEvent(result, eventError, start, end, fileName);
        if (result != nullptr)
        {
            SweepLoadedModules("dynamic_load", false, nullptr);
        }
    }

    SetLastError(lastError);
    return result;
}

HMODULE WINAPI HookedLoadLibraryA(LPCSTR fileName)
{
    if (g_inHook || !HooksEnabled() || g_originalLoadLibraryA == nullptr)
    {
        if (g_originalLoadLibraryA == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalLoadLibraryA(fileName);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HMODULE result = g_originalLoadLibraryA(fileName);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitLoadLibraryAEvent(result, eventError, start, end, fileName);
        if (result != nullptr)
        {
            SweepLoadedModules("dynamic_load", false, nullptr);
        }
    }

    SetLastError(lastError);
    return result;
}

HMODULE WINAPI HookedLoadLibraryExW(LPCWSTR fileName, HANDLE file, DWORD flags)
{
    if (g_inHook || !HooksEnabled() || g_originalLoadLibraryExW == nullptr)
    {
        if (g_originalLoadLibraryExW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalLoadLibraryExW(fileName, file, flags);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HMODULE result = g_originalLoadLibraryExW(fileName, file, flags);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitLoadLibraryExWEvent(result, eventError, start, end, fileName, file, flags);
        if (result != nullptr)
        {
            SweepLoadedModules("dynamic_load", false, nullptr);
        }
    }

    SetLastError(lastError);
    return result;
}

HMODULE WINAPI HookedLoadLibraryExA(LPCSTR fileName, HANDLE file, DWORD flags)
{
    if (g_inHook || !HooksEnabled() || g_originalLoadLibraryExA == nullptr)
    {
        if (g_originalLoadLibraryExA == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalLoadLibraryExA(fileName, file, flags);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HMODULE result = g_originalLoadLibraryExA(fileName, file, flags);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitLoadLibraryExAEvent(result, eventError, start, end, fileName, file, flags);
        if (result != nullptr)
        {
            SweepLoadedModules("dynamic_load", false, nullptr);
        }
    }

    SetLastError(lastError);
    return result;
}

FARPROC WINAPI HookedGetProcAddress(HMODULE module, LPCSTR procName)
{
    if (g_inHook || !HooksEnabled() || g_originalGetProcAddress == nullptr)
    {
        if (g_originalGetProcAddress == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalGetProcAddress(module, procName);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    FARPROC result = g_originalGetProcAddress(module, procName);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitGetProcAddressEvent(result, eventError, start, end, module, procName);
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
    if (HooksEnabled())
    {
        EmitNtCreateFileEvent(
            status,
            eventError,
            start,
            end,
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

    return status;
}

NTSTATUS NTAPI HookedLdrLoadDll(PWSTR pathToFile, ULONG flags, PUNICODE_STRING moduleFileName, PHANDLE moduleHandle)
{
    if (g_inHook || !HooksEnabled() || g_originalLdrLoadDll == nullptr)
    {
        if (g_originalLdrLoadDll == nullptr)
        {
            return static_cast<NTSTATUS>(0xC000007AL);
        }

        return g_originalLdrLoadDll(pathToFile, flags, moduleFileName, moduleHandle);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    NTSTATUS status = g_originalLdrLoadDll(pathToFile, flags, moduleFileName, moduleHandle);
    QueryPerformanceCounter(&end);

    const DWORD eventError = NtStatusToDosError(status);
    if (HooksEnabled())
    {
        EmitLdrLoadDllEvent(status, eventError, start, end, pathToFile, flags, moduleFileName, moduleHandle);
        if (NT_SUCCESS(status))
        {
            SweepLoadedModules("dynamic_load", false, nullptr);
        }
    }

    return status;
}

NTSTATUS NTAPI HookedLdrGetProcedureAddress(HMODULE module, PANSI_STRING functionName, ULONG ordinal, PVOID* functionAddress)
{
    if (g_inHook || !HooksEnabled() || g_originalLdrGetProcedureAddress == nullptr)
    {
        if (g_originalLdrGetProcedureAddress == nullptr)
        {
            return static_cast<NTSTATUS>(0xC000007AL);
        }

        return g_originalLdrGetProcedureAddress(module, functionName, ordinal, functionAddress);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    NTSTATUS status = g_originalLdrGetProcedureAddress(module, functionName, ordinal, functionAddress);
    QueryPerformanceCounter(&end);

    const DWORD eventError = NtStatusToDosError(status);
    if (HooksEnabled())
    {
        EmitLdrGetProcedureAddressEvent(status, eventError, start, end, module, functionName, ordinal, functionAddress);
    }

    return status;
}

bool InstallHooks()
{
    const bool allInstalled = SweepLoadedModules("initial", true, nullptr);

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
    CloseTransport();
    CloseAgentPipe();
}

DWORD WINAPI AgentWorker(void*)
{
    const std::wstring pipeName = ReadEnv(L"KNMON_AGENT_PIPE");
    const std::wstring transportName = ReadEnv(L"KNMON_TRANSPORT_NAME");
    const bool transportRequired = EnvEnabled(L"KNMON_TRANSPORT_REQUIRED");
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

        if (transportRequired && !OpenTransport(transportName))
        {
            SendHookStatus("knmon-transport", "shared_memory", false, "Required shared-memory transport could not be opened by the agent.");
            SendDroppedEvents();
            ShutdownAgent("transport_open_failed", AgentLifecycleState::Failed);
            break;
        }

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
        g_agentModule = moduleHandle;
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
