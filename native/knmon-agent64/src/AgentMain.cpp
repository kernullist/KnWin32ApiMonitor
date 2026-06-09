#include <knmon/common/Protocol.h>

#include <Windows.h>
#include <winternl.h>

#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iomanip>
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

template <typename T>
bool ReadCurrentProcessValue(const T* address, T* value);

std::uint64_t DurationUs(const LARGE_INTEGER& start, const LARGE_INTEGER& end);

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
