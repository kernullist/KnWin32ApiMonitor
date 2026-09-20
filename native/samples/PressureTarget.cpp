#include <Windows.h>
#include <knmon/common/AttachConfig.h>
#include <knmon/common/Protocol.h>
#include "../tests/ProcessResourceSamples.h"
#include <array>
#include <cstdio>
#include <string>

namespace
{
struct Worker
{
    HANDLE Start = nullptr;
    DWORD Duration = 0;
    std::uint64_t Calls = 0;
    std::uint64_t Errors = 0;
};

DWORD WINAPI RunWorker(void* argument)
{
    auto& worker = *static_cast<Worker*>(argument);
    if (WaitForSingleObject(worker.Start, 5000) != WAIT_OBJECT_0)
    {
        ++worker.Errors;
    }
    else
    {
        const auto deadline = GetTickCount64() + worker.Duration;
        do
        {
            SetLastError(7319);
            const BOOL result = CloseHandle(nullptr);
            const DWORD error = GetLastError();
            ++worker.Calls;
            if (result || error != ERROR_INVALID_HANDLE)
            {
                ++worker.Errors;
            }
        }
        while (GetTickCount64() < deadline);
    }
    return 0;
}

bool WaitForAgent()
{
    bool ready = false;
    const auto deadline = GetTickCount64() + 5000;
    do
    {
        const HMODULE agent = GetModuleHandleW(sizeof(void*) == 8 ? L"knmon-agent64.dll" : L"knmon-agent32.dll");
        using Query = DWORD(WINAPI*)(knmon::KnMonAgentStateV1*);
        const auto query = agent == nullptr ? nullptr : reinterpret_cast<Query>(GetProcAddress(agent, "KnMonAgentQueryState"));
        if (query != nullptr)
        {
            knmon::KnMonAgentStateV1 state;
            state.StructSize = sizeof(state);
            ready = query(&state) == 0 && state.HooksEnabled != 0 &&
                state.LifecycleState == static_cast<std::uint32_t>(knmon::KnMonAgentLifecycleState::Running);
        }
        if (!ready)
        {
            Sleep(10);
        }
    }
    while (!ready && GetTickCount64() < deadline);
    return ready;
}
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 4)
    {
        return 2;
    }
    wchar_t* end = nullptr;
    const DWORD duration = wcstoul(argv[2], &end, 10);
    const bool observed = wcscmp(argv[3], L"observed") == 0;
    if (*end != L'\0' || duration < 2000 || duration > 30000 ||
        (!observed && wcscmp(argv[3], L"original") != 0) || (observed && !WaitForAgent()))
    {
        return 3;
    }
    HANDLE output = CreateFileW(argv[1], GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (output == INVALID_HANDLE_VALUE)
    {
        return 4;
    }
    const knmon::KnMonTransportHeader* header = nullptr;
    if (observed)
    {
        std::array<wchar_t, 256> name = {};
        const DWORD length = GetEnvironmentVariableW(L"KNMON_TRANSPORT_NAME", name.data(), static_cast<DWORD>(name.size()));
        HANDLE mapping = length > 0 && length < name.size() ? OpenFileMappingW(FILE_MAP_READ, FALSE, name.data()) : nullptr;
        if (mapping != nullptr)
        {
            header = static_cast<const knmon::KnMonTransportHeader*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, sizeof(*header)));
            CloseHandle(mapping);
        }
        const auto architecture = sizeof(void*) == 8 ? knmon::KnMonAgentArchitecture::X64 : knmon::KnMonAgentArchitecture::X86;
        if (header == nullptr || header->Magic != knmon::KnMonTransportMagic ||
            header->AbiVersion != knmon::KnMonTransportAbiVersion || header->HeaderSize != sizeof(*header) ||
            header->RecordSize != sizeof(knmon::KnMonTransportRecord) || header->Capacity != 64 ||
            header->Architecture != static_cast<std::uint32_t>(architecture))
        {
            if (header != nullptr)
            {
                UnmapViewOfFile(header);
            }
            CloseHandle(output);
            return 5;
        }
    }
    HANDLE start = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::array<Worker, 4> workers = {};
    std::array<HANDLE, 4> threads = {};
    bool valid = start != nullptr;
    for (std::size_t index = 0; index < workers.size() && valid; ++index)
    {
        workers[index].Start = start;
        workers[index].Duration = duration;
        threads[index] = CreateThread(nullptr, 0, RunWorker, &workers[index], 0, nullptr);
        valid = threads[index] != nullptr;
    }
    if (!valid)
    {
        // Worker contexts remain alive until the process exits on this failure path.
        ExitProcess(6);
    }
    // The fixture has no active producers before Start or after all workers join.
    const auto beginSequence = header == nullptr ? 0 : header->ProducerSequence;
    const auto beginDrops = header == nullptr ? 0 : header->DroppedEvents;
    ProcessResourceSamples resources;
    resources.Sample();
    const auto started = GetTickCount64();
    if (!SetEvent(start))
    {
        ExitProcess(6);
    }
    DWORD waited = WAIT_TIMEOUT;
    while (waited == WAIT_TIMEOUT && GetTickCount64() - started < duration + 5000)
    {
        waited = WaitForMultipleObjects(static_cast<DWORD>(threads.size()), threads.data(), TRUE, 50);
        resources.Sample();
    }
    if (waited != WAIT_OBJECT_0)
    {
        ExitProcess(7);
    }
    std::uint64_t calls = 0;
    std::uint64_t errors = 0;
    for (std::size_t index = 0; index < workers.size(); ++index)
    {
        calls += workers[index].Calls;
        errors += workers[index].Errors;
        valid = CloseHandle(threads[index]) != FALSE && valid;
    }
    valid = CloseHandle(start) != FALSE && valid;
    const auto endSequence = header == nullptr ? 0 : header->ProducerSequence;
    const auto endDrops = header == nullptr ? 0 : header->DroppedEvents;
    if (header != nullptr)
    {
        UnmapViewOfFile(header);
    }
    const std::string report = "{\"schemaVersion\":1,\"durationMs\":" + std::to_string(duration) +
        ",\"threads\":4,\"workloadCalls\":" + std::to_string(calls) + ",\"errors\":" + std::to_string(errors) +
        ",\"windowCalls\":" + std::to_string(calls + threads.size() + 1) +
        ",\"beginSequence\":" + std::to_string(beginSequence) + ",\"endSequence\":" + std::to_string(endSequence) +
        ",\"beginDrops\":" + std::to_string(beginDrops) + ",\"endDrops\":" + std::to_string(endDrops) +
        ",\"resources\":" + resources.Json() + "}";
    DWORD written = 0;
    valid = WriteFile(output, report.data(), static_cast<DWORD>(report.size()), &written, nullptr) && written == report.size() && valid;
    valid = CloseHandle(output) != FALSE && valid;
    return valid && errors == 0 && !resources.Failed ? 0 : 8;
}
