#include "CorpusProtocol.h"
#include <psapi.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>

volatile LONG g_corpusMarker = 0;
extern "C" __declspec(dllexport) __declspec(noinline) void __cdecl KnMonCorpusBegin()
{
    InterlockedIncrement(&g_corpusMarker);
}
extern "C" __declspec(dllexport) __declspec(noinline) void __cdecl KnMonCorpusEnd()
{
    InterlockedIncrement(&g_corpusMarker);
}

std::uint64_t FileTimeBits(const FILETIME& value)
{
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

int wmain(int argc, wchar_t** argv)
{
    int exitCode = 1;
    do
    {
        if (argc < 3 || argc > 4)
        {
            break;
        }
        wchar_t* end = nullptr;
        const auto iterations = wcstoul(argv[2], &end, 10);
        if (*end != L'\0' || iterations == 0 || iterations > 10000)
        {
            break;
        }
        const std::filesystem::path directory(argv[1]);
        const auto reportPath = directory / L"oracle.json";
        const auto dataPath = directory / L"corpus.bin";
        if (!std::filesystem::is_directory(directory) || std::filesystem::exists(reportPath) || std::filesystem::exists(dataPath))
        {
            break;
        }
        CorpusEtw etw;
        const bool trace = argc == 4 && std::wstring(argv[3]) == L"--etw-private";
        const bool failExit = argc == 4 && std::wstring(argv[3]) == L"--nonzero-exit";
        if (argc == 4 && !trace && !failExit)
        {
            break;
        }
        if (trace && !etw.Start((directory / L"corpus.etl").wstring()))
        {
            return static_cast<int>(etw.Status);
        }
        std::vector<CorpusEvent> events;
        events.reserve(iterations * 7 + 2);
        std::array<unsigned char, 64> input;
        for (std::size_t index = 0; index < input.size(); ++index)
        {
            input[index] = static_cast<unsigned char>(index + 32);
        }
        LARGE_INTEGER frequency = {};
        LARGE_INTEGER begin = {};
        LARGE_INTEGER finish = {};
        LARGE_INTEGER callStart = {};
        FILETIME created = {}, exited = {}, kernelBefore = {}, userBefore = {}, kernelAfter = {}, userAfter = {};
        QueryPerformanceFrequency(&frequency);
        const auto record = [&](std::uint32_t api, bool success, std::uint32_t bytes = 0, const unsigned char* preview = nullptr)
        {
            const DWORD error = GetLastError();
            LARGE_INTEGER now = {};
            QueryPerformanceCounter(&now);
            CorpusEvent event;
            event.Sequence = static_cast<std::uint32_t>(events.size());
            event.Api = api;
            event.Success = success ? 1 : 0;
            event.Error = error;
            event.StartQpc = callStart.QuadPart;
            event.EndQpc = now.QuadPart;
            event.ByteCount = bytes;
            event.PreviewBytes = preview == nullptr ? 0 : (std::min)(bytes, 16U);
            if (event.PreviewBytes != 0)
            {
                std::memcpy(event.Preview, preview, event.PreviewBytes);
            }
            events.push_back(event);
            etw.Write(event);
        };
        bool correct = true;
        KnMonCorpusBegin();
        correct = GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernelBefore, &userBefore) != FALSE;
        QueryPerformanceCounter(&begin);
        for (unsigned long iteration = 0; iteration < iterations; ++iteration)
        {
            SetLastError(1101);
            QueryPerformanceCounter(&callStart);
            const HANDLE file = CreateFileW(dataPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
            record(0, file != INVALID_HANDLE_VALUE);
            if (file == INVALID_HANDLE_VALUE)
            {
                correct = false;
                break;
            }
            DWORD written = 0;
            SetLastError(1102);
            QueryPerformanceCounter(&callStart);
            const BOOL wrote = WriteFile(file, input.data(), static_cast<DWORD>(input.size()), &written, nullptr);
            record(1, wrote != FALSE, written, input.data());
            LARGE_INTEGER zero = {};
            correct = correct && wrote && written == input.size();
            correct = SetFilePointerEx(file, zero, nullptr, FILE_BEGIN) && correct;
            std::array<unsigned char, 64> output = {};
            DWORD read = 0;
            SetLastError(1103);
            QueryPerformanceCounter(&callStart);
            const BOOL got = ReadFile(file, output.data(), static_cast<DWORD>(output.size()), &read, nullptr);
            record(2, got != FALSE, read, output.data());
            correct = correct && got && read == input.size() && output == input;
            SetLastError(1104);
            QueryPerformanceCounter(&callStart);
            const BOOL eof = ReadFile(file, output.data(), static_cast<DWORD>(output.size()), &read, nullptr);
            record(2, eof != FALSE, read, output.data());
            correct = correct && eof && read == 0;
            SetLastError(1105);
            QueryPerformanceCounter(&callStart);
            const BOOL closed = CloseHandle(file);
            record(3, closed != FALSE);
            correct = correct && closed;
            SetLastError(1106);
            QueryPerformanceCounter(&callStart);
            void* memory = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            record(4, memory != nullptr);
            correct = correct && memory != nullptr;
            SetLastError(1107);
            QueryPerformanceCounter(&callStart);
            const BOOL freed = VirtualFree(memory, 0, MEM_RELEASE);
            record(5, freed != FALSE);
            correct = correct && freed;
            Sleep(0);
        }
        std::array<unsigned char, 16> output = {};
        DWORD count = 0;
        SetLastError(1108);
        QueryPerformanceCounter(&callStart);
        const BOOL invalidRead = ReadFile(INVALID_HANDLE_VALUE, output.data(), static_cast<DWORD>(output.size()), &count, nullptr);
        record(2, invalidRead != FALSE);
        correct = correct && !invalidRead;
        const auto missing = directory / L"missing-file.bin";
        SetLastError(1109);
        QueryPerformanceCounter(&callStart);
        const HANDLE invalidFile = CreateFileW(missing.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        record(0, invalidFile != INVALID_HANDLE_VALUE);
        correct = correct && invalidFile == INVALID_HANDLE_VALUE;
        QueryPerformanceCounter(&finish);
        correct = GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernelAfter, &userAfter) && correct;
        KnMonCorpusEnd();
        PROCESS_MEMORY_COUNTERS memory = {};
        memory.cb = sizeof(memory);
        correct = GetProcessMemoryInfo(GetCurrentProcess(), &memory, sizeof(memory)) && correct;
        etw.Stop();
        std::ofstream stream(reportPath, std::ios::binary);
        stream << "{\"schemaVersion\":1,\"correct\":" << (correct ? "true" : "false")
            << ",\"pid\":" << GetCurrentProcessId() << ",\"tid\":" << GetCurrentThreadId()
            << ",\"iterations\":" << iterations << ",\"qpcFrequency\":\"" << frequency.QuadPart
            << "\",\"startQpc\":\"" << begin.QuadPart << "\",\"endQpc\":\"" << finish.QuadPart
            << "\",\"kernelCpu100ns\":\"" << FileTimeBits(kernelAfter) - FileTimeBits(kernelBefore)
            << "\",\"userCpu100ns\":\"" << FileTimeBits(userAfter) - FileTimeBits(userBefore)
            << "\",\"workingSetBytes\":" << memory.WorkingSetSize << ",\"peakWorkingSetBytes\":" << memory.PeakWorkingSetSize
            << ",\"etwEnabled\":" << (trace ? "true" : "false") << ",\"etwStatus\":" << etw.Status
            << ",\"etwWriteFailures\":" << etw.WriteFailures << ",\"etwEventsLost\":" << etw.EventsLost
            << ",\"etwBuffersLost\":" << etw.BuffersLost << ",\"events\":[";
        for (const auto& event : events)
        {
            stream << (event.Sequence == 0 ? "" : ",") << "{\"sequence\":" << event.Sequence
                << ",\"api\":\"" << CorpusApiNames[event.Api] << "\",\"success\":" << (event.Success ? "true" : "false")
                << ",\"error\":" << event.Error << ",\"byteCount\":" << event.ByteCount << ",\"preview\":\"";
            for (std::uint32_t index = 0; index < event.PreviewBytes; ++index)
            {
                stream << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned int>(event.Preview[index]);
            }
            stream << std::dec << "\",\"startQpc\":\"" << event.StartQpc << "\",\"endQpc\":\"" << event.EndQpc << "\"}";
        }
        stream << "]}";
        stream.close();
        if (correct && stream && (!trace || (etw.Status == 0 && etw.WriteFailures == 0 && etw.EventsLost == 0 && etw.BuffersLost == 0)))
        {
            exitCode = failExit ? 7 : 0;
        }
    }
    while (false);
    return exitCode;
}
