#include <Windows.h>
#include <knmon/common/BoundedJson.h>
#include <knmon/core/Controller.h>
#include "ProcessResourceSamples.h"
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <thread>
#include <vector>

namespace
{
void Require(bool value, const char* message)
{
    if (!value)
    {
        throw std::runtime_error(message);
    }
}

std::string Utf8(const std::filesystem::path& path)
{
    const auto value = path.u8string();
    return {value.begin(), value.end()};
}

knmon::JsonDocument ReadReport(const std::filesystem::path& path)
{
    Require(std::filesystem::file_size(path) <= 4096, "Pressure oracle exceeds its bound.");
    std::ifstream input(path, std::ios::binary);
    Require(input.is_open(), "Cannot open pressure oracle.");
    const std::string report(std::istreambuf_iterator<char>(input), {});
    Require(!input.bad(), "Cannot read pressure oracle.");
    return knmon::JsonDocument(report);
}

void ValidateResources(const knmon::JsonDocument& resources, std::uint64_t maximumBytes)
{
    Require(!resources.Bool("failed", true) && resources.UInt64("samples", true) >= 20, "Resource sampling failed or was incomplete.");
    Require(resources.UInt64("elapsedMs", true) >= 1900 && resources.UInt64("cpu100ns", true) > 0,
        "Resource samples lack an actual elapsed interval or CPU measurement.");
    Require(resources.UInt64("peakWorkingSetBytes", true) < maximumBytes &&
        resources.UInt64("maxPrivateBytes", true) < maximumBytes, "Process memory exceeded the regression budget.");
    Require(resources.UInt64("latePrivateGrowthBytes", true) < 32 * 1024 * 1024 &&
        resources.UInt64("maxHandles", true) < 256, "Resource growth or handle count exceeded its bound.");
}

void RunOriginal(const std::filesystem::path& target, const std::filesystem::path& report, DWORD duration)
{
    std::wstring command = L"\"" + target.wstring() + L"\" \"" + report.wstring() + L"\" " + std::to_wstring(duration) + L" original";
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {};
    Require(CreateProcessW(target.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &process) != FALSE, "Original pressure target failed to start.");
    DWORD code = 0;
    const bool completed = WaitForSingleObject(process.hProcess, duration + 10000) == WAIT_OBJECT_0;
    const bool exited = completed && GetExitCodeProcess(process.hProcess, &code) && code == 0;
    if (!exited)
    {
        std::cerr << "Original pressure exit=" << code << " completed=" << completed << "\n";
    }
    if (!completed)
    {
        TerminateProcess(process.hProcess, 99);
        WaitForSingleObject(process.hProcess, 5000);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    Require(exited, "Original pressure target failed its behavior oracle.");
}
}

int wmain(int argc, wchar_t** argv)
{
    try
    {
        Require(argc == 2 || argc == 3, "Expected a native binary directory and optional duration.");
        wchar_t* end = nullptr;
        const DWORD duration = argc == 3 ? wcstoul(argv[2], &end, 10) : 5000;
        Require((end == nullptr || *end == L'\0') && duration >= 2000 && duration <= 30000, "Invalid pressure duration.");
        const auto directory = std::filesystem::absolute(argv[1]);
        const auto evidence = directory.parent_path() /
            ("pressure-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
        Require(std::filesystem::create_directory(evidence), "Cannot create fresh pressure evidence.");
        const auto target = directory / "knmon-pressure-target.exe";
        RunOriginal(target, evidence / "original.json", duration);
        const auto original = ReadReport(evidence / "original.json");
        Require(original.UInt64("errors", true) == 0 && original.UInt64("workloadCalls", true) > 10000,
            "Original workload did not run correctly.");
        ValidateResources(original.Object("resources", true), 128 * 1024 * 1024);

        Require(SetEnvironmentVariableW(L"KNMON_TRANSPORT_CAPACITY", L"64") != FALSE, "Cannot configure bounded transport.");
        knmon::KnMonLaunchRequest request;
        request.OperationId = "pressure-" + std::to_string(GetCurrentProcessId());
        request.SessionId = request.OperationId;
        request.TargetPath = Utf8(target);
        request.AgentPath = Utf8(directory / (sizeof(void*) == 8 ? "knmon-agent64.dll" : "knmon-agent32.dll"));
        request.CommandLineArguments = "\"" + Utf8(evidence / "observed.json") + "\" " + std::to_string(duration) + " observed";
        request.Architecture = sizeof(void*) == 8 ? knmon::KnMonAgentArchitecture::X64 : knmon::KnMonAgentArchitecture::X86;
        request.ApiSelection = "kernel32.dll!CloseHandle";
        request.TimeoutMs = duration + 10000;
        request.DurationMs = duration + 10000;
        std::vector<std::uint64_t> sequences;
        sequences.reserve(65536);
        std::uint64_t batches = 0;
        knmon::KnMonCaptureStreamCallbacks callbacks;
        callbacks.MaxRecordsPerBatch = 64;
        callbacks.OnTraceBatch = [&](const knmon::KnMonTraceBatch& batch)
        {
            Require(batch.Events.size() <= 64 && sequences.size() + batch.Events.size() <= 262144, "Unbounded stream delivery.");
            for (const auto& event : batch.Events)
            {
                const knmon::JsonDocument payload(event.RawPayload);
                Require(payload.String("api", true) == "CloseHandle", "Unselected API reached the pressure consumer.");
                const auto result = payload.DecimalUInt64("rawReturnValue");
                Require(result == 1 || (result == 0 && payload.UInt64("rawLastErrorCode", true) == ERROR_INVALID_HANDLE),
                    "Monitoring altered a CloseHandle result or error.");
                const auto sequence = payload.DecimalUInt64("recordSequence");
                Require(sequences.empty() || sequences.back() < sequence, "Duplicated or reversed pressure record.");
                sequences.push_back(sequence);
            }
            ++batches;
            Sleep(20);
            return true;
        };
        ProcessResourceSamples host;
        knmon::KnMonCaptureResult captured;
        {
            std::jthread sampler([&](std::stop_token stop)
            {
                while (!stop.stop_requested())
                {
                    host.Sample();
                    Sleep(50);
                }
            });
            captured = knmon::Controller().LaunchCapture(request, &callbacks);
        }
        const auto observed = ReadReport(evidence / "observed.json");
        const auto begin = observed.UInt64("beginSequence", true);
        const auto endSequence = observed.UInt64("endSequence", true);
        Require(endSequence >= begin && observed.UInt64("endDrops", true) >= observed.UInt64("beginDrops", true),
            "Pressure transport counters moved backwards.");
        const auto produced = endSequence - begin;
        const auto drops = observed.UInt64("endDrops", true) - observed.UInt64("beginDrops", true);
        const auto delivered = static_cast<std::uint64_t>(std::count_if(sequences.begin(), sequences.end(), [&](auto sequence)
        {
            return sequence >= begin && sequence < endSequence;
        }));
        std::cout << "Pressure evidence: " << Utf8(evidence) << "\n";
        Require(captured.Success && captured.TargetExitCode == 0, captured.Message.c_str());
        Require(observed.UInt64("errors", true) == 0 && observed.UInt64("workloadCalls", true) > 10000,
            "Observed workload did not preserve original behavior.");
        Require(drops > 0 && produced > 0 && produced + drops == observed.UInt64("windowCalls", true) && delivered == produced,
            "API attempts do not reconcile with delivered records and explicit transport loss.");
        Require(captured.TransportRecordsProduced == captured.TransportRecordsConsumed && captured.TransportAbortedRecords == 0,
            "Pressure capture lost its committed tail or abandoned reservations.");
        Require(captured.TransportCapacity == 64 && captured.TransportHighWaterMark <= 64 && captured.HistoryBounded &&
            captured.CapturedEvents.size() <= 128 && captured.CapturedEvents.size() + captured.CapturedEventsOmitted == sequences.size(),
            "Pressure retention or queue bounds failed.");
        ValidateResources(observed.Object("resources", true), 128 * 1024 * 1024);
        ValidateResources(knmon::JsonDocument(host.Json()), 512 * 1024 * 1024);
        std::ofstream summary(evidence / "summary.json", std::ios::binary);
        summary << "{\"schemaVersion\":1,\"status\":\"passed\",\"architecture\":\"" << (sizeof(void*) == 8 ? "x64" : "x86")
            << "\",\"durationMs\":" << duration << ",\"windowProduced\":" << produced << ",\"windowDropped\":" << drops
            << ",\"windowDelivered\":" << delivered << ",\"transportProduced\":" << captured.TransportRecordsProduced
            << ",\"transportConsumed\":" << captured.TransportRecordsConsumed << ",\"transportDropped\":" << captured.TransportDroppedEvents
            << ",\"transportCapacity\":" << captured.TransportCapacity << ",\"highWater\":" << captured.TransportHighWaterMark
            << ",\"retained\":" << captured.CapturedEvents.size() << ",\"omitted\":" << captured.CapturedEventsOmitted
            << ",\"batches\":" << batches << ",\"controller\":" << host.Json() << "}";
        summary.close();
        Require(summary.good(), "Cannot persist passing pressure evidence.");
        std::cout << "Sustained capture PASS: calls=" << observed.UInt64("windowCalls") << " delivered=" << delivered << " dropped=" << drops << "\n";
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << "\n";
        return 1;
    }
    return 0;
}
