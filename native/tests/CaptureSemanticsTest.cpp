#include <WinSock2.h>
#include <Windows.h>
#include <knmon/common/ApiResult.h>
#include <knmon/common/BoundedJson.h>
#include <knmon/common/ThreadErrorState.h>
#include <knmon/core/Controller.h>
#include <filesystem>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace
{
void Check(bool condition, const char* message)
{
    if (!condition)
    {
        throw std::runtime_error(message);
    }
}

void RaiseInsideOriginal()
{
    knmon::ThreadErrorState state;
    SetLastError(900);
    state.Call([]()
    {
        SetLastError(777);
        RaiseException(0xe0570001, 0, 0, nullptr);
    });
}

bool CheckOriginalSeh()
{
    bool propagated = false;
    __try
    {
        RaiseInsideOriginal();
    }
    __except (GetExceptionCode() == 0xe0570001 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        propagated = GetLastError() == 777;
    }
    return propagated;
}

void CheckResult(const char* name, std::uint64_t value, std::uint32_t error, const char* domain,
    const char* outcome, bool hasError, std::uint32_t expectedCode, std::uint32_t bits = 32)
{
    const knmon::KnMonGeneratedApiMetadata* metadata = nullptr;
    for (const auto& entry : knmon::KnMonGeneratedApis)
    {
        if (entry.Name == name)
        {
            metadata = &entry;
            break;
        }
    }
    Check(metadata != nullptr, "Missing test API metadata.");
    knmon::KnMonTransportRecord record;
    record.RawReturnValue = value;
    record.RawReturnBits = bits;
    record.RawLastErrorCode = error;
    record.RawWinsockErrorCode = error;
    record.HasWinsockError = 1;
    const auto result = knmon::ClassifyApiResult(metadata, record);
    if (result.Domain != domain || result.Outcome != outcome || result.HasError != hasError || (hasError && result.Code != expectedCode))
    {
        std::cerr << name << ": " << result.Domain << "/" << result.Outcome << "/" << result.Code << "\n";
        Check(false, "API result semantics mismatch.");
    }
}

void CheckDelayedCollector(const wchar_t* agentTestPath)
{
    const auto directory = std::filesystem::path(agentTestPath).parent_path();
    knmon::KnMonLaunchRequest request;
    request.OperationId = "clock-test-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64());
    request.SessionId = request.OperationId;
    request.TargetPath = (directory / "knmon-sample-fileio.exe").string();
    request.AgentPath = (directory / (sizeof(void*) == 8 ? "knmon-agent64.dll" : "knmon-agent32.dll")).string();
    request.Architecture = sizeof(void*) == 8 ? knmon::KnMonAgentArchitecture::X64 : knmon::KnMonAgentArchitecture::X86;
    request.ApiSelection = "kernel32.dll!CreateFileW;kernel32.dll!CreateFileA;kernel32.dll!ReadFile;kernel32.dll!WriteFile;kernel32.dll!CloseHandle";
    request.TimeoutMs = 10000;
    request.DurationMs = 3000;
    std::uint64_t batches = 0;
    std::uint64_t delayedEvents = 0;
    std::string base;
    knmon::KnMonCaptureStreamCallbacks callbacks;
    callbacks.MaxRecordsPerBatch = 1;
    callbacks.OnTraceBatch = [&](const knmon::KnMonTraceBatch& batch)
    {
        for (const auto& event : batch.Events)
        {
            const auto payload = knmon::ParseAgentJson(event.RawPayload);
            const auto timing = payload.Object("timing");
            if (base.empty())
            {
                base = timing.String("qpcBase");
            }
            Check(base == timing.String("qpcBase"), "Collector changed the session clock anchor.");
            LARGE_INTEGER now = {};
            QueryPerformanceCounter(&now);
            std::uint64_t ageUs = 0;
            Check(knmon::ScaleQpcTicks(static_cast<std::uint64_t>(now.QuadPart) - timing.DecimalUInt64("startQpc"),
                timing.DecimalUInt64("qpcFrequency"), 1000000, ageUs), "Delayed event age conversion failed.");
            if (batches != 0 && ageUs >= 700000)
            {
                ++delayedEvents;
            }
        }
        if (++batches == 1)
        {
            Sleep(750);
        }
        return true;
    };
    const auto captured = knmon::Controller().LaunchCapture(request, &callbacks);
    std::cout << "Delayed capture evidence: batches=" << batches << " delayedEvents=" << delayedEvents
        << " success=" << captured.Success << " operation=" << captured.Operation
        << " error=" << captured.Win32ErrorCode << " targetExit=" << captured.TargetExitCode << "\n";
    Check(captured.Success, captured.Message.c_str());
    Check(batches > 1 && delayedEvents > 0, "Collector delay did not exercise queued capture timestamps.");
    Check(captured.TransportDroppedEvents == 0, "Delayed collector lost events.");
    Check(captured.TransportRecordsConsumed == captured.TransportRecordsProduced,
        "Delayed collector discarded committed tail batches during shutdown.");
    std::cout << "Delayed collector passed: batches=" << batches << " delayedEvents=" << delayedEvents << "\n";
}

void CheckFailedLaunch(const wchar_t* agentTestPath)
{
    const auto directory = std::filesystem::path(agentTestPath).parent_path();
    knmon::KnMonLaunchRequest request;
    request.OperationId = "failed-launch-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64());
    request.SessionId = request.OperationId;
    request.TargetPath = (directory / "knmon-lifecycle-exit-target.exe").string();
    request.AgentPath = (directory / (sizeof(void*) == 8 ? "knmon-agent64.dll" : "knmon-agent32.dll")).string();
    request.Architecture = sizeof(void*) == 8 ? knmon::KnMonAgentArchitecture::X64 : knmon::KnMonAgentArchitecture::X86;
    request.ApiSelection = "kernel32.dll!CloseHandle";
    request.TimeoutMs = 7000;
    request.DurationMs = 2000;
    const auto captured = knmon::Controller().LaunchCapture(request);
    Check(!captured.Success && captured.TargetExitCode == 1 && captured.Operation == "target_exit_failed",
        "Nonzero launch target exit was not preserved.");
    Check(captured.OperationState == "failed" && captured.SessionState == "failed" && !captured.StoppedUtc.empty(),
        "Failed launch result retained a nonterminal state.");
    Check(captured.SessionShutdownEvidence == "released_by_process_exit", "Failed target exit lost address-space cleanup evidence.");
    std::cout << "Failed launch is terminal with target exit code 1.\n";
}

void CheckStreamRetention(const wchar_t* agentTestPath, bool reject)
{
    const auto directory = std::filesystem::path(agentTestPath).parent_path();
    for (int pass = 0; pass < (reject ? 2 : 1); ++pass)
    {
        knmon::KnMonLaunchRequest request;
        request.OperationId = "stream-test-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64());
        request.SessionId = request.OperationId;
        request.TargetPath = (directory / "knmon-sample-fileio.exe").string();
        request.AgentPath = (directory / (sizeof(void*) == 8 ? "knmon-agent64.dll" : "knmon-agent32.dll")).string();
        request.Architecture = sizeof(void*) == 8 ? knmon::KnMonAgentArchitecture::X64 : knmon::KnMonAgentArchitecture::X86;
        request.ApiSelection = "kernel32.dll!CreateFileW;kernel32.dll!CreateFileA;kernel32.dll!ReadFile;kernel32.dll!WriteFile;kernel32.dll!CloseHandle";
        request.CommandLineArguments = "--attach-loop --iterations 50 --delay-ms 10";
        request.TimeoutMs = 10000;
        request.DurationMs = 3000;
        knmon::KnMonCaptureStreamCallbacks callbacks;
        callbacks.MaxRecordsPerBatch = 100000;
        std::uint64_t seen = 0;
        std::uint64_t batches = 0;
        callbacks.OnTraceBatch = [&](const knmon::KnMonTraceBatch& batch)
        {
            ++batches;
            Check(batch.Events.size() <= 64, "Native batch record bound was exceeded.");
            seen += batch.Events.size();
            if (reject && pass == 1)
            {
                throw std::runtime_error("Injected consumer exception.");
            }
            return !reject;
        };
        const auto captured = knmon::Controller().LaunchCapture(request, &callbacks);
        std::cout << "Stream evidence: delivered=" << seen << " retained=" << captured.CapturedEvents.size()
            << " omitted=" << captured.CapturedEventsOmitted << " operation=" << captured.Operation << "\n";
        if (reject)
        {
            Check(!captured.Success && captured.StreamConsumerFailed && batches == 1,
                "Consumer rejection or exception must be sticky and suppress subsequent delivery.");
            Check(captured.Operation == "stream_consumer_failed" && captured.OperationState == "failed",
                "A consumer failure was reported as a successful capture.");
            Check(captured.AgentCleanupSucceeded || captured.SessionShutdownEvidence == "released_by_process_exit",
                "Consumer failure skipped agent cleanup.");
        }
        else
        {
            Check(captured.Success, captured.Message.c_str());
            Check(seen > 128 && captured.CapturedEventsSeen == seen && captured.CapturedEvents.size() <= 128,
                "Bounded history altered or truncated complete stream delivery.");
            Check(captured.CapturedEvents.size() + captured.CapturedEventsOmitted == seen,
                "Retained history counts do not reconcile.");
            Check(captured.TransportDroppedEvents == 0, "Retention smoke lost transport events.");
            Check(captured.TransportRecordsConsumed == captured.TransportRecordsProduced,
                "Streaming capture discarded its final transport tail.");
        }
    }
}
}

int wmain(int argc, wchar_t** argv)
{
    int result = 0;
    if (argc == 2 && std::wcscmp(argv[1], L"--scale") == 0)
    {
        std::uint64_t ticks = 0, frequency = 0, scale = 0, value = 0;
        while (std::cin >> ticks >> frequency >> scale)
        {
            if (knmon::ScaleQpcTicks(ticks, frequency, scale, value))
            {
                std::cout << value << "\n";
            }
            else
            {
                std::cout << "overflow\n";
            }
        }
        return std::cin.eof() ? 0 : 1;
    }
    try
    {
        if (argc == 3)
        {
            if (std::wcscmp(argv[2], L"--consumer-failure") == 0)
            {
                CheckStreamRetention(argv[1], true);
            }
            else if (std::wcscmp(argv[2], L"--retention") == 0)
            {
                CheckStreamRetention(argv[1], false);
                CheckFailedLaunch(argv[1]);
            }
            else
            {
                CheckDelayedCollector(argv[1]);
            }
            return 0;
        }
        std::uint64_t value = 0;
        Check(knmon::ScaleQpcTicks(0xffffffffffffffffULL, 10000000, 1000000, value) && value == 1844674407370955161ULL,
            "Long-uptime QPC scaling overflowed.");
        Check(!knmon::ScaleQpcTicks(1, 0, 1000, value), "Zero QPC frequency accepted.");
        Check(!knmon::ScaleQpcTicks(0xffffffffffffffffULL, 1, 1000, value), "QPC result overflow accepted.");
        Check(knmon::ScaleQpcTicks(0xfffffffffffffffeULL, 0xffffffffffffffffULL, 10000000, value) && value == 9999999,
            "High-frequency QPC scaling failed.");
        const knmon::CaptureClock clock{10000000, 9007199254740993ULL, 133000000000000000ULL, 7};
        knmon::CaptureTime time, delayed;
        Check(knmon::ConvertCaptureTime(clock, clock.QpcBase + 12345, clock.QpcBase + 33345, time), "QPC conversion failed.");
        Check(time.RelativeUs == 1234 && time.DurationUs == 2100 && time.UtcFileTime == clock.UtcBaseFileTime + 12345,
            "QPC exact integer conversion failed.");
        Sleep(20);
        Check(knmon::ConvertCaptureTime(clock, clock.QpcBase + 12345, clock.QpcBase + 33345, delayed) &&
            delayed.RelativeUs == time.RelativeUs && delayed.UtcFileTime == time.UtcFileTime, "Collector delay changed capture time.");
        Check(!knmon::ConvertCaptureTime(clock, clock.QpcBase - 1, clock.QpcBase, time), "Pre-anchor QPC accepted.");
        Check(!knmon::ConvertCaptureTime(clock, clock.QpcBase + 1, clock.QpcBase, time), "Reversed QPC interval accepted.");
        Check(knmon::JsonDocument("{\"n\":\"18446744073709551615\",\"ms\":0.125}").DecimalUInt64("n") ==
            std::numeric_limits<std::uint64_t>::max(), "Exact JSON uint64 string lost precision.");
        Check(knmon::JsonDocument("{\"ms\":0.125}").NonnegativeNumber("ms") == 0.125, "Fractional timing lost precision.");
        for (const char* invalid : {"", "01", "+1", "-1", "1.0", "18446744073709551616"})
        {
            bool rejected = false;
            try
            {
                knmon::JsonDocument(std::string("{\"n\":\"") + invalid + "\"}").DecimalUInt64("n");
            }
            catch (const knmon::JsonInputError&)
            {
                rejected = true;
            }
            Check(rejected, "Malformed decimal clock value accepted.");
        }
        SetLastError(321);
        {
            knmon::ThreadErrorState state;
            SetLastError(654);
            const auto raw = state.Call([]() -> BOOL
            {
                Check(GetLastError() == 321, "Instrumentation changed incoming last error.");
                SetLastError(987);
                return 2;
            });
            Check(raw == 2 && state.ReturnValue() == 2 && state.ReturnBits() == 32, "BOOL raw return was normalized.");
            SetLastError(999);
        }
        Check(GetLastError() == 987, "Instrumentation changed outgoing last error.");
        WSASetLastError(WSAECONNREFUSED);
        {
            knmon::ThreadErrorState state(WSAGetLastError, WSASetLastError);
            WSASetLastError(WSAENOBUFS);
            const auto incoming = state.Call([]()
            {
                const auto before = WSAGetLastError();
                WSASetLastError(WSAEWOULDBLOCK);
                return before;
            });
            Check(incoming == WSAECONNREFUSED && state.Winsock() == WSAEWOULDBLOCK, "Winsock boundary changed error state.");
            WSASetLastError(0);
        }
        Check(WSAGetLastError() == WSAEWOULDBLOCK && WSAGetLastError() == WSAEWOULDBLOCK, "Winsock post-state was not restored.");
        Check(CheckOriginalSeh(), "Original SEH or its error state did not propagate.");
        CheckResult("CreateFileW", 0xffffffff, 2, "win32", "failure", true, 2);
        CheckResult("CreateFileW", 0xffffffffffffffffULL, 5, "win32", "failure", true, 5, 64);
        CheckResult("CreateFileW", 100, 183, "win32", "success", false, 0);
        CheckResult("ReadFile", 0, 997, "win32", "pending", false, 0);
        CheckResult("ReadFile", 2, 5, "win32", "success", false, 0);
        CheckResult("socket", 0xffffffffffffffffULL, 10047, "winsock", "failure", true, 10047, 64);
        CheckResult("closesocket", 0xffffffff, 10038, "winsock", "failure", true, 10038);
        CheckResult("WSARevertImpersonation", 0xffffffff, 10107, "winsock", "failure", true, 10107);
        CheckResult("WSAStartup", 10092, 123, "winsock", "failure", true, 10092);
        CheckResult("getaddrinfo", 11001, 123, "winsock", "failure", true, 11001);
        CheckResult("WSAGetLastError", 10061, 10061, "none", "success", false, 0);
        CheckResult("NtCreateFile", 0x103, 5, "ntstatus", "pending", false, 0);
        CheckResult("NtCreateFile", 0xc0000022, 0, "ntstatus", "failure", true, 0xc0000022);
        CheckResult("CoInitializeEx", 1, 5, "hresult", "success", false, 0);
        CheckResult("CoInitializeEx", 0x80010106, 0, "hresult", "failure", true, 0x80010106);
        CheckResult("PSRefreshPropertySchema", 0x800401f0, 0, "hresult", "failure", true, 0x800401f0);
        CheckResult("GetActiveWindow", 0, 5, "none", "unknown", false, 0);
        CheckResult("GetClipboardOwner", 0, 5, "win32", "unknown", false, 0);
        CheckResult("UuidCreate", 1824, 5, "win32", "success", false, 0);
        CheckResult("GetAdaptersAddresses", 111, 5, "win32", "failure", true, 111);
        Check(argc == 2, "Test Agent path required.");
        HMODULE agent = LoadLibraryW(argv[1]);
        auto parity = agent == nullptr ? nullptr : reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(agent, "KnMonTestErrorParity"));
        Check(parity != nullptr, "Test Agent error parity export missing.");
        const auto parityResult = parity(nullptr);
        if (parityResult != 0)
        {
            std::cerr << "Agent parity result: " << parityResult << "\n";
        }
        Check(parityResult == 0, "Actual Agent wrapper error parity failed.");
        FreeLibrary(agent);
        std::cout << "QPC, result semantics, error preservation, SEH and actual Agent parity passed.\n";
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << "\n";
        result = 1;
    }
    return result;
}
