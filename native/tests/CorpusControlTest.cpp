#include <Windows.h>
#include <knmon/common/BoundedJson.h>
#include <knmon/core/Controller.h>
#include "../samples/CorpusRunControl.h"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
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

std::wstring Quote(std::wstring_view value)
{
    std::wstring result = L"\"";
    std::size_t slashes = 0;
    for (const wchar_t ch : value)
    {
        if (ch == L'\\')
        {
            ++slashes;
        }
        else
        {
            result.append(ch == L'\"' ? slashes * 2 + 1 : slashes, L'\\');
            result += ch;
            slashes = 0;
        }
    }
    result.append(slashes * 2, L'\\');
    result += L'\"';
    return result;
}

class Events
{
public:
    Events() = default;
    Events(const Events&) = delete;
    Events& operator=(const Events&) = delete;
    ~Events()
    {
        for (const HANDLE handle : Handles)
        {
            if (handle != nullptr)
            {
                CloseHandle(handle);
            }
        }
    }
    void Create(const std::wstring& id)
    {
        for (std::size_t index = 0; index < Handles.size(); ++index)
        {
            Handles[index] = CreateEventW(nullptr, TRUE, FALSE, knmon::corpus::ControlEventName(id, index).c_str());
            const DWORD error = GetLastError();
            Require(Handles[index] != nullptr && error != ERROR_ALREADY_EXISTS, "Cannot create fresh corpus control events.");
        }
    }
    void Signal(std::size_t index)
    {
        Require(SetEvent(Handles.at(index)) != FALSE, "Cannot signal corpus control event.");
    }
    std::array<HANDLE, 4> Handles = {};
};

class Child
{
public:
    Child() = default;
    Child(const Child&) = delete;
    Child& operator=(const Child&) = delete;
    ~Child()
    {
        if (Process_.hProcess != nullptr)
        {
            if (WaitForSingleObject(Process_.hProcess, 0) != WAIT_OBJECT_0)
            {
                if (Assigned_)
                {
                    TerminateJobObject(Job_, 99);
                }
                else
                {
                    TerminateProcess(Process_.hProcess, 99);
                }
                WaitForSingleObject(Process_.hProcess, 5000);
            }
            CloseHandle(Process_.hThread);
            CloseHandle(Process_.hProcess);
        }
        if (Job_ != nullptr)
        {
            CloseHandle(Job_);
        }
    }
    void Start(const std::filesystem::path& target, const std::vector<std::wstring>& args)
    {
        Require(Job_ == nullptr && Process_.hProcess == nullptr, "Corpus child is single-use.");
        Job_ = CreateJobObjectW(nullptr, nullptr);
        Require(Job_ != nullptr, "Cannot create corpus test job.");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        Require(SetInformationJobObject(Job_, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE,
            "Cannot configure corpus test job.");
        std::wstring command = Quote(target.wstring());
        for (const auto& argument : args)
        {
            command += L" " + Quote(argument);
        }
        STARTUPINFOW startup = {};
        startup.cb = sizeof(startup);
        Require(CreateProcessW(target.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
            nullptr, target.parent_path().c_str(), &startup, &Process_) != FALSE, "Cannot start corpus target.");
        Require(AssignProcessToJobObject(Job_, Process_.hProcess) != FALSE, "Cannot own corpus target before resume.");
        Assigned_ = true;
        Require(ResumeThread(Process_.hThread) != MAXDWORD, "Cannot resume corpus target.");
    }
    void Event(HANDLE event)
    {
        const HANDLE handles[] = {event, Process_.hProcess};
        Require(WaitForMultipleObjects(2, handles, FALSE, 10000) == WAIT_OBJECT_0, "Corpus event was absent or target exited early.");
    }
    bool Alive() const
    {
        return WaitForSingleObject(Process_.hProcess, 0) == WAIT_TIMEOUT;
    }
    DWORD Exit()
    {
        DWORD code = 0;
        Require(WaitForSingleObject(Process_.hProcess, 10000) == WAIT_OBJECT_0 &&
            GetExitCodeProcess(Process_.hProcess, &code) != FALSE, "Corpus target did not finish.");
        return code;
    }
    DWORD Id() const
    {
        return Process_.dwProcessId;
    }
private:
    HANDLE Job_ = nullptr;
    PROCESS_INFORMATION Process_ = {};
    bool Assigned_ = false;
};

knmon::JsonDocument ReadOracle(const std::filesystem::path& directory)
{
    const auto path = directory / L"oracle.json";
    Require(std::filesystem::file_size(path) <= 1024 * 1024, "Corpus oracle exceeds test bound.");
    std::ifstream input(path, std::ios::binary);
    Require(input.is_open(), "Cannot read corpus oracle.");
    const std::string text(std::istreambuf_iterator<char>(input), {});
    Require(!input.bad(), "Cannot finish reading corpus oracle.");
    knmon::JsonDocument oracle(text);
    Require(oracle.Bool("correct", true) && oracle.UInt64("iterations", true) == 8 &&
        oracle.Array("events", true).Objects().size() == 58, "Independent corpus oracle failed.");
    const std::array<const char*, 7> order = {"CreateFileW", "WriteFile", "ReadFile", "ReadFile", "CloseHandle", "VirtualAlloc", "VirtualFree"};
    const auto events = oracle.Array("events", true).Objects();
    std::uint64_t previous = oracle.DecimalUInt64("startQpc");
    for (std::size_t index = 0; index < events.size(); ++index)
    {
        const auto& event = events[index];
        const bool data = index < 56 && (index % 7 == 1 || index % 7 == 2);
        Require(event.UInt64("sequence", true) == index && event.String("api", true) ==
            (index < 56 ? order[index % 7] : index == 56 ? "ReadFile" : "CreateFileW") &&
            event.Bool("success", true) == (index < 56) && event.UInt64("byteCount", true) == (data ? 64 : 0) &&
            event.String("preview", true) == (data ? "202122232425262728292a2b2c2d2e2f" : ""), "Corpus behavior or order changed.");
        Require(previous <= event.DecimalUInt64("startQpc") && event.DecimalUInt64("startQpc") <= event.DecimalUInt64("endQpc") &&
            event.DecimalUInt64("endQpc") <= oracle.DecimalUInt64("endQpc"), "Corpus clock is outside its measured interval.");
        previous = event.DecimalUInt64("endQpc");
    }
    Require(events[56].UInt64("error", true) == ERROR_INVALID_HANDLE && events[57].UInt64("error", true) == ERROR_FILE_NOT_FOUND,
        "Corpus failure behavior changed.");
    Require(std::filesystem::file_size(directory / L"corpus.bin") == 64, "Corpus output file exceeds its exact bound.");
    std::ifstream bytes(directory / L"corpus.bin", std::ios::binary);
    const std::string contents(std::istreambuf_iterator<char>(bytes), {});
    Require(contents.size() == 64, "Corpus output file size differs.");
    for (std::size_t index = 0; index < contents.size(); ++index)
    {
        Require(static_cast<unsigned char>(contents[index]) == index + 32, "Corpus output file bytes differ.");
    }
    return oracle;
}
}

int wmain(int argc, wchar_t** argv)
{
    int result = 1;
    try
    {
        Require(argc == 2, "Expected the comparison target path.");
        const auto target = std::filesystem::absolute(argv[1]);
        const std::wstring prefix = L"test-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
        const auto root = target.parent_path().parent_path() / (L"corpus-control-" + prefix);
        Require(std::filesystem::create_directory(root), "Cannot create fresh corpus control evidence.");
        DWORD value = 17;
        for (const auto invalid : {L"", L"-1", L"+1", L" 1", L"01", L"1x", L"4294967296", L"1001"})
        {
            Require(!knmon::corpus::ParseBoundedDecimal(invalid, 1000, value) && value == 17, "Invalid decimal operand accepted or changed output.");
        }
        Require(knmon::corpus::ParseBoundedDecimal(L"0", 1000, value) && value == 0 &&
            knmon::corpus::ParseBoundedDecimal(L"1000", 1000, value) && value == 1000, "Valid decimal boundary rejected.");
        for (const auto invalid : {L"short", L"Global\\escaped-object", L"invalid/control-name", L"invalid.control.name", L"invalid\"control-name"})
        {
            Require(!knmon::corpus::ValidControlId(invalid), "Invalid event identifier accepted.");
        }
        for (const bool forced : {false, true})
        {
            const auto directory = root / (forced ? L"forced-exit" : L"legacy default");
            Require(std::filesystem::create_directory(directory), "Cannot create legacy corpus directory.");
            Child child;
            std::vector<std::wstring> args = {directory.wstring(), L"8"};
            if (forced)
            {
                args.push_back(L"--nonzero-exit");
            }
            child.Start(target, args);
            Require(child.Exit() == (forced ? 7U : 0U), "Legacy corpus exit changed.");
            Require(!ReadOracle(directory).Has("coordination"), "Legacy corpus unexpectedly used coordination.");
        }
        for (const auto mode : {L"normal", L"start-timeout", L"release-timeout", L"presignaled"})
        {
            const std::wstring name(mode);
            const auto directory = root / name;
            Require(std::filesystem::create_directory(directory), "Cannot create controlled corpus directory.");
            const std::wstring id = prefix + L"-" + name;
            Events events;
            events.Create(id);
            if (name == L"presignaled")
            {
                events.Signal(1);
            }
            Child child;
            child.Start(target, {directory.wstring(), L"8", L"--coordinated", id, name == L"normal" ? L"30" : L"0",
                name == L"normal" ? L"5000" : L"100"});
            if (name == L"presignaled")
            {
                Require(child.Exit() == 1 && !std::filesystem::exists(directory / L"oracle.json"), "Pre-signaled control was accepted.");
                continue;
            }
            child.Event(events.Handles[0]);
            Require(child.Alive() && !std::filesystem::exists(directory / L"corpus.bin") &&
                !std::filesystem::exists(directory / L"oracle.json"), "Corpus ran before its start gate.");
            if (name == L"start-timeout")
            {
                Require(child.Exit() == 1 && !std::filesystem::exists(directory / L"corpus.bin"), "Missing start did not time out before work.");
                continue;
            }
            events.Signal(1);
            child.Event(events.Handles[2]);
            const auto oracle = ReadOracle(directory);
            const auto control = oracle.Object("coordination", true);
            Require(control.DecimalUInt64("readyQpc") > 0 && control.DecimalUInt64("readyQpc") <= control.DecimalUInt64("startGateQpc") &&
                control.DecimalUInt64("startGateQpc") <= oracle.DecimalUInt64("startQpc"), "Control waits leaked into workload timing.");
            if (name == L"release-timeout")
            {
                Require(child.Exit() == 1, "Missing release did not fail after the published oracle.");
            }
            else
            {
                const auto duration = oracle.DecimalUInt64("endQpc") - oracle.DecimalUInt64("startQpc");
                Require(control.UInt64("delayMs", true) == 30 && control.UInt64("waitTimeoutMs", true) == 5000 &&
                    duration * 1000 / oracle.DecimalUInt64("qpcFrequency") >= 160, "Requested pacing did not produce an observed interval.");
                Sleep(100);
                Require(child.Alive(), "Corpus exited before release.");
                events.Signal(3);
                Require(child.Exit() == 0, "Controlled corpus failed after release.");
            }
        }
        Events invalidEvents;
        invalidEvents.Create(prefix);
        for (const auto& options : std::vector<std::vector<std::wstring>>{
            {L"--coordinated", prefix + L"-absent", L"0", L"100"},
            {L"--coordinated", L"Global\\invalid-name", L"0", L"100"},
            {L"--coordinated", prefix, L"-1", L"100"},
            {L"--coordinated", prefix, L"0", L"99"},
            {L"--coordinated", prefix, L"0", L"30001"},
            {L"--coordinated", prefix, L"1001", L"100"},
            {L"--coordinated", prefix, L"0"}})
        {
            static unsigned int index = 0;
            const auto directory = root / (L"invalid-" + std::to_wstring(index++));
            Require(std::filesystem::create_directory(directory), "Cannot create invalid-control directory.");
            Child child;
            std::vector<std::wstring> args = {directory.wstring(), L"8"};
            args.insert(args.end(), options.begin(), options.end());
            child.Start(target, args);
            Require(child.Exit() == 1 && !std::filesystem::exists(directory / L"corpus.bin") &&
                WaitForSingleObject(invalidEvents.Handles[0], 0) == WAIT_TIMEOUT, "Invalid control options reached readiness or executed work.");
        }
        const auto excessive = root / L"excessive-pacing";
        Require(std::filesystem::create_directory(excessive), "Cannot create excessive-pacing directory.");
        Child excessiveChild;
        excessiveChild.Start(target, {excessive.wstring(), L"64", L"--coordinated", prefix, L"1000", L"100"});
        Require(excessiveChild.Exit() == 1 && !std::filesystem::exists(excessive / L"corpus.bin") &&
            WaitForSingleObject(invalidEvents.Handles[0], 0) == WAIT_TIMEOUT, "Excessive total pacing reached readiness or executed work.");
        const auto attached = root / L"actual-attach";
        Require(std::filesystem::create_directory(attached), "Cannot create actual attach directory.");
        Events attachedEvents;
        const auto attachedId = prefix + L"-attached";
        attachedEvents.Create(attachedId);
        Child attachedChild;
        attachedChild.Start(target, {attached.wstring(), L"8", L"--coordinated", attachedId, L"10", L"15000"});
        attachedChild.Event(attachedEvents.Handles[0]);
        knmon::KnMonAttachRequest request;
        request.OperationId = "corpus-control-" + std::to_string(GetCurrentProcessId());
        request.SessionId = request.OperationId;
        request.ProcessId = attachedChild.Id();
        const auto agent = (target.parent_path() / (sizeof(void*) == 8 ? L"knmon-agent64.dll" : L"knmon-agent32.dll")).u8string();
        request.AgentPath = std::string(agent.begin(), agent.end());
        request.Architecture = sizeof(void*) == 8 ? knmon::KnMonAgentArchitecture::X64 : knmon::KnMonAgentArchitecture::X86;
        request.ApiSelection = "kernel32.dll!CreateFileW;kernel32.dll!WriteFile;kernel32.dll!ReadFile;kernel32.dll!CloseHandle;kernel32.dll!VirtualAlloc;kernel32.dll!VirtualFree";
        request.DurationMs = 3000;
        request.TimeoutMs = 7000;
        bool started = false;
        knmon::KnMonCaptureStreamCallbacks callbacks;
        callbacks.OnSessionFrame = [&](const std::string& kind, const knmon::KnMonCaptureResult& state)
        {
            if (kind == "session_state" && state.SessionState == "running")
            {
                Require(!started && state.Handshake.Received && state.AgentControlStatus == 0,
                    "Capture readiness preceded authenticated initialized-agent evidence.");
                started = true;
                attachedEvents.Signal(1);
            }
        };
        const auto capture = knmon::Controller().AttachCapture(request, &callbacks);
        Require(started, "Initialized attach never published capture readiness.");
        Require(capture.Success && capture.AgentCleanupSucceeded && capture.HookCleanupOutcome == "restored_by_agent" &&
            capture.CapturedEvents.size() == 58 && capture.TransportRecordsProduced == 58 && capture.TransportRecordsConsumed == 58 &&
            capture.TransportDroppedEvents == 0 && capture.TransportAbortedRecords == 0 && capture.DroppedEvents == 0,
            "Coordinated attach lost corpus records or included control cleanup calls.");
        Require(WaitForSingleObject(attachedEvents.Handles[2], 0) == WAIT_OBJECT_0 && attachedChild.Alive(),
            "Corpus did not publish its oracle and survive detach.");
        const auto attachedOracle = ReadOracle(attached);
        const auto calls = attachedOracle.Array("events", true).Objects();
        for (std::size_t index = 0; index < calls.size(); ++index)
        {
            const knmon::JsonDocument event(capture.CapturedEvents[index].RawPayload);
            Require(event.String("api", true) == calls[index].String("api", true) &&
                event.DecimalUInt64("recordSequence") == index && event.UInt64("rawLastErrorCode", true) == calls[index].UInt64("error", true),
                "Coordinated capture reordered calls or changed errors.");
        }
        attachedEvents.Signal(3);
        Require(attachedChild.Exit() == 0, "Observed corpus failed after detach and release.");
        for (const auto* mode : {L"missing", L"missing-continuous", L"bad-detail", L"bad-stack", L"duplicate", L"prehello", L"init-failed", L"after-shutdown"})
        {
            const auto directory = root / (L"readiness-" + std::wstring(mode));
            Require(std::filesystem::create_directory(directory), "Cannot create readiness fault directory.");
            Events events;
            const auto id = prefix + L"-fault-" + mode;
            events.Create(id);
            Child child;
            child.Start(target, {directory.wstring(), L"8", L"--coordinated", id, L"0", L"15000"});
            child.Event(events.Handles[0]);
            auto fault = request;
            fault.OperationId = "readiness-";
            for (const wchar_t ch : std::wstring_view(mode))
            {
                fault.OperationId += static_cast<char>(ch);
            }
            fault.SessionId = fault.OperationId;
            fault.ProcessId = child.Id();
            const auto probe = (target.parent_path() / L"knmon-readiness-probe-agent.dll").u8string();
            fault.AgentPath = std::string(probe.begin(), probe.end());
            fault.DurationMs = std::wstring_view(mode) == L"missing-continuous" ? 0 : 1500;
            fault.TimeoutMs = 500;
            std::uint32_t running = 0;
            knmon::KnMonCaptureStreamCallbacks faultCallbacks;
            faultCallbacks.OnSessionFrame = [&](const std::string&, const knmon::KnMonCaptureResult& state)
            {
                running += state.SessionState == "running" ? 1 : 0;
            };
            const auto rejected = knmon::Controller().AttachCapture(fault, &faultCallbacks);
            const bool duplicate = std::wstring_view(mode) == L"duplicate";
            Require(!rejected.Success && rejected.SessionState == "failed" && running == (duplicate ? 1u : 0u),
                "Invalid readiness became successful or emitted unexpected running state.");
            if (std::wstring_view(mode).starts_with(L"missing"))
            {
                Require(rejected.Handshake.Received && rejected.Operation == "agent_ready_timeout",
                    "Missing readiness did not obey its own initialization timeout.");
            }
            Require(child.Alive() && !std::filesystem::exists(directory / L"corpus.bin"),
                "Readiness fault killed the attach target or released the workload.");
            Require(rejected.AgentCleanupSucceeded && rejected.HookCleanupOutcome == "restored_by_agent",
                "Readiness failure did not complete owned-agent cleanup.");
            events.Signal(1);
            child.Event(events.Handles[2]);
            ReadOracle(directory);
            events.Signal(3);
            Require(child.Exit() == 0, "Readiness failure damaged the independent caller.");
            std::cout << "Readiness fault rejected: " << fault.OperationId << " operation=" << rejected.Operation << "\n";
        }
        std::cout << "Corpus control PASS: legacy, gated work, pacing, timeouts, actual attach and readiness faults\n";
        result = 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << "\n";
    }
    return result;
}
