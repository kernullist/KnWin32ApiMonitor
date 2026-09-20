#include <Windows.h>
#include <knmon/common/AttachConfig.h>
#include <knmon/common/IpcSecurity.h>
#include <sstream>
#include <string>

// This test DLL never installs hooks. It sends deliberately invalid control flows.
namespace
{
HANDLE Pipe = INVALID_HANDLE_VALUE;
knmon::KnMonAttachConfigV1 Config;
bool Stopped = false;
std::uint64_t Sequence = 0;

std::string Ascii(const std::wstring& value)
{
    std::string result;
    for (const auto ch : value)
    {
        result += static_cast<char>(ch);
    }
    return result;
}

bool Send(const char* type, const char* fields)
{
    std::ostringstream text;
    text << "{\"schemaVersion\":\"0.1.0\",\"messageType\":\"" << type
        << "\",\"operationId\":\"" << Ascii(Config.OperationId)
        << "\",\"channelNonce\":\"" << Ascii(knmon::ChannelNonce(Config.PipeName))
        << "\",\"pid\":" << GetCurrentProcessId() << ",\"tid\":" << GetCurrentThreadId()
        << ",\"sequence\":" << ++Sequence << ",\"timestampUtc\":\"2026-09-21T00:00:00Z\","
        << fields << "}";
    return knmon::TryWriteAgentMessage(Pipe, text.str());
}
}

extern "C" __declspec(dllexport) DWORD WINAPI KnMonAgentInitialize(const knmon::KnMonAttachConfigV1* config)
{
    DWORD status = static_cast<DWORD>(knmon::KnMonAgentControlStatus::WorkerStartFailed);
    do
    {
        if (config == nullptr || config->Magic != knmon::KnMonAttachConfigMagic ||
            config->AbiVersion != knmon::KnMonAttachConfigAbiVersion || config->StructSize != sizeof(*config))
        {
            break;
        }
        Config = *config;
        const std::wstring mode(Config.OperationId);
        if (mode == L"readiness-init-failed")
        {
            break;
        }
        Pipe = CreateFileW(Config.PipeName, knmon::AgentPipeClientAccess, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (Pipe == INVALID_HANDLE_VALUE || !knmon::ConfigureAgentPipeWriter(Pipe))
        {
            break;
        }
        const char* ready = "\"captureDetail\":\"preview\",\"stackFrames\":0";
        if (mode == L"readiness-prehello")
        {
            Send("agent_ready", ready);
        }
        else
        {
            Send("agent_hello", sizeof(void*) == 8 ?
                "\"architecture\":\"x64\",\"agentVersion\":\"0.5.0\"" :
                "\"architecture\":\"x86\",\"agentVersion\":\"0.5.0\"");
            if (mode == L"readiness-bad-detail")
            {
                Send("agent_ready", "\"captureDetail\":\"metadata\",\"stackFrames\":0");
            }
            else if (mode == L"readiness-bad-stack")
            {
                Send("agent_ready", "\"captureDetail\":\"preview\",\"stackFrames\":32");
            }
            else if (mode == L"readiness-duplicate")
            {
                Send("agent_ready", ready);
                Send("agent_ready", ready);
            }
            else if (mode == L"readiness-after-shutdown")
            {
                Send("agent_shutdown", "\"reason\":\"failed\",\"installedHooks\":0,\"restoredHooks\":0,\"failedHooks\":0,\"droppedCount\":0");
                Send("agent_ready", ready);
            }
        }
        status = static_cast<DWORD>(knmon::KnMonAgentControlStatus::Success);
    }
    while (false);
    return status;
}

extern "C" __declspec(dllexport) DWORD WINAPI KnMonAgentStop()
{
    if (Pipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(Pipe);
        Pipe = INVALID_HANDLE_VALUE;
    }
    Stopped = true;
    return static_cast<DWORD>(knmon::KnMonAgentControlStatus::Success);
}

extern "C" __declspec(dllexport) DWORD WINAPI KnMonAgentQueryState(knmon::KnMonAgentStateV1* state)
{
    *state = {};
    state->StructSize = sizeof(*state);
    state->LifecycleState = static_cast<std::uint32_t>(Stopped ?
        knmon::KnMonAgentLifecycleState::Disabled : knmon::KnMonAgentLifecycleState::Starting);
    wcscpy_s(state->OperationId, Config.OperationId);
    return static_cast<DWORD>(knmon::KnMonAgentControlStatus::Success);
}

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:KnMonAgentInitialize=_KnMonAgentInitialize@4")
#pragma comment(linker, "/EXPORT:KnMonAgentStop=_KnMonAgentStop@0")
#pragma comment(linker, "/EXPORT:KnMonAgentQueryState=_KnMonAgentQueryState@4")
#endif
