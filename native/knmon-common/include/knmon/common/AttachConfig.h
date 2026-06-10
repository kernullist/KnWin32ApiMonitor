#pragma once

#include <cstdint>

namespace knmon
{
inline constexpr std::uint32_t KnMonAttachConfigMagic = 0x31434e4b;
inline constexpr std::uint16_t KnMonAttachConfigAbiVersion = 1;
inline constexpr std::uint32_t KnMonAttachConfigOperationIdChars = 64;
inline constexpr std::uint32_t KnMonAttachConfigPipeNameChars = 260;
inline constexpr std::uint32_t KnMonAttachConfigTransportNameChars = 128;
inline constexpr std::uint32_t KnMonAttachConfigControlNameChars = 128;
inline constexpr std::uint32_t KnMonAgentStateMagic = 0x31534e4b;
inline constexpr std::uint16_t KnMonAgentStateAbiVersion = 1;
inline constexpr std::uint32_t KnMonAgentStateOperationIdChars = 64;
inline constexpr std::uint32_t KnMonAgentStateFlagResettable = 0x00000001;
inline constexpr std::uint32_t KnMonAgentStateFlagActive = 0x00000002;
inline constexpr std::uint32_t KnMonAgentStateFlagBusy = 0x00000004;

enum class KnMonAttachMode : std::uint32_t
{
    Unknown = 0,
    RunningProcess = 1,
};

enum class KnMonAgentControlStatus : std::uint32_t
{
    Success = 0,
    InvalidConfig = 1,
    UnsupportedAbi = 2,
    AlreadyRunning = 3,
    WorkerStartFailed = 4,
    NotRunning = 5,
    InvalidState = 6,
};

enum class KnMonAgentLifecycleState : std::uint32_t
{
    Unknown = 0,
    Starting = 1,
    Running = 2,
    Stopping = 3,
    Disabled = 4,
    Failed = 5,
};

struct KnMonAttachConfigV1
{
    std::uint32_t Magic = KnMonAttachConfigMagic;
    std::uint16_t AbiVersion = KnMonAttachConfigAbiVersion;
    std::uint16_t StructSize = 0;
    std::uint32_t AttachMode = static_cast<std::uint32_t>(KnMonAttachMode::RunningProcess);
    std::uint32_t Flags = 0;
    wchar_t OperationId[KnMonAttachConfigOperationIdChars] = {};
    wchar_t PipeName[KnMonAttachConfigPipeNameChars] = {};
    wchar_t TransportName[KnMonAttachConfigTransportNameChars] = {};
    wchar_t ControlEventName[KnMonAttachConfigControlNameChars] = {};
    std::uint64_t Reserved[8] = {};
};

struct KnMonAgentStateV1
{
    std::uint32_t Magic = KnMonAgentStateMagic;
    std::uint16_t AbiVersion = KnMonAgentStateAbiVersion;
    std::uint16_t StructSize = 0;
    std::uint32_t LifecycleState = static_cast<std::uint32_t>(KnMonAgentLifecycleState::Unknown);
    std::uint32_t Flags = 0;
    std::uint32_t WorkerStarted = 0;
    std::uint32_t HooksEnabled = 0;
    std::uint32_t AttachConfigAbiVersion = KnMonAttachConfigAbiVersion;
    std::uint32_t AgentVersion = 0;
    std::uint32_t InstalledHooks = 0;
    std::uint32_t RestoredHooks = 0;
    std::uint32_t FailedHooks = 0;
    std::uint64_t DroppedEvents = 0;
    wchar_t OperationId[KnMonAgentStateOperationIdChars] = {};
    std::uint64_t Reserved[8] = {};
};

static_assert(sizeof(KnMonAttachConfigV1) % 8 == 0, "attach config must remain 8-byte aligned");
static_assert(sizeof(KnMonAgentStateV1) % 8 == 0, "agent state must remain 8-byte aligned");
}
