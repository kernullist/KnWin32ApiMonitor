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

static_assert(sizeof(KnMonAttachConfigV1) % 8 == 0, "attach config must remain 8-byte aligned");
}
