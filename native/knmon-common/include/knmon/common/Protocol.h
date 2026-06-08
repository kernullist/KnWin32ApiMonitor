#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace knmon
{
inline constexpr std::uint16_t KnMonProtocolMajor = 0;
inline constexpr std::uint16_t KnMonProtocolMinor = 1;
inline constexpr std::uint16_t KnMonProtocolPatch = 0;

enum class KnMonDecodeStatus : std::uint32_t
{
    Decoded = 0,
    Partial = 1,
    InvalidPointer = 2,
    UnreadableMemory = 3,
    DefinitionMissing = 4,
    Truncated = 5,
};

enum class KnMonCaptureSessionState : std::uint32_t
{
    Stopped = 0,
    Starting = 1,
    Running = 2,
    Stopping = 3,
    Failed = 4,
};

enum class KnMonBackendMode : std::uint32_t
{
    Mock = 0,
    NativeEnum = 1,
    NativeCapture = 2,
};

enum class KnMonAgentArchitecture : std::uint32_t
{
    Unknown = 0,
    X86 = 1,
    X64 = 2,
};

enum class KnMonInjectionMethod : std::uint32_t
{
    None = 0,
    EarlyBirdApc = 1,
};

struct KnMonProtocolVersion
{
    std::uint16_t Major = KnMonProtocolMajor;
    std::uint16_t Minor = KnMonProtocolMinor;
    std::uint16_t Patch = KnMonProtocolPatch;
};

struct KnMonError
{
    std::uint32_t Code = 0;
    std::string Subsystem;
    std::string Operation;
    std::string Message;
};

struct KnMonArgument
{
    std::uint32_t Index = 0;
    std::string Name;
    std::string Type;
    std::string Direction;
    std::string RawValue;
    std::string PreCallValue;
    std::string PostCallValue;
    std::string DecodedValue;
    std::uint64_t PointerAddress = 0;
    KnMonDecodeStatus DecodeStatus = KnMonDecodeStatus::Decoded;
};

struct KnMonMemorySnapshot
{
    std::uint64_t SnapshotId = 0;
    std::uint32_t ProcessId = 0;
    std::uint64_t Address = 0;
    std::uint64_t RequestedSize = 0;
    std::uint64_t CapturedSize = 0;
    std::uint64_t RegionBase = 0;
    std::uint64_t RegionSize = 0;
    std::string Protection;
    std::string State;
    std::string Type;
    std::string EncodingHint;
    std::string TruncationReason;
};

struct KnMonEvent
{
    std::uint64_t EventId = 0;
    std::string SchemaVersion = "0.1.0";
    std::uint64_t TimestampQpc = 0;
    std::uint64_t RelativeTimeNs = 0;
    std::uint32_t ProcessId = 0;
    std::uint32_t ThreadId = 0;
    std::string ProcessName;
    std::string ImagePath;
    std::string ModuleName;
    std::string ApiName;
    std::string ReturnValue;
    std::string ErrorKind;
    std::string ErrorCode;
    std::string ErrorMessage;
    std::uint64_t DurationNs = 0;
    std::vector<KnMonArgument> Arguments;
    std::vector<std::string> Tags;
    std::vector<std::string> Stack;
};

struct KnMonTargetProcess
{
    std::uint32_t ProcessId = 0;
    std::uint32_t ParentProcessId = 0;
    bool HasParentProcessId = false;
    std::string ImageName;
    std::string ImagePath;
    std::string Architecture;
    std::string Status;
};

struct KnMonAuditEvent
{
    std::string SchemaVersion = "0.1.0";
    std::string OperationId;
    std::string EventType;
    std::string TimestampUtc;
    std::string Subsystem;
    std::string Operation;
    std::uint32_t Win32ErrorCode = 0;
    std::string NtStatus;
    std::string Message;
};

struct KnMonAgentHandshake
{
    bool Received = false;
    std::string SchemaVersion = "0.1.0";
    std::string OperationId;
    std::uint32_t ProcessId = 0;
    std::uint32_t ThreadId = 0;
    std::string Architecture;
    std::string AgentVersion;
    std::string Message;
    std::string RawPayload;
};

struct KnMonLaunchRequest
{
    std::string OperationId;
    std::string TargetPath;
    std::string AgentPath;
    std::string WorkingDirectory;
    std::uint32_t TimeoutMs = 5000;
    KnMonAgentArchitecture Architecture = KnMonAgentArchitecture::X64;
    KnMonInjectionMethod InjectionMethod = KnMonInjectionMethod::EarlyBirdApc;
};

struct KnMonLaunchResult
{
    std::string SchemaVersion = "0.1.0";
    std::string OperationId;
    bool Success = false;
    std::string BackendMode = "native-capture";
    std::string InjectionMethod = "early-bird APC";
    std::string TargetPath;
    std::string AgentPath;
    std::uint32_t TargetProcessId = 0;
    std::uint32_t TargetThreadId = 0;
    std::string Architecture;
    std::uint32_t Win32ErrorCode = 0;
    std::string NtStatus;
    std::string Subsystem;
    std::string Operation;
    std::string Message;
    KnMonAgentHandshake Handshake;
    std::vector<KnMonAuditEvent> AuditEvents;
};
}
