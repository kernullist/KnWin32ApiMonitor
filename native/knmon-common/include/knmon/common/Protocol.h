#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <knmon/common/GeneratedApiIds.h>

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
    RemoteLoadLibrary = 2,
};

enum class KnMonChildPolicy : std::uint32_t
{
    Observe = 0,
    AttachSupported = 1,
};

enum class KnMonProcessEligibility : std::uint32_t
{
    Eligible = 0,
    Missing = 1,
    Exited = 2,
    UnknownArchitecture = 3,
    HelperTargetMismatch = 4,
    AccessDenied = 5,
    ProtectedProcess = 6,
    Unsupported = 7,
};

enum class KnMonProcessPolicyDecision : std::uint32_t
{
    ObserveOnly = 0,
    AttachAllowed = 1,
    AttachSkipped = 2,
    AttachFailed = 3,
    Unsupported = 4,
};

enum class KnMonAgentMessageType : std::uint32_t
{
    Unknown = 0,
    AgentHello = 1,
    HookInstalled = 2,
    HookInstallFailed = 3,
    ApiCall = 4,
    DroppedEvents = 5,
    AgentShutdown = 6,
};

enum class KnMonTransportEventKind : std::uint16_t
{
    Unknown = 0,
    ApiCall = 1,
};

inline constexpr std::uint32_t KnMonTransportMagic = 0x4d54534b;
inline constexpr std::uint16_t KnMonTransportAbiVersion = 1;
inline constexpr std::uint32_t KnMonTransportDefaultCapacity = 1024;
inline constexpr std::uint32_t KnMonTransportMinCapacity = 2;
inline constexpr std::uint32_t KnMonTransportMaxCapacity = 65536;
inline constexpr std::uint32_t KnMonTransportOperationIdChars = 64;
inline constexpr std::uint32_t KnMonTransportText0Bytes = 512;
inline constexpr std::uint32_t KnMonTransportText1Bytes = 160;
inline constexpr std::uint32_t KnMonTransportText2Bytes = 80;
inline constexpr std::uint32_t KnMonTransportSlotCount64 = 8;
inline constexpr std::uint32_t KnMonTransportSlotCount32 = 8;

enum class KnMonTransportRecordState : std::int32_t
{
    Free = 0,
    Writing = 1,
    Committed = 2,
};

struct KnMonTransportHeader
{
    std::uint32_t Magic = KnMonTransportMagic;
    std::uint16_t AbiVersion = KnMonTransportAbiVersion;
    std::uint16_t HeaderSize = 0;
    std::uint32_t Architecture = 0;
    std::uint32_t Capacity = 0;
    std::uint32_t RecordSize = 0;
    std::uint32_t Flags = 0;
    alignas(8) volatile std::int64_t ProducerSequence = 0;
    alignas(8) volatile std::int64_t ConsumerSequence = 0;
    alignas(8) volatile std::int64_t DroppedEvents = 0;
    alignas(8) volatile std::int64_t HighWaterMark = 0;
    wchar_t OperationId[KnMonTransportOperationIdChars] = {};
};

struct KnMonTransportRecord
{
    alignas(8) volatile std::int64_t Sequence = -1;
    volatile std::int32_t State = static_cast<std::int32_t>(KnMonTransportRecordState::Free);
    std::uint16_t RecordSize = 0;
    std::uint16_t EventKind = static_cast<std::uint16_t>(KnMonTransportEventKind::Unknown);
    std::uint16_t ApiId = static_cast<std::uint16_t>(KnMonTransportApiId::Unknown);
    std::uint16_t ModuleId = static_cast<std::uint16_t>(KnMonTransportModuleId::Unknown);
    std::uint32_t Flags = 0;
    std::uint32_t ProcessId = 0;
    std::uint32_t ThreadId = 0;
    std::uint64_t DurationUs = 0;
    std::uint64_t HookOverheadUs = 0;
    std::uint64_t StartQpc = 0;
    std::uint64_t EndQpc = 0;
    std::uint64_t ReturnValue = 0;
    std::uint32_t ReturnCode = 0;
    std::uint32_t LastErrorCode = 0;
    std::uint64_t Values64[KnMonTransportSlotCount64] = {};
    std::uint32_t Values32[KnMonTransportSlotCount32] = {};
    std::uint32_t Text0Length = 0;
    std::uint32_t Text1Length = 0;
    std::uint32_t Text2Length = 0;
    char Text0[KnMonTransportText0Bytes] = {};
    char Text1[KnMonTransportText1Bytes] = {};
    char Text2[KnMonTransportText2Bytes] = {};
};

static_assert(sizeof(KnMonTransportHeader) % 8 == 0, "transport header must remain 8-byte aligned");
static_assert(alignof(KnMonTransportRecord) >= 8, "transport records must keep 64-bit counters aligned");
static_assert(sizeof(KnMonTransportRecord) % 8 == 0, "transport record must remain 8-byte aligned");

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

struct KnMonAttachRequest
{
    std::string OperationId;
    std::uint32_t ProcessId = 0;
    std::string AgentPath;
    std::uint32_t TimeoutMs = 5000;
    std::uint32_t DurationMs = 3000;
    KnMonAgentArchitecture Architecture = KnMonAgentArchitecture::Unknown;
    KnMonInjectionMethod InjectionMethod = KnMonInjectionMethod::RemoteLoadLibrary;
};

struct KnMonProcessTreeRequest
{
    std::string OperationId;
    std::uint32_t RootProcessId = 0;
    std::string AgentPath;
    std::uint32_t TimeoutMs = 7000;
    std::uint32_t DurationMs = 3000;
    std::uint32_t PollIntervalMs = 100;
    KnMonAgentArchitecture Architecture = KnMonAgentArchitecture::Unknown;
    KnMonChildPolicy ChildPolicy = KnMonChildPolicy::Observe;
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

struct KnMonAgentMessage
{
    std::string SchemaVersion = "0.1.0";
    std::string MessageType;
    std::string OperationId;
    std::uint32_t ProcessId = 0;
    std::uint32_t ThreadId = 0;
    std::string TimestampUtc;
    std::uint64_t Sequence = 0;
    std::string RawPayload;
};

struct KnMonCaptureResult
{
    std::string SchemaVersion = "0.1.0";
    std::string OperationId;
    bool Success = false;
    std::string BackendMode = "native-capture";
    std::string CaptureMode = "bounded-native-capture";
    std::string InjectionMethod = "early-bird APC";
    std::string TargetPath;
    std::string AgentPath;
    std::uint32_t AttachProcessId = 0;
    std::string DetachPolicy;
    std::uint32_t TargetProcessId = 0;
    std::uint32_t TargetThreadId = 0;
    std::string Architecture;
    std::uint32_t Win32ErrorCode = 0;
    std::string NtStatus;
    std::string Subsystem;
    std::string Operation;
    std::string Message;
    std::uint64_t DroppedEvents = 0;
    std::string TransportMode = "named-pipe-json";
    std::uint64_t TransportCapacity = 0;
    std::uint64_t TransportRecordsProduced = 0;
    std::uint64_t TransportRecordsConsumed = 0;
    std::uint64_t TransportDroppedEvents = 0;
    std::uint64_t TransportHighWaterMark = 0;
    std::uint64_t HookOverheadMinUs = 0;
    std::uint64_t HookOverheadAvgUs = 0;
    std::uint64_t HookOverheadMaxUs = 0;
    KnMonAgentHandshake Handshake;
    std::vector<KnMonAuditEvent> AuditEvents;
    std::vector<KnMonAgentMessage> AgentMessages;
    std::vector<KnMonAgentMessage> CapturedEvents;
};

struct KnMonChildPolicyDecision
{
    std::uint32_t ProcessId = 0;
    std::uint32_t ParentProcessId = 0;
    std::string ImageName;
    std::string Architecture;
    std::string EligibilityStatus;
    std::string Decision;
    bool MutationAttempted = false;
    bool AttachSucceeded = false;
    std::string Reason;
};

struct KnMonProcessTreeNode
{
    std::uint32_t ProcessId = 0;
    std::uint32_t ParentProcessId = 0;
    bool IsRoot = false;
    std::string ImageName;
    std::string ImagePath;
    std::string Architecture;
    std::string FirstSeenUtc;
    std::string LastSeenUtc;
    bool IsAlive = false;
    bool Exited = false;
    std::string EligibilityStatus;
    std::string PolicyDecision;
    std::string Message;
};

struct KnMonProcessTreeResult
{
    std::string SchemaVersion = "0.1.0";
    std::string OperationId;
    bool Success = false;
    std::string BackendMode = "native-capture";
    std::string SupervisionMode = "process-tree";
    std::uint32_t RootProcessId = 0;
    std::uint32_t DurationMs = 0;
    std::string ChildPolicy;
    std::uint32_t Win32ErrorCode = 0;
    std::string NtStatus;
    std::string Subsystem;
    std::string Operation;
    std::string Message;
    std::vector<KnMonProcessTreeNode> ProcessNodes;
    std::vector<KnMonChildPolicyDecision> PolicyDecisions;
    std::vector<KnMonAuditEvent> AuditEvents;
    std::vector<KnMonCaptureResult> ChildAttachResults;
};
}
