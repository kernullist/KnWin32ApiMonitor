#pragma once

#include <knmon/common/Protocol.h>

#include <functional>
#include <cstdint>
#include <vector>

namespace knmon
{
struct KnMonTraceBatch
{
    std::string SchemaVersion = "0.1.0";
    std::string SessionId;
    std::string OperationId;
    std::uint64_t BatchSequence = 0;
    std::uint64_t FirstRecordSequence = 0;
    std::uint64_t LastRecordSequence = 0;
    std::uint64_t EventCount = 0;
    std::uint64_t DroppedEvents = 0;
    std::uint64_t RecordsStreamed = 0;
    std::uint64_t HostDroppedBatches = 0;
    std::vector<KnMonAgentMessage> Events;
};

struct KnMonCaptureStreamCallbacks
{
    std::uint32_t MaxRecordsPerBatch = 0;
    std::function<bool(const KnMonTraceBatch& batch)> OnTraceBatch;
    std::function<void(const std::string& frameType, const KnMonCaptureResult& result)> OnSessionFrame;
};

class Controller
{
public:
    std::vector<KnMonTargetProcess> EnumerateTargets(KnMonError* error) const;
    KnMonLaunchResult LaunchWithEarlyBirdApc(const KnMonLaunchRequest& request) const;
    KnMonCaptureResult CaptureSampleFileIo(const KnMonLaunchRequest& request) const;
    KnMonCaptureResult AttachCapture(const KnMonAttachRequest& request) const;
    KnMonCaptureResult AttachCapture(const KnMonAttachRequest& request, const KnMonCaptureStreamCallbacks* streamCallbacks) const;
    KnMonProcessTreeResult SuperviseProcessTree(const KnMonProcessTreeRequest& request) const;

    KnMonError LaunchTarget(const std::string& imagePath) const;
    KnMonError AttachToTarget(std::uint32_t processId) const;
    KnMonError DetachFromTarget(std::uint32_t processId) const;
    KnMonError StartCapture(std::uint32_t processId) const;
    KnMonError StopCapture(std::uint32_t processId) const;
};
}
