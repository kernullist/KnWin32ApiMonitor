#pragma once

#include <knmon/common/Protocol.h>

#include <cstdint>
#include <functional>
#include <string>

namespace knmon
{
struct SharedTransportReaderConfig
{
    std::uint32_t ExpectedArchitecture = 0;
    std::string ExpectedOperationId;
    std::uint32_t MaxRecordsPerDrain = 0;
};

struct SharedTransportDrainResult
{
    bool HeaderValid = false;
    bool StoppedOnUnavailableRecord = false;
    std::string ErrorMessage;
    std::uint64_t RecordsDrained = 0;
    std::uint64_t RecordsProduced = 0;
    std::uint64_t RecordsConsumed = 0;
    std::uint64_t RecordsDropped = 0;
    std::uint64_t HighWaterMark = 0;
    std::uint64_t Capacity = 0;
    std::uint64_t HookOverheadMinUs = 0;
    std::uint64_t HookOverheadAvgUs = 0;
    std::uint64_t HookOverheadMaxUs = 0;
};

using SharedTransportRecordCallback = std::function<bool(const KnMonTransportRecord& record)>;

class SharedTransportReader
{
public:
    SharedTransportReader(
        KnMonTransportHeader* header,
        KnMonTransportRecord* records,
        const SharedTransportReaderConfig& config);

    SharedTransportDrainResult SnapshotMetrics() const;
    SharedTransportDrainResult DrainAvailable(const SharedTransportRecordCallback& callback);

private:
    bool ValidateHeader(SharedTransportDrainResult& result) const;
    void SnapshotCounters(SharedTransportDrainResult& result) const;
    void RecordHookOverhead(SharedTransportDrainResult& result, std::uint64_t overheadUs) const;

    KnMonTransportHeader* m_header = nullptr;
    KnMonTransportRecord* m_records = nullptr;
    SharedTransportReaderConfig m_config;
};
}
