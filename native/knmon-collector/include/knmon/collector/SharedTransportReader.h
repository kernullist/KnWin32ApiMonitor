#pragma once

#include <knmon/common/Protocol.h>

#include <cstdint>
#include <functional>
#include <string>

namespace knmon
{
// Host-owned state survives per-drain reader construction. One consumer owns it.
struct SharedTransportReaderState
{
    std::int64_t NextConsumer = 0;
    std::int64_t LastProducer = 0;
    std::int64_t LastDropped = 0;
    std::int64_t LastHighWaterMark = 0;
    bool Corrupted = false;
    std::string ErrorMessage;
};

struct SharedTransportReaderConfig
{
    std::uint32_t TrustedCapacity = 0;
    std::uint64_t TrustedRecordBytes = 0;
    SharedTransportReaderState* State = nullptr;
    std::function<bool(const KnMonTransportRecord&)> ValidateRecordIdentity;
    std::uint32_t ExpectedArchitecture = 0;
    std::string ExpectedOperationId;
    std::uint32_t MaxRecordsPerDrain = 0;
};

struct SharedTransportDrainResult
{
    bool TransportCorrupted = false;
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

    SharedTransportReader(const SharedTransportReader&) = delete;
    SharedTransportReader& operator=(const SharedTransportReader&) = delete;

    SharedTransportDrainResult SnapshotMetrics() const;
    SharedTransportDrainResult DrainAvailable(const SharedTransportRecordCallback& callback);

private:
    bool ValidateHeader(SharedTransportDrainResult& result) const;
    bool SnapshotCounters(SharedTransportDrainResult& result) const;
    bool Fail(SharedTransportDrainResult& result, const char* message) const;
    bool ValidateRecord(const KnMonTransportRecord& record, SharedTransportDrainResult& result) const;
    void RecordHookOverhead(SharedTransportDrainResult& result, std::uint64_t overheadUs) const;

    KnMonTransportHeader* m_header = nullptr;
    KnMonTransportRecord* m_records = nullptr;
    SharedTransportReaderConfig m_config;
    mutable SharedTransportReaderState m_localState;
    SharedTransportReaderState* m_state = nullptr;
};
}
