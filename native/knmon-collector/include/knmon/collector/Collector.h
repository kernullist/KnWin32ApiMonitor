#pragma once

#include <knmon/common/Protocol.h>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <vector>

namespace knmon
{
enum class CollectorOverflowPolicy : std::uint32_t
{
    DropNewest = 0,
};

struct CollectorConfig
{
    std::size_t QueueCapacity = 1024;
    CollectorOverflowPolicy OverflowPolicy = CollectorOverflowPolicy::DropNewest;
    std::size_t MaxPayloadBytes = 65536;
};

struct CollectorStats
{
    std::uint64_t AcceptedEvents = 0;
    std::uint64_t DrainedEvents = 0;
    std::uint64_t DroppedEvents = 0;
    std::uint64_t QueueDepth = 0;
    std::uint64_t HighWaterMark = 0;
    std::uint64_t BackpressureActivations = 0;
};

struct CollectorEvent
{
    std::uint64_t Sequence = 0;
    std::string SchemaVersion = "0.1.0";
    std::uint32_t ProcessId = 0;
    std::uint32_t ThreadId = 0;
    std::string ApiName;
    std::uint64_t RelativeTimeUs = 0;
    std::string Payload;

    std::size_t PayloadSize() const;
};

class Collector
{
public:
    explicit Collector(const CollectorConfig& config);

    bool Enqueue(const CollectorEvent& event);
    std::vector<CollectorEvent> Drain(std::size_t maxEvents = 0);
    CollectorStats SnapshotStats() const;
    void Reset();

    const CollectorConfig& Config() const;

private:
    bool HasCapacityFor(const CollectorEvent& event) const;
    void RecordDrop();
    void RefreshDepthStats();

    CollectorConfig m_config;
    CollectorStats m_stats;
    std::deque<CollectorEvent> m_queue;
};

const char* CollectorOverflowPolicyName(CollectorOverflowPolicy policy);
}
