#include <knmon/collector/Collector.h>

#include <algorithm>

namespace knmon
{
std::size_t CollectorEvent::PayloadSize() const
{
    return Payload.size();
}

Collector::Collector(const CollectorConfig& config) :
    m_config(config)
{
}

bool Collector::Enqueue(const CollectorEvent& event)
{
    bool accepted = false;

    do
    {
        if (!HasCapacityFor(event))
        {
            RecordDrop();
            break;
        }

        m_queue.push_back(event);
        ++m_stats.AcceptedEvents;
        RefreshDepthStats();
        accepted = true;
    }
    while (false);

    return accepted;
}

std::vector<CollectorEvent> Collector::Drain(std::size_t maxEvents)
{
    std::vector<CollectorEvent> drained;

    const std::size_t limit = maxEvents == 0 ? m_queue.size() : std::min(maxEvents, m_queue.size());
    drained.reserve(limit);

    for (std::size_t index = 0; index < limit; ++index)
    {
        drained.push_back(m_queue.front());
        m_queue.pop_front();
    }

    m_stats.DrainedEvents += drained.size();
    RefreshDepthStats();
    return drained;
}

CollectorStats Collector::SnapshotStats() const
{
    CollectorStats stats = m_stats;
    stats.QueueDepth = m_queue.size();
    return stats;
}

void Collector::Reset()
{
    m_queue.clear();
    m_stats = {};
}

const CollectorConfig& Collector::Config() const
{
    return m_config;
}

bool Collector::HasCapacityFor(const CollectorEvent& event) const
{
    bool hasCapacity = false;

    do
    {
        if (m_config.QueueCapacity == 0)
        {
            break;
        }

        if (event.PayloadSize() > m_config.MaxPayloadBytes)
        {
            break;
        }

        if (m_queue.size() >= m_config.QueueCapacity)
        {
            break;
        }

        hasCapacity = true;
    }
    while (false);

    return hasCapacity;
}

void Collector::RecordDrop()
{
    ++m_stats.DroppedEvents;
    ++m_stats.BackpressureActivations;
    RefreshDepthStats();
}

void Collector::RefreshDepthStats()
{
    m_stats.QueueDepth = m_queue.size();
    if (m_stats.QueueDepth > m_stats.HighWaterMark)
    {
        m_stats.HighWaterMark = m_stats.QueueDepth;
    }
}

const char* CollectorOverflowPolicyName(CollectorOverflowPolicy policy)
{
    const char* name = "unknown";

    switch (policy)
    {
    case CollectorOverflowPolicy::DropNewest:
        name = "drop-newest";
        break;
    default:
        break;
    }

    return name;
}
}
