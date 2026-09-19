#include <knmon/collector/SharedTransportReader.h>

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace knmon
{
namespace
{
std::int64_t ReadCounter(volatile std::int64_t* value)
{
    return InterlockedCompareExchange64(value, 0, 0);
}

std::int32_t ReadState(volatile std::int32_t* value)
{
    return InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(value), 0, 0);
}

bool OperationMatches(const KnMonTransportHeader& header, const std::string& expected)
{
    bool matches = expected.size() < KnMonTransportOperationIdChars;
    if (matches && !expected.empty())
    {
        for (std::size_t index = 0; index < expected.size(); ++index)
        {
            if (header.OperationId[index] != static_cast<unsigned char>(expected[index]))
            {
                matches = false;
                break;
            }
        }
        matches = matches && header.OperationId[expected.size()] == L'\0';
    }
    return matches;
}
}

SharedTransportReader::SharedTransportReader(
    KnMonTransportHeader* header,
    KnMonTransportRecord* records,
    const SharedTransportReaderConfig& config) :
    m_header(header),
    m_records(records),
    m_config(config),
    m_state(config.State == nullptr ? &m_localState : config.State)
{
}

bool SharedTransportReader::Fail(SharedTransportDrainResult& result, const char* message) const
{
    if (!m_state->Corrupted)
    {
        m_state->Corrupted = true;
        m_state->ErrorMessage = message;
    }
    result.HeaderValid = false;
    result.TransportCorrupted = true;
    result.ErrorMessage = m_state->ErrorMessage;
    result.Capacity = m_config.TrustedCapacity;
    result.RecordsProduced = static_cast<std::uint64_t>(m_state->LastProducer);
    result.RecordsConsumed = static_cast<std::uint64_t>(m_state->NextConsumer);
    result.RecordsDropped = static_cast<std::uint64_t>(m_state->LastDropped);
    result.HighWaterMark = static_cast<std::uint64_t>(m_state->LastHighWaterMark);
    return false;
}

bool SharedTransportReader::ValidateHeader(SharedTransportDrainResult& result) const
{
    bool valid = false;
    do
    {
        if (m_state->Corrupted)
        {
            Fail(result, "Shared transport was previously corrupted.");
            break;
        }
        if (m_header == nullptr || m_records == nullptr ||
            (reinterpret_cast<std::uintptr_t>(m_header) % alignof(KnMonTransportHeader)) != 0 ||
            (reinterpret_cast<std::uintptr_t>(m_records) % alignof(KnMonTransportRecord)) != 0)
        {
            Fail(result, "Shared transport pointers are null or misaligned.");
            break;
        }
        if (m_config.TrustedCapacity < KnMonTransportMinCapacity ||
            m_config.TrustedCapacity > KnMonTransportMaxCapacity ||
            m_config.TrustedRecordBytes < static_cast<std::uint64_t>(m_config.TrustedCapacity) * sizeof(KnMonTransportRecord) ||
            !m_config.ValidateRecordIdentity)
        {
            Fail(result, "Trusted transport bounds or record validator are missing or invalid.");
            break;
        }
        KnMonTransportHeader header;
        std::memcpy(&header, m_header, sizeof(header));
        if (header.Magic != KnMonTransportMagic || header.AbiVersion != KnMonTransportAbiVersion ||
            header.HeaderSize != sizeof(KnMonTransportHeader) || header.RecordSize != sizeof(KnMonTransportRecord) ||
            header.Capacity != m_config.TrustedCapacity || header.Flags != 0)
        {
            Fail(result, "Shared transport header differs from the trusted layout.");
            break;
        }
        if ((m_config.ExpectedArchitecture != 0 && header.Architecture != m_config.ExpectedArchitecture) ||
            !OperationMatches(header, m_config.ExpectedOperationId))
        {
            Fail(result, "Shared transport architecture or operation identity mismatch.");
            break;
        }
        result.HeaderValid = true;
        result.Capacity = m_config.TrustedCapacity;
        valid = true;
    }
    while (false);
    return valid;
}

bool SharedTransportReader::SnapshotCounters(SharedTransportDrainResult& result) const
{
    const std::int64_t consumer = ReadCounter(&m_header->ConsumerSequence);
    const std::int64_t producer = ReadCounter(&m_header->ProducerSequence);
    const std::int64_t dropped = ReadCounter(&m_header->DroppedEvents);
    const std::int64_t highWater = ReadCounter(&m_header->HighWaterMark);
    bool valid = false;
    do
    {
        if (consumer != m_state->NextConsumer || consumer < 0 || producer < consumer ||
            producer < m_state->LastProducer || producer == (std::numeric_limits<std::int64_t>::max)() ||
            producer - consumer > static_cast<std::int64_t>(m_config.TrustedCapacity) ||
            dropped < m_state->LastDropped || highWater < m_state->LastHighWaterMark ||
            highWater > static_cast<std::int64_t>(m_config.TrustedCapacity))
        {
            Fail(result, "Shared transport counters are negative, regressed, or outside trusted bounds.");
            break;
        }
        m_state->LastProducer = producer;
        m_state->LastDropped = dropped;
        m_state->LastHighWaterMark = highWater;
        result.RecordsProduced = static_cast<std::uint64_t>(producer);
        result.RecordsConsumed = static_cast<std::uint64_t>(consumer);
        result.RecordsDropped = static_cast<std::uint64_t>(dropped);
        result.HighWaterMark = static_cast<std::uint64_t>(highWater);
        valid = true;
    }
    while (false);
    return valid;
}

bool SharedTransportReader::ValidateRecord(const KnMonTransportRecord& record, SharedTransportDrainResult& result) const
{
    bool valid = false;
    do
    {
        if (record.RecordSize != sizeof(KnMonTransportRecord) ||
            record.Text0Length > sizeof(record.Text0) || record.Text1Length > sizeof(record.Text1) ||
            record.Text2Length > sizeof(record.Text2) ||
            (record.Flags & ~KnMonTransportRecordFlagGenericInventory) != 0)
        {
            Fail(result, "Shared transport record layout, flags, or text length is invalid.");
            break;
        }
        if (record.EventKind == static_cast<std::uint16_t>(KnMonTransportEventKind::Unknown))
        {
            valid = record.ApiId == 0 && record.Flags == 0;
        }
        else if (record.EventKind == static_cast<std::uint16_t>(KnMonTransportEventKind::ApiCall))
        {
            valid = ((record.Flags & KnMonTransportRecordFlagGenericInventory) == 0 ||
                record.Values32[0] <= KnMonTransportSlotCount64) && m_config.ValidateRecordIdentity(record);
        }
        if (!valid)
        {
            Fail(result, "Shared transport event kind, API identity, or argument count is invalid.");
        }
    }
    while (false);
    return valid;
}

SharedTransportDrainResult SharedTransportReader::SnapshotMetrics() const
{
    SharedTransportDrainResult result;
    if (ValidateHeader(result))
    {
        SnapshotCounters(result);
    }
    return result;
}

SharedTransportDrainResult SharedTransportReader::DrainAvailable(const SharedTransportRecordCallback& callback)
{
    SharedTransportDrainResult result;
    do
    {
        if (!ValidateHeader(result))
        {
            break;
        }
        // A continuously refilling producer cannot monopolize the host thread.
        const std::uint32_t budget = m_config.MaxRecordsPerDrain == 0
            ? m_config.TrustedCapacity : std::min(m_config.TrustedCapacity, m_config.MaxRecordsPerDrain);
        while (result.RecordsDrained < budget)
        {
            if (!ValidateHeader(result) || !SnapshotCounters(result))
            {
                break;
            }
            const std::int64_t consumer = m_state->NextConsumer;
            if (consumer == m_state->LastProducer)
            {
                break;
            }
            KnMonTransportRecord& shared = m_records[consumer % m_config.TrustedCapacity];
            const std::int32_t state = ReadState(&shared.State);
            const std::int64_t sequence = ReadCounter(&shared.Sequence);
            if (state != static_cast<std::int32_t>(KnMonTransportRecordState::Committed))
            {
                if (state != static_cast<std::int32_t>(KnMonTransportRecordState::Free) &&
                    state != static_cast<std::int32_t>(KnMonTransportRecordState::Writing))
                {
                    Fail(result, "Shared transport slot state is invalid.");
                }
                result.StoppedOnUnavailableRecord = true;
                break;
            }
            KnMonTransportRecord record;
            std::memcpy(&record, &shared, sizeof(record));
            MemoryBarrier();
            if (sequence != consumer || record.Sequence != consumer || record.State != state ||
                ReadCounter(&shared.Sequence) != consumer || ReadState(&shared.State) != state)
            {
                Fail(result, "Shared transport commit token changed or sequence is invalid.");
                break;
            }
            if (!ValidateRecord(record, result))
            {
                break;
            }
            // Only the bounded local snapshot crosses the parser boundary.
            if (callback && !callback(record))
            {
                result.ErrorMessage = "Shared transport callback rejected a committed record.";
                break;
            }
            if (!ValidateHeader(result) || !SnapshotCounters(result))
            {
                break;
            }
            if (ReadCounter(&shared.Sequence) != consumer || ReadState(&shared.State) != state)
            {
                Fail(result, "Shared transport commit token changed during consumption.");
                break;
            }
            RecordHookOverhead(result, record.HookOverheadUs);
            InterlockedExchange(reinterpret_cast<volatile LONG*>(&shared.State), static_cast<LONG>(KnMonTransportRecordState::Free));
            InterlockedExchange64(&shared.Sequence, -1);
            MemoryBarrier();
            ++m_state->NextConsumer;
            InterlockedExchange64(&m_header->ConsumerSequence, m_state->NextConsumer);
            ++result.RecordsDrained;
        }
        if (!m_state->Corrupted && ValidateHeader(result))
        {
            SnapshotCounters(result);
        }
    }
    while (false);
    return result;
}

void SharedTransportReader::RecordHookOverhead(SharedTransportDrainResult& result, std::uint64_t overheadUs) const
{
    const std::uint64_t count = result.RecordsDrained + 1;
    if (count == 1)
    {
        result.HookOverheadMinUs = overheadUs;
        result.HookOverheadAvgUs = overheadUs;
        result.HookOverheadMaxUs = overheadUs;
    }
    else
    {
        result.HookOverheadMinUs = std::min(result.HookOverheadMinUs, overheadUs);
        result.HookOverheadMaxUs = std::max(result.HookOverheadMaxUs, overheadUs);
        if (overheadUs >= result.HookOverheadAvgUs)
        {
            result.HookOverheadAvgUs += (overheadUs - result.HookOverheadAvgUs) / count;
        }
        else
        {
            result.HookOverheadAvgUs -= (result.HookOverheadAvgUs - overheadUs) / count;
        }
    }
}
}
