#include <knmon/collector/SharedTransportReader.h>

#include <Windows.h>

#include <algorithm>

namespace knmon
{
namespace
{
std::uint64_t NonNegativeCounter(std::int64_t value)
{
    return value < 0 ? 0 : static_cast<std::uint64_t>(value);
}

std::int64_t ReadTransportCounter(volatile std::int64_t* value)
{
    std::int64_t result = 0;

    if (value != nullptr)
    {
        result = InterlockedCompareExchange64(value, 0, 0);
    }

    return result;
}

std::wstring WidenAscii(const std::string& value)
{
    std::wstring result;
    result.reserve(value.size());

    for (const char ch : value)
    {
        result.push_back(static_cast<unsigned char>(ch));
    }

    return result;
}

bool OperationIdMatches(const wchar_t* actual, const std::string& expected)
{
    bool matches = false;

    do
    {
        if (expected.empty())
        {
            matches = true;
            break;
        }

        if (actual == nullptr)
        {
            break;
        }

        const std::wstring wideExpected = WidenAscii(expected);
        matches = wcsncmp(actual, wideExpected.c_str(), KnMonTransportOperationIdChars) == 0;
    }
    while (false);

    return matches;
}
}

SharedTransportReader::SharedTransportReader(
    KnMonTransportHeader* header,
    KnMonTransportRecord* records,
    const SharedTransportReaderConfig& config) :
    m_header(header),
    m_records(records),
    m_config(config)
{
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

        for (;;)
        {
            if (m_config.MaxRecordsPerDrain != 0 && result.RecordsDrained >= m_config.MaxRecordsPerDrain)
            {
                break;
            }

            const std::int64_t consumer = ReadTransportCounter(&m_header->ConsumerSequence);
            const std::int64_t producer = ReadTransportCounter(&m_header->ProducerSequence);
            if (consumer >= producer)
            {
                break;
            }

            KnMonTransportRecord& record = m_records[consumer % m_header->Capacity];
            if (
                record.Sequence != consumer ||
                record.State != static_cast<std::int32_t>(KnMonTransportRecordState::Committed))
            {
                result.StoppedOnUnavailableRecord = true;
                break;
            }

            bool shouldConsume = true;
            if (callback)
            {
                shouldConsume = callback(record);
            }

            if (!shouldConsume)
            {
                result.ErrorMessage = "Shared transport callback rejected a committed record.";
                break;
            }

            RecordHookOverhead(result, record.HookOverheadUs);

            record.State = static_cast<std::int32_t>(KnMonTransportRecordState::Free);
            record.Sequence = -1;
            MemoryBarrier();
            InterlockedExchange64(&m_header->ConsumerSequence, consumer + 1);
            ++result.RecordsDrained;
        }

        SnapshotCounters(result);
    }
    while (false);

    return result;
}

bool SharedTransportReader::ValidateHeader(SharedTransportDrainResult& result) const
{
    bool valid = false;

    do
    {
        if (m_header == nullptr || m_records == nullptr)
        {
            result.ErrorMessage = "Shared transport header or record pointer is null.";
            break;
        }

        if (m_header->Magic != KnMonTransportMagic)
        {
            result.ErrorMessage = "Shared transport magic mismatch.";
            break;
        }

        if (m_header->AbiVersion != KnMonTransportAbiVersion)
        {
            result.ErrorMessage = "Shared transport ABI version mismatch.";
            break;
        }

        if (m_header->HeaderSize != sizeof(KnMonTransportHeader))
        {
            result.ErrorMessage = "Shared transport header size mismatch.";
            break;
        }

        if (m_header->RecordSize != sizeof(KnMonTransportRecord))
        {
            result.ErrorMessage = "Shared transport record size mismatch.";
            break;
        }

        if (m_header->Capacity < KnMonTransportMinCapacity || m_header->Capacity > KnMonTransportMaxCapacity)
        {
            result.ErrorMessage = "Shared transport capacity is outside supported bounds.";
            break;
        }

        if (m_config.ExpectedArchitecture != 0 && m_header->Architecture != m_config.ExpectedArchitecture)
        {
            result.ErrorMessage = "Shared transport architecture mismatch.";
            break;
        }

        if (!OperationIdMatches(m_header->OperationId, m_config.ExpectedOperationId))
        {
            result.ErrorMessage = "Shared transport operation id mismatch.";
            break;
        }

        valid = true;
    }
    while (false);

    result.HeaderValid = valid;
    if (valid)
    {
        result.Capacity = m_header->Capacity;
    }

    return valid;
}

void SharedTransportReader::SnapshotCounters(SharedTransportDrainResult& result) const
{
    if (m_header == nullptr)
    {
        return;
    }

    result.HeaderValid = true;
    result.Capacity = m_header->Capacity;
    result.RecordsProduced = NonNegativeCounter(ReadTransportCounter(&m_header->ProducerSequence));
    result.RecordsConsumed = NonNegativeCounter(ReadTransportCounter(&m_header->ConsumerSequence));
    result.RecordsDropped = NonNegativeCounter(ReadTransportCounter(&m_header->DroppedEvents));
    result.HighWaterMark = NonNegativeCounter(ReadTransportCounter(&m_header->HighWaterMark));
}

void SharedTransportReader::RecordHookOverhead(SharedTransportDrainResult& result, std::uint64_t overheadUs) const
{
    const std::uint64_t nextCount = result.RecordsDrained + 1;

    if (nextCount == 1)
    {
        result.HookOverheadMinUs = overheadUs;
        result.HookOverheadAvgUs = overheadUs;
        result.HookOverheadMaxUs = overheadUs;
        return;
    }

    result.HookOverheadMinUs = std::min(result.HookOverheadMinUs, overheadUs);
    result.HookOverheadMaxUs = std::max(result.HookOverheadMaxUs, overheadUs);
    result.HookOverheadAvgUs = ((result.HookOverheadAvgUs * (nextCount - 1)) + overheadUs) / nextCount;
}
}
