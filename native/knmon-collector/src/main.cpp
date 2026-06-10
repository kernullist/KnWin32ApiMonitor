#include <knmon/core/Controller.h>
#include <knmon/collector/Collector.h>
#include <knmon/collector/SharedTransportReader.h>

#include <algorithm>
#include <cwchar>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace
{
std::string JsonEscape(const std::string& value)
{
    std::ostringstream stream;

    for (const char ch : value)
    {
        const unsigned char byte = static_cast<unsigned char>(ch);
        switch (ch)
        {
        case '\\':
            stream << "\\\\";
            break;
        case '"':
            stream << "\\\"";
            break;
        case '\n':
            stream << "\\n";
            break;
        case '\r':
            stream << "\\r";
            break;
        case '\t':
            stream << "\\t";
            break;
        default:
            if (byte < 0x20)
            {
                const char* hex = "0123456789abcdef";
                stream << "\\u00" << hex[(byte >> 4) & 0x0f] << hex[byte & 0x0f];
            }
            else
            {
                stream << ch;
            }
            break;
        }
    }

    return stream.str();
}

std::string Q(const std::string& value)
{
    return "\"" + JsonEscape(value) + "\"";
}

bool ParseSizeArgument(int argc, char** argv, const std::string& name, std::size_t* value)
{
    bool parsed = false;

    do
    {
        if (value == nullptr)
        {
            break;
        }

        for (int index = 2; index + 1 < argc; ++index)
        {
            if (argv[index] == name)
            {
                *value = static_cast<std::size_t>(std::stoull(argv[index + 1]));
                parsed = true;
                break;
            }
        }
    }
    while (false);

    return parsed;
}

bool HasFlag(int argc, char** argv, const std::string& name)
{
    bool found = false;

    for (int index = 2; index < argc; ++index)
    {
        if (argv[index] == name)
        {
            found = true;
            break;
        }
    }

    return found;
}

knmon::CollectorEvent MakeSyntheticEvent(std::uint64_t sequence)
{
    knmon::CollectorEvent event;
    event.Sequence = sequence;
    event.ProcessId = 4000;
    event.ThreadId = 4001;
    event.ApiName = "CreateFileW";
    event.RelativeTimeUs = sequence * 10;
    event.Payload = "{\"schemaVersion\":\"0.1.0\",\"api\":\"CreateFileW\"}";
    return event;
}

knmon::KnMonTransportRecord MakeSyntheticTransportRecord(std::int64_t sequence)
{
    knmon::KnMonTransportRecord record;
    record.Sequence = sequence;
    record.State = static_cast<std::int32_t>(knmon::KnMonTransportRecordState::Committed);
    record.RecordSize = sizeof(knmon::KnMonTransportRecord);
    record.EventKind = static_cast<std::uint16_t>(knmon::KnMonTransportEventKind::ApiCall);
    record.ApiId = static_cast<std::uint16_t>(knmon::KnMonTransportApiId::CreateFileW);
    record.ModuleId = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Kernel32);
    record.ProcessId = 4000;
    record.ThreadId = 4001;
    record.DurationUs = static_cast<std::uint64_t>((sequence + 1) * 10);
    record.HookOverheadUs = static_cast<std::uint64_t>((sequence + 1) * 2);
    return record;
}

std::string SequenceArrayJson(const std::vector<knmon::CollectorEvent>& events)
{
    std::ostringstream stream;
    stream << "[";
    for (std::size_t index = 0; index < events.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << events[index].Sequence;
    }
    stream << "]";
    return stream.str();
}

std::string SequenceArrayJson(const std::vector<std::uint64_t>& sequences)
{
    std::ostringstream stream;
    stream << "[";
    for (std::size_t index = 0; index < sequences.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << sequences[index];
    }
    stream << "]";
    return stream.str();
}

int RunBackpressureSmoke(int argc, char** argv)
{
    std::size_t capacity = 4;
    std::size_t eventCount = 10;
    ParseSizeArgument(argc, argv, "--capacity", &capacity);
    ParseSizeArgument(argc, argv, "--events", &eventCount);

    knmon::CollectorConfig config;
    config.QueueCapacity = capacity;
    config.OverflowPolicy = knmon::CollectorOverflowPolicy::DropNewest;

    knmon::Collector collector(config);
    for (std::size_t index = 0; index < eventCount; ++index)
    {
        collector.Enqueue(MakeSyntheticEvent(static_cast<std::uint64_t>(index + 1)));
    }

    const auto drained = collector.Drain();
    const auto stats = collector.SnapshotStats();
    const std::uint64_t firstSequence = drained.empty() ? 0 : drained.front().Sequence;
    const std::uint64_t lastSequence = drained.empty() ? 0 : drained.back().Sequence;
    const bool overflowExpected = eventCount > capacity;
    const std::uint64_t expectedDropped = overflowExpected ? static_cast<std::uint64_t>(eventCount - capacity) : 0;
    const std::uint64_t expectedAccepted = static_cast<std::uint64_t>(eventCount < capacity ? eventCount : capacity);
    const bool success =
        stats.AcceptedEvents == expectedAccepted &&
        stats.AcceptedEvents == drained.size() &&
        stats.DrainedEvents == drained.size() &&
        stats.DroppedEvents == expectedDropped &&
        stats.BackpressureActivations == expectedDropped &&
        stats.HighWaterMark == expectedAccepted &&
        firstSequence == (drained.empty() ? 0 : 1) &&
        lastSequence == drained.size();

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (success ? "true" : "false") << ",";
    stream << "\"operation\":\"smoke-backpressure\",";
    stream << "\"policy\":" << Q(knmon::CollectorOverflowPolicyName(config.OverflowPolicy)) << ",";
    stream << "\"capacity\":" << capacity << ",";
    stream << "\"eventsRequested\":" << eventCount << ",";
    stream << "\"acceptedEvents\":" << stats.AcceptedEvents << ",";
    stream << "\"drainedEvents\":" << stats.DrainedEvents << ",";
    stream << "\"droppedEvents\":" << stats.DroppedEvents << ",";
    stream << "\"queueDepth\":" << stats.QueueDepth << ",";
    stream << "\"highWaterMark\":" << stats.HighWaterMark << ",";
    stream << "\"backpressureActivations\":" << stats.BackpressureActivations << ",";
    stream << "\"firstSequence\":" << firstSequence << ",";
    stream << "\"lastSequence\":" << lastSequence << ",";
    stream << "\"retainedSequences\":" << SequenceArrayJson(drained) << ",";
    stream << "\"message\":" << Q(success ? "Collector backpressure smoke passed." : "Collector backpressure smoke failed.");
    stream << "}";
    std::cout << stream.str() << "\n";

    return success ? 0 : 1;
}

int RunSharedTransportReaderSmoke(int argc, char** argv)
{
    std::size_t capacity = 4;
    std::size_t recordCount = 3;
    std::size_t maxDrain = 0;
    ParseSizeArgument(argc, argv, "--capacity", &capacity);
    ParseSizeArgument(argc, argv, "--records", &recordCount);
    ParseSizeArgument(argc, argv, "--max-drain", &maxDrain);
    const bool partial = HasFlag(argc, argv, "--partial");

    capacity = std::min<std::size_t>(std::max<std::size_t>(capacity, knmon::KnMonTransportMinCapacity), knmon::KnMonTransportMaxCapacity);
    recordCount = std::min(recordCount, capacity);

    knmon::KnMonTransportHeader header;
    header.Magic = knmon::KnMonTransportMagic;
    header.AbiVersion = knmon::KnMonTransportAbiVersion;
    header.HeaderSize = sizeof(knmon::KnMonTransportHeader);
    header.Architecture = static_cast<std::uint32_t>(knmon::KnMonAgentArchitecture::X64);
    header.Capacity = static_cast<std::uint32_t>(capacity);
    header.RecordSize = sizeof(knmon::KnMonTransportRecord);
    header.ProducerSequence = static_cast<std::int64_t>(recordCount);
    header.ConsumerSequence = 0;
    header.DroppedEvents = 0;
    header.HighWaterMark = static_cast<std::int64_t>(recordCount);
    wcsncpy_s(header.OperationId, L"collector-reader-smoke", _TRUNCATE);

    std::vector<knmon::KnMonTransportRecord> records(capacity);
    const std::size_t committedCount = partial && recordCount > 0 ? recordCount - 1 : recordCount;
    for (std::size_t index = 0; index < committedCount; ++index)
    {
        records[index] = MakeSyntheticTransportRecord(static_cast<std::int64_t>(index));
    }

    if (partial && committedCount < recordCount)
    {
        records[committedCount] = MakeSyntheticTransportRecord(static_cast<std::int64_t>(committedCount));
        records[committedCount].State = static_cast<std::int32_t>(knmon::KnMonTransportRecordState::Writing);
    }

    knmon::SharedTransportReaderConfig config;
    config.ExpectedArchitecture = static_cast<std::uint32_t>(knmon::KnMonAgentArchitecture::X64);
    config.ExpectedOperationId = "collector-reader-smoke";
    config.MaxRecordsPerDrain = static_cast<std::uint32_t>(maxDrain);

    std::vector<std::uint64_t> consumedSequences;
    knmon::SharedTransportReader reader(&header, records.data(), config);
    const knmon::SharedTransportDrainResult drain = reader.DrainAvailable([&consumedSequences](const knmon::KnMonTransportRecord& record)
    {
        consumedSequences.push_back(static_cast<std::uint64_t>(record.Sequence));
        return true;
    });

    const std::size_t configuredLimit = maxDrain == 0 ? recordCount : std::min(maxDrain, recordCount);
    const std::size_t expectedDrained = partial ? std::min(committedCount, configuredLimit) : configuredLimit;
    bool sequencesMatch = consumedSequences.size() == expectedDrained;
    for (std::size_t index = 0; index < consumedSequences.size(); ++index)
    {
        if (consumedSequences[index] != index)
        {
            sequencesMatch = false;
            break;
        }
    }

    const bool expectedUnavailable = partial && expectedDrained == committedCount && configuredLimit > committedCount;
    const bool success =
        drain.HeaderValid &&
        drain.RecordsDrained == expectedDrained &&
        drain.RecordsProduced == recordCount &&
        drain.RecordsConsumed == expectedDrained &&
        drain.RecordsDropped == 0 &&
        drain.HighWaterMark == recordCount &&
        drain.StoppedOnUnavailableRecord == expectedUnavailable &&
        sequencesMatch;

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (success ? "true" : "false") << ",";
    stream << "\"operation\":\"smoke-shared-transport-reader\",";
    stream << "\"capacity\":" << capacity << ",";
    stream << "\"recordsRequested\":" << recordCount << ",";
    stream << "\"maxDrain\":" << maxDrain << ",";
    stream << "\"partial\":" << (partial ? "true" : "false") << ",";
    stream << "\"headerValid\":" << (drain.HeaderValid ? "true" : "false") << ",";
    stream << "\"stoppedOnUnavailableRecord\":" << (drain.StoppedOnUnavailableRecord ? "true" : "false") << ",";
    stream << "\"recordsDrained\":" << drain.RecordsDrained << ",";
    stream << "\"recordsProduced\":" << drain.RecordsProduced << ",";
    stream << "\"recordsConsumed\":" << drain.RecordsConsumed << ",";
    stream << "\"recordsDropped\":" << drain.RecordsDropped << ",";
    stream << "\"highWaterMark\":" << drain.HighWaterMark << ",";
    stream << "\"hookOverheadMinUs\":" << drain.HookOverheadMinUs << ",";
    stream << "\"hookOverheadAvgUs\":" << drain.HookOverheadAvgUs << ",";
    stream << "\"hookOverheadMaxUs\":" << drain.HookOverheadMaxUs << ",";
    stream << "\"consumedSequences\":" << SequenceArrayJson(consumedSequences) << ",";
    stream << "\"message\":" << Q(success ? "Shared transport reader smoke passed." : drain.ErrorMessage.empty() ? "Shared transport reader smoke failed." : drain.ErrorMessage);
    stream << "}";
    std::cout << stream.str() << "\n";

    return success ? 0 : 1;
}
}

int main(int argc, char** argv)
{
    if (argc >= 2 && std::string(argv[1]) == "smoke-backpressure")
    {
        return RunBackpressureSmoke(argc, argv);
    }

    if (argc >= 2 && std::string(argv[1]) == "smoke-shared-transport-reader")
    {
        return RunSharedTransportReaderSmoke(argc, argv);
    }

    knmon::Controller controller;
    knmon::KnMonError error;
    const auto targets = controller.EnumerateTargets(&error);

    std::cout << "knmon-collector protocol "
              << knmon::KnMonProtocolMajor << "."
              << knmon::KnMonProtocolMinor << "."
              << knmon::KnMonProtocolPatch << "\n";

    if (error.Code != 0)
    {
        std::cout << "enumerate error: " << error.Message << "\n";
    }
    else
    {
        std::cout << "targets: " << targets.size() << "\n";
    }

    std::cout << "capture backend: mock-only safe MVP\n";
    std::cout << "collector smoke: smoke-backpressure --capacity 4 --events 10\n";
    std::cout << "collector smoke: smoke-shared-transport-reader --capacity 4 --records 3\n";
    return error.Code == 0 ? 0 : 1;
}
