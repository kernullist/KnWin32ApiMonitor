#include <knmon/core/Controller.h>
#include <knmon/collector/Collector.h>

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
}

int main(int argc, char** argv)
{
    if (argc >= 2 && std::string(argv[1]) == "smoke-backpressure")
    {
        return RunBackpressureSmoke(argc, argv);
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
    return error.Code == 0 ? 0 : 1;
}
