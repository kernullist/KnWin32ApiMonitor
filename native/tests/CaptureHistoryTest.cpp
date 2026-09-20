#include "knmon/common/CaptureHistory.h"
#include <iostream>
#include <stdexcept>

int main()
{
    int status = 1;
    try
    {
        knmon::KnMonCaptureResult result;
        result.HistoryBounded = true;
        knmon::KnMonAgentMessage message;
        message.MessageType = "api_call";
        message.RawPayload.assign(8192, 'A');
        knmon::KnMonAuditEvent audit;
        audit.Message.assign(8192, 'A');
        for (int index = 0; index < 10000; ++index)
        {
            knmon::RetainCapturedEvent(result, message);
            knmon::RetainAgentMessage(result, message);
            knmon::RetainAuditEvent(result, audit);
        }
        if (result.CapturedEventsSeen != 10000 || result.CapturedEvents.size() != 64 ||
            result.CapturedEventsOmitted != 9936 || result.AgentMessagesOmitted != 10000 ||
            result.AuditEvents.size() != 32 || result.AuditEventsOmitted != 9968)
        {
            throw std::runtime_error("History limits or omitted counts failed.");
        }
        message.MessageType = "diagnostic";
        for (int index = 0; index < 10000; ++index)
        {
            knmon::RetainAgentMessage(result, message);
        }
        const auto diagnostics = result.AgentMessages.size();
        for (const auto* type : { "agent_hello", "dropped_events", "agent_shutdown" })
        {
            message.MessageType = type;
            message.RawPayload.assign(256 * 1024, 'B');
            for (int index = 0; index < 5; ++index)
            {
                knmon::RetainAgentMessage(result, message);
            }
        }
        if (result.AgentMessages.size() != diagnostics + 3 || result.AgentHistoryBytes > 256 * 1024)
        {
            throw std::runtime_error("Lifecycle retention must survive a full diagnostic budget without unbounded duplicates.");
        }
        std::cout << "Capture history bounds and lifecycle retention passed.\n";
        status = 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
    }
    return status;
}
