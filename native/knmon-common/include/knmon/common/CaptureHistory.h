#pragma once

#include "knmon/common/Protocol.h"
#include <algorithm>

namespace knmon
{
    inline void RetainCapturedEvent(KnMonCaptureResult& result, const KnMonAgentMessage& event)
    {
        ++result.CapturedEventsSeen;
        if (result.HistoryBounded && (result.CapturedEvents.size() >= 128 ||
            event.RawPayload.size() > 512 * 1024 - result.CapturedHistoryBytes))
        {
            ++result.CapturedEventsOmitted;
        }
        else
        {
            result.CapturedEvents.push_back(event);
            if (result.HistoryBounded)
            {
                result.CapturedHistoryBytes += event.RawPayload.size();
            }
        }
    }

    inline void RetainAgentMessage(KnMonCaptureResult& result, const KnMonAgentMessage& event)
    {
        const bool lifecycle = event.MessageType == "agent_hello" || event.MessageType == "dropped_events" ||
            event.MessageType == "agent_shutdown";
        if (!result.HistoryBounded)
        {
            result.AgentMessages.push_back(event);
        }
        else if (lifecycle && event.RawPayload.size() <= 256 * 1024)
        {
            const auto existing = std::find_if(result.AgentMessages.begin(), result.AgentMessages.end(),
                [&](const auto& item)
                {
                    return item.MessageType == event.MessageType;
                });
            if (existing == result.AgentMessages.end())
            {
                result.AgentMessages.push_back(event);
            }
            else
            {
                *existing = event;
                ++result.AgentMessagesOmitted;
            }
        }
        else if (event.MessageType == "api_call" || result.AgentMessages.size() >= 512 ||
            event.RawPayload.size() > 256 * 1024 - result.AgentHistoryBytes)
        {
            ++result.AgentMessagesOmitted;
            if (event.MessageType == "resolver_pointer_candidate" || event.MessageType == "resolver_pointer_instrumented")
            {
                ++result.ResolverCandidatesOmitted;
            }
            else if (event.MessageType == "resolver_pointer_unsupported")
            {
                ++result.ResolverUnsupportedOmitted;
            }
        }
        else
        {
            result.AgentMessages.push_back(event);
            result.AgentHistoryBytes += event.RawPayload.size();
        }
    }

    inline void RetainAuditEvent(KnMonCaptureResult& result, const KnMonAuditEvent& event)
    {
        const auto bytes = event.Message.size() + event.Operation.size() + event.EventType.size() +
            event.OperationId.size() + event.TimestampUtc.size() + event.Subsystem.size() + event.NtStatus.size();
        if (result.HistoryBounded && (result.AuditEvents.size() >= 256 || bytes > 256 * 1024 - result.AuditHistoryBytes))
        {
            ++result.AuditEventsOmitted;
        }
        else
        {
            result.AuditEvents.push_back(event);
            if (result.HistoryBounded)
            {
                result.AuditHistoryBytes += bytes;
            }
        }
    }
}
