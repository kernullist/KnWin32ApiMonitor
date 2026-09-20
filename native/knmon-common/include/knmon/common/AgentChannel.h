#pragma once

#include <knmon/common/BoundedJson.h>
#include <cstdint>
#include <string>

namespace knmon
{
class AgentChannel
{
public:
    AgentChannel(const std::string& operationId, std::uint32_t processId, const std::string& nonce) :
        m_operationId(operationId), m_processId(processId), m_nonce(nonce)
    {
    }

    void Accept(const JsonDocument& message)
    {
        if (m_failed)
        {
            throw JsonInputError("Agent channel is already invalid.");
        }
        m_failed = true;
        ValidateAgentJson(message);
        const bool hello = message.String("messageType", true) == "agent_hello";
        if (m_nonce.size() != 64 || m_nonce.find_first_not_of("0123456789abcdef") != std::string::npos ||
            message.String("operationId", true) != m_operationId || message.UInt32("pid", true) != m_processId ||
            message.String("channelNonce", true) != m_nonce || (!m_receivedHello && !hello) || (m_receivedHello && hello))
        {
            throw JsonInputError("Agent channel identity or HELLO order mismatch.");
        }
        m_receivedHello = true;
        m_failed = false;
    }

private:
    std::string m_operationId;
    std::uint32_t m_processId;
    std::string m_nonce;
    bool m_receivedHello = false;
    bool m_failed = false;
};
}
