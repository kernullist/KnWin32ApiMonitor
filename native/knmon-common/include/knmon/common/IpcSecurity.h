#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace knmon
{
struct ProcessIdentity
{
    DWORD ProcessId = 0;
    DWORD SessionId = 0;
    LUID AuthenticationId = {};
    std::uint64_t CreationTime = 0;
    std::vector<unsigned char> LogonSid;
};

bool ReadProcessIdentity(HANDLE process, ProcessIdentity& identity);
bool SameLogon(const ProcessIdentity& left, const ProcessIdentity& right);
std::uint64_t ProcessCreationTime(HANDLE process);
bool RandomIpcName(const wchar_t* prefix, std::wstring& name);
std::wstring ChannelNonce(const std::wstring& pipeName);

class LocalIpcSecurity
{
public:
    LocalIpcSecurity() = default;
    LocalIpcSecurity(const LocalIpcSecurity&) = delete;
    LocalIpcSecurity& operator=(const LocalIpcSecurity&) = delete;
    bool Initialize(DWORD accessMask);
    SECURITY_ATTRIBUTES* Attributes();

private:
    ProcessIdentity m_identity;
    std::vector<unsigned char> m_acl;
    std::vector<unsigned char> m_labelAcl;
    SECURITY_DESCRIPTOR m_descriptor = {};
    SECURITY_ATTRIBUTES m_attributes = {};
};

inline constexpr DWORD AgentPipeClientAccess = FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
inline constexpr DWORD AgentPipeAclAccess = FILE_GENERIC_READ | AgentPipeClientAccess;
inline constexpr DWORD TransportAclAccess = SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_QUERY | READ_CONTROL;

HANDLE CreateLocalAgentPipe(std::wstring& name, DWORD timeoutMs);
bool AuthenticatePipeClient(HANDLE pipe, HANDLE expectedProcess);
// On success, an optional retained handle belongs to the caller.
bool AuthenticatePipeServer(HANDLE pipe, DWORD expectedPid, std::uint64_t expectedCreationTime, HANDLE* retainedProcess = nullptr);
inline constexpr std::size_t MaxAgentMessageBytes = 65536;
// Only message pipes are accepted; writes never wait for the controller to read.
bool ConfigureAgentPipeWriter(HANDLE pipe);
bool TryWriteAgentMessage(HANDLE pipe, std::string_view message);
}
