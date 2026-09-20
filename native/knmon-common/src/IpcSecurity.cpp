#include <knmon/common/IpcSecurity.h>
#include <bcrypt.h>

namespace knmon
{
namespace
{
class HandleScope
{
public:
    explicit HandleScope(HANDLE& handle) : m_handle(handle)
    {
    }
    ~HandleScope()
    {
        if (m_handle != nullptr)
        {
            const DWORD error = GetLastError();
            CloseHandle(m_handle);
            SetLastError(error);
        }
    }
    HandleScope(const HandleScope&) = delete;
    HandleScope& operator=(const HandleScope&) = delete;

private:
    HANDLE& m_handle;
};

bool TokenInformation(HANDLE token, TOKEN_INFORMATION_CLASS type, std::vector<unsigned char>& data)
{
    DWORD bytes = 0;
    GetTokenInformation(token, type, nullptr, 0, &bytes);
    if (bytes == 0 || bytes > 1024 * 1024)
    {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    data.resize(bytes);
    return GetTokenInformation(token, type, data.data(), bytes, &bytes) != FALSE;
}
}

std::uint64_t ProcessCreationTime(HANDLE process)
{
    FILETIME creation = {}, exit = {}, kernel = {}, user = {};
    if (!GetProcessTimes(process, &creation, &exit, &kernel, &user))
    {
        return 0;
    }
    return (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
}

bool ReadProcessIdentity(HANDLE process, ProcessIdentity& identity)
{
    bool valid = false;
    HANDLE token = nullptr;
    HandleScope tokenScope(token);
    identity = {};
    do
    {
        identity.ProcessId = GetProcessId(process);
        identity.CreationTime = ProcessCreationTime(process);
        if (identity.ProcessId == 0 || identity.CreationTime == 0 || !OpenProcessToken(process, TOKEN_QUERY, &token))
        {
            break;
        }
        TOKEN_STATISTICS statistics = {};
        DWORD bytes = 0;
        if (!GetTokenInformation(token, TokenStatistics, &statistics, sizeof(statistics), &bytes) ||
            !GetTokenInformation(token, TokenSessionId, &identity.SessionId, sizeof(identity.SessionId), &bytes))
        {
            break;
        }
        identity.AuthenticationId = statistics.AuthenticationId;
        std::vector<unsigned char> groups;
        if (!TokenInformation(token, TokenGroups, groups))
        {
            break;
        }
        const auto* tokenGroups = reinterpret_cast<const TOKEN_GROUPS*>(groups.data());
        for (DWORD index = 0; index < tokenGroups->GroupCount; ++index)
        {
            const auto& group = tokenGroups->Groups[index];
            if ((group.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID && IsValidSid(group.Sid))
            {
                identity.LogonSid.resize(GetLengthSid(group.Sid));
                valid = CopySid(static_cast<DWORD>(identity.LogonSid.size()), identity.LogonSid.data(), group.Sid) != FALSE;
                break;
            }
        }
    }
    while (false);
    const DWORD error = valid ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
    SetLastError(error);
    return valid;
}

bool SameLogon(const ProcessIdentity& left, const ProcessIdentity& right)
{
    return !left.LogonSid.empty() && left.LogonSid == right.LogonSid && left.SessionId == right.SessionId &&
        left.AuthenticationId.LowPart == right.AuthenticationId.LowPart && left.AuthenticationId.HighPart == right.AuthenticationId.HighPart;
}

bool RandomIpcName(const wchar_t* prefix, std::wstring& name)
{
    unsigned char nonce[32] = {};
    if (BCryptGenRandom(nullptr, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
    {
        SetLastError(ERROR_GEN_FAILURE);
        return false;
    }
    constexpr wchar_t hex[] = L"0123456789abcdef";
    name = prefix;
    for (const unsigned char value : nonce)
    {
        name.push_back(hex[value >> 4]);
        name.push_back(hex[value & 15]);
    }
    return true;
}

std::wstring ChannelNonce(const std::wstring& pipeName)
{
    const std::wstring prefix = L"\\\\.\\pipe\\knmon_agent_";
    if (pipeName.size() != prefix.size() + 64 || pipeName.compare(0, prefix.size(), prefix) != 0)
    {
        return {};
    }
    const std::wstring nonce = pipeName.substr(prefix.size());
    if (nonce.find_first_not_of(L"0123456789abcdef") != std::wstring::npos)
    {
        return {};
    }
    return nonce;
}

bool LocalIpcSecurity::Initialize(DWORD accessMask)
{
    bool initialized = false;
    do
    {
        if (!ReadProcessIdentity(GetCurrentProcess(), m_identity))
        {
            break;
        }
        unsigned char ownerRightsSid[SECURITY_MAX_SID_SIZE] = {};
        DWORD ownerRightsBytes = sizeof(ownerRightsSid);
        if (!CreateWellKnownSid(WinCreatorOwnerRightsSid, nullptr, ownerRightsSid, &ownerRightsBytes))
        {
            break;
        }
        const DWORD bytes = sizeof(ACL) + 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) +
            static_cast<DWORD>(m_identity.LogonSid.size()) + ownerRightsBytes;
        m_acl.resize(bytes);
        auto* acl = reinterpret_cast<ACL*>(m_acl.data());
        if (!InitializeAcl(acl, bytes, ACL_REVISION) ||
            !AddAccessAllowedAce(acl, ACL_REVISION, accessMask, m_identity.LogonSid.data()) ||
            !AddAccessAllowedAce(acl, ACL_REVISION, READ_CONTROL, ownerRightsSid) ||
            !InitializeSecurityDescriptor(&m_descriptor, SECURITY_DESCRIPTOR_REVISION) ||
            !SetSecurityDescriptorDacl(&m_descriptor, TRUE, acl, FALSE) ||
            !SetSecurityDescriptorControl(&m_descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED))
        {
            break;
        }
        unsigned char mediumSid[SECURITY_MAX_SID_SIZE] = {};
        DWORD sidBytes = sizeof(mediumSid);
        if (!CreateWellKnownSid(WinMediumLabelSid, nullptr, mediumSid, &sidBytes))
        {
            break;
        }
        const DWORD labelBytes = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) - sizeof(DWORD) + sidBytes;
        m_labelAcl.resize(labelBytes);
        auto* labelAcl = reinterpret_cast<ACL*>(m_labelAcl.data());
        if (!InitializeAcl(labelAcl, labelBytes, ACL_REVISION) ||
            !AddMandatoryAce(labelAcl, ACL_REVISION, 0, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, mediumSid) ||
            !SetSecurityDescriptorSacl(&m_descriptor, TRUE, labelAcl, FALSE))
        {
            break;
        }
        m_attributes.nLength = sizeof(m_attributes);
        m_attributes.lpSecurityDescriptor = &m_descriptor;
        m_attributes.bInheritHandle = FALSE;
        initialized = true;
    }
    while (false);
    return initialized;
}

SECURITY_ATTRIBUTES* LocalIpcSecurity::Attributes()
{
    return &m_attributes;
}

HANDLE CreateLocalAgentPipe(std::wstring& name, DWORD timeoutMs)
{
    LocalIpcSecurity security;
    if (!security.Initialize(AgentPipeAclAccess) || !RandomIpcName(L"\\\\.\\pipe\\knmon_agent_", name))
    {
        return INVALID_HANDLE_VALUE;
    }
    return CreateNamedPipeW(name.c_str(), PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 65536, 65536, timeoutMs, security.Attributes());
}

bool AuthenticatePipeClient(HANDLE pipe, HANDLE expectedProcess)
{
    ULONG connectedPid = 0;
    ProcessIdentity expected;
    ProcessIdentity current;
    const bool valid = GetNamedPipeClientProcessId(pipe, &connectedPid) && connectedPid != 0 &&
        connectedPid == GetProcessId(expectedProcess) && ReadProcessIdentity(expectedProcess, expected) &&
        ReadProcessIdentity(GetCurrentProcess(), current) && SameLogon(expected, current);
    if (!valid)
    {
        SetLastError(ERROR_ACCESS_DENIED);
    }
    return valid;
}

bool AuthenticatePipeServer(HANDLE pipe, DWORD expectedPid, std::uint64_t expectedCreationTime, HANDLE* retainedProcess)
{
    bool valid = false;
    HANDLE server = nullptr;
    HandleScope serverScope(server);
    if (retainedProcess != nullptr)
    {
        *retainedProcess = nullptr;
    }
    do
    {
        ULONG connectedPid = 0;
        if (expectedPid == 0 || expectedCreationTime == 0 || !GetNamedPipeServerProcessId(pipe, &connectedPid) || connectedPid != expectedPid)
        {
            break;
        }
        server = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, expectedPid);
        ProcessIdentity expected;
        ProcessIdentity current;
        if (server == nullptr || WaitForSingleObject(server, 0) != WAIT_TIMEOUT ||
            !ReadProcessIdentity(server, expected) || expected.CreationTime != expectedCreationTime ||
            !ReadProcessIdentity(GetCurrentProcess(), current) || !SameLogon(expected, current))
        {
            break;
        }
        valid = true;
        if (retainedProcess != nullptr)
        {
            *retainedProcess = server;
            server = nullptr;
        }
    }
    while (false);
    SetLastError(valid ? ERROR_SUCCESS : ERROR_ACCESS_DENIED);
    return valid;
}

bool ConfigureAgentPipeWriter(HANDLE pipe)
{
    DWORD mode = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
    return SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr) != FALSE;
}

bool TryWriteAgentMessage(HANDLE pipe, std::string_view message)
{
    bool sent = false;
    do
    {
        if (message.empty() || message.size() > MaxAgentMessageBytes)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            break;
        }
        DWORD written = 0;
        sent = WriteFile(pipe, message.data(), static_cast<DWORD>(message.size()), &written, nullptr) != FALSE &&
            written == message.size();
    }
    while (false);
    return sent;
}
}
