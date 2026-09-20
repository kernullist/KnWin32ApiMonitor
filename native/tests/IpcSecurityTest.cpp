#include <knmon/common/IpcSecurity.h>
#include <knmon/common/AgentChannel.h>
#include <AclAPI.h>
#include <array>
#include <cstdio>
#include <stdexcept>

namespace
{
void Require(bool value, const char* message)
{
    if (!value)
    {
        std::fprintf(stderr, "%s; error=%lu\n", message, GetLastError());
        throw std::runtime_error(message);
    }
}

void VerifyAcl(HANDLE object, SE_OBJECT_TYPE type, DWORD expectedMask)
{
    PACL acl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    Require(GetSecurityInfo(object, type, DACL_SECURITY_INFORMATION, nullptr, nullptr, &acl, nullptr, &descriptor) == ERROR_SUCCESS,
        "Read explicit DACL");
    knmon::ProcessIdentity identity;
    Require(knmon::ReadProcessIdentity(GetCurrentProcess(), identity), "Read logon identity");
    bool valid = acl != nullptr && acl->AceCount == 2;
    if (valid)
    {
        void* ace = nullptr;
        valid = GetAce(acl, 0, &ace) != FALSE;
        if (valid)
        {
            const auto* allowed = static_cast<ACCESS_ALLOWED_ACE*>(ace);
            valid = allowed->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && allowed->Mask == expectedMask &&
                EqualSid(const_cast<DWORD*>(&allowed->SidStart), identity.LogonSid.data());
            void* ownerAce = nullptr;
            valid = valid && GetAce(acl, 1, &ownerAce);
            if (valid)
            {
                const auto* ownerRights = static_cast<ACCESS_ALLOWED_ACE*>(ownerAce);
                valid = ownerRights->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ownerRights->Mask == READ_CONTROL &&
                    IsWellKnownSid(const_cast<DWORD*>(&ownerRights->SidStart), WinCreatorOwnerRightsSid);
            }
        }
    }
    LocalFree(descriptor);
    Require(valid, "DACL grants only the current logon SID and exact rights");
    PACL labelAcl = nullptr;
    descriptor = nullptr;
    Require(GetSecurityInfo(object, type, LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, &labelAcl, &descriptor) == ERROR_SUCCESS,
        "Read integrity label");
    valid = labelAcl != nullptr && labelAcl->AceCount == 1;
    if (valid)
    {
        void* ace = nullptr;
        valid = GetAce(labelAcl, 0, &ace) != FALSE;
        if (valid)
        {
            const auto* label = static_cast<SYSTEM_MANDATORY_LABEL_ACE*>(ace);
            valid = label->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE && label->Mask == SYSTEM_MANDATORY_LABEL_NO_WRITE_UP &&
                IsWellKnownSid(const_cast<DWORD*>(&label->SidStart), WinMediumLabelSid);
        }
    }
    LocalFree(descriptor);
    Require(valid, "Medium integrity label rejects lower-integrity writers");
}

void VerifyLowIntegrityDenied(const std::wstring& mappingName)
{
    HANDLE original = nullptr;
    HANDLE restricted = nullptr;
    Require(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &original) != FALSE, "Open own process token");
    const BOOL duplicated = DuplicateTokenEx(original, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_DEFAULT,
        nullptr, SecurityImpersonation, TokenImpersonation, &restricted);
    CloseHandle(original);
    Require(duplicated != FALSE, "Duplicate own impersonation token");
    unsigned char sid[SECURITY_MAX_SID_SIZE] = {};
    DWORD size = sizeof(sid);
    Require(CreateWellKnownSid(WinLowLabelSid, nullptr, sid, &size) != FALSE, "Build low integrity SID");
    TOKEN_MANDATORY_LABEL label = {};
    label.Label.Sid = sid;
    label.Label.Attributes = SE_GROUP_INTEGRITY;
    const BOOL lowered = SetTokenInformation(restricted, TokenIntegrityLevel, &label, sizeof(label) + size);
    const BOOL impersonated = lowered && SetThreadToken(nullptr, restricted);
    if (!impersonated)
    {
        CloseHandle(restricted);
        Require(false, "Lower the test thread integrity level");
    }
    HANDLE mapping = OpenFileMappingW(FILE_MAP_WRITE, FALSE, mappingName.c_str());
    const DWORD error = GetLastError();
    const BOOL reverted = RevertToSelf();
    CloseHandle(restricted);
    if (mapping != nullptr)
    {
        CloseHandle(mapping);
    }
    Require(reverted && mapping == nullptr && error == ERROR_ACCESS_DENIED, "Low integrity peer cannot write to the shared transport");
}

void RunPipeCase(bool correctClient, bool correctServer)
{
    std::wstring name;
    HANDLE pipe = knmon::CreateLocalAgentPipe(name, 5000);
    Require(pipe != INVALID_HANDLE_VALUE && knmon::ChannelNonce(name).size() == 64, "Create protected random pipe");
    VerifyAcl(pipe, SE_KERNEL_OBJECT, knmon::AgentPipeAclAccess);
    Require((knmon::AgentPipeAclAccess & FILE_CREATE_PIPE_INSTANCE) == 0, "DACL excludes pipe instance creation");
    HANDLE collision = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, nullptr);
    Require(collision == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED, "Pipe name squatting fails closed");

    std::array<wchar_t, 32768> executable = {};
    Require(GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size())) != 0, "Locate test image");
    std::wstring command = L"\"" + std::wstring(executable.data()) + L"\" --client " + name + L" " +
        std::to_wstring(GetCurrentProcessId()) + L" " + std::to_wstring(knmon::ProcessCreationTime(GetCurrentProcess()) + (correctServer ? 0 : 1)) +
        (correctServer ? L" 1" : L" 0");
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {};
    Require(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) != FALSE,
        "Start actual independent pipe client");
    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Require(overlapped.hEvent != nullptr, "Create connection completion event");
    const BOOL immediate = ConnectNamedPipe(pipe, &overlapped);
    const DWORD error = GetLastError();
    if (!immediate && error != ERROR_PIPE_CONNECTED)
    {
        Require(error == ERROR_IO_PENDING && WaitForSingleObject(overlapped.hEvent, 5000) == WAIT_OBJECT_0, "Connect actual client");
        DWORD transferred = 0;
        Require(GetOverlappedResult(pipe, &overlapped, &transferred, FALSE) != FALSE, "Complete client connection");
    }
    Require(knmon::AuthenticatePipeClient(pipe, correctClient ? process.hProcess : GetCurrentProcess()) == correctClient,
        "Authenticate exact client process object");
    Require(WaitForSingleObject(process.hProcess, 5000) == WAIT_OBJECT_0, "Client exits");
    DWORD exitCode = 0;
    Require(GetExitCodeProcess(process.hProcess, &exitCode) && exitCode == 0, "Client server-authentication expectation");
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    CloseHandle(overlapped.hEvent);
    CloseHandle(pipe);
}
}

int wmain(int argc, wchar_t** argv)
{
    try
    {
        if (argc == 6 && wcscmp(argv[1], L"--client") == 0)
        {
            HANDLE pipe = CreateFileW(argv[2], knmon::AgentPipeClientAccess, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            Require(pipe != INVALID_HANDLE_VALUE, "Client opens with minimal rights");
            HANDLE retained = nullptr;
            const DWORD expectedPid = wcstoul(argv[3], nullptr, 10);
            const std::uint64_t expectedCreation = _wcstoui64(argv[4], nullptr, 10);
            const bool valid = knmon::AuthenticatePipeServer(pipe, expectedPid, expectedCreation, &retained);
            Require(valid == (wcscmp(argv[5], L"1") == 0), "Server creation time authentication");
            Require(valid == (retained != nullptr), "Only an authenticated server handle is retained");
            if (valid)
            {
                Require(GetProcessId(retained) == expectedPid && knmon::ProcessCreationTime(retained) == expectedCreation &&
                    WaitForSingleObject(retained, 0) == WAIT_TIMEOUT, "Retained server identity and synchronization rights");
                CloseHandle(retained);
                Require(knmon::ConfigureAgentPipeWriter(pipe), "Configure a nonblocking message writer with minimum rights");
                const std::string message(4096, 'a');
                const auto started = GetTickCount64();
                unsigned sent = 0;
                unsigned rejected = 0;
                for (unsigned index = 0; index < 256; ++index)
                {
                    if (knmon::TryWriteAgentMessage(pipe, message))
                    {
                        ++sent;
                    }
                    else
                    {
                        ++rejected;
                    }
                }
                Require(sent != 0 && rejected != 0 && GetTickCount64() - started < 2000,
                    "A connected controller that never reads cannot block the writer");
                Require(!knmon::TryWriteAgentMessage(pipe, {}) &&
                    !knmon::TryWriteAgentMessage(pipe, std::string(knmon::MaxAgentMessageBytes + 1, 'a')),
                    "Empty and oversized control messages are rejected");
            }
            Sleep(300);
            CloseHandle(pipe);
        }
        else
        {
            HANDLE byteReader = nullptr;
            HANDLE byteWriter = nullptr;
            Require(CreatePipe(&byteReader, &byteWriter, nullptr, 4096) != FALSE, "Create byte-pipe negative control");
            const bool acceptedBytePipe = knmon::ConfigureAgentPipeWriter(byteWriter);
            CloseHandle(byteWriter);
            CloseHandle(byteReader);
            Require(!acceptedBytePipe, "Byte pipes cannot provide atomic nonblocking control messages");
            const std::string nonce(64, 'a');
            const std::string hello = "{\"schemaVersion\":\"0.1.0\",\"messageType\":\"agent_hello\",\"operationId\":\"test\",\"pid\":42,\"tid\":1,\"timestampUtc\":\"2026-09-20T00:00:00Z\",\"sequence\":1,\"architecture\":\"x64\",\"agentVersion\":\"0.3.0\",\"channelNonce\":\"" + nonce + "\"}";
            const auto expectFailure = [&](knmon::AgentChannel& channel, const std::string& text)
            {
                bool rejected = false;
                try
                {
                    channel.Accept(knmon::JsonDocument(text));
                }
                catch (const knmon::JsonInputError&)
                {
                    rejected = true;
                }
                Require(rejected, "Host rejects channel forgery or invalid HELLO ordering");
            };
            knmon::AgentChannel valid("test", 42, nonce);
            valid.Accept(knmon::JsonDocument(hello));
            expectFailure(valid, hello);
            knmon::AgentChannel foreignPid("test", 43, nonce);
            expectFailure(foreignPid, hello);
            knmon::AgentChannel foreignNonce("test", 42, std::string(64, 'b'));
            expectFailure(foreignNonce, hello);
            knmon::AgentChannel foreignOperation("other", 42, nonce);
            expectFailure(foreignOperation, hello);
            knmon::AgentChannel wrongOrder("test", 42, nonce);
            auto beforeHello = hello;
            beforeHello.replace(beforeHello.find("agent_hello"), 11, "module_inventory");
            expectFailure(wrongOrder, beforeHello);
            expectFailure(wrongOrder, hello);
            knmon::ProcessIdentity identity;
            Require(knmon::ReadProcessIdentity(GetCurrentProcess(), identity), "Read current identity");
            auto changed = identity;
            Require(knmon::SameLogon(identity, changed), "Same logon accepted");
            ++changed.AuthenticationId.LowPart;
            Require(!knmon::SameLogon(identity, changed), "Different authentication session rejected");
            changed = identity;
            ++changed.SessionId;
            Require(!knmon::SameLogon(identity, changed), "Different terminal session rejected");
            changed = identity;
            changed.LogonSid.back() ^= 1;
            Require(!knmon::SameLogon(identity, changed), "Different logon SID rejected");
            std::wstring first, second;
            Require(knmon::RandomIpcName(L"Local\\KNMonTransport_", first) && knmon::RandomIpcName(L"Local\\KNMonTransport_", second) && first != second,
                "Independent cryptographic channel names");
            knmon::LocalIpcSecurity security;
            Require(security.Initialize(knmon::TransportAclAccess), "Build mapping ACL");
            HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, security.Attributes(), PAGE_READWRITE, 0, 4096, first.c_str());
            Require(mapping != nullptr, "Create protected mapping");
            VerifyAcl(mapping, SE_KERNEL_OBJECT, knmon::TransportAclAccess);
            VerifyLowIntegrityDenied(first);
            knmon::LocalIpcSecurity eventSecurity;
            Require(eventSecurity.Initialize(EVENT_MODIFY_STATE | SYNCHRONIZE | READ_CONTROL), "Build event ACL");
            std::wstring eventName;
            Require(knmon::RandomIpcName(L"Local\\KNMonEventTest_", eventName), "Generate event name");
            HANDLE event = CreateEventW(eventSecurity.Attributes(), TRUE, FALSE, eventName.c_str());
            Require(event != nullptr, "Create protected event");
            HANDLE aclWriter = OpenEventW(WRITE_DAC, FALSE, eventName.c_str());
            const DWORD aclError = GetLastError();
            if (aclWriter != nullptr)
            {
                CloseHandle(aclWriter);
            }
            CloseHandle(event);
            Require(aclWriter == nullptr && aclError == ERROR_ACCESS_DENIED, "Implicit owner WRITE_DAC must not bypass the logon policy");
            HANDLE opened = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, first.c_str());
            Require(opened != nullptr, "Mapping minimum access works");
            void* oversized = MapViewOfFile(opened, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 8192);
            Require(oversized == nullptr, "Undersized mapping cannot satisfy trusted extent");
            CloseHandle(opened);
            CloseHandle(mapping);
            RunPipeCase(true, true);
            RunPipeCase(false, true);
            RunPipeCase(true, false);
            Require(knmon::ChannelNonce(L"\\\\remote\\pipe\\knmon_agent_bad").empty(), "Reject nonlocal channel config");
            std::puts("IPC identity, DACL, PID mismatch, server creation time, and mapping extent checks passed.");
        }
    }
    catch (const std::exception&)
    {
        return 1;
    }
    return 0;
}
