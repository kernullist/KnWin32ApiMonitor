#include <knmon/core/Controller.h>

#include <Windows.h>

#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace
{
std::string WideToUtf8(const wchar_t* value)
{
    std::string result;

    do
    {
        if (value == nullptr)
        {
            break;
        }

        const int required = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
        if (required <= 1)
        {
            break;
        }

        result.resize(static_cast<std::size_t>(required - 1));
        const int converted = WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), required, nullptr, nullptr);
        if (converted <= 0)
        {
            result.clear();
            break;
        }
    }
    while (false);

    return result;
}

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
        case '\b':
            stream << "\\b";
            break;
        case '\f':
            stream << "\\f";
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
                stream << "\\u00";
                const char* hex = "0123456789abcdef";
                stream << hex[(byte >> 4) & 0x0f] << hex[byte & 0x0f];
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

std::filesystem::path HelperDirectory()
{
    std::filesystem::path result;
    wchar_t modulePath[MAX_PATH * 8] = {};

    do
    {
        const DWORD length = GetModuleFileNameW(nullptr, modulePath, static_cast<DWORD>(std::size(modulePath)));
        if (length == 0 || length >= std::size(modulePath))
        {
            result = std::filesystem::current_path();
            break;
        }

        result = std::filesystem::path(modulePath).parent_path();
    }
    while (false);

    return result;
}

std::string NewOperationId()
{
    std::ostringstream stream;
    stream << "op-" << GetCurrentProcessId() << "-" << GetTickCount64();
    return stream.str();
}

std::string ToJson(const knmon::KnMonTargetProcess& target)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"pid\":" << target.ProcessId << ",";
    stream << "\"parentPid\":";
    if (target.HasParentProcessId)
    {
        stream << target.ParentProcessId;
    }
    else
    {
        stream << "null";
    }
    stream << ",";
    stream << "\"imageName\":" << Q(target.ImageName) << ",";
    stream << "\"imagePath\":";
    if (target.ImagePath.empty())
    {
        stream << "null";
    }
    else
    {
        stream << Q(target.ImagePath);
    }
    stream << ",";
    stream << "\"architecture\":" << Q(target.Architecture) << ",";
    stream << "\"status\":" << Q(target.Status);
    stream << "}";
    return stream.str();
}

std::string ToJson(const knmon::KnMonAuditEvent& event)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":" << Q(event.SchemaVersion) << ",";
    stream << "\"operationId\":" << Q(event.OperationId) << ",";
    stream << "\"eventType\":" << Q(event.EventType) << ",";
    stream << "\"timestampUtc\":" << Q(event.TimestampUtc) << ",";
    stream << "\"subsystem\":" << Q(event.Subsystem) << ",";
    stream << "\"operation\":" << Q(event.Operation) << ",";
    stream << "\"win32ErrorCode\":" << event.Win32ErrorCode << ",";
    stream << "\"ntStatus\":" << Q(event.NtStatus) << ",";
    stream << "\"message\":" << Q(event.Message);
    stream << "}";
    return stream.str();
}

std::string ToJson(const knmon::KnMonAgentHandshake& handshake)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"received\":" << (handshake.Received ? "true" : "false") << ",";
    stream << "\"schemaVersion\":" << Q(handshake.SchemaVersion) << ",";
    stream << "\"operationId\":" << Q(handshake.OperationId) << ",";
    stream << "\"processId\":" << handshake.ProcessId << ",";
    stream << "\"threadId\":" << handshake.ThreadId << ",";
    stream << "\"architecture\":" << Q(handshake.Architecture) << ",";
    stream << "\"agentVersion\":" << Q(handshake.AgentVersion) << ",";
    stream << "\"message\":" << Q(handshake.Message) << ",";
    stream << "\"rawPayload\":" << Q(handshake.RawPayload);
    stream << "}";
    return stream.str();
}

std::string ToJson(const knmon::KnMonLaunchResult& result)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":" << Q(result.SchemaVersion) << ",";
    stream << "\"operationId\":" << Q(result.OperationId) << ",";
    stream << "\"success\":" << (result.Success ? "true" : "false") << ",";
    stream << "\"backendMode\":" << Q(result.BackendMode) << ",";
    stream << "\"injectionMethod\":" << Q(result.InjectionMethod) << ",";
    stream << "\"targetPath\":" << Q(result.TargetPath) << ",";
    stream << "\"agentPath\":" << Q(result.AgentPath) << ",";
    stream << "\"targetProcessId\":" << result.TargetProcessId << ",";
    stream << "\"targetThreadId\":" << result.TargetThreadId << ",";
    stream << "\"architecture\":" << Q(result.Architecture) << ",";
    stream << "\"win32ErrorCode\":" << result.Win32ErrorCode << ",";
    stream << "\"ntStatus\":" << Q(result.NtStatus) << ",";
    stream << "\"subsystem\":" << Q(result.Subsystem) << ",";
    stream << "\"operation\":" << Q(result.Operation) << ",";
    stream << "\"message\":" << Q(result.Message) << ",";
    stream << "\"handshake\":" << ToJson(result.Handshake) << ",";
    stream << "\"auditEvents\":[";
    for (std::size_t index = 0; index < result.AuditEvents.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(result.AuditEvents[index]);
    }
    stream << "]";
    stream << "}";
    return stream.str();
}

std::string ListTargetsJson()
{
    knmon::Controller controller;
    knmon::KnMonError error;
    const auto targets = controller.EnumerateTargets(&error);

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"backendMode\":\"native-enum\",";
    stream << "\"success\":" << (error.Code == 0 ? "true" : "false") << ",";
    stream << "\"win32ErrorCode\":" << error.Code << ",";
    stream << "\"subsystem\":" << Q(error.Subsystem) << ",";
    stream << "\"operation\":" << Q(error.Operation) << ",";
    stream << "\"message\":" << Q(error.Message) << ",";
    stream << "\"targets\":[";
    for (std::size_t index = 0; index < targets.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(targets[index]);
    }
    stream << "]}";
    return stream.str();
}

std::string GetOption(const std::vector<std::string>& args, const std::string& name)
{
    std::string value;

    for (std::size_t index = 0; index + 1 < args.size(); ++index)
    {
        if (args[index] == name)
        {
            value = args[index + 1];
            break;
        }
    }

    return value;
}

std::string LaunchSampleJson(const std::vector<std::string>& args)
{
    const auto helperDir = HelperDirectory();
    const std::string defaultTarget = WideToUtf8((helperDir / L"knmon-sample-fileio.exe").wstring().c_str());
    const std::string defaultAgent = WideToUtf8((helperDir / L"knmon-agent64.dll").wstring().c_str());

    knmon::KnMonLaunchRequest request;
    request.OperationId = NewOperationId();
    request.TargetPath = GetOption(args, "--target");
    request.AgentPath = GetOption(args, "--agent");
    request.WorkingDirectory = GetOption(args, "--cwd");
    request.TimeoutMs = 7000;
    request.Architecture = knmon::KnMonAgentArchitecture::X64;
    request.InjectionMethod = knmon::KnMonInjectionMethod::EarlyBirdApc;

    if (request.TargetPath.empty())
    {
        request.TargetPath = defaultTarget;
    }

    if (request.AgentPath.empty())
    {
        request.AgentPath = defaultAgent;
    }

    knmon::Controller controller;
    return ToJson(controller.LaunchWithEarlyBirdApc(request));
}

void PrintUsage()
{
    std::cout << "{";
    std::cout << "\"schemaVersion\":\"0.1.0\",";
    std::cout << "\"success\":false,";
    std::cout << "\"message\":\"Usage: knmon-native-helper.exe list-targets | launch-sample [--target path] [--agent path]\"";
    std::cout << "}\n";
}
}

int wmain(int argc, wchar_t** argv)
{
    std::vector<std::string> args;
    for (int index = 1; index < argc; ++index)
    {
        args.push_back(WideToUtf8(argv[index]));
    }

    if (args.empty())
    {
        PrintUsage();
        return 1;
    }

    if (args[0] == "list-targets")
    {
        std::cout << ListTargetsJson() << "\n";
        return 0;
    }

    if (args[0] == "launch-sample")
    {
        std::cout << LaunchSampleJson(args) << "\n";
        return 0;
    }

    PrintUsage();
    return 1;
}
