#include <knmon/core/Controller.h>

#include <Windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
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

std::wstring Utf8ToWide(const std::string& value)
{
    std::wstring result;

    do
    {
        if (value.empty())
        {
            break;
        }

        const int required = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
        if (required <= 1)
        {
            break;
        }

        result.resize(static_cast<std::size_t>(required - 1));
        const int converted = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, result.data(), required);
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

std::string NowUtc()
{
    SYSTEMTIME time = {};
    GetSystemTime(&time);

    std::ostringstream stream;
    stream << std::setfill('0')
           << std::setw(4) << time.wYear << "-"
           << std::setw(2) << time.wMonth << "-"
           << std::setw(2) << time.wDay << "T"
           << std::setw(2) << time.wHour << ":"
           << std::setw(2) << time.wMinute << ":"
           << std::setw(2) << time.wSecond << "."
           << std::setw(3) << time.wMilliseconds << "Z";
    return stream.str();
}

std::string PathToUtf8(const std::filesystem::path& path)
{
    return WideToUtf8(path.wstring().c_str());
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

std::string SanitizeFileName(const std::string& value)
{
    std::string result;

    for (const char ch : value)
    {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_')
        {
            result.push_back(ch);
        }
        else
        {
            result.push_back('-');
        }
    }

    if (result.empty())
    {
        result = "session";
    }

    return result;
}

std::filesystem::path PathFromUtf8(const std::string& value)
{
    std::filesystem::path result;

    do
    {
        const std::wstring wide = Utf8ToWide(value);
        if (!wide.empty())
        {
            result = std::filesystem::path(wide);
            break;
        }

        result = std::filesystem::path(value);
    }
    while (false);

    return result;
}

bool WriteTextFile(const std::filesystem::path& path, const std::string& text, std::string* error)
{
    bool written = false;

    do
    {
        std::error_code createError;
        std::filesystem::create_directories(path.parent_path(), createError);
        if (createError)
        {
            if (error != nullptr)
            {
                *error = "create_directories failed for " + PathToUtf8(path.parent_path()) + ": " + createError.message();
            }
            break;
        }

        const std::filesystem::path tempPath = path.wstring() + L".tmp";
        {
            std::ofstream file(tempPath, std::ios::binary | std::ios::trunc);
            if (!file)
            {
                if (error != nullptr)
                {
                    *error = "open failed for " + PathToUtf8(tempPath);
                }
                break;
            }

            file << text;
            if (!file)
            {
                if (error != nullptr)
                {
                    *error = "write failed for " + PathToUtf8(tempPath);
                }
                break;
            }
        }

        std::error_code removeError;
        std::filesystem::remove(path, removeError);

        std::error_code renameError;
        std::filesystem::rename(tempPath, path, renameError);
        if (renameError)
        {
            if (error != nullptr)
            {
                *error = "rename failed for " + PathToUtf8(path) + ": " + renameError.message();
            }
            break;
        }

        written = true;
    }
    while (false);

    return written;
}

bool ReadTextFile(const std::filesystem::path& path, std::string* text, std::string* error)
{
    bool read = false;

    do
    {
        if (text != nullptr)
        {
            text->clear();
        }

        std::ifstream file(path, std::ios::binary);
        if (!file)
        {
            if (error != nullptr)
            {
                *error = "open failed for " + PathToUtf8(path);
            }
            break;
        }

        std::ostringstream stream;
        stream << file.rdbuf();
        if (!file.good() && !file.eof())
        {
            if (error != nullptr)
            {
                *error = "read failed for " + PathToUtf8(path);
            }
            break;
        }

        if (text != nullptr)
        {
            *text = stream.str();
        }
        read = true;
    }
    while (false);

    return read;
}

std::vector<std::string> SplitJsonl(const std::string& value)
{
    std::vector<std::string> lines;
    std::istringstream stream(value);
    std::string line;

    while (std::getline(stream, line))
    {
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }

        if (!line.empty())
        {
            lines.push_back(line);
        }
    }

    return lines;
}

bool PayloadContains(const std::string& payload, const std::string& marker)
{
    return payload.find(marker) != std::string::npos;
}

std::string ExtractJsonString(const std::string& payload, const std::string& key)
{
    std::string result;

    do
    {
        const std::string quotedKey = "\"" + key + "\"";
        std::size_t position = payload.find(quotedKey);
        if (position == std::string::npos)
        {
            break;
        }

        position = payload.find(':', position + quotedKey.size());
        if (position == std::string::npos)
        {
            break;
        }

        position = payload.find('"', position + 1);
        if (position == std::string::npos)
        {
            break;
        }

        ++position;
        std::ostringstream stream;
        bool escaped = false;
        for (; position < payload.size(); ++position)
        {
            const char ch = payload[position];
            if (escaped)
            {
                switch (ch)
                {
                case '"':
                    stream << '"';
                    break;
                case '\\':
                    stream << '\\';
                    break;
                case 'n':
                    stream << '\n';
                    break;
                case 'r':
                    stream << '\r';
                    break;
                case 't':
                    stream << '\t';
                    break;
                default:
                    stream << ch;
                    break;
                }
                escaped = false;
                continue;
            }

            if (ch == '\\')
            {
                escaped = true;
                continue;
            }

            if (ch == '"')
            {
                break;
            }

            stream << ch;
        }

        result = stream.str();
    }
    while (false);

    return result;
}

std::uint64_t ExtractJsonUInt64(const std::string& payload, const std::string& key)
{
    std::uint64_t result = 0;

    do
    {
        const std::string quotedKey = "\"" + key + "\"";
        std::size_t position = payload.find(quotedKey);
        if (position == std::string::npos)
        {
            break;
        }

        position = payload.find(':', position + quotedKey.size());
        if (position == std::string::npos)
        {
            break;
        }

        ++position;
        while (position < payload.size() && payload[position] == ' ')
        {
            ++position;
        }

        std::uint64_t value = 0;
        bool sawDigit = false;
        for (; position < payload.size(); ++position)
        {
            const char ch = payload[position];
            if (ch < '0' || ch > '9')
            {
                break;
            }

            sawDigit = true;
            value = (value * 10) + static_cast<std::uint64_t>(ch - '0');
        }

        if (sawDigit)
        {
            result = value;
        }
    }
    while (false);

    return result;
}

std::string ExtractJsonArray(const std::string& payload, const std::string& key)
{
    std::string result = "[]";

    do
    {
        const std::string quotedKey = "\"" + key + "\"";
        std::size_t position = payload.find(quotedKey);
        if (position == std::string::npos)
        {
            break;
        }

        position = payload.find(':', position + quotedKey.size());
        if (position == std::string::npos)
        {
            break;
        }

        position = payload.find('[', position + 1);
        if (position == std::string::npos)
        {
            break;
        }

        const std::size_t start = position;
        int depth = 0;
        bool inString = false;
        bool escaped = false;
        for (; position < payload.size(); ++position)
        {
            const char ch = payload[position];
            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                    continue;
                }

                if (ch == '\\')
                {
                    escaped = true;
                    continue;
                }

                if (ch == '"')
                {
                    inString = false;
                }
                continue;
            }

            if (ch == '"')
            {
                inString = true;
                continue;
            }

            if (ch == '[')
            {
                ++depth;
            }
            else if (ch == ']')
            {
                --depth;
                if (depth == 0)
                {
                    result = payload.substr(start, position - start + 1);
                    break;
                }
            }
        }
    }
    while (false);

    return result;
}

std::string BuildTraceEventJson(const knmon::KnMonAgentMessage& message, std::uint64_t eventId)
{
    const std::string& payload = message.RawPayload;
    const std::uint64_t lastErrorCode = ExtractJsonUInt64(payload, "lastErrorCode");
    const std::uint64_t sequence = ExtractJsonUInt64(payload, "sequence");
    const std::string lastErrorMessage = ExtractJsonString(payload, "lastErrorMessage");

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"eventId\":" << eventId << ",";
    stream << "\"relativeTimeMs\":" << sequence * 10 << ",";
    stream << "\"pid\":" << ExtractJsonUInt64(payload, "pid") << ",";
    stream << "\"tid\":" << ExtractJsonUInt64(payload, "tid") << ",";
    stream << "\"process\":" << Q(ExtractJsonString(payload, "process")) << ",";
    stream << "\"module\":" << Q(ExtractJsonString(payload, "module")) << ",";
    stream << "\"api\":" << Q(ExtractJsonString(payload, "api")) << ",";
    stream << "\"arguments\":" << ExtractJsonArray(payload, "arguments") << ",";
    stream << "\"returnValue\":" << Q(ExtractJsonString(payload, "returnValue")) << ",";
    stream << "\"error\":";
    if (lastErrorCode == 0)
    {
        stream << "null";
    }
    else
    {
        std::ostringstream code;
        code << "0x" << std::hex << std::setfill('0') << std::setw(8) << lastErrorCode;
        stream << "{";
        stream << "\"kind\":\"win32\",";
        stream << "\"code\":" << Q(code.str()) << ",";
        stream << "\"message\":" << Q(lastErrorMessage);
        stream << "}";
    }
    stream << ",";
    stream << "\"durationUs\":" << ExtractJsonUInt64(payload, "durationUs") << ",";
    stream << "\"tags\":" << ExtractJsonArray(payload, "tags") << ",";
    stream << "\"stack\":" << ExtractJsonArray(payload, "stack") << ",";
    stream << "\"bufferPreview\":" << Q(ExtractJsonString(payload, "bufferPreview"));
    stream << "}";
    return stream.str();
}

std::string JoinJsonl(const std::vector<std::string>& lines)
{
    std::ostringstream stream;

    for (const std::string& line : lines)
    {
        stream << line << "\n";
    }

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

std::string ToJson(const knmon::KnMonAgentMessage& message)
{
    if (!message.RawPayload.empty())
    {
        return message.RawPayload;
    }

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":" << Q(message.SchemaVersion) << ",";
    stream << "\"messageType\":" << Q(message.MessageType) << ",";
    stream << "\"operationId\":" << Q(message.OperationId) << ",";
    stream << "\"pid\":" << message.ProcessId << ",";
    stream << "\"tid\":" << message.ThreadId << ",";
    stream << "\"timestampUtc\":" << Q(message.TimestampUtc) << ",";
    stream << "\"sequence\":" << message.Sequence;
    stream << "}";
    return stream.str();
}

std::string ToJson(const knmon::KnMonCaptureResult& result)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":" << Q(result.SchemaVersion) << ",";
    stream << "\"operationId\":" << Q(result.OperationId) << ",";
    stream << "\"success\":" << (result.Success ? "true" : "false") << ",";
    stream << "\"backendMode\":" << Q(result.BackendMode) << ",";
    stream << "\"captureMode\":" << Q(result.CaptureMode) << ",";
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
    stream << "\"droppedEvents\":" << result.DroppedEvents << ",";
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
    stream << "],";
    stream << "\"agentMessages\":[";
    for (std::size_t index = 0; index < result.AgentMessages.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(result.AgentMessages[index]);
    }
    stream << "],";
    stream << "\"capturedEvents\":[";
    for (std::size_t index = 0; index < result.CapturedEvents.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(result.CapturedEvents[index]);
    }
    stream << "]";
    stream << "}";
    return stream.str();
}

struct SessionInfo
{
    bool Success = false;
    std::string SessionId;
    std::string SessionPath;
    std::string CreatedUtc;
    std::uint64_t TraceEventCount = 0;
    std::uint64_t AgentEventCount = 0;
    std::uint64_t AuditEventCount = 0;
    std::uint64_t DroppedEvents = 0;
    std::uint32_t Win32ErrorCode = 0;
    std::string Message;
    std::vector<std::string> ValidationErrors;
};

std::string ToJson(const SessionInfo& session)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (session.Success ? "true" : "false") << ",";
    stream << "\"sessionId\":" << Q(session.SessionId) << ",";
    stream << "\"sessionPath\":" << Q(session.SessionPath) << ",";
    stream << "\"createdUtc\":" << Q(session.CreatedUtc) << ",";
    stream << "\"traceEventCount\":" << session.TraceEventCount << ",";
    stream << "\"agentEventCount\":" << session.AgentEventCount << ",";
    stream << "\"auditEventCount\":" << session.AuditEventCount << ",";
    stream << "\"droppedEvents\":" << session.DroppedEvents << ",";
    stream << "\"win32ErrorCode\":" << session.Win32ErrorCode << ",";
    stream << "\"message\":" << Q(session.Message) << ",";
    stream << "\"validationErrors\":[";
    for (std::size_t index = 0; index < session.ValidationErrors.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << Q(session.ValidationErrors[index]);
    }
    stream << "]";
    stream << "}";
    return stream.str();
}

std::string CaptureResultWithSessionJson(const knmon::KnMonCaptureResult& result, const SessionInfo& session)
{
    std::string json = ToJson(result);

    if (!json.empty() && json.back() == '}')
    {
        json.pop_back();
        json += ",\"session\":";
        json += ToJson(session);
        json += "}";
    }

    return json;
}

std::string BuildManifestJson(
    const knmon::KnMonCaptureResult& result,
    const SessionInfo& session,
    const std::string& auditFile,
    const std::string& agentEventsFile,
    const std::string& traceEventsFile)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"sessionId\":" << Q(session.SessionId) << ",";
    stream << "\"createdUtc\":" << Q(session.CreatedUtc) << ",";
    stream << "\"source\":\"knmon-native-helper capture-sample\",";
    stream << "\"backendMode\":" << Q(result.BackendMode) << ",";
    stream << "\"captureMode\":" << Q(result.CaptureMode) << ",";
    stream << "\"operationId\":" << Q(result.OperationId) << ",";
    stream << "\"target\":{";
    stream << "\"path\":" << Q(result.TargetPath) << ",";
    stream << "\"pid\":" << result.TargetProcessId << ",";
    stream << "\"tid\":" << result.TargetThreadId << ",";
    stream << "\"architecture\":" << Q(result.Architecture);
    stream << "},";
    stream << "\"agent\":{";
    stream << "\"path\":" << Q(result.AgentPath) << ",";
    stream << "\"architecture\":" << Q(result.Architecture) << ",";
    stream << "\"version\":" << Q(result.Handshake.AgentVersion);
    stream << "},";
    stream << "\"eventCounts\":{";
    stream << "\"audit\":" << session.AuditEventCount << ",";
    stream << "\"agentEvents\":" << session.AgentEventCount << ",";
    stream << "\"traceEvents\":" << session.TraceEventCount << ",";
    stream << "\"capturedEvents\":" << result.CapturedEvents.size();
    stream << "},";
    stream << "\"droppedEvents\":" << result.DroppedEvents << ",";
    stream << "\"files\":{";
    stream << "\"audit\":" << Q(auditFile) << ",";
    stream << "\"agentEvents\":" << Q(agentEventsFile) << ",";
    stream << "\"traceEvents\":" << Q(traceEventsFile);
    stream << "}";
    stream << "}";
    return stream.str();
}

SessionInfo WriteSession(const knmon::KnMonCaptureResult& result, const std::filesystem::path& sessionDirectory)
{
    SessionInfo session;
    session.SessionId = SanitizeFileName(result.OperationId);
    session.SessionPath = PathToUtf8(sessionDirectory);
    session.CreatedUtc = NowUtc();
    session.DroppedEvents = result.DroppedEvents;

    const std::string auditFile = "audit.jsonl";
    const std::string agentEventsFile = "agent-events.jsonl";
    const std::string traceEventsFile = "trace-events.jsonl";

    do
    {
        if (!result.Success)
        {
            session.Win32ErrorCode = result.Win32ErrorCode;
            session.Message = "capture failed; session was not written: " + result.Message;
            session.ValidationErrors.push_back(session.Message);
            break;
        }

        std::vector<std::string> auditLines;
        for (const auto& event : result.AuditEvents)
        {
            auditLines.push_back(ToJson(event));
        }

        std::vector<std::string> agentLines;
        for (const auto& message : result.AgentMessages)
        {
            agentLines.push_back(ToJson(message));
        }

        std::vector<std::string> traceLines;
        std::uint64_t eventId = 1;
        for (const auto& message : result.CapturedEvents)
        {
            traceLines.push_back(BuildTraceEventJson(message, eventId));
            ++eventId;
        }

        session.AuditEventCount = auditLines.size();
        session.AgentEventCount = agentLines.size();
        session.TraceEventCount = traceLines.size();

        const std::string manifest = BuildManifestJson(result, session, auditFile, agentEventsFile, traceEventsFile);
        std::string writeError;
        if (!WriteTextFile(sessionDirectory / L"manifest.json", manifest + "\n", &writeError))
        {
            session.Win32ErrorCode = ERROR_WRITE_FAULT;
            session.Message = writeError;
            session.ValidationErrors.push_back(writeError);
            break;
        }

        if (!WriteTextFile(sessionDirectory / L"audit.jsonl", JoinJsonl(auditLines), &writeError))
        {
            session.Win32ErrorCode = ERROR_WRITE_FAULT;
            session.Message = writeError;
            session.ValidationErrors.push_back(writeError);
            break;
        }

        if (!WriteTextFile(sessionDirectory / L"agent-events.jsonl", JoinJsonl(agentLines), &writeError))
        {
            session.Win32ErrorCode = ERROR_WRITE_FAULT;
            session.Message = writeError;
            session.ValidationErrors.push_back(writeError);
            break;
        }

        if (!WriteTextFile(sessionDirectory / L"trace-events.jsonl", JoinJsonl(traceLines), &writeError))
        {
            session.Win32ErrorCode = ERROR_WRITE_FAULT;
            session.Message = writeError;
            session.ValidationErrors.push_back(writeError);
            break;
        }

        session.Success = true;
        session.Win32ErrorCode = 0;
        session.Message = "Session written.";
    }
    while (false);

    return session;
}

SessionInfo ValidateSessionDirectory(const std::filesystem::path& sessionDirectory)
{
    SessionInfo session;
    session.SessionPath = PathToUtf8(sessionDirectory);

    do
    {
        const std::filesystem::path manifestPath = sessionDirectory / L"manifest.json";
        const std::filesystem::path auditPath = sessionDirectory / L"audit.jsonl";
        const std::filesystem::path agentPath = sessionDirectory / L"agent-events.jsonl";
        const std::filesystem::path tracePath = sessionDirectory / L"trace-events.jsonl";

        std::string manifest;
        std::string readError;
        if (!ReadTextFile(manifestPath, &manifest, &readError))
        {
            session.ValidationErrors.push_back(readError);
            break;
        }

        session.SessionId = ExtractJsonString(manifest, "sessionId");
        session.CreatedUtc = ExtractJsonString(manifest, "createdUtc");
        session.DroppedEvents = ExtractJsonUInt64(manifest, "droppedEvents");

        if (!PayloadContains(manifest, "\"schemaVersion\":\"0.1.0\""))
        {
            session.ValidationErrors.push_back("manifest schemaVersion is missing or unsupported.");
        }

        if (session.SessionId.empty())
        {
            session.ValidationErrors.push_back("manifest sessionId is missing.");
        }

        if (!PayloadContains(manifest, "\"files\""))
        {
            session.ValidationErrors.push_back("manifest files block is missing.");
        }

        std::string auditText;
        if (!ReadTextFile(auditPath, &auditText, &readError))
        {
            session.ValidationErrors.push_back(readError);
        }
        else
        {
            session.AuditEventCount = SplitJsonl(auditText).size();
        }

        std::string agentText;
        if (!ReadTextFile(agentPath, &agentText, &readError))
        {
            session.ValidationErrors.push_back(readError);
        }
        else
        {
            const auto lines = SplitJsonl(agentText);
            session.AgentEventCount = lines.size();
            bool hasHello = false;
            bool hasDropped = false;
            bool hasShutdown = false;
            for (const auto& line : lines)
            {
                if (!PayloadContains(line, "\"schemaVersion\":\"0.1.0\""))
                {
                    session.ValidationErrors.push_back("agent-events.jsonl contains an event without schemaVersion 0.1.0.");
                    break;
                }

                hasHello = hasHello || PayloadContains(line, "\"messageType\":\"agent_hello\"");
                hasDropped = hasDropped || PayloadContains(line, "\"messageType\":\"dropped_events\"");
                if (PayloadContains(line, "\"messageType\":\"agent_shutdown\""))
                {
                    hasShutdown = true;
                    if (ExtractJsonString(line, "reason").empty())
                    {
                        session.ValidationErrors.push_back("agent_shutdown reason is missing.");
                    }

                    if (!PayloadContains(line, "\"installedHooks\"") || !PayloadContains(line, "\"restoredHooks\"") || !PayloadContains(line, "\"failedHooks\""))
                    {
                        session.ValidationErrors.push_back("agent_shutdown hook lifecycle counts are missing.");
                    }

                    const std::uint64_t installedHooks = ExtractJsonUInt64(line, "installedHooks");
                    const std::uint64_t restoredHooks = ExtractJsonUInt64(line, "restoredHooks");
                    const std::uint64_t failedHooks = ExtractJsonUInt64(line, "failedHooks");
                    if (restoredHooks < installedHooks || failedHooks != 0)
                    {
                        session.ValidationErrors.push_back("agent_shutdown reports unrestored or failed hooks.");
                    }
                }
            }

            if (!hasHello)
            {
                session.ValidationErrors.push_back("agent-events.jsonl does not contain agent_hello.");
            }

            if (!hasDropped)
            {
                session.ValidationErrors.push_back("agent-events.jsonl does not contain dropped_events.");
            }

            if (!hasShutdown)
            {
                session.ValidationErrors.push_back("agent-events.jsonl does not contain agent_shutdown.");
            }
        }

        std::string traceText;
        if (!ReadTextFile(tracePath, &traceText, &readError))
        {
            session.ValidationErrors.push_back(readError);
        }
        else
        {
            const auto lines = SplitJsonl(traceText);
            session.TraceEventCount = lines.size();
            if (lines.empty())
            {
                session.ValidationErrors.push_back("trace-events.jsonl is empty.");
            }

            for (const auto& line : lines)
            {
                if (!PayloadContains(line, "\"schemaVersion\":\"0.1.0\"") || !PayloadContains(line, "\"api\""))
                {
                    session.ValidationErrors.push_back("trace-events.jsonl contains a malformed trace event.");
                    break;
                }
            }
        }
    }
    while (false);

    session.Success = session.ValidationErrors.empty();
    session.Win32ErrorCode = session.Success ? 0 : ERROR_BAD_FORMAT;
    session.Message = session.Success ? "Session validation passed." : "Session validation failed.";
    return session;
}

std::string ReplaySessionJson(const std::filesystem::path& sessionDirectory)
{
    const SessionInfo validation = ValidateSessionDirectory(sessionDirectory);
    std::string traceText;
    std::string readError;
    std::vector<std::string> traceLines;

    if (validation.Success)
    {
        if (ReadTextFile(sessionDirectory / L"trace-events.jsonl", &traceText, &readError))
        {
            traceLines = SplitJsonl(traceText);
        }
    }

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (validation.Success ? "true" : "false") << ",";
    stream << "\"backendMode\":\"native-capture\",";
    stream << "\"captureMode\":\"session-replay\",";
    stream << "\"session\":" << ToJson(validation) << ",";
    stream << "\"message\":" << Q(validation.Success ? "Session replay loaded trace events without launching a target." : validation.Message) << ",";
    stream << "\"traceEvents\":[";
    for (std::size_t index = 0; index < traceLines.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << traceLines[index];
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

std::string CaptureSampleJson(const std::vector<std::string>& args)
{
    const auto helperDir = HelperDirectory();
    const std::string defaultTarget = WideToUtf8((helperDir / L"knmon-sample-fileio.exe").wstring().c_str());
    const std::string defaultAgent = WideToUtf8((helperDir / L"knmon-agent64.dll").wstring().c_str());

    knmon::KnMonLaunchRequest request;
    request.OperationId = NewOperationId();
    request.TargetPath = GetOption(args, "--target");
    request.AgentPath = GetOption(args, "--agent");
    request.WorkingDirectory = GetOption(args, "--cwd");
    request.TimeoutMs = 9000;
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
    knmon::KnMonCaptureResult result = controller.CaptureSampleFileIo(request);

    const std::string sessionPath = GetOption(args, "--write-session");
    if (!sessionPath.empty())
    {
        SessionInfo session = WriteSession(result, PathFromUtf8(sessionPath));
        if (!session.Success)
        {
            result.Success = false;
            result.Win32ErrorCode = session.Win32ErrorCode;
            result.Subsystem = "knmon-native-helper";
            result.Operation = "write_session";
            result.Message = session.Message;
        }

        return CaptureResultWithSessionJson(result, session);
    }

    return ToJson(result);
}

std::string ReplaySessionCommandJson(const std::vector<std::string>& args)
{
    const std::string sessionPath = GetOption(args, "--session");

    if (sessionPath.empty())
    {
        SessionInfo session;
        session.Success = false;
        session.Win32ErrorCode = ERROR_INVALID_PARAMETER;
        session.Message = "Missing --session path.";
        session.ValidationErrors.push_back(session.Message);

        std::ostringstream stream;
        stream << "{";
        stream << "\"schemaVersion\":\"0.1.0\",";
        stream << "\"success\":false,";
        stream << "\"backendMode\":\"native-capture\",";
        stream << "\"captureMode\":\"session-replay\",";
        stream << "\"session\":" << ToJson(session) << ",";
        stream << "\"message\":" << Q(session.Message) << ",";
        stream << "\"traceEvents\":[]";
        stream << "}";
        return stream.str();
    }

    return ReplaySessionJson(PathFromUtf8(sessionPath));
}

std::string ValidateSessionCommandJson(const std::vector<std::string>& args)
{
    const std::string sessionPath = GetOption(args, "--session");

    if (sessionPath.empty())
    {
        SessionInfo session;
        session.Success = false;
        session.Win32ErrorCode = ERROR_INVALID_PARAMETER;
        session.Message = "Missing --session path.";
        session.ValidationErrors.push_back(session.Message);
        return ToJson(session);
    }

    return ToJson(ValidateSessionDirectory(PathFromUtf8(sessionPath)));
}

void PrintUsage()
{
    std::cout << "{";
    std::cout << "\"schemaVersion\":\"0.1.0\",";
    std::cout << "\"success\":false,";
    std::cout << "\"message\":\"Usage: knmon-native-helper.exe list-targets | launch-sample [--target path] [--agent path] | capture-sample [--target path] [--agent path] [--write-session dir] | replay-session --session dir | validate-session --session dir\"";
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

    if (args[0] == "capture-sample")
    {
        std::cout << CaptureSampleJson(args) << "\n";
        return 0;
    }

    if (args[0] == "replay-session")
    {
        std::cout << ReplaySessionCommandJson(args) << "\n";
        return 0;
    }

    if (args[0] == "validate-session")
    {
        std::cout << ValidateSessionCommandJson(args) << "\n";
        return 0;
    }

    PrintUsage();
    return 1;
}
