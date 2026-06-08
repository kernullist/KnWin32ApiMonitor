#include <Windows.h>

#include <array>
#include <sstream>
#include <string>

namespace
{
constexpr const wchar_t* AgentVersion = L"0.1.0";

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

std::wstring ReadEnv(const wchar_t* name)
{
    std::wstring result;
    std::array<wchar_t, 2048> buffer = {};
    const DWORD length = GetEnvironmentVariableW(name, buffer.data(), static_cast<DWORD>(buffer.size()));

    if (length > 0 && length < buffer.size())
    {
        result.assign(buffer.data(), length);
    }

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

std::string BuildHelloPayload(const std::wstring& operationId)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"eventType\":\"agent_hello_received\",";
    stream << "\"operationId\":" << Q(WideToUtf8(operationId.c_str())) << ",";
    stream << "\"processId\":" << GetCurrentProcessId() << ",";
    stream << "\"threadId\":" << GetCurrentThreadId() << ",";
    stream << "\"architecture\":\"x64\",";
    stream << "\"agentVersion\":" << Q(WideToUtf8(AgentVersion)) << ",";
    stream << "\"message\":\"KNMon x64 agent loaded by controlled early-bird APC\"";
    stream << "}";
    return stream.str();
}

DWORD WINAPI AgentWorker(void*)
{
    const std::wstring pipeName = ReadEnv(L"KNMON_AGENT_PIPE");
    const std::wstring operationId = ReadEnv(L"KNMON_OPERATION_ID");

    do
    {
        if (pipeName.empty())
        {
            break;
        }

        HANDLE pipeHandle = INVALID_HANDLE_VALUE;
        for (int attempt = 0; attempt < 50; ++attempt)
        {
            pipeHandle = CreateFileW(
                pipeName.c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (pipeHandle != INVALID_HANDLE_VALUE)
            {
                break;
            }

            if (GetLastError() != ERROR_PIPE_BUSY)
            {
                Sleep(50);
            }
            else
            {
                WaitNamedPipeW(pipeName.c_str(), 100);
            }
        }

        if (pipeHandle == INVALID_HANDLE_VALUE)
        {
            break;
        }

        const std::string payload = BuildHelloPayload(operationId);
        DWORD bytesWritten = 0;
        WriteFile(pipeHandle, payload.data(), static_cast<DWORD>(payload.size()), &bytesWritten, nullptr);
        FlushFileBuffers(pipeHandle);
        CloseHandle(pipeHandle);
    }
    while (false);

    return 0;
}
}

extern "C" __declspec(dllexport) DWORD KnMonAgentVersion()
{
    return 0x00010000;
}

BOOL APIENTRY DllMain(HMODULE moduleHandle, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(moduleHandle);
        HANDLE threadHandle = CreateThread(nullptr, 0, AgentWorker, nullptr, 0, nullptr);
        if (threadHandle != nullptr)
        {
            CloseHandle(threadHandle);
        }
    }

    return TRUE;
}
