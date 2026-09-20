#include <functional>
#include <deque>
#include "knmon/common/SessionCodec.h"
#include <knmon/core/Controller.h>
#include <knmon/common/BoundedJson.h>
#include <knmon/common/RuntimeSupport.h>

#include <Windows.h>
#include <bcrypt.h>
#include <winsqlite/winsqlite3.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace
{
using knmon::JsonDocument;
using knmon::JsonInputError;

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

std::string JsonStringArray(const std::vector<std::string>& values)
{
    std::ostringstream stream;

    stream << "[";
    for (std::size_t index = 0; index < values.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }

        stream << Q(values[index]);
    }
    stream << "]";
    return stream.str();
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

bool ParseDecimalField(const std::string& value, std::size_t offset, std::size_t length, WORD* output)
{
    bool parsed = false;

    do
    {
        if (output == nullptr || offset + length > value.size())
        {
            break;
        }

        WORD number = 0;
        bool digitsOnly = true;
        for (std::size_t index = 0; index < length; ++index)
        {
            const char ch = value[offset + index];
            if (ch < '0' || ch > '9')
            {
                digitsOnly = false;
                break;
            }

            number = static_cast<WORD>((number * 10) + static_cast<WORD>(ch - '0'));
        }

        if (!digitsOnly)
        {
            break;
        }

        *output = number;
        parsed = true;
    }
    while (false);

    return parsed;
}

bool ParseUtcFileTime(const std::string& value, ULONGLONG* fileTimeValue)
{
    bool parsed = false;

    do
    {
        if (fileTimeValue == nullptr)
        {
            break;
        }

        const bool hasMilliseconds = value.size() == 24 && value[19] == '.' && value[23] == 'Z';
        const bool hasSecondsOnly = value.size() == 20 && value[19] == 'Z';
        if (!hasMilliseconds && !hasSecondsOnly)
        {
            break;
        }

        if (value[4] != '-' || value[7] != '-' || value[10] != 'T' || value[13] != ':' || value[16] != ':')
        {
            break;
        }

        SYSTEMTIME time = {};
        WORD milliseconds = 0;
        if (
            !ParseDecimalField(value, 0, 4, &time.wYear) ||
            !ParseDecimalField(value, 5, 2, &time.wMonth) ||
            !ParseDecimalField(value, 8, 2, &time.wDay) ||
            !ParseDecimalField(value, 11, 2, &time.wHour) ||
            !ParseDecimalField(value, 14, 2, &time.wMinute) ||
            !ParseDecimalField(value, 17, 2, &time.wSecond))
        {
            break;
        }

        if (hasMilliseconds && !ParseDecimalField(value, 20, 3, &milliseconds))
        {
            break;
        }

        time.wMilliseconds = milliseconds;
        FILETIME fileTime = {};
        if (!SystemTimeToFileTime(&time, &fileTime))
        {
            break;
        }

        ULARGE_INTEGER integer = {};
        integer.LowPart = fileTime.dwLowDateTime;
        integer.HighPart = fileTime.dwHighDateTime;
        *fileTimeValue = integer.QuadPart;
        parsed = true;
    }
    while (false);

    return parsed;
}

std::string FormatUtcFileTime(ULONGLONG fileTimeValue)
{
    ULARGE_INTEGER integer = {};
    integer.QuadPart = fileTimeValue;

    FILETIME fileTime = {};
    fileTime.dwLowDateTime = integer.LowPart;
    fileTime.dwHighDateTime = integer.HighPart;

    SYSTEMTIME time = {};
    FileTimeToSystemTime(&fileTime, &time);

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

std::string UtcAfterMilliseconds(std::uint64_t milliseconds)
{
    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);

    ULARGE_INTEGER integer = {};
    integer.LowPart = now.dwLowDateTime;
    integer.HighPart = now.dwHighDateTime;
    integer.QuadPart += milliseconds * 10000ULL;
    return FormatUtcFileTime(integer.QuadPart);
}

bool IsUtcExpired(const std::string& utc)
{
    bool expired = false;

    do
    {
        ULONGLONG deadline = 0;
        if (!ParseUtcFileTime(utc, &deadline))
        {
            break;
        }

        FILETIME now = {};
        GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER current = {};
        current.LowPart = now.dwLowDateTime;
        current.HighPart = now.dwHighDateTime;
        expired = current.QuadPart >= deadline;
    }
    while (false);

    return expired;
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
            std::error_code currentError;
            const std::filesystem::path current = std::filesystem::current_path(currentError);
            if (!currentError)
            {
                result = current;
            }
            break;
        }

        result = std::filesystem::path(modulePath).parent_path();
    }
    while (false);

    return result;
}

std::filesystem::path CurrentExecutablePath()
{
    std::filesystem::path result;
    wchar_t modulePath[MAX_PATH * 8] = {};

    do
    {
        const DWORD length = GetModuleFileNameW(nullptr, modulePath, static_cast<DWORD>(std::size(modulePath)));
        if (length == 0 || length >= std::size(modulePath))
        {
            break;
        }

        result = std::filesystem::path(modulePath);
    }
    while (false);

    return result;
}

knmon::KnMonAgentArchitecture NativeHelperArchitecture()
{
#if defined(_WIN64)
    return knmon::KnMonAgentArchitecture::X64;
#else
    return knmon::KnMonAgentArchitecture::X86;
#endif
}

const wchar_t* DefaultAgentFileName()
{
#if defined(_WIN64)
    return L"knmon-agent64.dll";
#else
    return L"knmon-agent32.dll";
#endif
}

std::uint64_t NextUniqueCounter()
{
    static volatile LONG64 counter = 0;
    return static_cast<std::uint64_t>(InterlockedIncrement64(&counter));
}

std::string NewOperationId()
{
    LARGE_INTEGER qpc = {};
    QueryPerformanceCounter(&qpc);
    std::ostringstream stream;
    stream << "op-" << GetCurrentProcessId() << "-" << GetTickCount64() << "-" << static_cast<std::uint64_t>(qpc.QuadPart)
           << "-" << NextUniqueCounter();
    return stream.str();
}

std::string NewWriterInstanceId()
{
    LARGE_INTEGER qpc = {};
    QueryPerformanceCounter(&qpc);
    std::ostringstream stream;
    stream << "writer-" << GetCurrentProcessId() << "-" << GetTickCount64() << "-" << static_cast<std::uint64_t>(qpc.QuadPart)
           << "-" << NextUniqueCounter();
    return stream.str();
}

std::string NewDaemonInstanceId()
{
    LARGE_INTEGER qpc = {};
    QueryPerformanceCounter(&qpc);
    std::ostringstream stream;
    stream << "daemon-" << GetCurrentProcessId() << "-" << GetTickCount64() << "-" << static_cast<std::uint64_t>(qpc.QuadPart)
           << "-" << NextUniqueCounter();
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

std::string LowerAsciiPathKey(const std::string& value)
{
    std::string result = value;

    for (char& ch : result)
    {
        if (ch >= 'A' && ch <= 'Z')
        {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
        else if (ch == '/')
        {
            ch = '\\';
        }
    }

    return result;
}

std::string NormalizedPathKey(const std::filesystem::path& path)
{
    std::filesystem::path normalized = path;
    std::error_code pathError;
    const std::filesystem::path absolute = std::filesystem::absolute(path, pathError);
    if (!pathError)
    {
        normalized = absolute;
    }

    return LowerAsciiPathKey(PathToUtf8(normalized));
}

bool WriteTextFile(const std::filesystem::path& path, const std::string& text, std::string* error)
{
    bool written = false;
    HANDLE file = INVALID_HANDLE_VALUE;
    std::wstring temporary;
    bool ownsTemporary = false;
    static std::atomic<std::uint64_t> sequence{0};

    do
    {
        std::error_code createError;
        if (!path.parent_path().empty())
        {
            std::filesystem::create_directories(path.parent_path(), createError);
        }
        if (createError)
        {
            if (error != nullptr)
            {
                *error = "create_directories failed for " + PathToUtf8(path.parent_path()) + ": " + createError.message();
            }
            break;
        }

        temporary = path.wstring() + L".tmp." + std::to_wstring(GetCurrentProcessId()) + L"." +
            std::to_wstring(GetTickCount64()) + L"." + std::to_wstring(sequence.fetch_add(1));
        file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error = "Temporary file creation failed with " + std::to_string(GetLastError()) + ".";
            }
            break;
        }
        ownsTemporary = true;

        std::size_t offset = 0;
        DWORD writeError = 0;
        while (offset < text.size())
        {
            DWORD bytes = 0;
            const auto length = static_cast<DWORD>(std::min<std::size_t>(text.size() - offset, 1024 * 1024));
            if (!WriteFile(file, text.data() + offset, length, &bytes, nullptr) || bytes == 0)
            {
                writeError = GetLastError();
                writeError = writeError == 0 ? ERROR_WRITE_FAULT : writeError;
                break;
            }
            offset += bytes;
        }
        if (writeError == 0 && !FlushFileBuffers(file))
        {
            writeError = GetLastError();
        }
        CloseHandle(file);
        file = INVALID_HANDLE_VALUE;
        if (writeError != 0)
        {
            if (error != nullptr)
            {
                *error = "Write or flush failed for " + PathToUtf8(path) + ": " + std::to_string(writeError);
            }
            break;
        }

        // Replace atomically so concurrent readers never observe the file missing
        // and concurrent writers cannot interleave into one shared temp file.
        if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            const DWORD moveError = GetLastError();
            if (error != nullptr)
            {
                *error = "replace failed for " + PathToUtf8(path) + ": move failed with " + std::to_string(moveError);
            }

            break;
        }

        written = true;
    }
    while (false);

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
    if (ownsTemporary && !written)
    {
        DeleteFileW(temporary.c_str());
    }
    return written;
}

bool ReadTextFile(const std::filesystem::path& path, std::string* text, std::string* error,
    std::size_t maxFileBytes = 64 * 1024 * 1024)
{
    bool read = false;
    HANDLE file = INVALID_HANDLE_VALUE;

    do
    {
        if (text != nullptr)
        {
            text->clear();
        }

        // Readers hold the previous immutable file version while a writer replaces it.
        file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error = "open failed for " + PathToUtf8(path);
            }
            break;
        }

        std::string content;
        char block[8192];
        bool tooLarge = false;
        bool readFailed = false;
        while (true)
        {
            DWORD bytes = 0;
            if (!ReadFile(file, block, sizeof(block), &bytes, nullptr))
            {
                readFailed = true;
                break;
            }
            if (bytes == 0)
            {
                break;
            }
            if (bytes > maxFileBytes - content.size())
            {
                tooLarge = true;
                break;
            }
            content.append(block, bytes);
        }
        if (tooLarge || readFailed)
        {
            if (error != nullptr)
            {
                *error = "read failed or file byte limit exceeded: " + PathToUtf8(path);
            }
            break;
        }

        if (text != nullptr)
        {
            *text = std::move(content);
        }
        read = true;
    }
    while (false);

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
    return read;
}

bool ReadTextFile(const std::filesystem::path& path, JsonDocument* document, std::string* error)
{
    bool read = false;
    std::string text;
    if (ReadTextFile(path, &text, error, knmon::JsonLimits{}.DocumentBytes))
    {
        try
        {
            JsonDocument parsed(text);
            parsed.RequireObject();
            *document = std::move(parsed);
            read = true;
        }
        catch (const std::exception& exception)
        {
            if (error != nullptr)
            {
                *error = exception.what();
            }
        }
    }
    return read;
}

std::vector<JsonDocument> ParseJsonl(const std::string& value)
{
    std::vector<JsonDocument> lines;
    std::size_t totalValues = 0;
    std::istringstream stream(value);
    std::string line;

    while (std::getline(stream, line))
    {
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }

        if (line.find_first_not_of(" \t\r") != std::string::npos)
        {
            lines.emplace_back(line, knmon::JsonLimits{1024 * 1024, 256 * 1024, 32, 65536, 250000});
            lines.back().RequireObject();
            totalValues += lines.back().ValueCount();
            if (lines.size() > 250000 || totalValues > 1000000)
            {
                throw JsonInputError("JSONL record or aggregate value limit exceeded.");
            }
        }
    }

    return lines;
}

std::vector<JsonDocument> ParseTraceJsonl(const std::string& value)
{
    auto lines = ParseJsonl(value);
    std::uint64_t previousEventId = 0;
    for (const auto& line : lines)
    {
        knmon::ValidateTraceJson(line);
        const auto eventId = line.UInt64("eventId", true);
        if (eventId == 0 || eventId <= previousEventId)
        {
            throw JsonInputError("Trace event IDs must be nonzero and strictly increasing.");
        }
        previousEventId = eventId;
    }
    return lines;
}

std::vector<JsonDocument> ParseAgentJsonl(const std::string& value)
{
    auto lines = ParseJsonl(value);
    for (const auto& line : lines)
    {
        knmon::ValidateAgentJson(line);
    }
    return lines;
}

bool IsSupportedArchitecture(const std::string& value)
{
    return value == "x86" || value == "x64";
}

std::string ArchitectureName(knmon::KnMonAgentArchitecture architecture)
{
    std::string name = "unknown";

    switch (architecture)
    {
    case knmon::KnMonAgentArchitecture::X86:
        name = "x86";
        break;
    case knmon::KnMonAgentArchitecture::X64:
        name = "x64";
        break;
    default:
        break;
    }

    return name;
}

std::string HexBytes(const std::vector<unsigned char>& bytes)
{
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');

    for (const unsigned char byte : bytes)
    {
        stream << std::setw(2) << static_cast<unsigned int>(byte);
    }

    return stream.str();
}

std::string Sha256Hex(const std::string& text)
{
    std::string result;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<unsigned char> hashObject;
    std::vector<unsigned char> hashBytes;

    do
    {
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        {
            break;
        }

        DWORD objectLength = 0;
        DWORD hashLength = 0;
        DWORD returned = 0;
        if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &returned, 0) < 0)
        {
            break;
        }

        if (BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &returned, 0) < 0)
        {
            break;
        }

        hashObject.resize(objectLength);
        hashBytes.resize(hashLength);
        if (BCryptCreateHash(algorithm, &hash, hashObject.data(), static_cast<ULONG>(hashObject.size()), nullptr, 0, 0) < 0)
        {
            break;
        }

        if (BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(text.data())), static_cast<ULONG>(text.size()), 0) < 0)
        {
            break;
        }

        if (BCryptFinishHash(hash, hashBytes.data(), static_cast<ULONG>(hashBytes.size()), 0) < 0)
        {
            break;
        }

        result = HexBytes(hashBytes);
    }
    while (false);

    if (hash != nullptr)
    {
        BCryptDestroyHash(hash);
    }

    if (algorithm != nullptr)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }

    return result;
}









std::string BuildTraceEventJson(const knmon::KnMonAgentMessage& message, std::uint64_t eventId)
{
    const JsonDocument payload(message.RawPayload);
    const std::uint64_t lastErrorCode = ExtractJsonUInt64(payload, "lastErrorCode");
    const std::string lastErrorMessage = ExtractJsonString(payload, "lastErrorMessage");

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"eventId\":" << eventId << ",";
    if (payload.Has("recordSequence"))
    {
        stream << "\"recordSequence\":" << Q(payload.String("recordSequence")) << ",";
    }
    if (payload.Has("observation"))
    {
        stream << "\"observation\":" << payload.Object("observation") << ",";
    }
    stream << "\"relativeTimeMs\":" << std::setprecision(17) << payload.NonnegativeNumber("relativeTimeMs") << ",";
    stream << "\"timeSource\":" << Q(payload.Has("timing") ? "qpc" : "unavailable") << ",";
    if (payload.Has("timing"))
    {
        stream << "\"timing\":" << payload.Object("timing") << ",";
        stream << "\"timestampUtc\":" << Q(payload.String("timestampUtc")) << ",";
        stream << "\"collectedAtUtc\":" << Q(payload.String("collectedAtUtc")) << ",";
    }
    stream << "\"pid\":" << ExtractJsonUInt64(payload, "pid") << ",";
    stream << "\"tid\":" << ExtractJsonUInt64(payload, "tid") << ",";
    stream << "\"process\":" << Q(ExtractJsonString(payload, "process")) << ",";
    stream << "\"module\":" << Q(ExtractJsonString(payload, "module")) << ",";
    stream << "\"api\":" << Q(ExtractJsonString(payload, "api")) << ",";
    stream << "\"arguments\":" << ExtractJsonArray(payload, "arguments") << ",";
    stream << "\"returnValue\":" << Q(ExtractJsonString(payload, "returnValue")) << ",";
    stream << "\"error\":";
    if (payload.Has("hasError") ? !payload.Bool("hasError") : lastErrorCode == 0)
    {
        stream << "null";
    }
    else
    {
        std::ostringstream code;
        code << "0x" << std::hex << std::setfill('0') << std::setw(8) << lastErrorCode;
        stream << "{";
        stream << "\"kind\":" << Q(payload.Has("errorDomain") ? payload.String("errorDomain") : "win32") << ",";
        stream << "\"code\":" << Q(code.str()) << ",";
        stream << "\"message\":" << Q(lastErrorMessage);
        stream << "}";
    }
    stream << ",";
    for (const auto* key : {"rawReturnValue", "rawReturnBytes", "rawReturnEncoding", "callId", "parentCallId",
        "errorDomain", "outcome", "errorValidity", "successPredicate"})
    {
        if (payload.Has(key))
        {
            stream << Q(key) << ":" << Q(payload.String(key)) << ",";
        }
    }
    for (const auto* key : {"rawReturnBits", "rawLastErrorCode", "rawWinsockErrorCode", "callDepth"})
    {
        if (payload.Has(key))
        {
            stream << Q(key) << ":" << payload.UInt32(key) << ",";
        }
    }
    if (payload.Has("winsockErrorSampled"))
    {
        stream << "\"winsockErrorSampled\":" << (payload.Bool("winsockErrorSampled") ? "true" : "false") << ",";
    }
    stream << "\"durationUs\":" << ExtractJsonUInt64(payload, "durationUs") << ",";
    stream << "\"tags\":" << ExtractJsonArray(payload, "tags") << ",";
    stream << "\"stack\":" << ExtractJsonArray(payload, "stack") << ",";
    stream << "\"stackSource\":" << Q(payload.Has("stackSource") ? payload.String("stackSource") : "legacy_unverified") << ",";
    if (payload.Has("hookContext"))
    {
        stream << "\"hookContext\":" << payload.Object("hookContext") << ",";
    }
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

std::string CaptureHistoryJson(const knmon::KnMonCaptureResult& result)
{
    std::ostringstream stream;
    stream << "{\"bounded\":" << (result.HistoryBounded ? "true" : "false")
        << ",\"capturedEventsTotal\":" << result.CapturedEventsSeen
        << ",\"omittedCapturedEvents\":" << result.CapturedEventsOmitted
        << ",\"omittedAgentMessages\":" << result.AgentMessagesOmitted
        << ",\"omittedResolverPointerCandidates\":" << result.ResolverCandidatesOmitted
        << ",\"omittedResolverPointerUnsupported\":" << result.ResolverUnsupportedOmitted
        << ",\"omittedAuditEvents\":" << result.AuditEventsOmitted << "}";
    return stream.str();
}

std::string ToJson(const knmon::KnMonCaptureResult& result)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":" << Q(result.SchemaVersion) << ",";
    stream << "\"operationId\":" << Q(result.OperationId) << ",";
    stream << "\"sessionId\":" << Q(result.SessionId) << ",";
    stream << "\"sessionState\":" << Q(result.SessionState) << ",";
    stream << "\"sessionKind\":" << Q(result.SessionKind) << ",";
    stream << "\"ownerProcessId\":" << result.OwnerProcessId << ",";
    stream << "\"helperProcessId\":" << result.HelperProcessId << ",";
    stream << "\"startedUtc\":" << Q(result.StartedUtc) << ",";
    stream << "\"updatedUtc\":" << Q(result.UpdatedUtc) << ",";
    stream << "\"stoppedUtc\":" << Q(result.StoppedUtc) << ",";
    stream << "\"cancellationEventName\":" << Q(result.CancellationEventName) << ",";
    stream << "\"lastTransportSequence\":" << result.LastTransportSequence << ",";
    stream << "\"recordsStreamed\":" << result.RecordsStreamed << ",";
    stream << "\"staleReason\":" << Q(result.StaleReason) << ",";
    stream << "\"recoveryAction\":" << Q(result.RecoveryAction) << ",";
    stream << "\"sessionShutdownEvidence\":" << Q(result.SessionShutdownEvidence) << ",";
    stream << "\"success\":" << (result.Success ? "true" : "false") << ",";
    stream << "\"backendMode\":" << Q(result.BackendMode) << ",";
    stream << "\"captureMode\":" << Q(result.CaptureMode) << ",";
    stream << "\"injectionMethod\":" << Q(result.InjectionMethod) << ",";
    stream << "\"targetPath\":" << Q(result.TargetPath) << ",";
    stream << "\"agentPath\":" << Q(result.AgentPath) << ",";
    stream << "\"apiSelection\":" << Q(result.ApiSelection) << ",";
    stream << "\"attachProcessId\":" << result.AttachProcessId << ",";
    stream << "\"detachPolicy\":" << Q(result.DetachPolicy) << ",";
    stream << "\"attachState\":" << Q(result.AttachState) << ",";
    stream << "\"attachStrategy\":" << Q(result.AttachStrategy) << ",";
    stream << "\"loadedAgentDetected\":" << (result.LoadedAgentDetected ? "true" : "false") << ",";
    stream << "\"loadedAgentModuleBase\":" << result.LoadedAgentModuleBase << ",";
    stream << "\"loadedAgentPath\":" << Q(result.LoadedAgentPath) << ",";
    stream << "\"agentControlStatus\":" << result.AgentControlStatus << ",";
    stream << "\"agentAbiVersion\":" << result.AgentAbiVersion << ",";
    stream << "\"targetProcessId\":" << result.TargetProcessId << ",";
    stream << "\"targetThreadId\":" << result.TargetThreadId << ",";
    stream << "\"architecture\":" << Q(result.Architecture) << ",";
    stream << "\"win32ErrorCode\":" << result.Win32ErrorCode << ",";
    stream << "\"ntStatus\":" << Q(result.NtStatus) << ",";
    stream << "\"subsystem\":" << Q(result.Subsystem) << ",";
    stream << "\"operation\":" << Q(result.Operation) << ",";
    stream << "\"message\":" << Q(result.Message) << ",";
    stream << "\"cancelRequested\":" << (result.CancelRequested ? "true" : "false") << ",";
    stream << "\"cancelObserved\":" << (result.CancelObserved ? "true" : "false") << ",";
    stream << "\"cancelStage\":" << Q(result.CancelStage) << ",";
    stream << "\"operationState\":" << Q(result.OperationState) << ",";
    stream << "\"agentCleanupAttempted\":" << (result.AgentCleanupAttempted ? "true" : "false") << ",";
    stream << "\"agentCleanupSucceeded\":" << (result.AgentCleanupSucceeded ? "true" : "false") << ",";
    stream << "\"staleAgentOperationId\":" << Q(result.StaleAgentOperationId) << ",";
    stream << "\"staleAgentState\":" << Q(result.StaleAgentState) << ",";
    stream << "\"droppedEvents\":" << result.DroppedEvents << ",";
    stream << "\"resolverPointerCandidates\":" << result.ResolverPointerCandidates << ",";
    stream << "\"resolverPointerUnsupported\":" << result.ResolverPointerUnsupported << ",";
    stream << "\"transportMode\":" << Q(result.TransportMode) << ",";
    stream << "\"transportCapacity\":" << result.TransportCapacity << ",";
    stream << "\"transportRecordsProduced\":" << result.TransportRecordsProduced << ",";
    stream << "\"transportRecordsConsumed\":" << result.TransportRecordsConsumed << ",";
    stream << "\"retainedHistory\":" << CaptureHistoryJson(result) << ",";
    stream << "\"cleanupState\":" << result.CleanupStateJson << ",";
    stream << "\"hookCleanupOutcome\":" << Q(result.HookCleanupOutcome) << ",";
    stream << "\"targetExitCode\":" << result.TargetExitCode << ",";
    stream << "\"transportAbortedRecords\":" << result.TransportAbortedRecords << ",";
    stream << "\"transportDroppedEvents\":" << result.TransportDroppedEvents << ",";
    stream << "\"transportHighWaterMark\":" << result.TransportHighWaterMark << ",";
    stream << "\"hookOverheadMinUs\":" << result.HookOverheadMinUs << ",";
    stream << "\"hookOverheadAvgUs\":" << result.HookOverheadAvgUs << ",";
    stream << "\"hookOverheadMaxUs\":" << result.HookOverheadMaxUs << ",";
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

std::string ToJson(const knmon::KnMonChildPolicyDecision& decision)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"processId\":" << decision.ProcessId << ",";
    stream << "\"parentProcessId\":" << decision.ParentProcessId << ",";
    stream << "\"imageName\":" << Q(decision.ImageName) << ",";
    stream << "\"architecture\":" << Q(decision.Architecture) << ",";
    stream << "\"eligibilityStatus\":" << Q(decision.EligibilityStatus) << ",";
    stream << "\"decision\":" << Q(decision.Decision) << ",";
    stream << "\"mutationAttempted\":" << (decision.MutationAttempted ? "true" : "false") << ",";
    stream << "\"attachSucceeded\":" << (decision.AttachSucceeded ? "true" : "false") << ",";
    stream << "\"reason\":" << Q(decision.Reason);
    stream << "}";
    return stream.str();
}

std::string ToJson(const knmon::KnMonProcessTreeNode& node)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"processId\":" << node.ProcessId << ",";
    stream << "\"parentProcessId\":" << node.ParentProcessId << ",";
    stream << "\"isRoot\":" << (node.IsRoot ? "true" : "false") << ",";
    stream << "\"imageName\":" << Q(node.ImageName) << ",";
    stream << "\"imagePath\":" << Q(node.ImagePath) << ",";
    stream << "\"architecture\":" << Q(node.Architecture) << ",";
    stream << "\"firstSeenUtc\":" << Q(node.FirstSeenUtc) << ",";
    stream << "\"lastSeenUtc\":" << Q(node.LastSeenUtc) << ",";
    stream << "\"isAlive\":" << (node.IsAlive ? "true" : "false") << ",";
    stream << "\"exited\":" << (node.Exited ? "true" : "false") << ",";
    stream << "\"eligibilityStatus\":" << Q(node.EligibilityStatus) << ",";
    stream << "\"policyDecision\":" << Q(node.PolicyDecision) << ",";
    stream << "\"message\":" << Q(node.Message);
    stream << "}";
    return stream.str();
}

std::string ToJson(const knmon::KnMonProcessTreeResult& result)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":" << Q(result.SchemaVersion) << ",";
    stream << "\"operationId\":" << Q(result.OperationId) << ",";
    stream << "\"sessionId\":" << Q(result.SessionId) << ",";
    stream << "\"sessionState\":" << Q(result.SessionState) << ",";
    stream << "\"sessionKind\":" << Q(result.SessionKind) << ",";
    stream << "\"ownerProcessId\":" << result.OwnerProcessId << ",";
    stream << "\"helperProcessId\":" << result.HelperProcessId << ",";
    stream << "\"startedUtc\":" << Q(result.StartedUtc) << ",";
    stream << "\"updatedUtc\":" << Q(result.UpdatedUtc) << ",";
    stream << "\"stoppedUtc\":" << Q(result.StoppedUtc) << ",";
    stream << "\"cancellationEventName\":" << Q(result.CancellationEventName) << ",";
    stream << "\"lastTransportSequence\":" << result.LastTransportSequence << ",";
    stream << "\"recordsStreamed\":" << result.RecordsStreamed << ",";
    stream << "\"staleReason\":" << Q(result.StaleReason) << ",";
    stream << "\"recoveryAction\":" << Q(result.RecoveryAction) << ",";
    stream << "\"success\":" << (result.Success ? "true" : "false") << ",";
    stream << "\"backendMode\":" << Q(result.BackendMode) << ",";
    stream << "\"supervisionMode\":" << Q(result.SupervisionMode) << ",";
    stream << "\"rootProcessId\":" << result.RootProcessId << ",";
    stream << "\"durationMs\":" << result.DurationMs << ",";
    stream << "\"childPolicy\":" << Q(result.ChildPolicy) << ",";
    stream << "\"win32ErrorCode\":" << result.Win32ErrorCode << ",";
    stream << "\"ntStatus\":" << Q(result.NtStatus) << ",";
    stream << "\"subsystem\":" << Q(result.Subsystem) << ",";
    stream << "\"operation\":" << Q(result.Operation) << ",";
    stream << "\"message\":" << Q(result.Message) << ",";
    stream << "\"cancelRequested\":" << (result.CancelRequested ? "true" : "false") << ",";
    stream << "\"cancelObserved\":" << (result.CancelObserved ? "true" : "false") << ",";
    stream << "\"cancelStage\":" << Q(result.CancelStage) << ",";
    stream << "\"operationState\":" << Q(result.OperationState) << ",";
    stream << "\"processNodes\":[";
    for (std::size_t index = 0; index < result.ProcessNodes.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(result.ProcessNodes[index]);
    }
    stream << "],";
    stream << "\"policyDecisions\":[";
    for (std::size_t index = 0; index < result.PolicyDecisions.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(result.PolicyDecisions[index]);
    }
    stream << "],";
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
    stream << "\"childAttachResults\":[";
    for (std::size_t index = 0; index < result.ChildAttachResults.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(result.ChildAttachResults[index]);
    }
    stream << "]";
    stream << "}";
    return stream.str();
}

struct SessionInfo
{
    std::string ReplayIndexSha256;
    std::string ReplayTraceSha256;
    bool Success = false;
    std::string Format;
    std::string SessionId;
    std::string SessionPath;
    std::string CreatedUtc;
    bool Finalized = false;
    std::uint64_t TraceEventCount = 0;
    std::uint64_t AgentEventCount = 0;
    std::uint64_t AuditEventCount = 0;
    std::uint64_t ResolverPointerCandidates = 0;
    std::uint64_t ResolverPointerUnsupported = 0;
    std::uint64_t DroppedEvents = 0;
    std::uint64_t TransportDroppedEvents = 0;
    std::uint64_t TransportAbortedRecords = 0;
    std::uint64_t HostDroppedBatches = 0;
    std::uint64_t ChunkCount = 0;
    std::uint64_t LastBatchSequence = 0;
    std::uint64_t LastRecordSequence = 0;
    std::string CompressionSummary;
    std::uint64_t StoredBytes = 0;
    std::uint64_t UncompressedBytes = 0;
    std::string WriterState;
    std::string RecoveryState;
    std::string RecoveryReason;
    std::string RecoveryAction;
    bool OwnerAlive = false;
    bool HelperAlive = false;
    bool WriterAlive = false;
    bool TargetAlive = false;
    bool LeaseExpired = false;
    bool RestartEligible = false;
    std::uint32_t Win32ErrorCode = 0;
    std::string Message;
    std::vector<std::string> ValidationErrors;
};

struct NativeSessionInfo
{
    std::string SchemaVersion = "0.1.0";
    std::string SessionId;
    std::string OperationId;
    std::string SessionKind;
    std::uint32_t OwnerProcessId = 0;
    std::uint32_t HelperProcessId = 0;
    std::uint32_t TargetProcessId = 0;
    std::uint64_t TargetProcessCreationTime = 0;
    std::string SessionState;
    std::string StartedUtc;
    std::string UpdatedUtc;
    std::string StoppedUtc;
    std::string CancellationEventName;
    std::uint64_t LastTransportSequence = 0;
    std::uint64_t RecordsStreamed = 0;
    std::uint64_t TransportDroppedEvents = 0;
    std::uint64_t TransportAbortedRecords = 0;
    std::uint64_t HostDroppedBatches = 0;
    std::string StaleReason;
    std::string RecoveryAction;
    std::string ShutdownEvidence;
    bool StopRequested = false;
    bool AgentCleanupAttempted = false;
    bool AgentCleanupSucceeded = false;
    std::string LastError;
    std::uint64_t ElapsedMs = 0;
    std::uint32_t DurationMs = 0;
    std::uint32_t DaemonProcessId = 0;
    std::string DaemonInstanceId;
    std::string DaemonStartedUtc;
    std::string DaemonHeartbeatUtc;
    std::string DaemonControlEndpoint;
    std::string KnapmPath;
    bool DaemonAlive = false;
    bool SessionProcessAlive = false;
    bool TargetAlive = false;
    bool TargetExitObserved = false;
    bool KnapmExists = false;
    bool KnapmValid = false;
    std::string RecoveryState;
    std::string RecoveryReason;
    bool PruneEligible = false;
    std::string PruneReason;
};

std::string ToJson(const SessionInfo& session)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (session.Success ? "true" : "false") << ",";
    stream << "\"format\":" << Q(session.Format) << ",";
    stream << "\"sessionId\":" << Q(session.SessionId) << ",";
    stream << "\"sessionPath\":" << Q(session.SessionPath) << ",";
    stream << "\"createdUtc\":" << Q(session.CreatedUtc) << ",";
    stream << "\"finalized\":" << (session.Finalized ? "true" : "false") << ",";
    stream << "\"traceEventCount\":" << session.TraceEventCount << ",";
    stream << "\"agentEventCount\":" << session.AgentEventCount << ",";
    stream << "\"auditEventCount\":" << session.AuditEventCount << ",";
    stream << "\"resolverPointerCandidates\":" << session.ResolverPointerCandidates << ",";
    stream << "\"resolverPointerUnsupported\":" << session.ResolverPointerUnsupported << ",";
    stream << "\"droppedEvents\":" << session.DroppedEvents << ",";
    stream << "\"transportDroppedEvents\":" << session.TransportDroppedEvents << ",";
    stream << "\"transportAbortedRecords\":" << session.TransportAbortedRecords << ",";
    stream << "\"hostDroppedBatches\":" << session.HostDroppedBatches << ",";
    stream << "\"chunkCount\":" << session.ChunkCount << ",";
    stream << "\"lastBatchSequence\":" << session.LastBatchSequence << ",";
    stream << "\"lastRecordSequence\":" << session.LastRecordSequence << ",";
    stream << "\"compression\":" << Q(session.CompressionSummary) << ",";
    stream << "\"storedBytes\":" << session.StoredBytes << ",";
    stream << "\"uncompressedBytes\":" << session.UncompressedBytes << ",";
    stream << "\"writerState\":" << Q(session.WriterState) << ",";
    stream << "\"recoveryState\":" << Q(session.RecoveryState) << ",";
    stream << "\"recoveryReason\":" << Q(session.RecoveryReason) << ",";
    stream << "\"recoveryAction\":" << Q(session.RecoveryAction) << ",";
    stream << "\"ownerAlive\":" << (session.OwnerAlive ? "true" : "false") << ",";
    stream << "\"helperAlive\":" << (session.HelperAlive ? "true" : "false") << ",";
    stream << "\"writerAlive\":" << (session.WriterAlive ? "true" : "false") << ",";
    stream << "\"targetAlive\":" << (session.TargetAlive ? "true" : "false") << ",";
    stream << "\"leaseExpired\":" << (session.LeaseExpired ? "true" : "false") << ",";
    stream << "\"restartEligible\":" << (session.RestartEligible ? "true" : "false") << ",";
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

std::string ToJson(const NativeSessionInfo& session)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":" << Q(session.SchemaVersion) << ",";
    stream << "\"sessionId\":" << Q(session.SessionId) << ",";
    stream << "\"operationId\":" << Q(session.OperationId) << ",";
    stream << "\"sessionKind\":" << Q(session.SessionKind) << ",";
    stream << "\"ownerProcessId\":" << session.OwnerProcessId << ",";
    stream << "\"helperProcessId\":" << session.HelperProcessId << ",";
    stream << "\"targetProcessId\":" << session.TargetProcessId << ",";
    stream << "\"targetProcessCreationTime\":" << Q(std::to_string(session.TargetProcessCreationTime)) << ",";
    stream << "\"sessionState\":" << Q(session.SessionState) << ",";
    stream << "\"startedUtc\":" << Q(session.StartedUtc) << ",";
    stream << "\"updatedUtc\":" << Q(session.UpdatedUtc) << ",";
    stream << "\"stoppedUtc\":" << Q(session.StoppedUtc) << ",";
    stream << "\"cancellationEventName\":" << Q(session.CancellationEventName) << ",";
    stream << "\"lastTransportSequence\":" << session.LastTransportSequence << ",";
    stream << "\"recordsStreamed\":" << session.RecordsStreamed << ",";
    stream << "\"transportDroppedEvents\":" << session.TransportDroppedEvents << ",";
    stream << "\"transportAbortedRecords\":" << session.TransportAbortedRecords << ",";
    stream << "\"hostDroppedBatches\":" << session.HostDroppedBatches << ",";
    stream << "\"staleReason\":" << Q(session.StaleReason) << ",";
    stream << "\"recoveryAction\":" << Q(session.RecoveryAction) << ",";
    stream << "\"shutdownEvidence\":" << Q(session.ShutdownEvidence) << ",";
    stream << "\"stopRequested\":" << (session.StopRequested ? "true" : "false") << ",";
    stream << "\"agentCleanupAttempted\":" << (session.AgentCleanupAttempted ? "true" : "false") << ",";
    stream << "\"agentCleanupSucceeded\":" << (session.AgentCleanupSucceeded ? "true" : "false") << ",";
    stream << "\"lastError\":" << Q(session.LastError) << ",";
    stream << "\"elapsedMs\":" << session.ElapsedMs << ",";
    stream << "\"durationMs\":" << session.DurationMs << ",";
    stream << "\"daemonProcessId\":" << session.DaemonProcessId << ",";
    stream << "\"daemonInstanceId\":" << Q(session.DaemonInstanceId) << ",";
    stream << "\"daemonStartedUtc\":" << Q(session.DaemonStartedUtc) << ",";
    stream << "\"daemonHeartbeatUtc\":" << Q(session.DaemonHeartbeatUtc) << ",";
    stream << "\"daemonControlEndpoint\":" << Q(session.DaemonControlEndpoint) << ",";
    stream << "\"knapmPath\":" << Q(session.KnapmPath) << ",";
    stream << "\"daemonAlive\":" << (session.DaemonAlive ? "true" : "false") << ",";
    stream << "\"sessionProcessAlive\":" << (session.SessionProcessAlive ? "true" : "false") << ",";
    stream << "\"targetAlive\":" << (session.TargetAlive ? "true" : "false") << ",";
    stream << "\"targetExitObserved\":" << (session.TargetExitObserved ? "true" : "false") << ",";
    stream << "\"knapmExists\":" << (session.KnapmExists ? "true" : "false") << ",";
    stream << "\"knapmValid\":" << (session.KnapmValid ? "true" : "false") << ",";
    stream << "\"recoveryState\":" << Q(session.RecoveryState) << ",";
    stream << "\"recoveryReason\":" << Q(session.RecoveryReason) << ",";
    stream << "\"pruneEligible\":" << (session.PruneEligible ? "true" : "false") << ",";
    stream << "\"pruneReason\":" << Q(session.PruneReason);
    stream << "}";
    return stream.str();
}

std::string SessionFrameJson(const std::string& frameType, const NativeSessionInfo& session)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"frameType\":" << Q(frameType) << ",";
    stream << "\"session\":" << ToJson(session);
    stream << "}";
    return stream.str();
}

std::string TraceBatchFrameJson(const knmon::KnMonTraceBatch& batch)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":" << Q(batch.SchemaVersion) << ",";
    stream << "\"frameType\":\"trace_batch\",";
    stream << "\"sessionId\":" << Q(batch.SessionId) << ",";
    stream << "\"operationId\":" << Q(batch.OperationId) << ",";
    stream << "\"batchSequence\":" << batch.BatchSequence << ",";
    stream << "\"firstRecordSequence\":" << batch.FirstRecordSequence << ",";
    stream << "\"lastRecordSequence\":" << batch.LastRecordSequence << ",";
    stream << "\"eventCount\":" << batch.EventCount << ",";
    stream << "\"droppedEvents\":" << batch.DroppedEvents << ",";
    stream << "\"transportAbortedRecords\":" << batch.AbortedRecords << ",";
    stream << "\"recordsStreamed\":" << batch.RecordsStreamed << ",";
    stream << "\"hostDroppedBatches\":" << batch.HostDroppedBatches << ",";
    stream << "\"events\":[";
    for (std::size_t index = 0; index < batch.Events.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(batch.Events[index]);
    }
    stream << "]";
    stream << "}";
    return stream.str();
}

bool WriteTraceBatchFrame(const knmon::KnMonTraceBatch& batch)
{
    const auto frame = TraceBatchFrameJson(batch);
    bool written = false;
    if (frame.size() < 8 * 1024 * 1024)
    {
        std::cout << frame << "\n" << std::flush;
        written = static_cast<bool>(std::cout);
    }
    return written;
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
    std::string source = "knmon-native-helper capture-sample";
    if (result.CaptureMode == "bounded-native-attach")
    {
        source = "knmon-native-helper attach-capture";
    }

    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"sessionId\":" << Q(session.SessionId) << ",";
    stream << "\"createdUtc\":" << Q(session.CreatedUtc) << ",";
    stream << "\"shutdownEvidence\":" << Q(result.SessionShutdownEvidence) << ",";
    stream << "\"cleanupState\":" << result.CleanupStateJson << ",";
    stream << "\"source\":" << Q(source) << ",";
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
    stream << "\"capturedEvents\":" << result.CapturedEvents.size() << ",";
    stream << "\"resolverPointerCandidates\":" << result.ResolverPointerCandidates << ",";
    stream << "\"resolverPointerUnsupported\":" << result.ResolverPointerUnsupported;
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
    session.Format = "legacy-jsonl";
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
        session.ResolverPointerCandidates = result.ResolverPointerCandidates;
        session.ResolverPointerUnsupported = result.ResolverPointerUnsupported;

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
        session.Finalized = true;
        session.Win32ErrorCode = 0;
        session.WriterState = "finalized";
        session.Message = "Session written.";
    }
    while (false);

    if (!session.Success && session.WriterState.empty())
    {
        session.WriterState = "failed";
    }

    return session;
}

struct KnapmChunkInfo
{
    std::uint64_t ChunkSequence = 0;
    std::uint64_t BatchSequence = 0;
    std::string File;
    std::string Compression = "none";
    std::uint64_t EventCount = 0;
    std::uint64_t FirstRecordSequence = 0;
    std::uint64_t LastRecordSequence = 0;
    std::uint64_t FirstEventId = 0;
    std::uint64_t LastEventId = 0;
    std::uint64_t ByteLength = 0;
    std::string Sha256;
    std::uint64_t UncompressedByteLength = 0;
    std::string UncompressedSha256;
};

struct KnapmOwnerInfo
{
    std::string OwnerKind = "bounded-helper";
    std::uint32_t HostProcessId = 0;
    std::uint32_t HelperProcessId = 0;
    std::uint32_t WriterProcessId = 0;
    std::string WriterInstanceId;
    std::uint64_t WriterGeneration = 1;
    std::string StartedUtc;
    std::string UpdatedUtc;
    std::string HeartbeatUtc;
    std::uint64_t LeaseTimeoutMs = 15000;
    std::string LeaseExpiresUtc;
    std::uint32_t DaemonProcessId = 0;
    std::string DaemonInstanceId;
    std::string DaemonStartedUtc;
    std::string DaemonHeartbeatUtc;
    std::string ControlEndpoint;
};

struct KnapmCheckpointInfo
{
    std::uint64_t LastCommittedChunkSequence = 0;
    std::uint64_t LastCommittedBatchSequence = 0;
    std::uint64_t LastCommittedRecordSequence = 0;
    std::uint64_t LastCommittedEventId = 0;
    std::string LastManifestUpdateUtc;
    std::string LastIndexUpdateUtc;
    bool IndexConsistent = true;
};

struct KnapmRecoveryInfo
{
    std::string State = "owned";
    std::string Reason = "owner_alive";
    std::string Action = "wait";
    std::string ClassifiedUtc;
    bool OwnerAlive = true;
    bool HelperAlive = true;
    bool WriterAlive = true;
    bool TargetAlive = true;
    bool LeaseExpired = false;
    bool RestartEligible = false;
};

std::string NormalizeKnapmCompression(const std::string& compression)
{
    if (compression.empty())
    {
        return "none";
    }

    return compression;
}

bool IsSupportedKnapmCompression(const std::string& compression)
{
    const std::string normalized = NormalizeKnapmCompression(compression);
    return normalized == "none" || normalized == "zstd";
}

std::string KnapmChunkFileName(std::uint64_t chunkSequence, const std::string& compression)
{
    std::ostringstream stream;
    stream << "chunks/trace-" << std::setfill('0') << std::setw(6) << chunkSequence << ".jsonl";
    if (NormalizeKnapmCompression(compression) == "zstd")
    {
        stream << ".zst";
    }
    return stream.str();
}

std::filesystem::path KnapmChildPath(const std::filesystem::path& root, const std::string& relativePath)
{
    std::filesystem::path result = root;
    std::string component;

    for (const char ch : relativePath)
    {
        if (ch == '/' || ch == '\\')
        {
            if (!component.empty())
            {
                result /= PathFromUtf8(component);
                component.clear();
            }
        }
        else
        {
            component.push_back(ch);
        }
    }

    if (!component.empty())
    {
        result /= PathFromUtf8(component);
    }

    return result;
}

bool IsSafeKnapmChunkPath(const std::string& relativePath)
{
    bool safe = false;

    do
    {
        if (relativePath.empty())
        {
            break;
        }

        if (relativePath.find('\\') != std::string::npos)
        {
            break;
        }

        std::string normalized = relativePath;
        std::replace(normalized.begin(), normalized.end(), '\\', '/');
        if (normalized.empty() || normalized.front() == '/' || normalized.find(':') != std::string::npos)
        {
            break;
        }

        const std::string prefix = "chunks/trace-";
        const std::string suffix = normalized.ends_with(".jsonl.zst") ? ".jsonl.zst" : ".jsonl";
        if (normalized.rfind(prefix, 0) != 0)
        {
            break;
        }

        // setw(6) pads but never truncates, so accept 6..20 digits: a session that
        // reaches chunk 1,000,000 must not self-invalidate as malformed.
        const std::size_t digitCount = normalized.size() - prefix.size() - suffix.size();
        if (digitCount < 6 || digitCount > 20)
        {
            break;
        }

        if (normalized.substr(normalized.size() - suffix.size()) != suffix)
        {
            break;
        }

        bool digitsOnly = true;
        for (std::size_t index = prefix.size(); index < prefix.size() + digitCount; ++index)
        {
            const char ch = normalized[index];
            if (ch < '0' || ch > '9')
            {
                digitsOnly = false;
                break;
            }
        }

        if (!digitsOnly)
        {
            break;
        }

        safe = true;
    }
    while (false);

    return safe;
}

std::string ToJson(const KnapmOwnerInfo& owner)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"ownerKind\":" << Q(owner.OwnerKind) << ",";
    stream << "\"hostProcessId\":" << owner.HostProcessId << ",";
    stream << "\"helperProcessId\":" << owner.HelperProcessId << ",";
    stream << "\"writerProcessId\":" << owner.WriterProcessId << ",";
    stream << "\"writerInstanceId\":" << Q(owner.WriterInstanceId) << ",";
    stream << "\"writerGeneration\":" << owner.WriterGeneration << ",";
    stream << "\"startedUtc\":" << Q(owner.StartedUtc) << ",";
    stream << "\"updatedUtc\":" << Q(owner.UpdatedUtc) << ",";
    stream << "\"heartbeatUtc\":" << Q(owner.HeartbeatUtc) << ",";
    stream << "\"leaseTimeoutMs\":" << owner.LeaseTimeoutMs << ",";
    stream << "\"leaseExpiresUtc\":" << Q(owner.LeaseExpiresUtc) << ",";
    stream << "\"daemonProcessId\":" << owner.DaemonProcessId << ",";
    stream << "\"daemonInstanceId\":" << Q(owner.DaemonInstanceId) << ",";
    stream << "\"daemonStartedUtc\":" << Q(owner.DaemonStartedUtc) << ",";
    stream << "\"daemonHeartbeatUtc\":" << Q(owner.DaemonHeartbeatUtc) << ",";
    stream << "\"controlEndpoint\":" << Q(owner.ControlEndpoint);
    stream << "}";
    return stream.str();
}

std::string ToJson(const KnapmCheckpointInfo& checkpoint)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"lastCommittedChunkSequence\":" << checkpoint.LastCommittedChunkSequence << ",";
    stream << "\"lastCommittedBatchSequence\":" << checkpoint.LastCommittedBatchSequence << ",";
    stream << "\"lastCommittedRecordSequence\":" << checkpoint.LastCommittedRecordSequence << ",";
    stream << "\"lastCommittedEventId\":" << checkpoint.LastCommittedEventId << ",";
    stream << "\"lastManifestUpdateUtc\":" << Q(checkpoint.LastManifestUpdateUtc) << ",";
    stream << "\"lastIndexUpdateUtc\":" << Q(checkpoint.LastIndexUpdateUtc) << ",";
    stream << "\"indexConsistent\":" << (checkpoint.IndexConsistent ? "true" : "false");
    stream << "}";
    return stream.str();
}

std::string ToJson(const KnapmRecoveryInfo& recovery)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"state\":" << Q(recovery.State) << ",";
    stream << "\"reason\":" << Q(recovery.Reason) << ",";
    stream << "\"action\":" << Q(recovery.Action) << ",";
    stream << "\"classifiedUtc\":" << Q(recovery.ClassifiedUtc) << ",";
    stream << "\"ownerAlive\":" << (recovery.OwnerAlive ? "true" : "false") << ",";
    stream << "\"helperAlive\":" << (recovery.HelperAlive ? "true" : "false") << ",";
    stream << "\"writerAlive\":" << (recovery.WriterAlive ? "true" : "false") << ",";
    stream << "\"targetAlive\":" << (recovery.TargetAlive ? "true" : "false") << ",";
    stream << "\"leaseExpired\":" << (recovery.LeaseExpired ? "true" : "false") << ",";
    stream << "\"restartEligible\":" << (recovery.RestartEligible ? "true" : "false");
    stream << "}";
    return stream.str();
}

std::string ToJson(const KnapmChunkInfo& chunk)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"chunkSequence\":" << chunk.ChunkSequence << ",";
    stream << "\"batchSequence\":" << chunk.BatchSequence << ",";
    stream << "\"file\":" << Q(chunk.File) << ",";
    stream << "\"compression\":" << Q(chunk.Compression) << ",";
    stream << "\"eventCount\":" << chunk.EventCount << ",";
    stream << "\"firstRecordSequence\":" << chunk.FirstRecordSequence << ",";
    stream << "\"lastRecordSequence\":" << chunk.LastRecordSequence << ",";
    stream << "\"firstEventId\":" << chunk.FirstEventId << ",";
    stream << "\"lastEventId\":" << chunk.LastEventId << ",";
    stream << "\"byteLength\":" << chunk.ByteLength << ",";
    stream << "\"sha256\":" << Q(chunk.Sha256);
    if (chunk.Compression == "zstd" || chunk.UncompressedByteLength != 0 || !chunk.UncompressedSha256.empty())
    {
        stream << ",\"uncompressedByteLength\":" << chunk.UncompressedByteLength;
        stream << ",\"uncompressedSha256\":" << Q(chunk.UncompressedSha256);
    }
    stream << "}";
    return stream.str();
}

struct KnapmSessionWriter
{
    bool Enabled = false;
    bool Failed = false;
    std::filesystem::path Root;
    std::string Error;
    std::string SessionId;
    std::string OperationId;
    std::string CreatedUtc;
    std::string UpdatedUtc;
    std::string FinalizedUtc;
    std::string WriterState = "created";
    KnapmOwnerInfo Owner;
    KnapmCheckpointInfo Checkpoint;
    KnapmRecoveryInfo Recovery;
    NativeSessionInfo Session;
    std::string TargetPath;
    std::uint32_t TargetThreadId = 0;
    std::string Architecture;
    std::string AgentPath;
    std::string AgentVersion;
    std::uint64_t DroppedEvents = 0;
    std::uint64_t TransportDroppedEvents = 0;
    std::uint64_t TransportAbortedRecords = 0;
    std::uint64_t HostDroppedBatches = 0;
    std::uint64_t TraceEventCount = 0;
    std::uint64_t AgentEventCount = 0;
    std::uint64_t AuditEventCount = 0;
    std::uint64_t CapturedEventCount = 0;
    std::string RetainedHistory = "{}";
    std::string CleanupState = "null";
    std::uint64_t ResolverPointerCandidates = 0;
    std::uint64_t ResolverPointerUnsupported = 0;
    std::uint64_t LastBatchSequence = 0;
    std::uint64_t LastRecordSequence = 0;
    std::uint64_t NextEventId = 1;
    std::uint64_t StoredBytes = 0;
    std::uint64_t UncompressedBytes = 0;
    bool Finalized = false;
    std::string Compression = "none";
    std::vector<KnapmChunkInfo> Chunks;

    void TouchOwnership()
    {
        const std::string now = NowUtc();
        UpdatedUtc = now;
        Owner.UpdatedUtc = now;
        Owner.HeartbeatUtc = now;
        Owner.LeaseExpiresUtc = UtcAfterMilliseconds(Owner.LeaseTimeoutMs);
        if (Owner.OwnerKind == "persistent-daemon")
        {
            Owner.DaemonHeartbeatUtc = now;
            Session.DaemonHeartbeatUtc = now;
        }
        Recovery.ClassifiedUtc = now;
    }

    void RefreshCheckpoint()
    {
        Checkpoint.LastCommittedChunkSequence = static_cast<std::uint64_t>(Chunks.size());
        Checkpoint.LastCommittedBatchSequence = LastBatchSequence;
        Checkpoint.LastCommittedRecordSequence = LastRecordSequence;
        Checkpoint.LastCommittedEventId = NextEventId > 1 ? NextEventId - 1 : 0;
    }

    void SetRecoveryState(
        const std::string& state,
        const std::string& reason,
        const std::string& action,
        bool restartEligible)
    {
        Recovery.State = state;
        Recovery.Reason = reason;
        Recovery.Action = action;
        Recovery.OwnerAlive = true;
        Recovery.HelperAlive = true;
        Recovery.WriterAlive = true;
        Recovery.TargetAlive = Session.TargetProcessId != 0;
        Recovery.LeaseExpired = false;
        Recovery.RestartEligible = restartEligible;
        Recovery.ClassifiedUtc = NowUtc();
    }

    bool Start(
        const std::filesystem::path& root,
        const NativeSessionInfo& session,
        const knmon::KnMonAttachRequest& request,
        const std::string& compression)
    {
        bool started = false;

        do
        {
            const std::string normalizedCompression = NormalizeKnapmCompression(compression);
            if (!IsSupportedKnapmCompression(normalizedCompression))
            {
                MarkFailed("unsupported_compression");
                break;
            }

            Enabled = true;
            Root = root;
            Compression = normalizedCompression;
            Session = session;
            SessionId = session.SessionId;
            OperationId = session.OperationId;
            CreatedUtc = session.StartedUtc.empty() ? NowUtc() : session.StartedUtc;
            UpdatedUtc = NowUtc();
            WriterState = "writing";
            Owner.OwnerKind = session.DaemonProcessId != 0 ? "persistent-daemon" : "bounded-helper";
            Owner.HostProcessId = session.OwnerProcessId;
            Owner.HelperProcessId = session.HelperProcessId;
            Owner.WriterProcessId = GetCurrentProcessId();
            Owner.WriterInstanceId = NewWriterInstanceId();
            Owner.WriterGeneration = 1;
            Owner.StartedUtc = CreatedUtc;
            Owner.LeaseTimeoutMs = 15000;
            Owner.DaemonProcessId = session.DaemonProcessId;
            Owner.DaemonInstanceId = session.DaemonInstanceId;
            Owner.DaemonStartedUtc = session.DaemonStartedUtc;
            Owner.DaemonHeartbeatUtc = session.DaemonHeartbeatUtc;
            Owner.ControlEndpoint = session.DaemonControlEndpoint;
            SetRecoveryState("owned", "owner_alive", "wait", false);
            TouchOwnership();
            RefreshCheckpoint();
            AgentPath = request.AgentPath;
            Architecture = ArchitectureName(request.Architecture);
            if (!IsSupportedArchitecture(Architecture))
            {
                Architecture = ArchitectureName(NativeHelperArchitecture());
            }

            std::string writeError;
            if (!WriteTextFile(KnapmChildPath(Root, "audit.jsonl"), "", &writeError))
            {
                MarkFailed(writeError);
                break;
            }

            if (!WriteTextFile(KnapmChildPath(Root, "agent-events.jsonl"), "", &writeError))
            {
                MarkFailed(writeError);
                break;
            }

            Checkpoint.LastIndexUpdateUtc = NowUtc();
            if (!WriteIndex(&writeError))
            {
                MarkFailed(writeError);
                break;
            }

            if (!WriteManifest(&writeError))
            {
                MarkFailed(writeError);
                break;
            }

            started = true;
        }
        while (false);

        return started;
    }

    void UpdateSession(const NativeSessionInfo& session)
    {
        if (!Enabled)
        {
            return;
        }

        Session = session;
        TouchOwnership();
        if (!session.UpdatedUtc.empty())
        {
            UpdatedUtc = session.UpdatedUtc;
            Owner.UpdatedUtc = session.UpdatedUtc;
        }
        TransportDroppedEvents = session.TransportDroppedEvents;
        TransportAbortedRecords = session.TransportAbortedRecords;
        HostDroppedBatches = session.HostDroppedBatches;
        if (Chunks.empty())
        {
            LastRecordSequence = session.LastTransportSequence;
        }
        RefreshCheckpoint();
    }

    bool WriteBatch(const knmon::KnMonTraceBatch& batch)
    {
        bool written = false;

        do
        {
            if (!Enabled)
            {
                written = true;
                break;
            }

            if (Failed)
            {
                break;
            }

            if (batch.Events.empty())
            {
                written = true;
                break;
            }

            // Keep the complete index within the bounded JSON reader contract.
            if (Chunks.size() >= 8192)
            {
                MarkFailed("Session chunk limit reached; start a new session.");
                break;
            }

            std::vector<std::string> lines;
            std::uint64_t firstEventId = NextEventId;
            for (const auto& event : batch.Events)
            {
                lines.push_back(BuildTraceEventJson(event, NextEventId));
                ++NextEventId;
            }

            const std::uint64_t chunkSequence = static_cast<std::uint64_t>(Chunks.size()) + 1;
            const std::string chunkFile = KnapmChunkFileName(chunkSequence, Compression);
            const std::string chunkText = JoinJsonl(lines);
            const std::string uncompressedHash = Sha256Hex(chunkText);
            if (uncompressedHash.empty())
            {
                MarkFailed("sha256 failed for " + chunkFile);
                break;
            }

            std::string storedChunk = chunkText;
            if (Compression == "zstd")
            {
                std::string compressionError;
                if (!knmon::EncodeSessionZstd(chunkText, &storedChunk, &compressionError))
                {
                    MarkFailed(compressionError.empty() ? "zstd compression failed for " + chunkFile : compressionError);
                    break;
                }
            }

            const std::string storedHash = Sha256Hex(storedChunk);
            if (storedHash.empty())
            {
                MarkFailed("stored sha256 failed for " + chunkFile);
                break;
            }

            std::string writeError;
            if (!WriteTextFile(KnapmChildPath(Root, chunkFile), storedChunk, &writeError))
            {
                MarkFailed(writeError);
                break;
            }

            KnapmChunkInfo chunk;
            chunk.ChunkSequence = chunkSequence;
            chunk.BatchSequence = batch.BatchSequence;
            chunk.File = chunkFile;
            chunk.Compression = Compression;
            chunk.EventCount = static_cast<std::uint64_t>(lines.size());
            chunk.FirstRecordSequence = batch.FirstRecordSequence;
            chunk.LastRecordSequence = batch.LastRecordSequence;
            chunk.FirstEventId = firstEventId;
            chunk.LastEventId = NextEventId - 1;
            chunk.ByteLength = static_cast<std::uint64_t>(storedChunk.size());
            chunk.Sha256 = storedHash;
            chunk.UncompressedByteLength = static_cast<std::uint64_t>(chunkText.size());
            chunk.UncompressedSha256 = uncompressedHash;
            Chunks.push_back(chunk);

            StoredBytes += chunk.ByteLength;
            UncompressedBytes += chunk.UncompressedByteLength;
            TraceEventCount += chunk.EventCount;
            LastBatchSequence = batch.BatchSequence;
            LastRecordSequence = batch.LastRecordSequence;
            DroppedEvents = batch.DroppedEvents;
            TransportDroppedEvents = batch.DroppedEvents;
            TransportAbortedRecords = batch.AbortedRecords;
            HostDroppedBatches = batch.HostDroppedBatches;
            TouchOwnership();
            RefreshCheckpoint();

            Checkpoint.LastIndexUpdateUtc = NowUtc();
            if (!WriteIndex(&writeError))
            {
                MarkFailed(writeError);
                break;
            }

            if (!WriteManifest(&writeError))
            {
                MarkFailed(writeError);
                break;
            }

            written = true;
        }
        while (false);

        return written;
    }

    void Finalize(const knmon::KnMonCaptureResult& result, const NativeSessionInfo& session)
    {
        if (!Enabled)
        {
            return;
        }

        UpdateSession(session);
        TargetPath = result.TargetPath;
        TargetThreadId = result.TargetThreadId;
        Architecture = result.Architecture;
        AgentPath = result.AgentPath;
        AgentVersion = result.Handshake.AgentVersion;
        DroppedEvents = result.DroppedEvents;
        TransportDroppedEvents = result.TransportDroppedEvents;
        TransportAbortedRecords = result.TransportAbortedRecords;
        HostDroppedBatches = session.HostDroppedBatches;
        ResolverPointerCandidates = result.ResolverPointerCandidates;
        ResolverPointerUnsupported = result.ResolverPointerUnsupported;
        if (Chunks.empty())
        {
            LastRecordSequence = result.LastTransportSequence;
        }
        CapturedEventCount = result.CapturedEventsSeen;
        RetainedHistory = CaptureHistoryJson(result);
        CleanupState = result.CleanupStateJson;

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

        AuditEventCount = static_cast<std::uint64_t>(auditLines.size());
        AgentEventCount = static_cast<std::uint64_t>(agentLines.size());

        std::string writeError;
        if (!WriteTextFile(KnapmChildPath(Root, "audit.jsonl"), JoinJsonl(auditLines), &writeError))
        {
            MarkFailed(writeError);
        }

        if (!WriteTextFile(KnapmChildPath(Root, "agent-events.jsonl"), JoinJsonl(agentLines), &writeError))
        {
            MarkFailed(writeError);
        }

        Finalized = !Failed && (session.SessionState == "stopped" || result.Success || result.Operation == "operation_cancelled");
        FinalizedUtc = Finalized ? NowUtc() : "";
        WriterState = Failed ? "failed" : (Finalized ? "finalized" : "partial");
        if (Finalized)
        {
            SetRecoveryState("none", "finalized", "none", false);
        }
        else if (Failed)
        {
            SetRecoveryState("malformed", "writer_failed", "manual_inspection", false);
        }
        else
        {
            SetRecoveryState("owned", "owner_alive", "wait", false);
        }
        TouchOwnership();
        RefreshCheckpoint();

        Checkpoint.LastIndexUpdateUtc = NowUtc();
        if (!WriteIndex(&writeError))
        {
            MarkFailed(writeError);
        }

        if (!WriteManifest(&writeError))
        {
            MarkFailed(writeError);
        }
    }

    void MarkFailed(const std::string& error)
    {
        if (!Failed)
        {
            Error = error;
        }
        Failed = true;
        Finalized = false;
        FinalizedUtc.clear();
        WriterState = "failed";
        Session.SessionState = "failed";
        Session.LastError = Error;
        SetRecoveryState("malformed", "writer_failed", "manual_inspection", false);
        TouchOwnership();
        Checkpoint.IndexConsistent = false;
    }

    bool WriteIndex(std::string* error) const
    {
        std::ostringstream stream;
        stream << "{";
        stream << "\"schemaVersion\":\"0.1.0\",";
        stream << "\"format\":\"knapm-index\",";
        stream << "\"sessionId\":" << Q(SessionId) << ",";
        stream << "\"operationId\":" << Q(OperationId) << ",";
        stream << "\"chunks\":[";
        for (std::size_t index = 0; index < Chunks.size(); ++index)
        {
            if (index != 0)
            {
                stream << ",";
            }
            stream << ToJson(Chunks[index]);
        }
        stream << "]";
        stream << "}";
        return WriteTextFile(KnapmChildPath(Root, "index.json"), stream.str() + "\n", error);
    }

    bool WriteManifest(std::string* error)
    {
        Checkpoint.LastManifestUpdateUtc = NowUtc();
        RefreshCheckpoint();

        std::ostringstream stream;
        stream << "{";
        stream << "\"schemaVersion\":\"0.1.0\",";
        stream << "\"format\":\"knapm\",";
        stream << "\"formatVersion\":\"1\",";
        stream << "\"sessionId\":" << Q(SessionId) << ",";
        stream << "\"operationId\":" << Q(OperationId) << ",";
        stream << "\"createdUtc\":" << Q(CreatedUtc) << ",";
        stream << "\"updatedUtc\":" << Q(UpdatedUtc) << ",";
        stream << "\"finalizedUtc\":" << Q(FinalizedUtc) << ",";
        stream << "\"finalized\":" << (Finalized ? "true" : "false") << ",";
        stream << "\"source\":\"knmon-native-helper attach-session\",";
        stream << "\"backendMode\":\"native-capture\",";
        stream << "\"captureMode\":\"bounded-native-attach\",";
        stream << "\"injectionMethod\":\"remote LoadLibraryW\",";
        stream << "\"target\":{";
        stream << "\"path\":" << Q(TargetPath) << ",";
        stream << "\"pid\":" << Session.TargetProcessId << ",";
        stream << "\"tid\":" << TargetThreadId << ",";
        stream << "\"architecture\":" << Q(Architecture);
        stream << "},";
        stream << "\"agent\":{";
        stream << "\"path\":" << Q(AgentPath) << ",";
        stream << "\"architecture\":" << Q(Architecture) << ",";
        stream << "\"version\":" << Q(AgentVersion);
        stream << "},";
        stream << "\"session\":" << ToJson(Session) << ",";
        stream << "\"retainedHistory\":" << RetainedHistory << ",";
        stream << "\"cleanupState\":" << CleanupState << ",";
        stream << "\"eventCounts\":{";
        stream << "\"audit\":" << AuditEventCount << ",";
        stream << "\"agentEvents\":" << AgentEventCount << ",";
        stream << "\"traceEvents\":" << TraceEventCount << ",";
        stream << "\"capturedEvents\":" << CapturedEventCount << ",";
        stream << "\"resolverPointerCandidates\":" << ResolverPointerCandidates << ",";
        stream << "\"resolverPointerUnsupported\":" << ResolverPointerUnsupported;
        stream << "},";
        stream << "\"droppedEvents\":" << DroppedEvents << ",";
        stream << "\"transportDroppedEvents\":" << TransportDroppedEvents << ",";
        stream << "\"transportAbortedRecords\":" << TransportAbortedRecords << ",";
        stream << "\"hostDroppedBatches\":" << HostDroppedBatches << ",";
        stream << "\"chunkCount\":" << Chunks.size() << ",";
        stream << "\"lastBatchSequence\":" << LastBatchSequence << ",";
        stream << "\"lastRecordSequence\":" << LastRecordSequence << ",";
        stream << "\"compression\":" << Q(Compression) << ",";
        stream << "\"compressionAlgorithms\":[";
        if (!Chunks.empty())
        {
            stream << Q(Compression);
        }
        stream << "],";
        stream << "\"storedBytes\":" << StoredBytes << ",";
        stream << "\"uncompressedBytes\":" << UncompressedBytes << ",";
        stream << "\"writerState\":" << Q(WriterState) << ",";
        stream << "\"writerError\":" << Q(Error) << ",";
        stream << "\"owner\":" << ToJson(Owner) << ",";
        stream << "\"checkpoint\":" << ToJson(Checkpoint) << ",";
        stream << "\"recovery\":" << ToJson(Recovery) << ",";
        stream << "\"files\":{";
        stream << "\"audit\":\"audit.jsonl\",";
        stream << "\"agentEvents\":\"agent-events.jsonl\",";
        stream << "\"index\":\"index.json\",";
        stream << "\"chunkDirectory\":\"chunks\"";
        stream << "}";
        stream << "}";
        return WriteTextFile(KnapmChildPath(Root, "manifest.json"), stream.str() + "\n", error);
    }
};

bool IsProcessAlive(std::uint32_t processId);

KnapmChunkInfo KnapmChunkFromJson(const JsonDocument& json)
{
    KnapmChunkInfo chunk;
    chunk.ChunkSequence = json.UInt64("chunkSequence", true);
    chunk.BatchSequence = json.UInt64("batchSequence", true);
    chunk.File = json.String("file", true);
    chunk.Compression = ExtractJsonString(json, "compression");
    chunk.EventCount = json.UInt64("eventCount", true);
    chunk.FirstRecordSequence = json.UInt64("firstRecordSequence", true);
    chunk.LastRecordSequence = json.UInt64("lastRecordSequence", true);
    chunk.FirstEventId = json.UInt64("firstEventId", true);
    chunk.LastEventId = json.UInt64("lastEventId", true);
    chunk.ByteLength = json.UInt64("byteLength", true);
    chunk.Sha256 = json.String("sha256", true);
    chunk.UncompressedByteLength = ExtractJsonUInt64(json, "uncompressedByteLength");
    chunk.UncompressedSha256 = ExtractJsonString(json, "uncompressedSha256");
    if (chunk.LastRecordSequence < chunk.FirstRecordSequence || chunk.LastEventId < chunk.FirstEventId ||
        (chunk.EventCount != 0 && (chunk.EventCount - 1 > chunk.LastRecordSequence - chunk.FirstRecordSequence ||
            chunk.EventCount - 1 > chunk.LastEventId - chunk.FirstEventId)))
    {
        throw JsonInputError("Chunk sequence range cannot contain its declared events.");
    }
    return chunk;
}

KnapmOwnerInfo KnapmOwnerFromJson(const JsonDocument& json)
{
    KnapmOwnerInfo owner;
    owner.OwnerKind = ExtractJsonString(json, "ownerKind");
    owner.HostProcessId = ExtractJsonUInt32(json, "hostProcessId");
    owner.HelperProcessId = ExtractJsonUInt32(json, "helperProcessId");
    owner.WriterProcessId = ExtractJsonUInt32(json, "writerProcessId");
    owner.WriterInstanceId = ExtractJsonString(json, "writerInstanceId");
    owner.WriterGeneration = ExtractJsonUInt64(json, "writerGeneration");
    owner.StartedUtc = ExtractJsonString(json, "startedUtc");
    owner.UpdatedUtc = ExtractJsonString(json, "updatedUtc");
    owner.HeartbeatUtc = ExtractJsonString(json, "heartbeatUtc");
    owner.LeaseTimeoutMs = ExtractJsonUInt64(json, "leaseTimeoutMs");
    owner.LeaseExpiresUtc = ExtractJsonString(json, "leaseExpiresUtc");
    owner.DaemonProcessId = ExtractJsonUInt32(json, "daemonProcessId");
    owner.DaemonInstanceId = ExtractJsonString(json, "daemonInstanceId");
    owner.DaemonStartedUtc = ExtractJsonString(json, "daemonStartedUtc");
    owner.DaemonHeartbeatUtc = ExtractJsonString(json, "daemonHeartbeatUtc");
    owner.ControlEndpoint = ExtractJsonString(json, "controlEndpoint");
    return owner;
}

KnapmCheckpointInfo KnapmCheckpointFromJson(const JsonDocument& json)
{
    KnapmCheckpointInfo checkpoint;
    checkpoint.LastCommittedChunkSequence = ExtractJsonUInt64(json, "lastCommittedChunkSequence");
    checkpoint.LastCommittedBatchSequence = ExtractJsonUInt64(json, "lastCommittedBatchSequence");
    checkpoint.LastCommittedRecordSequence = ExtractJsonUInt64(json, "lastCommittedRecordSequence");
    checkpoint.LastCommittedEventId = ExtractJsonUInt64(json, "lastCommittedEventId");
    checkpoint.LastManifestUpdateUtc = ExtractJsonString(json, "lastManifestUpdateUtc");
    checkpoint.LastIndexUpdateUtc = ExtractJsonString(json, "lastIndexUpdateUtc");
    checkpoint.IndexConsistent = ExtractJsonBool(json, "indexConsistent");
    return checkpoint;
}

KnapmRecoveryInfo KnapmRecoveryFromJson(const JsonDocument& json)
{
    KnapmRecoveryInfo recovery;
    recovery.State = ExtractJsonString(json, "state");
    recovery.Reason = ExtractJsonString(json, "reason");
    recovery.Action = ExtractJsonString(json, "action");
    recovery.ClassifiedUtc = ExtractJsonString(json, "classifiedUtc");
    recovery.OwnerAlive = ExtractJsonBool(json, "ownerAlive");
    recovery.HelperAlive = ExtractJsonBool(json, "helperAlive");
    recovery.WriterAlive = ExtractJsonBool(json, "writerAlive");
    recovery.TargetAlive = ExtractJsonBool(json, "targetAlive");
    recovery.LeaseExpired = ExtractJsonBool(json, "leaseExpired");
    recovery.RestartEligible = ExtractJsonBool(json, "restartEligible");
    return recovery;
}

bool ReadKnapmChunkDecoded(
    const std::filesystem::path& sessionPath,
    const KnapmChunkInfo& chunk,
    std::string* decodedText,
    std::string* error)
{
    bool read = false;

    do
    {
        if (decodedText == nullptr)
        {
            if (error != nullptr)
            {
                *error = "decoded output is null.";
            }
            break;
        }

        decodedText->clear();
        std::string storedBytes;
        std::string readError;
        if (!ReadTextFile(KnapmChildPath(sessionPath, chunk.File), &storedBytes, &readError))
        {
            if (error != nullptr)
            {
                *error = readError;
            }
            break;
        }

        if (chunk.ByteLength != storedBytes.size())
        {
            if (error != nullptr)
            {
                *error = "chunk byteLength does not match file size.";
            }
            break;
        }

        const std::string storedHash = Sha256Hex(storedBytes);
        if (storedHash.empty() || storedHash != chunk.Sha256)
        {
            if (error != nullptr)
            {
                *error = "chunk stored sha256 does not match file content.";
            }
            break;
        }

        const std::string compression = NormalizeKnapmCompression(chunk.Compression);
        if (compression == "none")
        {
            *decodedText = storedBytes;
        }
        else if (compression == "zstd")
        {
            if (chunk.UncompressedByteLength == 0 || chunk.UncompressedByteLength > knmon::SessionChunkByteLimit || chunk.UncompressedSha256.empty())
            {
                if (error != nullptr)
                {
                    *error = "zstd chunk is missing uncompressed integrity fields.";
                }
                break;
            }

            std::string decodeError;
            if (!knmon::DecodeSessionZstd(storedBytes, static_cast<std::size_t>(chunk.UncompressedByteLength), decodedText, &decodeError))
            {
                if (error != nullptr)
                {
                    *error = decodeError.empty() ? "corrupt_zstd_frame" : decodeError;
                }
                break;
            }
        }
        else
        {
            if (error != nullptr)
            {
                *error = "unsupported_compression";
            }
            break;
        }

        if (chunk.UncompressedByteLength != 0 && chunk.UncompressedByteLength != decodedText->size())
        {
            if (error != nullptr)
            {
                *error = "chunk uncompressedByteLength does not match decoded size.";
            }
            break;
        }

        if (!chunk.UncompressedSha256.empty())
        {
            const std::string decodedHash = Sha256Hex(*decodedText);
            if (decodedHash.empty() || decodedHash != chunk.UncompressedSha256)
            {
                if (error != nullptr)
                {
                    *error = "chunk uncompressedSha256 does not match decoded content.";
                }
                break;
            }
        }

        read = true;
    }
    while (false);

    return read;
}

void SetKnapmSessionRecovery(
    SessionInfo& session,
    const std::string& state,
    const std::string& reason,
    const std::string& action,
    bool ownerAlive,
    bool helperAlive,
    bool writerAlive,
    bool targetAlive,
    bool leaseExpired,
    bool restartEligible)
{
    session.RecoveryState = state;
    session.RecoveryReason = reason;
    session.RecoveryAction = action;
    session.OwnerAlive = ownerAlive;
    session.HelperAlive = helperAlive;
    session.WriterAlive = writerAlive;
    session.TargetAlive = targetAlive;
    session.LeaseExpired = leaseExpired;
    session.RestartEligible = restartEligible;
    if (state == "stale" || state == "recovery_required" || state == "malformed")
    {
        session.WriterState = state;
    }
}

void SetKnapmMalformedRecovery(SessionInfo& session, const std::string& reason)
{
    SetKnapmSessionRecovery(session, "malformed", reason, "manual_inspection", false, false, false, false, false, false);
}

void ValidateManifestTypes(const JsonDocument& manifest, bool knapm)
{
    const auto cleanup = manifest.ObjectOrNull("cleanupState");
    if (!cleanup.empty())
    {
        cleanup.String("source", true);
        cleanup.String("operationId", true);
        cleanup.String("lifecycle", true);
        cleanup.Bool("active", true);
        cleanup.Bool("busy", true);
        for (const auto* key : { "hooksEnabled", "installedHooks", "restoredHooks", "failedHooks" })
        {
            cleanup.UInt32(key, true);
        }
        cleanup.UInt64("droppedEvents", true);
    }
    for (const auto* key : {"schemaVersion", "sessionId", "operationId", "createdUtc", "updatedUtc", "finalizedUtc",
        "format", "formatVersion", "source", "backendMode", "captureMode", "injectionMethod", "writerState", "writerError", "compression", "shutdownEvidence"})
    {
        manifest.String(key);
    }
    manifest.Bool("finalized", knapm);
    for (const auto* key : {"droppedEvents", "transportDroppedEvents", "transportAbortedRecords", "hostDroppedBatches",
        "chunkCount", "lastBatchSequence", "lastRecordSequence", "storedBytes", "uncompressedBytes"})
    {
        manifest.UInt64(key);
    }
    const auto target = manifest.Object("target", true);
    target.UInt32("pid", true);
    target.UInt32("tid");
    target.String("path");
    target.String("architecture", true);
    const auto agent = manifest.Object("agent", true);
    agent.String("path");
    agent.String("architecture", true);
    agent.String("version");
    if (manifest.Has("retainedHistory"))
    {
        const auto history = manifest.Object("retainedHistory", true);
        if (!history.empty())
        {
            history.Bool("bounded");
            for (const auto* key : { "capturedEventsTotal", "omittedCapturedEvents", "omittedAgentMessages", "omittedAuditEvents",
                "omittedResolverPointerCandidates", "omittedResolverPointerUnsupported" })
            {
                history.UInt64(key);
            }
        }
    }
    const auto counts = manifest.Object("eventCounts", true);
    for (const auto* key : {"audit", "agentEvents", "traceEvents", "capturedEvents", "resolverPointerCandidates", "resolverPointerUnsupported"})
    {
        counts.UInt64(key);
    }
    const auto files = manifest.Object("files", true);
    for (const auto* key : {"audit", "agentEvents", "traceEvents", "index", "chunkDirectory"})
    {
        files.String(key);
    }
    const auto session = manifest.Object("session");
    for (const auto* key : {"schemaVersion", "sessionId", "operationId", "sessionKind", "sessionState", "startedUtc",
        "updatedUtc", "stoppedUtc", "cancellationEventName", "staleReason", "recoveryAction", "shutdownEvidence", "lastError",
        "daemonInstanceId", "daemonStartedUtc", "daemonHeartbeatUtc", "daemonControlEndpoint", "knapmPath", "recoveryState", "recoveryReason", "pruneReason"})
    {
        session.String(key);
    }
    for (const auto* key : {"ownerProcessId", "helperProcessId", "targetProcessId", "daemonProcessId", "durationMs"})
    {
        session.UInt32(key);
    }
    for (const auto* key : {"lastTransportSequence", "recordsStreamed", "transportDroppedEvents", "transportAbortedRecords", "hostDroppedBatches", "elapsedMs"})
    {
        session.UInt64(key);
    }
    for (const auto* key : {"stopRequested", "agentCleanupAttempted", "agentCleanupSucceeded", "daemonAlive", "sessionProcessAlive",
        "targetAlive", "targetExitObserved", "knapmExists", "knapmValid", "pruneEligible"})
    {
        session.Bool(key);
    }
    if (manifest.Has("owner"))
    {
        KnapmOwnerFromJson(manifest.Object("owner"));
    }
    if (manifest.Has("checkpoint"))
    {
        KnapmCheckpointFromJson(manifest.Object("checkpoint"));
    }
    if (manifest.Has("recovery"))
    {
        KnapmRecoveryFromJson(manifest.Object("recovery"));
    }
}

bool HasProcessExitEvidence(const JsonDocument& manifest)
{
    return manifest.String("shutdownEvidence") == "released_by_process_exit" ||
        manifest.Object("session").String("shutdownEvidence") == "released_by_process_exit";
}

bool HasQueriedCleanupEvidence(const JsonDocument& manifest)
{
    const auto state = manifest.ObjectOrNull("cleanupState");
    return !state.empty() && state.String("source") == "controller_query" &&
        !manifest.String("operationId").empty() && state.String("operationId") == manifest.String("operationId") &&
        state.String("lifecycle") == "disabled" && !state.Bool("active", true) && !state.Bool("busy", true) &&
        state.UInt32("hooksEnabled", true) == 0 && state.UInt32("failedHooks", true) == 0 &&
        state.UInt32("restoredHooks", true) >= state.UInt32("installedHooks", true);
}

void ClassifyKnapmSession(SessionInfo& session, const JsonDocument& manifest)
{
    const JsonDocument sessionObject = ExtractJsonObject(manifest, "session");
    const JsonDocument targetObject = ExtractJsonObject(manifest, "target");
    const JsonDocument ownerObject = ExtractJsonObject(manifest, "owner");
    const JsonDocument checkpointObject = ExtractJsonObject(manifest, "checkpoint");
    const JsonDocument recoveryObject = ExtractJsonObject(manifest, "recovery");
    const std::uint32_t ownerProcessId = ExtractJsonUInt32(sessionObject, "ownerProcessId");
    const std::uint32_t helperProcessId = ExtractJsonUInt32(sessionObject, "helperProcessId");
    std::uint32_t targetProcessId = ExtractJsonUInt32(sessionObject, "targetProcessId");
    if (targetProcessId == 0)
    {
        targetProcessId = ExtractJsonUInt32(targetObject, "pid");
    }

    const std::string state = ExtractJsonString(sessionObject, "sessionState");

    if (!manifest.Has("owner"))
    {
        if (session.Finalized)
        {
            SetKnapmSessionRecovery(session, "none", "finalized", "none", false, false, false, false, false, false);
            return;
        }

        const bool legacyOwnerAlive = IsProcessAlive(ownerProcessId);
        const bool legacyHelperAlive = IsProcessAlive(helperProcessId);
        const bool legacyTargetAlive = IsProcessAlive(targetProcessId);
        if (state == "stopped" || state == "failed" || state == "stale" || state == "recovery_required")
        {
            SetKnapmSessionRecovery(session, "legacy", "terminal_session_state", "none", legacyOwnerAlive, legacyHelperAlive, false, legacyTargetAlive, false, false);
            return;
        }

        if (targetProcessId != 0 && !legacyTargetAlive)
        {
            SetKnapmSessionRecovery(session, "stale", "legacy_target_exited", "replay_only", legacyOwnerAlive, legacyHelperAlive, false, false, false, false);
            return;
        }

        if (targetProcessId != 0 && legacyTargetAlive && ownerProcessId != 0 && helperProcessId != 0 && !legacyOwnerAlive && !legacyHelperAlive)
        {
            SetKnapmSessionRecovery(session, "recovery_required", "legacy_owner_dead_target_alive", "manual_inspection", false, false, false, true, false, false);
            return;
        }

        SetKnapmSessionRecovery(session, "legacy", "metadata_incomplete", "manual_inspection", legacyOwnerAlive, legacyHelperAlive, false, legacyTargetAlive, false, false);
        return;
    }

    if (checkpointObject.empty() || recoveryObject.empty())
    {
        session.ValidationErrors.push_back("manifest owner metadata requires checkpoint and recovery sections.");
        SetKnapmMalformedRecovery(session, "metadata_incomplete");
        return;
    }

    const KnapmOwnerInfo owner = KnapmOwnerFromJson(ownerObject);
    const KnapmCheckpointInfo checkpoint = KnapmCheckpointFromJson(checkpointObject);
    const KnapmRecoveryInfo recovery = KnapmRecoveryFromJson(recoveryObject);

    ULONGLONG parsedLease = 0;
    const bool supportedOwnerKind = owner.OwnerKind == "bounded-helper" || owner.OwnerKind == "persistent-daemon";
    if (
        !supportedOwnerKind ||
        owner.WriterInstanceId.empty() ||
        owner.HostProcessId == 0 ||
        owner.HelperProcessId == 0 ||
        owner.WriterProcessId == 0 ||
        owner.LeaseTimeoutMs == 0 ||
        owner.StartedUtc.empty() ||
        owner.UpdatedUtc.empty() ||
        owner.HeartbeatUtc.empty() ||
        owner.LeaseExpiresUtc.empty() ||
        !ParseUtcFileTime(owner.LeaseExpiresUtc, &parsedLease))
    {
        session.ValidationErrors.push_back("manifest owner metadata is incomplete or has an invalid lease.");
        SetKnapmMalformedRecovery(session, "metadata_incomplete");
        return;
    }

    if (
        owner.OwnerKind == "persistent-daemon" &&
        (
            owner.DaemonProcessId == 0 ||
            owner.DaemonInstanceId.empty() ||
            owner.DaemonStartedUtc.empty() ||
            owner.DaemonHeartbeatUtc.empty() ||
            owner.ControlEndpoint.empty()))
    {
        session.ValidationErrors.push_back("manifest persistent daemon owner metadata is incomplete.");
        SetKnapmMalformedRecovery(session, "metadata_incomplete");
        return;
    }

    if (checkpoint.LastCommittedChunkSequence != session.ChunkCount)
    {
        session.ValidationErrors.push_back("manifest checkpoint chunk sequence does not match chunkCount.");
        SetKnapmMalformedRecovery(session, "checkpoint_mismatch");
        return;
    }

    if (!checkpoint.IndexConsistent)
    {
        session.ValidationErrors.push_back("manifest checkpoint reports an inconsistent index.");
        SetKnapmMalformedRecovery(session, "index_corrupt");
        return;
    }

    if (recovery.State.empty() || recovery.Reason.empty() || recovery.Action.empty())
    {
        session.ValidationErrors.push_back("manifest recovery metadata is incomplete.");
        SetKnapmMalformedRecovery(session, "metadata_incomplete");
        return;
    }

    if (session.Finalized)
    {
        SetKnapmSessionRecovery(session, "none", "finalized", "none", false, false, false, false, false, false);
        return;
    }

    if (state == "stopped" || state == "failed" || state == "stale" || state == "recovery_required")
    {
        SetKnapmSessionRecovery(session, recovery.State, "terminal_session_state", recovery.Action, recovery.OwnerAlive, recovery.HelperAlive, recovery.WriterAlive, recovery.TargetAlive, recovery.LeaseExpired, recovery.RestartEligible);
        return;
    }

    const bool ownerAlive = IsProcessAlive(owner.HostProcessId);
    const bool helperAlive = IsProcessAlive(owner.HelperProcessId);
    const bool writerAlive = IsProcessAlive(owner.WriterProcessId);
    const bool targetAlive = IsProcessAlive(targetProcessId);
    const bool leaseExpired = IsUtcExpired(owner.LeaseExpiresUtc);

    if (targetProcessId != 0 && !targetAlive)
    {
        SetKnapmSessionRecovery(session, "stale", "target_exited", "replay_only", ownerAlive, helperAlive, writerAlive, false, leaseExpired, false);
        return;
    }

    if (leaseExpired)
    {
        SetKnapmSessionRecovery(session, "recovery_required", "lease_expired", "recover_writer", ownerAlive, helperAlive, writerAlive, targetAlive, true, targetAlive);
        return;
    }

    if (targetProcessId != 0 && targetAlive && (!ownerAlive || !helperAlive || !writerAlive))
    {
        SetKnapmSessionRecovery(session, "recovery_required", "owner_dead_target_alive", "recover_writer", ownerAlive, helperAlive, writerAlive, true, false, true);
        return;
    }

    SetKnapmSessionRecovery(session, "owned", "owner_alive", "wait", ownerAlive, helperAlive, writerAlive, targetAlive, false, false);
}

SessionInfo ValidateKnapmSession(const std::filesystem::path& sessionPath)
{
    SessionInfo session;
    session.Format = "knapm";
    session.SessionPath = PathToUtf8(sessionPath);

    try
    {
        do
        {
            const std::filesystem::path manifestPath = KnapmChildPath(sessionPath, "manifest.json");
            const std::filesystem::path indexPath = KnapmChildPath(sessionPath, "index.json");
            const std::filesystem::path auditPath = KnapmChildPath(sessionPath, "audit.jsonl");
            const std::filesystem::path agentPath = KnapmChildPath(sessionPath, "agent-events.jsonl");

            JsonDocument manifest;
            std::string readError;
            if (!ReadTextFile(manifestPath, &manifest, &readError))
            {
                session.ValidationErrors.push_back(readError);
                break;
            }

            ValidateManifestTypes(manifest, true);
            session.SessionId = ExtractJsonString(manifest, "sessionId");
            session.CreatedUtc = ExtractJsonString(manifest, "createdUtc");
            session.Finalized = manifest.Bool("finalized", true);
            session.DroppedEvents = ExtractJsonUInt64(manifest, "droppedEvents");
            session.TransportDroppedEvents = ExtractJsonUInt64(manifest, "transportDroppedEvents");
            session.TransportAbortedRecords = ExtractJsonUInt64(manifest, "transportAbortedRecords");
            session.HostDroppedBatches = ExtractJsonUInt64(manifest, "hostDroppedBatches");
            session.ChunkCount = ExtractJsonUInt64(manifest, "chunkCount");
            session.LastBatchSequence = ExtractJsonUInt64(manifest, "lastBatchSequence");
            session.LastRecordSequence = ExtractJsonUInt64(manifest, "lastRecordSequence");
            session.WriterState = ExtractJsonString(manifest, "writerState");
            session.CompressionSummary = ExtractJsonString(manifest, "compression");
            session.StoredBytes = ExtractJsonUInt64(manifest, "storedBytes");
            session.UncompressedBytes = ExtractJsonUInt64(manifest, "uncompressedBytes");
            const std::uint64_t manifestLastBatchSequence = session.LastBatchSequence;
            const std::uint64_t manifestLastRecordSequence = session.LastRecordSequence;

            const std::string operationId = ExtractJsonString(manifest, "operationId");
            const std::string finalizedUtc = ExtractJsonString(manifest, "finalizedUtc");
            const JsonDocument targetManifest = ExtractJsonObject(manifest, "target");
            const JsonDocument agentManifest = ExtractJsonObject(manifest, "agent");
            const JsonDocument eventCounts = ExtractJsonObject(manifest, "eventCounts");
            const JsonDocument sessionObject = ExtractJsonObject(manifest, "session");

            if (ExtractJsonString(manifest, "schemaVersion") != "0.1.0")
            {
                session.ValidationErrors.push_back("manifest schemaVersion is missing or unsupported.");
            }

            if (ExtractJsonString(manifest, "format") != "knapm")
            {
                session.ValidationErrors.push_back("manifest format must be knapm.");
            }

            if (ExtractJsonString(manifest, "formatVersion").empty())
            {
                session.ValidationErrors.push_back("manifest formatVersion is missing.");
            }

            if (session.SessionId.empty())
            {
                session.ValidationErrors.push_back("manifest sessionId is missing.");
            }

            if (operationId.empty())
            {
                session.ValidationErrors.push_back("manifest operationId is missing.");
            }

            if (session.CreatedUtc.empty() || ExtractJsonString(manifest, "updatedUtc").empty())
            {
                session.ValidationErrors.push_back("manifest timestamps are missing.");
            }

            if (session.Finalized && finalizedUtc.empty())
            {
                session.ValidationErrors.push_back("finalized manifest must include finalizedUtc.");
            }

            if (ExtractJsonString(manifest, "source") != "knmon-native-helper attach-session")
            {
                session.ValidationErrors.push_back("manifest source must be knmon-native-helper attach-session.");
            }

            if (ExtractJsonString(manifest, "backendMode") != "native-capture")
            {
                session.ValidationErrors.push_back("manifest backendMode must be native-capture.");
            }

            if (ExtractJsonString(manifest, "captureMode") != "bounded-native-attach")
            {
                session.ValidationErrors.push_back("manifest captureMode must be bounded-native-attach.");
            }

            if (ExtractJsonString(manifest, "injectionMethod") != "remote LoadLibraryW")
            {
                session.ValidationErrors.push_back("manifest injectionMethod must be remote LoadLibraryW.");
            }

            const std::string targetArchitecture = ExtractJsonString(targetManifest, "architecture");
            const std::string agentArchitecture = ExtractJsonString(agentManifest, "architecture");
            if (!IsSupportedArchitecture(targetArchitecture))
            {
                session.ValidationErrors.push_back("manifest target architecture is missing or unsupported.");
            }

            if (!IsSupportedArchitecture(agentArchitecture))
            {
                session.ValidationErrors.push_back("manifest agent architecture is missing or unsupported.");
            }

            if (IsSupportedArchitecture(targetArchitecture) && IsSupportedArchitecture(agentArchitecture) && targetArchitecture != agentArchitecture)
            {
                session.ValidationErrors.push_back("manifest target and agent architecture must match.");
            }

            if (session.Finalized && ExtractJsonString(agentManifest, "version").empty())
            {
                session.ValidationErrors.push_back("finalized manifest agent version is missing.");
            }

            session.AuditEventCount = ExtractJsonUInt64(eventCounts, "audit");
            session.AgentEventCount = ExtractJsonUInt64(eventCounts, "agentEvents");
            session.TraceEventCount = ExtractJsonUInt64(eventCounts, "traceEvents");
            session.ResolverPointerCandidates = ExtractJsonUInt64(eventCounts, "resolverPointerCandidates");
            session.ResolverPointerUnsupported = ExtractJsonUInt64(eventCounts, "resolverPointerUnsupported");
            const std::uint64_t capturedEventCount = ExtractJsonUInt64(eventCounts, "capturedEvents");
            const std::uint64_t sessionRecordsStreamed = ExtractJsonUInt64(sessionObject, "recordsStreamed");
            const std::uint64_t sessionLastTransport = ExtractJsonUInt64(sessionObject, "lastTransportSequence");
            const std::uint64_t sessionTransportDrops = ExtractJsonUInt64(sessionObject, "transportDroppedEvents");
            const std::uint64_t sessionHostDrops = ExtractJsonUInt64(sessionObject, "hostDroppedBatches");

            std::string auditText;
            if (!ReadTextFile(auditPath, &auditText, &readError))
            {
                session.ValidationErrors.push_back(readError);
            }
            else if (ParseJsonl(auditText).size() != session.AuditEventCount)
            {
                session.ValidationErrors.push_back("audit.jsonl count does not match manifest eventCounts.audit.");
            }

            std::string agentText;
            if (!ReadTextFile(agentPath, &agentText, &readError))
            {
                session.ValidationErrors.push_back(readError);
            }
            else
            {
                const auto agentLines = ParseAgentJsonl(agentText);
                std::uint64_t resolverPointerCandidates = 0;
                std::uint64_t resolverPointerUnsupported = 0;
                if (agentLines.size() != session.AgentEventCount)
                {
                    session.ValidationErrors.push_back("agent-events.jsonl count does not match manifest eventCounts.agentEvents.");
                }

                for (const auto& line : agentLines)
                {
                    if (
                        (ExtractJsonString(line, "messageType") == "resolver_pointer_candidate") ||
                        (ExtractJsonString(line, "messageType") == "resolver_pointer_instrumented"))
                    {
                        ++resolverPointerCandidates;
                    }
                    else if ((ExtractJsonString(line, "messageType") == "resolver_pointer_unsupported"))
                    {
                        ++resolverPointerUnsupported;
                    }
                }

                if (eventCounts.Has("resolverPointerCandidates"))
                {
                    if (session.ResolverPointerCandidates < resolverPointerCandidates ||
                        session.ResolverPointerCandidates - resolverPointerCandidates != manifest.Object("retainedHistory").UInt64("omittedResolverPointerCandidates"))
                    {
                        session.ValidationErrors.push_back("agent-events.jsonl resolver_pointer_candidate count does not match manifest eventCounts.resolverPointerCandidates.");
                    }
                }
                else
                {
                    session.ResolverPointerCandidates = resolverPointerCandidates;
                }

                if (eventCounts.Has("resolverPointerUnsupported"))
                {
                    if (session.ResolverPointerUnsupported < resolverPointerUnsupported ||
                        session.ResolverPointerUnsupported - resolverPointerUnsupported != manifest.Object("retainedHistory").UInt64("omittedResolverPointerUnsupported"))
                    {
                        session.ValidationErrors.push_back("agent-events.jsonl resolver_pointer_unsupported count does not match manifest eventCounts.resolverPointerUnsupported.");
                    }
                }
                else
                {
                    session.ResolverPointerUnsupported = resolverPointerUnsupported;
                }

                if (session.Finalized)
                {
                    bool hasHello = false;
                    bool hasDropped = false;
                    bool hasShutdown = false;
                    for (const auto& line : agentLines)
                    {
                        hasHello = hasHello || (ExtractJsonString(line, "messageType") == "agent_hello");
                        hasDropped = hasDropped || (ExtractJsonString(line, "messageType") == "dropped_events");
                        if ((ExtractJsonString(line, "messageType") == "agent_shutdown"))
                        {
                            hasShutdown = true;
                            if (ExtractJsonString(line, "reason").empty())
                            {
                                session.ValidationErrors.push_back("finalized agent_shutdown reason is missing.");
                            }

                            if (!line.Has("installedHooks") || !line.Has("restoredHooks") || !line.Has("failedHooks"))
                            {
                                session.ValidationErrors.push_back("finalized agent_shutdown hook lifecycle counts are missing.");
                            }

                            const std::uint64_t installedHooks = ExtractJsonUInt64(line, "installedHooks");
                            const std::uint64_t restoredHooks = ExtractJsonUInt64(line, "restoredHooks");
                            const std::uint64_t failedHooks = ExtractJsonUInt64(line, "failedHooks");
                            if (restoredHooks < installedHooks || failedHooks != 0)
                            {
                                session.ValidationErrors.push_back("finalized agent_shutdown reports unrestored or failed hooks.");
                            }
                        }
                    }

                    if (!hasHello)
                    {
                        session.ValidationErrors.push_back("finalized agent-events.jsonl does not contain agent_hello.");
                    }

                    if (!hasDropped && !HasProcessExitEvidence(manifest))
                    {
                        session.ValidationErrors.push_back("finalized agent-events.jsonl does not contain dropped_events.");
                    }

                    if (!hasShutdown && !HasProcessExitEvidence(manifest) && !HasQueriedCleanupEvidence(manifest))
                    {
                        session.ValidationErrors.push_back("finalized agent-events.jsonl does not contain agent_shutdown.");
                    }
                }
            }

            JsonDocument indexText;
            if (!ReadTextFile(indexPath, &indexText, &readError))
            {
                session.ValidationErrors.push_back(readError);
                break;
            }

            if (ExtractJsonString(indexText, "format") != "knapm-index")
            {
                session.ValidationErrors.push_back("index format must be knapm-index.");
            }

            if (ExtractJsonString(indexText, "sessionId") != session.SessionId)
            {
                session.ValidationErrors.push_back("index sessionId must match manifest sessionId.");
            }

            if (ExtractJsonString(indexText, "operationId") != operationId)
            {
                session.ValidationErrors.push_back("index operationId must match manifest operationId.");
            }

            session.ReplayIndexSha256 = Sha256Hex(indexText.Text());
            const auto chunkObjects = SplitJsonObjectArray(indexText.Array("chunks", true));
            const std::uint64_t indexChunkCount = static_cast<std::uint64_t>(chunkObjects.size());
            if (indexChunkCount != session.ChunkCount)
            {
                session.ValidationErrors.push_back("index chunk count does not match manifest chunkCount.");
            }

            std::uint64_t totalTraceEvents = 0;
            std::uint64_t previousTraceEventId = 0;
            std::uint64_t previousBatchSequence = 0;
            std::uint64_t previousRecordSequence = 0;
            bool hasPreviousRecordSequence = false;
            std::uint64_t expectedChunkSequence = 1;
            std::uint64_t indexedLastBatchSequence = 0;
            std::uint64_t indexedLastRecordSequence = 0;
            std::uint64_t indexedStoredBytes = 0;
            std::uint64_t indexedUncompressedBytes = 0;
            std::string indexedCompression;
            for (const auto& chunkJson : chunkObjects)
            {
                const std::size_t chunkErrorStart = session.ValidationErrors.size();
                const KnapmChunkInfo chunk = KnapmChunkFromJson(chunkJson);
                const std::string chunkCompression = NormalizeKnapmCompression(chunk.Compression);
                if (chunk.ChunkSequence != expectedChunkSequence)
                {
                    session.ValidationErrors.push_back("index chunkSequence is not contiguous.");
                    break;
                }

                if (chunk.BatchSequence == 0)
                {
                    session.ValidationErrors.push_back("index batchSequence is missing.");
                    break;
                }

                if (previousBatchSequence != 0 && chunk.BatchSequence != previousBatchSequence + 1)
                {
                    session.ValidationErrors.push_back("index batchSequence is not contiguous.");
                    break;
                }

                if (chunk.EventCount == 0)
                {
                    session.ValidationErrors.push_back("chunk eventCount must be non-zero.");
                    break;
                }

                if (chunk.LastRecordSequence < chunk.FirstRecordSequence)
                {
                    session.ValidationErrors.push_back("chunk record sequence range is invalid.");
                    break;
                }

                if (hasPreviousRecordSequence && chunk.FirstRecordSequence <= previousRecordSequence)
                {
                    session.ValidationErrors.push_back("chunk record sequence ranges are not monotonic.");
                    break;
                }

                if (!IsSupportedKnapmCompression(chunkCompression))
                {
                    session.ValidationErrors.push_back("unsupported_compression");
                    break;
                }

                if (!IsSafeKnapmChunkPath(chunk.File))
                {
                    session.ValidationErrors.push_back("chunk file path is not a safe KNAPM chunk path.");
                    break;
                }

                std::string chunkText;
                if (!ReadKnapmChunkDecoded(sessionPath, chunk, &chunkText, &readError))
                {
                    session.ValidationErrors.push_back(readError);
                    break;
                }

                const auto traceLines = ParseTraceJsonl(chunkText);
                if (traceLines.size() != chunk.EventCount)
                {
                    session.ValidationErrors.push_back("chunk eventCount does not match trace row count.");
                    break;
                }

                if (traceLines.empty())
                {
                    session.ValidationErrors.push_back("chunk is empty.");
                    break;
                }

                const std::uint64_t firstEventId = ExtractJsonUInt64(traceLines.front(), "eventId");
                const std::uint64_t lastEventId = ExtractJsonUInt64(traceLines.back(), "eventId");
                if (firstEventId != chunk.FirstEventId || lastEventId != chunk.LastEventId || firstEventId <= previousTraceEventId)
                {
                    session.ValidationErrors.push_back("chunk eventId range does not match index.");
                    break;
                }

                previousTraceEventId = lastEventId;
                const bool hasSequence = traceLines.front().Has("recordSequence");
                std::uint64_t previousSequence = 0;
                for (std::size_t rowIndex = 0; rowIndex < traceLines.size(); ++rowIndex)
                {
                    const auto& row = traceLines[rowIndex];
                    if (row.Has("recordSequence") != hasSequence)
                    {
                        throw JsonInputError("Mixed transport identity availability within a chunk.");
                    }
                    if (hasSequence)
                    {
                        const auto sequence = row.DecimalUInt64("recordSequence");
                        if ((rowIndex != 0 && sequence <= previousSequence) ||
                            sequence < chunk.FirstRecordSequence || sequence > chunk.LastRecordSequence ||
                            (rowIndex == 0 && sequence != chunk.FirstRecordSequence) ||
                            (rowIndex + 1 == traceLines.size() && sequence != chunk.LastRecordSequence))
                        {
                            throw JsonInputError("Trace transport sequence does not match chunk range/order.");
                        }
                        previousSequence = sequence;
                    }
                }


                if (session.ValidationErrors.size() != chunkErrorStart)
                {
                    break;
                }

                totalTraceEvents += chunk.EventCount;
                indexedStoredBytes += chunk.ByteLength;
                indexedUncompressedBytes += static_cast<std::uint64_t>(chunkText.size());
                if (indexedCompression.empty())
                {
                    indexedCompression = chunkCompression;
                }
                else if (indexedCompression != chunkCompression)
                {
                    indexedCompression = "mixed";
                }
                previousBatchSequence = chunk.BatchSequence;
                previousRecordSequence = chunk.LastRecordSequence;
                hasPreviousRecordSequence = true;
                indexedLastBatchSequence = chunk.BatchSequence;
                indexedLastRecordSequence = chunk.LastRecordSequence;
                ++expectedChunkSequence;
            }

            if (!chunkObjects.empty())
            {
                session.LastBatchSequence = indexedLastBatchSequence;
                session.LastRecordSequence = indexedLastRecordSequence;
                session.StoredBytes = indexedStoredBytes;
                session.UncompressedBytes = indexedUncompressedBytes;
                session.CompressionSummary = indexedCompression.empty() ? "none" : indexedCompression;
            }

            if (!chunkObjects.empty() && manifestLastBatchSequence != indexedLastBatchSequence)
            {
                session.ValidationErrors.push_back("manifest lastBatchSequence does not match indexed chunks.");
            }

            if (!chunkObjects.empty() && manifestLastRecordSequence != indexedLastRecordSequence)
            {
                session.ValidationErrors.push_back("manifest lastRecordSequence does not match indexed chunks.");
            }

            if (chunkObjects.empty() && manifestLastBatchSequence != 0)
            {
                session.ValidationErrors.push_back("empty index must have manifest lastBatchSequence set to zero.");
            }

            if (totalTraceEvents != session.TraceEventCount)
            {
                session.ValidationErrors.push_back("manifest trace event count does not match indexed chunks.");
            }

            if (session.Finalized && capturedEventCount != session.TraceEventCount)
            {
                session.ValidationErrors.push_back("finalized capturedEvents count does not match indexed trace count.");
            }

            if (session.Finalized && sessionRecordsStreamed != session.TraceEventCount)
            {
                session.ValidationErrors.push_back("finalized session recordsStreamed does not match indexed trace count.");
            }

            if (session.Finalized && sessionLastTransport != 0 && sessionLastTransport < session.LastRecordSequence)
            {
                session.ValidationErrors.push_back("finalized session lastTransportSequence is behind the last indexed record.");
            }

            if (session.Finalized && sessionTransportDrops != session.TransportDroppedEvents)
            {
                session.ValidationErrors.push_back("finalized transport drop counters disagree.");
            }

            if (session.Finalized && sessionHostDrops != session.HostDroppedBatches)
            {
                session.ValidationErrors.push_back("finalized host drop counters disagree.");
            }

            if (session.ValidationErrors.empty())
            {
                ClassifyKnapmSession(session, manifest);
            }
            else
            {
                SetKnapmMalformedRecovery(session, "index_corrupt");
            }
        }
        while (false);
    }
    catch (const std::exception& exception)
    {
        session.Success = false;
        session.ValidationErrors.push_back(exception.what());
    }

    if (!session.ValidationErrors.empty() && session.RecoveryState.empty())
    {
        SetKnapmMalformedRecovery(session, "index_corrupt");
    }

    session.Success = session.ValidationErrors.empty();
    session.Win32ErrorCode = session.Success ? 0 : ERROR_BAD_FORMAT;
    if (!session.Success)
    {
        session.Message = "KNAPM session validation failed.";
    }
    else if (session.Finalized)
    {
        session.Message = "KNAPM session validation passed.";
    }
    else
    {
        session.Message = "KNAPM partial session validation passed.";
    }

    return session;
}

class TraceReplayWindow
{
public:
    TraceReplayWindow(std::size_t limit, std::uint64_t selectedEventId)
        : Limit_(limit), SelectedEventId_(selectedEventId)
    {
    }

    void Add(const JsonDocument& line)
    {
        ++Seen;
        if (line.UInt64("eventId", true) > 9007199254740991ULL)
        {
            throw JsonInputError("Replay event ID exceeds the renderer integer range.");
        }
        if (!Found_)
        {
            const auto size = line.Text().size();
            Lines_.emplace_back(line, size);
            Bytes_ += size;
            while (Lines_.size() > Limit_ || Bytes_ > 6 * 1024 * 1024)
            {
                Bytes_ -= Lines_.front().second;
                Lines_.pop_front();
            }
            Found_ = SelectedEventId_ != 0 && line.UInt64("eventId", true) == SelectedEventId_;
        }
    }

    std::vector<JsonDocument> Finish() const
    {
        if (SelectedEventId_ != 0 && !Found_)
        {
            throw JsonInputError("Requested replay event was not found.");
        }
        std::vector<JsonDocument> lines;
        for (const auto& entry : Lines_)
        {
            lines.push_back(entry.first);
        }
        return lines;
    }

    std::uint64_t Seen = 0;

private:
    std::size_t Limit_;
    std::uint64_t SelectedEventId_;
    std::size_t Bytes_ = 0;
    bool Found_ = false;
    std::deque<std::pair<JsonDocument, std::size_t>> Lines_;
};

std::vector<JsonDocument> ReadKnapmTraceLines(const std::filesystem::path& sessionPath, const SessionInfo& validation,
    std::size_t windowLimit = 0, std::uint64_t selectedEventId = 0)
{
    std::vector<JsonDocument> traceLines;
    TraceReplayWindow window(windowLimit, selectedEventId);
    std::size_t totalBytes = 0;
    std::size_t totalValues = 0;

    do
    {
        if (!validation.Success)
        {
            break;
        }

        JsonDocument indexText;
        std::string readError;
        if (!ReadTextFile(KnapmChildPath(sessionPath, "index.json"), &indexText, &readError))
        {
            throw JsonInputError(readError);
        }

        const auto chunkObjects = SplitJsonObjectArray(indexText.Array("chunks", true));
        if (validation.ReplayIndexSha256.empty() || Sha256Hex(indexText.Text()) != validation.ReplayIndexSha256 ||
            indexText.String("format", true) != "knapm-index" ||
            indexText.String("sessionId", true) != validation.SessionId || chunkObjects.size() != validation.ChunkCount)
        {
            throw JsonInputError("Replay index identity or chunk count changed after validation.");
        }
        for (const auto& chunkJson : chunkObjects)
        {
            const KnapmChunkInfo chunk = KnapmChunkFromJson(chunkJson);
            // The index was re-read after validation; re-check chunk paths so a
            // swapped index cannot steer reads outside the session directory.
            if (!IsSafeKnapmChunkPath(chunk.File))
            {
                throw JsonInputError("Unsafe chunk path on replay.");
            }

            std::string chunkText;
            if (!ReadKnapmChunkDecoded(sessionPath, chunk, &chunkText, &readError))
            {
                throw JsonInputError(readError);
            }

            if (windowLimit == 0 && chunkText.size() > 64 * 1024 * 1024 - totalBytes)
            {
                throw JsonInputError("Replay byte limit exceeded.");
            }
            if (windowLimit == 0)
            {
                totalBytes += chunkText.size();
            }
            const auto lines = ParseTraceJsonl(chunkText);
            if (lines.size() != chunk.EventCount)
            {
                throw JsonInputError("Replay chunk event count changed after validation.");
            }
            for (const auto& line : lines)
            {
                if (windowLimit == 0)
                {
                    totalValues += line.ValueCount();
                }
                else
                {
                    window.Add(line);
                }
            }
            if (windowLimit == 0 && (lines.size() > 250000 - traceLines.size() || totalValues > 1000000))
            {
                throw JsonInputError("Replay record or value limit exceeded.");
            }
            if (windowLimit == 0)
            {
                traceLines.insert(traceLines.end(), lines.begin(), lines.end());
            }
        }
        if ((windowLimit == 0 ? traceLines.size() : window.Seen) != validation.TraceEventCount)
        {
            throw JsonInputError("Replay event count changed after validation.");
        }
    }
    while (false);

    return windowLimit == 0 ? traceLines : window.Finish();
}

bool IsKnapmSessionPath(const std::filesystem::path& sessionPath)
{
    bool result = false;

    do
    {
        if (sessionPath.extension() == L".knapm")
        {
            result = true;
            break;
        }

        std::error_code error;
        if (std::filesystem::exists(KnapmChildPath(sessionPath, "index.json"), error))
        {
            result = true;
            break;
        }
    }
    while (false);

    return result;
}

SessionInfo ValidateSessionDirectory(const std::filesystem::path& sessionDirectory)
{
    SessionInfo session;
    session.Format = "legacy-jsonl";
    session.SessionPath = PathToUtf8(sessionDirectory);

    try
    {
        do
        {
            const std::filesystem::path manifestPath = sessionDirectory / L"manifest.json";
            const std::filesystem::path auditPath = sessionDirectory / L"audit.jsonl";
            const std::filesystem::path agentPath = sessionDirectory / L"agent-events.jsonl";
            const std::filesystem::path tracePath = sessionDirectory / L"trace-events.jsonl";

            JsonDocument manifest;
            std::string readError;
            if (!ReadTextFile(manifestPath, &manifest, &readError))
            {
                session.ValidationErrors.push_back(readError);
                break;
            }

            ValidateManifestTypes(manifest, false);
            session.SessionId = ExtractJsonString(manifest, "sessionId");
            session.CreatedUtc = ExtractJsonString(manifest, "createdUtc");
            session.DroppedEvents = ExtractJsonUInt64(manifest, "droppedEvents");
            const std::string manifestOperationId = ExtractJsonString(manifest, "operationId");
            const JsonDocument targetManifest = ExtractJsonObject(manifest, "target");
            const JsonDocument agentManifest = ExtractJsonObject(manifest, "agent");
            const JsonDocument eventCounts = ExtractJsonObject(manifest, "eventCounts");
            const std::string manifestTargetArchitecture = ExtractJsonString(targetManifest, "architecture");
            const std::string manifestAgentArchitecture = ExtractJsonString(agentManifest, "architecture");
            const std::string manifestAgentVersion = ExtractJsonString(agentManifest, "version");
            session.ResolverPointerCandidates = ExtractJsonUInt64(eventCounts, "resolverPointerCandidates");
            session.ResolverPointerUnsupported = ExtractJsonUInt64(eventCounts, "resolverPointerUnsupported");

            if (!(ExtractJsonString(manifest, "schemaVersion") == "0.1.0"))
            {
                session.ValidationErrors.push_back("manifest schemaVersion is missing or unsupported.");
            }

            if (session.SessionId.empty())
            {
                session.ValidationErrors.push_back("manifest sessionId is missing.");
            }

            if (!manifest.Has("files"))
            {
                session.ValidationErrors.push_back("manifest files block is missing.");
            }

            if (!IsSupportedArchitecture(manifestTargetArchitecture))
            {
                session.ValidationErrors.push_back("manifest target architecture is missing or unsupported.");
            }

            if (!IsSupportedArchitecture(manifestAgentArchitecture))
            {
                session.ValidationErrors.push_back("manifest agent architecture is missing or unsupported.");
            }

            if (
                IsSupportedArchitecture(manifestTargetArchitecture) &&
                IsSupportedArchitecture(manifestAgentArchitecture) &&
                manifestTargetArchitecture != manifestAgentArchitecture)
            {
                session.ValidationErrors.push_back("manifest target and agent architecture must match.");
            }

            if (manifestAgentVersion.empty())
            {
                session.ValidationErrors.push_back("manifest agent version is missing.");
            }

            std::string auditText;
            if (!ReadTextFile(auditPath, &auditText, &readError))
            {
                session.ValidationErrors.push_back(readError);
            }
            else
            {
                session.AuditEventCount = ParseJsonl(auditText).size();
            }

            std::string agentText;
            if (!ReadTextFile(agentPath, &agentText, &readError))
            {
                session.ValidationErrors.push_back(readError);
            }
            else
            {
                const auto lines = ParseAgentJsonl(agentText);
                session.AgentEventCount = lines.size();
                std::uint64_t helloCount = 0;
                std::uint64_t resolverPointerCandidates = 0;
                std::uint64_t resolverPointerUnsupported = 0;
                bool hasDropped = false;
                bool hasShutdown = false;
                for (const auto& line : lines)
                {
                    if (!(ExtractJsonString(line, "schemaVersion") == "0.1.0"))
                    {
                        session.ValidationErrors.push_back("agent-events.jsonl contains an event without schemaVersion 0.1.0.");
                        break;
                    }

                    if (!manifestOperationId.empty() && ExtractJsonString(line, "operationId") != manifestOperationId)
                    {
                        session.ValidationErrors.push_back("agent-events.jsonl contains an event with mismatched operationId.");
                        break;
                    }

                    if ((ExtractJsonString(line, "messageType") == "agent_hello"))
                    {
                        ++helloCount;
                        const std::string helloArchitecture = ExtractJsonString(line, "architecture");
                        const std::string helloVersion = ExtractJsonString(line, "agentVersion");

                        if (!IsSupportedArchitecture(helloArchitecture))
                        {
                            session.ValidationErrors.push_back("agent_hello architecture is missing or unsupported.");
                        }

                        if (helloVersion.empty())
                        {
                            session.ValidationErrors.push_back("agent_hello agentVersion is missing.");
                        }

                        if (IsSupportedArchitecture(manifestAgentArchitecture) && helloArchitecture != manifestAgentArchitecture)
                        {
                            session.ValidationErrors.push_back("agent_hello architecture does not match manifest agent architecture.");
                        }

                        if (!manifestAgentVersion.empty() && helloVersion != manifestAgentVersion)
                        {
                            session.ValidationErrors.push_back("agent_hello agentVersion does not match manifest agent version.");
                        }
                    }

                    hasDropped = hasDropped || (ExtractJsonString(line, "messageType") == "dropped_events");
                    if (
                        (ExtractJsonString(line, "messageType") == "resolver_pointer_candidate") ||
                        (ExtractJsonString(line, "messageType") == "resolver_pointer_instrumented"))
                    {
                        ++resolverPointerCandidates;
                    }
                    else if ((ExtractJsonString(line, "messageType") == "resolver_pointer_unsupported"))
                    {
                        ++resolverPointerUnsupported;
                    }

                    if ((ExtractJsonString(line, "messageType") == "agent_shutdown"))
                    {
                        hasShutdown = true;
                        if (ExtractJsonString(line, "reason").empty())
                        {
                            session.ValidationErrors.push_back("agent_shutdown reason is missing.");
                        }

                        if (!line.Has("installedHooks") || !line.Has("restoredHooks") || !line.Has("failedHooks"))
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

                if (helloCount == 0)
                {
                    session.ValidationErrors.push_back("agent-events.jsonl does not contain agent_hello.");
                }

                if (helloCount > 1)
                {
                    session.ValidationErrors.push_back("agent-events.jsonl contains more than one agent_hello.");
                }

                if (!hasDropped && !HasProcessExitEvidence(manifest))
                {
                    session.ValidationErrors.push_back("agent-events.jsonl does not contain dropped_events.");
                }

                if (!hasShutdown && !HasProcessExitEvidence(manifest) && !HasQueriedCleanupEvidence(manifest))
                {
                    session.ValidationErrors.push_back("agent-events.jsonl does not contain agent_shutdown.");
                }

                if (eventCounts.Has("resolverPointerCandidates"))
                {
                    if (session.ResolverPointerCandidates < resolverPointerCandidates ||
                        session.ResolverPointerCandidates - resolverPointerCandidates != manifest.Object("retainedHistory").UInt64("omittedResolverPointerCandidates"))
                    {
                        session.ValidationErrors.push_back("agent-events.jsonl resolver_pointer_candidate count does not match manifest eventCounts.resolverPointerCandidates.");
                    }
                }
                else
                {
                    session.ResolverPointerCandidates = resolverPointerCandidates;
                }

                if (eventCounts.Has("resolverPointerUnsupported"))
                {
                    if (session.ResolverPointerUnsupported < resolverPointerUnsupported ||
                        session.ResolverPointerUnsupported - resolverPointerUnsupported != manifest.Object("retainedHistory").UInt64("omittedResolverPointerUnsupported"))
                    {
                        session.ValidationErrors.push_back("agent-events.jsonl resolver_pointer_unsupported count does not match manifest eventCounts.resolverPointerUnsupported.");
                    }
                }
                else
                {
                    session.ResolverPointerUnsupported = resolverPointerUnsupported;
                }
            }

            std::string traceText;
            if (!ReadTextFile(tracePath, &traceText, &readError))
            {
                session.ValidationErrors.push_back(readError);
            }
            else
            {
                session.ReplayTraceSha256 = Sha256Hex(traceText);
                const auto lines = ParseTraceJsonl(traceText);
                session.TraceEventCount = lines.size();
                session.CompressionSummary = "none";
                session.StoredBytes = static_cast<std::uint64_t>(traceText.size());
                session.UncompressedBytes = static_cast<std::uint64_t>(traceText.size());
                if (lines.empty())
                {
                    session.ValidationErrors.push_back("trace-events.jsonl is empty.");
                }

            }
        }
        while (false);
    }
    catch (const std::exception& exception)
    {
        session.Success = false;
        session.ValidationErrors.push_back(exception.what());
    }

    session.Success = session.ValidationErrors.empty();
    session.Finalized = session.Success;
    session.Win32ErrorCode = session.Success ? 0 : ERROR_BAD_FORMAT;
    session.WriterState = session.Success ? "finalized" : "failed";
    session.Message = session.Success ? "Session validation passed." : "Session validation failed.";
    return session;
}

SessionInfo ValidateSessionPath(const std::filesystem::path& sessionPath)
{
    if (IsKnapmSessionPath(sessionPath))
    {
        return ValidateKnapmSession(sessionPath);
    }

    return ValidateSessionDirectory(sessionPath);
}

std::string ReplaySessionJson(const std::filesystem::path& sessionDirectory,
    std::size_t windowLimit = 0, std::uint64_t selectedEventId = 0)
{
    const SessionInfo validation = ValidateSessionPath(sessionDirectory);
    std::string traceText;
    std::string readError;
    std::vector<JsonDocument> traceLines;

    if (validation.Success)
    {
        if (validation.Format == "knapm")
        {
            traceLines = ReadKnapmTraceLines(sessionDirectory, validation, windowLimit, selectedEventId);
        }
        else if (ReadTextFile(sessionDirectory / L"trace-events.jsonl", &traceText, &readError))
        {
            if (validation.ReplayTraceSha256.empty() || Sha256Hex(traceText) != validation.ReplayTraceSha256)
            {
                throw JsonInputError("Replay trace changed after validation.");
            }
            traceLines = ParseTraceJsonl(traceText);
        }
        else
        {
            throw JsonInputError(readError);
        }
        if ((windowLimit == 0 || validation.Format != "knapm") && traceLines.size() != validation.TraceEventCount)
        {
            throw JsonInputError("Replay event count changed after validation.");
        }
    }

    if (validation.Success && windowLimit != 0 && validation.Format != "knapm")
    {
        TraceReplayWindow window(windowLimit, selectedEventId);
        for (const auto& line : traceLines)
        {
            window.Add(line);
        }
        traceLines = window.Finish();
    }

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (validation.Success ? "true" : "false") << ",";
    stream << "\"backendMode\":\"native-capture\",";
    stream << "\"captureMode\":\"session-replay\",";
    stream << "\"session\":" << ToJson(validation) << ",";
    stream << "\"message\":";
    if (!validation.Success)
    {
        stream << Q(validation.Message);
    }
    else if (windowLimit != 0)
    {
        stream << Q("Validated session replay loaded a bounded display window; use the trace index for older events.");
    }
    else if (validation.Format == "knapm")
    {
        stream << Q("KNAPM session replay loaded indexed chunks without launching a target.");
    }
    else
    {
        stream << Q("Session replay loaded trace events without launching a target.");
    }
    stream << ",";
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

bool HasOption(const std::vector<std::string>& args, const std::string& name)
{
    bool found = false;

    for (const std::string& arg : args)
    {
        if (arg == name)
        {
            found = true;
            break;
        }
    }

    return found;
}

std::uint32_t GetUInt32Option(const std::vector<std::string>& args, const std::string& name, std::uint32_t fallback)
{
    std::uint32_t value = fallback;
    const std::string text = GetOption(args, name);

    do
    {
        if (text.empty())
        {
            break;
        }

        char* end = nullptr;
        errno = 0;
        const unsigned long parsed = std::strtoul(text.c_str(), &end, 10);
        if (errno == ERANGE || end == text.c_str() || (end != nullptr && *end != '\0') || parsed > 0xffffffffUL)
        {
            break;
        }

        value = static_cast<std::uint32_t>(parsed);
    }
    while (false);

    return value;
}

struct KnapmCatalogRow
{
    std::string ReplayIndexSha256;
    std::string SessionPath;
    std::string Format;
    std::string SessionId;
    std::string OperationId;
    std::uint32_t TargetProcessId = 0;
    std::string TargetImage;
    std::string TargetPath;
    std::string TargetArchitecture;
    std::string OwnerKind;
    std::string DaemonInstanceId;
    std::string WriterState;
    bool Finalized = false;
    std::string RecoveryState;
    std::string RecoveryReason;
    std::string RecoveryAction;
    std::uint64_t ChunkCount = 0;
    std::uint64_t TraceEventCount = 0;
    std::uint64_t LastBatchSequence = 0;
    std::uint64_t LastRecordSequence = 0;
    std::string Compression;
    std::uint64_t StoredBytes = 0;
    std::uint64_t UncompressedBytes = 0;
    bool ValidationSuccess = false;
    std::uint64_t ValidationErrorCount = 0;
    std::string ValidationStatus;
    std::string LastValidatedUtc;
    std::string ContentIdentity;
    bool StaleIdentity = false;
};

std::string FileNameFromUtf8Path(const std::string& value)
{
    std::string result = value;
    const std::size_t slash = result.find_last_of("\\/");
    if (slash != std::string::npos && slash + 1 < result.size())
    {
        result = result.substr(slash + 1);
    }

    return result;
}

std::string CatalogContentIdentity(const KnapmCatalogRow& row)
{
    std::ostringstream stream;
    stream << row.SessionPath << "|"
           << row.SessionId << "|"
           << row.OperationId << "|"
           << row.TraceEventCount << "|"
           << row.ChunkCount << "|"
           << row.LastRecordSequence << "|"
           << row.StoredBytes << "|"
           << row.UncompressedBytes << "|"
           << row.ValidationStatus;
    return Sha256Hex(stream.str());
}

std::string ToJson(const KnapmCatalogRow& row)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"path\":" << Q(row.SessionPath) << ",";
    stream << "\"format\":" << Q(row.Format) << ",";
    stream << "\"sessionId\":" << Q(row.SessionId) << ",";
    stream << "\"operationId\":" << Q(row.OperationId) << ",";
    stream << "\"targetProcessId\":" << row.TargetProcessId << ",";
    stream << "\"targetImage\":" << Q(row.TargetImage) << ",";
    stream << "\"targetPath\":" << Q(row.TargetPath) << ",";
    stream << "\"targetArchitecture\":" << Q(row.TargetArchitecture) << ",";
    stream << "\"ownerKind\":" << Q(row.OwnerKind) << ",";
    stream << "\"daemonInstanceId\":" << Q(row.DaemonInstanceId) << ",";
    stream << "\"writerState\":" << Q(row.WriterState) << ",";
    stream << "\"finalized\":" << (row.Finalized ? "true" : "false") << ",";
    stream << "\"recoveryState\":" << Q(row.RecoveryState) << ",";
    stream << "\"recoveryReason\":" << Q(row.RecoveryReason) << ",";
    stream << "\"recoveryAction\":" << Q(row.RecoveryAction) << ",";
    stream << "\"chunkCount\":" << row.ChunkCount << ",";
    stream << "\"traceEventCount\":" << row.TraceEventCount << ",";
    stream << "\"lastBatchSequence\":" << row.LastBatchSequence << ",";
    stream << "\"lastRecordSequence\":" << row.LastRecordSequence << ",";
    stream << "\"compression\":" << Q(row.Compression) << ",";
    stream << "\"storedBytes\":" << row.StoredBytes << ",";
    stream << "\"uncompressedBytes\":" << row.UncompressedBytes << ",";
    stream << "\"validationSuccess\":" << (row.ValidationSuccess ? "true" : "false") << ",";
    stream << "\"validationErrorCount\":" << row.ValidationErrorCount << ",";
    stream << "\"validationStatus\":" << Q(row.ValidationStatus) << ",";
    stream << "\"lastValidatedUtc\":" << Q(row.LastValidatedUtc) << ",";
    stream << "\"contentIdentity\":" << Q(row.ContentIdentity) << ",";
    stream << "\"staleIdentity\":" << (row.StaleIdentity ? "true" : "false");
    stream << "}";
    return stream.str();
}

KnapmCatalogRow KnapmCatalogRowFromJson(const JsonDocument& json)
{
    KnapmCatalogRow row;
    row.SessionPath = ExtractJsonString(json, "path");
    row.Format = ExtractJsonString(json, "format");
    row.SessionId = ExtractJsonString(json, "sessionId");
    row.OperationId = ExtractJsonString(json, "operationId");
    row.TargetProcessId = ExtractJsonUInt32(json, "targetProcessId");
    row.TargetImage = ExtractJsonString(json, "targetImage");
    row.TargetPath = ExtractJsonString(json, "targetPath");
    row.TargetArchitecture = ExtractJsonString(json, "targetArchitecture");
    row.OwnerKind = ExtractJsonString(json, "ownerKind");
    row.DaemonInstanceId = ExtractJsonString(json, "daemonInstanceId");
    row.WriterState = ExtractJsonString(json, "writerState");
    row.Finalized = ExtractJsonBool(json, "finalized");
    row.RecoveryState = ExtractJsonString(json, "recoveryState");
    row.RecoveryReason = ExtractJsonString(json, "recoveryReason");
    row.RecoveryAction = ExtractJsonString(json, "recoveryAction");
    row.ChunkCount = ExtractJsonUInt64(json, "chunkCount");
    row.TraceEventCount = ExtractJsonUInt64(json, "traceEventCount");
    row.LastBatchSequence = ExtractJsonUInt64(json, "lastBatchSequence");
    row.LastRecordSequence = ExtractJsonUInt64(json, "lastRecordSequence");
    row.Compression = ExtractJsonString(json, "compression");
    row.StoredBytes = ExtractJsonUInt64(json, "storedBytes");
    row.UncompressedBytes = ExtractJsonUInt64(json, "uncompressedBytes");
    row.ValidationSuccess = ExtractJsonBool(json, "validationSuccess");
    row.ValidationErrorCount = ExtractJsonUInt64(json, "validationErrorCount");
    row.ValidationStatus = ExtractJsonString(json, "validationStatus");
    row.LastValidatedUtc = ExtractJsonString(json, "lastValidatedUtc");
    row.ContentIdentity = ExtractJsonString(json, "contentIdentity");
    row.StaleIdentity = ExtractJsonBool(json, "staleIdentity");
    return row;
}

std::string KnapmCatalogJson(
    const std::string& operation,
    const std::string& rootPath,
    const std::string& catalogPath,
    const std::vector<KnapmCatalogRow>& rows,
    bool success,
    const std::string& message,
    bool dryRun,
    bool mutationAttempted,
    const std::vector<std::string>& missingSessionPaths,
    const std::string& databasePath = "",
    const std::string& indexBackend = "",
    std::uint32_t indexSchemaVersion = 0)
{
    std::uint64_t validCount = 0;
    std::uint64_t invalidCount = 0;
    std::uint64_t storedBytes = 0;
    std::uint64_t uncompressedBytes = 0;
    std::uint64_t staleIdentityCount = 0;
    for (const KnapmCatalogRow& row : rows)
    {
        if (row.ValidationSuccess)
        {
            ++validCount;
        }
        else
        {
            ++invalidCount;
        }

        storedBytes += row.StoredBytes;
        uncompressedBytes += row.UncompressedBytes;
        if (row.StaleIdentity)
        {
            ++staleIdentityCount;
        }
    }

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"format\":\"knapm-session-catalog\",";
    stream << "\"buildTimeUtc\":" << Q(NowUtc()) << ",";
    stream << "\"backendMode\":\"native-capture\",";
    stream << "\"operation\":" << Q(operation) << ",";
    stream << "\"success\":" << (success ? "true" : "false") << ",";
    stream << "\"rootPath\":" << Q(rootPath) << ",";
    stream << "\"catalogPath\":" << Q(catalogPath) << ",";
    stream << "\"sessionCount\":" << rows.size() << ",";
    stream << "\"validSessionCount\":" << validCount << ",";
    stream << "\"invalidSessionCount\":" << invalidCount << ",";
    stream << "\"storedBytes\":" << storedBytes << ",";
    stream << "\"uncompressedBytes\":" << uncompressedBytes << ",";
    if (!databasePath.empty())
    {
        stream << "\"databasePath\":" << Q(databasePath) << ",";
        stream << "\"indexBackend\":" << Q(indexBackend.empty() ? "winsqlite3" : indexBackend) << ",";
        stream << "\"indexSchemaVersion\":" << indexSchemaVersion << ",";
        stream << "\"staleIdentityCount\":" << staleIdentityCount << ",";
    }
    stream << "\"dryRun\":" << (dryRun ? "true" : "false") << ",";
    stream << "\"mutationAttempted\":" << (mutationAttempted ? "true" : "false") << ",";
    stream << "\"missingSessionPaths\":[";
    for (std::size_t index = 0; index < missingSessionPaths.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << Q(missingSessionPaths[index]);
    }
    stream << "],";
    stream << "\"sessions\":[";
    for (std::size_t index = 0; index < rows.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(rows[index]);
    }
    stream << "],";
    stream << "\"message\":" << Q(message);
    stream << "}";
    return stream.str();
}

KnapmCatalogRow BuildKnapmCatalogRow(const std::filesystem::path& sessionPath)
{
    KnapmCatalogRow row;
    std::error_code pathError;
    const std::filesystem::path absolutePath = std::filesystem::absolute(sessionPath, pathError);
    row.SessionPath = PathToUtf8(pathError ? sessionPath : absolutePath);
    row.LastValidatedUtc = NowUtc();

    const SessionInfo validation = ValidateSessionPath(sessionPath);
    row.Format = validation.Format;
    row.SessionId = validation.SessionId;
    row.WriterState = validation.WriterState;
    row.Finalized = validation.Finalized;
    row.RecoveryState = validation.RecoveryState;
    row.RecoveryReason = validation.RecoveryReason;
    row.RecoveryAction = validation.RecoveryAction;
    row.ChunkCount = validation.ChunkCount;
    row.ReplayIndexSha256 = validation.ReplayIndexSha256;
    row.TraceEventCount = validation.TraceEventCount;
    row.LastBatchSequence = validation.LastBatchSequence;
    row.LastRecordSequence = validation.LastRecordSequence;
    row.Compression = validation.CompressionSummary.empty() ? "none" : validation.CompressionSummary;
    row.StoredBytes = validation.StoredBytes;
    row.UncompressedBytes = validation.UncompressedBytes;
    row.ValidationSuccess = validation.Success;
    row.ValidationErrorCount = static_cast<std::uint64_t>(validation.ValidationErrors.size());
    row.ValidationStatus = validation.Success ? "valid" : "invalid";

    JsonDocument manifest;
    std::string readError;
    if (ReadTextFile(KnapmChildPath(sessionPath, "manifest.json"), &manifest, &readError))
    {
        row.OperationId = ExtractJsonString(manifest, "operationId");

        const JsonDocument targetObject = ExtractJsonObject(manifest, "target");
        row.TargetProcessId = ExtractJsonUInt32(targetObject, "pid");
        row.TargetPath = ExtractJsonString(targetObject, "path");
        row.TargetImage = FileNameFromUtf8Path(row.TargetPath);
        row.TargetArchitecture = ExtractJsonString(targetObject, "architecture");

        const JsonDocument ownerObject = ExtractJsonObject(manifest, "owner");
        row.OwnerKind = ExtractJsonString(ownerObject, "ownerKind");
        row.DaemonInstanceId = ExtractJsonString(ownerObject, "daemonInstanceId");
    }

    if (row.ContentIdentity.empty())
    {
        row.ContentIdentity = CatalogContentIdentity(row);
    }

    return row;
}

std::vector<std::filesystem::path> DiscoverKnapmSessionPaths(const std::filesystem::path& root)
{
    std::vector<std::filesystem::path> sessions;

    do
    {
        std::error_code error;
        if (!std::filesystem::exists(root, error))
        {
            break;
        }

        if (std::filesystem::is_directory(root, error) && IsKnapmSessionPath(root))
        {
            sessions.push_back(root);
            break;
        }

        const std::filesystem::directory_options options = std::filesystem::directory_options::skip_permission_denied;
        std::filesystem::recursive_directory_iterator iterator(root, options, error);
        const std::filesystem::recursive_directory_iterator end;
        while (!error && iterator != end)
        {
            const std::filesystem::directory_entry entry = *iterator;
            if (entry.is_directory(error) && IsKnapmSessionPath(entry.path()))
            {
                sessions.push_back(entry.path());
                iterator.disable_recursion_pending();
            }

            iterator.increment(error);
            if (error)
            {
                error.clear();
            }
        }
    }
    while (false);

    std::sort(sessions.begin(), sessions.end());
    return sessions;
}

std::vector<KnapmCatalogRow> KnapmCatalogRowsFromJson(const JsonDocument& json)
{
    std::vector<KnapmCatalogRow> rows;
    const auto rowObjects = SplitJsonObjectArray(json.Array("sessions", true));
    for (const JsonDocument& rowObject : rowObjects)
    {
        rows.push_back(KnapmCatalogRowFromJson(rowObject));
    }

    return rows;
}

constexpr std::uint32_t CatalogIndexSchemaVersion = 1;
constexpr std::uint32_t TraceIndexSchemaVersion = 2;

struct SqliteStatement
{
    sqlite3_stmt* Statement = nullptr;

    ~SqliteStatement()
    {
        if (Statement != nullptr)
        {
            sqlite3_finalize(Statement);
            Statement = nullptr;
        }
    }
};

std::string SqliteError(sqlite3* database)
{
    return database == nullptr ? "sqlite database unavailable." : sqlite3_errmsg(database);
}

bool ExecSql(sqlite3* database, const std::string& sql, std::string* error)
{
    bool success = false;
    char* sqliteError = nullptr;

    do
    {
        if (database == nullptr)
        {
            if (error != nullptr)
            {
                *error = "sqlite database unavailable.";
            }
            break;
        }

        const int rc = sqlite3_exec(database, sql.c_str(), nullptr, nullptr, &sqliteError);
        if (rc != SQLITE_OK)
        {
            if (error != nullptr)
            {
                *error = sqliteError != nullptr ? sqliteError : SqliteError(database);
            }
            break;
        }

        success = true;
    }
    while (false);

    if (sqliteError != nullptr)
    {
        sqlite3_free(sqliteError);
    }

    return success;
}

bool PrepareSql(sqlite3* database, const std::string& sql, SqliteStatement* statement, std::string* error)
{
    bool success = false;

    do
    {
        if (database == nullptr || statement == nullptr)
        {
            if (error != nullptr)
            {
                *error = "sqlite statement preparation received invalid arguments.";
            }
            break;
        }

        const int rc = sqlite3_prepare_v2(database, sql.c_str(), -1, &statement->Statement, nullptr);
        if (rc != SQLITE_OK)
        {
            if (error != nullptr)
            {
                *error = SqliteError(database);
            }
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

bool BindText(sqlite3_stmt* statement, int index, const std::string& value, std::string* error)
{
    const int rc = sqlite3_bind_text(statement, index, value.c_str(), -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK && error != nullptr)
    {
        *error = "sqlite bind text failed.";
    }

    return rc == SQLITE_OK;
}

bool BindUInt64(sqlite3_stmt* statement, int index, std::uint64_t value, std::string* error)
{
    const int rc = sqlite3_bind_int64(statement, index, static_cast<sqlite3_int64>(value));
    if (rc != SQLITE_OK && error != nullptr)
    {
        *error = "sqlite bind integer failed.";
    }

    return rc == SQLITE_OK;
}

bool BindDouble(sqlite3_stmt* statement, int index, double value, std::string* error)
{
    const int rc = sqlite3_bind_double(statement, index, value);
    if (rc != SQLITE_OK && error != nullptr)
    {
        *error = "sqlite bind real failed.";
    }
    return rc == SQLITE_OK;
}

std::string ColumnText(sqlite3_stmt* statement, int index)
{
    const unsigned char* text = sqlite3_column_text(statement, index);
    return text == nullptr ? "" : std::string(reinterpret_cast<const char*>(text),
        static_cast<std::size_t>(sqlite3_column_bytes(statement, index)));
}

std::uint64_t ColumnUInt64(sqlite3_stmt* statement, int index)
{
    const sqlite3_int64 value = sqlite3_column_int64(statement, index);
    return value < 0 ? 0 : static_cast<std::uint64_t>(value);
}

bool ColumnBool(sqlite3_stmt* statement, int index)
{
    return sqlite3_column_int(statement, index) != 0;
}

bool OpenCatalogIndexDatabase(
    const std::filesystem::path& databasePath,
    int flags,
    sqlite3** database,
    std::string* error)
{
    bool success = false;

    do
    {
        if (database == nullptr)
        {
            if (error != nullptr)
            {
                *error = "database output pointer is null.";
            }
            break;
        }

        *database = nullptr;
        if ((flags & SQLITE_OPEN_CREATE) != 0)
        {
            std::error_code createError;
            const std::filesystem::path parent = databasePath.parent_path();
            if (!parent.empty())
            {
                std::filesystem::create_directories(parent, createError);
                if (createError)
                {
                    if (error != nullptr)
                    {
                        *error = "create_directories failed for " + PathToUtf8(parent) + ": " + createError.message();
                    }
                    break;
                }
            }
        }

        const std::string databasePathUtf8 = PathToUtf8(databasePath);
        const int rc = sqlite3_open_v2(databasePathUtf8.c_str(), database, flags, nullptr);
        if (rc != SQLITE_OK)
        {
            if (error != nullptr)
            {
                *error = *database == nullptr ? "sqlite open failed." : SqliteError(*database);
            }
            if (*database != nullptr)
            {
                sqlite3_close(*database);
                *database = nullptr;
            }
            break;
        }

        sqlite3_limit(*database, SQLITE_LIMIT_LENGTH, 8 * 1024 * 1024);
        sqlite3_busy_timeout(*database, 3000);
        success = true;
    }
    while (false);

    return success;
}

std::string ReadCatalogIndexMetadata(sqlite3* database, const std::string& key, bool* found, std::string* error)
{
    std::string value;
    bool localFound = false;

    do
    {
        SqliteStatement statement;
        if (!PrepareSql(database, "SELECT value FROM metadata WHERE key = ?;", &statement, error))
        {
            break;
        }

        if (!BindText(statement.Statement, 1, key, error))
        {
            break;
        }

        const int rc = sqlite3_step(statement.Statement);
        if (rc == SQLITE_ROW)
        {
            value = ColumnText(statement.Statement, 0);
            localFound = true;
        }
        else if (rc != SQLITE_DONE && error != nullptr)
        {
            *error = SqliteError(database);
        }
    }
    while (false);

    if (found != nullptr)
    {
        *found = localFound;
    }

    return value;
}

bool SetCatalogIndexMetadata(sqlite3* database, const std::string& key, const std::string& value, std::string* error)
{
    bool success = false;

    do
    {
        SqliteStatement statement;
        if (!PrepareSql(database, "INSERT OR REPLACE INTO metadata(key, value) VALUES(?, ?);", &statement, error))
        {
            break;
        }

        if (!BindText(statement.Statement, 1, key, error) || !BindText(statement.Statement, 2, value, error))
        {
            break;
        }

        const int rc = sqlite3_step(statement.Statement);
        if (rc != SQLITE_DONE)
        {
            if (error != nullptr)
            {
                *error = SqliteError(database);
            }
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

bool EnsureCatalogIndexSchema(sqlite3* database, std::string* error)
{
    bool success = false;

    do
    {
        if (!ExecSql(database, "PRAGMA foreign_keys = ON;", error))
        {
            break;
        }

        if (!ExecSql(
            database,
            "CREATE TABLE IF NOT EXISTS metadata("
            "key TEXT PRIMARY KEY NOT NULL,"
            "value TEXT NOT NULL"
            ");",
            error))
        {
            break;
        }

        bool found = false;
        const std::string schemaVersion = ReadCatalogIndexMetadata(database, "schema_version", &found, error);
        if (found && schemaVersion != std::to_string(CatalogIndexSchemaVersion))
        {
            if (error != nullptr)
            {
                *error = "unsupported catalog index schema version " + schemaVersion + ".";
            }
            break;
        }

        if (!ExecSql(
            database,
            "CREATE TABLE IF NOT EXISTS sessions("
            "path TEXT PRIMARY KEY NOT NULL,"
            "format TEXT NOT NULL,"
            "session_id TEXT NOT NULL,"
            "operation_id TEXT NOT NULL,"
            "target_process_id INTEGER NOT NULL,"
            "target_image TEXT NOT NULL,"
            "target_path TEXT NOT NULL,"
            "target_architecture TEXT NOT NULL,"
            "owner_kind TEXT NOT NULL,"
            "daemon_instance_id TEXT NOT NULL,"
            "writer_state TEXT NOT NULL,"
            "finalized INTEGER NOT NULL,"
            "recovery_state TEXT NOT NULL,"
            "recovery_reason TEXT NOT NULL,"
            "recovery_action TEXT NOT NULL,"
            "chunk_count INTEGER NOT NULL,"
            "trace_event_count INTEGER NOT NULL,"
            "last_batch_sequence INTEGER NOT NULL,"
            "last_record_sequence INTEGER NOT NULL,"
            "compression TEXT NOT NULL,"
            "stored_bytes INTEGER NOT NULL,"
            "uncompressed_bytes INTEGER NOT NULL,"
            "validation_success INTEGER NOT NULL,"
            "validation_error_count INTEGER NOT NULL,"
            "validation_status TEXT NOT NULL,"
            "last_validated_utc TEXT NOT NULL,"
            "content_identity TEXT NOT NULL,"
            "stale_identity INTEGER NOT NULL"
            ");",
            error))
        {
            break;
        }

        if (!ExecSql(database, "CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(validation_status, recovery_state, writer_state);", error))
        {
            break;
        }
        if (!ExecSql(database, "CREATE INDEX IF NOT EXISTS idx_sessions_target_pid ON sessions(target_process_id);", error))
        {
            break;
        }
        if (!ExecSql(database, "CREATE INDEX IF NOT EXISTS idx_sessions_target_text ON sessions(target_image, target_path);", error))
        {
            break;
        }
        if (!SetCatalogIndexMetadata(database, "schema_version", std::to_string(CatalogIndexSchemaVersion), error))
        {
            break;
        }
        if (!ExecSql(database, "PRAGMA user_version = 1;", error))
        {
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

bool ValidateCatalogIndexSchema(sqlite3* database, std::string* error)
{
    bool success = false;

    do
    {
        bool found = false;
        const std::string schemaVersion = ReadCatalogIndexMetadata(database, "schema_version", &found, error);
        if (!found)
        {
            if (error != nullptr && error->empty())
            {
                *error = "catalog index schema metadata is missing.";
            }
            break;
        }

        if (schemaVersion != std::to_string(CatalogIndexSchemaVersion))
        {
            if (error != nullptr)
            {
                *error = "unsupported catalog index schema version " + schemaVersion + ".";
            }
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

std::string CatalogRowsContentIdentity(const std::vector<KnapmCatalogRow>& rows)
{
    std::ostringstream stream;
    for (const KnapmCatalogRow& row : rows)
    {
        stream << row.ContentIdentity << "\n";
    }

    return Sha256Hex(stream.str());
}

bool InsertCatalogIndexRow(sqlite3* database, const KnapmCatalogRow& row, std::string* error)
{
    bool success = false;

    do
    {
        SqliteStatement statement;
        if (!PrepareSql(
            database,
            "INSERT OR REPLACE INTO sessions("
            "path,format,session_id,operation_id,target_process_id,target_image,target_path,target_architecture,"
            "owner_kind,daemon_instance_id,writer_state,finalized,recovery_state,recovery_reason,recovery_action,"
            "chunk_count,trace_event_count,last_batch_sequence,last_record_sequence,compression,stored_bytes,"
            "uncompressed_bytes,validation_success,validation_error_count,validation_status,last_validated_utc,"
            "content_identity,stale_identity"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            &statement,
            error))
        {
            break;
        }

        int index = 1;
        if (!BindText(statement.Statement, index++, row.SessionPath, error) ||
            !BindText(statement.Statement, index++, row.Format, error) ||
            !BindText(statement.Statement, index++, row.SessionId, error) ||
            !BindText(statement.Statement, index++, row.OperationId, error) ||
            !BindUInt64(statement.Statement, index++, row.TargetProcessId, error) ||
            !BindText(statement.Statement, index++, row.TargetImage, error) ||
            !BindText(statement.Statement, index++, row.TargetPath, error) ||
            !BindText(statement.Statement, index++, row.TargetArchitecture, error) ||
            !BindText(statement.Statement, index++, row.OwnerKind, error) ||
            !BindText(statement.Statement, index++, row.DaemonInstanceId, error) ||
            !BindText(statement.Statement, index++, row.WriterState, error) ||
            !BindUInt64(statement.Statement, index++, row.Finalized ? 1 : 0, error) ||
            !BindText(statement.Statement, index++, row.RecoveryState, error) ||
            !BindText(statement.Statement, index++, row.RecoveryReason, error) ||
            !BindText(statement.Statement, index++, row.RecoveryAction, error) ||
            !BindUInt64(statement.Statement, index++, row.ChunkCount, error) ||
            !BindUInt64(statement.Statement, index++, row.TraceEventCount, error) ||
            !BindUInt64(statement.Statement, index++, row.LastBatchSequence, error) ||
            !BindUInt64(statement.Statement, index++, row.LastRecordSequence, error) ||
            !BindText(statement.Statement, index++, row.Compression, error) ||
            !BindUInt64(statement.Statement, index++, row.StoredBytes, error) ||
            !BindUInt64(statement.Statement, index++, row.UncompressedBytes, error) ||
            !BindUInt64(statement.Statement, index++, row.ValidationSuccess ? 1 : 0, error) ||
            !BindUInt64(statement.Statement, index++, row.ValidationErrorCount, error) ||
            !BindText(statement.Statement, index++, row.ValidationStatus, error) ||
            !BindText(statement.Statement, index++, row.LastValidatedUtc, error) ||
            !BindText(statement.Statement, index++, row.ContentIdentity, error) ||
            !BindUInt64(statement.Statement, index++, row.StaleIdentity ? 1 : 0, error))
        {
            break;
        }

        const int rc = sqlite3_step(statement.Statement);
        if (rc != SQLITE_DONE)
        {
            if (error != nullptr)
            {
                *error = SqliteError(database);
            }
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

const char* CatalogIndexSelectColumns()
{
    return
        "path,format,session_id,operation_id,target_process_id,target_image,target_path,target_architecture,"
        "owner_kind,daemon_instance_id,writer_state,finalized,recovery_state,recovery_reason,recovery_action,"
        "chunk_count,trace_event_count,last_batch_sequence,last_record_sequence,compression,stored_bytes,"
        "uncompressed_bytes,validation_success,validation_error_count,validation_status,last_validated_utc,"
        "content_identity,stale_identity";
}

KnapmCatalogRow CatalogRowFromStatement(sqlite3_stmt* statement)
{
    KnapmCatalogRow row;
    int index = 0;
    row.SessionPath = ColumnText(statement, index++);
    row.Format = ColumnText(statement, index++);
    row.SessionId = ColumnText(statement, index++);
    row.OperationId = ColumnText(statement, index++);
    row.TargetProcessId = static_cast<std::uint32_t>(ColumnUInt64(statement, index++));
    row.TargetImage = ColumnText(statement, index++);
    row.TargetPath = ColumnText(statement, index++);
    row.TargetArchitecture = ColumnText(statement, index++);
    row.OwnerKind = ColumnText(statement, index++);
    row.DaemonInstanceId = ColumnText(statement, index++);
    row.WriterState = ColumnText(statement, index++);
    row.Finalized = ColumnBool(statement, index++);
    row.RecoveryState = ColumnText(statement, index++);
    row.RecoveryReason = ColumnText(statement, index++);
    row.RecoveryAction = ColumnText(statement, index++);
    row.ChunkCount = ColumnUInt64(statement, index++);
    row.TraceEventCount = ColumnUInt64(statement, index++);
    row.LastBatchSequence = ColumnUInt64(statement, index++);
    row.LastRecordSequence = ColumnUInt64(statement, index++);
    row.Compression = ColumnText(statement, index++);
    row.StoredBytes = ColumnUInt64(statement, index++);
    row.UncompressedBytes = ColumnUInt64(statement, index++);
    row.ValidationSuccess = ColumnBool(statement, index++);
    row.ValidationErrorCount = ColumnUInt64(statement, index++);
    row.ValidationStatus = ColumnText(statement, index++);
    row.LastValidatedUtc = ColumnText(statement, index++);
    row.ContentIdentity = ColumnText(statement, index++);
    row.StaleIdentity = ColumnBool(statement, index++);
    return row;
}

bool TryParseCatalogTargetPid(const std::string& target, std::uint32_t* pid)
{
    bool parsed = false;

    do
    {
        if (pid == nullptr || target.empty())
        {
            break;
        }

        char* end = nullptr;
        errno = 0;
        const unsigned long value = std::strtoul(target.c_str(), &end, 10);
        if (errno == ERANGE || end == target.c_str() || end == nullptr || *end != '\0' || value > 0xffffffffUL)
        {
            break;
        }

        *pid = static_cast<std::uint32_t>(value);
        parsed = true;
    }
    while (false);

    return parsed;
}

bool QueryCatalogIndexRows(
    sqlite3* database,
    const std::string& state,
    const std::string& target,
    std::uint32_t limit,
    std::vector<KnapmCatalogRow>* rows,
    std::string* error)
{
    bool success = false;

    do
    {
        if (rows == nullptr)
        {
            if (error != nullptr)
            {
                *error = "catalog query rows output is null.";
            }
            break;
        }

        std::string sql = std::string("SELECT ") + CatalogIndexSelectColumns() + " FROM sessions";
        std::vector<std::string> predicates;
        std::uint32_t targetPid = 0;
        const bool hasState = !state.empty();
        const bool hasTargetPid = TryParseCatalogTargetPid(target, &targetPid);
        const bool hasTargetText = !target.empty() && !hasTargetPid;

        if (hasState)
        {
            predicates.push_back("(validation_status = ? OR recovery_state = ? OR writer_state = ?)");
        }
        if (hasTargetPid)
        {
            predicates.push_back("target_process_id = ?");
        }
        else if (hasTargetText)
        {
            predicates.push_back("(instr(lower(target_image), ?) > 0 OR instr(lower(target_path), ?) > 0)");
        }

        if (!predicates.empty())
        {
            sql += " WHERE ";
            for (std::size_t index = 0; index < predicates.size(); ++index)
            {
                if (index != 0)
                {
                    sql += " AND ";
                }
                sql += predicates[index];
            }
        }

        sql += " ORDER BY last_validated_utc DESC, path ASC";
        if (limit != 0)
        {
            sql += " LIMIT ?";
        }
        sql += ";";

        SqliteStatement statement;
        if (!PrepareSql(database, sql, &statement, error))
        {
            break;
        }

        int bindIndex = 1;
        if (hasState)
        {
            if (!BindText(statement.Statement, bindIndex++, state, error) ||
                !BindText(statement.Statement, bindIndex++, state, error) ||
                !BindText(statement.Statement, bindIndex++, state, error))
            {
                break;
            }
        }
        if (hasTargetPid)
        {
            if (!BindUInt64(statement.Statement, bindIndex++, targetPid, error))
            {
                break;
            }
        }
        else if (hasTargetText)
        {
            const std::string needle = LowerAsciiPathKey(target);
            if (!BindText(statement.Statement, bindIndex++, needle, error) ||
                !BindText(statement.Statement, bindIndex++, needle, error))
            {
                break;
            }
        }
        if (limit != 0 && !BindUInt64(statement.Statement, bindIndex++, limit, error))
        {
            break;
        }

        while (true)
        {
            const int rc = sqlite3_step(statement.Statement);
            if (rc == SQLITE_ROW)
            {
                rows->push_back(CatalogRowFromStatement(statement.Statement));
                continue;
            }
            if (rc == SQLITE_DONE)
            {
                success = true;
            }
            else if (error != nullptr)
            {
                *error = SqliteError(database);
            }
            break;
        }
    }
    while (false);

    return success;
}

std::string CatalogIndexBuildJson(const std::vector<std::string>& args)
{
    const std::string rootOption = GetOption(args, "--root");
    const std::string databaseOption = GetOption(args, "--database");
    const bool rebuild = HasOption(args, "--rebuild");
    std::vector<KnapmCatalogRow> rows;
    sqlite3* database = nullptr;
    std::string error;

    do
    {
        if (rootOption.empty())
        {
            return KnapmCatalogJson("catalog-index-build", "", databaseOption, rows, false, "missing --root.", false, false, {}, databaseOption, "winsqlite3", CatalogIndexSchemaVersion);
        }
        if (databaseOption.empty())
        {
            return KnapmCatalogJson("catalog-index-build", rootOption, "", rows, false, "missing --database.", false, false, {}, databaseOption, "winsqlite3", CatalogIndexSchemaVersion);
        }

        const std::filesystem::path rootPath = PathFromUtf8(rootOption);
        std::error_code rootError;
        if (!std::filesystem::exists(rootPath, rootError))
        {
            return KnapmCatalogJson("catalog-index-build", rootOption, databaseOption, rows, false, "root does not exist.", false, false, {}, databaseOption, "winsqlite3", CatalogIndexSchemaVersion);
        }

        const auto sessionPaths = DiscoverKnapmSessionPaths(rootPath);
        for (const std::filesystem::path& sessionPath : sessionPaths)
        {
            rows.push_back(BuildKnapmCatalogRow(sessionPath));
        }

        if (!OpenCatalogIndexDatabase(PathFromUtf8(databaseOption), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, &database, &error))
        {
            break;
        }
        if (!EnsureCatalogIndexSchema(database, &error))
        {
            break;
        }

        bool rootFound = false;
        const std::string existingRoot = ReadCatalogIndexMetadata(database, "root_path", &rootFound, &error);
        if (rootFound && existingRoot != rootOption && !rebuild)
        {
            error = "catalog index root mismatch; rebuild required.";
            break;
        }

        if (!ExecSql(database, "BEGIN IMMEDIATE TRANSACTION;", &error))
        {
            break;
        }

        bool transactionActive = true;
        bool transactionSuccess = false;
        do
        {
            if (rebuild && !ExecSql(database, "DELETE FROM sessions;", &error))
            {
                break;
            }

            for (const KnapmCatalogRow& row : rows)
            {
                if (!InsertCatalogIndexRow(database, row, &error))
                {
                    break;
                }
            }
            if (!error.empty())
            {
                break;
            }

            const std::string buildTimeUtc = NowUtc();
            if (!SetCatalogIndexMetadata(database, "schema_version", std::to_string(CatalogIndexSchemaVersion), &error) ||
                !SetCatalogIndexMetadata(database, "format", "knapm-session-catalog-index", &error) ||
                !SetCatalogIndexMetadata(database, "root_path", rootOption, &error) ||
                !SetCatalogIndexMetadata(database, "build_time_utc", buildTimeUtc, &error) ||
                !SetCatalogIndexMetadata(database, "content_identity", CatalogRowsContentIdentity(rows), &error) ||
                !SetCatalogIndexMetadata(database, "session_count", std::to_string(rows.size()), &error))
            {
                break;
            }

            if (!ExecSql(database, "COMMIT;", &error))
            {
                transactionActive = false;
                break;
            }

            transactionActive = false;
            transactionSuccess = true;
        }
        while (false);

        if (transactionActive)
        {
            std::string rollbackError;
            ExecSql(database, "ROLLBACK;", &rollbackError);
        }

        if (!transactionSuccess)
        {
            break;
        }
    }
    while (false);

    if (database != nullptr)
    {
        sqlite3_close(database);
        database = nullptr;
    }

    if (!error.empty())
    {
        return KnapmCatalogJson("catalog-index-build", rootOption, databaseOption, rows, false, error, false, true, {}, databaseOption, "winsqlite3", CatalogIndexSchemaVersion);
    }

    return KnapmCatalogJson("catalog-index-build", rootOption, databaseOption, rows, true, "Catalog index built.", false, true, {}, databaseOption, "winsqlite3", CatalogIndexSchemaVersion);
}

std::string CatalogIndexQueryJson(const std::vector<std::string>& args)
{
    const std::string databaseOption = GetOption(args, "--database");
    const std::string state = GetOption(args, "--state");
    const std::string target = GetOption(args, "--target");
    const std::uint32_t limit = GetUInt32Option(args, "--limit", 100);
    std::vector<KnapmCatalogRow> rows;
    sqlite3* database = nullptr;
    std::string error;
    std::string rootPath;

    do
    {
        if (databaseOption.empty())
        {
            return KnapmCatalogJson("catalog-index-query", "", "", rows, false, "missing --database.", false, false, {}, databaseOption, "winsqlite3", CatalogIndexSchemaVersion);
        }

        if (!OpenCatalogIndexDatabase(PathFromUtf8(databaseOption), SQLITE_OPEN_READONLY, &database, &error))
        {
            break;
        }
        if (!ValidateCatalogIndexSchema(database, &error))
        {
            break;
        }

        bool rootFound = false;
        rootPath = ReadCatalogIndexMetadata(database, "root_path", &rootFound, &error);
        if (!rootFound)
        {
            rootPath.clear();
        }

        if (!QueryCatalogIndexRows(database, state, target, limit, &rows, &error))
        {
            break;
        }
    }
    while (false);

    if (database != nullptr)
    {
        sqlite3_close(database);
        database = nullptr;
    }

    if (!error.empty())
    {
        return KnapmCatalogJson("catalog-index-query", rootPath, databaseOption, rows, false, error, false, false, {}, databaseOption, "winsqlite3", CatalogIndexSchemaVersion);
    }

    return KnapmCatalogJson("catalog-index-query", rootPath, databaseOption, rows, true, "Catalog index query completed.", false, false, {}, databaseOption, "winsqlite3", CatalogIndexSchemaVersion);
}

bool DeleteCatalogIndexRow(sqlite3* database, const std::string& path, std::string* error)
{
    bool success = false;

    do
    {
        SqliteStatement statement;
        if (!PrepareSql(database, "DELETE FROM sessions WHERE path = ?;", &statement, error))
        {
            break;
        }
        if (!BindText(statement.Statement, 1, path, error))
        {
            break;
        }

        const int rc = sqlite3_step(statement.Statement);
        if (rc != SQLITE_DONE)
        {
            if (error != nullptr)
            {
                *error = SqliteError(database);
            }
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

std::string CatalogIndexRemoveMissingJson(const std::vector<std::string>& args)
{
    const std::string databaseOption = GetOption(args, "--database");
    const bool dryRun = HasOption(args, "--dry-run");
    std::vector<KnapmCatalogRow> rows;
    std::vector<KnapmCatalogRow> keptRows;
    std::vector<std::string> missingSessionPaths;
    sqlite3* database = nullptr;
    std::string error;
    std::string rootPath;

    do
    {
        if (databaseOption.empty())
        {
            return KnapmCatalogJson("catalog-index-remove-missing", "", "", rows, false, "missing --database.", dryRun, false, {}, databaseOption, "winsqlite3", CatalogIndexSchemaVersion);
        }

        if (!OpenCatalogIndexDatabase(PathFromUtf8(databaseOption), SQLITE_OPEN_READWRITE, &database, &error))
        {
            break;
        }
        if (!ValidateCatalogIndexSchema(database, &error))
        {
            break;
        }

        bool rootFound = false;
        rootPath = ReadCatalogIndexMetadata(database, "root_path", &rootFound, &error);
        if (!rootFound)
        {
            rootPath.clear();
        }

        if (!QueryCatalogIndexRows(database, "", "", 0, &rows, &error))
        {
            break;
        }

        for (const KnapmCatalogRow& row : rows)
        {
            std::error_code existsError;
            if (row.SessionPath.empty() || !std::filesystem::exists(PathFromUtf8(row.SessionPath), existsError))
            {
                missingSessionPaths.push_back(row.SessionPath);
                continue;
            }

            keptRows.push_back(row);
        }

        if (!dryRun)
        {
            if (!ExecSql(database, "BEGIN IMMEDIATE TRANSACTION;", &error))
            {
                break;
            }

            bool transactionActive = true;
            bool transactionSuccess = false;
            do
            {
                for (const std::string& path : missingSessionPaths)
                {
                    if (!DeleteCatalogIndexRow(database, path, &error))
                    {
                        break;
                    }
                }
                if (!error.empty())
                {
                    break;
                }

                if (!SetCatalogIndexMetadata(database, "session_count", std::to_string(keptRows.size()), &error) ||
                    !SetCatalogIndexMetadata(database, "content_identity", CatalogRowsContentIdentity(keptRows), &error) ||
                    !SetCatalogIndexMetadata(database, "build_time_utc", NowUtc(), &error))
                {
                    break;
                }

                if (!ExecSql(database, "COMMIT;", &error))
                {
                    transactionActive = false;
                    break;
                }

                transactionActive = false;
                transactionSuccess = true;
            }
            while (false);

            if (transactionActive)
            {
                std::string rollbackError;
                ExecSql(database, "ROLLBACK;", &rollbackError);
            }

            if (!transactionSuccess)
            {
                break;
            }
        }
    }
    while (false);

    if (database != nullptr)
    {
        sqlite3_close(database);
        database = nullptr;
    }

    if (!error.empty())
    {
        return KnapmCatalogJson("catalog-index-remove-missing", rootPath, databaseOption, rows, false, error, dryRun, !dryRun, missingSessionPaths, databaseOption, "winsqlite3", CatalogIndexSchemaVersion);
    }

    return KnapmCatalogJson(
        "catalog-index-remove-missing",
        rootPath,
        databaseOption,
        dryRun ? rows : keptRows,
        true,
        dryRun ? "Missing catalog index rows identified." : "Missing catalog index rows removed.",
        dryRun,
        !dryRun,
        missingSessionPaths,
        databaseOption,
        "winsqlite3",
        CatalogIndexSchemaVersion);
}

struct KnapmTraceIndexEvent
{
    std::string SessionPath;
    std::string SessionId;
    std::string OperationId;
    std::uint64_t EventId = 0;
    std::string RecordSequence;
    std::uint64_t ChunkSequence = 0;
    std::uint64_t BatchSequence = 0;
    std::uint32_t TargetProcessId = 0;
    std::uint32_t Pid = 0;
    std::uint32_t Tid = 0;
    std::string Process;
    std::string Module;
    std::string Api;
    std::string ReturnValue;
    std::string ErrorText;
    std::uint64_t DurationUs = 0;
    double RelativeTimeMs = 0;
    std::string TagsText;
    std::string ArgumentsText;
    std::string BufferPreview;
    std::string EventJson;
    std::string Excerpt;
};

std::string TrimAscii(const std::string& value)
{
    std::size_t first = 0;
    while (first < value.size())
    {
        const char ch = value[first];
        if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n')
        {
            break;
        }

        ++first;
    }

    std::size_t last = value.size();
    while (last > first)
    {
        const char ch = value[last - 1];
        if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n')
        {
            break;
        }

        --last;
    }

    return value.substr(first, last - first);
}

std::string TraceIndexExcerpt(const std::string& value)
{
    const std::size_t limit = 240;
    if (value.size() <= limit)
    {
        return value;
    }

    std::size_t end = limit;
    while (end != 0 && (static_cast<unsigned char>(value[end]) & 0xc0) == 0x80)
    {
        --end;
    }
    return value.substr(0, end) + "...";
}

std::string TraceIndexFtsQueryFromText(const std::string& value)
{
    std::ostringstream stream;
    const std::string trimmed = TrimAscii(value);
    std::size_t position = 0;
    std::size_t tokenCount = 0;

    while (position < trimmed.size())
    {
        while (position < trimmed.size())
        {
            const char ch = trimmed[position];
            if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n')
            {
                break;
            }

            ++position;
        }

        const std::size_t start = position;
        while (position < trimmed.size())
        {
            const char ch = trimmed[position];
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
            {
                break;
            }

            ++position;
        }

        if (position <= start)
        {
            continue;
        }

        if (tokenCount != 0)
        {
            stream << " AND ";
        }

        stream << "\"";
        const std::string token = trimmed.substr(start, position - start);
        for (const char ch : token)
        {
            if (ch == '"')
            {
                stream << "\"\"";
            }
            else
            {
                stream << ch;
            }
        }
        stream << "\"";
        ++tokenCount;
    }

    return stream.str();
}

std::string TraceIndexFormat()
{
    return "knapm-trace-index";
}

std::string ToJson(const KnapmTraceIndexEvent& event)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"sessionPath\":" << Q(event.SessionPath) << ",";
    stream << "\"sessionId\":" << Q(event.SessionId) << ",";
    stream << "\"operationId\":" << Q(event.OperationId) << ",";
    stream << "\"eventId\":" << event.EventId << ",";
    stream << "\"recordSequence\":" << (event.RecordSequence.empty() ? "null" : Q(event.RecordSequence)) << ",";
    stream << "\"chunkSequence\":" << event.ChunkSequence << ",";
    stream << "\"batchSequence\":" << event.BatchSequence << ",";
    stream << "\"targetProcessId\":" << event.TargetProcessId << ",";
    stream << "\"pid\":" << event.Pid << ",";
    stream << "\"tid\":" << event.Tid << ",";
    stream << "\"process\":" << Q(event.Process) << ",";
    stream << "\"module\":" << Q(event.Module) << ",";
    stream << "\"api\":" << Q(event.Api) << ",";
    stream << "\"returnValue\":" << Q(event.ReturnValue) << ",";
    stream << "\"errorText\":" << Q(event.ErrorText) << ",";
    stream << "\"durationUs\":" << event.DurationUs << ",";
    stream << "\"relativeTimeMs\":" << std::setprecision(17) << event.RelativeTimeMs << ",";
    stream << "\"tagsText\":" << Q(event.TagsText) << ",";
    stream << "\"argumentsText\":" << Q(event.ArgumentsText) << ",";
    stream << "\"bufferPreview\":" << Q(event.BufferPreview) << ",";
    stream << "\"excerpt\":" << Q(event.Excerpt) << ",";
    stream << "\"eventJson\":" << Q(event.EventJson);
    stream << "}";
    return stream.str();
}

std::string TraceIndexJson(
    const std::string& operation,
    const std::string& rootPath,
    const std::string& databasePath,
    bool success,
    const std::string& message,
    std::uint64_t sessionCount,
    std::uint64_t indexedSessionCount,
    std::uint64_t invalidSessionCount,
    std::uint64_t eventCount,
    bool dryRun,
    bool mutationAttempted,
    const std::vector<std::string>& missingSessionPaths,
    const std::vector<KnapmTraceIndexEvent>& events)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"format\":" << Q(TraceIndexFormat()) << ",";
    stream << "\"buildTimeUtc\":" << Q(NowUtc()) << ",";
    stream << "\"backendMode\":\"native-capture\",";
    stream << "\"operation\":" << Q(operation) << ",";
    stream << "\"success\":" << (success ? "true" : "false") << ",";
    stream << "\"rootPath\":" << Q(rootPath) << ",";
    stream << "\"databasePath\":" << Q(databasePath) << ",";
    stream << "\"indexBackend\":\"winsqlite3-fts5\",";
    stream << "\"indexSchemaVersion\":" << TraceIndexSchemaVersion << ",";
    stream << "\"sessionCount\":" << sessionCount << ",";
    stream << "\"indexedSessionCount\":" << indexedSessionCount << ",";
    stream << "\"invalidSessionCount\":" << invalidSessionCount << ",";
    stream << "\"eventCount\":" << eventCount << ",";
    stream << "\"matchedEventCount\":" << events.size() << ",";
    stream << "\"dryRun\":" << (dryRun ? "true" : "false") << ",";
    stream << "\"mutationAttempted\":" << (mutationAttempted ? "true" : "false") << ",";
    stream << "\"missingSessionPaths\":[";
    for (std::size_t index = 0; index < missingSessionPaths.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << Q(missingSessionPaths[index]);
    }
    stream << "],";
    stream << "\"events\":[";
    for (std::size_t index = 0; index < events.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(events[index]);
    }
    stream << "],";
    stream << "\"message\":" << Q(message);
    stream << "}";
    return stream.str();
}

KnapmTraceIndexEvent TraceIndexEventFromJson(
    const KnapmCatalogRow& session,
    const KnapmChunkInfo& chunk,
    const JsonDocument& line)
{
    KnapmTraceIndexEvent event;
    event.SessionPath = session.SessionPath;
    event.SessionId = session.SessionId;
    event.OperationId = session.OperationId;
    event.EventId = ExtractJsonUInt64(line, "eventId");
    event.RecordSequence = line.String("recordSequence");
    event.ChunkSequence = chunk.ChunkSequence;
    event.BatchSequence = chunk.BatchSequence;
    event.TargetProcessId = session.TargetProcessId;
    event.Pid = ExtractJsonUInt32(line, "pid");
    event.Tid = ExtractJsonUInt32(line, "tid");
    event.Process = ExtractJsonString(line, "process");
    event.Module = ExtractJsonString(line, "module");
    event.Api = ExtractJsonString(line, "api");
    event.ReturnValue = ExtractJsonString(line, "returnValue");
    event.ErrorText = line.ObjectOrNull("error").Text();
    event.DurationUs = ExtractJsonUInt64(line, "durationUs");
    event.RelativeTimeMs = line.NonnegativeNumber("relativeTimeMs", true);
    event.TagsText = ExtractJsonArray(line, "tags").Text();
    event.ArgumentsText = ExtractJsonArray(line, "arguments").Text();
    event.BufferPreview = ExtractJsonString(line, "bufferPreview");
    event.EventJson = line.Text();
    event.Excerpt = TraceIndexExcerpt(line.Text());
    return event;
}

bool ReadKnapmTraceIndexEvents(
    const std::filesystem::path& sessionPath,
    const KnapmCatalogRow& session,
    const std::function<bool(const KnapmTraceIndexEvent&)>& consume,
    std::uint64_t* eventCount,
    std::string* error)
{
    bool success = false;

    try
    {
        do
        {
            if (eventCount == nullptr || !consume)
            {
                if (error != nullptr)
                {
                    *error = "trace index event consumer is missing.";
                }
                break;
            }

            JsonDocument indexText;
            std::string readError;
            if (!ReadTextFile(KnapmChildPath(sessionPath, "index.json"), &indexText, &readError))
            {
                if (error != nullptr)
                {
                    *error = readError;
                }
                break;
            }

            if (session.ReplayIndexSha256.empty() || Sha256Hex(indexText.Text()) != session.ReplayIndexSha256)
            {
                throw JsonInputError("Trace index changed after validation.");
            }
            *eventCount = 0;
            const auto chunkObjects = SplitJsonObjectArray(indexText.Array("chunks", true));
            for (const auto& chunkJson : chunkObjects)
            {
                const KnapmChunkInfo chunk = KnapmChunkFromJson(chunkJson);
                // Re-check chunk paths on this fresh index read so a swapped index
                // cannot steer reads outside the session directory.
                if (!IsSafeKnapmChunkPath(chunk.File))
                {
                    if (error != nullptr)
                    {
                        *error = "chunk file path is not a safe KNAPM chunk path.";
                    }
                    break;
                }

                std::string chunkText;
                if (!ReadKnapmChunkDecoded(sessionPath, chunk, &chunkText, &readError))
                {
                    if (error != nullptr)
                    {
                        *error = readError;
                    }
                    break;
                }

                const auto lines = ParseTraceJsonl(chunkText);
                if (lines.size() != chunk.EventCount)
                {
                    throw JsonInputError("Trace index chunk row count changed.");
                }
                for (std::size_t lineIndex = 0; lineIndex < lines.size(); ++lineIndex)
                {
                    const JsonDocument& line = lines[lineIndex];
                    if (!consume(TraceIndexEventFromJson(session, chunk, line)))
                    {
                        throw JsonInputError("Trace index row insertion failed.");
                    }
                    ++*eventCount;
                }

                if (error != nullptr && !error->empty())
                {
                    break;
                }
            }

            if (error == nullptr || error->empty())
            {
                if (*eventCount != session.TraceEventCount)
                {
                    throw JsonInputError("Trace index total row count changed.");
                }
                success = true;
            }
        }
        while (false);
    }
    catch (const std::exception& exception)
    {
        success = false;
        if (error != nullptr)
        {
            *error = exception.what();
        }
    }

    return success;
}

bool EnsureTraceIndexSchema(sqlite3* database, std::string* error, bool rebuild)
{
    bool success = false;
    bool migrationActive = false;

    do
    {
        if (!ExecSql(database, "PRAGMA foreign_keys = ON;", error))
        {
            break;
        }

        if (!ExecSql(database, "BEGIN IMMEDIATE TRANSACTION;", error))
        {
            break;
        }
        migrationActive = true;
        {
            SqliteStatement objects;
            if (!PrepareSql(database,
                "SELECT COUNT(*), SUM(type='table' AND name='metadata') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%';",
                &objects, error) || sqlite3_step(objects.Statement) != SQLITE_ROW)
            {
                break;
            }
            if (ColumnUInt64(objects.Statement, 0) != 0)
            {
                bool found = false;
                const bool owned = ColumnUInt64(objects.Statement, 1) != 0 &&
                    ReadCatalogIndexMetadata(database, "format", &found, error) == TraceIndexFormat() && found;
                if (!owned)
                {
                    if (error != nullptr)
                    {
                        *error = "existing database is not an owned trace index; choose a new database path.";
                    }
                    break;
                }
            }
        }
        if (!ExecSql(
            database,
            "CREATE TABLE IF NOT EXISTS metadata("
            "key TEXT PRIMARY KEY NOT NULL,"
            "value TEXT NOT NULL"
            ");",
            error))
        {
            break;
        }

        bool foundSchema = false;
        const std::string schemaVersion = ReadCatalogIndexMetadata(database, "schema_version", &foundSchema, error);
        bool foundFormat = false;
        const std::string format = ReadCatalogIndexMetadata(database, "format", &foundFormat, error);
        if (foundFormat && format != TraceIndexFormat())
        {
            if (error != nullptr)
            {
                *error = "database format is " + format + ", not " + TraceIndexFormat() + ".";
            }
            break;
        }

        if (foundSchema && schemaVersion != std::to_string(TraceIndexSchemaVersion))
        {
            if (!rebuild || schemaVersion != "1" || !foundFormat || format != TraceIndexFormat())
            {
                if (error != nullptr)
                {
                    *error = "unsupported trace index schema version " + schemaVersion +
                        "; schema 1 requires an explicit --rebuild.";
                }
                break;
            }
            if (!ExecSql(database, "DROP TABLE IF EXISTS trace_events_fts; DROP TABLE IF EXISTS trace_events; DROP TABLE IF EXISTS sessions;", error))
            {
                break;
            }
        }

        if (!ExecSql(
            database,
            "CREATE TABLE IF NOT EXISTS sessions("
            "path TEXT PRIMARY KEY NOT NULL,"
            "session_id TEXT NOT NULL,"
            "operation_id TEXT NOT NULL,"
            "target_process_id INTEGER NOT NULL,"
            "target_image TEXT NOT NULL,"
            "target_path TEXT NOT NULL,"
            "target_architecture TEXT NOT NULL,"
            "validation_status TEXT NOT NULL,"
            "recovery_state TEXT NOT NULL,"
            "writer_state TEXT NOT NULL,"
            "content_identity TEXT NOT NULL,"
            "trace_event_count INTEGER NOT NULL,"
            "last_validated_utc TEXT NOT NULL"
            ");",
            error))
        {
            break;
        }

        if (!ExecSql(
            database,
            "CREATE TABLE IF NOT EXISTS trace_events("
            "session_path TEXT NOT NULL,"
            "session_id TEXT NOT NULL,"
            "operation_id TEXT NOT NULL,"
            "event_id INTEGER NOT NULL,"
            "record_sequence TEXT NOT NULL,"
            "chunk_sequence INTEGER NOT NULL,"
            "batch_sequence INTEGER NOT NULL,"
            "target_process_id INTEGER NOT NULL,"
            "pid INTEGER NOT NULL,"
            "tid INTEGER NOT NULL,"
            "process TEXT NOT NULL,"
            "module TEXT NOT NULL,"
            "api TEXT NOT NULL,"
            "return_value TEXT NOT NULL,"
            "error_text TEXT NOT NULL,"
            "duration_us INTEGER NOT NULL,"
            "relative_time_ms REAL NOT NULL,"
            "tags_text TEXT NOT NULL,"
            "arguments_text TEXT NOT NULL,"
            "buffer_preview TEXT NOT NULL,"
            "event_json TEXT NOT NULL,"
            "FOREIGN KEY(session_path) REFERENCES sessions(path) ON DELETE CASCADE"
            ");",
            error))
        {
            break;
        }

        if (!ExecSql(
            database,
            "CREATE VIRTUAL TABLE IF NOT EXISTS trace_events_fts USING fts5("
            "module,"
            "api,"
            "process,"
            "tags_text,"
            "arguments_text,"
            "error_text,"
            "buffer_preview,"
            "event_json,"
            "session_path UNINDEXED,"
            "event_rowid UNINDEXED"
            ");",
            error))
        {
            break;
        }

        if (!ExecSql(database, "CREATE INDEX IF NOT EXISTS idx_trace_events_session ON trace_events(session_path, event_id);", error))
        {
            break;
        }
        if (!ExecSql(database, "CREATE INDEX IF NOT EXISTS idx_trace_events_api_module ON trace_events(api, module);", error))
        {
            break;
        }
        if (!ExecSql(database, "CREATE INDEX IF NOT EXISTS idx_trace_events_pid ON trace_events(pid, target_process_id);", error))
        {
            break;
        }
        if (!SetCatalogIndexMetadata(database, "schema_version", std::to_string(TraceIndexSchemaVersion), error))
        {
            break;
        }
        if (!SetCatalogIndexMetadata(database, "format", TraceIndexFormat(), error))
        {
            break;
        }
        if (!ExecSql(database, "PRAGMA user_version = 2;", error))
        {
            break;
        }

        success = true;
    }
    while (false);

    if (migrationActive)
    {
        if (success)
        {
            success = ExecSql(database, "COMMIT;", error);
        }
        if (!success)
        {
            std::string rollbackError;
            ExecSql(database, "ROLLBACK;", &rollbackError);
        }
    }

    if (!success && error != nullptr && error->empty())
    {
        *error = "trace index schema initialization failed.";
    }
    return success;
}

bool ValidateTraceIndexSchema(sqlite3* database, std::string* error)
{
    bool success = false;

    do
    {
        bool foundFormat = false;
        const std::string format = ReadCatalogIndexMetadata(database, "format", &foundFormat, error);
        if (!foundFormat || format != TraceIndexFormat())
        {
            if (error != nullptr && error->empty())
            {
                *error = foundFormat ? "database is not a trace index." : "trace index format metadata is missing.";
            }
            break;
        }

        bool foundSchema = false;
        const std::string schemaVersion = ReadCatalogIndexMetadata(database, "schema_version", &foundSchema, error);
        if (!foundSchema)
        {
            if (error != nullptr && error->empty())
            {
                *error = "trace index schema metadata is missing.";
            }
            break;
        }

        if (schemaVersion != std::to_string(TraceIndexSchemaVersion))
        {
            if (error != nullptr)
            {
                *error = "unsupported trace index schema version " + schemaVersion + ".";
            }
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

bool DeleteTraceIndexSessionRows(sqlite3* database, const std::string& sessionPath, std::string* error)
{
    bool success = false;

    do
    {
        SqliteStatement ftsStatement;
        if (!PrepareSql(database, "DELETE FROM trace_events_fts WHERE session_path = ?;", &ftsStatement, error))
        {
            break;
        }
        if (!BindText(ftsStatement.Statement, 1, sessionPath, error))
        {
            break;
        }
        if (sqlite3_step(ftsStatement.Statement) != SQLITE_DONE)
        {
            if (error != nullptr)
            {
                *error = SqliteError(database);
            }
            break;
        }

        SqliteStatement eventsStatement;
        if (!PrepareSql(database, "DELETE FROM trace_events WHERE session_path = ?;", &eventsStatement, error))
        {
            break;
        }
        if (!BindText(eventsStatement.Statement, 1, sessionPath, error))
        {
            break;
        }
        if (sqlite3_step(eventsStatement.Statement) != SQLITE_DONE)
        {
            if (error != nullptr)
            {
                *error = SqliteError(database);
            }
            break;
        }

        SqliteStatement sessionsStatement;
        if (!PrepareSql(database, "DELETE FROM sessions WHERE path = ?;", &sessionsStatement, error))
        {
            break;
        }
        if (!BindText(sessionsStatement.Statement, 1, sessionPath, error))
        {
            break;
        }
        if (sqlite3_step(sessionsStatement.Statement) != SQLITE_DONE)
        {
            if (error != nullptr)
            {
                *error = SqliteError(database);
            }
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

bool InsertTraceIndexSessionRow(sqlite3* database, const KnapmCatalogRow& row, std::string* error)
{
    bool success = false;

    do
    {
        SqliteStatement statement;
        if (!PrepareSql(
            database,
            "INSERT OR REPLACE INTO sessions("
            "path,session_id,operation_id,target_process_id,target_image,target_path,target_architecture,"
            "validation_status,recovery_state,writer_state,content_identity,trace_event_count,last_validated_utc"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?);",
            &statement,
            error))
        {
            break;
        }

        int index = 1;
        if (!BindText(statement.Statement, index++, row.SessionPath, error) ||
            !BindText(statement.Statement, index++, row.SessionId, error) ||
            !BindText(statement.Statement, index++, row.OperationId, error) ||
            !BindUInt64(statement.Statement, index++, row.TargetProcessId, error) ||
            !BindText(statement.Statement, index++, row.TargetImage, error) ||
            !BindText(statement.Statement, index++, row.TargetPath, error) ||
            !BindText(statement.Statement, index++, row.TargetArchitecture, error) ||
            !BindText(statement.Statement, index++, row.ValidationStatus, error) ||
            !BindText(statement.Statement, index++, row.RecoveryState, error) ||
            !BindText(statement.Statement, index++, row.WriterState, error) ||
            !BindText(statement.Statement, index++, row.ContentIdentity, error) ||
            !BindUInt64(statement.Statement, index++, row.TraceEventCount, error) ||
            !BindText(statement.Statement, index++, row.LastValidatedUtc, error))
        {
            break;
        }

        const int rc = sqlite3_step(statement.Statement);
        if (rc != SQLITE_DONE)
        {
            if (error != nullptr)
            {
                *error = SqliteError(database);
            }
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

bool InsertTraceIndexEventRow(sqlite3* database, const KnapmTraceIndexEvent& event, std::string* error)
{
    bool success = false;

    do
    {
        SqliteStatement statement;
        if (!PrepareSql(
            database,
            "INSERT INTO trace_events("
            "session_path,session_id,operation_id,event_id,record_sequence,chunk_sequence,batch_sequence,"
            "target_process_id,pid,tid,process,module,api,return_value,error_text,duration_us,"
            "relative_time_ms,tags_text,arguments_text,buffer_preview,event_json"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            &statement,
            error))
        {
            break;
        }

        int index = 1;
        if (!BindText(statement.Statement, index++, event.SessionPath, error) ||
            !BindText(statement.Statement, index++, event.SessionId, error) ||
            !BindText(statement.Statement, index++, event.OperationId, error) ||
            !BindUInt64(statement.Statement, index++, event.EventId, error) ||
            !BindText(statement.Statement, index++, event.RecordSequence, error) ||
            !BindUInt64(statement.Statement, index++, event.ChunkSequence, error) ||
            !BindUInt64(statement.Statement, index++, event.BatchSequence, error) ||
            !BindUInt64(statement.Statement, index++, event.TargetProcessId, error) ||
            !BindUInt64(statement.Statement, index++, event.Pid, error) ||
            !BindUInt64(statement.Statement, index++, event.Tid, error) ||
            !BindText(statement.Statement, index++, event.Process, error) ||
            !BindText(statement.Statement, index++, event.Module, error) ||
            !BindText(statement.Statement, index++, event.Api, error) ||
            !BindText(statement.Statement, index++, event.ReturnValue, error) ||
            !BindText(statement.Statement, index++, event.ErrorText, error) ||
            !BindUInt64(statement.Statement, index++, event.DurationUs, error) ||
            !BindDouble(statement.Statement, index++, event.RelativeTimeMs, error) ||
            !BindText(statement.Statement, index++, event.TagsText, error) ||
            !BindText(statement.Statement, index++, event.ArgumentsText, error) ||
            !BindText(statement.Statement, index++, event.BufferPreview, error) ||
            !BindText(statement.Statement, index++, event.EventJson, error))
        {
            break;
        }

        const int rc = sqlite3_step(statement.Statement);
        if (rc != SQLITE_DONE)
        {
            if (error != nullptr)
            {
                *error = SqliteError(database);
            }
            break;
        }

        const sqlite3_int64 rowId = sqlite3_last_insert_rowid(database);
        SqliteStatement ftsStatement;
        if (!PrepareSql(
            database,
            "INSERT INTO trace_events_fts("
            "module,api,process,tags_text,arguments_text,error_text,buffer_preview,event_json,session_path,event_rowid"
            ") VALUES(?,?,?,?,?,?,?,?,?,?);",
            &ftsStatement,
            error))
        {
            break;
        }

        index = 1;
        if (!BindText(ftsStatement.Statement, index++, event.Module, error) ||
            !BindText(ftsStatement.Statement, index++, event.Api, error) ||
            !BindText(ftsStatement.Statement, index++, event.Process, error) ||
            !BindText(ftsStatement.Statement, index++, event.TagsText, error) ||
            !BindText(ftsStatement.Statement, index++, event.ArgumentsText, error) ||
            !BindText(ftsStatement.Statement, index++, event.ErrorText, error) ||
            !BindText(ftsStatement.Statement, index++, event.BufferPreview, error) ||
            !BindText(ftsStatement.Statement, index++, event.EventJson, error) ||
            !BindText(ftsStatement.Statement, index++, event.SessionPath, error) ||
            !BindUInt64(ftsStatement.Statement, index++, static_cast<std::uint64_t>(rowId), error))
        {
            break;
        }

        if (sqlite3_step(ftsStatement.Statement) != SQLITE_DONE)
        {
            if (error != nullptr)
            {
                *error = SqliteError(database);
            }
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

const char* TraceIndexSelectColumns()
{
    return
        "e.session_path,e.session_id,e.operation_id,e.event_id,e.record_sequence,e.chunk_sequence,e.batch_sequence,"
        "e.target_process_id,e.pid,e.tid,e.process,e.module,e.api,e.return_value,e.error_text,e.duration_us,"
        "e.relative_time_ms,e.tags_text,e.arguments_text,e.buffer_preview,e.event_json";
}

KnapmTraceIndexEvent TraceIndexEventFromStatement(sqlite3_stmt* statement)
{
    KnapmTraceIndexEvent event;
    int index = 0;
    event.SessionPath = ColumnText(statement, index++);
    event.SessionId = ColumnText(statement, index++);
    event.OperationId = ColumnText(statement, index++);
    event.EventId = ColumnUInt64(statement, index++);
    event.RecordSequence = ColumnText(statement, index++);
    event.ChunkSequence = ColumnUInt64(statement, index++);
    event.BatchSequence = ColumnUInt64(statement, index++);
    event.TargetProcessId = static_cast<std::uint32_t>(ColumnUInt64(statement, index++));
    event.Pid = static_cast<std::uint32_t>(ColumnUInt64(statement, index++));
    event.Tid = static_cast<std::uint32_t>(ColumnUInt64(statement, index++));
    event.Process = ColumnText(statement, index++);
    event.Module = ColumnText(statement, index++);
    event.Api = ColumnText(statement, index++);
    event.ReturnValue = ColumnText(statement, index++);
    event.ErrorText = ColumnText(statement, index++);
    event.DurationUs = ColumnUInt64(statement, index++);
    event.RelativeTimeMs = sqlite3_column_double(statement, index++);
    event.TagsText = ColumnText(statement, index++);
    event.ArgumentsText = ColumnText(statement, index++);
    event.BufferPreview = ColumnText(statement, index++);
    event.EventJson = ColumnText(statement, index++);
    event.Excerpt = TraceIndexExcerpt(event.EventJson);
    return event;
}

std::uint64_t ReadTraceIndexMetadataUInt64(sqlite3* database, const std::string& key)
{
    std::uint64_t result = 0;
    bool found = false;
    std::string error;
    const std::string value = ReadCatalogIndexMetadata(database, key, &found, &error);

    do
    {
        if (!found || !error.empty())
        {
            break;
        }

        char* end = nullptr;
        const unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
        if (end == value.c_str() || end == nullptr || *end != '\0')
        {
            break;
        }

        result = static_cast<std::uint64_t>(parsed);
    }
    while (false);

    return result;
}

bool QueryTraceIndexEvents(
    sqlite3* database,
    const std::string& text,
    const std::string& api,
    const std::string& module,
    const std::string& session,
    const std::string& pidText,
    std::uint32_t limit,
    std::vector<KnapmTraceIndexEvent>* events,
    std::string* error)
{
    bool success = false;

    do
    {
        if (events == nullptr)
        {
            if (error != nullptr)
            {
                *error = "trace index query output is null.";
            }
            break;
        }

        events->clear();
        if (limit == 0 || limit > 5000)
        {
            if (error != nullptr)
            {
                *error = "trace index query limit must be between 1 and 5000.";
            }
            break;
        }

        const std::string ftsQuery = TraceIndexFtsQueryFromText(text);
        const bool hasText = !ftsQuery.empty();
        const bool hasApi = !TrimAscii(api).empty();
        const bool hasModule = !TrimAscii(module).empty();
        const bool hasSession = !TrimAscii(session).empty();
        std::uint32_t pid = 0;
        const bool hasPid = TryParseCatalogTargetPid(pidText, &pid);

        std::string sql = std::string("SELECT ") + TraceIndexSelectColumns() + " FROM trace_events e";
        if (hasText)
        {
            sql += " JOIN trace_events_fts ON trace_events_fts.event_rowid = e.rowid";
        }

        std::vector<std::string> predicates;
        if (hasText)
        {
            predicates.push_back("trace_events_fts MATCH ?");
        }
        if (hasApi)
        {
            predicates.push_back("lower(e.api) = ?");
        }
        if (hasModule)
        {
            predicates.push_back("lower(e.module) = ?");
        }
        if (hasSession)
        {
            predicates.push_back("(e.session_id = ? OR instr(lower(e.session_path), ?) > 0)");
        }
        if (hasPid)
        {
            predicates.push_back("(e.pid = ? OR e.target_process_id = ?)");
        }

        if (!predicates.empty())
        {
            sql += " WHERE ";
            for (std::size_t index = 0; index < predicates.size(); ++index)
            {
                if (index != 0)
                {
                    sql += " AND ";
                }
                sql += predicates[index];
            }
        }

        sql += " ORDER BY e.session_path ASC, e.event_id ASC, e.record_sequence ASC";
        if (limit != 0)
        {
            sql += " LIMIT ?";
        }
        sql += ";";

        SqliteStatement statement;
        if (!PrepareSql(database, sql, &statement, error))
        {
            break;
        }

        int bindIndex = 1;
        if (hasText && !BindText(statement.Statement, bindIndex++, ftsQuery, error))
        {
            break;
        }
        if (hasApi && !BindText(statement.Statement, bindIndex++, LowerAsciiPathKey(api), error))
        {
            break;
        }
        if (hasModule && !BindText(statement.Statement, bindIndex++, LowerAsciiPathKey(module), error))
        {
            break;
        }
        if (hasSession)
        {
            const std::string sessionNeedle = LowerAsciiPathKey(session);
            if (!BindText(statement.Statement, bindIndex++, session, error) ||
                !BindText(statement.Statement, bindIndex++, sessionNeedle, error))
            {
                break;
            }
        }
        if (hasPid)
        {
            if (!BindUInt64(statement.Statement, bindIndex++, pid, error) ||
                !BindUInt64(statement.Statement, bindIndex++, pid, error))
            {
                break;
            }
        }
        if (limit != 0 && !BindUInt64(statement.Statement, bindIndex++, limit, error))
        {
            break;
        }

        std::size_t encodedBytes = 0;
        while (true)
        {
            const int rc = sqlite3_step(statement.Statement);
            if (rc == SQLITE_ROW)
            {
                KnapmTraceIndexEvent event = TraceIndexEventFromStatement(statement.Statement);
                const std::size_t eventBytes = ToJson(event).size() + 1;
                if (eventBytes > 6 * 1024 * 1024 - encodedBytes)
                {
                    if (error != nullptr)
                    {
                        *error = "trace index query exceeds its byte budget; reduce --limit or narrow filters.";
                    }
                    break;
                }
                encodedBytes += eventBytes;
                events->push_back(std::move(event));
                continue;
            }

            if (rc == SQLITE_DONE)
            {
                success = true;
            }
            else if (error != nullptr)
            {
                *error = SqliteError(database);
            }
            break;
        }
    }
    while (false);

    if (!success && events != nullptr)
    {
        events->clear();
    }
    return success;
}

bool ReadTraceIndexSessionPaths(sqlite3* database, std::vector<std::string>* paths, std::string* error)
{
    bool success = false;

    do
    {
        if (paths == nullptr)
        {
            if (error != nullptr)
            {
                *error = "trace index session path output is null.";
            }
            break;
        }

        SqliteStatement statement;
        if (!PrepareSql(database, "SELECT path FROM sessions ORDER BY path ASC;", &statement, error))
        {
            break;
        }

        while (true)
        {
            const int rc = sqlite3_step(statement.Statement);
            if (rc == SQLITE_ROW)
            {
                paths->push_back(ColumnText(statement.Statement, 0));
                continue;
            }

            if (rc == SQLITE_DONE)
            {
                success = true;
            }
            else if (error != nullptr)
            {
                *error = SqliteError(database);
            }
            break;
        }
    }
    while (false);

    return success;
}

std::string TraceIndexBuildJson(const std::vector<std::string>& args)
{
    const std::string rootOption = GetOption(args, "--root");
    const std::string databaseOption = GetOption(args, "--database");
    const bool rebuild = HasOption(args, "--rebuild");
    sqlite3* database = nullptr;
    std::string error;
    std::uint64_t sessionCount = 0;
    std::uint64_t indexedSessionCount = 0;
    std::uint64_t invalidSessionCount = 0;
    std::uint64_t eventCount = 0;

    do
    {
        if (rootOption.empty())
        {
            return TraceIndexJson("trace-index-build", "", databaseOption, false, "missing --root.", 0, 0, 0, 0, false, false, {}, {});
        }
        if (databaseOption.empty())
        {
            return TraceIndexJson("trace-index-build", rootOption, "", false, "missing --database.", 0, 0, 0, 0, false, false, {}, {});
        }

        const std::filesystem::path rootPath = PathFromUtf8(rootOption);
        std::error_code rootError;
        if (!std::filesystem::exists(rootPath, rootError))
        {
            return TraceIndexJson("trace-index-build", rootOption, databaseOption, false, "root does not exist.", 0, 0, 0, 0, false, false, {}, {});
        }

        if (!OpenCatalogIndexDatabase(PathFromUtf8(databaseOption), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, &database, &error))
        {
            break;
        }
        if (!EnsureTraceIndexSchema(database, &error, rebuild))
        {
            break;
        }

        bool rootFound = false;
        const std::string existingRoot = ReadCatalogIndexMetadata(database, "root_path", &rootFound, &error);
        if (rootFound && existingRoot != rootOption && !rebuild)
        {
            error = "trace index root mismatch; rebuild required.";
            break;
        }

        const auto sessionPaths = DiscoverKnapmSessionPaths(rootPath);
        sessionCount = static_cast<std::uint64_t>(sessionPaths.size());

        if (!ExecSql(database, "BEGIN IMMEDIATE TRANSACTION;", &error))
        {
            break;
        }

        bool transactionActive = true;
        bool transactionSuccess = false;
        do
        {
            if (rebuild)
            {
                if (!ExecSql(database, "DELETE FROM trace_events_fts;", &error) ||
                    !ExecSql(database, "DELETE FROM trace_events;", &error) ||
                    !ExecSql(database, "DELETE FROM sessions;", &error))
                {
                    break;
                }
            }

            for (const std::filesystem::path& sessionPath : sessionPaths)
            {
                KnapmCatalogRow row = BuildKnapmCatalogRow(sessionPath);
                if (!DeleteTraceIndexSessionRows(database, row.SessionPath, &error))
                {
                    break;
                }

                if (!row.ValidationSuccess || row.Format != "knapm")
                {
                    ++invalidSessionCount;
                    continue;
                }

                if (!InsertTraceIndexSessionRow(database, row, &error))
                {
                    break;
                }
                std::uint64_t insertedEvents = 0;
                if (!ReadKnapmTraceIndexEvents(sessionPath, row,
                    [&](const KnapmTraceIndexEvent& event)
                    {
                        return InsertTraceIndexEventRow(database, event, &error);
                    }, &insertedEvents, &error))
                {
                    break;
                }
                if (!error.empty())
                {
                    break;
                }

                ++indexedSessionCount;
                eventCount += insertedEvents;
            }
            if (!error.empty())
            {
                break;
            }

            const std::string buildTimeUtc = NowUtc();
            if (!SetCatalogIndexMetadata(database, "schema_version", std::to_string(TraceIndexSchemaVersion), &error) ||
                !SetCatalogIndexMetadata(database, "format", TraceIndexFormat(), &error) ||
                !SetCatalogIndexMetadata(database, "root_path", rootOption, &error) ||
                !SetCatalogIndexMetadata(database, "build_time_utc", buildTimeUtc, &error) ||
                !SetCatalogIndexMetadata(database, "session_count", std::to_string(sessionCount), &error) ||
                !SetCatalogIndexMetadata(database, "indexed_session_count", std::to_string(indexedSessionCount), &error) ||
                !SetCatalogIndexMetadata(database, "invalid_session_count", std::to_string(invalidSessionCount), &error) ||
                !SetCatalogIndexMetadata(database, "event_count", std::to_string(eventCount), &error))
            {
                break;
            }

            if (!ExecSql(database, "COMMIT;", &error))
            {
                transactionActive = false;
                break;
            }

            transactionActive = false;
            transactionSuccess = true;
        }
        while (false);

        if (transactionActive)
        {
            std::string rollbackError;
            ExecSql(database, "ROLLBACK;", &rollbackError);
        }

        if (!transactionSuccess)
        {
            break;
        }
    }
    while (false);

    if (database != nullptr)
    {
        sqlite3_close(database);
        database = nullptr;
    }

    if (!error.empty())
    {
        return TraceIndexJson("trace-index-build", rootOption, databaseOption, false, error, sessionCount, indexedSessionCount, invalidSessionCount, eventCount, false, true, {}, {});
    }

    return TraceIndexJson("trace-index-build", rootOption, databaseOption, true, "Trace event index built.", sessionCount, indexedSessionCount, invalidSessionCount, eventCount, false, true, {}, {});
}

std::string TraceIndexQueryJson(const std::vector<std::string>& args)
{
    const std::string databaseOption = GetOption(args, "--database");
    const std::string text = GetOption(args, "--text");
    const std::string api = GetOption(args, "--api");
    const std::string module = GetOption(args, "--module");
    const std::string session = GetOption(args, "--session");
    const std::string pid = GetOption(args, "--pid");
    const std::uint32_t limit = GetUInt32Option(args, "--limit", 100);
    sqlite3* database = nullptr;
    std::string error;
    std::string rootPath;
    std::vector<KnapmTraceIndexEvent> events;
    std::uint64_t sessionCount = 0;
    std::uint64_t indexedSessionCount = 0;
    std::uint64_t invalidSessionCount = 0;
    std::uint64_t eventCount = 0;

    do
    {
        if (databaseOption.empty())
        {
            return TraceIndexJson("trace-index-query", "", "", false, "missing --database.", 0, 0, 0, 0, false, false, {}, {});
        }

        if (!OpenCatalogIndexDatabase(PathFromUtf8(databaseOption), SQLITE_OPEN_READONLY, &database, &error))
        {
            break;
        }
        if (!ValidateTraceIndexSchema(database, &error))
        {
            break;
        }

        bool rootFound = false;
        rootPath = ReadCatalogIndexMetadata(database, "root_path", &rootFound, &error);
        if (!rootFound)
        {
            rootPath.clear();
        }

        sessionCount = ReadTraceIndexMetadataUInt64(database, "session_count");
        indexedSessionCount = ReadTraceIndexMetadataUInt64(database, "indexed_session_count");
        invalidSessionCount = ReadTraceIndexMetadataUInt64(database, "invalid_session_count");
        eventCount = ReadTraceIndexMetadataUInt64(database, "event_count");

        if (!QueryTraceIndexEvents(database, text, api, module, session, pid, limit, &events, &error))
        {
            break;
        }
    }
    while (false);

    if (database != nullptr)
    {
        sqlite3_close(database);
        database = nullptr;
    }

    if (!error.empty())
    {
        return TraceIndexJson("trace-index-query", rootPath, databaseOption, false, error, sessionCount, indexedSessionCount, invalidSessionCount, eventCount, false, false, {}, events);
    }

    return TraceIndexJson("trace-index-query", rootPath, databaseOption, true, "Trace event index query completed.", sessionCount, indexedSessionCount, invalidSessionCount, eventCount, false, false, {}, events);
}

std::string TraceIndexRemoveMissingJson(const std::vector<std::string>& args)
{
    const std::string databaseOption = GetOption(args, "--database");
    const bool dryRun = HasOption(args, "--dry-run");
    sqlite3* database = nullptr;
    std::string error;
    std::string rootPath;
    std::vector<std::string> sessionPaths;
    std::vector<std::string> missingSessionPaths;
    std::uint64_t sessionCount = 0;
    std::uint64_t indexedSessionCount = 0;
    std::uint64_t invalidSessionCount = 0;
    std::uint64_t eventCount = 0;

    do
    {
        if (databaseOption.empty())
        {
            return TraceIndexJson("trace-index-remove-missing", "", "", false, "missing --database.", 0, 0, 0, 0, dryRun, false, {}, {});
        }

        if (!OpenCatalogIndexDatabase(PathFromUtf8(databaseOption), SQLITE_OPEN_READWRITE, &database, &error))
        {
            break;
        }
        if (!ValidateTraceIndexSchema(database, &error))
        {
            break;
        }

        bool rootFound = false;
        rootPath = ReadCatalogIndexMetadata(database, "root_path", &rootFound, &error);
        if (!rootFound)
        {
            rootPath.clear();
        }

        if (!ReadTraceIndexSessionPaths(database, &sessionPaths, &error))
        {
            break;
        }

        for (const std::string& path : sessionPaths)
        {
            std::error_code existsError;
            if (path.empty() || !std::filesystem::exists(PathFromUtf8(path), existsError))
            {
                missingSessionPaths.push_back(path);
            }
        }

        if (!dryRun)
        {
            if (!ExecSql(database, "BEGIN IMMEDIATE TRANSACTION;", &error))
            {
                break;
            }

            bool transactionActive = true;
            bool transactionSuccess = false;
            do
            {
                for (const std::string& path : missingSessionPaths)
                {
                    if (!DeleteTraceIndexSessionRows(database, path, &error))
                    {
                        break;
                    }
                }
                if (!error.empty())
                {
                    break;
                }

                sessionCount = sessionPaths.size() - missingSessionPaths.size();
                indexedSessionCount = sessionCount;
                invalidSessionCount = ReadTraceIndexMetadataUInt64(database, "invalid_session_count");
                SqliteStatement countStatement;
                if (!PrepareSql(database, "SELECT COUNT(*) FROM trace_events;", &countStatement, &error))
                {
                    break;
                }
                if (sqlite3_step(countStatement.Statement) == SQLITE_ROW)
                {
                    eventCount = ColumnUInt64(countStatement.Statement, 0);
                }
                else
                {
                    error = SqliteError(database);
                    break;
                }

                if (!SetCatalogIndexMetadata(database, "session_count", std::to_string(sessionCount), &error) ||
                    !SetCatalogIndexMetadata(database, "indexed_session_count", std::to_string(indexedSessionCount), &error) ||
                    !SetCatalogIndexMetadata(database, "event_count", std::to_string(eventCount), &error) ||
                    !SetCatalogIndexMetadata(database, "build_time_utc", NowUtc(), &error))
                {
                    break;
                }

                if (!ExecSql(database, "COMMIT;", &error))
                {
                    transactionActive = false;
                    break;
                }

                transactionActive = false;
                transactionSuccess = true;
            }
            while (false);

            if (transactionActive)
            {
                std::string rollbackError;
                ExecSql(database, "ROLLBACK;", &rollbackError);
            }

            if (!transactionSuccess)
            {
                break;
            }
        }

        if (dryRun)
        {
            sessionCount = ReadTraceIndexMetadataUInt64(database, "session_count");
            indexedSessionCount = ReadTraceIndexMetadataUInt64(database, "indexed_session_count");
            invalidSessionCount = ReadTraceIndexMetadataUInt64(database, "invalid_session_count");
            eventCount = ReadTraceIndexMetadataUInt64(database, "event_count");
        }
    }
    while (false);

    if (database != nullptr)
    {
        sqlite3_close(database);
        database = nullptr;
    }

    if (!error.empty())
    {
        return TraceIndexJson("trace-index-remove-missing", rootPath, databaseOption, false, error, sessionCount, indexedSessionCount, invalidSessionCount, eventCount, dryRun, !dryRun, missingSessionPaths, {});
    }

    return TraceIndexJson(
        "trace-index-remove-missing",
        rootPath,
        databaseOption,
        true,
        dryRun ? "Missing trace index rows identified." : "Missing trace index rows removed.",
        sessionCount,
        indexedSessionCount,
        invalidSessionCount,
        eventCount,
        dryRun,
        !dryRun,
        missingSessionPaths,
        {});
}

bool CatalogRowMatchesState(const KnapmCatalogRow& row, const std::string& state)
{
    if (state.empty())
    {
        return true;
    }

    return row.ValidationStatus == state || row.RecoveryState == state || row.WriterState == state;
}

bool CatalogRowMatchesTarget(const KnapmCatalogRow& row, const std::string& target)
{
    bool matched = target.empty();

    do
    {
        if (matched)
        {
            break;
        }

        char* end = nullptr;
        const unsigned long parsed = std::strtoul(target.c_str(), &end, 10);
        if (end != target.c_str() && end != nullptr && *end == '\0')
        {
            matched = row.TargetProcessId == parsed;
            break;
        }

        const std::string needle = LowerAsciiPathKey(target);
        matched =
            LowerAsciiPathKey(row.TargetImage).find(needle) != std::string::npos ||
            LowerAsciiPathKey(row.TargetPath).find(needle) != std::string::npos;
    }
    while (false);

    return matched;
}

std::string CatalogSessionsJson(const std::vector<std::string>& args)
{
    const std::string rootOption = GetOption(args, "--root");
    const std::string catalogOption = GetOption(args, "--catalog");
    std::vector<KnapmCatalogRow> rows;

    do
    {
        if (rootOption.empty())
        {
            return KnapmCatalogJson("catalog-sessions", "", catalogOption, rows, false, "missing --root.", false, false, {});
        }

        const std::filesystem::path rootPath = PathFromUtf8(rootOption);
        std::error_code rootError;
        if (!std::filesystem::exists(rootPath, rootError))
        {
            return KnapmCatalogJson("catalog-sessions", rootOption, catalogOption, rows, false, "root does not exist.", false, false, {});
        }

        const auto sessionPaths = DiscoverKnapmSessionPaths(rootPath);
        for (const std::filesystem::path& sessionPath : sessionPaths)
        {
            rows.push_back(BuildKnapmCatalogRow(sessionPath));
        }

        if (!catalogOption.empty())
        {
            std::string writeError;
            const std::string catalogJson = KnapmCatalogJson("catalog-sessions", rootOption, catalogOption, rows, true, "Catalog built.", false, true, {});
            if (!WriteTextFile(PathFromUtf8(catalogOption), catalogJson + "\n", &writeError))
            {
                return KnapmCatalogJson("catalog-sessions", rootOption, catalogOption, rows, false, writeError, false, true, {});
            }
        }
    }
    while (false);

    return KnapmCatalogJson("catalog-sessions", rootOption, catalogOption, rows, true, "Catalog built.", false, !catalogOption.empty(), {});
}

std::string CatalogQueryJson(const std::vector<std::string>& args)
{
    const std::string catalogOption = GetOption(args, "--catalog");
    std::vector<KnapmCatalogRow> rows;
    std::vector<KnapmCatalogRow> filteredRows;

    do
    {
        if (catalogOption.empty())
        {
            return KnapmCatalogJson("catalog-query", "", "", rows, false, "missing --catalog.", false, false, {});
        }

        JsonDocument catalogText;
        std::string readError;
        if (!ReadTextFile(PathFromUtf8(catalogOption), &catalogText, &readError))
        {
            return KnapmCatalogJson("catalog-query", "", catalogOption, rows, false, readError, false, false, {});
        }

        rows = KnapmCatalogRowsFromJson(catalogText);
        const std::string state = GetOption(args, "--state");
        const std::string target = GetOption(args, "--target");
        const std::uint32_t limit = GetUInt32Option(args, "--limit", 100);
        for (const KnapmCatalogRow& row : rows)
        {
            if (!CatalogRowMatchesState(row, state) || !CatalogRowMatchesTarget(row, target))
            {
                continue;
            }

            filteredRows.push_back(row);
            if (limit != 0 && filteredRows.size() >= limit)
            {
                break;
            }
        }
    }
    while (false);

    return KnapmCatalogJson(
        "catalog-query",
        "",
        catalogOption,
        filteredRows,
        true,
        "Catalog query completed.",
        false,
        false,
        {});
}

std::string CatalogRemoveMissingJson(const std::vector<std::string>& args)
{
    const std::string catalogOption = GetOption(args, "--catalog");
    const bool dryRun = HasOption(args, "--dry-run");
    std::string rootPath;
    std::vector<KnapmCatalogRow> rows;
    std::vector<KnapmCatalogRow> keptRows;
    std::vector<std::string> missingSessionPaths;

    do
    {
        if (catalogOption.empty())
        {
            return KnapmCatalogJson("catalog-remove-missing", "", "", rows, false, "missing --catalog.", dryRun, false, {});
        }

        JsonDocument catalogText;
        std::string readError;
        if (!ReadTextFile(PathFromUtf8(catalogOption), &catalogText, &readError))
        {
            return KnapmCatalogJson("catalog-remove-missing", "", catalogOption, rows, false, readError, dryRun, false, {});
        }

        rows = KnapmCatalogRowsFromJson(catalogText);
        rootPath = ExtractJsonString(catalogText, "rootPath");
        for (const KnapmCatalogRow& row : rows)
        {
            std::error_code existsError;
            if (row.SessionPath.empty() || !std::filesystem::exists(PathFromUtf8(row.SessionPath), existsError))
            {
                missingSessionPaths.push_back(row.SessionPath);
                continue;
            }

            keptRows.push_back(row);
        }

        if (!dryRun)
        {
            std::string writeError;
            const std::string catalogJson = KnapmCatalogJson(
                "catalog-remove-missing",
                rootPath,
                catalogOption,
                keptRows,
                true,
                "Missing catalog rows removed.",
                false,
                true,
                missingSessionPaths);
            if (!WriteTextFile(PathFromUtf8(catalogOption), catalogJson + "\n", &writeError))
            {
                return KnapmCatalogJson(
                    "catalog-remove-missing",
                    rootPath,
                    catalogOption,
                    rows,
                    false,
                    writeError,
                    dryRun,
                    true,
                    missingSessionPaths);
            }
        }
    }
    while (false);

    return KnapmCatalogJson(
        "catalog-remove-missing",
        rootPath,
        catalogOption,
        dryRun ? rows : keptRows,
        true,
        dryRun ? "Missing catalog rows identified." : "Missing catalog rows removed.",
        dryRun,
        !dryRun,
        missingSessionPaths);
}

std::string OperationIdFromArgs(const std::vector<std::string>& args)
{
    std::string operationId = GetOption(args, "--operation-id");

    if (operationId.empty())
    {
        operationId = NewOperationId();
    }

    return operationId;
}

std::string SessionIdFromArgs(const std::vector<std::string>& args, const std::string& operationId)
{
    std::string sessionId = GetOption(args, "--session-id");

    if (sessionId.empty())
    {
        sessionId = "session-" + SanitizeFileName(operationId);
    }

    return sessionId;
}

std::string CancellationEventNameForOperation(const std::string& operationId)
{
    return "Local\\KNMonCancel_" + SanitizeFileName(operationId);
}

std::string CancellationEventNameFromArgs(const std::vector<std::string>& args, const std::string& operationId)
{
    std::string eventName = GetOption(args, "--cancel-event");

    if (eventName.empty())
    {
        eventName = CancellationEventNameForOperation(operationId);
    }

    return eventName;
}

bool IsProcessAlive(std::uint32_t processId)
{
    bool alive = false;
    HANDLE processHandle = nullptr;

    do
    {
        if (processId == 0)
        {
            break;
        }

        processHandle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (processHandle == nullptr)
        {
            break;
        }

        alive = WaitForSingleObject(processHandle, 0) == WAIT_TIMEOUT;
    }
    while (false);

    if (processHandle != nullptr)
    {
        CloseHandle(processHandle);
    }

    return alive;
}

NativeSessionInfo BuildAttachSessionInfo(
    const std::string& sessionId,
    const std::string& operationId,
    std::uint32_t targetProcessId,
    const std::string& cancellationEventName,
    const std::string& state,
    const std::string& startedUtc)
{
    NativeSessionInfo session;
    session.SessionId = sessionId;
    session.OperationId = operationId;
    session.SessionKind = "attach_capture";
    session.OwnerProcessId = GetCurrentProcessId();
    session.HelperProcessId = GetCurrentProcessId();
    session.TargetProcessId = targetProcessId;
    session.SessionState = state;
    session.StartedUtc = startedUtc;
    session.UpdatedUtc = NowUtc();
    session.CancellationEventName = cancellationEventName;
    session.SessionProcessAlive = IsProcessAlive(session.HelperProcessId);
    session.TargetAlive = IsProcessAlive(session.TargetProcessId);
    return session;
}

NativeSessionInfo BuildSessionInfoFromCapture(const knmon::KnMonCaptureResult& result, const NativeSessionInfo& previous)
{
    NativeSessionInfo session = previous;
    if (result.TargetProcessId != 0)
    {
        session.TargetProcessId = result.TargetProcessId;
        session.TargetProcessCreationTime = result.TargetProcessCreationTime;
    }

    session.SessionState = result.SessionState.empty() ? (result.Success ? "stopped" : "failed") : result.SessionState;
    session.UpdatedUtc = result.UpdatedUtc.empty() ? NowUtc() : result.UpdatedUtc;
    if (!result.StoppedUtc.empty())
    {
        session.StoppedUtc = result.StoppedUtc;
    }
    else if (session.SessionState == "stopped" || session.SessionState == "failed" || session.SessionState == "stale" || session.SessionState == "recovery_required")
    {
        session.StoppedUtc = session.UpdatedUtc;
    }

    session.LastTransportSequence = result.LastTransportSequence;
    session.RecordsStreamed = result.RecordsStreamed;
    session.TransportDroppedEvents = result.TransportDroppedEvents;
    session.TransportAbortedRecords = result.TransportAbortedRecords;
    session.ShutdownEvidence = result.SessionShutdownEvidence;
    session.StopRequested = result.CancelRequested || result.CancelObserved;
    session.AgentCleanupAttempted = result.AgentCleanupAttempted;
    session.AgentCleanupSucceeded = result.AgentCleanupSucceeded;

    if (!result.Success && result.Operation != "operation_cancelled")
    {
        session.SessionState = "failed";
    }

    if (result.Operation == "operation_cancelled" && result.AgentCleanupSucceeded)
    {
        session.SessionState = "stopped";
    }

    session.SessionProcessAlive = IsProcessAlive(session.HelperProcessId);
    session.TargetAlive = IsProcessAlive(session.TargetProcessId);
    session.TargetExitObserved = previous.TargetExitObserved || (session.TargetProcessId != 0 && previous.TargetAlive && !session.TargetAlive);

    return session;
}

int LaunchSessionCommand(const std::vector<std::string>& args)
{
    const auto helperDir = HelperDirectory();
    const std::string defaultAgent = WideToUtf8((helperDir / DefaultAgentFileName()).wstring().c_str());
    const std::string operationId = OperationIdFromArgs(args);
    const std::string sessionId = SessionIdFromArgs(args, operationId);
    const std::string startedUtc = NowUtc();
    const std::string cancellationEventName = CancellationEventNameFromArgs(args, operationId);
    const std::string targetPath = GetOption(args, "--target");
    const std::uint32_t ownerProcessId = GetUInt32Option(args, "--owner-pid", GetCurrentProcessId());
    const bool streamBatches = HasOption(args, "--stream-batches");
    std::uint32_t batchSize = GetUInt32Option(args, "--batch-size", 64);

    if (batchSize == 0)
    {
        batchSize = 64;
    }

    NativeSessionInfo session = BuildAttachSessionInfo(
        sessionId,
        operationId,
        0,
        cancellationEventName,
        "starting",
        startedUtc);
    session.SessionKind = streamBatches ? "launch_capture_stream" : "launch_capture";
    session.OwnerProcessId = ownerProcessId;
    session.HelperProcessId = GetCurrentProcessId();

    if (targetPath.empty())
    {
        session.SessionState = "failed";
        session.LastError = "missing_target";
        session.RecoveryAction = "fix_launch_target_path";
        std::cout << SessionFrameJson("session_failed", session) << "\n";
        return 1;
    }

    knmon::KnMonLaunchRequest request;
    request.OperationId = operationId;
    request.SessionId = sessionId;
    request.SessionKind = session.SessionKind;
    request.StartedUtc = startedUtc;
    request.TargetPath = targetPath;
    request.AgentPath = GetOption(args, "--agent");
    request.WorkingDirectory = GetOption(args, "--cwd");
    request.CommandLineArguments = GetOption(args, "--args");
    request.ApiSelection = GetOption(args, "--api-selection");
    request.OwnerProcessId = ownerProcessId;
    request.OwnLaunchJob = HasOption(args, "--own-launch-job");
    const std::string ownerCreated = GetOption(args, "--owner-created");
    if (!ownerCreated.empty())
    {
        if (ownerCreated.size() > 20 || ownerCreated.find_first_not_of("0123456789") != std::string::npos)
        {
            throw std::runtime_error("Invalid owner creation time.");
        }
        request.OwnerProcessCreationTime = std::stoull(ownerCreated);
    }
    request.HelperProcessId = GetCurrentProcessId();
    request.CancellationEventName = cancellationEventName;
    request.TimeoutMs = GetUInt32Option(args, "--timeout-ms", 7000);
    request.DurationMs = GetUInt32Option(args, "--duration-ms", 0);
    request.Architecture = NativeHelperArchitecture();
    request.InjectionMethod = knmon::KnMonInjectionMethod::EarlyBirdApc;

    if (request.AgentPath.empty())
    {
        request.AgentPath = defaultAgent;
    }

    std::cout << SessionFrameJson("session_started", session) << "\n" << std::flush;
    session.SessionState = "running";
    session.UpdatedUtc = NowUtc();
    std::cout << SessionFrameJson("session_state", session) << "\n" << std::flush;

    knmon::Controller controller;
    knmon::KnMonCaptureStreamCallbacks callbacks;
    callbacks.MaxRecordsPerBatch = batchSize;
    callbacks.OnTraceBatch = [&](const knmon::KnMonTraceBatch& batch) -> bool
    {
        session.LastTransportSequence = batch.LastRecordSequence;
        session.RecordsStreamed = batch.RecordsStreamed;
        session.TransportDroppedEvents = batch.DroppedEvents;
        session.TransportAbortedRecords = batch.AbortedRecords;
        session.HostDroppedBatches = batch.HostDroppedBatches;
        session.UpdatedUtc = NowUtc();
        return WriteTraceBatchFrame(batch);
    };
    callbacks.OnSessionFrame = [&](const std::string& frameType, const knmon::KnMonCaptureResult& partialResult)
    {
        session = BuildSessionInfoFromCapture(partialResult, session);
        session.SessionState = partialResult.SessionState.empty() ? session.SessionState : partialResult.SessionState;
        std::cout << SessionFrameJson(frameType, session) << "\n" << std::flush;
    };

    const knmon::KnMonCaptureStreamCallbacks* callbackPtr = streamBatches ? &callbacks : nullptr;
    knmon::KnMonCaptureResult result = controller.LaunchCapture(request, callbackPtr);
    session = BuildSessionInfoFromCapture(result, session);

    const std::string finalFrame = session.SessionState == "failed" ? "session_failed" : "session_stopped";
    std::cout << SessionFrameJson(finalFrame, session) << "\n";

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"frameType\":\"capture_result\",";
    stream << "\"session\":" << ToJson(session) << ",";
    stream << "\"captureResult\":" << ToJson(result);
    stream << "}";
    std::cout << stream.str() << "\n";

    return 0;
}

knmon::KnMonChildPolicy ParseChildPolicy(const std::string& value)
{
    knmon::KnMonChildPolicy policy = knmon::KnMonChildPolicy::Observe;

    if (value == "attach-supported")
    {
        policy = knmon::KnMonChildPolicy::AttachSupported;
    }

    return policy;
}

std::string LaunchSampleJson(const std::vector<std::string>& args)
{
    const auto helperDir = HelperDirectory();
    const std::string defaultTarget = WideToUtf8((helperDir / L"knmon-sample-fileio.exe").wstring().c_str());
    const std::string defaultAgent = WideToUtf8((helperDir / DefaultAgentFileName()).wstring().c_str());

    knmon::KnMonLaunchRequest request;
    request.OperationId = NewOperationId();
    request.TargetPath = GetOption(args, "--target");
    request.AgentPath = GetOption(args, "--agent");
    request.WorkingDirectory = GetOption(args, "--cwd");
    request.TimeoutMs = 7000;
    request.Architecture = NativeHelperArchitecture();
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
    const std::string defaultAgent = WideToUtf8((helperDir / DefaultAgentFileName()).wstring().c_str());

    knmon::KnMonLaunchRequest request;
    request.OperationId = NewOperationId();
    request.TargetPath = GetOption(args, "--target");
    request.AgentPath = GetOption(args, "--agent");
    request.WorkingDirectory = GetOption(args, "--cwd");
    request.CommandLineArguments = GetOption(args, "--target-args");
    if (HasOption(args, "--generated-preview-probe"))
    {
        if (!request.CommandLineArguments.empty())
        {
            request.CommandLineArguments += " ";
        }

        request.CommandLineArguments += "--generated-preview-probe";
    }
    const std::string targetStartupDelay = GetOption(args, "--target-startup-delay-ms");
    if (!targetStartupDelay.empty())
    {
        if (!request.CommandLineArguments.empty())
        {
            request.CommandLineArguments += " ";
        }

        request.CommandLineArguments += "--startup-delay-ms ";
        request.CommandLineArguments += targetStartupDelay;
    }
    request.ApiSelection = GetOption(args, "--api-selection");
    request.TimeoutMs = GetUInt32Option(args, "--timeout-ms", 9000);
    request.Architecture = NativeHelperArchitecture();
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

std::string AttachCaptureJson(const std::vector<std::string>& args)
{
    const auto helperDir = HelperDirectory();
    const std::string defaultAgent = WideToUtf8((helperDir / DefaultAgentFileName()).wstring().c_str());

    knmon::KnMonAttachRequest request;
    request.OperationId = OperationIdFromArgs(args);
    const std::string pidOption = GetOption(args, "--pid");
    request.ProcessId = pidOption == "self" ? GetCurrentProcessId() : GetUInt32Option(args, "--pid", 0);
    request.AgentPath = GetOption(args, "--agent");
    request.CancellationEventName = CancellationEventNameFromArgs(args, request.OperationId);
    request.ApiSelection = GetOption(args, "--api-selection");
    request.TimeoutMs = GetUInt32Option(args, "--timeout-ms", 7000);
    request.DurationMs = GetUInt32Option(args, "--duration-ms", 3000);
    request.Architecture = NativeHelperArchitecture();
    request.InjectionMethod = knmon::KnMonInjectionMethod::RemoteLoadLibrary;

    if (request.AgentPath.empty())
    {
        request.AgentPath = defaultAgent;
    }

    knmon::Controller controller;
    knmon::KnMonCaptureResult result = controller.AttachCapture(request);

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

int AttachSessionCommand(const std::vector<std::string>& args)
{
    const auto helperDir = HelperDirectory();
    const std::string defaultAgent = WideToUtf8((helperDir / DefaultAgentFileName()).wstring().c_str());
    const std::string operationId = OperationIdFromArgs(args);
    const std::string sessionId = SessionIdFromArgs(args, operationId);
    const std::string startedUtc = NowUtc();
    const std::string cancellationEventName = CancellationEventNameFromArgs(args, operationId);
    const std::string pidOption = GetOption(args, "--pid");
    const std::string knapmPath = GetOption(args, "--write-knapm");
    const std::string knapmCompression = NormalizeKnapmCompression(GetOption(args, "--knapm-compression"));
    const std::string ownerKind = GetOption(args, "--owner-kind");
    const bool daemonOwned = ownerKind == "persistent-daemon";
    const std::uint32_t daemonProcessId = GetUInt32Option(args, "--daemon-process-id", 0);
    const std::string daemonInstanceId = GetOption(args, "--daemon-instance-id");
    const std::string daemonStartedUtc = GetOption(args, "--daemon-started-utc");
    const std::string daemonControlEndpoint = GetOption(args, "--daemon-control-endpoint");
    const bool streamBatches = HasOption(args, "--stream-batches") || !knapmPath.empty();
    std::uint32_t batchSize = GetUInt32Option(args, "--batch-size", 64);
    const std::uint32_t batchIntervalMs = GetUInt32Option(args, "--batch-interval-ms", 100);

    if (batchSize == 0)
    {
        batchSize = 64;
    }

    if (!IsSupportedKnapmCompression(knapmCompression))
    {
        NativeSessionInfo failedSession = BuildAttachSessionInfo(
            sessionId,
            operationId,
            pidOption == "self" ? GetCurrentProcessId() : GetUInt32Option(args, "--pid", 0),
            cancellationEventName,
            "failed",
            startedUtc);
        failedSession.LastError = "unsupported_compression";
        failedSession.RecoveryAction = "manual_inspection";
        std::cout << SessionFrameJson("session_failed", failedSession) << "\n";
        return 1;
    }

    (void)batchIntervalMs;

    knmon::KnMonAttachRequest request;
    request.OperationId = operationId;
    request.SessionId = sessionId;
    request.SessionKind = streamBatches ? "attach_capture_stream" : "attach_capture";
    request.StartedUtc = startedUtc;
    request.ProcessId = pidOption == "self" ? GetCurrentProcessId() : GetUInt32Option(args, "--pid", 0);
    request.OwnerProcessId = daemonOwned && daemonProcessId != 0 ? daemonProcessId : GetCurrentProcessId();
    request.HelperProcessId = GetCurrentProcessId();
    request.AgentPath = GetOption(args, "--agent");
    request.CancellationEventName = cancellationEventName;
    request.ApiSelection = GetOption(args, "--api-selection");
    request.TimeoutMs = GetUInt32Option(args, "--timeout-ms", 7000);
    request.DurationMs = GetUInt32Option(args, "--duration-ms", 0);
    request.Architecture = NativeHelperArchitecture();
    request.InjectionMethod = knmon::KnMonInjectionMethod::RemoteLoadLibrary;

    if (request.AgentPath.empty())
    {
        request.AgentPath = defaultAgent;
    }

    NativeSessionInfo session = BuildAttachSessionInfo(
        sessionId,
        operationId,
        request.ProcessId,
        cancellationEventName,
        "starting",
        startedUtc);
    session.SessionKind = daemonOwned ? "daemon_attach_capture_stream" : request.SessionKind;
    session.OwnerProcessId = request.OwnerProcessId;
    session.HelperProcessId = request.HelperProcessId;
    session.DaemonProcessId = daemonOwned ? request.OwnerProcessId : 0;
    session.DaemonInstanceId = daemonInstanceId;
    session.DaemonStartedUtc = daemonStartedUtc;
    session.DaemonHeartbeatUtc = daemonOwned ? NowUtc() : "";
    session.DaemonControlEndpoint = daemonControlEndpoint;
    session.KnapmPath = knapmPath;

    std::cout << SessionFrameJson("session_started", session) << "\n" << std::flush;
    session.SessionState = "running";
    session.UpdatedUtc = NowUtc();
    std::cout << SessionFrameJson("session_state", session) << "\n" << std::flush;

    KnapmSessionWriter knapmWriter;
    if (!knapmPath.empty())
    {
        knapmWriter.Start(PathFromUtf8(knapmPath), session, request, knapmCompression);
        if (knapmWriter.Failed)
        {
            std::cerr << "KNAPM writer failed: " << knapmWriter.Error << "\n";
        }
    }

    knmon::Controller controller;
    knmon::KnMonCaptureStreamCallbacks callbacks;
    callbacks.MaxRecordsPerBatch = batchSize;
    callbacks.OnTraceBatch = [&](const knmon::KnMonTraceBatch& batch) -> bool
    {
        session.LastTransportSequence = batch.LastRecordSequence;
        session.RecordsStreamed = batch.RecordsStreamed;
        session.TransportDroppedEvents = batch.DroppedEvents;
        session.TransportAbortedRecords = batch.AbortedRecords;
        session.HostDroppedBatches = batch.HostDroppedBatches;
        session.UpdatedUtc = NowUtc();
        const bool outputWritten = WriteTraceBatchFrame(batch);
        knapmWriter.UpdateSession(session);
        const bool stored = knapmWriter.WriteBatch(batch);
        if (!stored && !knapmWriter.Error.empty())
        {
            std::cerr << "KNAPM writer failed: " << knapmWriter.Error << "\n";
        }
        return outputWritten && stored;
    };
    callbacks.OnSessionFrame = [&](const std::string& frameType, const knmon::KnMonCaptureResult& partialResult)
    {
        session.SessionState = partialResult.SessionState.empty() ? session.SessionState : partialResult.SessionState;
        session.LastTransportSequence = partialResult.LastTransportSequence;
        session.RecordsStreamed = partialResult.RecordsStreamed;
        session.TransportDroppedEvents = partialResult.TransportDroppedEvents;
        session.TransportAbortedRecords = partialResult.TransportAbortedRecords;
        session.StopRequested = partialResult.CancelRequested || partialResult.CancelObserved;
        session.AgentCleanupAttempted = partialResult.AgentCleanupAttempted;
        session.AgentCleanupSucceeded = partialResult.AgentCleanupSucceeded;
        session.UpdatedUtc = partialResult.UpdatedUtc.empty() ? NowUtc() : partialResult.UpdatedUtc;
        knapmWriter.UpdateSession(session);
        std::cout << SessionFrameJson(frameType, session) << "\n" << std::flush;
    };

    const knmon::KnMonCaptureStreamCallbacks* callbackPtr = streamBatches ? &callbacks : nullptr;
    knmon::KnMonCaptureResult result;
    if (!knapmWriter.Failed)
    {
        result = controller.AttachCapture(request, callbackPtr);
    }
    else
    {
        result.OperationId = request.OperationId;
        result.SessionId = request.SessionId;
        result.TargetProcessId = request.ProcessId;
    }
    session = BuildSessionInfoFromCapture(result, session);
    knapmWriter.Finalize(result, session);
    if (knapmWriter.Failed && !knapmWriter.Error.empty())
    {
        std::cerr << "KNAPM writer failed: " << knapmWriter.Error << "\n";
        result.Success = false;
        result.Win32ErrorCode = ERROR_WRITE_FAULT;
        result.Operation = "session_storage_failed";
        result.OperationState = "failed";
        result.SessionState = "failed";
        result.Message = knapmWriter.Error;
        session.SessionState = "failed";
        session.LastError = knapmWriter.Error;
    }

    const std::string finalFrame = session.SessionState == "failed" ? "session_failed" : "session_stopped";
    std::cout << SessionFrameJson(finalFrame, session) << "\n";

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"frameType\":\"capture_result\",";
    stream << "\"session\":" << ToJson(session) << ",";
    stream << "\"captureResult\":" << ToJson(result);
    stream << "}";
    std::cout << stream.str() << "\n";

    return knapmWriter.Failed ? 1 : 0;
}

std::string SuperviseTreeJson(const std::vector<std::string>& args)
{
    const auto helperDir = HelperDirectory();
    const std::string defaultAgent = WideToUtf8((helperDir / DefaultAgentFileName()).wstring().c_str());

    knmon::KnMonProcessTreeRequest request;
    request.OperationId = OperationIdFromArgs(args);
    const std::string pidOption = GetOption(args, "--pid");
    request.RootProcessId = pidOption == "self" ? GetCurrentProcessId() : GetUInt32Option(args, "--pid", 0);
    request.AgentPath = GetOption(args, "--agent");
    request.CancellationEventName = CancellationEventNameFromArgs(args, request.OperationId);
    request.ApiSelection = GetOption(args, "--api-selection");
    request.TimeoutMs = GetUInt32Option(args, "--timeout-ms", 7000);
    request.DurationMs = GetUInt32Option(args, "--duration-ms", 3000);
    request.PollIntervalMs = GetUInt32Option(args, "--poll-ms", 100);
    request.Architecture = NativeHelperArchitecture();
    request.ChildPolicy = ParseChildPolicy(GetOption(args, "--child-policy"));

    if (request.AgentPath.empty())
    {
        request.AgentPath = defaultAgent;
    }

    knmon::Controller controller;
    return ToJson(controller.SuperviseProcessTree(request));
}

std::string ClassifySessionRecordJson(const std::vector<std::string>& args)
{
    const std::string sessionRecordPath = GetOption(args, "--session-record");
    JsonDocument record;
    std::string readError;
    NativeSessionInfo session;
    bool success = false;
    std::uint32_t win32ErrorCode = 0;
    std::string message;

    do
    {
        if (sessionRecordPath.empty())
        {
            win32ErrorCode = ERROR_INVALID_PARAMETER;
            message = "Missing --session-record path.";
            break;
        }

        if (!ReadTextFile(PathFromUtf8(sessionRecordPath), &record, &readError))
        {
            win32ErrorCode = ERROR_FILE_NOT_FOUND;
            message = readError;
            break;
        }

        session.SessionId = ExtractJsonString(record, "sessionId");
        session.OperationId = ExtractJsonString(record, "operationId");
        session.SessionKind = ExtractJsonString(record, "sessionKind");
        session.SessionState = ExtractJsonString(record, "sessionState");
        session.OwnerProcessId = ExtractJsonUInt32(record, "ownerProcessId");
        session.HelperProcessId = ExtractJsonUInt32(record, "helperProcessId");
        session.TargetProcessId = ExtractJsonUInt32(record, "targetProcessId");
        session.StartedUtc = ExtractJsonString(record, "startedUtc");
        session.UpdatedUtc = NowUtc();
        session.CancellationEventName = ExtractJsonString(record, "cancellationEventName");
        session.LastTransportSequence = ExtractJsonUInt64(record, "lastTransportSequence");
        session.RecordsStreamed = ExtractJsonUInt64(record, "recordsStreamed");

        const bool runningState = session.SessionState == "running" || session.SessionState == "starting" || session.SessionState == "stop_requested";
        const bool ownerAlive = IsProcessAlive(session.OwnerProcessId);
        const bool helperAlive = IsProcessAlive(session.HelperProcessId);
        const bool targetAlive = IsProcessAlive(session.TargetProcessId);

        if (runningState && !ownerAlive && !helperAlive)
        {
            if (targetAlive)
            {
                session.SessionState = "recovery_required";
                session.StaleReason = "owner_missing_target_alive";
                session.RecoveryAction = "manual_same_bitness_cleanup_required";
            }
            else
            {
                session.SessionState = "stale";
                session.StaleReason = "owner_missing_target_exited";
                session.RecoveryAction = "none";
            }
        }
        else
        {
            session.StaleReason = "owner_observed_or_terminal_state";
            session.RecoveryAction = "none";
        }

        success = true;
        message = "Session record classified without target mutation.";
    }
    while (false);

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (success ? "true" : "false") << ",";
    stream << "\"backendMode\":\"native-capture\",";
    stream << "\"operation\":\"classify_session_record\",";
    stream << "\"win32ErrorCode\":" << win32ErrorCode << ",";
    stream << "\"mutationAttempted\":false,";
    stream << "\"session\":" << ToJson(session) << ",";
    stream << "\"message\":" << Q(message);
    stream << "}";
    return stream.str();
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

    const auto windowText = GetOption(args, "--window-limit");
    if (!windowText.empty() && (windowText.size() > 4 || windowText.find_first_not_of("0123456789") != std::string::npos))
    {
        throw JsonInputError("Invalid replay window limit.");
    }
    const auto windowLimit = GetUInt32Option(args, "--window-limit", 0);
    if (windowLimit > 5000)
    {
        throw JsonInputError("Replay window limit exceeds 5000 events.");
    }
    const auto selected = GetOption(args, "--selected-event-id");
    std::uint64_t selectedEventId = 0;
    if (!selected.empty())
    {
        if (windowLimit == 0 || selected.size() > 20 || selected.find_first_not_of("0123456789") != std::string::npos)
        {
            throw JsonInputError("Invalid selected replay event ID.");
        }
        selectedEventId = std::stoull(selected);
    }
    return ReplaySessionJson(PathFromUtf8(sessionPath), windowLimit, selectedEventId);
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

    return ToJson(ValidateSessionPath(PathFromUtf8(sessionPath)));
}

std::string CancelOperationJson(const std::vector<std::string>& args)
{
    const std::string operationId = GetOption(args, "--operation-id");
    const std::string eventName = operationId.empty() ? GetOption(args, "--cancel-event") : CancellationEventNameFromArgs(args, operationId);
    bool success = false;
    DWORD errorCode = 0;
    std::string message;

    do
    {
        if (operationId.empty() && eventName.empty())
        {
            errorCode = ERROR_INVALID_PARAMETER;
            message = "Missing --operation-id or --cancel-event.";
            break;
        }

        const std::wstring wideEventName = Utf8ToWide(eventName);
        if (wideEventName.empty())
        {
            errorCode = ERROR_INVALID_PARAMETER;
            message = "Cancellation event name is invalid.";
            break;
        }

        HANDLE eventHandle = OpenEventW(EVENT_MODIFY_STATE, FALSE, wideEventName.c_str());
        if (eventHandle == nullptr)
        {
            errorCode = GetLastError();
            message = "Cancellation event is not available.";
            break;
        }

        if (!SetEvent(eventHandle))
        {
            errorCode = GetLastError();
            CloseHandle(eventHandle);
            message = "Failed to signal cancellation event.";
            break;
        }

        CloseHandle(eventHandle);
        success = true;
        message = "Cancellation signal set.";
    }
    while (false);

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (success ? "true" : "false") << ",";
    stream << "\"backendMode\":\"native-capture\",";
    stream << "\"operationId\":" << Q(operationId) << ",";
    stream << "\"cancellationEventName\":" << Q(eventName) << ",";
    stream << "\"win32ErrorCode\":" << errorCode << ",";
    stream << "\"ntStatus\":\"0x00000000\",";
    stream << "\"subsystem\":\"knmon-native-helper\",";
    stream << "\"operation\":\"cancel_operation\",";
    stream << "\"message\":" << Q(message);
    stream << "}";
    return stream.str();
}

struct DaemonStatusInfo
{
    bool Success = false;
    std::string BackendMode = "native-capture";
    std::string Operation = "daemon_status";
    std::string DaemonState = "not_running";
    std::uint32_t DaemonProcessId = 0;
    std::string DaemonInstanceId;
    std::string DaemonStartedUtc;
    std::string DaemonHeartbeatUtc;
    std::string ControlEndpoint;
    std::string RuntimeDirectory;
    std::uint64_t SessionCount = 0;
    std::uint32_t Win32ErrorCode = 0;
    std::string Message;
};

struct DaemonSessionRecord
{
    std::string SessionId;
    std::string OperationId;
    std::uint32_t TargetProcessId = 0;
    std::uint32_t DaemonProcessId = 0;
    std::string DaemonInstanceId;
    std::string DaemonStartedUtc;
    std::string DaemonControlEndpoint;
    std::uint32_t SessionProcessId = 0;
    std::string KnapmPath;
    std::string CancellationEventName;
    std::string StartedUtc;
    std::uint32_t DurationMs = 0;
    std::filesystem::path RegistryPath;
    bool RegistryMalformed = false;
    std::string RegistryError;
};

struct DaemonRecoveryPlanItem
{
    std::string SessionId;
    std::string RecoveryState;
    std::string RecoveryReason;
    std::string RecommendedAction;
    std::string SafetyState = "dry_run_only";
    bool AutomaticRecoveryAllowed = false;
    bool TargetMutationAllowed = false;
    bool RegistryPruneAllowed = false;
    bool ReplayAllowed = false;
    std::vector<std::string> BlockedMutations;
    std::vector<std::string> OperatorRunbook;
    std::string Message;
};

std::string ToJson(const DaemonStatusInfo& status)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (status.Success ? "true" : "false") << ",";
    stream << "\"backendMode\":" << Q(status.BackendMode) << ",";
    stream << "\"operation\":" << Q(status.Operation) << ",";
    stream << "\"daemonState\":" << Q(status.DaemonState) << ",";
    stream << "\"daemonProcessId\":" << status.DaemonProcessId << ",";
    stream << "\"daemonInstanceId\":" << Q(status.DaemonInstanceId) << ",";
    stream << "\"daemonStartedUtc\":" << Q(status.DaemonStartedUtc) << ",";
    stream << "\"daemonHeartbeatUtc\":" << Q(status.DaemonHeartbeatUtc) << ",";
    stream << "\"controlEndpoint\":" << Q(status.ControlEndpoint) << ",";
    stream << "\"runtimeDirectory\":" << Q(status.RuntimeDirectory) << ",";
    stream << "\"sessionCount\":" << status.SessionCount << ",";
    stream << "\"win32ErrorCode\":" << status.Win32ErrorCode << ",";
    stream << "\"message\":" << Q(status.Message);
    stream << "}";
    return stream.str();
}

std::string ToJson(const DaemonSessionRecord& record)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"sessionId\":" << Q(record.SessionId) << ",";
    stream << "\"operationId\":" << Q(record.OperationId) << ",";
    stream << "\"targetProcessId\":" << record.TargetProcessId << ",";
    stream << "\"daemonProcessId\":" << record.DaemonProcessId << ",";
    stream << "\"daemonInstanceId\":" << Q(record.DaemonInstanceId) << ",";
    stream << "\"daemonStartedUtc\":" << Q(record.DaemonStartedUtc) << ",";
    stream << "\"daemonControlEndpoint\":" << Q(record.DaemonControlEndpoint) << ",";
    stream << "\"sessionProcessId\":" << record.SessionProcessId << ",";
    stream << "\"knapmPath\":" << Q(record.KnapmPath) << ",";
    stream << "\"cancellationEventName\":" << Q(record.CancellationEventName) << ",";
    stream << "\"startedUtc\":" << Q(record.StartedUtc) << ",";
    stream << "\"durationMs\":" << record.DurationMs;
    stream << "}";
    return stream.str();
}

std::string ToJson(const DaemonRecoveryPlanItem& plan)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"sessionId\":" << Q(plan.SessionId) << ",";
    stream << "\"recoveryState\":" << Q(plan.RecoveryState) << ",";
    stream << "\"recoveryReason\":" << Q(plan.RecoveryReason) << ",";
    stream << "\"recommendedAction\":" << Q(plan.RecommendedAction) << ",";
    stream << "\"safetyState\":" << Q(plan.SafetyState) << ",";
    stream << "\"automaticRecoveryAllowed\":" << (plan.AutomaticRecoveryAllowed ? "true" : "false") << ",";
    stream << "\"targetMutationAllowed\":" << (plan.TargetMutationAllowed ? "true" : "false") << ",";
    stream << "\"registryPruneAllowed\":" << (plan.RegistryPruneAllowed ? "true" : "false") << ",";
    stream << "\"replayAllowed\":" << (plan.ReplayAllowed ? "true" : "false") << ",";
    stream << "\"blockedMutations\":" << JsonStringArray(plan.BlockedMutations) << ",";
    stream << "\"operatorRunbook\":" << JsonStringArray(plan.OperatorRunbook) << ",";
    stream << "\"message\":" << Q(plan.Message);
    stream << "}";
    return stream.str();
}

std::filesystem::path DaemonRuntimeDirectoryFromArgs(const std::vector<std::string>& args)
{
    std::filesystem::path directory;
    const std::string runtimeDir = GetOption(args, "--runtime-dir");

    if (!runtimeDir.empty())
    {
        directory = PathFromUtf8(runtimeDir);
    }
    else
    {
        // current_path() throws when the working directory was deleted; fall back
        // to the helper executable directory instead of crashing the CLI.
        std::error_code currentError;
        const std::filesystem::path current = std::filesystem::current_path(currentError);
        directory = currentError ? HelperDirectory() / L".tmp" / L"daemon" : current / L".tmp" / L"daemon";
    }

    std::error_code pathError;
    const std::filesystem::path absolute = std::filesystem::absolute(directory, pathError);
    if (!pathError)
    {
        directory = absolute;
    }

    return directory;
}

std::filesystem::path DaemonStatePath(const std::filesystem::path& runtimeDirectory)
{
    return runtimeDirectory / L"daemon-state.json";
}

std::filesystem::path DaemonStopFlagPath(const std::filesystem::path& runtimeDirectory)
{
    return runtimeDirectory / L"daemon-stop.flag";
}

std::filesystem::path DaemonSessionsDirectory(const std::filesystem::path& runtimeDirectory)
{
    return runtimeDirectory / L"sessions";
}

std::filesystem::path DaemonLogsDirectory(const std::filesystem::path& runtimeDirectory)
{
    return runtimeDirectory / L"logs";
}

std::filesystem::path DaemonSessionRecordPath(const std::filesystem::path& runtimeDirectory, const std::string& sessionId)
{
    return DaemonSessionsDirectory(runtimeDirectory) / PathFromUtf8(SanitizeFileName(sessionId) + ".json");
}

std::string DaemonControlEndpoint(const std::filesystem::path& runtimeDirectory)
{
    return "file-registry:" + PathToUtf8(runtimeDirectory);
}

std::uint64_t CountDaemonSessionRecords(const std::filesystem::path& runtimeDirectory)
{
    std::uint64_t count = 0;
    std::error_code iterateError;
    const std::filesystem::path sessionsDirectory = DaemonSessionsDirectory(runtimeDirectory);

    if (!std::filesystem::exists(sessionsDirectory, iterateError))
    {
        return count;
    }

    // Manual increment(error) loop: the throwing range-for increment and
    // is_regular_file() would terminate the helper when files disappear mid-scan.
    std::filesystem::directory_iterator iterator(sessionsDirectory, iterateError);
    for (; !iterateError && iterator != std::filesystem::directory_iterator(); iterator.increment(iterateError))
    {
        std::error_code entryError;
        if (iterator->is_regular_file(entryError) && !entryError && iterator->path().extension() == L".json")
        {
            ++count;
        }
    }

    return count;
}

DaemonStatusInfo DaemonStatusFromJson(const JsonDocument& json)
{
    DaemonStatusInfo status;
    status.Success = ExtractJsonBool(json, "success");
    status.BackendMode = ExtractJsonString(json, "backendMode");
    status.Operation = ExtractJsonString(json, "operation");
    status.DaemonState = ExtractJsonString(json, "daemonState");
    status.DaemonProcessId = ExtractJsonUInt32(json, "daemonProcessId");
    status.DaemonInstanceId = ExtractJsonString(json, "daemonInstanceId");
    status.DaemonStartedUtc = ExtractJsonString(json, "daemonStartedUtc");
    status.DaemonHeartbeatUtc = ExtractJsonString(json, "daemonHeartbeatUtc");
    status.ControlEndpoint = ExtractJsonString(json, "controlEndpoint");
    status.RuntimeDirectory = ExtractJsonString(json, "runtimeDirectory");
    status.SessionCount = ExtractJsonUInt64(json, "sessionCount");
    status.Win32ErrorCode = ExtractJsonUInt32(json, "win32ErrorCode");
    status.Message = ExtractJsonString(json, "message");
    return status;
}

DaemonSessionRecord DaemonSessionRecordFromJson(const JsonDocument& json)
{
    DaemonSessionRecord record;
    record.SessionId = ExtractJsonString(json, "sessionId");
    record.OperationId = ExtractJsonString(json, "operationId");
    record.TargetProcessId = ExtractJsonUInt32(json, "targetProcessId");
    record.DaemonProcessId = ExtractJsonUInt32(json, "daemonProcessId");
    record.DaemonInstanceId = ExtractJsonString(json, "daemonInstanceId");
    record.DaemonStartedUtc = ExtractJsonString(json, "daemonStartedUtc");
    record.DaemonControlEndpoint = ExtractJsonString(json, "daemonControlEndpoint");
    record.SessionProcessId = ExtractJsonUInt32(json, "sessionProcessId");
    record.KnapmPath = ExtractJsonString(json, "knapmPath");
    record.CancellationEventName = ExtractJsonString(json, "cancellationEventName");
    record.StartedUtc = ExtractJsonString(json, "startedUtc");
    record.DurationMs = ExtractJsonUInt32(json, "durationMs");
    return record;
}

DaemonStatusInfo ReadDaemonStatus(const std::filesystem::path& runtimeDirectory)
{
    DaemonStatusInfo status;
    status.RuntimeDirectory = PathToUtf8(runtimeDirectory);
    status.ControlEndpoint = DaemonControlEndpoint(runtimeDirectory);
    status.SessionCount = CountDaemonSessionRecords(runtimeDirectory);

    try
    {
        do
        {
            JsonDocument text;
            std::string readError;
            if (!ReadTextFile(DaemonStatePath(runtimeDirectory), &text, &readError))
            {
                status.Success = false;
                status.Win32ErrorCode = ERROR_FILE_NOT_FOUND;
                status.Message = "Daemon state is not available.";
                break;
            }

            status = DaemonStatusFromJson(text);
            status.RuntimeDirectory = PathToUtf8(runtimeDirectory);
            status.ControlEndpoint = DaemonControlEndpoint(runtimeDirectory);
            status.SessionCount = CountDaemonSessionRecords(runtimeDirectory);
            const bool alive = IsProcessAlive(status.DaemonProcessId);
            status.Success = alive && status.DaemonState == "running";
            if (status.DaemonState == "running" && !alive)
            {
                status.DaemonState = "stale";
                status.Win32ErrorCode = ERROR_PROCESS_ABORTED;
                status.Message = "Daemon state is stale; daemon process is not alive.";
            }
        }
        while (false);
    }
    catch (const std::exception& exception)
    {
        status.Success = false;
        status.Win32ErrorCode = ERROR_INVALID_DATA;
        status.Message = exception.what();
    }

    return status;
}

bool WriteDaemonStatus(const std::filesystem::path& runtimeDirectory, const DaemonStatusInfo& status, std::string* error)
{
    return WriteTextFile(DaemonStatePath(runtimeDirectory), ToJson(status) + "\n", error);
}

bool WriteDaemonSessionRecord(const std::filesystem::path& runtimeDirectory, const DaemonSessionRecord& record, std::string* error)
{
    return WriteTextFile(DaemonSessionRecordPath(runtimeDirectory, record.SessionId), ToJson(record) + "\n", error);
}

bool ReadDaemonSessionRecord(const std::filesystem::path& runtimeDirectory, const std::string& sessionId, DaemonSessionRecord* record, std::string* error)
{
    bool read = false;

    try
    {
        do
        {
            if (record == nullptr)
            {
                if (error != nullptr)
                {
                    *error = "record output is null.";
                }
                break;
            }

            JsonDocument text;
            if (!ReadTextFile(DaemonSessionRecordPath(runtimeDirectory, sessionId), &text, error))
            {
                break;
            }

            *record = DaemonSessionRecordFromJson(text);
            record->RegistryPath = DaemonSessionRecordPath(runtimeDirectory, sessionId);
            read = !record->SessionId.empty();
            if (!read && error != nullptr)
            {
                *error = "session record is malformed.";
            }
        }
        while (false);
    }
    catch (const std::exception& exception)
    {
        read = false;
        if (error != nullptr)
        {
            *error = exception.what();
        }
    }

    return read;
}

std::wstring QuoteWindowsCommandArg(const std::wstring& value)
{
    if (value.empty())
    {
        return L"\"\"";
    }

    bool needsQuotes = false;
    for (const wchar_t ch : value)
    {
        if (ch == L' ' || ch == L'\t' || ch == L'"')
        {
            needsQuotes = true;
            break;
        }
    }

    if (!needsQuotes)
    {
        return value;
    }

    std::wstring result = L"\"";
    std::size_t backslashCount = 0;
    for (const wchar_t ch : value)
    {
        if (ch == L'\\')
        {
            ++backslashCount;
            continue;
        }

        if (ch == L'"')
        {
            result.append(backslashCount * 2 + 1, L'\\');
            result.push_back(ch);
            backslashCount = 0;
            continue;
        }

        if (backslashCount != 0)
        {
            result.append(backslashCount, L'\\');
            backslashCount = 0;
        }

        result.push_back(ch);
    }

    if (backslashCount != 0)
    {
        result.append(backslashCount * 2, L'\\');
    }

    result.push_back(L'"');
    return result;
}

bool LaunchBackgroundHelper(
    const std::vector<std::string>& args,
    const std::filesystem::path& stdoutPath,
    const std::filesystem::path& stderrPath,
    std::uint32_t* processId,
    std::string* error)
{
    bool launched = false;
    PROCESS_INFORMATION processInfo = {};
    HANDLE nullStream = INVALID_HANDLE_VALUE;
    STARTUPINFOEXW startupInfo = {};
    std::vector<unsigned char> attributeStorage;
    bool attributesInitialized = false;
    // Background sessions persist KNAPM directly; their console streams are sinks.
    (void)stdoutPath;
    (void)stderrPath;

    do
    {
        const std::filesystem::path executable = CurrentExecutablePath();
        if (executable.empty())
        {
            if (error != nullptr)
            {
                *error = "current executable path is unavailable.";
            }
            break;
        }

        std::wstring commandLine = QuoteWindowsCommandArg(executable.wstring());
        for (const std::string& arg : args)
        {
            commandLine.push_back(L' ');
            commandLine += QuoteWindowsCommandArg(Utf8ToWide(arg));
        }

        std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
        mutableCommandLine.push_back(L'\0');

        SECURITY_ATTRIBUTES security = { sizeof(security), nullptr, TRUE };
        nullStream = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        SIZE_T attributeBytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeBytes);
        attributeStorage.resize(attributeBytes);
        startupInfo.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributeStorage.data());
        if (nullStream == INVALID_HANDLE_VALUE || attributeBytes == 0 ||
            !InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, &attributeBytes))
        {
            if (error != nullptr)
            {
                *error = "Background standard-handle initialization failed.";
            }
            break;
        }
        attributesInitialized = true;
        if (!UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            &nullStream, sizeof(nullStream), nullptr, nullptr))
        {
            if (error != nullptr)
            {
                *error = "Background handle inheritance restriction failed.";
            }
            break;
        }
        startupInfo.StartupInfo.cb = sizeof(startupInfo);
        startupInfo.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startupInfo.StartupInfo.hStdInput = nullStream;
        startupInfo.StartupInfo.hStdOutput = nullStream;
        startupInfo.StartupInfo.hStdError = nullStream;

        const BOOL created = CreateProcessW(
            nullptr,
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            nullptr,
            HelperDirectory().wstring().c_str(),
            &startupInfo.StartupInfo,
            &processInfo);
        if (!created)
        {
            if (error != nullptr)
            {
                *error = "CreateProcessW failed with " + std::to_string(GetLastError()) + ".";
            }
            break;
        }

        if (processId != nullptr)
        {
            *processId = processInfo.dwProcessId;
        }
        launched = true;
    }
    while (false);

    if (attributesInitialized)
    {
        DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
    }
    if (nullStream != INVALID_HANDLE_VALUE)
    {
        CloseHandle(nullStream);
    }
    if (processInfo.hThread != nullptr)
    {
        CloseHandle(processInfo.hThread);
    }

    if (processInfo.hProcess != nullptr)
    {
        CloseHandle(processInfo.hProcess);
    }

    return launched;
}

bool WaitForDaemonRunning(const std::filesystem::path& runtimeDirectory, DWORD timeoutMs, DaemonStatusInfo* status)
{
    const ULONGLONG start = GetTickCount64();
    bool running = false;

    do
    {
        DaemonStatusInfo current = ReadDaemonStatus(runtimeDirectory);
        if (current.Success)
        {
            if (status != nullptr)
            {
                *status = current;
            }
            running = true;
            break;
        }

        if (GetTickCount64() - start >= timeoutMs)
        {
            if (status != nullptr)
            {
                *status = current;
            }
            break;
        }

        Sleep(50);
    }
    while (true);

    return running;
}

bool WaitForKnapmOwnerKind(const std::filesystem::path& knapmPath, const std::string& ownerKind, DWORD timeoutMs)
{
    const ULONGLONG start = GetTickCount64();
    bool matched = false;

    do
    {
        JsonDocument manifest;
        std::string readError;
        if (ReadTextFile(KnapmChildPath(knapmPath, "manifest.json"), &manifest, &readError))
        {
            const JsonDocument ownerObject = ExtractJsonObject(manifest, "owner");
            if (ExtractJsonString(ownerObject, "ownerKind") == ownerKind)
            {
                matched = true;
                break;
            }
        }

        if (GetTickCount64() - start >= timeoutMs)
        {
            break;
        }

        Sleep(50);
    }
    while (true);

    return matched;
}

NativeSessionInfo NativeSessionFromDaemonRecord(const DaemonSessionRecord& record)
{
    NativeSessionInfo session;
    session.SessionId = record.SessionId;
    session.OperationId = record.OperationId;
    session.SessionKind = "daemon_attach_capture_stream";
    session.OwnerProcessId = record.DaemonProcessId;
    session.HelperProcessId = record.SessionProcessId;
    session.TargetProcessId = record.TargetProcessId;
    session.SessionState = IsProcessAlive(record.SessionProcessId) ? "running" : "recovery_required";
    session.StartedUtc = record.StartedUtc;
    session.UpdatedUtc = NowUtc();
    session.CancellationEventName = record.CancellationEventName;
    session.RecoveryAction = session.SessionState == "recovery_required" ? "manual_inspection" : "wait";
    session.DaemonProcessId = record.DaemonProcessId;
    session.DaemonInstanceId = record.DaemonInstanceId;
    session.DaemonStartedUtc = record.DaemonStartedUtc;
    session.DaemonHeartbeatUtc = NowUtc();
    session.DaemonControlEndpoint = record.DaemonControlEndpoint;
    session.KnapmPath = record.KnapmPath;
    session.DurationMs = record.DurationMs;
    session.DaemonAlive = IsProcessAlive(record.DaemonProcessId);
    session.SessionProcessAlive = IsProcessAlive(record.SessionProcessId);
    session.TargetAlive = IsProcessAlive(record.TargetProcessId);
    session.KnapmExists = false;
    session.KnapmValid = false;
    bool finalized = false;
    std::string manifestSessionState;

    do
    {
        if (record.RegistryMalformed)
        {
            session.SessionState = "failed";
            session.StaleReason = record.RegistryError.empty() ? "daemon_registry_malformed" : record.RegistryError;
            session.RecoveryState = "malformed";
            session.RecoveryReason = session.StaleReason;
            session.RecoveryAction = "manual_inspection";
            session.PruneEligible = !session.SessionProcessAlive && !session.TargetAlive;
            session.PruneReason = session.PruneEligible ? "malformed_registry_terminal" : "";
            break;
        }

        if (record.KnapmPath.empty())
        {
            session.SessionState = "failed";
            session.StaleReason = "knapm_path_missing";
            session.RecoveryState = "malformed";
            session.RecoveryReason = "knapm_path_missing";
            session.RecoveryAction = "manual_inspection";
            session.PruneEligible = !session.SessionProcessAlive && !session.TargetAlive;
            session.PruneReason = session.PruneEligible ? "missing_knapm_path_terminal" : "";
            break;
        }

        const std::filesystem::path knapmPath = PathFromUtf8(record.KnapmPath);
        std::error_code existsError;
        session.KnapmExists = std::filesystem::exists(knapmPath, existsError);
        if (!session.KnapmExists)
        {
            session.SessionState = session.SessionProcessAlive ? "running" : "recovery_required";
            session.StaleReason = "knapm_path_not_found";
            session.RecoveryState = session.SessionProcessAlive ? "healthy" : "malformed";
            session.RecoveryReason = "knapm_path_not_found";
            session.RecoveryAction = session.SessionProcessAlive ? "wait" : "manual_inspection";
            session.PruneEligible = !session.SessionProcessAlive;
            session.PruneReason = session.PruneEligible ? "missing_knapm_record" : "";
            break;
        }

        JsonDocument manifest;
        std::string readError;
        if (!ReadTextFile(KnapmChildPath(knapmPath, "manifest.json"), &manifest, &readError))
        {
            break;
        }

        const JsonDocument sessionObject = ExtractJsonObject(manifest, "session");
        if (sessionObject.empty())
        {
            break;
        }
        try
        {
            ValidateManifestTypes(manifest, true);
            if (manifest.String("format", true) != "knapm" || manifest.String("sessionId", true) != record.SessionId ||
                manifest.String("operationId", true) != record.OperationId ||
                sessionObject.String("sessionId", true) != record.SessionId ||
                sessionObject.String("operationId", true) != record.OperationId ||
                sessionObject.UInt32("targetProcessId", true) != record.TargetProcessId)
            {
                throw JsonInputError("Daemon manifest identity differs from its registry record.");
            }
        }
        catch (const std::exception& exception)
        {
            session.SessionState = "failed";
            session.RecoveryState = "malformed";
            session.RecoveryReason = "manifest_invalid";
            session.RecoveryAction = "manual_inspection";
            session.LastError = exception.what();
            break;
        }

        const std::string sessionState = ExtractJsonString(sessionObject, "sessionState");
        if (!sessionState.empty())
        {
            session.SessionState = sessionState;
            manifestSessionState = sessionState;
        }

        session.LastTransportSequence = ExtractJsonUInt64(sessionObject, "lastTransportSequence");
        session.RecordsStreamed = ExtractJsonUInt64(sessionObject, "recordsStreamed");
        session.TransportDroppedEvents = ExtractJsonUInt64(sessionObject, "transportDroppedEvents");
        session.TransportAbortedRecords = ExtractJsonUInt64(sessionObject, "transportAbortedRecords");
        session.HostDroppedBatches = ExtractJsonUInt64(sessionObject, "hostDroppedBatches");
        session.StopRequested = ExtractJsonBool(sessionObject, "stopRequested");
        session.AgentCleanupAttempted = ExtractJsonBool(sessionObject, "agentCleanupAttempted");
        session.AgentCleanupSucceeded = ExtractJsonBool(sessionObject, "agentCleanupSucceeded");
        session.LastError = sessionObject.String("lastError");
        if (session.LastError.empty())
        {
            session.LastError = manifest.String("writerError");
        }
        session.ShutdownEvidence = ExtractJsonString(sessionObject, "shutdownEvidence");
        session.StoppedUtc = ExtractJsonString(sessionObject, "stoppedUtc");
        session.DaemonHeartbeatUtc = ExtractJsonString(sessionObject, "daemonHeartbeatUtc");
        if (session.DaemonHeartbeatUtc.empty())
        {
            session.DaemonHeartbeatUtc = NowUtc();
        }

        finalized = manifest.Bool("finalized", true);
        if (!finalized && session.DaemonAlive && session.SessionProcessAlive && session.TargetAlive &&
            manifest.String("writerState") != "failed" &&
            (session.SessionState == "running" || session.SessionState == "created" ||
                session.SessionState == "stopping_agent" || session.SessionState == "draining"))
        {
            // Progress is a manifest snapshot, not a full replay-integrity claim.
            session.KnapmValid = false;
            session.RecoveryState = "healthy";
            session.RecoveryReason = "writer_active_integrity_pending";
            session.RecoveryAction = "wait";
            break;
        }

        const SessionInfo validation = ValidateSessionPath(knapmPath);
        session.KnapmValid = validation.Success;
        finalized = validation.Finalized;
        if (!validation.Success)
        {
            session.SessionState = "failed";
            session.StaleReason = "knapm_validation_failed";
            session.RecoveryState = "malformed";
            session.RecoveryReason = "knapm_validation_failed";
            session.RecoveryAction = "manual_inspection";
            session.PruneEligible = !session.SessionProcessAlive && !session.TargetAlive;
            session.PruneReason = session.PruneEligible ? "invalid_knapm_terminal" : "";
            break;
        }
    }
    while (false);

    if (session.RecoveryState.empty())
    {
        if (finalized || manifestSessionState == "stopped" || manifestSessionState == "failed")
        {
            session.SessionState = "stopped";
            session.RecoveryState = "finalized";
            session.RecoveryReason = finalized ? "finalized" : "terminal_session_state";
            session.RecoveryAction = "none";
            session.PruneEligible = !session.SessionProcessAlive;
            session.PruneReason = session.PruneEligible ? "finalized_record" : "";
        }
        else if (record.TargetProcessId != 0 && !session.TargetAlive)
        {
            session.SessionState = "stale";
            session.StaleReason = "target_exited";
            session.RecoveryState = "stale";
            session.RecoveryReason = "target_exited";
            session.RecoveryAction = "replay_only";
            session.PruneEligible = !session.SessionProcessAlive;
            session.PruneReason = session.PruneEligible ? "target_exited" : "";
        }
        else if (!session.DaemonAlive && session.SessionProcessAlive)
        {
            session.SessionState = "running";
            session.StaleReason = "daemon_process_exited";
            session.RecoveryState = "daemon_crashed";
            session.RecoveryReason = "daemon_dead_writer_alive";
            session.RecoveryAction = "manual_inspection";
        }
        else if (!session.SessionProcessAlive && session.TargetAlive)
        {
            session.SessionState = "recovery_required";
            session.StaleReason = session.DaemonAlive ? "session_writer_exited" : "daemon_and_writer_exited";
            session.RecoveryState = session.DaemonAlive ? "writer_crashed" : "orphaned_agent_risk";
            session.RecoveryReason = session.DaemonAlive ? "session_writer_dead_target_alive" : "daemon_and_writer_dead_target_alive";
            session.RecoveryAction = "manual_inspection";
            session.PruneEligible = true;
            session.PruneReason = session.DaemonAlive ? "writer_dead_registry_stale" : "orphaned_agent_registry_stale";
        }
        else if (session.DaemonAlive && session.SessionProcessAlive && session.TargetAlive && session.KnapmValid)
        {
            session.SessionState = "running";
            session.RecoveryState = "healthy";
            session.RecoveryReason = "owned";
            session.RecoveryAction = "wait";
        }
        else
        {
            session.SessionState = "stale";
            session.StaleReason = "daemon_registry_stale";
            session.RecoveryState = "stale";
            session.RecoveryReason = "registry_stale";
            session.RecoveryAction = "manual_inspection";
            session.PruneEligible = !session.SessionProcessAlive;
            session.PruneReason = session.PruneEligible ? "registry_stale" : "";
        }
    }

    return session;
}

std::vector<DaemonSessionRecord> ReadAllDaemonSessionRecords(const std::filesystem::path& runtimeDirectory)
{
    std::vector<DaemonSessionRecord> records;
    std::error_code iterateError;
    const std::filesystem::path sessionsDirectory = DaemonSessionsDirectory(runtimeDirectory);

    if (!std::filesystem::exists(sessionsDirectory, iterateError))
    {
        return records;
    }

    // Manual increment(error) loop: the throwing range-for increment and
    // is_regular_file() would terminate the helper when files disappear mid-scan.
    std::filesystem::directory_iterator iterator(sessionsDirectory, iterateError);
    for (; !iterateError && iterator != std::filesystem::directory_iterator(); iterator.increment(iterateError))
    {
        std::error_code entryError;
        if (!iterator->is_regular_file(entryError) || entryError || iterator->path().extension() != L".json")
        {
            continue;
        }

        const std::filesystem::path entryPath = iterator->path();
        JsonDocument text;
        std::string readError;
        if (ReadTextFile(entryPath, &text, &readError))
        {
            DaemonSessionRecord record;
            try
            {
                record = DaemonSessionRecordFromJson(text);
            }
            catch (const JsonInputError& exception)
            {
                record.SessionId = PathToUtf8(entryPath.stem());
                record.RegistryMalformed = true;
                record.RegistryError = exception.what();
            }
            record.RegistryPath = entryPath;
            if (record.SessionId.empty())
            {
                record.SessionId = PathToUtf8(entryPath.stem());
                record.RegistryMalformed = true;
                record.RegistryError = "session_id_missing";
            }

            if (record.OperationId.empty() || record.TargetProcessId == 0 || record.SessionProcessId == 0 || record.KnapmPath.empty())
            {
                record.RegistryMalformed = true;
                if (record.RegistryError.empty())
                {
                    record.RegistryError = "required_field_missing";
                }
            }

            records.push_back(record);
        }
        else
        {
            DaemonSessionRecord record;
            record.SessionId = PathToUtf8(entryPath.stem());
            record.RegistryPath = entryPath;
            record.RegistryMalformed = true;
            record.RegistryError = readError.empty() ? "registry_read_failed" : readError;
            records.push_back(record);
        }
    }

    return records;
}

DaemonStatusInfo StartDaemonIfNeeded(const std::filesystem::path& runtimeDirectory)
{
    DaemonStatusInfo status = ReadDaemonStatus(runtimeDirectory);

    do
    {
        if (status.Success)
        {
            break;
        }

        std::error_code createError;
        std::filesystem::create_directories(DaemonLogsDirectory(runtimeDirectory), createError);
        std::filesystem::create_directories(DaemonSessionsDirectory(runtimeDirectory), createError);
        std::filesystem::remove(DaemonStopFlagPath(runtimeDirectory), createError);

        const std::string instanceId = NewDaemonInstanceId();
        std::uint32_t daemonProcessId = 0;
        std::string launchError;
        const bool launched = LaunchBackgroundHelper(
            {
                "daemon-run",
                "--runtime-dir",
                PathToUtf8(runtimeDirectory),
                "--daemon-instance-id",
                instanceId
            },
            DaemonLogsDirectory(runtimeDirectory) / L"daemon.stdout.log",
            DaemonLogsDirectory(runtimeDirectory) / L"daemon.stderr.log",
            &daemonProcessId,
            &launchError);
        if (!launched)
        {
            status.Success = false;
            status.DaemonState = "start_failed";
            status.Win32ErrorCode = ERROR_PROCESS_ABORTED;
            status.Message = launchError;
            break;
        }

        if (!WaitForDaemonRunning(runtimeDirectory, 3000, &status))
        {
            status.Success = false;
            status.DaemonState = "start_failed";
            status.Win32ErrorCode = ERROR_TIMEOUT;
            status.Message = "daemon_start_failed";
            break;
        }
    }
    while (false);

    status.Operation = "daemon_start";
    return status;
}

int DaemonRunCommand(const std::vector<std::string>& args)
{
    const std::filesystem::path runtimeDirectory = DaemonRuntimeDirectoryFromArgs(args);
    const std::string daemonInstanceId = GetOption(args, "--daemon-instance-id").empty() ? NewDaemonInstanceId() : GetOption(args, "--daemon-instance-id");
    const std::string startedUtc = NowUtc();

    std::error_code createError;
    std::filesystem::create_directories(DaemonLogsDirectory(runtimeDirectory), createError);
    std::filesystem::create_directories(DaemonSessionsDirectory(runtimeDirectory), createError);

    for (;;)
    {
        // exists() without error_code throws when the runtime directory is removed
        // from under the daemon; treat status errors as "stop requested" instead.
        std::error_code stopFlagError;
        const bool stopFlagPresent = std::filesystem::exists(DaemonStopFlagPath(runtimeDirectory), stopFlagError);
        if (stopFlagPresent || stopFlagError)
        {
            break;
        }
        DaemonStatusInfo status;
        status.Success = true;
        status.Operation = "daemon_run";
        status.DaemonState = "running";
        status.DaemonProcessId = GetCurrentProcessId();
        status.DaemonInstanceId = daemonInstanceId;
        status.DaemonStartedUtc = startedUtc;
        status.DaemonHeartbeatUtc = NowUtc();
        status.ControlEndpoint = DaemonControlEndpoint(runtimeDirectory);
        status.RuntimeDirectory = PathToUtf8(runtimeDirectory);
        status.SessionCount = CountDaemonSessionRecords(runtimeDirectory);
        status.Message = "Daemon heartbeat updated.";
        std::string writeError;
        WriteDaemonStatus(runtimeDirectory, status, &writeError);
        Sleep(250);
    }

    DaemonStatusInfo stopped;
    stopped.Success = false;
    stopped.Operation = "daemon_run";
    stopped.DaemonState = "stopped";
    stopped.DaemonProcessId = GetCurrentProcessId();
    stopped.DaemonInstanceId = daemonInstanceId;
    stopped.DaemonStartedUtc = startedUtc;
    stopped.DaemonHeartbeatUtc = NowUtc();
    stopped.ControlEndpoint = DaemonControlEndpoint(runtimeDirectory);
    stopped.RuntimeDirectory = PathToUtf8(runtimeDirectory);
    stopped.SessionCount = CountDaemonSessionRecords(runtimeDirectory);
    stopped.Message = "Daemon stopped.";
    std::string writeError;
    WriteDaemonStatus(runtimeDirectory, stopped, &writeError);
    return 0;
}

std::string DaemonStartJson(const std::vector<std::string>& args)
{
    DaemonStatusInfo status = StartDaemonIfNeeded(DaemonRuntimeDirectoryFromArgs(args));
    return ToJson(status);
}

std::string DaemonStatusJson(const std::vector<std::string>& args)
{
    DaemonStatusInfo status = ReadDaemonStatus(DaemonRuntimeDirectoryFromArgs(args));
    status.Operation = "daemon_status";
    return ToJson(status);
}

std::string DaemonListSessionsJson(const std::vector<std::string>& args)
{
    const std::filesystem::path runtimeDirectory = DaemonRuntimeDirectoryFromArgs(args);
    DaemonStatusInfo status = ReadDaemonStatus(runtimeDirectory);
    const auto records = ReadAllDaemonSessionRecords(runtimeDirectory);

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (status.Success ? "true" : "false") << ",";
    stream << "\"backendMode\":\"native-capture\",";
    stream << "\"operation\":\"daemon_list_sessions\",";
    stream << "\"daemon\":" << ToJson(status) << ",";
    stream << "\"sessions\":[";
    for (std::size_t index = 0; index < records.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(NativeSessionFromDaemonRecord(records[index]));
    }
    stream << "],";
    stream << "\"message\":\"Daemon sessions listed.\"";
    stream << "}";
    return stream.str();
}

std::vector<NativeSessionInfo> DaemonAuditSessionsFromRecords(const std::vector<DaemonSessionRecord>& records)
{
    std::vector<NativeSessionInfo> sessions;
    sessions.reserve(records.size());

    for (const DaemonSessionRecord& record : records)
    {
        sessions.push_back(NativeSessionFromDaemonRecord(record));
    }

    return sessions;
}

std::uint64_t CountPruneEligibleSessions(const std::vector<NativeSessionInfo>& sessions)
{
    std::uint64_t count = 0;

    for (const NativeSessionInfo& session : sessions)
    {
        if (session.PruneEligible)
        {
            ++count;
        }
    }

    return count;
}

std::vector<std::string> DefaultBlockedRecoveryMutations()
{
    return {
        "kill_target_process",
        "unload_agent_module",
        "remote_thread_repair",
        "reinjection_repair",
        "delete_knapm_data"
    };
}

DaemonRecoveryPlanItem BuildDaemonRecoveryPlanItem(const NativeSessionInfo& session)
{
    DaemonRecoveryPlanItem plan;
    plan.SessionId = session.SessionId;
    plan.RecoveryState = session.RecoveryState;
    plan.RecoveryReason = session.RecoveryReason;
    plan.RegistryPruneAllowed = session.PruneEligible;
    plan.ReplayAllowed = session.KnapmExists && session.KnapmValid;
    plan.BlockedMutations = DefaultBlockedRecoveryMutations();

    if (session.RecoveryState == "healthy")
    {
        plan.RecommendedAction = "continue_monitoring";
        plan.OperatorRunbook = {"daemon_audit_periodic", "operator_stop_session_only_on_explicit_request"};
        plan.Message = "Session is healthy; no recovery action is planned.";
    }
    else if (session.RecoveryState == "finalized")
    {
        plan.RecommendedAction = session.PruneEligible ? "replay_then_prune_registry_record" : "replay_only";
        plan.OperatorRunbook = {"validate_session", "replay_session", "daemon_prune_stale_dry_run_before_registry_cleanup"};
        plan.Message = "Session is finalized; only replay and registry cleanup are in scope.";
    }
    else if (session.RecoveryState == "stale")
    {
        plan.RecommendedAction = session.PruneEligible ? "prune_registry_record_after_dry_run" : "manual_stale_registry_review";
        plan.OperatorRunbook = {"preserve_knapm", "validate_session", "daemon_prune_stale_dry_run", "daemon_prune_stale_if_registry_only_cleanup_is_accepted"};
        plan.Message = "Session is stale; plan allows registry cleanup only.";
    }
    else if (session.RecoveryState == "daemon_crashed")
    {
        plan.RecommendedAction = "operator_restart_daemon_then_audit";
        plan.OperatorRunbook = {"preserve_knapm", "start_daemon_if_needed", "daemon_audit", "operator_stop_session_if_shutdown_is_required"};
        plan.Message = "Daemon is gone while writer is alive; automatic recovery is not enabled.";
    }
    else if (session.RecoveryState == "writer_crashed")
    {
        plan.RecommendedAction = "manual_orphan_triage_preserve_evidence";
        plan.OperatorRunbook = {"preserve_knapm", "validate_session", "replay_session_if_valid", "daemon_prune_stale_dry_run", "manual_target_restart_for_agent_eviction"};
        plan.Message = "Writer is gone while target is alive; do not attempt agent unload or target mutation.";
    }
    else if (session.RecoveryState == "orphaned_agent_risk")
    {
        plan.RecommendedAction = "manual_orphan_risk_triage";
        plan.OperatorRunbook = {"preserve_knapm", "validate_session", "replay_session_if_valid", "daemon_prune_stale_dry_run", "manual_target_restart_required_for_agent_eviction"};
        plan.Message = "Daemon and writer are gone while target is alive; active-agent repair remains blocked.";
    }
    else if (session.RecoveryState == "malformed")
    {
        plan.RecommendedAction = session.PruneEligible ? "manual_inspection_then_registry_prune" : "manual_registry_inspection";
        plan.OperatorRunbook = {"inspect_registry_record", "validate_or_archive_knapm", "daemon_prune_stale_dry_run_if_terminal"};
        plan.Message = "Registry or KNAPM metadata is malformed; operator inspection is required.";
    }
    else
    {
        plan.RecommendedAction = "manual_inspection";
        plan.OperatorRunbook = {"daemon_audit", "preserve_knapm", "manual_review"};
        plan.Message = "Recovery state is unknown; no automatic action is allowed.";
    }

    return plan;
}

std::vector<DaemonRecoveryPlanItem> BuildDaemonRecoveryPlanItems(const std::vector<NativeSessionInfo>& sessions)
{
    std::vector<DaemonRecoveryPlanItem> plans;
    plans.reserve(sessions.size());

    for (const NativeSessionInfo& session : sessions)
    {
        plans.push_back(BuildDaemonRecoveryPlanItem(session));
    }

    return plans;
}

std::uint64_t CountRegistryPruneAllowedPlans(const std::vector<DaemonRecoveryPlanItem>& plans)
{
    std::uint64_t count = 0;

    for (const DaemonRecoveryPlanItem& plan : plans)
    {
        if (plan.RegistryPruneAllowed)
        {
            ++count;
        }
    }

    return count;
}

std::uint64_t CountBlockedRecoveryMutations(const std::vector<DaemonRecoveryPlanItem>& plans)
{
    std::uint64_t count = 0;

    for (const DaemonRecoveryPlanItem& plan : plans)
    {
        count += plan.BlockedMutations.size();
    }

    return count;
}

std::string DaemonAuditResultJson(
    const std::string& operation,
    const DaemonStatusInfo& status,
    const std::vector<NativeSessionInfo>& sessions,
    bool dryRun,
    bool mutationAttempted,
    const std::vector<std::string>& prunedSessionIds,
    bool success,
    std::uint32_t win32ErrorCode,
    const std::string& message)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (success ? "true" : "false") << ",";
    stream << "\"backendMode\":\"native-capture\",";
    stream << "\"operation\":" << Q(operation) << ",";
    stream << "\"daemon\":" << ToJson(status) << ",";
    stream << "\"sessions\":[";
    for (std::size_t index = 0; index < sessions.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(sessions[index]);
    }
    stream << "],";
    stream << "\"pruneEligibleCount\":" << CountPruneEligibleSessions(sessions) << ",";
    stream << "\"dryRun\":" << (dryRun ? "true" : "false") << ",";
    stream << "\"mutationAttempted\":" << (mutationAttempted ? "true" : "false") << ",";
    stream << "\"prunedSessionIds\":[";
    for (std::size_t index = 0; index < prunedSessionIds.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << Q(prunedSessionIds[index]);
    }
    stream << "],";
    stream << "\"win32ErrorCode\":" << win32ErrorCode << ",";
    stream << "\"message\":" << Q(message);
    stream << "}";
    return stream.str();
}

std::string DaemonRecoveryPlanResultJson(
    const DaemonStatusInfo& status,
    const std::vector<NativeSessionInfo>& sessions,
    const std::vector<DaemonRecoveryPlanItem>& plans,
    bool success,
    std::uint32_t win32ErrorCode,
    const std::string& message)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (success ? "true" : "false") << ",";
    stream << "\"backendMode\":\"native-capture\",";
    stream << "\"operation\":\"daemon_recovery_plan\",";
    stream << "\"daemon\":" << ToJson(status) << ",";
    stream << "\"sessions\":[";
    for (std::size_t index = 0; index < sessions.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(sessions[index]);
    }
    stream << "],";
    stream << "\"recoveryPlans\":[";
    for (std::size_t index = 0; index < plans.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(plans[index]);
    }
    stream << "],";
    stream << "\"recoveryPlanCount\":" << plans.size() << ",";
    stream << "\"registryPruneAllowedCount\":" << CountRegistryPruneAllowedPlans(plans) << ",";
    stream << "\"blockedMutationCount\":" << CountBlockedRecoveryMutations(plans) << ",";
    stream << "\"automaticRecoveryAllowed\":false,";
    stream << "\"targetMutationAllowed\":false,";
    stream << "\"dryRun\":true,";
    stream << "\"mutationAttempted\":false,";
    stream << "\"win32ErrorCode\":" << win32ErrorCode << ",";
    stream << "\"message\":" << Q(message);
    stream << "}";
    return stream.str();
}

std::string DaemonRecoveryApplyResultJson(
    const DaemonStatusInfo& status,
    const std::vector<NativeSessionInfo>& sessions,
    const std::vector<DaemonRecoveryPlanItem>& plans,
    bool dryRun,
    bool mutationAttempted,
    const std::vector<std::string>& prunedSessionIds,
    bool success,
    std::uint32_t win32ErrorCode,
    const std::string& message)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (success ? "true" : "false") << ",";
    stream << "\"backendMode\":\"native-capture\",";
    stream << "\"operation\":\"daemon_recovery_apply\",";
    stream << "\"daemon\":" << ToJson(status) << ",";
    stream << "\"sessions\":[";
    for (std::size_t index = 0; index < sessions.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(sessions[index]);
    }
    stream << "],";
    stream << "\"recoveryPlans\":[";
    for (std::size_t index = 0; index < plans.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << ToJson(plans[index]);
    }
    stream << "],";
    stream << "\"recoveryPlanCount\":" << plans.size() << ",";
    stream << "\"registryPruneAllowedCount\":" << CountRegistryPruneAllowedPlans(plans) << ",";
    stream << "\"blockedMutationCount\":" << CountBlockedRecoveryMutations(plans) << ",";
    stream << "\"automaticRecoveryAllowed\":false,";
    stream << "\"targetMutationAllowed\":false,";
    stream << "\"dryRun\":" << (dryRun ? "true" : "false") << ",";
    stream << "\"mutationAttempted\":" << (mutationAttempted ? "true" : "false") << ",";
    stream << "\"prunedSessionIds\":[";
    for (std::size_t index = 0; index < prunedSessionIds.size(); ++index)
    {
        if (index != 0)
        {
            stream << ",";
        }
        stream << Q(prunedSessionIds[index]);
    }
    stream << "],";
    stream << "\"win32ErrorCode\":" << win32ErrorCode << ",";
    stream << "\"message\":" << Q(message);
    stream << "}";
    return stream.str();
}

std::string DaemonAuditJson(const std::vector<std::string>& args)
{
    const std::filesystem::path runtimeDirectory = DaemonRuntimeDirectoryFromArgs(args);
    DaemonStatusInfo status = ReadDaemonStatus(runtimeDirectory);
    const auto records = ReadAllDaemonSessionRecords(runtimeDirectory);
    const auto sessions = DaemonAuditSessionsFromRecords(records);
    return DaemonAuditResultJson(
        "daemon_audit",
        status,
        sessions,
        false,
        false,
        {},
        true,
        0,
        "Daemon registry audited.");
}

std::string DaemonRecoveryPlanJson(const std::vector<std::string>& args)
{
    const std::filesystem::path runtimeDirectory = DaemonRuntimeDirectoryFromArgs(args);
    DaemonStatusInfo status = ReadDaemonStatus(runtimeDirectory);
    const auto records = ReadAllDaemonSessionRecords(runtimeDirectory);
    const auto sessions = DaemonAuditSessionsFromRecords(records);
    const auto plans = BuildDaemonRecoveryPlanItems(sessions);
    return DaemonRecoveryPlanResultJson(
        status,
        sessions,
        plans,
        true,
        0,
        "Daemon recovery plan generated without mutation.");
}

std::string DaemonPruneStaleJson(const std::vector<std::string>& args)
{
    const std::filesystem::path runtimeDirectory = DaemonRuntimeDirectoryFromArgs(args);
    const bool dryRun = HasOption(args, "--dry-run");
    DaemonStatusInfo status = ReadDaemonStatus(runtimeDirectory);
    const auto records = ReadAllDaemonSessionRecords(runtimeDirectory);
    std::vector<NativeSessionInfo> sessions;
    std::vector<std::string> prunedSessionIds;
    bool success = true;
    std::uint32_t win32ErrorCode = 0;
    std::string message = dryRun ? "Daemon stale registry prune dry-run completed." : "Daemon stale registry prune completed.";

    sessions.reserve(records.size());
    for (const DaemonSessionRecord& record : records)
    {
        NativeSessionInfo session = NativeSessionFromDaemonRecord(record);
        sessions.push_back(session);
        if (!session.PruneEligible)
        {
            continue;
        }

        prunedSessionIds.push_back(session.SessionId);
        if (dryRun)
        {
            continue;
        }

        const std::filesystem::path recordPath = record.RegistryPath.empty() ? DaemonSessionRecordPath(runtimeDirectory, record.SessionId) : record.RegistryPath;
        std::error_code removeError;
        std::filesystem::remove(recordPath, removeError);
        if (removeError)
        {
            success = false;
            win32ErrorCode = ERROR_DELETE_PENDING;
            message = "failed_to_prune_stale_registry";
            break;
        }
    }

    DaemonStatusInfo refreshedStatus = ReadDaemonStatus(runtimeDirectory);
    if (dryRun)
    {
        refreshedStatus = status;
    }

    return DaemonAuditResultJson(
        "daemon_prune_stale",
        refreshedStatus,
        sessions,
        dryRun,
        !dryRun && !prunedSessionIds.empty(),
        prunedSessionIds,
        success,
        win32ErrorCode,
        message);
}

std::string DaemonRecoveryApplyJson(const std::vector<std::string>& args)
{
    const std::filesystem::path runtimeDirectory = DaemonRuntimeDirectoryFromArgs(args);
    const bool applyRegistryPrune = HasOption(args, "--apply-registry-prune");
    const bool dryRun = HasOption(args, "--dry-run") || !applyRegistryPrune;
    DaemonStatusInfo status = ReadDaemonStatus(runtimeDirectory);
    const auto records = ReadAllDaemonSessionRecords(runtimeDirectory);
    std::vector<NativeSessionInfo> sessions;
    std::vector<DaemonRecoveryPlanItem> plans;
    std::vector<std::string> prunedSessionIds;
    bool success = true;
    std::uint32_t win32ErrorCode = 0;
    std::string message = dryRun ? "Daemon recovery apply dry-run completed." : "Daemon recovery apply completed with registry-only cleanup.";

    sessions.reserve(records.size());
    plans.reserve(records.size());
    for (const DaemonSessionRecord& record : records)
    {
        NativeSessionInfo session = NativeSessionFromDaemonRecord(record);
        DaemonRecoveryPlanItem plan = BuildDaemonRecoveryPlanItem(session);
        sessions.push_back(session);
        plans.push_back(plan);
        if (!plan.RegistryPruneAllowed)
        {
            continue;
        }

        prunedSessionIds.push_back(session.SessionId);
        if (dryRun)
        {
            continue;
        }

        const std::filesystem::path recordPath = record.RegistryPath.empty() ? DaemonSessionRecordPath(runtimeDirectory, record.SessionId) : record.RegistryPath;
        std::error_code removeError;
        std::filesystem::remove(recordPath, removeError);
        if (removeError)
        {
            success = false;
            win32ErrorCode = ERROR_DELETE_PENDING;
            message = "failed_to_apply_daemon_recovery_registry_prune";
            break;
        }
    }

    DaemonStatusInfo refreshedStatus = ReadDaemonStatus(runtimeDirectory);
    if (dryRun)
    {
        refreshedStatus = status;
    }

    return DaemonRecoveryApplyResultJson(
        refreshedStatus,
        sessions,
        plans,
        dryRun,
        !dryRun && !prunedSessionIds.empty(),
        prunedSessionIds,
        success,
        win32ErrorCode,
        message);
}

std::string DaemonStartSessionJson(const std::vector<std::string>& args)
{
    const std::filesystem::path runtimeDirectory = DaemonRuntimeDirectoryFromArgs(args);
    DaemonStatusInfo status = ReadDaemonStatus(runtimeDirectory);
    DaemonSessionRecord record;
    NativeSessionInfo session;
    bool success = false;
    std::uint32_t win32ErrorCode = 0;
    std::string message;

    do
    {
        const std::string pidOption = GetOption(args, "--pid");
        const std::uint32_t targetProcessId = pidOption == "self" ? GetCurrentProcessId() : GetUInt32Option(args, "--pid", 0);
        const std::string knapmPath = GetOption(args, "--write-knapm");
        const std::string knapmCompression = NormalizeKnapmCompression(GetOption(args, "--knapm-compression"));
        if (targetProcessId == 0 || knapmPath.empty())
        {
            win32ErrorCode = ERROR_INVALID_PARAMETER;
            message = "Missing --pid or --write-knapm.";
            break;
        }

        if (!IsSupportedKnapmCompression(knapmCompression))
        {
            win32ErrorCode = ERROR_INVALID_PARAMETER;
            message = "unsupported_compression";
            break;
        }

        const std::uint32_t durationMs = GetUInt32Option(args, "--duration-ms", 0);
        const std::uint32_t timeoutMs = GetUInt32Option(args, "--timeout-ms", 7000);
        const std::string apiSelection = GetOption(args, "--api-selection");
        const std::string operationId = OperationIdFromArgs(args);
        const std::string sessionId = SessionIdFromArgs(args, operationId);
        const std::string cancellationEventName = CancellationEventNameForOperation(operationId);
        const std::string requestedKnapmPathKey = NormalizedPathKey(PathFromUtf8(knapmPath));

        for (const DaemonSessionRecord& existing : ReadAllDaemonSessionRecords(runtimeDirectory))
        {
            NativeSessionInfo existingSession = NativeSessionFromDaemonRecord(existing);
            const bool sameSessionId = existing.SessionId == sessionId;
            const bool sameTarget = existing.TargetProcessId == targetProcessId;
            const bool sameKnapmPath =
                !existing.KnapmPath.empty() &&
                !requestedKnapmPathKey.empty() &&
                NormalizedPathKey(PathFromUtf8(existing.KnapmPath)) == requestedKnapmPathKey;

            if (sameSessionId)
            {
                session = existingSession;
                win32ErrorCode = ERROR_ALREADY_EXISTS;
                message = existingSession.PruneEligible ? "stale_registry_requires_prune" : "session_id_in_use";
                break;
            }

            if (sameKnapmPath)
            {
                session = existingSession;
                win32ErrorCode = ERROR_ALREADY_EXISTS;
                message = existingSession.PruneEligible ? "stale_registry_requires_prune" : "knapm_path_in_use";
                break;
            }

            if (sameTarget)
            {
                session = existingSession;
                win32ErrorCode = ERROR_ALREADY_EXISTS;
                message = existingSession.PruneEligible ? "stale_registry_requires_prune" : "already_supervised";
                break;
            }
        }

        if (win32ErrorCode != 0)
        {
            break;
        }

        status = StartDaemonIfNeeded(runtimeDirectory);
        if (!status.Success)
        {
            win32ErrorCode = status.Win32ErrorCode == 0 ? ERROR_SERVICE_NOT_ACTIVE : status.Win32ErrorCode;
            message = "daemon_not_running";
            break;
        }

        std::uint32_t sessionProcessId = 0;
        std::string launchError;
        std::vector<std::string> childArgs = {
            "attach-session",
            "--pid",
            std::to_string(targetProcessId),
            "--timeout-ms",
            std::to_string(timeoutMs),
            "--operation-id",
            operationId,
            "--session-id",
            sessionId,
            "--stream-batches",
            "--write-knapm",
            knapmPath,
            "--knapm-compression",
            knapmCompression,
            "--owner-kind",
            "persistent-daemon",
            "--daemon-process-id",
            std::to_string(status.DaemonProcessId),
            "--daemon-instance-id",
            status.DaemonInstanceId,
            "--daemon-started-utc",
            status.DaemonStartedUtc,
            "--daemon-control-endpoint",
            status.ControlEndpoint
        };

        if (!apiSelection.empty())
        {
            childArgs.push_back("--api-selection");
            childArgs.push_back(apiSelection);
        }

        if (durationMs != 0)
        {
            // Forward the requested bounded duration; otherwise the attach child
            // defaults to a continuous (duration 0) session while the registry
            // record claims a bounded one.
            childArgs.push_back("--duration-ms");
            childArgs.push_back(std::to_string(durationMs));
        }

        const bool launched = LaunchBackgroundHelper(
            childArgs,
            DaemonLogsDirectory(runtimeDirectory) / PathFromUtf8(SanitizeFileName(sessionId) + ".stdout.log"),
            DaemonLogsDirectory(runtimeDirectory) / PathFromUtf8(SanitizeFileName(sessionId) + ".stderr.log"),
            &sessionProcessId,
            &launchError);
        if (!launched)
        {
            win32ErrorCode = ERROR_PROCESS_ABORTED;
            message = launchError.empty() ? "session_start_failed" : launchError;
            break;
        }

        record.SessionId = sessionId;
        record.OperationId = operationId;
        record.TargetProcessId = targetProcessId;
        record.DaemonProcessId = status.DaemonProcessId;
        record.DaemonInstanceId = status.DaemonInstanceId;
        record.DaemonStartedUtc = status.DaemonStartedUtc;
        record.DaemonControlEndpoint = status.ControlEndpoint;
        record.SessionProcessId = sessionProcessId;
        record.KnapmPath = knapmPath;
        record.CancellationEventName = cancellationEventName;
        record.StartedUtc = NowUtc();
        record.DurationMs = durationMs;

        std::string writeError;
        if (!WriteDaemonSessionRecord(runtimeDirectory, record, &writeError))
        {
            win32ErrorCode = ERROR_WRITE_FAULT;
            message = writeError;
            break;
        }

        if (!WaitForKnapmOwnerKind(PathFromUtf8(knapmPath), "persistent-daemon", 5000))
        {
            win32ErrorCode = ERROR_TIMEOUT;
            message = "session_start_failed";
            break;
        }

        session = NativeSessionFromDaemonRecord(record);
        success = true;
        message = "Daemon session started.";
    }
    while (false);

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (success ? "true" : "false") << ",";
    stream << "\"backendMode\":\"native-capture\",";
    stream << "\"operation\":\"daemon_start_session\",";
    stream << "\"daemon\":" << ToJson(status) << ",";
    stream << "\"session\":" << ToJson(session) << ",";
    stream << "\"sessionProcessId\":" << record.SessionProcessId << ",";
    stream << "\"knapmPath\":" << Q(record.KnapmPath) << ",";
    stream << "\"win32ErrorCode\":" << win32ErrorCode << ",";
    stream << "\"message\":" << Q(message);
    stream << "}";
    return stream.str();
}

std::string DaemonStopSessionJson(const std::vector<std::string>& args)
{
    const std::filesystem::path runtimeDirectory = DaemonRuntimeDirectoryFromArgs(args);
    const std::string sessionId = GetOption(args, "--session-id");
    DaemonStatusInfo status = ReadDaemonStatus(runtimeDirectory);
    DaemonSessionRecord record;
    NativeSessionInfo session;
    bool success = false;
    std::uint32_t win32ErrorCode = 0;
    std::string message;

    do
    {
        if (sessionId.empty())
        {
            win32ErrorCode = ERROR_INVALID_PARAMETER;
            message = "session_not_found";
            break;
        }

        std::string readError;
        if (!ReadDaemonSessionRecord(runtimeDirectory, sessionId, &record, &readError))
        {
            win32ErrorCode = ERROR_FILE_NOT_FOUND;
            message = "session_not_found";
            break;
        }

        session = NativeSessionFromDaemonRecord(record);
        if (session.SessionState == "stopped")
        {
            success = true;
            message = "Daemon session already stopped.";
            break;
        }

        const std::string eventName = record.CancellationEventName.empty() ? CancellationEventNameForOperation(record.OperationId) : record.CancellationEventName;
        const std::wstring wideEventName = Utf8ToWide(eventName);
        HANDLE eventHandle = OpenEventW(EVENT_MODIFY_STATE, FALSE, wideEventName.c_str());
        if (eventHandle == nullptr)
        {
            win32ErrorCode = GetLastError();
            message = "control_endpoint_unavailable";
            break;
        }

        if (!SetEvent(eventHandle))
        {
            win32ErrorCode = GetLastError();
            CloseHandle(eventHandle);
            message = "control_endpoint_unavailable";
            break;
        }
        CloseHandle(eventHandle);

        const ULONGLONG start = GetTickCount64();
        while (GetTickCount64() - start < 15000)
        {
            DaemonSessionRecord refreshedRecord;
            std::string refreshError;
            if (ReadDaemonSessionRecord(runtimeDirectory, sessionId, &refreshedRecord, &refreshError))
            {
                record = refreshedRecord;
            }

            session = NativeSessionFromDaemonRecord(record);
            if (session.SessionState == "stopped" || !IsProcessAlive(record.SessionProcessId))
            {
                break;
            }

            Sleep(100);
        }

        {
            DaemonSessionRecord refreshedRecord;
            std::string refreshError;
            if (ReadDaemonSessionRecord(runtimeDirectory, sessionId, &refreshedRecord, &refreshError))
            {
                record = refreshedRecord;
            }
        }
        session = NativeSessionFromDaemonRecord(record);
        if (session.SessionState == "stopped")
        {
            success = true;
            message = "Daemon session stopped.";
        }
        else
        {
            win32ErrorCode = ERROR_TIMEOUT;
            message = "stop_timeout";
        }
    }
    while (false);

    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"success\":" << (success ? "true" : "false") << ",";
    stream << "\"backendMode\":\"native-capture\",";
    stream << "\"operation\":\"daemon_stop_session\",";
    stream << "\"daemon\":" << ToJson(status) << ",";
    stream << "\"session\":" << ToJson(session) << ",";
    stream << "\"win32ErrorCode\":" << win32ErrorCode << ",";
    stream << "\"message\":" << Q(message);
    stream << "}";
    return stream.str();
}

std::string DaemonStopJson(const std::vector<std::string>& args)
{
    const std::filesystem::path runtimeDirectory = DaemonRuntimeDirectoryFromArgs(args);
    const auto records = ReadAllDaemonSessionRecords(runtimeDirectory);
    for (const DaemonSessionRecord& record : records)
    {
        std::vector<std::string> stopArgs = {
            "daemon-stop-session",
            "--runtime-dir",
            PathToUtf8(runtimeDirectory),
            "--session-id",
            record.SessionId
        };
        DaemonStopSessionJson(stopArgs);
    }

    std::string writeError;
    WriteTextFile(DaemonStopFlagPath(runtimeDirectory), "stop\n", &writeError);

    DaemonStatusInfo status = ReadDaemonStatus(runtimeDirectory);
    const ULONGLONG start = GetTickCount64();
    while (IsProcessAlive(status.DaemonProcessId) && GetTickCount64() - start < 5000)
    {
        Sleep(100);
    }

    status = ReadDaemonStatus(runtimeDirectory);
    status.Operation = "daemon_stop";
    status.Success = !IsProcessAlive(status.DaemonProcessId);
    status.DaemonState = status.Success ? "stopped" : "stop_timeout";
    status.Win32ErrorCode = status.Success ? 0 : ERROR_TIMEOUT;
    status.Message = status.Success ? "Daemon stopped." : "stop_timeout";
    return ToJson(status);
}

void PrintUsage()
{
    std::cout << "{";
    std::cout << "\"schemaVersion\":\"0.1.0\",";
    std::cout << "\"success\":false,";
    std::cout << "\"message\":\"Usage: knmon-native-helper.exe list-targets | launch-sample [--target path] [--agent path] | launch-session --target path [--cwd dir] [--session-id id] [--operation-id id] [--owner-pid pid] [--duration-ms ms optional bounded mode] [--api-selection module!api;...] [--stream-batches] [--batch-size n] | capture-sample [--target path] [--agent path] [--target-args args] [--generated-preview-probe] [--target-startup-delay-ms ms] [--api-selection module!api;...] [--timeout-ms ms] [--write-session dir] | attach-capture --pid pid [--agent path] [--duration-ms ms] [--operation-id id] [--api-selection module!api;...] [--write-session dir] | attach-session --pid pid [--session-id id] [--operation-id id] [--duration-ms ms optional bounded mode] [--api-selection module!api;...] [--stream-batches] [--batch-size n] [--batch-interval-ms n] [--write-knapm path] [--knapm-compression none|zstd] | daemon-start [--runtime-dir dir] | daemon-status [--runtime-dir dir] | daemon-audit [--runtime-dir dir] | daemon-recovery-plan [--runtime-dir dir] | daemon-recovery-apply [--runtime-dir dir] [--dry-run|--apply-registry-prune] | daemon-prune-stale [--runtime-dir dir] [--dry-run] | daemon-start-session --pid pid --write-knapm path [--knapm-compression none|zstd] [--api-selection module!api;...] [--runtime-dir dir] | daemon-list-sessions [--runtime-dir dir] | daemon-stop-session --session-id id [--runtime-dir dir] | daemon-stop [--runtime-dir dir] | supervise-tree --pid pid [--duration-ms ms] [--operation-id id] [--child-policy observe|attach-supported] [--api-selection module!api;...] | cancel-operation --operation-id id | classify-session --session-record path | catalog-sessions --root dir [--catalog path] [--rebuild] | catalog-query --catalog path [--limit n] [--state state] [--target pid-or-text] | catalog-remove-missing --catalog path [--dry-run] | catalog-index-build --root dir --database path [--rebuild] | catalog-index-query --database path [--limit n] [--state state] [--target pid-or-text] | catalog-index-remove-missing --database path [--dry-run] | trace-index-build --root dir --database path [--rebuild] | trace-index-query --database path [--text text] [--api api] [--module module] [--session id-or-path] [--pid pid] [--limit n] | trace-index-remove-missing --database path [--dry-run] | replay-session --session dir-or-knapm | validate-session --session dir-or-knapm\"";
    std::cout << "}\n";
}
}

int DispatchCommand(const std::vector<std::string>& args);

int wmain(int argc, wchar_t** argv)
{
    std::vector<std::string> args;
    for (int index = 1; index < argc; ++index)
    {
        args.push_back(WideToUtf8(argv[index]));
    }

    // Exception barrier: this helper's contract is one well-formed JSON object (or
    // JSONL frame stream) on stdout; an escaping exception would truncate the
    // stream mid-frame and terminate the CLI silently.
    try
    {
        return DispatchCommand(args);
    }
    catch (const JsonInputError& error)
    {
        std::cout << "{\"schemaVersion\":\"0.1.0\",\"success\":false,\"operation\":\"invalid_json\",\"win32ErrorCode\":13,\"message\":"
                  << Q(error.what()) << "}\n";
        return 1;
    }
    catch (const std::exception& error)
    {
        std::ostringstream stream;
        stream << "{";
        stream << "\"schemaVersion\":\"0.1.0\",";
        stream << "\"success\":false,";
        stream << "\"operation\":\"unhandled_exception\",";
        stream << "\"win32ErrorCode\":" << ERROR_UNIDENTIFIED_ERROR << ",";
        stream << "\"message\":" << Q(error.what());
        stream << "}";
        std::cout << stream.str() << "\n";
        return 1;
    }
    catch (...)
    {
        std::ostringstream stream;
        stream << "{";
        stream << "\"schemaVersion\":\"0.1.0\",";
        stream << "\"success\":false,";
        stream << "\"operation\":\"unhandled_exception\",";
        stream << "\"win32ErrorCode\":" << ERROR_UNIDENTIFIED_ERROR << ",";
        stream << "\"message\":\"unknown exception\"";
        stream << "}";
        std::cout << stream.str() << "\n";
        return 1;
    }
}

int DispatchCommand(const std::vector<std::string>& args)
{
    std::string rejectedApi;
    if (!knmon::ValidateRuntimeApiSelection(GetOption(args, "--api-selection"), rejectedApi))
    {
        std::cout << "{\"schemaVersion\":\"0.1.0\",\"success\":false,"
            << "\"operation\":\"validate_api_selection\",\"win32ErrorCode\":" << ERROR_NOT_SUPPORTED
            << ",\"message\":\"unsupported_api_selection\",\"rejectedApi\":" << Q(rejectedApi) << "}\n";
        return 1;
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

    if (args[0] == "runtime-support")
    {
        std::cout << "{\"schemaVersion\":1,\"success\":true,\"policy\":\"manual-typed-only\","
            << "\"differentialVerifiedCount\":0,\"supportedKeys\":[";
        bool first = true;
        for (const std::string_view key : knmon::RuntimeSupportedApiKeys)
        {
            if (!first)
            {
                std::cout << ",";
            }
            std::cout << Q(std::string(key));
            first = false;
        }
        std::cout << "]}\n";
        return 0;
    }

    if (args[0] == "launch-sample")
    {
        std::cout << LaunchSampleJson(args) << "\n";
        return 0;
    }

    if (args[0] == "launch-session")
    {
        return LaunchSessionCommand(args);
    }

    if (args[0] == "capture-sample")
    {
        std::cout << CaptureSampleJson(args) << "\n";
        return 0;
    }

    if (args[0] == "attach-capture")
    {
        std::cout << AttachCaptureJson(args) << "\n";
        return 0;
    }

    if (args[0] == "attach-session")
    {
        return AttachSessionCommand(args);
    }

    if (args[0] == "daemon-run")
    {
        return DaemonRunCommand(args);
    }

    if (args[0] == "daemon-start")
    {
        std::cout << DaemonStartJson(args) << "\n";
        return 0;
    }

    if (args[0] == "daemon-status")
    {
        std::cout << DaemonStatusJson(args) << "\n";
        return 0;
    }

    if (args[0] == "daemon-audit")
    {
        std::cout << DaemonAuditJson(args) << "\n";
        return 0;
    }

    if (args[0] == "daemon-recovery-plan")
    {
        std::cout << DaemonRecoveryPlanJson(args) << "\n";
        return 0;
    }

    if (args[0] == "daemon-recovery-apply")
    {
        std::cout << DaemonRecoveryApplyJson(args) << "\n";
        return 0;
    }

    if (args[0] == "daemon-prune-stale")
    {
        std::cout << DaemonPruneStaleJson(args) << "\n";
        return 0;
    }

    if (args[0] == "daemon-start-session")
    {
        std::cout << DaemonStartSessionJson(args) << "\n";
        return 0;
    }

    if (args[0] == "daemon-list-sessions")
    {
        std::cout << DaemonListSessionsJson(args) << "\n";
        return 0;
    }

    if (args[0] == "daemon-stop-session")
    {
        std::cout << DaemonStopSessionJson(args) << "\n";
        return 0;
    }

    if (args[0] == "daemon-stop")
    {
        std::cout << DaemonStopJson(args) << "\n";
        return 0;
    }

    if (args[0] == "supervise-tree")
    {
        std::cout << SuperviseTreeJson(args) << "\n";
        return 0;
    }

    if (args[0] == "cancel-operation")
    {
        std::cout << CancelOperationJson(args) << "\n";
        return 0;
    }

    if (args[0] == "classify-session")
    {
        std::cout << ClassifySessionRecordJson(args) << "\n";
        return 0;
    }

    if (args[0] == "catalog-sessions")
    {
        std::cout << CatalogSessionsJson(args) << "\n";
        return 0;
    }

    if (args[0] == "catalog-query")
    {
        std::cout << CatalogQueryJson(args) << "\n";
        return 0;
    }

    if (args[0] == "catalog-remove-missing")
    {
        std::cout << CatalogRemoveMissingJson(args) << "\n";
        return 0;
    }

    if (args[0] == "catalog-index-build")
    {
        std::cout << CatalogIndexBuildJson(args) << "\n";
        return 0;
    }

    if (args[0] == "catalog-index-query")
    {
        std::cout << CatalogIndexQueryJson(args) << "\n";
        return 0;
    }

    if (args[0] == "catalog-index-remove-missing")
    {
        std::cout << CatalogIndexRemoveMissingJson(args) << "\n";
        return 0;
    }

    if (args[0] == "trace-index-build")
    {
        std::cout << TraceIndexBuildJson(args) << "\n";
        return 0;
    }

    if (args[0] == "trace-index-query")
    {
        std::cout << TraceIndexQueryJson(args) << "\n";
        return 0;
    }

    if (args[0] == "trace-index-remove-missing")
    {
        std::cout << TraceIndexRemoveMissingJson(args) << "\n";
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
