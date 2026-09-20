#pragma once
#include <Windows.h>
#include <evntprov.h>
#include <evntrace.h>
#include <cstdint>
#include <string>
#include <vector>

inline constexpr GUID CorpusProvider = {0x9e28e13c, 0x73f3, 0x48ea, {0x91, 0xa3, 0x6c, 0xc8, 0x17, 0xfa, 0x6a, 0x42}};
inline constexpr const char* CorpusApiNames[] = {"CreateFileW", "WriteFile", "ReadFile", "CloseHandle", "VirtualAlloc", "VirtualFree"};

struct CorpusEvent
{
    std::uint64_t StartQpc = 0;
    std::uint64_t EndQpc = 0;
    std::uint32_t Sequence = 0;
    std::uint32_t Api = 0;
    std::uint32_t Success = 0;
    std::uint32_t Error = 0;
    std::uint32_t ByteCount = 0;
    std::uint32_t PreviewBytes = 0;
    unsigned char Preview[16] = {};
};
static_assert(sizeof(CorpusEvent) == 56);

struct CorpusTraceProperties
{
    EVENT_TRACE_PROPERTIES Properties = {};
    wchar_t Name[96] = {};
    wchar_t File[1024] = {};
};

class CorpusEtw
{
public:
    bool Start(const std::wstring& file)
    {
        bool success = false;
        do
        {
            if (file.size() >= std::size(m_properties.File))
            {
                Status = ERROR_FILENAME_EXCED_RANGE;
                break;
            }
            Status = EventRegister(&CorpusProvider, nullptr, nullptr, &m_provider);
            if (Status != ERROR_SUCCESS)
            {
                break;
            }
            auto& properties = m_properties.Properties;
            properties.Wnode.BufferSize = sizeof(m_properties);
            properties.Wnode.Guid = CorpusProvider;
            properties.Wnode.ClientContext = 1;
            properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            properties.BufferSize = 64;
            properties.MinimumBuffers = 2;
            properties.MaximumBuffers = 8;
            properties.MaximumFileSize = 64;
            properties.LogFileMode = EVENT_TRACE_PRIVATE_LOGGER_MODE | EVENT_TRACE_PRIVATE_IN_PROC | EVENT_TRACE_FILE_MODE_SEQUENTIAL;
            properties.LoggerNameOffset = offsetof(CorpusTraceProperties, Name);
            properties.LogFileNameOffset = offsetof(CorpusTraceProperties, File);
            const std::wstring name = L"KNMon.Corpus." + std::to_wstring(GetCurrentProcessId());
            wcscpy_s(m_properties.Name, name.c_str());
            wcscpy_s(m_properties.File, file.c_str());
            Status = StartTraceW(&m_session, m_properties.Name, &properties);
            if (Status != ERROR_SUCCESS)
            {
                break;
            }
            Status = EnableTraceEx2(m_session, &CorpusProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_INFORMATION, 1, 0, 0, nullptr);
            success = Status == ERROR_SUCCESS;
        }
        while (false);
        return success;
    }

    void Write(const CorpusEvent& event)
    {
        if (m_session != 0)
        {
            const EVENT_DESCRIPTOR descriptor{1, 1, 0, TRACE_LEVEL_INFORMATION, 0, 0, 1};
            EVENT_DATA_DESCRIPTOR data;
            EventDataDescCreate(&data, &event, sizeof(event));
            if (EventWrite(m_provider, &descriptor, 1, &data) != ERROR_SUCCESS)
            {
                ++WriteFailures;
            }
        }
    }

    void Stop()
    {
        if (m_session != 0)
        {
            const auto result = ControlTraceW(m_session, m_properties.Name, &m_properties.Properties, EVENT_TRACE_CONTROL_STOP);
            if (Status == ERROR_SUCCESS)
            {
                Status = result;
            }
            EventsLost = m_properties.Properties.EventsLost;
            BuffersLost = m_properties.Properties.LogBuffersLost;
            m_session = 0;
        }
        if (m_provider != 0)
        {
            EventUnregister(m_provider);
            m_provider = 0;
        }
    }

    ~CorpusEtw()
    {
        Stop();
    }

    ULONG Status = ERROR_SUCCESS;
    ULONG WriteFailures = 0;
    ULONG EventsLost = 0;
    ULONG BuffersLost = 0;

private:
    REGHANDLE m_provider = 0;
    TRACEHANDLE m_session = 0;
    CorpusTraceProperties m_properties;
};
