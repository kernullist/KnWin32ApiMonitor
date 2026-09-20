#include "CorpusProtocol.h"
#include <evntcons.h>
#include <cstring>
#include <iomanip>
#include <iostream>

struct ReadContext
{
    std::vector<CorpusEvent> Events;
    bool Invalid = false;
};

void WINAPI OnEvent(EVENT_RECORD* record)
{
    auto& context = *static_cast<ReadContext*>(record->UserContext);
    if (IsEqualGUID(record->EventHeader.ProviderId, CorpusProvider))
    {
        if (record->EventHeader.EventDescriptor.Id != 1 || record->EventHeader.EventDescriptor.Version != 1 ||
            record->UserData == nullptr || record->UserDataLength != sizeof(CorpusEvent) || context.Events.size() >= 100000)
        {
            context.Invalid = true;
        }
        else
        {
            CorpusEvent event;
            std::memcpy(&event, record->UserData, sizeof(event));
            if (event.Api >= std::size(CorpusApiNames) || event.PreviewBytes > 16 || event.Success > 1 ||
                event.EndQpc < event.StartQpc || event.Sequence != context.Events.size())
            {
                context.Invalid = true;
            }
            else
            {
                context.Events.push_back(event);
            }
        }
    }
}

int wmain(int argc, wchar_t** argv)
{
    int result = 1;
    if (argc == 3 && std::wstring(argv[1]) == L"--probe-kernel")
    {
        CorpusTraceProperties properties;
        const std::wstring file(argv[2]);
        if (file.size() >= std::size(properties.File))
        {
            return 1;
        }
        properties.Properties.Wnode.BufferSize = sizeof(properties);
        properties.Properties.Wnode.Guid = {};
        properties.Properties.Wnode.ClientContext = 1;
        properties.Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties.Properties.BufferSize = 64;
        properties.Properties.MinimumBuffers = 2;
        properties.Properties.MaximumBuffers = 8;
        properties.Properties.MaximumFileSize = 1;
        properties.Properties.LogFileMode = EVENT_TRACE_SYSTEM_LOGGER_MODE | EVENT_TRACE_FILE_MODE_SEQUENTIAL;
        properties.Properties.EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_FILE_IO;
        properties.Properties.LoggerNameOffset = offsetof(CorpusTraceProperties, Name);
        properties.Properties.LogFileNameOffset = offsetof(CorpusTraceProperties, File);
        const std::wstring name = L"KNMon.Corpus.KernelAvailability";
        wcscpy_s(properties.Name, name.c_str());
        wcscpy_s(properties.File, file.c_str());
        TRACEHANDLE handle = 0;
        const auto started = StartTraceW(&handle, properties.Name, &properties.Properties);
        ULONG stopped = ERROR_SUCCESS;
        if (started == ERROR_SUCCESS)
        {
            stopped = ControlTraceW(handle, properties.Name, &properties.Properties, EVENT_TRACE_CONTROL_STOP);
        }
        std::cout << "{\"scope\":\"kernel_etw_session_availability\",\"startStatus\":" << started
            << ",\"stopStatus\":" << (started == ERROR_SUCCESS ? std::to_string(stopped) : "null")
            << ",\"available\":" << (started == ERROR_SUCCESS && stopped == ERROR_SUCCESS ? "true" : "false") << "}\n";
        result = stopped == ERROR_SUCCESS ? 0 : 1;
    }
    else if (argc == 2)
    {
        ReadContext context;
        context.Events.reserve(100000);
        EVENT_TRACE_LOGFILEW logfile = {};
        logfile.LogFileName = argv[1];
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = OnEvent;
        logfile.Context = &context;
        TRACEHANDLE handle = OpenTraceW(&logfile);
        if (handle != INVALID_PROCESSTRACE_HANDLE)
        {
            const auto status = ProcessTrace(&handle, 1, nullptr, nullptr);
            CloseTrace(handle);
            if (status == ERROR_SUCCESS && !context.Invalid && !context.Events.empty())
            {
                std::cout << "{\"source\":\"application_instrumented_private_etw\",\"events\":[";
                for (const auto& event : context.Events)
                {
                    std::cout << (event.Sequence == 0 ? "" : ",") << "{\"sequence\":" << event.Sequence
                        << ",\"api\":\"" << CorpusApiNames[event.Api] << "\",\"success\":" << (event.Success ? "true" : "false")
                        << ",\"error\":" << event.Error << ",\"byteCount\":" << event.ByteCount << ",\"preview\":\"";
                    for (std::uint32_t index = 0; index < event.PreviewBytes; ++index)
                    {
                        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned int>(event.Preview[index]);
                    }
                    std::cout << std::dec << "\",\"startQpc\":\"" << event.StartQpc << "\",\"endQpc\":\"" << event.EndQpc << "\"}";
                }
                std::cout << "]}\n";
                result = 0;
            }
            else
            {
                std::cerr << "ETW replay failed: " << status << " invalid=" << context.Invalid << "\n";
            }
        }
        else
        {
            std::cerr << "OpenTrace failed: " << GetLastError() << "\n";
        }
    }
    return result;
}
