// Test-only controlled originals exercise production observation boundaries.
BOOL WINAPI ProfileRead(HANDLE, LPVOID, DWORD bytes, LPDWORD count, LPOVERLAPPED)
{
    *count = bytes;
    SetLastError(4321);
    return 2;
}

BOOL WINAPI ProfileWrite(HANDLE, LPCVOID, DWORD bytes, LPDWORD count, LPOVERLAPPED)
{
    *count = bytes;
    SetLastError(4321);
    return 2;
}

HANDLE WINAPI ProfileCreate(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)
{
    SetLastError(4321);
    return reinterpret_cast<HANDLE>(0x1234);
}

FLOAT WINAPI ProfileFloat(FLOAT x, FLOAT y, FLOAT z)
{
    SetLastError(4321);
    return x + y + z;
}

extern "C" __declspec(dllexport) DWORD WINAPI KnMonTestCaptureDetail(void*)
{
    DWORD failure = 1;
    AgentControlGuard control;
    const auto oldRead = g_originalReadFile;
    const auto oldWrite = g_originalWriteFile;
    const auto oldCreate = g_originalCreateFileW;
    const auto oldFloat = g_originalTypedD2D1Vec3Length;
    try
    {
        AbiCheck(control.Acquired(), "Capture detail control lock failed.");
        for (const auto detail : {knmon::CaptureDetail::Metadata, knmon::CaptureDetail::Arguments, knmon::CaptureDetail::Preview})
        {
            AbiCheck(CreateTestTransport(64) && g_sessionGate.Open(), "Capture detail transport failed.");
            SetLifecycleState(AgentLifecycleState::Running);
            InterlockedExchange(&g_hooksEnabled, 1);
            g_captureDetail = detail;
            g_stackFrameLimit = 8;
            g_originalReadFile = ProfileRead;
            g_originalWriteFile = ProfileWrite;
            g_originalCreateFileW = ProfileCreate;
            g_originalTypedD2D1Vec3Length = ProfileFloat;
            const auto expectedReads = detail == knmon::CaptureDetail::Metadata ? 0u :
                detail == knmon::CaptureDetail::Arguments ? 1u : 2u;
            DWORD count = 0;
            knmon::ObservationReadCalls = 0;
            SetLastError(1234);
            AbiCheck(HookedReadFile(nullptr, reinterpret_cast<void*>(1), 4, &count, nullptr) == 2 &&
                count == 4 && GetLastError() == 4321, "ReadFile profile changed original behavior.");
            AbiCheck(knmon::ObservationReadCalls == expectedReads, "ReadFile profile did not suppress memory reads.");
            knmon::ObservationReadCalls = 0;
            AbiCheck(HookedWriteFile(nullptr, reinterpret_cast<void*>(1), 4, &count, nullptr) == 2 &&
                count == 4 && GetLastError() == 4321, "WriteFile profile changed original behavior.");
            AbiCheck(knmon::ObservationReadCalls == expectedReads, "WriteFile profile did not suppress memory reads.");
            const auto path = detail == knmon::CaptureDetail::Metadata ? reinterpret_cast<LPCWSTR>(1) : L"profile-path";
            AbiCheck(HookedCreateFileW(path, 1, 2, nullptr, 3, 4, nullptr) == reinterpret_cast<HANDLE>(0x1234) &&
                GetLastError() == 4321, "CreateFileW profile changed original behavior.");
            AbiCheck(HookedTypedD2D1Vec3Length(1.0f, 2.0f, 4.0f) == 7.0f && GetLastError() == 4321,
                "Typed profile changed floating return or error state.");
            {
                HookReentryGuard guard;
                LARGE_INTEGER tick = {};
                QueryPerformanceCounter(&tick);
                EmitGenericSingleArgumentTier1Event("kernel32.dll", "GetSystemTime", "system-safe", "system",
                    "system/system-information", "kernel32.dll!GetSystemTime", "value|DWORD|in|value",
                    1234, 0, GenericReturnFormat::Void, 0, tick, tick);
            }
            AbiCheck(g_transportHeader->ProducerSequence == 5 && g_transportHeader->DroppedEvents == 0,
                "Capture detail unexpectedly dropped or omitted an event.");
            for (std::uint32_t index = 0; index < 5; ++index)
            {
                const auto& record = g_transportRecords[index];
                AbiCheck(record.Detail == detail && record.Stack.RequestedFrames == 8 &&
                    record.Stack.Status == knmon::NativeStackCaptureStatus::Captured,
                    "Capture detail or orthogonal stack capture was lost.");
                if (detail == knmon::CaptureDetail::Metadata)
                {
                    AbiCheck(std::all_of(std::begin(record.Values64), std::end(record.Values64),
                        [](std::uint64_t value)
                        {
                            return value == 0;
                        }), "Metadata profile captured argument values.");
                    AbiCheck(record.Values32[0] == 0 && record.Text2Length == 0,
                        "Metadata profile captured argument count or preview.");
                }
            }
            AbiCheck(g_transportRecords[0].RawReturnValue == 2 && g_transportRecords[0].RawLastErrorCode == 4321,
                "Metadata lost raw result or error state.");
            AbiCheck(g_transportRecords[2].Text0Length == (CaptureArguments() ? 12u : 0u),
                "String capture boundary was not respected.");
            AbiCheck(g_transportRecords[3].Values32[0] == (CaptureArguments() ? 3u : 0u) &&
                g_transportRecords[4].Values32[0] == (CaptureArguments() ? 1u : 0u),
                "Typed or generic argument count disagrees with detail.");
            char preview[32] = {};
            std::uint32_t length = 0;
            knmon::ObservationReadCalls = 0;
            const auto status = CopyRegistryDataPreviewText(preview, &length, sizeof(preview), REG_BINARY,
                reinterpret_cast<const BYTE*>(1), 4);
            AbiCheck(knmon::ObservationReadCalls == (CaptureBufferPreviews() ? 1u : 0u),
                "Registry buffer profile did not suppress memory reads.");
            if (!CaptureBufferPreviews())
            {
                AbiCheck(status == static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::NotCaptured) && length == 0,
                    "Disabled preview reported a decoded value.");
            }
            InterlockedExchange(&g_hooksEnabled, 0);
            g_sessionGate.Close();
            AbiCheck(g_sessionGate.Quiescent(), "Capture detail lease did not drain.");
            CloseTransport();
        }
        failure = 0;
    }
    catch (const char* message)
    {
        OutputDebugStringA(message);
    }
    catch (...)
    {
        OutputDebugStringA("Capture detail test threw unexpectedly.");
    }
    InterlockedExchange(&g_hooksEnabled, 0);
    g_sessionGate.Close();
    CloseTransport();
    g_captureDetail = knmon::CaptureDetail::Preview;
    g_stackFrameLimit = 0;
    g_originalReadFile = oldRead;
    g_originalWriteFile = oldWrite;
    g_originalCreateFileW = oldCreate;
    g_originalTypedD2D1Vec3Length = oldFloat;
    SetLifecycleState(AgentLifecycleState::Disabled);
    return failure;
}

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:KnMonTestCaptureDetail=_KnMonTestCaptureDetail@4")
#endif
