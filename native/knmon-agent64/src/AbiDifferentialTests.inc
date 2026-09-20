// Test-only code. This file is never compiled into a production agent.
void AbiCheck(bool condition, const char* message)
{
    if (!condition)
    {
        throw message;
    }
}

BOOL WINAPI AbiMutatingWrite(HANDLE, LPCVOID buffer, DWORD size, LPDWORD written, LPOVERLAPPED)
{
    if (size != 0)
    {
        static_cast<char*>(const_cast<void*>(buffer))[0] = 'Z';
    }
    *written = size;
    SetLastError(4321);
    return 2;
}

BOOL WINAPI AbiPendingRead(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)
{
    SetLastError(ERROR_IO_PENDING);
    return FALSE;
}

BOOL WINAPI AbiImmediateRead(HANDLE, LPVOID, DWORD, LPDWORD count, LPOVERLAPPED)
{
    if (count != nullptr)
    {
        *count = 0;
    }
    SetLastError(4321);
    return TRUE;
}

const knmon::KnMonTransportRecord& AbiLastRecord()
{
    AbiCheck(g_transportHeader->ProducerSequence > 0, "No API record was emitted.");
    return g_transportRecords[(g_transportHeader->ProducerSequence - 1) % g_transportCapacity];
}

#include "TypedAbiDifferentialTests.inc"

extern "C" __declspec(dllexport) DWORD WINAPI KnMonTestAbiDifferential(void* captureStack)
{
    DWORD failure = 1;
    AgentControlGuard control;
    HANDLE file = INVALID_HANDLE_VALUE;
    void* pages = nullptr;
    try
    {
        AbiCheck(control.Acquired() && CreateTestTransport(1024) && g_sessionGate.Open(), "Test transport setup failed.");
        g_stackFrameLimit = captureStack == nullptr ? 0 : knmon::NativeStackFrameLimit;
        SetLifecycleState(AgentLifecycleState::Running);
        InterlockedExchange(&g_hooksEnabled, 1);
        g_originalReadFile = &::ReadFile;
        g_originalWriteFile = &::WriteFile;
        wchar_t temporary[MAX_PATH] = {};
        wchar_t filePath[MAX_PATH] = {};
        const auto length = GetTempPathW(MAX_PATH, temporary);
        AbiCheck(length != 0 && length < MAX_PATH, "Temporary directory unavailable.");
        const auto formatted = swprintf_s(filePath, L"%sknmon-abi-%lu-%llu.tmp", temporary,
            GetCurrentProcessId(), GetTickCount64());
        AbiCheck(formatted > 0, "Temporary path exceeds capacity.");
        file = CreateFileW(filePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        AbiCheck(file != INVALID_HANDLE_VALUE, "Temporary file creation failed.");
        char data[32] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ12345";
        DWORD countA = 0;
        DWORD countB = 0;
        SetLastError(1234);
        const auto writeA = ::WriteFile(file, data, sizeof(data), &countA, nullptr);
        const auto writeErrorA = GetLastError();
        SetFilePointer(file, 0, nullptr, FILE_BEGIN);
        SetLastError(1234);
        const auto writeB = HookedWriteFile(file, data, sizeof(data), &countB, nullptr);
        const auto writeErrorB = GetLastError();
        AbiCheck(writeA == writeB && countA == countB && writeErrorA == writeErrorB, "WriteFile A/B result/output/error mismatch.");
        AbiCheck(AbiLastRecord().Values32[6] == 1 && AbiLastRecord().Values32[3] == sizeof(data) &&
            AbiLastRecord().Values32[4] == 16 && AbiLastRecord().Values64[2] == reinterpret_cast<std::uintptr_t>(&countB),
            "WriteFile entry snapshot or output pointer identity mismatch.");
        char outputA[32] = {};
        char outputB[32] = {};
        SetFilePointer(file, 0, nullptr, FILE_BEGIN);
        SetLastError(2468);
        const auto readA = ::ReadFile(file, outputA, sizeof(outputA), &countA, nullptr);
        const auto readErrorA = GetLastError();
        SetFilePointer(file, 0, nullptr, FILE_BEGIN);
        SetLastError(2468);
        const auto readB = HookedReadFile(file, outputB, sizeof(outputB), &countB, nullptr);
        const auto readErrorB = GetLastError();
        AbiCheck(readA == readB && countA == countB && readErrorA == readErrorB &&
            memcmp(outputA, outputB, sizeof(outputA)) == 0, "ReadFile A/B result/output/error mismatch.");
        AbiCheck(AbiLastRecord().Values32[6] == 2 && AbiLastRecord().Values32[2] == 1 &&
            AbiLastRecord().Values32[4] == 16, "ReadFile synchronous output snapshot mismatch.");

        // The original deliberately mutates its input to distinguish entry from exit.
        g_originalWriteFile = AbiMutatingWrite;
        char mutatedA[] = "ABCD";
        char mutatedB[] = "ABCD";
        const auto mutateA = AbiMutatingWrite(nullptr, mutatedA, 4, &countA, nullptr);
        const auto mutateErrorA = GetLastError();
        const auto mutateB = HookedWriteFile(nullptr, mutatedB, 4, &countB, nullptr);
        AbiCheck(mutateA == mutateB && GetLastError() == mutateErrorA && countA == countB &&
            memcmp(mutatedA, mutatedB, sizeof(mutatedA)) == 0, "Mutating original A/B mismatch.");
        AbiCheck(std::string_view(AbiLastRecord().Text0) == "41 42 43 44" &&
            AbiLastRecord().RawReturnValue == 2, "Entry sample was replaced by post-call memory or BOOL normalized.");
        const bool negativeControlDetected = AbiLastRecord().Text0[0] != '5';
        AbiCheck(negativeControlDetected, "Entry/exit negative control did not differ.");

        pages = VirtualAlloc(nullptr, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        AbiCheck(pages != nullptr, "Guarded buffer allocation failed.");
        DWORD oldProtection = 0;
        auto* unreadable = static_cast<char*>(pages) + 4096;
        AbiCheck(VirtualProtect(unreadable, 4096, PAGE_NOACCESS, &oldProtection), "Guarded buffer setup failed.");
        g_originalReadFile = AbiPendingRead;
        OVERLAPPED overlapped = {};
        const auto pending = HookedReadFile(nullptr, unreadable, 32, reinterpret_cast<LPDWORD>(unreadable), &overlapped);
        AbiCheck(!pending && GetLastError() == ERROR_IO_PENDING && AbiLastRecord().Values32[2] == 0 &&
            AbiLastRecord().Values32[6] == 0 && AbiLastRecord().Text0Length == 0,
            "Pending output was dereferenced or reported as complete.");
        g_originalReadFile = AbiImmediateRead;
        const auto immediate = HookedReadFile(nullptr, outputB, sizeof(outputB), &countB, &overlapped);
        AbiCheck(immediate && GetLastError() == 4321 && AbiLastRecord().Values32[6] == 0 &&
            AbiLastRecord().Values32[2] == 0, "Overlapped return was treated as tracked completion.");
        const auto empty = HookedReadFile(nullptr, nullptr, 0, &countB, nullptr);
        AbiCheck(empty && GetLastError() == 4321 && AbiLastRecord().Values32[6] == 2 &&
            AbiLastRecord().Values32[3] == 0 && AbiLastRecord().Values32[5] == 1, "Zero-length output capture is inconsistent.");
        const auto guarded = knmon::CaptureIoBuffer(unreadable, 16);
        AbiCheck(guarded.Captured == 0 && guarded.Status == knmon::IoReadStatus::Unreadable,
            "Unreadable buffer capture must report failure without a target exception.");
        const auto crossing = knmon::CaptureIoBuffer(unreadable - 8, 32);
        AbiCheck(crossing.Captured <= 8 && crossing.Status != knmon::IoReadStatus::Complete,
            "Page-crossing capture claimed complete readable memory.");

        g_originalLdrLoadDll = reinterpret_cast<LdrLoadDllFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrLoadDll"));
        g_originalLdrGetProcedureAddress = reinterpret_cast<LdrGetProcedureAddressFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrGetProcedureAddress"));
        AbiCheck(g_originalLdrLoadDll != nullptr && g_originalLdrGetProcedureAddress != nullptr, "Native loader exports missing.");
        wchar_t libraryName[] = L"kernel32.dll";
        UNICODE_STRING name{static_cast<USHORT>(sizeof(libraryName) - sizeof(wchar_t)), sizeof(libraryName), libraryName};
        ULONG characteristics = 0;
        HANDLE moduleA = nullptr;
        HANDLE moduleB = nullptr;
        SetLastError(3141);
        const auto loadA = g_originalLdrLoadDll(nullptr, &characteristics, &name, &moduleA);
        const auto loadErrorA = GetLastError();
        SetLastError(3141);
        const auto loadB = HookedLdrLoadDll(nullptr, &characteristics, &name, &moduleB);
        const auto loadErrorB = GetLastError();
        if (moduleA != nullptr)
        {
            FreeLibrary(static_cast<HMODULE>(moduleA));
        }
        if (moduleB != nullptr)
        {
            FreeLibrary(static_cast<HMODULE>(moduleB));
        }
        AbiCheck(loadA == loadB && NT_SUCCESS(loadB) && moduleA == moduleB && loadErrorA == loadErrorB,
            "LdrLoadDll A/B result/output/error mismatch.");
        AbiCheck(AbiLastRecord().Values64[2] == reinterpret_cast<std::uintptr_t>(&characteristics),
            "LdrLoadDll characteristics pointer was truncated.");
        if constexpr (sizeof(void*) == 8)
        {
            AbiCheck(reinterpret_cast<std::uintptr_t>(&characteristics) > UINT32_MAX &&
                AbiLastRecord().Values64[2] != static_cast<ULONG>(reinterpret_cast<std::uintptr_t>(&characteristics)),
                "Pointer-width negative control did not expose the old ABI defect.");
        }
        char procedureName[] = "GetCurrentProcessId";
        ANSI_STRING procedure{sizeof(procedureName) - 1, sizeof(procedureName), procedureName};
        PVOID addressA = nullptr;
        PVOID addressB = nullptr;
        SetLastError(2718);
        const auto resolveA = g_originalLdrGetProcedureAddress(moduleA, &procedure, 0, &addressA);
        const auto resolveErrorA = GetLastError();
        SetLastError(2718);
        const auto resolveB = HookedLdrGetProcedureAddress(moduleA, &procedure, 0, &addressB);
        const auto resolveErrorB = GetLastError();
        AbiCheck(resolveA == resolveB && NT_SUCCESS(resolveB) && addressA == addressB && resolveErrorA == resolveErrorB,
            "LdrGetProcedureAddress A/B result/output/error mismatch.");
        CheckTypedAbiDifferential();
        const auto& stack = g_transportRecords[0].Stack;
        AbiCheck(knmon::ValidateNativeStackRecord(stack, sizeof(void*) * 8) && stack.RequestedFrames == g_stackFrameLimit &&
            (g_stackFrameLimit == 0 || stack.Status == knmon::NativeStackCaptureStatus::Captured),
            "Actual ABI callback did not preserve the requested stack mode.");
        AbiCheck(!g_inHook && g_hookEpoch == 0 && g_callErrorState == nullptr, "Hook scope leaked into the caller.");
        std::printf("ABI A/B PASS: file I/O, entry mutation, pending, overlapped, guard pages, native loader, negative controls.\n");
        failure = 0;
    }
    catch (const char* message)
    {
        std::printf("ABI A/B failure: %s\n", message);
    }
    InterlockedExchange(&g_hooksEnabled, 0);
    g_sessionGate.Close();
    if (!g_sessionGate.Quiescent())
    {
        failure = 2;
    }
    CloseTransport();
    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
    if (pages != nullptr)
    {
        VirtualFree(pages, 0, MEM_RELEASE);
    }
    return failure;
}

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:KnMonTestAbiDifferential=_KnMonTestAbiDifferential@4")
#endif
