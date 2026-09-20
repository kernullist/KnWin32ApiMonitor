// Test-only original/wrapped comparisons using SDK-typed function pointers.

struct AbiModule
{
    HMODULE Handle = nullptr;
    explicit AbiModule(const wchar_t* name) : Handle(LoadLibraryExW(name, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32))
    {
        AbiCheck(Handle != nullptr, "Typed ABI provider unavailable.");
    }
    ~AbiModule()
    {
        FreeLibrary(Handle);
    }
};

template <typename T>
bool AbiSameBits(const T& left, const T& right)
{
    return std::memcmp(&left, &right, sizeof(T)) == 0;
}

struct AbiMachineState
{
    DWORD Error;
    unsigned int Mxcsr;
    unsigned int FloatingStatus;
};

template <typename Action>
AbiMachineState AbiRun(Action action)
{
    std::feclearexcept(FE_ALL_EXCEPT);
    SetLastError(0x12345678);
    action();
    const DWORD error = GetLastError();
    return {error, _mm_getcsr(), _statusfp()};
}

void AbiStateEqual(const AbiMachineState& left, const AbiMachineState& right)
{
    AbiCheck(left.Error == right.Error && left.Mxcsr == right.Mxcsr && left.FloatingStatus == right.FloatingStatus,
        "Typed ABI changed caller error or floating-point state.");
}

struct AbiWindowTree
{
    HWND Parent = nullptr;
    AbiWindowTree()
    {
        Parent = CreateWindowExW(0, L"STATIC", L"", WS_OVERLAPPED, 0, 0, 1, 1, nullptr, nullptr, nullptr, nullptr);
        AbiCheck(Parent != nullptr, "Hidden window tree setup failed.");
    }
    ~AbiWindowTree()
    {
        DestroyWindow(Parent);
    }
};

struct AbiCallbackContext
{
    bool Wrapped = false;
    bool StopEarly = false;
    int Count = 0;
    int Ids[4] = {};
    bool ValuesMatch = true;
};

BOOL CALLBACK AbiEnumCallback(HWND window, LPARAM parameter)
{
    auto& context = *reinterpret_cast<AbiCallbackContext*>(parameter);
    context.Ids[context.Count++] = GetDlgCtrlID(window);
    const float length = context.Wrapped ? HookedTypedD2D1Vec3Length(3.0f, 4.0f, 0.0f) :
        g_originalTypedD2D1Vec3Length(3.0f, 4.0f, 0.0f);
    context.ValuesMatch = context.ValuesMatch && length == 5.0f;
    SetLastError(7654);
    return context.StopEarly ? FALSE : TRUE;
}

FLOAT WINAPI AbiThrowingFloat(FLOAT, FLOAT, FLOAT)
{
    SetLastError(4567);
    throw 0x2345;
}

D2D1_COLOR_F WINAPI AbiRaisingColor(D2D1_COLOR_SPACE, D2D1_COLOR_SPACE, const D2D1_COLOR_F*)
{
    SetLastError(5678);
    RaiseException(0xe0570010, 0, 0, nullptr);
    return {};
}

bool AbiColorSeh()
{
    bool caught = false;
    D2D1_COLOR_F color = {};
    __try
    {
        HookedTypedD2D1ConvertColorSpace(D2D1_COLOR_SPACE_SRGB, D2D1_COLOR_SPACE_SRGB, &color);
    }
    __except (GetExceptionCode() == 0xe0570010 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        caught = GetLastError() == 5678;
    }
    return caught;
}

void CheckTypedAbiDifferential()
{
    AbiModule automation(L"oleaut32.dll");
    AbiModule drawing(L"d2d1.dll");
    g_originalTypedVarR8FromR4 = reinterpret_cast<decltype(&::VarR8FromR4)>(GetProcAddress(automation.Handle, "VarR8FromR4"));
    g_originalTypedVarR4FromR8 = reinterpret_cast<decltype(&::VarR4FromR8)>(GetProcAddress(automation.Handle, "VarR4FromR8"));
    g_originalTypedD2D1ConvertColorSpace = reinterpret_cast<decltype(&::D2D1ConvertColorSpace)>(GetProcAddress(drawing.Handle, "D2D1ConvertColorSpace"));
    g_originalTypedD2D1MakeRotateMatrix = reinterpret_cast<decltype(&::D2D1MakeRotateMatrix)>(GetProcAddress(drawing.Handle, "D2D1MakeRotateMatrix"));
    g_originalTypedD2D1Vec3Length = reinterpret_cast<decltype(&::D2D1Vec3Length)>(GetProcAddress(drawing.Handle, "D2D1Vec3Length"));
    g_originalTypedEnumChildWindows = &::EnumChildWindows;
    AbiCheck(g_originalTypedVarR8FromR4 && g_originalTypedVarR4FromR8 && g_originalTypedD2D1ConvertColorSpace &&
        g_originalTypedD2D1MakeRotateMatrix && g_originalTypedD2D1Vec3Length, "Typed SDK export missing.");
    static_assert(!std::is_same_v<decltype(&::VarR8FromR4), HRESULT(WINAPI*)(std::uintptr_t, DOUBLE*)>);
    static_assert(!std::is_same_v<decltype(&::D2D1ConvertColorSpace), std::uintptr_t(WINAPI*)(D2D1_COLOR_SPACE, D2D1_COLOR_SPACE, const D2D1_COLOR_F*)>);
#if defined(_M_IX86)
    static_assert(!std::is_same_v<decltype(&::VarR8FromR4), HRESULT(__cdecl*)(FLOAT, DOUBLE*)>);
#endif
    std::fenv_t savedEnvironment;
    std::fegetenv(&savedEnvironment);
    g_nextCallId.store(9007199254740992ULL);
    for (const std::uint32_t bits : {0U, 0x80000000U, 1U, 0x00800000U, 0x3fa00000U, 0xc1234000U,
        0x7f7fffffU, 0x7f800000U, 0xff800000U, 0x7fc12345U, 0x7f812345U})
    {
        float input = 0;
        std::memcpy(&input, &bits, sizeof(input));
        double outputA = -99;
        double outputB = -99;
        HRESULT resultA = E_UNEXPECTED;
        HRESULT resultB = E_UNEXPECTED;
        const auto stateA = AbiRun([&]()
        {
            resultA = g_originalTypedVarR8FromR4(input, &outputA);
        });
        const auto stateB = AbiRun([&]()
        {
            resultB = HookedTypedVarR8FromR4(input, &outputB);
        });
        AbiStateEqual(stateA, stateB);
        AbiCheck(resultA == resultB && AbiSameBits(outputA, outputB), "FLOAT argument/output differential mismatch.");
        AbiCheck(AbiLastRecord().Values64[0] == bits, "FLOAT argument bits were not preserved.");
    }
    for (const double input : {0.0, -0.0, 1.25, -20.125, 1.0e-40, 1.0e300, std::numeric_limits<double>::infinity()})
    {
        float outputA = -99;
        float outputB = -99;
        HRESULT resultA = E_UNEXPECTED;
        HRESULT resultB = E_UNEXPECTED;
        const auto stateA = AbiRun([&]()
        {
            resultA = g_originalTypedVarR4FromR8(input, &outputA);
        });
        const auto stateB = AbiRun([&]()
        {
            resultB = HookedTypedVarR4FromR8(input, &outputB);
        });
        AbiStateEqual(stateA, stateB);
        AbiCheck(resultA == resultB && AbiSameBits(outputA, outputB), "DOUBLE argument/failure output differential mismatch.");
        AbiCheck(AbiLastRecord().Values64[0] == std::bit_cast<std::uint64_t>(input), "DOUBLE argument bits were not preserved.");
    }
    for (int index = 0; index < 32; ++index)
    {
        const float angle = static_cast<float>(index) * 11.25f - 125.5f;
        const D2D1_POINT_2F center{1.25f, -3.75f};
        D2D1_MATRIX_3X2_F matrixA = {};
        D2D1_MATRIX_3X2_F matrixB = {};
        const auto stateA = AbiRun([&]()
        {
            g_originalTypedD2D1MakeRotateMatrix(angle, center, &matrixA);
        });
        const auto stateB = AbiRun([&]()
        {
            HookedTypedD2D1MakeRotateMatrix(angle, center, &matrixB);
        });
        AbiStateEqual(stateA, stateB);
        AbiCheck(AbiSameBits(matrixA, matrixB), "Mixed FLOAT/by-value aggregate output mismatch.");
        AbiCheck(AbiLastRecord().RawReturnBits == 0 && AbiLastRecord().Values64[1] == std::bit_cast<std::uint64_t>(center),
            "Void result or aggregate argument bits mismatch.");
        float lengthA = 0;
        float lengthB = 0;
        const auto lengthStateA = AbiRun([&]()
        {
            lengthA = g_originalTypedD2D1Vec3Length(angle, 4.25f, -0.5f);
        });
        const auto lengthStateB = AbiRun([&]()
        {
            lengthB = HookedTypedD2D1Vec3Length(angle, 4.25f, -0.5f);
        });
        AbiStateEqual(lengthStateA, lengthStateB);
        AbiCheck(AbiSameBits(lengthA, lengthB) && AbiLastRecord().RawReturnValue == std::bit_cast<std::uint32_t>(lengthB),
            "FLOAT return register or captured bits mismatch.");
    }
    const D2D1_COLOR_F input{0.125f, 0.5f, 0.875f, 0.75f};
    D2D1_COLOR_F colorA = {};
    D2D1_COLOR_F colorB = {};
    const auto colorStateA = AbiRun([&]()
    {
        colorA = g_originalTypedD2D1ConvertColorSpace(D2D1_COLOR_SPACE_SRGB, D2D1_COLOR_SPACE_SCRGB, &input);
    });
    const auto colorStateB = AbiRun([&]()
    {
        colorB = HookedTypedD2D1ConvertColorSpace(D2D1_COLOR_SPACE_SRGB, D2D1_COLOR_SPACE_SCRGB, &input);
    });
    AbiStateEqual(colorStateA, colorStateB);
    AbiCheck(AbiSameBits(colorA, colorB) && AbiLastRecord().RawReturnBits == 128 &&
        std::memcmp(AbiLastRecord().RawReturnBytes, &colorB, 16) == 0, "Hidden aggregate return buffer/bytes mismatch.");
    AbiCheck(colorB.a != 0.0f && AbiLastRecord().RawReturnValue == 0, "Aggregate truncation negative control is ineffective.");
    AbiWindowTree tree;
    AbiCheck(CreateWindowExW(0, L"STATIC", L"", WS_CHILD, 0, 0, 1, 1, tree.Parent,
        reinterpret_cast<HMENU>(101), nullptr, nullptr) != nullptr, "First child setup failed.");
    AbiCheck(CreateWindowExW(0, L"STATIC", L"", WS_CHILD, 0, 0, 1, 1, tree.Parent,
        reinterpret_cast<HMENU>(102), nullptr, nullptr) != nullptr, "Second child setup failed.");
    for (const bool stop : {false, true})
    {
        AbiCallbackContext contextA{false, stop};
        AbiCallbackContext contextB{true, stop};
        BOOL resultA = FALSE;
        BOOL resultB = FALSE;
        const auto stateA = AbiRun([&]()
        {
            resultA = ::EnumChildWindows(tree.Parent, AbiEnumCallback, reinterpret_cast<LPARAM>(&contextA));
        });
        const auto sequence = g_transportHeader->ProducerSequence;
        const auto stateB = AbiRun([&]()
        {
            resultB = HookedTypedEnumChildWindows(tree.Parent, AbiEnumCallback, reinterpret_cast<LPARAM>(&contextB));
        });
        AbiStateEqual(stateA, stateB);
        AbiCheck(resultA == resultB && contextA.ValuesMatch && contextB.ValuesMatch && contextA.Count == contextB.Count &&
            contextB.Count == (stop ? 1 : 2) && std::memcmp(contextA.Ids, contextB.Ids, sizeof(contextA.Ids)) == 0,
            "Callback context, early stop, or window identity mismatch.");
        AbiCheck(g_transportHeader->ProducerSequence == sequence + 1, "Suppressed callback nesting emitted an extra record.");
    }
    const auto sequence = g_transportHeader->ProducerSequence;
    g_originalTypedD2D1Vec3Length = AbiThrowingFloat;
    bool caught = false;
    try
    {
        HookedTypedD2D1Vec3Length(1, 2, 3);
    }
    catch (int value)
    {
        caught = value == 0x2345 && GetLastError() == 4567;
    }
    AbiCheck(caught && g_transportHeader->ProducerSequence == sequence, "Original C++ exception was changed or emitted a return record.");
    g_originalTypedD2D1ConvertColorSpace = AbiRaisingColor;
    AbiCheck(AbiColorSeh() && g_transportHeader->ProducerSequence == sequence, "Original aggregate-return SEH was changed.");
    AbiCheck(!g_inHook && g_currentCallId == 0 && g_callErrorState == nullptr, "Typed hook scope leaked after exceptions.");
    std::uint64_t previousId = 0;
    for (LONG64 index = 0; index < g_transportHeader->ProducerSequence; ++index)
    {
        const auto& record = g_transportRecords[index];
        AbiCheck(record.CallId > previousId && record.ParentCallId == 0 && record.CallDepth == 0,
            "Root call identities are not unique/ordered in the single-thread corpus.");
        previousId = record.CallId;
    }
    AbiCheck(previousId > 9007199254740992ULL, "Large call identity control was not exercised.");
    std::array<std::uint64_t, 4000> identities = {};
    std::array<std::thread, 4> workers;
    for (std::size_t worker = 0; worker < workers.size(); ++worker)
    {
        workers[worker] = std::thread([&, worker]()
        {
            for (std::size_t index = 0; index < 1000; ++index)
            {
                identities[worker * 1000 + index] = NextCallId();
            }
        });
    }
    for (auto& worker : workers)
    {
        worker.join();
    }
    std::sort(identities.begin(), identities.end());
    for (std::size_t index = 1; index < identities.size(); ++index)
    {
        AbiCheck(identities[index] == identities[index - 1] + 1, "Concurrent call identity collision or gap.");
    }
    const auto next = g_nextCallId.load();
    g_nextCallId.store(static_cast<std::uint64_t>(INT64_MAX) - 1);
    AbiCheck(NextCallId() == static_cast<std::uint64_t>(INT64_MAX) && NextCallId() == 0 && NextCallId() == 0,
        "Exhausted call identities wrapped or were reused.");
    g_nextCallId.store(next);
    std::fesetenv(&savedEnvironment);
    std::printf("Typed SDK ABI A/B PASS: 6 APIs, FP bits/output/errors, aggregate ABI, callback/reentry, C++/SEH, MXCSR.\n");
}
