#include "ModuleTestPaths.h"

namespace
{
void ModuleTestCheck(bool passed, unsigned stage)
{
    if (!passed)
    {
        throw stage;
    }
}

template <typename Predicate>
bool ModuleTestWait(Predicate&& predicate)
{
    const auto deadline = GetTickCount64() + 4000;
    bool completed = false;
    do
    {
        completed = predicate();
        if (completed)
        {
            break;
        }
        Sleep(5);
    }
    while (GetTickCount64() < deadline);
    return completed;
}

ULONG_PTR* ModuleTestPidSlot(HMODULE module, IMAGE_IMPORT_DESCRIPTOR** descriptor = nullptr)
{
    ModuleReference reference(module);
    ModuleInfo info;
    ModuleTestCheck(ReadReferencedModuleInfo(reference, info), 20);
    IMAGE_IMPORT_DESCRIPTOR* imports = nullptr;
    std::size_t count = 0;
    ULONG_PTR* result = nullptr;
    if (ReadImageImportDirectory(module, info.SizeOfImage, &imports, &count))
    {
        auto* base = reinterpret_cast<std::uint8_t*>(module);
        const auto definitions = BuildManualHookDefinitions();
        for (std::size_t index = 0; index < count && imports[index].Name != 0; ++index)
        {
            auto* names = ImageRvaToPointer<IMAGE_THUNK_DATA>(base, info.SizeOfImage, imports[index].OriginalFirstThunk);
            auto* slots = ImageRvaToPointer<IMAGE_THUNK_DATA>(base, info.SizeOfImage, imports[index].FirstThunk);
            for (std::size_t slot = 0; names != nullptr && names[slot].u1.AddressOfData != 0; ++slot)
            {
                for (const auto& definition : definitions)
                {
                    if (std::strcmp(definition.ApiName, "GetCurrentProcessId") == 0 &&
                        ImportMatchesDefinition(base, info.SizeOfImage, &names[slot], definition))
                    {
                        result = reinterpret_cast<ULONG_PTR*>(&slots[slot].u1.Function);
                        if (descriptor != nullptr)
                        {
                            *descriptor = &imports[index];
                        }
                    }
                }
            }
        }
    }
    ModuleTestCheck(result != nullptr, 21);
    return result;
}

void ModuleTestWrite(void* destination, const void* data, std::size_t size)
{
    DWORD old = 0;
    ModuleTestCheck(VirtualProtect(destination, size, PAGE_READWRITE, &old) != FALSE, 22);
    std::memcpy(destination, data, size);
    DWORD ignored = 0;
    ModuleTestCheck(VirtualProtect(destination, size, old, &ignored) != FALSE, 23);
}

DWORD WINAPI ModuleTestForeignPid()
{
    return 4242;
}

using ModuleTestProbe = DWORD(WINAPI*)();

bool ModuleTestIsPatched(ULONG_PTR* slot)
{
    return std::atomic_ref<ULONG_PTR>(*slot).load() == reinterpret_cast<ULONG_PTR>(HookedGetCurrentProcessId);
}

void ModuleTestCallProbe(HMODULE module)
{
    const auto probe = reinterpret_cast<ModuleTestProbe>(GetProcAddress(module, "Probe"));
    ModuleTestCheck(probe != nullptr, 24);
    const auto before = InterlockedCompareExchange64(&g_transportHeader->ProducerSequence, 0, 0);
    InterlockedExchange64(&g_transportHeader->ConsumerSequence, before);
    SetLastError(7351);
    const DWORD result = probe();
    const DWORD error = GetLastError();
    ModuleTestCheck(result == GetCurrentProcessId() && error == 7351, 25);
    ModuleTestCheck(InterlockedCompareExchange64(&g_transportHeader->ProducerSequence, 0, 0) > before, 26);
}
}

extern "C" __declspec(dllexport) DWORD WINAPI KnMonTestModules(void* context)
{
    const auto& paths = *static_cast<const ModuleTestPaths*>(context);
    AgentControlGuard control;
    DWORD result = 0;
    HMODULE probeA = nullptr;
    HMODULE probeB = nullptr;
    HMODULE delay = nullptr;
    HMODULE twinA = nullptr;
    HMODULE twinB = nullptr;
    HANDLE entered = nullptr;
    HANDLE resume = nullptr;
    try
    {
        ModuleTestCheck(control.Acquired() && InitializeModuleTracking() && CreateTestTransport(256), 2);
        g_selectedApiSelection = "kernel32.dll!getcurrentprocessid;winmm.dll!timegettime;version.dll!getfileversioninfosizew;ws2_32.dll!wsagetlasterror";
        probeA = LoadLibraryW(paths.ProbeA);
        probeB = LoadLibraryW(paths.ProbeB);
        ModuleTestCheck(probeA != nullptr && probeB != nullptr, 3);
        IMAGE_IMPORT_DESCRIPTOR* descriptor = nullptr;
        auto* slotA = ModuleTestPidSlot(probeA, &descriptor);
        auto* slotB = ModuleTestPidSlot(probeB);
        const DWORD absent = 0;
        ModuleTestWrite(&descriptor->OriginalFirstThunk, &absent, sizeof(absent));
        {
            auto definitions = std::make_unique<std::array<HookDefinition, HookDefinitionCount>>();
            BuildHookDefinitions(definitions->data(), definitions->size());
            ResolveHookDefinitions(*definitions);
            HookDefinition canonical;
            for (const auto& definition : *definitions)
            {
                if (std::strcmp(definition.ApiName, "GetCurrentProcessId") == 0)
                {
                    canonical = definition;
                }
            }
            HookDefinition alias = canonical;
            alias.ApiName = "TestPidAlias";
            HookModuleIndex index{{"kernel32.dll", {&canonical, &alias}}};
            ModuleReference owner(probeA);
            ModuleInfo info;
            ModuleTestCheck(ReadReferencedModuleInfo(owner, info), 27);
            SweepStats stats;
            HookLockGuard lock;
            PatchImportsInModule(info, index, stats);
            ModuleTestCheck(stats.AmbiguousAddressSlots == 1 && stats.PatchedSlots == 0 && !ModuleTestIsPatched(slotA), 28);
        }
        const auto foreign = reinterpret_cast<ULONG_PTR>(ModuleTestForeignPid);
        ModuleTestWrite(slotB, &foreign, sizeof(foreign));
        ModuleTestCheck(InstallHooks(), 4);
        ModuleTestCheck(ModuleTestIsPatched(slotA), 5);
        ModuleTestCheck(*slotB == foreign, 6);
        ModuleTestCallProbe(probeA);
        const auto foreignProbe = reinterpret_cast<ModuleTestProbe>(GetProcAddress(probeB, "Probe"));
        ModuleTestCheck(foreignProbe() == 4242, 7);
        const auto realPid = reinterpret_cast<ULONG_PTR>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetCurrentProcessId"));
        ModuleTestWrite(slotB, &realPid, sizeof(realPid));
        RequestModuleSweep();
        ModuleTestCheck(ModuleTestWait([&]()
        {
            return ModuleTestIsPatched(slotB);
        }), 8);
        ModuleTestCallProbe(probeB);

        const HMODULE oldA = probeA;
        const HMODULE oldB = probeB;
        FreeLibrary(probeA);
        FreeLibrary(probeB);
        probeA = nullptr;
        probeB = nullptr;
        ModuleTestCheck(ModuleTestWait([&]()
        {
            return g_moduleGenerations.Read(oldA) == 0 && g_moduleGenerations.Read(oldB) == 0;
        }), 9);
        const auto burstStart = GetTickCount64();
        probeA = LoadLibraryW(paths.ProbeA);
        probeB = LoadLibraryW(paths.ProbeB);
        ModuleTestCheck(probeA != nullptr && probeB != nullptr && GetTickCount64() - burstStart < 250, 10);
        slotA = ModuleTestPidSlot(probeA);
        slotB = ModuleTestPidSlot(probeB);
        // No further loader call or explicit request may be needed for the trailing sweep.
        ModuleTestCheck(ModuleTestWait([&]()
        {
            return ModuleTestIsPatched(slotA) && ModuleTestIsPatched(slotB);
        }), 11);
        ModuleTestCallProbe(probeA);
        ModuleTestCallProbe(probeB);

        for (unsigned cycle = 0; cycle < 40; ++cycle)
        {
            const HMODULE previous = probeA;
            const auto generation = g_moduleGenerations.Read(previous);
            FreeLibrary(probeA);
            probeA = nullptr;
            ModuleTestCheck(ModuleTestWait([&]()
            {
                return g_moduleGenerations.Read(previous) == 0;
            }), 12);
            probeA = LoadLibraryW(paths.ProbeA);
            ModuleTestCheck(probeA != nullptr && g_moduleGenerations.Read(probeA) > generation, 13);
            slotA = ModuleTestPidSlot(probeA);
            ModuleTestCheck(ModuleTestWait([&]()
            {
                return ModuleTestIsPatched(slotA);
            }), 14);
            ModuleTestCallProbe(probeA);
        }

        delay = LoadLibraryW(paths.DelayProbe);
        ModuleTestCheck(delay != nullptr, 30);
        auto* delayPid = ModuleTestPidSlot(delay);
        ModuleTestCheck(ModuleTestWait([&]()
        {
            return ModuleTestIsPatched(delayPid);
        }), 31);
        const auto delayed = reinterpret_cast<ModuleTestProbe>(GetProcAddress(delay, "ProbeDelay"));
        ModuleTestCheck(delayed != nullptr, 32);
        const auto beforeDelay = InterlockedCompareExchange64(&g_transportHeader->ProducerSequence, 0, 0);
        InterlockedExchange64(&g_transportHeader->ConsumerSequence, beforeDelay);
        ModuleTestCheck(delayed() == 0, 33);
        const auto afterDelay = InterlockedCompareExchange64(&g_transportHeader->ProducerSequence, 0, 0);
        bool delayedCallObserved = false;
        for (auto sequence = beforeDelay; sequence < afterDelay; ++sequence)
        {
            const auto& record = g_transportRecords[sequence % g_transportCapacity];
            if (record.ApiId == static_cast<std::uint16_t>(knmon::KnMonTransportApiId::GetFileVersionInfoSizeW))
            {
                delayedCallObserved = true;
            }
        }
        ModuleTestCheck(delayedCallObserved, 34);

        twinA = LoadLibraryW(paths.TwinA);
        twinB = LoadLibraryW(paths.TwinB);
        ModuleTestCheck(twinA != nullptr && twinB != nullptr && twinA != twinB, 40);
        auto* addressA = reinterpret_cast<void*>(GetProcAddress(twinA, "timeGetTime"));
        auto* addressB = reinterpret_cast<void*>(GetProcAddress(twinB, "timeGetTime"));
        ModuleTestCheck(addressA != nullptr && addressB != nullptr && addressA != addressB, 41);
        auto classificationA = ClassifyResolverPointer(twinA, "timeGetTime", false, 0, addressA);
        void* wrapper = SelectResolverPointerReplacement(classificationA, addressA);
        if (wrapper == nullptr)
        {
            std::printf("Twin A rejection: %s / %s module=%s target=%s\n", classificationA.Reason.c_str(),
                classificationA.InstrumentationReason.c_str(), classificationA.RequestedModuleName.c_str(), classificationA.TargetModuleName.c_str());
        }
        ModuleTestCheck(wrapper != nullptr && reinterpret_cast<ModuleTestProbe>(wrapper)() == 111, 42);
        auto classificationB = ClassifyResolverPointer(twinB, "timeGetTime", false, 0, addressB);
        ModuleTestCheck(SelectResolverPointerReplacement(classificationB, addressB) == nullptr &&
            classificationB.InstrumentationReason == "original_conflict" && reinterpret_cast<ModuleTestProbe>(addressB)() == 222, 43);
        ModuleTestCheck(reinterpret_cast<void*>(HookedGetProcAddress(twinB, "timeGetTime")) == addressB, 44);
        ModuleTestCheck(HookedGetProcAddress(twinA, "TwinAlias") == reinterpret_cast<FARPROC>(addressA), 45);
        ModuleTestCheck(GetProcAddress(twinA, MAKEINTRESOURCEA(141)) == reinterpret_cast<FARPROC>(addressA), 46);
        ModuleTestCheck(HookedGetProcAddress(twinA, MAKEINTRESOURCEA(141)) == reinterpret_cast<FARPROC>(wrapper), 47);
        ModuleTestCheck(HookedGetProcAddress(twinA, MAKEINTRESOURCEA(142)) == reinterpret_cast<FARPROC>(addressA), 48);
        auto exportConflict = ClassifyResolverPointer(twinA, "timeGetTime", false, 0, addressB);
        ModuleTestCheck(SelectResolverPointerReplacement(exportConflict, addressB) == nullptr &&
            exportConflict.InstrumentationReason == "export_identity_conflict", 49);
        char timeName[] = "timeGetTime";
        ANSI_STRING name{11, 12, timeName};
        void* ldrPointer = nullptr;
        ModuleTestCheck(NT_SUCCESS(HookedLdrGetProcedureAddress(twinB, &name, 0, &ldrPointer)) && ldrPointer == addressB, 50);
        ModuleTestCheck(NT_SUCCESS(HookedLdrGetProcedureAddress(twinA, &name, 0, &ldrPointer)) && ldrPointer == wrapper, 51);

        const HMODULE previousTwin = twinA;
        const auto previousGeneration = g_moduleGenerations.Read(twinA);
        FreeLibrary(twinA);
        twinA = nullptr;
        ModuleTestCheck(ModuleTestWait([&]()
        {
            return g_moduleGenerations.Read(previousTwin) == 0;
        }), 52);
        twinA = LoadLibraryW(paths.TwinA);
        ModuleTestCheck(twinA != nullptr && g_moduleGenerations.Read(twinA) > previousGeneration, 53);
        addressA = reinterpret_cast<void*>(GetProcAddress(twinA, "timeGetTime"));
        auto reloaded = ClassifyResolverPointer(twinA, "timeGetTime", false, 0, addressA);
        ModuleTestCheck(SelectResolverPointerReplacement(reloaded, addressA) == nullptr &&
            reloaded.InstrumentationReason == "original_conflict" && reinterpret_cast<ModuleTestProbe>(addressA)() == 111, 54);

        HMODULE winsock = LoadLibraryW(L"ws2_32.dll");
        ModuleTestCheck(winsock != nullptr, 60);
        {
            WinsockErrorAccessors accessors(true);
            ModuleTestCheck(accessors.Get != nullptr && accessors.Set != nullptr, 61);
            FreeLibrary(winsock);
            accessors.Set(19001);
            ModuleTestCheck(accessors.Get() == 19001, 62);
        }

        entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        resume = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ModuleTestCheck(entered != nullptr && resume != nullptr, 70);
        g_testSweepResume.store(resume);
        g_testSweepEntered.store(entered);
        RequestModuleSweep();
        ModuleTestCheck(WaitForSingleObject(entered, 5000) == WAIT_OBJECT_0, 71);
        FreeLibrary(probeB);
        probeB = nullptr;
        const auto beforeUnscanned = g_moduleGenerations.UnscannedUnloads();
        HMODULE shortLived = LoadLibraryW(paths.ProbeB);
        ModuleTestCheck(shortLived != nullptr, 75);
        FreeLibrary(shortLived);
        ModuleTestCheck(g_moduleGenerations.UnscannedUnloads() > beforeUnscanned, 76);
        const auto* mapping = g_transportHeader;
        ShutdownAgent("module_test_paused", AgentLifecycleState::Disabled);
        ModuleTestCheck(!g_sessionGate.Quiescent() && g_transportHeader == mapping && GetLifecycleState() == AgentLifecycleState::Stopping, 72);
        SetEvent(resume);
        ModuleTestCheck(WaitForSingleObject(g_moduleSweepThread, 5000) == WAIT_OBJECT_0, 73);
        g_testSweepEntered.store(nullptr);
        g_testSweepResume.store(nullptr);
        const auto stopped = ShutdownAgent("module_test_complete", AgentLifecycleState::Disabled);
        ModuleTestCheck(stopped.FailedHooks == 0 && stopped.InstalledHooks == stopped.RestoredHooks &&
            g_transportHeader == nullptr && g_moduleSweepThread == nullptr, 74);
    }
    catch (unsigned stage)
    {
        result = stage;
    }
    catch (...)
    {
        result = 99;
    }
    if (resume != nullptr)
    {
        SetEvent(resume);
    }
    ShutdownAgent("module_test_cleanup", AgentLifecycleState::Disabled);
    for (HMODULE module : {probeA, probeB, delay, twinA, twinB})
    {
        if (module != nullptr)
        {
            FreeLibrary(module);
        }
    }
    if (g_moduleSweepThread == nullptr)
    {
        g_testSweepEntered.store(nullptr);
        g_testSweepResume.store(nullptr);
        if (entered != nullptr)
        {
            CloseHandle(entered);
        }
        if (resume != nullptr)
        {
            CloseHandle(resume);
        }
    }
    return result;
}

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:KnMonTestModules=_KnMonTestModules@4")
#endif
