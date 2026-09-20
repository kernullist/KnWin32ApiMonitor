#include <Windows.h>
#include <knmon/common/ModuleGeneration.h>
#include "ModuleTestPaths.h"
#include <iostream>
#include <memory>

int wmain(int argc, wchar_t** argv)
{
    int result = 1;
    do
    {
        if (argc != 7)
        {
            break;
        }
        auto generations = std::make_unique<knmon::ModuleGenerationTable>();
        const void* address = reinterpret_cast<void*>(0x10000);
        if (generations->Read(address) != 1 || generations->Read(nullptr) != 0)
        {
            break;
        }
        generations->Notify(address, true);
        const auto first = generations->Read(address);
        generations->Notify(address, false);
        if (first <= 1 || generations->Read(address) != 0)
        {
            break;
        }
        generations->Notify(address, true);
        if (generations->Read(address) <= first)
        {
            break;
        }
        const auto unscanned = generations->UnscannedUnloads();
        generations->MarkScanned(address, generations->Read(address));
        generations->Notify(address, false);
        if (unscanned != 1 || generations->UnscannedUnloads() != unscanned || !generations->Changed(address, first))
        {
            break;
        }
        generations->Notify(address, true);
        for (unsigned index = 1; index <= knmon::ModuleGenerationTable::Capacity; ++index)
        {
            generations->Notify(reinterpret_cast<void*>(static_cast<ULONG_PTR>(index + 1) << 16), true);
        }
        if (!generations->Overflowed() || generations->Read(reinterpret_cast<void*>(0x7fff0000)) != 0 || generations->Read(address) == 0)
        {
            break;
        }
        if (generations->Changed(reinterpret_cast<void*>(0x7fff0000), 1))
        {
            break;
        }
        const ModuleTestPaths paths{argv[2], argv[3], argv[4], argv[5], argv[6]};
        HMODULE agent = LoadLibraryW(argv[1]);
        const auto test = agent == nullptr ? nullptr : reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(agent, "KnMonTestModules"));
        if (test == nullptr)
        {
            break;
        }
        result = static_cast<int>(test(const_cast<ModuleTestPaths*>(&paths)));
        FreeLibrary(agent);
    }
    while (false);
    std::cout << "Module generation, burst, reload, OFT, delay and resolver result: " << result << "\n";
    return result;
}
