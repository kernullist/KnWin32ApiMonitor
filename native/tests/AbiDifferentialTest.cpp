#include <Windows.h>
#include <iostream>

int wmain(int argc, wchar_t** argv)
{
    int result = 1;
    HMODULE module = nullptr;
    do
    {
        if (argc != 2)
        {
            break;
        }
        module = LoadLibraryW(argv[1]);
        const auto run = module == nullptr ? nullptr : reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(module, "KnMonTestAbiDifferential"));
        if (run == nullptr)
        {
            std::cerr << "ABI test export unavailable: " << GetLastError() << "\n";
            break;
        }
        result = static_cast<int>(run(nullptr));
    }
    while (false);
    if (module != nullptr)
    {
        FreeLibrary(module);
    }
    return result;
}
