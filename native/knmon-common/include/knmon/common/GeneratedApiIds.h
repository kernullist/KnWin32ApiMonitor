#pragma once

#include <cstdint>

namespace knmon
{
enum class KnMonTransportApiId : std::uint16_t
{
    Unknown = 0,
    CreateFileW = 1,
    CreateFileA = 2,
    NtCreateFile = 3,
    ReadFile = 4,
    WriteFile = 5,
    CloseHandle = 6,
    LoadLibraryW = 7,
    LoadLibraryA = 8,
    LoadLibraryExW = 9,
    LoadLibraryExA = 10,
    LdrLoadDll = 11,
    GetProcAddress = 12,
    LdrGetProcedureAddress = 13,
};

enum class KnMonTransportModuleId : std::uint16_t
{
    Unknown = 0,
    Kernel32 = 1,
    Ntdll = 2,
    KernelBase = 3,
};
}
