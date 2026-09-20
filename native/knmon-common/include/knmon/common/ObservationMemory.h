#pragma once

#include <Windows.h>
#include <cstdint>

namespace knmon
{
#if defined(KNMON_LIFECYCLE_TESTING)
inline thread_local std::uint32_t ObservationReadCalls = 0;
#endif

inline BOOL ReadObservationMemory(HANDLE process, LPCVOID address, LPVOID buffer, SIZE_T bytes, SIZE_T* copied)
{
#if defined(KNMON_LIFECYCLE_TESTING)
    ++ObservationReadCalls;
#endif
    return ReadProcessMemory(process, address, buffer, bytes, copied);
}
}
