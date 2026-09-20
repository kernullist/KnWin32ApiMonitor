#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <algorithm>
#include <cstdint>
#include <limits>
#include <sstream>
#include <string>

struct ProcessResourceSamples
{
    std::uint64_t Count = 0;
    std::uint64_t Started = GetTickCount64();
    std::uint64_t PeakWorkingSet = 0;
    std::uint64_t MaxPrivate = 0;
    std::uint64_t LateMinPrivate = UINT64_MAX;
    std::uint64_t LateMaxPrivate = 0;
    std::uint64_t FirstCpu100ns = 0;
    std::uint64_t LastCpu100ns = 0;
    std::uint64_t ElapsedMs = 0;
    DWORD MaxHandles = 0;
    bool Failed = false;

    void Sample()
    {
        PROCESS_MEMORY_COUNTERS_EX memory = {};
        memory.cb = sizeof(memory);
        DWORD handles = 0;
        FILETIME creation = {}, exit = {}, kernel = {}, user = {};
        if (Count >= 2048 || !K32GetProcessMemoryInfo(GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory), sizeof(memory)) ||
            !GetProcessHandleCount(GetCurrentProcess(), &handles) ||
            !GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user))
        {
            Failed = true;
        }
        else
        {
            LastCpu100ns = (static_cast<std::uint64_t>(kernel.dwHighDateTime) << 32) + kernel.dwLowDateTime +
                (static_cast<std::uint64_t>(user.dwHighDateTime) << 32) + user.dwLowDateTime;
            if (Count == 0)
            {
                FirstCpu100ns = LastCpu100ns;
            }
            ++Count;
            ElapsedMs = GetTickCount64() - Started;
            PeakWorkingSet = (std::max)(PeakWorkingSet, static_cast<std::uint64_t>(memory.PeakWorkingSetSize));
            MaxPrivate = (std::max)(MaxPrivate, static_cast<std::uint64_t>(memory.PrivateUsage));
            MaxHandles = (std::max)(MaxHandles, handles);
            if (ElapsedMs >= 1000)
            {
                LateMinPrivate = (std::min)(LateMinPrivate, static_cast<std::uint64_t>(memory.PrivateUsage));
                LateMaxPrivate = (std::max)(LateMaxPrivate, static_cast<std::uint64_t>(memory.PrivateUsage));
            }
        }
    }

    std::string Json() const
    {
        std::ostringstream text;
        text << "{\"samples\":" << Count << ",\"failed\":" << (Failed ? "true" : "false")
            << ",\"peakWorkingSetBytes\":" << PeakWorkingSet << ",\"maxPrivateBytes\":" << MaxPrivate
            << ",\"latePrivateGrowthBytes\":" << (LateMinPrivate <= LateMaxPrivate ? LateMaxPrivate - LateMinPrivate : 0)
            << ",\"elapsedMs\":" << ElapsedMs << ",\"cpu100ns\":" << LastCpu100ns - FirstCpu100ns
            << ",\"maxHandles\":" << MaxHandles << "}";
        return text.str();
    }
};
