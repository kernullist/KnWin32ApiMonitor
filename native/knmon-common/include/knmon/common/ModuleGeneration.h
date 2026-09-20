#pragma once

#include <Windows.h>
#include <intrin.h>
#include <cstdint>

#if defined(_MSC_VER)
// Debug /RTC helpers must not enter the CRT from a loader callback.
#pragma runtime_checks("", off)
#endif

namespace knmon
{
inline LONG64 ModuleCounterIncrement(volatile LONG64* counter) noexcept
{
    LONG64 previous = _InterlockedCompareExchange64(counter, 0, 0);
    LONG64 next = 0;
    for (;;)
    {
        next = static_cast<LONG64>(static_cast<std::uint64_t>(previous) + 1);
        const LONG64 observed = _InterlockedCompareExchange64(counter, next, previous);
        if (observed == previous)
        {
            break;
        }
        previous = observed;
    }
    return next;
}

inline void ModuleCounterStore(volatile LONG64* counter, LONG64 value) noexcept
{
    LONG64 previous = _InterlockedCompareExchange64(counter, 0, 0);
    for (;;)
    {
        const LONG64 observed = _InterlockedCompareExchange64(counter, value, previous);
        if (observed == previous)
        {
            break;
        }
        previous = observed;
    }
}

// Keys never move or disappear. An absent key denotes a pre-registration image.
// Only the loader callback writes keys and generations. Scanners hold a module reference.
class ModuleGenerationTable
{
public:
    static constexpr unsigned Capacity = 8192;

    void Notify(const void* base, bool loaded) noexcept
    {
        const auto key = reinterpret_cast<ULONG_PTR>(base);
        if (key == 0)
        {
            return;
        }
        const LONG64 serial = ModuleCounterIncrement(&m_serial);
        if (serial < 0 || serial > 0x3fffffffffffffffLL)
        {
            _InterlockedExchange(&m_overflow, 1);
            return;
        }
        // Addition avoids the x86 debug compiler's out-of-line 64-bit shift helper.
        const LONG64 generation = serial + serial + (loaded ? 1 : 0);
        const unsigned first = static_cast<unsigned>((key >> 16) ^ (key >> 28)) % Capacity;
        for (unsigned probe = 0; probe < Capacity; ++probe)
        {
            Entry& entry = m_entries[(first + probe) % Capacity];
            void* existing = _InterlockedCompareExchangePointer(&entry.Base, const_cast<void*>(base), nullptr);
            if (existing == nullptr || existing == base)
            {
                const LONG64 previous = _InterlockedCompareExchange64(&entry.Generation, 0, 0);
                if (!loaded && (previous & 1) != 0 &&
                    previous != _InterlockedCompareExchange64(&entry.ScannedGeneration, 0, 0))
                {
                    ModuleCounterIncrement(&m_unscannedUnloads);
                }
                ModuleCounterStore(&entry.Generation, generation);
                return;
            }
        }
        _InterlockedExchange(&m_overflow, 1);
    }

    std::uint64_t Read(const void* base) const noexcept
    {
        const auto key = reinterpret_cast<ULONG_PTR>(base);
        std::uint64_t result = 0;
        if (key != 0)
        {
            const unsigned first = static_cast<unsigned>((key >> 16) ^ (key >> 28)) % Capacity;
            for (unsigned probe = 0; probe < Capacity; ++probe)
            {
                const Entry& entry = m_entries[(first + probe) % Capacity];
                const void* existing = _InterlockedCompareExchangePointer(&entry.Base, nullptr, nullptr);
                if (existing == base)
                {
                    const auto generation = static_cast<std::uint64_t>(_InterlockedCompareExchange64(&entry.Generation, 0, 0));
                    result = (generation & 1) != 0 ? generation : 0;
                    break;
                }
                if (existing == nullptr)
                {
                    result = Overflowed() ? 0 : 1;
                    break;
                }
            }
        }
        return result;
    }

    bool Overflowed() const noexcept
    {
        return _InterlockedCompareExchange(&m_overflow, 0, 0) != 0;
    }

    bool Changed(const void* base, std::uint64_t expected) const noexcept
    {
        const auto key = reinterpret_cast<ULONG_PTR>(base);
        const unsigned first = static_cast<unsigned>((key >> 16) ^ (key >> 28)) % Capacity;
        bool changed = false;
        for (unsigned probe = 0; key != 0 && probe < Capacity; ++probe)
        {
            const Entry& entry = m_entries[(first + probe) % Capacity];
            const void* existing = _InterlockedCompareExchangePointer(&entry.Base, nullptr, nullptr);
            if (existing == base)
            {
                const auto generation = static_cast<std::uint64_t>(_InterlockedCompareExchange64(&entry.Generation, 0, 0));
                changed = generation != 0 && generation != expected;
                break;
            }
            if (existing == nullptr)
            {
                break;
            }
        }
        return changed;
    }

    void MarkScanned(const void* base, std::uint64_t generation) noexcept
    {
        const auto key = reinterpret_cast<ULONG_PTR>(base);
        const unsigned first = static_cast<unsigned>((key >> 16) ^ (key >> 28)) % Capacity;
        for (unsigned probe = 0; key != 0 && probe < Capacity; ++probe)
        {
            Entry& entry = m_entries[(first + probe) % Capacity];
            const void* existing = _InterlockedCompareExchangePointer(&entry.Base, nullptr, nullptr);
            if (existing == base)
            {
                if (static_cast<std::uint64_t>(_InterlockedCompareExchange64(&entry.Generation, 0, 0)) == generation)
                {
                    ModuleCounterStore(&entry.ScannedGeneration, static_cast<LONG64>(generation));
                }
                break;
            }
            if (existing == nullptr)
            {
                break;
            }
        }
    }

    std::uint64_t UnscannedUnloads() const noexcept
    {
        return static_cast<std::uint64_t>(_InterlockedCompareExchange64(&m_unscannedUnloads, 0, 0));
    }

private:
    struct Entry
    {
        mutable void* volatile Base = nullptr;
        alignas(8) mutable volatile LONG64 Generation = 0;
        alignas(8) mutable volatile LONG64 ScannedGeneration = 0;
    };
    Entry m_entries[Capacity] = {};
    alignas(8) volatile LONG64 m_serial = 1;
    mutable volatile LONG m_overflow = 0;
    alignas(8) mutable volatile LONG64 m_unscannedUnloads = 0;
};
}
#if defined(_MSC_VER)
#pragma runtime_checks("", restore)
#endif
