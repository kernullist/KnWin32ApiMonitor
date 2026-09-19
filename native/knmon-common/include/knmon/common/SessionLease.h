#pragma once

#include <atomic>
#include <cstdint>
#include <limits>

namespace knmon
{
// Admission, reference count, and generation share one atomic state word.
class SessionLeaseGate
{
public:
    std::uint32_t Acquire() noexcept
    {
        const std::uint64_t previous = m_state.fetch_add(1, std::memory_order_acq_rel);
        std::uint32_t epoch = 0;
        if ((previous & Closed) == 0)
        {
            epoch = static_cast<std::uint32_t>(previous >> 32);
        }
        else
        {
            Release();
        }
        return epoch;
    }

    void Release() noexcept
    {
        m_state.fetch_sub(1, std::memory_order_release);
    }

    void Close() noexcept
    {
        m_state.fetch_or(Closed, std::memory_order_acq_rel);
    }

    bool Open() noexcept
    {
        std::uint64_t previous = m_state.load(std::memory_order_acquire);
        bool opened = false;
        const std::uint32_t epoch = static_cast<std::uint32_t>(previous >> 32);
        if ((previous & LowMask) == Closed && epoch != (std::numeric_limits<std::uint32_t>::max)())
        {
            const std::uint64_t next = static_cast<std::uint64_t>(epoch + 1) << 32;
            opened = m_state.compare_exchange_strong(previous, next, std::memory_order_acq_rel);
        }
        return opened;
    }

    bool Quiescent() const noexcept
    {
        return (m_state.load(std::memory_order_acquire) & LowMask) == Closed;
    }

    std::uint32_t Epoch() const noexcept
    {
        return static_cast<std::uint32_t>(m_state.load(std::memory_order_acquire) >> 32);
    }

private:
    static constexpr std::uint64_t Closed = 1ULL << 31;
    static constexpr std::uint64_t LowMask = 0xffffffffULL;
    alignas(8) std::atomic<std::uint64_t> m_state = Closed;
};

class SessionLease
{
public:
    explicit SessionLease(SessionLeaseGate& gate) noexcept : m_gate(gate), m_epoch(gate.Acquire())
    {
    }

    ~SessionLease()
    {
        if (m_epoch != 0)
        {
            m_gate.Release();
        }
    }

    SessionLease(const SessionLease&) = delete;
    SessionLease& operator=(const SessionLease&) = delete;

    std::uint32_t Epoch() const noexcept
    {
        return m_epoch;
    }

private:
    SessionLeaseGate& m_gate;
    std::uint32_t m_epoch;
};
}
