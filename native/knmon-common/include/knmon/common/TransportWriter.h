#pragma once

#include <knmon/common/Protocol.h>

#include <Windows.h>

#include <cstddef>
#include <cstring>
#include <limits>
#include <type_traits>

namespace knmon
{
enum class TransportWriteOutcome : std::uint32_t
{
    Completed = 0,
    Abandoned = 1,
    CppException = 2,
    MemoryFault = 3,
};

class TransportReservation
{
public:
    TransportReservation(KnMonTransportHeader* header, KnMonTransportRecord* records,
        std::uint32_t capacity, volatile std::int64_t* dropped) noexcept :
        m_header(header), m_dropped(dropped)
    {
        do
        {
            if (header == nullptr || records == nullptr || capacity < KnMonTransportMinCapacity ||
                capacity > KnMonTransportMaxCapacity)
            {
                Drop();
                break;
            }
            // Contention cannot cause an unbounded hook-side retry loop.
            for (std::uint32_t attempt = 0; attempt < 128; ++attempt)
            {
                const std::int64_t consumer = InterlockedCompareExchange64(&header->ConsumerSequence, 0, 0);
                const std::int64_t producer = InterlockedCompareExchange64(&header->ProducerSequence, 0, 0);
                if (consumer != InterlockedCompareExchange64(&header->ConsumerSequence, 0, 0))
                {
                    if (attempt == 127)
                    {
                        Drop();
                    }
                    continue;
                }
                if (InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&header->Flags), 0, 0) != 0 ||
                    producer < 0 || consumer < 0 || producer < consumer ||
                    producer == (std::numeric_limits<std::int64_t>::max)() ||
                    producer - consumer > capacity)
                {
                    MarkCorrupted();
                    break;
                }
                if (producer - consumer == capacity)
                {
                    Drop();
                    break;
                }
                if (InterlockedCompareExchange64(&header->ProducerSequence, producer + 1, producer) != producer)
                {
                    if (attempt == 127)
                    {
                        Drop();
                    }
                    continue;
                }
                KnMonTransportRecord* slot = &records[producer % capacity];
                if (InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&slot->State),
                    static_cast<LONG>(KnMonTransportRecordState::Writing),
                    static_cast<LONG>(KnMonTransportRecordState::Free)) != static_cast<LONG>(KnMonTransportRecordState::Free))
                {
                    // A failed ownership CAS must never overwrite another writer.
                    MarkCorrupted();
                    break;
                }
                m_record = slot;
                m_sequence = producer;
                ClearPayload();
                slot->EventKind = static_cast<std::uint16_t>(KnMonTransportEventKind::ApiCall);
                InterlockedExchange64(&slot->Sequence, producer);
                const std::int64_t depth = producer - consumer + 1;
                std::int64_t highWater = InterlockedCompareExchange64(&header->HighWaterMark, 0, 0);
                for (std::uint32_t update = 0; depth > highWater && update < capacity; ++update)
                {
                    const std::int64_t previous = InterlockedCompareExchange64(&header->HighWaterMark, depth, highWater);
                    if (previous == highWater)
                    {
                        break;
                    }
                    highWater = previous;
                }
                break;
            }
        }
        while (false);
    }

    ~TransportReservation()
    {
        Abort(TransportWriteOutcome::Abandoned);
    }

    TransportReservation(const TransportReservation&) = delete;
    TransportReservation& operator=(const TransportReservation&) = delete;

    KnMonTransportRecord* Get() const noexcept
    {
        return m_record;
    }

    void Commit() noexcept
    {
        if (m_record != nullptr)
        {
            KnMonTransportRecord* record = m_record;
            m_record = nullptr;
            MemoryBarrier();
            InterlockedExchange(reinterpret_cast<volatile LONG*>(&record->State),
                static_cast<LONG>(KnMonTransportRecordState::Committed));
        }
    }

    void Abort(TransportWriteOutcome reason) noexcept
    {
        if (m_record != nullptr)
        {
            ClearPayload();
            m_record->EventKind = static_cast<std::uint16_t>(KnMonTransportEventKind::Unknown);
            m_record->Values32[0] = static_cast<std::uint32_t>(reason);
            InterlockedExchange64(&m_record->Sequence, m_sequence);
            Drop();
            Commit();
        }
    }

private:
    void ClearPayload() noexcept
    {
        constexpr std::size_t offset = offsetof(KnMonTransportRecord, RecordSize);
        std::memset(reinterpret_cast<unsigned char*>(m_record) + offset, 0, sizeof(*m_record) - offset);
        m_record->RecordSize = sizeof(*m_record);
        m_record->ProcessId = GetCurrentProcessId();
        m_record->ThreadId = GetCurrentThreadId();
    }

    void Drop() noexcept
    {
        if (m_dropped != nullptr)
        {
            InterlockedIncrement64(m_dropped);
        }
        if (m_header != nullptr)
        {
            InterlockedIncrement64(&m_header->DroppedEvents);
        }
    }

    void MarkCorrupted() noexcept
    {
        InterlockedOr(reinterpret_cast<volatile LONG*>(&m_header->Flags), 1);
        Drop();
    }

    KnMonTransportHeader* m_header = nullptr;
    KnMonTransportRecord* m_record = nullptr;
    volatile std::int64_t* m_dropped = nullptr;
    std::int64_t m_sequence = -1;
};

using TransportWriteCallback = void (*)(void*, KnMonTransportRecord*);

inline TransportWriteOutcome InvokeTransportCallbackCpp(void* context, TransportWriteCallback callback,
    KnMonTransportRecord* record) noexcept
{
    TransportWriteOutcome outcome = TransportWriteOutcome::Completed;
    try
    {
        callback(context, record);
    }
    catch (...)
    {
        outcome = TransportWriteOutcome::CppException;
    }
    return outcome;
}

inline int TransportFaultFilter(DWORD code) noexcept
{
    return code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR ||
        code == EXCEPTION_DATATYPE_MISALIGNMENT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

// Keep SEH outside C++ object lifetimes. This boundary only contains telemetry.
__declspec(noinline) inline TransportWriteOutcome InvokeTransportCallback(void* context,
    TransportWriteCallback callback, TransportReservation* reservation) noexcept
{
    TransportWriteOutcome outcome = TransportWriteOutcome::Completed;
    __try
    {
        __try
        {
            outcome = InvokeTransportCallbackCpp(context, callback, reservation->Get());
        }
        __except (TransportFaultFilter(GetExceptionCode()))
        {
            outcome = TransportWriteOutcome::MemoryFault;
        }
    }
    __finally
    {
        // Unhandled SEH still releases sequence ownership during unwind.
        if (AbnormalTermination())
        {
            reservation->Abort(TransportWriteOutcome::Abandoned);
        }
    }
    return outcome;
}

template <typename Callback>
bool WriteTransportRecord(KnMonTransportHeader* header, KnMonTransportRecord* records,
    std::uint32_t capacity, volatile std::int64_t* dropped, Callback&& callback) noexcept
{
    bool written = false;
    TransportReservation reservation(header, records, capacity, dropped);
    if (reservation.Get() != nullptr)
    {
        struct WriterContext
        {
            std::remove_reference_t<Callback>* Writer;
        };
        WriterContext context = {&callback};
        const TransportWriteOutcome outcome = InvokeTransportCallback(&context, [](void* opaque, KnMonTransportRecord* record)
        {
            (*static_cast<WriterContext*>(opaque)->Writer)(record);
        }, &reservation);
        if (outcome == TransportWriteOutcome::Completed)
        {
            reservation.Commit();
            written = true;
        }
        else
        {
            reservation.Abort(outcome);
        }
    }
    return written;
}
}
