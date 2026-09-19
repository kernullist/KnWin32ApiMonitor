#include <knmon/common/TransportWriter.h>
#include <knmon/collector/SharedTransportReader.h>

#include <array>
#include <atomic>
#include <iostream>
#include <new>
#include <thread>
#include <vector>

namespace
{
int g_failures = 0;

void Check(bool condition, const char* name)
{
    if (!condition)
    {
        std::cerr << "FAIL: " << name << "\n";
        ++g_failures;
    }
}

struct Fixture
{
    knmon::KnMonTransportHeader Header;
    std::array<knmon::KnMonTransportRecord, 8> Records;
    alignas(8) volatile std::int64_t Dropped = 0;
    knmon::SharedTransportReaderState State;

    Fixture()
    {
        Header.HeaderSize = sizeof(Header);
        Header.RecordSize = sizeof(Records[0]);
        Header.Capacity = static_cast<std::uint32_t>(Records.size());
    }

    knmon::SharedTransportReader Reader()
    {
        knmon::SharedTransportReaderConfig config;
        config.TrustedCapacity = static_cast<std::uint32_t>(Records.size());
        config.TrustedRecordBytes = sizeof(Records);
        config.State = &State;
        config.ValidateRecordIdentity = [](const auto& record)
        {
            return record.ApiId == static_cast<std::uint16_t>(knmon::KnMonTransportApiId::CreateFileW) &&
                record.ModuleId == static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Kernel32);
        };
        return knmon::SharedTransportReader(&Header, Records.data(), config);
    }

    template <typename Callback>
    bool Write(Callback&& callback)
    {
        return knmon::WriteTransportRecord(&Header, Records.data(), Header.Capacity, &Dropped,
            std::forward<Callback>(callback));
    }
};

void Fill(knmon::KnMonTransportRecord* record)
{
    record->ApiId = static_cast<std::uint16_t>(knmon::KnMonTransportApiId::CreateFileW);
    record->ModuleId = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Kernel32);
    record->HookOverheadUs = 7;
}

bool ObserveUnrecognizedSeh(Fixture* fixture)
{
    bool caught = false;
    __try
    {
        fixture->Write([](auto*)
        {
            RaiseException(0xe0424242, 0, 0, nullptr);
        });
    }
    __except (GetExceptionCode() == 0xe0424242 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        caught = true;
    }
    return caught;
}

void TestFaults()
{
    for (int step = 0; step < 6; ++step)
    {
        for (bool memoryFault : {false, true})
        {
            Fixture f;
            Check(!f.Write([step, memoryFault](auto* record)
            {
                Fill(record);
                for (int index = 0; index < 6; ++index)
                {
                    record->Values32[index] = 0x1234;
                    if (index == step)
                    {
                        if (memoryFault)
                        {
                            RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, nullptr);
                        }
                        else
                        {
                            throw std::bad_alloc();
                        }
                    }
                }
            }), "Injected writer fault is contained");
            Check(f.Records[0].Values32[0] == static_cast<std::uint32_t>(memoryFault
                ? knmon::TransportWriteOutcome::MemoryFault : knmon::TransportWriteOutcome::CppException),
                "Abort reason preserved");
            Check(f.Write(Fill), "Later reservation succeeds");
            const auto drained = f.Reader().DrainAvailable({});
            Check(drained.HeaderValid && drained.RecordsDrained == 2 && drained.AbortedRecords == 1,
                "Consumer advances past aborted reservation");
            Check(f.Dropped == 1 && drained.RecordsDropped == 1, "Abort loss counted exactly once");
            Check(drained.HookOverheadSamples == 1 && drained.HookOverheadMinUs == 7 && drained.HookOverheadAvgUs == 7,
                "Abort placeholders do not bias API overhead statistics");
        }
    }
    Fixture f;
    {
        knmon::TransportReservation first(&f.Header, f.Records.data(), f.Header.Capacity, &f.Dropped);
        Check(f.Write(Fill), "Out-of-order later record commits");
        Check(f.Reader().DrainAvailable({}).StoppedOnUnavailableRecord, "Reader does not reclaim a live writer");
    }
    Check(f.Reader().DrainAvailable({}).RecordsDrained == 2 && f.Dropped == 1,
        "Scope abandonment commits tombstone");
    {
        knmon::TransportReservation reserved(&f.Header, f.Records.data(), f.Header.Capacity, &f.Dropped);
        reserved.Abort(knmon::TransportWriteOutcome::Abandoned);
        reserved.Abort(knmon::TransportWriteOutcome::Abandoned);
        reserved.Commit();
    }
    Check(f.Dropped == 2, "Repeated completion is inert");
    {
        Fixture unknown;
        Check(ObserveUnrecognizedSeh(&unknown), "Unexpected SEH preserves the caller exception handler");
        Check(unknown.Dropped == 1 && unknown.Reader().DrainAvailable({}).AbortedRecords == 1,
            "SEH termination handler releases reservation on unwind");
    }
    {
        Fixture actualFault;
        void* unreadable = VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
        Check(unreadable != nullptr, "Fault page allocation");
        if (unreadable != nullptr)
        {
            Check(!actualFault.Write([unreadable](auto* record)
            {
                record->Values32[0] = *static_cast<volatile std::uint32_t*>(unreadable);
            }), "Real inaccessible-memory read is contained");
            Check(actualFault.Dropped == 1 && actualFault.Reader().DrainAvailable({}).AbortedRecords == 1,
                "Real memory fault publishes one abort");
            VirtualFree(unreadable, 0, MEM_RELEASE);
        }
    }
}

void TestBounds()
{
    Fixture full;
    for (std::size_t index = 0; index < full.Records.size(); ++index)
    {
        Check(full.Write(Fill), "Fill bounded ring");
    }
    Check(!full.Write(Fill) && full.Header.ProducerSequence == full.Records.size() && full.Dropped == 1,
        "Full ring rejects before sequence reservation");
    Check(full.Reader().DrainAvailable({}).AbortedRecords == 0, "Overflow and abort accounting differ");

    Fixture conflict;
    conflict.Records[0].State = static_cast<std::int32_t>(knmon::KnMonTransportRecordState::Writing);
    conflict.Records[0].Values32[0] = 42;
    Check(!conflict.Write(Fill) && conflict.Records[0].Values32[0] == 42 && conflict.Header.Flags != 0,
        "Ownership conflict never overwrites another writer");
    Check(conflict.Reader().SnapshotMetrics().TransportCorrupted, "Ownership conflict terminates corrupt transport");

    Fixture invalid;
    invalid.Header.ProducerSequence = -1;
    Check(!invalid.Write(Fill) && invalid.Header.Flags != 0, "Negative producer never indexes records");
}

void TestConcurrent()
{
    constexpr int WriterCount = 4;
    constexpr int Attempts = 5000;
    Fixture f;
    std::atomic<int> active = WriterCount;
    std::vector<std::thread> writers;
    for (int thread = 0; thread < WriterCount; ++thread)
    {
        writers.emplace_back([&f, &active]()
        {
            for (int index = 0; index < Attempts; ++index)
            {
                f.Write([index](auto* record)
                {
                    Fill(record);
                    if (index % 101 == 0)
                    {
                        throw std::bad_alloc();
                    }
                });
                if (index % 8 == 0)
                {
                    std::this_thread::yield();
                }
            }
            --active;
        });
    }
    auto reader = f.Reader();
    std::uint64_t observed = 0;
    std::uint64_t completed = 0;
    while (active.load() != 0 || f.State.NextConsumer != InterlockedCompareExchange64(&f.Header.ProducerSequence, 0, 0))
    {
        const auto drain = reader.DrainAvailable([&observed, &completed](const auto& record)
        {
            Check(record.Sequence == observed, "Concurrent sequence is unique and ordered");
            ++observed;
            if (record.EventKind == static_cast<std::uint16_t>(knmon::KnMonTransportEventKind::ApiCall))
            {
                ++completed;
            }
            return true;
        });
        if (!drain.HeaderValid)
        {
            Check(false, drain.ErrorMessage.c_str());
            break;
        }
        std::this_thread::yield();
    }
    for (auto& writer : writers)
    {
        writer.join();
    }
    Check(completed + f.Dropped == WriterCount * Attempts, "Every concurrent attempt is delivered or counted once");
    Check(f.Dropped == f.Header.DroppedEvents, "Concurrent loss counters agree");
    Check(observed == completed + f.State.AbortedRecords, "Aborts account for every sequence hole");
    Check(completed > 0 && f.State.AbortedRecords > 0, "Concurrent run covers success and abort paths");
    Check(f.Header.Flags == 0, "Concurrent valid writers preserve transport invariants");
}
}

int main()
{
    TestFaults();
    TestBounds();
    TestConcurrent();
    if (g_failures == 0)
    {
        std::cout << "Reservation C++/SEH faults, abandonment, bounds, and 20000 concurrent attempts passed.\n";
    }
    return g_failures == 0 ? 0 : 1;
}
