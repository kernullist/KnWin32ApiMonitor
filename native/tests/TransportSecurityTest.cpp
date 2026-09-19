#include <knmon/collector/SharedTransportReader.h>
#include <knmon/collector/ThreadedSharedTransportReader.h>

#include <Windows.h>

#include <cstring>
#include <iostream>
#include <limits>
#include <new>
#include <stdexcept>

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
    static constexpr std::uint32_t Capacity = 2;
    knmon::KnMonTransportHeader Header;
    knmon::SharedTransportReaderState State;
    knmon::SharedTransportReaderConfig Config;
    knmon::KnMonTransportRecord* Records = nullptr;
    void* Allocation = nullptr;

    Fixture()
    {
        SYSTEM_INFO system = {};
        GetSystemInfo(&system);
        const std::size_t recordBytes = Capacity * sizeof(knmon::KnMonTransportRecord);
        const std::size_t accessibleBytes = ((recordBytes + system.dwPageSize - 1) / system.dwPageSize) * system.dwPageSize;
        Allocation = VirtualAlloc(nullptr, accessibleBytes + system.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (Allocation == nullptr)
        {
            throw std::runtime_error("Test allocation failed.");
        }
        auto* guard = static_cast<unsigned char*>(Allocation) + accessibleBytes;
        DWORD previous = 0;
        if (!VirtualProtect(guard, system.dwPageSize, PAGE_NOACCESS, &previous))
        {
            VirtualFree(Allocation, 0, MEM_RELEASE);
            throw std::runtime_error("Test guard page failed.");
        }
        Records = reinterpret_cast<knmon::KnMonTransportRecord*>(guard - recordBytes);
        for (std::uint32_t index = 0; index < Capacity; ++index)
        {
            new (&Records[index]) knmon::KnMonTransportRecord();
        }
        Header.HeaderSize = sizeof(Header);
        Header.RecordSize = sizeof(*Records);
        Header.Architecture = static_cast<std::uint32_t>(knmon::KnMonAgentArchitecture::X64);
        Header.Capacity = Capacity;
        wcscpy_s(Header.OperationId, L"transport-test");
        Config.TrustedCapacity = Capacity;
        Config.TrustedRecordBytes = recordBytes;
        Config.ExpectedArchitecture = Header.Architecture;
        Config.ExpectedOperationId = "transport-test";
        Config.State = &State;
        Config.ValidateRecordIdentity = [](const knmon::KnMonTransportRecord& record)
        {
            return record.ApiId == static_cast<std::uint16_t>(knmon::KnMonTransportApiId::CreateFileW) &&
                record.ModuleId == static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Kernel32);
        };
    }

    ~Fixture()
    {
        VirtualFree(Allocation, 0, MEM_RELEASE);
    }

    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;

    void Commit(std::int64_t sequence)
    {
        auto& record = Records[sequence % Capacity];
        record = {};
        record.Sequence = sequence;
        record.State = static_cast<std::int32_t>(knmon::KnMonTransportRecordState::Committed);
        record.RecordSize = sizeof(record);
        record.EventKind = static_cast<std::uint16_t>(knmon::KnMonTransportEventKind::ApiCall);
        record.ApiId = static_cast<std::uint16_t>(knmon::KnMonTransportApiId::CreateFileW);
        record.ModuleId = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Kernel32);
        Header.ProducerSequence = sequence + 1;
        Header.HighWaterMark = Capacity;
    }

    knmon::SharedTransportReader Reader()
    {
        return knmon::SharedTransportReader(&Header, Records, Config);
    }
};

template <typename Mutation>
void ExpectCorruption(const char* name, Mutation mutate)
{
    Fixture fixture;
    fixture.Commit(0);
    mutate(fixture);
    int callbacks = 0;
    const auto result = fixture.Reader().DrainAvailable([&callbacks](const auto&)
    {
        ++callbacks;
        return true;
    });
    Check(result.TransportCorrupted && !result.HeaderValid && callbacks == 0, name);
    fixture.Header.Capacity = Fixture::Capacity;
    Check(fixture.Reader().SnapshotMetrics().TransportCorrupted, "Corruption must remain latched across reader reconstruction");
}
}

int main()
{
    try
    {
        ExpectCorruption("capacity exceeds actual mapping", [](auto& f)
        {
            f.Header.Capacity = knmon::KnMonTransportMaxCapacity;
        });
        ExpectCorruption("zero capacity", [](auto& f)
        {
            f.Header.Capacity = 0;
        });
        ExpectCorruption("short trusted mapping", [](auto& f)
        {
            --f.Config.TrustedRecordBytes;
        });
        ExpectCorruption("negative consumer", [](auto& f)
        {
            f.Header.ConsumerSequence = -1;
        });
        ExpectCorruption("forged consumer", [](auto& f)
        {
            f.Header.ConsumerSequence = 1;
        });
        ExpectCorruption("negative producer", [](auto& f)
        {
            f.Header.ProducerSequence = (std::numeric_limits<std::int64_t>::min)();
        });
        ExpectCorruption("producer exceeds capacity", [](auto& f)
        {
            f.Header.ProducerSequence = Fixture::Capacity + 1;
        });
        ExpectCorruption("sequence overflow", [](auto& f)
        {
            f.Header.ProducerSequence = (std::numeric_limits<std::int64_t>::max)();
        });
        ExpectCorruption("negative dropped counter", [](auto& f)
        {
            f.Header.DroppedEvents = -1;
        });
        ExpectCorruption("invalid high water", [](auto& f)
        {
            f.Header.HighWaterMark = Fixture::Capacity + 1;
        });
        ExpectCorruption("record size", [](auto& f)
        {
            f.Records[0].RecordSize = 1;
        });
        ExpectCorruption("unknown event", [](auto& f)
        {
            f.Records[0].EventKind = 65535;
        });
        ExpectCorruption("unknown API", [](auto& f)
        {
            f.Records[0].ApiId = 65535;
        });
        ExpectCorruption("invalid state", [](auto& f)
        {
            f.Records[0].State = 99;
        });
        ExpectCorruption("stale committed sequence", [](auto& f)
        {
            f.Records[0].Sequence = -1;
        });
        ExpectCorruption("oversized generic arguments", [](auto& f)
        {
            f.Records[0].Flags = knmon::KnMonTransportRecordFlagGenericInventory;
            f.Records[0].Values32[0] = knmon::KnMonTransportSlotCount64 + 1;
        });
        for (std::uint32_t length : {513U, 65535U, 0xffffffffU})
        {
            ExpectCorruption("oversized text", [length](auto& f)
            {
                f.Records[0].Text0Length = length;
            });
        }
        {
            Fixture f;
            f.Commit(0);
            const auto result = f.Reader().DrainAvailable([&f](const auto& copy)
            {
                Check(&copy != &f.Records[0], "Callback must receive a host snapshot");
                f.Records[0].Text0Length = 0xffffffffU;
                Check(copy.Text0Length == 0, "Shared mutation must not change parsed snapshot");
                return true;
            });
            Check(result.HeaderValid && result.RecordsDrained == 1, "Local snapshot consumption");
            f.Header.ConsumerSequence = 0;
            Check(f.Reader().SnapshotMetrics().TransportCorrupted, "Reconstructed reader detects consumer regression");
        }
        {
            Fixture f;
            f.Commit(0);
            const auto result = f.Reader().DrainAvailable([&f](const auto&)
            {
                f.Header.Capacity = 0;
                return true;
            });
            Check(result.TransportCorrupted, "Header mutation after initial validation");
        }
        {
            Fixture f;
            f.Commit(0);
            const auto result = f.Reader().DrainAvailable([&f](const auto&)
            {
                f.Records[0].Sequence = 12;
                return true;
            });
            Check(result.TransportCorrupted && f.State.NextConsumer == 0, "Commit token mutation during callback");
        }
        {
            Fixture f;
            f.Commit(0);
            const auto result = f.Reader().DrainAvailable([&f](const auto&)
            {
                f.Commit(f.Header.ProducerSequence);
                return true;
            });
            Check(result.HeaderValid && result.RecordsDrained == Fixture::Capacity, "Continuously refilled drain is bounded");
        }
        {
            Fixture f;
            f.Commit(0);
            f.Commit(1);
            f.Records[1].State = static_cast<std::int32_t>(knmon::KnMonTransportRecordState::Writing);
            const auto result = f.Reader().DrainAvailable({});
            Check(result.HeaderValid && result.RecordsDrained == 1 && result.StoppedOnUnavailableRecord, "Slow producer remains pending");
        }
        {
            Fixture f;
            f.Commit(0);
            const auto rejected = f.Reader().DrainAvailable([](const auto&)
            {
                return false;
            });
            Check(rejected.HeaderValid && rejected.RecordsConsumed == 0, "Callback rejection preserves record");
            Check(f.Reader().DrainAvailable({}).RecordsDrained == 1, "Rejected callback can retry");
        }
        {
            Fixture f;
            f.Commit(0);
            f.Records[0].ApiId = 0;
            f.Records[0].EventKind = static_cast<std::uint16_t>(knmon::KnMonTransportEventKind::Unknown);
            Check(f.Reader().DrainAvailable({}).RecordsDrained == 1, "Abort tombstone advances consumer");
        }
        {
            Fixture f;
            f.Commit(0);
            knmon::ThreadedSharedTransportReaderConfig config;
            config.ReaderConfig = f.Config;
            knmon::ThreadedSharedTransportReader reader(&f.Header, f.Records, config);
            Check(reader.Start([](const auto&) -> bool
            {
                throw std::runtime_error("Injected callback failure.");
            }), "Threaded reader start");
            Check(reader.Join(5000), "Callback exception stops the reader without terminating the host");
            Check(reader.SnapshotMetrics().LastErrorMessage == "Injected callback failure.", "Callback failure is reported");
            Check(!reader.Start({}), "Completed reader cannot reset host sequence ownership");
        }
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << "\n";
        ++g_failures;
    }
    if (g_failures == 0)
    {
        std::cout << "Transport hostile-input, snapshot, and bounded-drain tests passed.\n";
    }
    return g_failures == 0 ? 0 : 1;
}
