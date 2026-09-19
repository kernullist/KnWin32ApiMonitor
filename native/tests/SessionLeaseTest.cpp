#include <knmon/common/SessionLease.h>
#include <knmon/common/TransportWriter.h>
#include <knmon/collector/SharedTransportReader.h>

#include <iostream>
#include <thread>

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

__declspec(noinline) void OriginalCallRaisesSeh(knmon::SessionLeaseGate* gate)
{
    knmon::SessionLease lease(*gate);
    RaiseException(0xe0424242, 0, 0, nullptr);
}

bool ObserveOriginalException(knmon::SessionLeaseGate* gate)
{
    bool caught = false;
    __try
    {
        OriginalCallRaisesSeh(gate);
    }
    __except (GetExceptionCode() == 0xe0424242 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        caught = true;
    }
    return caught;
}

void ForcedStopRace(bool beforeCommit)
{
    knmon::SessionLeaseGate gate;
    Check(gate.Open(), "Publish initial session");
    const std::uint32_t firstEpoch = gate.Epoch();
    const std::size_t bytes = sizeof(knmon::KnMonTransportHeader) + 2 * sizeof(knmon::KnMonTransportRecord);
    auto* header = static_cast<knmon::KnMonTransportHeader*>(VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (header == nullptr)
    {
        Check(false, "Mapping allocation");
        return;
    }
    new (header) knmon::KnMonTransportHeader();
    header->HeaderSize = sizeof(*header);
    header->RecordSize = sizeof(knmon::KnMonTransportRecord);
    header->Capacity = 2;
    auto* records = reinterpret_cast<knmon::KnMonTransportRecord*>(header + 1);
    for (int index = 0; index < 2; ++index)
    {
        new (&records[index]) knmon::KnMonTransportRecord();
    }
    HANDLE paused = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE resume = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Check(paused != nullptr && resume != nullptr, "Barrier allocation");
    if (paused == nullptr || resume == nullptr)
    {
        if (paused != nullptr)
        {
            CloseHandle(paused);
        }
        if (resume != nullptr)
        {
            CloseHandle(resume);
        }
        VirtualFree(header, 0, MEM_RELEASE);
        return;
    }
    std::thread producer([&]()
    {
        knmon::SessionLease lease(gate);
        knmon::TransportReservation reservation(header, records, 2, nullptr);
        auto* record = reservation.Get();
        if (beforeCommit)
        {
            record->ReturnValue = 42;
        }
        SetEvent(paused);
        WaitForSingleObject(resume, 10000);
        record->ApiId = static_cast<std::uint16_t>(knmon::KnMonTransportApiId::CreateFileW);
        record->ModuleId = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Kernel32);
        reservation.Commit();
    });
    Check(WaitForSingleObject(paused, 5000) == WAIT_OBJECT_0, "Writer reaches forced race barrier");
    gate.Close();
    Check(!gate.Quiescent() && !gate.Open(), "Stop retains mapping and rejects restart while a writer is paused");
    Check(gate.Acquire() == 0, "Stop rejects new admission");
    Check(gate.Epoch() == firstEpoch, "Old session identity remains immutable during stop");
    SetEvent(resume);
    producer.join();
    Check(gate.Quiescent(), "Stop observes completed writer release");
    Check(records[0].State == static_cast<std::int32_t>(knmon::KnMonTransportRecordState::Committed),
        "In-flight event finishes in its original mapping");
    VirtualFree(header, 0, MEM_RELEASE);
    Check(gate.Open() && gate.Epoch() != firstEpoch, "Reattach publishes a distinct generation after release");
    gate.Close();
    CloseHandle(paused);
    CloseHandle(resume);
}
}

int main()
{
    ForcedStopRace(false);
    ForcedStopRace(true);
    knmon::SessionLeaseGate gate;
    Check(gate.Open(), "SEH session open");
    Check(ObserveOriginalException(&gate), "Original API exception reaches its original caller");
    gate.Close();
    Check(gate.Quiescent(), "Asynchronous unwind releases the hook lease");
    for (int iteration = 0; iteration < 10000; ++iteration)
    {
        Check(gate.Open(), "Repeated generation publication");
        {
            knmon::SessionLease lease(gate);
            gate.Close();
            Check(!gate.Quiescent() && !gate.Open(), "Generation cannot reset before release");
        }
        Check(gate.Quiescent(), "Generation drains exactly once");
    }
    if (g_failures == 0)
    {
        std::cout << "Forced reservation/commit stop races, original SEH, and 10000 session epochs passed.\n";
    }
    return g_failures == 0 ? 0 : 1;
}
