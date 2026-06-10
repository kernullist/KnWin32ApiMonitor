#pragma once

#include <knmon/collector/SharedTransportReader.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

namespace knmon
{
struct ThreadedSharedTransportReaderConfig
{
    SharedTransportReaderConfig ReaderConfig;
    std::uint32_t PollIntervalMs = 25;
};

struct ThreadedSharedTransportReaderMetrics
{
    bool Started = false;
    bool Running = false;
    bool StopRequested = false;
    bool HeaderValid = false;
    bool StoppedOnUnavailableRecord = false;
    std::uint64_t DrainCalls = 0;
    std::uint64_t RecordsStreamed = 0;
    std::uint64_t RecordsProduced = 0;
    std::uint64_t RecordsConsumed = 0;
    std::uint64_t RecordsDropped = 0;
    std::uint64_t HighWaterMark = 0;
    std::uint64_t ValidationFailures = 0;
    std::uint64_t LastTransportSequence = 0;
    std::string ShutdownReason;
    std::string LastErrorMessage;
};

class ThreadedSharedTransportReader
{
public:
    ThreadedSharedTransportReader(
        KnMonTransportHeader* header,
        KnMonTransportRecord* records,
        const ThreadedSharedTransportReaderConfig& config);
    ~ThreadedSharedTransportReader();

    ThreadedSharedTransportReader(const ThreadedSharedTransportReader&) = delete;
    ThreadedSharedTransportReader& operator=(const ThreadedSharedTransportReader&) = delete;

    bool Start(const SharedTransportRecordCallback& callback);
    void RequestStop(const std::string& reason);
    bool Join(std::uint32_t timeoutMs);
    ThreadedSharedTransportReaderMetrics SnapshotMetrics() const;

private:
    void Run(const SharedTransportRecordCallback& callback);
    void ApplyDrainResult(const SharedTransportDrainResult& drain);

    KnMonTransportHeader* m_header = nullptr;
    KnMonTransportRecord* m_records = nullptr;
    ThreadedSharedTransportReaderConfig m_config;
    mutable std::mutex m_mutex;
    std::thread m_thread;
    std::atomic<bool> m_stopRequested = false;
    std::atomic<bool> m_running = false;
    ThreadedSharedTransportReaderMetrics m_metrics;
};
}
