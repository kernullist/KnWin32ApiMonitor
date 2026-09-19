#include <knmon/collector/ThreadedSharedTransportReader.h>

#include <chrono>

namespace knmon
{
ThreadedSharedTransportReader::ThreadedSharedTransportReader(
    KnMonTransportHeader* header,
    KnMonTransportRecord* records,
    const ThreadedSharedTransportReaderConfig& config) :
    m_header(header),
    m_records(records),
    m_config(config)
{
}

ThreadedSharedTransportReader::~ThreadedSharedTransportReader()
{
    RequestStop("destructor");
    // Destructor must not leave a joinable std::thread; that would call std::terminate.
    (void)Join(0);
}

bool ThreadedSharedTransportReader::Start(const SharedTransportRecordCallback& callback)
{
    bool started = false;

    do
    {
        bool expected = false;
        if (!m_started.compare_exchange_strong(expected, true))
        {
            break;
        }

        m_running.store(true);
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_metrics = {};
            m_metrics.Started = true;
            m_metrics.Running = true;
            m_metrics.ShutdownReason = "running";
        }

        try
        {
            m_thread = std::thread(&ThreadedSharedTransportReader::Run, this, callback);
        }
        catch (const std::exception& error)
        {
            m_running.store(false);
            std::lock_guard<std::mutex> lock(m_mutex);
            m_metrics.Running = false;
            m_metrics.ShutdownReason = "thread_start_failed";
            m_metrics.LastErrorMessage = error.what();
            break;
        }
        started = true;
    }
    while (false);

    return started;
}

void ThreadedSharedTransportReader::RequestStop(const std::string& reason)
{
    m_stopRequested.store(true);

    std::lock_guard<std::mutex> lock(m_mutex);
    m_metrics.StopRequested = true;
    if (!reason.empty())
    {
        m_metrics.ShutdownReason = reason;
    }
}

bool ThreadedSharedTransportReader::Join(std::uint32_t timeoutMs)
{
    bool joined = false;

    do
    {
        if (!m_thread.joinable())
        {
            joined = !m_running.load();
            break;
        }

        if (timeoutMs == 0)
        {
            // Infinite wait: required for destructor safety after RequestStop.
            m_thread.join();
            joined = true;
            break;
        }

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
        while (m_running.load() && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        if (m_running.load())
        {
            // Timed out while the worker is still marked running. Leave the thread
            // joinable so a later Join(0)/destructor can still reclaim it safely.
            break;
        }

        m_thread.join();
        joined = true;
    }
    while (false);

    return joined;
}

ThreadedSharedTransportReaderMetrics ThreadedSharedTransportReader::SnapshotMetrics() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    ThreadedSharedTransportReaderMetrics snapshot = m_metrics;
    snapshot.Running = m_running.load();
    snapshot.StopRequested = m_stopRequested.load();
    return snapshot;
}

void ThreadedSharedTransportReader::Run(const SharedTransportRecordCallback& callback)
{
    SharedTransportReader reader(m_header, m_records, m_config.ReaderConfig);
    const std::uint32_t pollIntervalMs = m_config.PollIntervalMs == 0 ? 1 : m_config.PollIntervalMs;

    while (!m_stopRequested.load())
    {
        SharedTransportDrainResult drain;
        try
        {
            drain = reader.DrainAvailable(callback);
        }
        catch (const std::exception& error)
        {
            drain = reader.SnapshotMetrics();
            drain.ErrorMessage = error.what();
        }
        catch (...)
        {
            drain = reader.SnapshotMetrics();
            drain.ErrorMessage = "Shared transport callback raised an unknown exception.";
        }
        ApplyDrainResult(drain);

        if (!drain.HeaderValid)
        {
            RequestStop("validation_failed");
            break;
        }

        if (!drain.ErrorMessage.empty())
        {
            RequestStop("callback_rejected");
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(pollIntervalMs));
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_metrics.Running = false;
        if (m_metrics.ShutdownReason == "running")
        {
            m_metrics.ShutdownReason = m_metrics.StopRequested ? "stop_requested" : "completed";
        }
    }

    m_running.store(false);
}

void ThreadedSharedTransportReader::ApplyDrainResult(const SharedTransportDrainResult& drain)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    ++m_metrics.DrainCalls;
    m_metrics.HeaderValid = drain.HeaderValid;
    m_metrics.StoppedOnUnavailableRecord = m_metrics.StoppedOnUnavailableRecord || drain.StoppedOnUnavailableRecord;
    m_metrics.RecordsStreamed += drain.RecordsDrained;
    m_metrics.RecordsProduced = drain.RecordsProduced;
    m_metrics.RecordsConsumed = drain.RecordsConsumed;
    m_metrics.RecordsDropped = drain.RecordsDropped;
    m_metrics.HighWaterMark = drain.HighWaterMark;
    m_metrics.LastTransportSequence = drain.RecordsConsumed;
    m_metrics.LastErrorMessage = drain.ErrorMessage;

    if (!drain.HeaderValid)
    {
        ++m_metrics.ValidationFailures;
    }
}
}
