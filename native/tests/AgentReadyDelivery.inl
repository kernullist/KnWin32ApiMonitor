// Included only by the isolated lifecycle test DLL.
bool ReadReadyTestMessage(HANDLE server, std::string& message)
{
    std::array<char, 4096> payload = {};
    OVERLAPPED read = {};
    read.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    DWORD bytes = 0;
    bool completed = false;
    if (read.hEvent != nullptr)
    {
        completed = ReadFile(server, payload.data(), static_cast<DWORD>(payload.size()), &bytes, &read) != FALSE;
        if (!completed && GetLastError() == ERROR_IO_PENDING)
        {
            if (WaitForSingleObject(read.hEvent, 2000) != WAIT_OBJECT_0)
            {
                CancelIoEx(server, &read);
            }
            completed = GetOverlappedResult(server, &read, &bytes, TRUE) != FALSE;
        }
        CloseHandle(read.hEvent);
    }
    if (completed)
    {
        message.assign(payload.data(), bytes);
    }
    return completed;
}

DWORD RunReadyDeliveryCase(unsigned scenario)
{
    DWORD result = 1;
    std::wstring name;
    HANDLE server = knmon::CreateLocalAgentPipe(name, 2000);
    HANDLE client = INVALID_HANDLE_VALUE;
    HANDLE held = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    OVERLAPPED transfer = {};
    transfer.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    do
    {
        if (server == INVALID_HANDLE_VALUE || held == nullptr || transfer.hEvent == nullptr)
        {
            break;
        }
        client = CreateFileW(name.c_str(), knmon::AgentPipeClientAccess, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (client == INVALID_HANDLE_VALUE || !knmon::ConfigureAgentPipeWriter(client))
        {
            break;
        }
        const BOOL connected = ConnectNamedPipe(server, &transfer);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED)
        {
            break;
        }
        g_pipeHandle = client;
        g_operationId = L"ready-delivery-test";
        g_channelNonce.assign(64, L'a');
        SetLifecycleState(AgentLifecycleState::Running);
        unsigned filled = 0;
        const bool fillPipe = scenario == 1 || scenario == 2;
        const std::string filler(4096, 'x');
        if (fillPipe)
        {
            while (filled < 256 && knmon::TryWriteAgentMessage(client, filler))
            {
                ++filled;
            }
            if (filled == 0 || filled == 256)
            {
                break;
            }
        }
        std::atomic<bool> readerPassed{true};
        std::thread worker;
        const bool lockPipe = scenario == 0 || scenario == 4;
        if (lockPipe)
        {
            worker = std::thread([&]()
            {
                AcquireSRWLockExclusive(&g_pipeLock);
                SetEvent(held);
                Sleep(75);
                if (scenario == 4)
                {
                    SetLifecycleState(AgentLifecycleState::Stopping);
                }
                ReleaseSRWLockExclusive(&g_pipeLock);
            });
        }
        else if (scenario == 1)
        {
            worker = std::thread([&]()
            {
                Sleep(75);
                for (unsigned index = 0; index < filled; ++index)
                {
                    std::string message;
                    if (!ReadReadyTestMessage(server, message) || message != filler)
                    {
                        readerPassed = false;
                        break;
                    }
                }
            });
        }
        else if (scenario == 5)
        {
            SetLifecycleState(AgentLifecycleState::Stopping);
        }
        const bool locked = !lockPipe || WaitForSingleObject(held, 2000) == WAIT_OBJECT_0;
        const bool heldByCaller = scenario == 3 || scenario == 6;
        if (heldByCaller)
        {
            AcquireSRWLockExclusive(&g_pipeLock);
        }
        const LONG64 dropped = InterlockedCompareExchange64(&g_droppedEvents, 0, 0);
        const ULONGLONG started = GetTickCount64();
        const bool sent = locked && (scenario == 6 ? SendJson("best-effort-test") : SendReady());
        const ULONGLONG elapsed = GetTickCount64() - started;
        if (heldByCaller)
        {
            ReleaseSRWLockExclusive(&g_pipeLock);
        }
        if (worker.joinable())
        {
            worker.join();
        }
        const bool expected = scenario == 0 || scenario == 1;
        result = 2;
        if (!locked || !readerPassed || sent != expected ||
            InterlockedCompareExchange64(&g_droppedEvents, 0, 0) != dropped + (expected ? 0 : 1) || elapsed > 2000 ||
            ((scenario == 2 || scenario == 3) && elapsed < 900) || ((scenario == 5 || scenario == 6) && elapsed >= 500))
        {
            break;
        }
        result = 3;
        if (sent)
        {
            std::string message;
            if (!ReadReadyTestMessage(server, message) || message.find("\"messageType\":\"agent_ready\"") == std::string::npos)
            {
                break;
            }
        }
        else if (fillPipe)
        {
            for (unsigned index = 0; index < filled; ++index)
            {
                std::string message;
                if (!ReadReadyTestMessage(server, message) || message != filler)
                {
                    readerPassed = false;
                    break;
                }
            }
        }
        DWORD available = 0;
        if (!readerPassed || !PeekNamedPipe(server, nullptr, 0, nullptr, &available, nullptr) || available != 0)
        {
            break;
        }
        result = 0;
    }
    while (false);
    g_pipeHandle = INVALID_HANDLE_VALUE;
    SetLifecycleState(AgentLifecycleState::Disabled);
    if (server != INVALID_HANDLE_VALUE)
    {
        CancelIoEx(server, nullptr);
        CloseHandle(server);
    }
    if (client != INVALID_HANDLE_VALUE)
    {
        CloseHandle(client);
    }
    if (held != nullptr)
    {
        CloseHandle(held);
    }
    if (transfer.hEvent != nullptr)
    {
        CloseHandle(transfer.hEvent);
    }
    return result;
}

extern "C" __declspec(dllexport) DWORD WINAPI KnMonTestReadyDelivery(void*)
{
    DWORD result = 0;
    for (unsigned scenario = 0; scenario < 7; ++scenario)
    {
        result = RunReadyDeliveryCase(scenario);
        if (result != 0)
        {
            result += scenario * 10;
            break;
        }
    }
    return result;
}

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:KnMonTestReadyDelivery=_KnMonTestReadyDelivery@4")
#endif
