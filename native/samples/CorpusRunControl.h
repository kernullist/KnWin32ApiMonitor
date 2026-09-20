#pragma once

#include <Windows.h>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace knmon::corpus
{
inline bool ParseBoundedDecimal(std::wstring_view text, DWORD maximum, DWORD& value)
{
    bool valid = !text.empty() && (text.size() == 1 || text.front() != L'0');
    DWORD parsed = 0;
    for (const wchar_t ch : text)
    {
        if (!valid || ch < L'0' || ch > L'9' || parsed > maximum / 10 ||
            (parsed == maximum / 10 && static_cast<DWORD>(ch - L'0') > maximum % 10))
        {
            valid = false;
            break;
        }
        parsed = parsed * 10 + static_cast<DWORD>(ch - L'0');
    }
    if (valid)
    {
        value = parsed;
    }
    return valid;
}

inline bool ValidControlId(std::wstring_view value)
{
    bool valid = value.size() >= 16 && value.size() <= 64;
    for (const wchar_t ch : value)
    {
        if (!((ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') ||
            (ch >= L'0' && ch <= L'9') || ch == L'-' || ch == L'_'))
        {
            valid = false;
            break;
        }
    }
    return valid;
}

inline constexpr std::array<const wchar_t*, 4> ControlSuffixes = {L"ready", L"start", L"done", L"release"};

inline std::wstring ControlEventName(std::wstring_view id, std::size_t index)
{
    return L"Local\\KNMon.Corpus." + std::wstring(id) + L"." + ControlSuffixes.at(index);
}

class RunControl
{
public:
    RunControl() = default;
    RunControl(const RunControl&) = delete;
    RunControl& operator=(const RunControl&) = delete;

    ~RunControl()
    {
        for (const HANDLE handle : Handles_)
        {
            if (handle != nullptr)
            {
                CloseHandle(handle);
            }
        }
    }

    bool Open(std::wstring_view id, std::wstring_view delay, std::wstring_view timeout, DWORD iterations)
    {
        bool success = false;
        do
        {
            if (!Id.empty() || !ValidControlId(id) || !ParseBoundedDecimal(delay, 1000, DelayMs) ||
                !ParseBoundedDecimal(timeout, 30000, WaitTimeoutMs) || WaitTimeoutMs < 100 || iterations == 0 ||
                static_cast<std::uint64_t>(DelayMs) * iterations > 20000)
            {
                Status = ERROR_INVALID_PARAMETER;
                break;
            }
            Id = id;
            for (std::size_t index = 0; index < Handles_.size(); ++index)
            {
                const DWORD access = SYNCHRONIZE | ((index == 0 || index == 2) ? EVENT_MODIFY_STATE : 0);
                Handles_[index] = OpenEventW(access, FALSE, ControlEventName(id, index).c_str());
                if (Handles_[index] == nullptr)
                {
                    Status = GetLastError();
                    break;
                }
                if (WaitForSingleObject(Handles_[index], 0) != WAIT_TIMEOUT)
                {
                    Status = ERROR_INVALID_STATE;
                    break;
                }
            }
            success = Status == ERROR_SUCCESS;
        }
        while (false);
        return success;
    }

    bool Begin()
    {
        bool success = true;
        if (!Id.empty())
        {
            LARGE_INTEGER clock = {};
            success = QueryPerformanceCounter(&clock) != FALSE;
            ReadyQpc = static_cast<std::uint64_t>(clock.QuadPart);
            success = success && Signal(0) && Wait(1);
            if (success)
            {
                success = QueryPerformanceCounter(&clock) != FALSE;
                StartGateQpc = static_cast<std::uint64_t>(clock.QuadPart);
            }
            if (!success && Status == ERROR_SUCCESS)
            {
                Status = ERROR_GEN_FAILURE;
            }
        }
        return success;
    }

    bool Complete()
    {
        return Id.empty() || (Signal(2) && Wait(3));
    }

    std::wstring Id;
    DWORD DelayMs = 0;
    DWORD WaitTimeoutMs = 0;
    DWORD Status = ERROR_SUCCESS;
    std::uint64_t ReadyQpc = 0;
    std::uint64_t StartGateQpc = 0;

private:
    bool Signal(std::size_t index)
    {
        const bool success = SetEvent(Handles_[index]) != FALSE;
        if (!success)
        {
            Status = GetLastError();
        }
        return success;
    }

    bool Wait(std::size_t index)
    {
        const DWORD status = WaitForSingleObject(Handles_[index], WaitTimeoutMs);
        if (status != WAIT_OBJECT_0)
        {
            Status = status == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT;
        }
        return status == WAIT_OBJECT_0;
    }

    std::array<HANDLE, 4> Handles_ = {};
};
}
