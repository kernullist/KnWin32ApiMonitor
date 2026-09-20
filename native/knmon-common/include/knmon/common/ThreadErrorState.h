#pragma once

#include <Windows.h>
#include <utility>
#include <type_traits>
#include <cstdint>
#include <bit>
#include <array>
#include <cstring>

namespace knmon
{
template <typename T>
inline constexpr bool CaptureAggregateReturn = false;

class ThreadErrorState
{
public:
    using WinsockGet = int(WINAPI*)();
    using WinsockSet = void(WINAPI*)(int);

    ThreadErrorState(WinsockGet get = nullptr, WinsockSet set = nullptr) noexcept :
        m_win32(GetLastError()), m_get(get), m_set(set)
    {
        if (HasWinsock())
        {
            m_winsock = m_get();
            SetLastError(m_win32);
        }
    }

    ~ThreadErrorState()
    {
        Restore();
    }

    template <typename Function>
    decltype(auto) Call(Function&& function)
    {
        Restore();
        m_return = 0;
        m_returnBits = 0;
        m_returnBytes.fill(0);
        struct CaptureOnExit
        {
            ThreadErrorState& State;
            ~CaptureOnExit()
            {
                State.Capture();
            }
        } capture{*this};
        using Result = std::invoke_result_t<Function>;
        if constexpr (std::is_void_v<Result>)
        {
            std::forward<Function>(function)();
        }
        else
        {
            const auto result = std::forward<Function>(function)();
            m_returnBits = sizeof(Result) * 8;
            if constexpr (std::is_pointer_v<Result>)
            {
                m_return = reinterpret_cast<std::uintptr_t>(result);
            }
            else if constexpr (std::is_floating_point_v<Result>)
            {
                if constexpr (sizeof(Result) == sizeof(std::uint64_t))
                {
                    m_return = std::bit_cast<std::uint64_t>(result);
                }
                else
                {
                    m_return = std::bit_cast<std::uint32_t>(result);
                }
            }
            else if constexpr (std::is_same_v<Result, bool>)
            {
                m_return = result ? 1 : 0;
            }
            else if constexpr (CaptureAggregateReturn<Result>)
            {
                static_assert(std::is_trivially_copyable_v<Result> && sizeof(Result) == 16);
                std::memcpy(m_returnBytes.data(), &result, sizeof(result));
            }
            else
            {
                m_return = static_cast<std::make_unsigned_t<Result>>(result);
            }
            return result;
        }
    }

    DWORD Win32() const noexcept
    {
        return m_win32;
    }

    int Winsock() const noexcept
    {
        return m_winsock;
    }

    bool HasWinsock() const noexcept
    {
        return m_get != nullptr && m_set != nullptr;
    }

    std::uint64_t ReturnValue() const noexcept
    {
        return m_return;
    }

    std::uint32_t ReturnBits() const noexcept
    {
        return m_returnBits;
    }

    const std::array<std::uint8_t, 16>& ReturnBytes() const noexcept
    {
        return m_returnBytes;
    }

    ThreadErrorState(const ThreadErrorState&) = delete;
    ThreadErrorState& operator=(const ThreadErrorState&) = delete;

private:
    void Capture() noexcept
    {
        m_win32 = GetLastError();
        if (HasWinsock())
        {
            m_winsock = m_get();
            SetLastError(m_win32);
        }
    }

    void Restore() const noexcept
    {
        if (HasWinsock())
        {
            m_set(m_winsock);
        }
        SetLastError(m_win32);
    }

    DWORD m_win32 = 0;
    WinsockGet m_get = nullptr;
    WinsockSet m_set = nullptr;
    int m_winsock = 0;
    std::uint64_t m_return = 0;
    std::uint32_t m_returnBits = 0;
    std::array<std::uint8_t, 16> m_returnBytes = {};
};
}
