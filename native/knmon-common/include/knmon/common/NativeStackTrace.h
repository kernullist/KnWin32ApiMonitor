#pragma once

#include <cstdint>

namespace knmon
{
inline constexpr std::uint32_t NativeStackFrameLimit = 32;

enum class NativeStackCaptureStatus : std::uint32_t
{
    Disabled = 0,
    Captured = 1,
    Empty = 2,
    MemoryFault = 3,
    CppException = 4,
    InvalidRequest = 5,
    Unavailable = 6,
    InvalidResult = 7,
};

struct NativeStackTrace
{
    NativeStackCaptureStatus Status = NativeStackCaptureStatus::Disabled;
    std::uint32_t RequestedFrames = 0;
    std::uint32_t FrameCount = 0;
    std::uint32_t ExceptionCode = 0;
    std::uint64_t Frames[NativeStackFrameLimit] = {};
};

inline bool ValidateNativeStackRecord(const NativeStackTrace& value, std::uint32_t addressBits) noexcept
{
    bool valid = false;
    do
    {
        if ((addressBits != 32 && addressBits != 64) || value.RequestedFrames > NativeStackFrameLimit ||
            value.FrameCount > value.RequestedFrames ||
            static_cast<std::uint32_t>(value.Status) > static_cast<std::uint32_t>(NativeStackCaptureStatus::InvalidResult) ||
            value.Status == NativeStackCaptureStatus::InvalidRequest ||
            ((value.Status == NativeStackCaptureStatus::Disabled) != (value.RequestedFrames == 0)) ||
            ((value.Status == NativeStackCaptureStatus::Captured) != (value.FrameCount != 0)) ||
            (value.Status == NativeStackCaptureStatus::MemoryFault ?
                (value.ExceptionCode != 0xc0000005 && value.ExceptionCode != 0xc0000006 && value.ExceptionCode != 0x80000002) :
                value.ExceptionCode != 0))
        {
            break;
        }
        valid = true;
        for (std::uint32_t index = 0; index < NativeStackFrameLimit; ++index)
        {
            if ((index < value.FrameCount ? value.Frames[index] == 0 : value.Frames[index] != 0) ||
                (addressBits == 32 && value.Frames[index] > UINT32_MAX))
            {
                valid = false;
                break;
            }
        }
    }
    while (false);
    return valid;
}
}
