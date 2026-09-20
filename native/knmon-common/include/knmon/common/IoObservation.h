#pragma once

#include <Windows.h>
#include <algorithm>
#include <cstdint>

namespace knmon
{
enum class IoReadStatus : std::uint32_t
{
    NotCaptured = 0,
    Complete = 1,
    NullPointer = 2,
    Unreadable = 3,
    Partial = 4,
};

struct IoObservation
{
    static constexpr DWORD Limit = 16;
    char Text[Limit * 3] = {};
    DWORD Requested = 0;
    DWORD Captured = 0;
    IoReadStatus Status = IoReadStatus::NotCaptured;
};

inline IoObservation CaptureIoBuffer(const void* buffer, DWORD bytes) noexcept
{
    IoObservation result;
    result.Requested = bytes;
    do
    {
        if (bytes == 0)
        {
            result.Status = IoReadStatus::Complete;
            break;
        }
        if (buffer == nullptr)
        {
            result.Status = IoReadStatus::NullPointer;
            break;
        }
        unsigned char captured[IoObservation::Limit] = {};
        SIZE_T copied = 0;
        const DWORD requested = (std::min)(bytes, IoObservation::Limit);
        const BOOL read = ReadProcessMemory(GetCurrentProcess(), buffer, captured, requested, &copied);
        result.Captured = static_cast<DWORD>((std::min)(copied, static_cast<SIZE_T>(requested)));
        result.Status = read && copied == requested ? IoReadStatus::Complete :
            (result.Captured == 0 ? IoReadStatus::Unreadable : IoReadStatus::Partial);
        static constexpr char Hex[] = "0123456789abcdef";
        for (DWORD index = 0; index < result.Captured; ++index)
        {
            result.Text[index * 3] = Hex[captured[index] >> 4];
            result.Text[index * 3 + 1] = Hex[captured[index] & 15];
            if (index + 1 != result.Captured)
            {
                result.Text[index * 3 + 2] = ' ';
            }
        }
    }
    while (false);
    return result;
}
}
