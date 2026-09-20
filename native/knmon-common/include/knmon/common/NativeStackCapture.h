#pragma once

#include <Windows.h>
#include <knmon/common/NativeStackTrace.h>

namespace knmon
{
using NativeStackCaptureFunction = USHORT(WINAPI*)(ULONG, ULONG, PVOID*, PULONG);

// Raw current-thread addresses only; reaching the limit does not prove truncation.
// The optional callback permits isolated fault tests without global hook state.
NativeStackTrace CaptureNativeStack(std::uint32_t frameLimit,
    NativeStackCaptureFunction capture = &RtlCaptureStackBackTrace) noexcept;
}
