#include <knmon/common/NativeStackCapture.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <iostream>
#include <intrin.h>
#include <stdexcept>
#include <thread>

namespace
{
int g_failures = 0;
unsigned g_calls = 0;
constexpr DWORD Sentinel = 0x12345678;

void Check(bool value, const char* name)
{
    if (!value)
    {
        std::cerr << "FAIL: " << name << "\n";
        ++g_failures;
    }
}

bool EmptyFrames(const knmon::NativeStackTrace& trace)
{
    return trace.FrameCount == 0 && std::all_of(std::begin(trace.Frames), std::end(trace.Frames),
        [](std::uint64_t address)
        {
            return address == 0;
        });
}

USHORT WINAPI Empty(ULONG skip, ULONG limit, PVOID*, PULONG hash)
{
    ++g_calls;
    Check(skip == 0 && limit > 0 && limit <= knmon::NativeStackFrameLimit && hash == nullptr,
        "bounded capture request");
    SetLastError(ERROR_BAD_COMMAND);
    return 0;
}

USHORT WINAPI TooMany(ULONG, ULONG limit, PVOID*, PULONG)
{
    return static_cast<USHORT>(limit + 1);
}

USHORT WINAPI ZeroAddress(ULONG, ULONG, PVOID* frames, PULONG)
{
    frames[0] = reinterpret_cast<void*>(0x1234);
    return 2;
}

USHORT WINAPI RepeatedAddress(ULONG, ULONG, PVOID* frames, PULONG)
{
    frames[0] = reinterpret_cast<void*>(0x1234);
    frames[1] = frames[0];
    SetLastError(ERROR_BAD_COMMAND);
    return 2;
}

USHORT WINAPI MemoryFault(ULONG, ULONG, PVOID* frames, PULONG)
{
    frames[0] = reinterpret_cast<void*>(0x1234);
    SetLastError(ERROR_BAD_COMMAND);
    RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, nullptr);
    return 1;
}

USHORT WINAPI CppFault(ULONG, ULONG, PVOID* frames, PULONG)
{
    frames[0] = reinterpret_cast<void*>(0x1234);
    SetLastError(ERROR_BAD_COMMAND);
    throw std::runtime_error("Injected capture failure");
}

USHORT WINAPI UnknownFault(ULONG, ULONG, PVOID*, PULONG)
{
    SetLastError(ERROR_BAD_COMMAND);
    RaiseException(0xe0424242, 0, 0, nullptr);
    return 0;
}

bool UnknownFaultPropagates()
{
    bool caught = false;
    SetLastError(Sentinel);
    __try
    {
        knmon::CaptureNativeStack(8, UnknownFault);
    }
    __except (GetExceptionCode() == 0xe0424242 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        caught = GetLastError() == Sentinel;
    }
    return caught;
}

__declspec(noinline) knmon::NativeStackTrace KnownCaller(std::uint32_t limit, std::uint64_t* caller)
{
    *caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    auto trace = knmon::CaptureNativeStack(limit);
    // Keep the call site alive even under optimized test builds.
    volatile std::uint32_t count = trace.FrameCount;
    (void)count;
    return trace;
}

__declspec(noinline) knmon::NativeStackTrace Recurse(unsigned depth)
{
    knmon::NativeStackTrace trace;
    if (depth == 0)
    {
        trace = knmon::CaptureNativeStack(knmon::NativeStackFrameLimit);
    }
    else
    {
        trace = Recurse(depth - 1);
    }
    volatile unsigned retainedDepth = depth;
    (void)retainedDepth;
    return trace;
}
}

int main()
{
    using Status = knmon::NativeStackCaptureStatus;
    const auto disabled = knmon::CaptureNativeStack(0, Empty);
    const auto invalid = knmon::CaptureNativeStack(UINT32_MAX, Empty);
    Check(disabled.Status == Status::Disabled && EmptyFrames(disabled) && g_calls == 0,
        "disabled capture does not call unwinder");
    Check(invalid.Status == Status::InvalidRequest && EmptyFrames(invalid) && g_calls == 0,
        "oversized request is rejected before capture");
    const auto unavailable = knmon::CaptureNativeStack(8, nullptr);
    Check(unavailable.Status == Status::Unavailable && EmptyFrames(unavailable), "unavailable capture");

    for (const auto capture : {Empty, TooMany, ZeroAddress, MemoryFault, CppFault})
    {
        SetLastError(Sentinel);
        const auto trace = knmon::CaptureNativeStack(8, capture);
        Check(GetLastError() == Sentinel, "capture failure preserves last error");
        const auto status = capture == Empty ? Status::Empty : capture == MemoryFault ? Status::MemoryFault :
            capture == CppFault ? Status::CppException : Status::InvalidResult;
        Check(trace.Status == status && trace.RequestedFrames == 8 && EmptyFrames(trace),
            "failed capture publishes no partial addresses");
        Check(trace.ExceptionCode == (capture == MemoryFault ? EXCEPTION_ACCESS_VIOLATION : 0),
            "memory-fault code is explicit");
    }
    SetLastError(Sentinel);
    const auto repeated = knmon::CaptureNativeStack(2, RepeatedAddress);
    Check(GetLastError() == Sentinel && repeated.Status == Status::Captured && repeated.FrameCount == 2 &&
        repeated.Frames[0] == repeated.Frames[1] && repeated.Frames[2] == 0,
        "duplicate recursive addresses are preserved");
    Check(UnknownFaultPropagates(), "unknown exception is dispatched with restored error");

    for (const auto limit : {1u, 8u, knmon::NativeStackFrameLimit})
    {
        SetLastError(Sentinel);
        std::uint64_t caller = 0;
        const auto trace = KnownCaller(limit, &caller);
        Check(GetLastError() == Sentinel && trace.Status == Status::Captured && trace.FrameCount > 0 &&
            trace.FrameCount <= limit, "actual OS capture obeys frame bound and preserves error");
        if (limit >= 8)
        {
            Check(std::find(std::begin(trace.Frames), std::begin(trace.Frames) + trace.FrameCount, caller) !=
                std::begin(trace.Frames) + trace.FrameCount, "actual caller return address is captured");
        }
        Check(std::all_of(std::begin(trace.Frames) + trace.FrameCount, std::end(trace.Frames),
            [](std::uint64_t address)
            {
                return address == 0;
            }), "unused frame storage is zero");
    }
    const auto recursion = Recurse(40);
    Check(recursion.Status == Status::Captured && recursion.FrameCount == knmon::NativeStackFrameLimit,
        "deep actual stack reaches the frame limit");

    std::atomic<unsigned> failures = 0;
    std::array<std::thread, 8> threads;
    for (auto& thread : threads)
    {
        thread = std::thread([&failures]()
        {
            for (unsigned iteration = 0; iteration < 500; ++iteration)
            {
                SetLastError(Sentinel + iteration);
                const auto trace = knmon::CaptureNativeStack(8);
                if (trace.Status != Status::Captured || trace.FrameCount == 0 || trace.FrameCount > 8 ||
                    GetLastError() != Sentinel + iteration)
                {
                    failures.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto& thread : threads)
    {
        thread.join();
    }
    Check(failures.load() == 0, "parallel actual captures retain independent thread state");
    std::cout << "Native stack capture: " << (g_failures == 0 ? "PASS" : "FAIL")
        << "; pointerBits=" << sizeof(void*) * 8 << "; concurrentCaptures=4000\n";
    return g_failures == 0 ? 0 : 1;
}
