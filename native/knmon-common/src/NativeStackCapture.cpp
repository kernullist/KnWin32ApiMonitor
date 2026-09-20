#include <knmon/common/NativeStackCapture.h>

namespace knmon
{
namespace
{
int StackFaultFilter(DWORD code) noexcept
{
    return code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR ||
        code == EXCEPTION_DATATYPE_MISALIGNMENT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

void CaptureRawCpp(NativeStackCaptureFunction capture, ULONG limit, PVOID* frames,
    NativeStackTrace* result) noexcept
{
    try
    {
        const auto count = capture(0, limit, frames, nullptr);
        bool valid = count <= limit;
        for (std::uint32_t index = 0; valid && index < count; ++index)
        {
            valid = frames[index] != nullptr;
        }
        if (!valid)
        {
            result->Status = NativeStackCaptureStatus::InvalidResult;
        }
        else
        {
            result->Status = count == 0 ? NativeStackCaptureStatus::Empty : NativeStackCaptureStatus::Captured;
            result->FrameCount = count;
            for (std::uint32_t index = 0; index < count; ++index)
            {
                result->Frames[index] = reinterpret_cast<std::uintptr_t>(frames[index]);
            }
        }
    }
    catch (...)
    {
        result->Status = NativeStackCaptureStatus::CppException;
    }
}
}

// Keep SEH outside C++ object lifetimes; unknown faults retain normal dispatch.
__declspec(noinline) NativeStackTrace CaptureNativeStack(std::uint32_t frameLimit,
    NativeStackCaptureFunction capture) noexcept
{
    const DWORD incomingError = GetLastError();
    NativeStackTrace result;
    result.RequestedFrames = frameLimit;
    PVOID frames[NativeStackFrameLimit] = {};
    __try
    {
        do
        {
            if (frameLimit == 0)
            {
                break;
            }
            if (frameLimit > NativeStackFrameLimit)
            {
                result.Status = NativeStackCaptureStatus::InvalidRequest;
                break;
            }
            if (capture == nullptr)
            {
                result.Status = NativeStackCaptureStatus::Unavailable;
                break;
            }
            __try
            {
                CaptureRawCpp(capture, frameLimit, frames, &result);
            }
            __except (StackFaultFilter(GetExceptionCode()))
            {
                result.Status = NativeStackCaptureStatus::MemoryFault;
                result.ExceptionCode = GetExceptionCode();
            }
        }
        while (false);
    }
    __finally
    {
        SetLastError(incomingError);
    }
    return result;
}
}
