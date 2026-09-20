#pragma once

#include <cstdint>
#include <string_view>

namespace knmon
{
enum class CaptureDetail : std::uint32_t
{
    Preview = 0,
    Arguments = 1,
    Metadata = 2,
};

inline constexpr bool IsValidCaptureDetail(CaptureDetail detail) noexcept
{
    return detail == CaptureDetail::Preview || detail == CaptureDetail::Arguments ||
        detail == CaptureDetail::Metadata;
}

inline constexpr const char* CaptureDetailName(CaptureDetail detail) noexcept
{
    switch (detail)
    {
    case CaptureDetail::Preview:
        return "preview";
    case CaptureDetail::Arguments:
        return "arguments";
    case CaptureDetail::Metadata:
        return "metadata";
    default:
        return "invalid";
    }
}

inline constexpr bool ParseCaptureDetail(std::string_view text, CaptureDetail& detail) noexcept
{
    bool valid = true;
    if (text == "preview")
    {
        detail = CaptureDetail::Preview;
    }
    else if (text == "arguments")
    {
        detail = CaptureDetail::Arguments;
    }
    else if (text == "metadata")
    {
        detail = CaptureDetail::Metadata;
    }
    else
    {
        valid = false;
    }
    return valid;
}
}
