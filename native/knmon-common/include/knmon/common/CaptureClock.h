#pragma once

#include <cstdint>
#include <limits>

namespace knmon
{
struct CaptureClock
{
    std::uint64_t Frequency = 0;
    std::uint64_t QpcBase = 0;
    std::uint64_t UtcBaseFileTime = 0;
    std::uint64_t AnchorSpanQpc = 0;
};

// Floor after scaling; split before multiplying to avoid long-uptime overflow.
inline bool ScaleQpcTicks(std::uint64_t ticks, std::uint64_t frequency,
    std::uint64_t scale, std::uint64_t& value) noexcept
{
    value = 0;
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    bool valid = false;
    do
    {
        if (frequency == 0 || scale == 0)
        {
            break;
        }
        const auto whole = ticks / frequency;
        const auto remainder = ticks % frequency;
        std::uint64_t fraction = 0;
        if (remainder <= maximum / scale)
        {
            fraction = (remainder * scale) / frequency;
        }
        else
        {
            // Binary long multiplication/division for unusual high frequencies.
            std::uint64_t carryRemainder = 0;
            for (int bit = 63; bit >= 0; --bit)
            {
                const bool carry = carryRemainder >= frequency - carryRemainder;
                carryRemainder = carry ? carryRemainder - (frequency - carryRemainder) : carryRemainder * 2;
                fraction = fraction * 2 + (carry ? 1 : 0);
                if (((scale >> bit) & 1) != 0)
                {
                    const bool addCarry = carryRemainder >= frequency - remainder;
                    carryRemainder = addCarry ? carryRemainder - (frequency - remainder) : carryRemainder + remainder;
                    fraction += addCarry ? 1 : 0;
                }
            }
        }
        if (whole > (maximum - fraction) / scale)
        {
            break;
        }
        value = whole * scale + fraction;
        valid = true;
    }
    while (false);
    return valid;
}

struct CaptureTime
{
    std::uint64_t RelativeUs = 0;
    std::uint64_t DurationUs = 0;
    std::uint64_t UtcFileTime = 0;
};

inline bool ConvertCaptureTime(const CaptureClock& clock, std::uint64_t start,
    std::uint64_t end, CaptureTime& time) noexcept
{
    time = {};
    bool valid = false;
    do
    {
        if (start < clock.QpcBase || end < start || clock.UtcBaseFileTime == 0)
        {
            break;
        }
        std::uint64_t utcDelta = 0;
        if (!ScaleQpcTicks(start - clock.QpcBase, clock.Frequency, 1000000, time.RelativeUs) ||
            !ScaleQpcTicks(end - start, clock.Frequency, 1000000, time.DurationUs) ||
            !ScaleQpcTicks(start - clock.QpcBase, clock.Frequency, 10000000, utcDelta) ||
            utcDelta > std::numeric_limits<std::uint64_t>::max() - clock.UtcBaseFileTime)
        {
            break;
        }
        time.UtcFileTime = clock.UtcBaseFileTime + utcDelta;
        valid = true;
    }
    while (false);
    return valid;
}
}
