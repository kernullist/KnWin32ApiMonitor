#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace knmon
{
    inline constexpr std::size_t SessionChunkByteLimit = 64 * 1024 * 1024;

    bool EncodeSessionZstd(std::string_view input, std::string* output, std::string* error);
    bool DecodeSessionZstd(std::string_view input, std::size_t expectedBytes,
        std::string* output, std::string* error);
}
