#include "knmon/common/SessionCodec.h"

#include <array>
#include <memory>
#include <zstd.h>

namespace knmon
{
    namespace
    {
        bool Fail(std::string* output, std::string* error, const char* reason)
        {
            if (output != nullptr)
            {
                output->clear();
            }
            if (error != nullptr)
            {
                *error = reason;
            }
            return false;
        }
    }

    bool EncodeSessionZstd(std::string_view input, std::string* output, std::string* error)
    {
        bool success = false;
        do
        {
            if (output == nullptr || input.size() > SessionChunkByteLimit)
            {
                break;
            }
            std::unique_ptr<ZSTD_CCtx, decltype(&ZSTD_freeCCtx)> context(ZSTD_createCCtx(), ZSTD_freeCCtx);
            if (!context || ZSTD_isError(ZSTD_CCtx_setParameter(context.get(), ZSTD_c_compressionLevel, 3)) ||
                ZSTD_isError(ZSTD_CCtx_setParameter(context.get(), ZSTD_c_checksumFlag, 1)))
            {
                break;
            }
            std::string encoded(ZSTD_compressBound(input.size()), '\0');
            const auto length = ZSTD_compress2(context.get(), encoded.data(), encoded.size(), input.data(), input.size());
            if (ZSTD_isError(length) || length > SessionChunkByteLimit)
            {
                break;
            }
            encoded.resize(length);
            *output = std::move(encoded);
            success = true;
        }
        while (false);
        if (!success)
        {
            Fail(output, error, "zstd_encode_failed_or_chunk_limit_exceeded");
        }
        return success;
    }

    bool DecodeSessionZstd(std::string_view input, std::size_t expectedBytes,
        std::string* output, std::string* error)
    {
        bool success = false;
        do
        {
            // A chunk contains exactly one ordinary frame, without an external dictionary.
            if (output == nullptr || input.size() < 4 || input.size() > SessionChunkByteLimit ||
                expectedBytes > SessionChunkByteLimit || input.substr(0, 4) != std::string_view("\x28\xb5\x2f\xfd", 4))
            {
                break;
            }
            const auto contentSize = ZSTD_getFrameContentSize(input.data(), input.size());
            if (contentSize == ZSTD_CONTENTSIZE_ERROR ||
                (contentSize != ZSTD_CONTENTSIZE_UNKNOWN && contentSize != expectedBytes) ||
                ZSTD_getDictID_fromFrame(input.data(), input.size()) != 0)
            {
                break;
            }
            std::unique_ptr<ZSTD_DCtx, decltype(&ZSTD_freeDCtx)> context(ZSTD_createDCtx(), ZSTD_freeDCtx);
            if (!context || ZSTD_isError(ZSTD_DCtx_setParameter(context.get(), ZSTD_d_windowLogMax, 26)))
            {
                break;
            }
            std::string decoded;
            std::array<char, 65536> buffer;
            ZSTD_inBuffer source{ input.data(), input.size(), 0 };
            while (true)
            {
                ZSTD_outBuffer destination{ buffer.data(), buffer.size(), 0 };
                const auto before = source.pos;
                const auto remaining = ZSTD_decompressStream(context.get(), &destination, &source);
                if (ZSTD_isError(remaining) || destination.pos > expectedBytes - decoded.size())
                {
                    break;
                }
                decoded.append(buffer.data(), destination.pos);
                if (remaining == 0)
                {
                    success = source.pos == source.size && decoded.size() == expectedBytes;
                    break;
                }
                if (source.pos == before && destination.pos == 0)
                {
                    break;
                }
            }
            if (success)
            {
                *output = std::move(decoded);
            }
        }
        while (false);
        if (!success)
        {
            Fail(output, error, "corrupt_unsupported_or_oversized_zstd_frame");
        }
        return success;
    }
}
