#include "knmon/common/SessionCodec.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

namespace
{
    void Require(bool condition, const char* message)
    {
        if (!condition)
        {
            throw std::runtime_error(message);
        }
    }
}

int main(int argc, char** argv)
{
    int result = 1;
    try
    {
        std::string encoded;
        std::string decoded;
        std::string error;
        if (argc == 6)
        {
            Require(std::filesystem::file_size(argv[2]) <= knmon::SessionChunkByteLimit, "input limit");
            std::ifstream file(argv[2], std::ios::binary);
            std::string input(std::istreambuf_iterator<char>(file), {});
            const auto expected = std::stoull(argv[4]);
            Require(expected <= knmon::SessionChunkByteLimit, "output limit");
            const bool success = std::string(argv[1]) == "encode"
                ? knmon::EncodeSessionZstd(input, &decoded, &error)
                : knmon::DecodeSessionZstd(input, static_cast<std::size_t>(expected), &decoded, &error);
            Require(success, error.c_str());
            std::ofstream output(argv[3], std::ios::binary);
            output.write(decoded.data(), static_cast<std::streamsize>(decoded.size()));
            Require(output.good(), "output write failed");
        }
        else
        {
            for (const std::string input : { std::string(), std::string("hello\0world", 11), std::string(1024 * 1024, 'A') })
            {
                Require(knmon::EncodeSessionZstd(input, &encoded, &error), "encode");
                Require(knmon::DecodeSessionZstd(encoded, input.size(), &decoded, &error) && decoded == input, "round trip");
                Require(!knmon::DecodeSessionZstd(encoded + "trailing", input.size(), &decoded, &error), "trailing accepted");
                Require(decoded.empty(), "failed output leaked");
                Require(!knmon::DecodeSessionZstd(encoded + encoded, input.size() * 2, &decoded, &error), "multiple frames accepted");
                Require(!knmon::DecodeSessionZstd(encoded, input.size() + 1, &decoded, &error), "wrong size accepted");
                encoded.back() ^= 1;
                Require(!knmon::DecodeSessionZstd(encoded, input.size(), &decoded, &error), "checksum accepted");
            }
            Require(!knmon::DecodeSessionZstd("", knmon::SessionChunkByteLimit + 1, &decoded, &error), "limit accepted");
            std::cout << "Session codec contract passed.\n";
        }
        result = 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
    }
    return result;
}
