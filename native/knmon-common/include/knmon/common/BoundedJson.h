#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace knmon
{
struct JsonLimits
{
    std::size_t DocumentBytes = 8 * 1024 * 1024;
    std::size_t StringBytes = 256 * 1024;
    std::size_t Depth = 32;
    std::size_t ContainerItems = 65536;
    std::size_t Values = 250000;
};

class JsonInputError : public std::runtime_error
{
public:
    explicit JsonInputError(const std::string& message);
};

struct JsonStorage;

// Immutable views retain the document, including when the parent view is destroyed.
class JsonDocument
{
public:
    JsonDocument();
    explicit JsonDocument(std::string_view text, const JsonLimits& limits = {});
    bool Has(std::string_view key) const;
    bool empty() const;
    std::size_t ValueCount() const;
    std::string Text() const;
    std::string String(std::string_view key, bool required = false) const;
    bool Bool(std::string_view key, bool required = false) const;
    std::uint64_t UInt64(std::string_view key, bool required = false) const;
    std::uint32_t UInt32(std::string_view key, bool required = false) const;
    double NonnegativeNumber(std::string_view key, bool required = false) const;
    std::uint64_t DecimalUInt64(std::string_view key) const;
    JsonDocument Object(std::string_view key, bool required = false) const;
    JsonDocument ObjectOrNull(std::string_view key, bool required = false) const;
    JsonDocument Array(std::string_view key, bool required = false) const;
    std::vector<JsonDocument> Objects() const;
    void RequireObject() const;
    void RequireStringArray() const;

private:
    JsonDocument(std::shared_ptr<const JsonStorage> storage, const void* value);
    const void* Find(std::string_view key, bool required) const;
    std::shared_ptr<const JsonStorage> Storage_;
    const void* Value_ = nullptr;
};

std::ostream& operator<<(std::ostream& stream, const JsonDocument& value);
std::string ExtractJsonString(const JsonDocument& value, std::string_view key);
bool ExtractJsonBool(const JsonDocument& value, std::string_view key);
std::uint64_t ExtractJsonUInt64(const JsonDocument& value, std::string_view key);
std::uint32_t ExtractJsonUInt32(const JsonDocument& value, std::string_view key);
JsonDocument ExtractJsonObject(const JsonDocument& value, std::string_view key);
JsonDocument ExtractJsonArray(const JsonDocument& value, std::string_view key);
std::vector<JsonDocument> SplitJsonObjectArray(const JsonDocument& value);
JsonDocument ParseAgentJson(std::string_view text);
void ValidateAgentJson(const JsonDocument& value);
void ValidateTraceJson(const JsonDocument& value);
}
