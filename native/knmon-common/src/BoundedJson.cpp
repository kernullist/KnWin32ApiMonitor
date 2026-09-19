#include <knmon/common/BoundedJson.h>
#include <nlohmann/json.hpp>

#include <limits>
#include <ostream>
#include <set>
#include <utility>

namespace knmon
{
using Json = nlohmann::json;

struct JsonStorage
{
    Json Value;
    std::string Text;
    std::size_t Values = 0;
};

JsonInputError::JsonInputError(const std::string& message) : std::runtime_error(message)
{
}

JsonDocument::JsonDocument()
{
    static const auto empty = std::make_shared<const JsonStorage>(JsonStorage{Json::object(), "{}", 1});
    Storage_ = empty;
    Value_ = &Storage_->Value;
}

JsonDocument::JsonDocument(std::shared_ptr<const JsonStorage> storage, const void* value)
    : Storage_(std::move(storage)), Value_(value)
{
}

JsonDocument::JsonDocument(std::string_view text, const JsonLimits& limits)
{
    if (text.size() > limits.DocumentBytes || text.empty())
    {
        throw JsonInputError("JSON document byte limit or empty input.");
    }
    // Reject BOMs and raw NUL explicitly; parse() otherwise accepts a UTF-8 BOM.
    if (text.find('\0') != std::string_view::npos ||
        (text.size() >= 3 && text.substr(0, 3) == "\xEF\xBB\xBF"))
    {
        throw JsonInputError("JSON encoding contains a BOM or raw NUL.");
    }

    struct Frame
    {
        std::set<std::string, std::less<>> Keys;
        std::size_t Items = 0;
    };
    std::vector<Frame> frames;
    std::size_t values = 0;
    auto countValue = [&]()
    {
        if (++values > limits.Values ||
            (!frames.empty() && ++frames.back().Items > limits.ContainerItems))
        {
            throw JsonInputError("JSON value or container item limit exceeded.");
        }
    };
    auto callback = [&](int, Json::parse_event_t event, Json& parsed)
    {
        if (event == Json::parse_event_t::object_start || event == Json::parse_event_t::array_start)
        {
            countValue();
            if (frames.size() >= limits.Depth)
            {
                throw JsonInputError("JSON nesting depth limit exceeded.");
            }
            frames.emplace_back();
        }
        else if (event == Json::parse_event_t::object_end || event == Json::parse_event_t::array_end)
        {
            frames.pop_back();
        }
        else if (event == Json::parse_event_t::key)
        {
            const auto& key = parsed.get_ref<const std::string&>();
            if (key.size() > limits.StringBytes || key.find('\0') != std::string::npos)
            {
                throw JsonInputError("JSON key length or embedded NUL is invalid.");
            }
            if (!frames.back().Keys.insert(key).second)
            {
                throw JsonInputError("Duplicate JSON object key.");
            }
        }
        else if (event == Json::parse_event_t::value)
        {
            countValue();
            if (parsed.is_string())
            {
                const auto& value = parsed.get_ref<const std::string&>();
                if (value.size() > limits.StringBytes || value.find('\0') != std::string::npos)
                {
                    throw JsonInputError("JSON string length or embedded NUL is invalid.");
                }
            }
        }
        return true;
    };

    try
    {
        auto storage = std::make_shared<JsonStorage>();
        storage->Value = Json::parse(text.begin(), text.end(), callback, true, false);
        storage->Text.assign(text);
        storage->Values = values;
        Value_ = &storage->Value;
        Storage_ = std::move(storage);
    }
    catch (const Json::exception&)
    {
        throw JsonInputError("Malformed JSON syntax, UTF-8, Unicode escape, or number.");
    }
}

void JsonDocument::RequireObject() const
{
    if (Value_ == nullptr || !static_cast<const Json*>(Value_)->is_object())
    {
        throw JsonInputError("JSON object required.");
    }
}

const void* JsonDocument::Find(std::string_view key, bool required) const
{
    RequireObject();
    const auto& object = *static_cast<const Json*>(Value_);
    const auto found = object.find(key);
    const Json* value = found == object.end() ? nullptr : &*found;
    if (required && value == nullptr)
    {
        throw JsonInputError("Required JSON field is missing: " + std::string(key));
    }
    return value;
}

bool JsonDocument::Has(std::string_view key) const
{
    return Find(key, false) != nullptr;
}

bool JsonDocument::empty() const
{
    return static_cast<const Json*>(Value_)->empty();
}

std::size_t JsonDocument::ValueCount() const
{
    return Storage_->Values;
}

std::string JsonDocument::Text() const
{
    return Value_ == &Storage_->Value ? Storage_->Text : static_cast<const Json*>(Value_)->dump();
}

std::string JsonDocument::String(std::string_view key, bool required) const
{
    const auto* value = static_cast<const Json*>(Find(key, required));
    if (value != nullptr && !value->is_string())
    {
        throw JsonInputError("JSON string required: " + std::string(key));
    }
    return value == nullptr ? std::string() : value->get<std::string>();
}

bool JsonDocument::Bool(std::string_view key, bool required) const
{
    const auto* value = static_cast<const Json*>(Find(key, required));
    if (value != nullptr && !value->is_boolean())
    {
        throw JsonInputError("JSON boolean required: " + std::string(key));
    }
    return value != nullptr && value->get<bool>();
}

std::uint64_t JsonDocument::UInt64(std::string_view key, bool required) const
{
    const auto* value = static_cast<const Json*>(Find(key, required));
    if (value != nullptr && !value->is_number_unsigned())
    {
        throw JsonInputError("JSON unsigned integer required: " + std::string(key));
    }
    return value == nullptr ? 0 : value->get<std::uint64_t>();
}

std::uint32_t JsonDocument::UInt32(std::string_view key, bool required) const
{
    const auto value = UInt64(key, required);
    if (value > std::numeric_limits<std::uint32_t>::max())
    {
        throw JsonInputError("JSON uint32 range exceeded: " + std::string(key));
    }
    return static_cast<std::uint32_t>(value);
}

JsonDocument JsonDocument::Object(std::string_view key, bool required) const
{
    const auto* value = static_cast<const Json*>(Find(key, required));
    if (value != nullptr && !value->is_object())
    {
        throw JsonInputError("JSON object required: " + std::string(key));
    }
    return value == nullptr ? JsonDocument() : JsonDocument(Storage_, value);
}

JsonDocument JsonDocument::Array(std::string_view key, bool required) const
{
    const auto* value = static_cast<const Json*>(Find(key, required));
    if (value != nullptr && !value->is_array())
    {
        throw JsonInputError("JSON array required: " + std::string(key));
    }
    return value == nullptr ? JsonDocument("[]") : JsonDocument(Storage_, value);
}

JsonDocument JsonDocument::ObjectOrNull(std::string_view key, bool required) const
{
    const auto* value = static_cast<const Json*>(Find(key, required));
    if (value != nullptr && !value->is_object() && !value->is_null())
    {
        throw JsonInputError("JSON object or null required: " + std::string(key));
    }
    return value == nullptr ? JsonDocument("null") : JsonDocument(Storage_, value);
}

void JsonDocument::RequireStringArray() const
{
    const auto& value = *static_cast<const Json*>(Value_);
    if (!value.is_array())
    {
        throw JsonInputError("JSON string array required.");
    }
    for (const auto& item : value)
    {
        if (!item.is_string())
        {
            throw JsonInputError("Non-string JSON array entry.");
        }
    }
}

std::vector<JsonDocument> JsonDocument::Objects() const
{
    const auto& value = *static_cast<const Json*>(Value_);
    if (!value.is_array())
    {
        throw JsonInputError("JSON object array required.");
    }
    std::vector<JsonDocument> objects;
    objects.reserve(value.size());
    for (const auto& item : value)
    {
        if (!item.is_object())
        {
            throw JsonInputError("Non-object JSON array entry.");
        }
        objects.push_back(JsonDocument(Storage_, &item));
    }
    return objects;
}

std::ostream& operator<<(std::ostream& stream, const JsonDocument& value)
{
    return stream << value.Text();
}

std::string ExtractJsonString(const JsonDocument& value, std::string_view key)
{
    return value.String(key);
}

bool ExtractJsonBool(const JsonDocument& value, std::string_view key)
{
    return value.Bool(key);
}

std::uint64_t ExtractJsonUInt64(const JsonDocument& value, std::string_view key)
{
    return value.UInt64(key);
}

std::uint32_t ExtractJsonUInt32(const JsonDocument& value, std::string_view key)
{
    return value.UInt32(key);
}

JsonDocument ExtractJsonObject(const JsonDocument& value, std::string_view key)
{
    return value.Object(key);
}

JsonDocument ExtractJsonArray(const JsonDocument& value, std::string_view key)
{
    return value.Array(key);
}

std::vector<JsonDocument> SplitJsonObjectArray(const JsonDocument& value)
{
    return value.Objects();
}

JsonDocument ParseAgentJson(std::string_view text)
{
    const JsonLimits limits{1024 * 1024, 64 * 1024, 16, 4096, 16384};
    JsonDocument value(text, limits);
    ValidateAgentJson(value);
    return value;
}

void ValidateAgentJson(const JsonDocument& value)
{
    value.RequireObject();
    if (value.String("schemaVersion", true) != "0.1.0" || value.String("messageType", true).empty() ||
        value.String("operationId", true).empty() || value.UInt32("pid", true) == 0)
    {
        throw JsonInputError("Invalid agent message envelope.");
    }
    value.UInt32("tid", true);
    value.String("timestampUtc", true);
    value.UInt64("sequence", true);
    const auto type = value.String("messageType");
    if (type == "agent_hello")
    {
        const auto architecture = value.String("architecture", true);
        if ((architecture != "x86" && architecture != "x64") || value.String("agentVersion", true).empty())
        {
            throw JsonInputError("Invalid agent HELLO architecture or version.");
        }
    }
    else if (type == "agent_shutdown")
    {
        value.String("reason", true);
        value.UInt64("installedHooks", true);
        value.UInt64("restoredHooks", true);
        value.UInt64("failedHooks", true);
        value.UInt64("droppedCount", true);
    }
    else if (type == "dropped_events")
    {
        value.UInt64("droppedCount", true);
    }
    else if (type == "api_call")
    {
        value.String("module", true);
        value.String("api", true);
        value.String("process", true);
        value.String("returnValue", true);
        value.UInt32("lastErrorCode", true);
        value.String("lastErrorMessage", true);
        value.UInt64("durationUs", true);
        for (const auto& argument : value.Array("arguments", true).Objects())
        {
            argument.UInt32("index", true);
            for (const auto* key : {"name", "type", "direction", "rawValue", "preCallValue",
                "postCallValue", "decodedValue", "decodeStatus"})
            {
                argument.String(key, true);
            }
        }
        value.Array("tags", true).RequireStringArray();
        value.Array("stack", true).RequireStringArray();
        value.String("bufferPreview", true);
    }
    else if (type == "resolver_pointer_instrumented" || type == "resolver_pointer_candidate" ||
        type == "resolver_pointer_unsupported")
    {
        for (const auto* key : {"resolverApi", "classification", "reason", "requestedModule", "requestedName",
            "lookupKind", "targetModule", "targetRvaHex", "definitionName", "replacementPointer", "instrumentationReason"})
        {
            value.String(key);
        }
        value.UInt32("definitionApiId");
        value.UInt32("requestedOrdinal");
        value.Bool("instrumented");
    }
}

void ValidateTraceJson(const JsonDocument& value)
{
    if (value.String("schemaVersion", true) != "0.1.0" || value.String("api", true).empty())
    {
        throw JsonInputError("Invalid trace event schema or API name.");
    }
    value.UInt64("eventId", true);
    value.UInt32("pid", true);
    value.UInt32("tid", true);
    value.String("process", true);
    value.String("module", true);
    value.String("returnValue", true);
    value.UInt64("durationUs", true);
    value.String("bufferPreview", true);
    value.Array("arguments", true).Objects();
    value.Array("tags", true).RequireStringArray();
    value.Array("stack", true).RequireStringArray();
    const auto error = value.ObjectOrNull("error", true);
    if (error.Text() != "null")
    {
        error.String("kind", true);
        error.String("code", true);
        error.String("message", true);
    }
}
}
