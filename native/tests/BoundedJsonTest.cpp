#include <knmon/common/BoundedJson.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <iostream>
#include <limits>
#include <string>

namespace
{
using knmon::JsonDocument;

void Check(bool condition, const char* message)
{
    if (!condition)
    {
        throw std::runtime_error(message);
    }
}

void Rejects(const std::function<void()>& action)
{
    bool rejected = false;
    try
    {
        action();
    }
    catch (const knmon::JsonInputError&)
    {
        rejected = true;
    }
    Check(rejected, "Invalid JSON was accepted.");
}

std::string FromHex(const std::string& hex)
{
    Check(hex.size() % 2 == 0, "Odd hex input.");
    std::string bytes;
    for (std::size_t index = 0; index < hex.size(); index += 2)
    {
        bytes.push_back(static_cast<char>(std::stoul(hex.substr(index, 2), nullptr, 16)));
    }
    return bytes;
}

void RunProbe()
{
    std::string line;
    while (std::getline(std::cin, line))
    {
        nlohmann::json response = {{"accepted", false}};
        try
        {
            const JsonDocument request(line);
            knmon::JsonLimits limits;
            for (const auto* name : {"documentBytes", "stringBytes", "depth", "containerItems", "values"})
            {
                if (request.Has(name))
                {
                    auto* target = name == std::string_view("documentBytes") ? &limits.DocumentBytes :
                        name == std::string_view("stringBytes") ? &limits.StringBytes :
                        name == std::string_view("depth") ? &limits.Depth :
                        name == std::string_view("containerItems") ? &limits.ContainerItems : &limits.Values;
                    *target = request.UInt32(name);
                }
            }
            const auto bytes = FromHex(request.String("wireHex", true));
            const auto kind = request.String("kind");
            const auto key = request.String("key");
            const bool required = request.Bool("required");
            const auto document = kind == "agent" ? knmon::ParseAgentJson(bytes) : JsonDocument(bytes, limits);
            document.RequireObject();
            std::string value;
            if (kind == "string")
            {
                value = document.String(key, required);
            }
            else if (kind == "bool")
            {
                value = document.Bool(key, required) ? "true" : "false";
            }
            else if (kind == "u64")
            {
                value = std::to_string(document.UInt64(key, required));
            }
            else if (kind == "u32")
            {
                value = std::to_string(document.UInt32(key, required));
            }
            else if (kind == "object")
            {
                value = document.Object(key, required).Text();
            }
            else if (kind == "array")
            {
                value = document.Array(key, required).Text();
            }
            else if (kind == "objects")
            {
                value = std::to_string(document.Array(key, required).Objects().size());
            }
            response = {{"accepted", true}, {"value", value}};
        }
        catch (const std::exception& exception)
        {
            response["error"] = exception.what();
        }
        std::cout << response.dump() << '\n';
    }
}

void RunTests()
{
    const JsonDocument nested(R"({"nested":{"sessionId":"wrong"},"sessionId":"right"})");
    Check(nested.String("sessionId", true) == "right", "Nested key shadowed the root.");
    Rejects([]()
    {
        JsonDocument(R"({"sessionId":123,"other":"text"})").String("sessionId");
    });
    Check(JsonDocument("{\"enabled\":\n\t\r true}").Bool("enabled", true), "JSON whitespace rejected.");
    for (const auto* input : {R"({"x":1,"x":2})", R"({"a":{"x":1,"\u0078":2}})",
        R"({"x":"\ud800"})", R"({"x":"\udc00"})", R"({"x":"\u0000"})", "{} trailing", "{\"x\":1,}",
        "{\"x\":1e999}", "{\"x\":01}", "/*comment*/{}", "\xEF\xBB\xBF{}"})
    {
        Rejects([&]()
        {
            JsonDocument document(input);
        });
    }
    Check(JsonDocument(R"({"x":"\ud83d\ude00"})").String("x") == "\xF0\x9F\x98\x80", "Surrogate pair mismatch.");
    for (const auto* value : {"-1", "-0", "1.0", "1e0", "18446744073709551616", "true", "null", "\"1\""})
    {
        Rejects([&]()
        {
            JsonDocument(std::string("{\"x\":") + value + "}").UInt64("x");
        });
    }
    Check(JsonDocument("{\"x\":18446744073709551615}").UInt64("x") ==
        std::numeric_limits<std::uint64_t>::max(), "Uint64 precision was lost.");
    Rejects([]()
    {
        JsonDocument("{\"x\":4294967296}").UInt32("x");
    });
    Rejects([]()
    {
        JsonDocument("{}").String("x", true);
    });
    Rejects([]()
    {
        JsonDocument("{\"x\":[{},null]}").Array("x").Objects();
    });
    const auto child = JsonDocument(R"({"parent":{"x":"retained"}})").Object("parent");
    Check(child.String("x") == "retained", "Child view lifetime was not retained.");

    knmon::JsonLimits limits;
    limits.Depth = 3;
    JsonDocument("{\"x\":[{}]}", limits);
    Rejects([&]()
    {
        JsonDocument("{\"x\":[[{}]]}", limits);
    });
    limits = {};
    limits.ContainerItems = 2;
    JsonDocument("{\"x\":[{},{}]}", limits);
    Rejects([&]()
    {
        JsonDocument("{\"x\":[{},{},{}]}", limits);
    });
    limits = {};
    limits.Values = 3;
    JsonDocument("{\"x\":[{}]}", limits);
    Rejects([&]()
    {
        JsonDocument("{\"x\":[{},{}]}", limits);
    });
    limits = {};
    limits.StringBytes = 4;
    JsonDocument(R"({"x":"\ud83d\ude00"})", limits);
    Rejects([&]()
    {
        JsonDocument(R"({"x":"\ud83d\ude00a"})", limits);
    });
    limits = {};
    limits.DocumentBytes = 2;
    JsonDocument("{}", limits);
    Rejects([&]()
    {
        JsonDocument("{} ", limits);
    });
}
}

int main(int argc, char** argv)
{
    int result = 0;
    try
    {
        if (argc == 2 && std::string_view(argv[1]) == "--probe")
        {
            RunProbe();
        }
        else
        {
            RunTests();
            std::cout << "Bounded JSON tests passed.\n";
        }
    }
    catch (const std::exception& exception)
    {
        std::cerr << exception.what() << '\n';
        result = 1;
    }
    return result;
}
