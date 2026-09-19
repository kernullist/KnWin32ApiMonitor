#pragma once

#include <knmon/common/GeneratedRuntimeSupport.h>
#include <knmon/common/AttachConfig.h>

#include <algorithm>
#include <string>
#include <string_view>

namespace knmon
{
inline constexpr bool RuntimeArchitectureSupported()
{
#if defined(_M_ARM64EC) || defined(_M_ARM64) || defined(__aarch64__)
    return false;
#elif defined(_M_X64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__)
    return true;
#else
    return false;
#endif
}

inline std::string NormalizeRuntimeApiKey(std::string_view value)
{
    std::string result(value);
    for (char& ch : result)
    {
        if (ch >= 'A' && ch <= 'Z')
        {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return result;
}

inline bool RuntimeApiSupported(std::string_view module, std::string_view api)
{
    const std::string key = NormalizeRuntimeApiKey(module) + "!" + NormalizeRuntimeApiKey(api);
    return RuntimeArchitectureSupported() &&
        std::binary_search(RuntimeSupportedApiKeys.begin(), RuntimeSupportedApiKeys.end(), key);
}

// Module selectors select only the supported subset. Explicit unsafe APIs fail.
inline bool ValidateRuntimeApiSelection(std::string_view selection, std::string& rejected)
{
    bool valid = true;
    bool foundToken = false;
    std::size_t offset = 0;
    rejected.clear();
    if (!RuntimeArchitectureSupported() || selection.size() >= KnMonAttachConfigSelectedApisChars)
    {
        rejected = !RuntimeArchitectureSupported() ? "unsupported_architecture" : "selection_too_long";
        valid = false;
    }
    while (valid && offset < selection.size())
    {
        const std::size_t begin = selection.find_first_not_of(",; \t\r\n", offset);
        if (begin == std::string_view::npos)
        {
            if (!foundToken)
            {
                rejected = "empty_selection_token";
                valid = false;
            }
            break;
        }
        const std::size_t end = selection.find_first_of(",; \t\r\n", begin);
        const std::string token = NormalizeRuntimeApiKey(selection.substr(begin, end - begin));
        const std::size_t separator = token.find('!');
        const bool moduleSelector = separator == std::string::npos || token.substr(separator) == "!*";
        bool supported = false;
        if (moduleSelector)
        {
            const std::string prefix = token.substr(0, separator) + "!";
            const auto candidate = std::lower_bound(RuntimeSupportedApiKeys.begin(), RuntimeSupportedApiKeys.end(), prefix);
            supported = candidate != RuntimeSupportedApiKeys.end() && candidate->starts_with(prefix);
        }
        else
        {
            supported = std::binary_search(RuntimeSupportedApiKeys.begin(), RuntimeSupportedApiKeys.end(), token);
        }
        if (!supported)
        {
            rejected = token;
            valid = false;
            break;
        }
        if (end == std::string_view::npos)
        {
            break;
        }
        offset = end + 1;
        foundToken = true;
    }
    return valid;
}
}
