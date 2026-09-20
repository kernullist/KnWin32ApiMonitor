template <typename T>
std::uint64_t TypedArgumentBits(const T& value) noexcept
{
    static_assert(sizeof(T) <= sizeof(std::uint64_t));
    std::uint64_t bits = 0;
    if constexpr (std::is_pointer_v<T>)
    {
        bits = reinterpret_cast<std::uintptr_t>(value);
    }
    else
    {
        static_assert(std::is_scalar_v<T> || std::is_same_v<T, D2D1_POINT_2F>);
        std::memcpy(&bits, &value, sizeof(value));
    }
    return bits;
}

template <std::uint16_t Id, typename Function, typename... Arguments>
auto InvokeTypedApi(Function original, const Arguments&... arguments) -> std::invoke_result_t<Function, Arguments...>
{
    using Result = std::invoke_result_t<Function, Arguments...>;
    if (original == nullptr)
    {
        SetLastError(ERROR_PROC_NOT_FOUND);
        if constexpr (std::is_void_v<Result>)
        {
            return;
        }
        else
        {
            return Result{};
        }
    }
    if (g_inHook || !HooksEnabled())
    {
        return original(arguments...);
    }
    HookReentryGuard guard;
    const std::array<std::uint64_t, sizeof...(Arguments)> values{TypedArgumentBits(arguments)...};
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const auto emit = [&]()
    {
        QueryPerformanceCounter(&end);
        if (HooksEnabled())
        {
            LARGE_INTEGER overhead = {};
            QueryPerformanceCounter(&overhead);
            EmitTransportRecord(overhead, [&](knmon::KnMonTransportRecord* record)
            {
                const auto* metadata = knmon::FindTypedAbi(Id);
                FillTransportCommon(record, static_cast<knmon::KnMonTransportApiId>(Id), metadata->Module, start, end, 0);
                record->Flags = knmon::KnMonTransportRecordFlagTypedAbi;
                record->ReturnValue = record->RawReturnValue;
                record->Values32[0] = static_cast<std::uint32_t>(values.size());
                std::copy(values.begin(), values.end(), record->Values64);
            });
        }
    };
    if constexpr (std::is_void_v<Result>)
    {
        guard.Call([&]()
        {
            original(arguments...);
        });
        emit();
    }
    else
    {
        const Result result = guard.Call([&]()
        {
            return original(arguments...);
        });
        emit();
        return result;
    }
}

#include "GeneratedTypedHooks.inc"
