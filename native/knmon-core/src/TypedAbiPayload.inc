std::string TypedValueText(TypedValueKind kind, std::uint64_t bits, const std::string& architecture,
    const std::uint8_t* aggregate = nullptr)
{
    std::ostringstream text;
    switch (kind)
    {
    case TypedValueKind::Void:
        text << "void";
        break;
    case TypedValueKind::Float32:
    {
        const std::uint32_t raw = static_cast<std::uint32_t>(bits);
        float value = 0;
        std::memcpy(&value, &raw, sizeof(value));
        text << std::setprecision(9) << value;
        break;
    }
    case TypedValueKind::Float64:
    {
        double value = 0;
        std::memcpy(&value, &bits, sizeof(value));
        text << std::setprecision(17) << value;
        break;
    }
    case TypedValueKind::Point2F:
        text << "{" << TypedValueText(TypedValueKind::Float32, bits, architecture) << ", "
             << TypedValueText(TypedValueKind::Float32, bits >> 32, architecture) << "}";
        break;
    case TypedValueKind::Color4F:
        text << "{";
        for (std::size_t index = 0; aggregate != nullptr && index < 4; ++index)
        {
            std::uint32_t raw = 0;
            std::memcpy(&raw, aggregate + index * sizeof(raw), sizeof(raw));
            text << (index == 0 ? "" : ", ") << TypedValueText(TypedValueKind::Float32, raw, architecture);
        }
        text << "}";
        break;
    case TypedValueKind::Pointer:
        text << HexPointerValue(bits, architecture);
        break;
    case TypedValueKind::Signed32:
        text << static_cast<std::int32_t>(bits);
        break;
    case TypedValueKind::SignedPointer:
        text << (architecture == "x86" ? static_cast<std::int64_t>(static_cast<std::int32_t>(bits)) :
            static_cast<std::int64_t>(bits));
        break;
    default:
        text << static_cast<std::uint32_t>(bits);
        break;
    }
    return text.str();
}

std::string TypedTransportApiPayload(const KnMonCaptureResult& result, const KnMonTransportRecord& record)
{
    const auto* contract = FindTypedAbi(record.ApiId);
    if (contract == nullptr || (record.Detail == CaptureDetail::Metadata ? 0u : contract->ArgumentCount) != record.Values32[0])
    {
        throw JsonInputError("Unknown typed ABI record.");
    }
    std::ostringstream arguments;
    for (std::uint32_t index = 0; index < record.Values32[0]; ++index)
    {
        const auto* parameter = FindGeneratedParameterMetadata(record.ApiId, static_cast<std::uint16_t>(index));
        if (parameter == nullptr)
        {
            throw JsonInputError("Typed ABI parameter metadata missing.");
        }
        const auto kind = contract->Arguments[index];
        const bool pointer = kind == TypedValueKind::Pointer;
        const bool pointerWidth = pointer || kind == TypedValueKind::SignedPointer;
        const std::uint32_t width = kind == TypedValueKind::Float64 || kind == TypedValueKind::Point2F ||
            (pointerWidth && result.Architecture == "x64") ? 64 : 32;
        std::ostringstream raw;
        raw << "0x" << std::hex << std::setfill('0') << std::setw(width / 4) << record.Values64[index];
        const char* encoding = kind == TypedValueKind::Float32 ? "ieee754_binary32" :
            kind == TypedValueKind::Float64 ? "ieee754_binary64" :
            kind == TypedValueKind::Point2F ? "two_binary32_little_endian" : "unsigned_bits";
        if (index != 0)
        {
            arguments << ",";
        }
        arguments << "{\"index\":" << index << ",\"type\":" << Q(std::string(parameter->Type))
            << ",\"name\":" << Q(std::string(parameter->Name)) << ",\"direction\":" << Q(std::string(parameter->Direction))
            << ",\"rawValue\":" << Q(raw.str()) << ",\"preCallValue\":" << Q(raw.str())
            << ",\"postCallValue\":" << Q(pointer ? "" : raw.str())
            << ",\"decodedValue\":" << Q(TypedValueText(kind, record.Values64[index], result.Architecture))
            << ",\"decodeStatus\":" << Q(pointer ? "not_captured" : "decoded")
            << ",\"targetMemoryRead\":false,\"payloadPolicy\":" << Q(pointer ? "pointer_value_only" : "value")
            << ",\"valueEncoding\":" << Q(encoding) << ",\"valueBits\":" << width
            << ",\"valuePhase\":\"entry\"}";
    }
    return ApiCallPayload(result, record,
        TypedValueText(contract->ReturnKind, record.RawReturnValue, result.Architecture, record.RawReturnBytes),
        arguments.str(), "");
}
