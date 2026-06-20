using System.Collections.Immutable;
using System.IO.Compression;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace KnMon.WinmdDump;

internal static class Program
{
    private static int Main(string[] args)
    {
        var exitCode = 1;

        do
        {
            if (args.Length != 1)
            {
                Console.Error.WriteLine("Usage: KnMon.WinmdDump <Windows.Win32.winmd>");
                break;
            }

            var inputPath = args[0];
            if (!File.Exists(inputPath))
            {
                Console.Error.WriteLine($"WinMD input not found: {inputPath}");
                break;
            }

            try
            {
                var dump = DumpWinmd(inputPath);
                var options = new JsonSerializerOptions
                {
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    WriteIndented = true
                };

                Console.WriteLine(JsonSerializer.Serialize(dump, options));
                exitCode = 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
            }
        } while (false);

        return exitCode;
    }

    private static WinmdDump DumpWinmd(string inputPath)
    {
        var input = OpenWinmdInput(inputPath);
        using var stream = input.Stream;
        using var peReader = new PEReader(stream);
        var reader = peReader.GetMetadataReader();
        var provider = new SignatureTextProvider(reader);
        var methods = new List<WinmdMethod>();

        foreach (var typeHandle in reader.TypeDefinitions)
        {
            var type = reader.GetTypeDefinition(typeHandle);
            var namespaceName = reader.GetString(type.Namespace);
            var typeName = reader.GetString(type.Name);

            if (!namespaceName.StartsWith("Windows.Win32", StringComparison.Ordinal))
            {
                continue;
            }

            foreach (var methodHandle in type.GetMethods())
            {
                var method = reader.GetMethodDefinition(methodHandle);
                var methodName = reader.GetString(method.Name);

                if (!IsPublicStaticExtern(method))
                {
                    continue;
                }

                var import = TryGetImport(reader, method);
                if (import is null)
                {
                    continue;
                }

                var signature = method.DecodeSignature(provider, null);
                var parameters = ReadParameters(reader, method, signature);
                var attributes = ReadAttributes(reader, method.GetCustomAttributes());
                methods.Add(new WinmdMethod
                {
                    Namespace = namespaceName,
                    Type = typeName,
                    Name = methodName,
                    EntryPoint = import.EntryPoint,
                    Module = import.Module,
                    ImportAttributes = import.Attributes,
                    CallingConvention = CallingConventionFromImport(import.Attributes),
                    ReturnType = signature.ReturnType,
                    Parameters = parameters,
                    Attributes = attributes
                });
            }
        }

        methods.Sort((left, right) =>
        {
            var moduleCompare = string.Compare(left.Module, right.Module, StringComparison.OrdinalIgnoreCase);
            if (moduleCompare != 0)
            {
                return moduleCompare;
            }

            return string.Compare(left.Name, right.Name, StringComparison.Ordinal);
        });

        return new WinmdDump
        {
            SchemaVersion = "0.1.0",
            Source = input.Source,
            MethodCount = methods.Count,
            Methods = methods
        };
    }

    private static WinmdInput OpenWinmdInput(string inputPath)
    {
        var extension = Path.GetExtension(inputPath);
        if (extension.Equals(".winmd", StringComparison.OrdinalIgnoreCase))
        {
            return new WinmdInput
            {
                Source = Path.GetFileName(inputPath),
                Stream = File.OpenRead(inputPath)
            };
        }

        if (!extension.Equals(".nupkg", StringComparison.OrdinalIgnoreCase) &&
            !extension.Equals(".zip", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Input must be a .winmd, .nupkg, or .zip file.");
        }

        using var archive = ZipFile.OpenRead(inputPath);
        var entry = archive.Entries.FirstOrDefault(item => item.FullName.Equals("Windows.Win32.winmd", StringComparison.OrdinalIgnoreCase));
        if (entry is null)
        {
            throw new InvalidOperationException("Windows.Win32.winmd was not found in the package.");
        }

        var memory = new MemoryStream();
        using (var entryStream = entry.Open())
        {
            entryStream.CopyTo(memory);
        }

        memory.Position = 0;
        return new WinmdInput
        {
            Source = $"{Path.GetFileName(inputPath)}!Windows.Win32.winmd",
            Stream = memory
        };
    }

    private static bool IsPublicStaticExtern(MethodDefinition method)
    {
        var attributes = method.Attributes;
        return (attributes & MethodAttributes.Public) != 0 &&
            (attributes & MethodAttributes.Static) != 0 &&
            (attributes & MethodAttributes.PinvokeImpl) != 0;
    }

    private static WinmdImport? TryGetImport(MetadataReader reader, MethodDefinition method)
    {
        if ((method.Attributes & MethodAttributes.PinvokeImpl) == 0)
        {
            return null;
        }

        var import = method.GetImport();
        if (import.Module.IsNil)
        {
            return null;
        }

        var moduleReference = reader.GetModuleReference(import.Module);
        return new WinmdImport
        {
            EntryPoint = reader.GetString(import.Name),
            Module = reader.GetString(moduleReference.Name),
            Attributes = import.Attributes.ToString()
        };
    }

    private static string CallingConventionFromImport(string attributes)
    {
        if (attributes.Contains("CallingConventionCDecl", StringComparison.Ordinal))
        {
            return "cdecl";
        }

        if (attributes.Contains("CallingConventionStdCall", StringComparison.Ordinal))
        {
            return "stdcall";
        }

        if (attributes.Contains("CallingConventionThisCall", StringComparison.Ordinal))
        {
            return "thiscall";
        }

        if (attributes.Contains("CallingConventionFastCall", StringComparison.Ordinal))
        {
            return "fastcall";
        }

        return "winapi";
    }

    private static IReadOnlyList<WinmdParameter> ReadParameters(
        MetadataReader reader,
        MethodDefinition method,
        MethodSignature<string> signature)
    {
        var metadataParameters = method.GetParameters()
            .Select(reader.GetParameter)
            .Where(parameter => parameter.SequenceNumber > 0)
            .OrderBy(parameter => parameter.SequenceNumber)
            .ToList();
        var parameters = new List<WinmdParameter>();

        for (var index = 0; index < metadataParameters.Count; index++)
        {
            var parameter = metadataParameters[index];
            var type = index < signature.ParameterTypes.Length ? signature.ParameterTypes[index] : "unknown";
            parameters.Add(new WinmdParameter
            {
                Name = reader.GetString(parameter.Name),
                Type = type,
                Direction = DirectionFromParameter(parameter.Attributes, type),
                Attributes = parameter.Attributes.ToString()
            });
        }

        return parameters;
    }

    private static string DirectionFromParameter(ParameterAttributes attributes, string type)
    {
        if ((attributes & ParameterAttributes.Out) != 0 && (attributes & ParameterAttributes.In) != 0)
        {
            return "inout";
        }

        if ((attributes & ParameterAttributes.Out) != 0)
        {
            return "out";
        }

        if (type.EndsWith("*", StringComparison.Ordinal) || type.EndsWith("&", StringComparison.Ordinal))
        {
            return "inout";
        }

        return "in";
    }

    private static IReadOnlyList<WinmdAttribute> ReadAttributes(MetadataReader reader, CustomAttributeHandleCollection handles)
    {
        var attributes = new List<WinmdAttribute>();

        foreach (var handle in handles)
        {
            var attribute = reader.GetCustomAttribute(handle);
            attributes.Add(new WinmdAttribute
            {
                Name = AttributeName(reader, attribute.Constructor),
                Strings = ReadSerializedStrings(reader.GetBlobBytes(attribute.Value))
            });
        }

        attributes.Sort((left, right) => string.Compare(left.Name, right.Name, StringComparison.Ordinal));
        return attributes;
    }

    private static string AttributeName(MetadataReader reader, EntityHandle constructor)
    {
        EntityHandle typeHandle = default;

        if (constructor.Kind == HandleKind.MemberReference)
        {
            var memberReference = reader.GetMemberReference((MemberReferenceHandle)constructor);
            typeHandle = memberReference.Parent;
        }
        else if (constructor.Kind == HandleKind.MethodDefinition)
        {
            var method = reader.GetMethodDefinition((MethodDefinitionHandle)constructor);
            typeHandle = method.GetDeclaringType();
        }

        if (typeHandle.Kind == HandleKind.TypeReference)
        {
            var type = reader.GetTypeReference((TypeReferenceHandle)typeHandle);
            return $"{reader.GetString(type.Namespace)}.{reader.GetString(type.Name)}";
        }

        if (typeHandle.Kind == HandleKind.TypeDefinition)
        {
            var type = reader.GetTypeDefinition((TypeDefinitionHandle)typeHandle);
            return $"{reader.GetString(type.Namespace)}.{reader.GetString(type.Name)}";
        }

        return typeHandle.Kind.ToString();
    }

    private static IReadOnlyList<string> ReadSerializedStrings(byte[] blob)
    {
        var strings = new List<string>();

        for (var offset = 2; offset < blob.Length; offset++)
        {
            var length = TryReadSerStringLength(blob, offset, out var lengthBytes);
            if (length < 0)
            {
                continue;
            }

            var start = offset + lengthBytes;
            if (start < 0 || start + length > blob.Length)
            {
                continue;
            }

            if (length == 0)
            {
                strings.Add(string.Empty);
                continue;
            }

            var value = System.Text.Encoding.UTF8.GetString(blob, start, length);
            if (IsUsefulSerializedString(value))
            {
                strings.Add(value);
            }
        }

        return strings.Distinct(StringComparer.Ordinal).ToArray();
    }

    private static int TryReadSerStringLength(byte[] blob, int offset, out int lengthBytes)
    {
        lengthBytes = 0;

        if (offset >= blob.Length)
        {
            return -1;
        }

        var first = blob[offset];
        if (first == 0xff)
        {
            lengthBytes = 1;
            return 0;
        }

        if ((first & 0x80) == 0)
        {
            lengthBytes = 1;
            return first;
        }

        if ((first & 0xc0) == 0x80)
        {
            if (offset + 1 >= blob.Length)
            {
                return -1;
            }

            lengthBytes = 2;
            return ((first & 0x3f) << 8) | blob[offset + 1];
        }

        if ((first & 0xe0) == 0xc0)
        {
            if (offset + 3 >= blob.Length)
            {
                return -1;
            }

            lengthBytes = 4;
            return ((first & 0x1f) << 24) | (blob[offset + 1] << 16) | (blob[offset + 2] << 8) | blob[offset + 3];
        }

        return -1;
    }

    private static bool IsUsefulSerializedString(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (!value.All(character => character >= 0x20 && character < 0x7f))
        {
            return false;
        }

        if (value.StartsWith("https://learn.microsoft.com/", StringComparison.Ordinal))
        {
            return true;
        }

        if (value.StartsWith("windows", StringComparison.OrdinalIgnoreCase) &&
            value.Length > "windows".Length &&
            char.IsDigit(value["windows".Length]))
        {
            return true;
        }

        return false;
    }
}

internal sealed record WinmdInput
{
    public required string Source { get; init; }

    public required Stream Stream { get; init; }
}

internal sealed class SignatureTextProvider : ISignatureTypeProvider<string, object?>
{
    private readonly MetadataReader _reader;

    public SignatureTextProvider(MetadataReader reader)
    {
        _reader = reader;
    }

    public string GetArrayType(string elementType, ArrayShape shape)
    {
        return $"{elementType}[]";
    }

    public string GetByReferenceType(string elementType)
    {
        return $"{elementType}&";
    }

    public string GetFunctionPointerType(MethodSignature<string> signature)
    {
        return "function_pointer";
    }

    public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments)
    {
        return $"{genericType}<{string.Join(",", typeArguments)}>";
    }

    public string GetGenericMethodParameter(object? genericContext, int index)
    {
        return $"!!{index}";
    }

    public string GetGenericTypeParameter(object? genericContext, int index)
    {
        return $"!{index}";
    }

    public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired)
    {
        return unmodifiedType;
    }

    public string GetPinnedType(string elementType)
    {
        return elementType;
    }

    public string GetPointerType(string elementType)
    {
        return $"{elementType}*";
    }

    public string GetPrimitiveType(PrimitiveTypeCode typeCode)
    {
        return typeCode switch
        {
            PrimitiveTypeCode.Boolean => "BOOL",
            PrimitiveTypeCode.Byte => "BYTE",
            PrimitiveTypeCode.Char => "WCHAR",
            PrimitiveTypeCode.Double => "DOUBLE",
            PrimitiveTypeCode.Int16 => "SHORT",
            PrimitiveTypeCode.Int32 => "INT",
            PrimitiveTypeCode.Int64 => "INT64",
            PrimitiveTypeCode.IntPtr => "INT_PTR",
            PrimitiveTypeCode.Object => "object",
            PrimitiveTypeCode.SByte => "CHAR",
            PrimitiveTypeCode.Single => "FLOAT",
            PrimitiveTypeCode.String => "PCWSTR",
            PrimitiveTypeCode.UInt16 => "USHORT",
            PrimitiveTypeCode.UInt32 => "UINT",
            PrimitiveTypeCode.UInt64 => "UINT64",
            PrimitiveTypeCode.UIntPtr => "UINT_PTR",
            PrimitiveTypeCode.Void => "void",
            _ => typeCode.ToString()
        };
    }

    public string GetSZArrayType(string elementType)
    {
        return $"{elementType}[]";
    }

    public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind)
    {
        var type = reader.GetTypeDefinition(handle);
        return TypeName(reader.GetString(type.Namespace), reader.GetString(type.Name));
    }

    public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind)
    {
        var type = reader.GetTypeReference(handle);
        return TypeName(reader.GetString(type.Namespace), reader.GetString(type.Name));
    }

    public string GetTypeFromSpecification(MetadataReader reader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind)
    {
        var specification = reader.GetTypeSpecification(handle);
        return specification.DecodeSignature(this, genericContext);
    }

    private static string TypeName(string namespaceName, string typeName)
    {
        if (namespaceName.StartsWith("Windows.Win32.Foundation", StringComparison.Ordinal))
        {
            return typeName;
        }

        if (namespaceName.StartsWith("Windows.Win32", StringComparison.Ordinal))
        {
            return typeName;
        }

        return string.IsNullOrEmpty(namespaceName) ? typeName : $"{namespaceName}.{typeName}";
    }
}

internal sealed record WinmdDump
{
    public required string SchemaVersion { get; init; }

    public required string Source { get; init; }

    public required int MethodCount { get; init; }

    public required IReadOnlyList<WinmdMethod> Methods { get; init; }
}

internal sealed record WinmdImport
{
    public required string EntryPoint { get; init; }

    public required string Module { get; init; }

    public required string Attributes { get; init; }
}

internal sealed record WinmdMethod
{
    public required string Namespace { get; init; }

    public required string Type { get; init; }

    public required string Name { get; init; }

    public required string EntryPoint { get; init; }

    public required string Module { get; init; }

    public required string ImportAttributes { get; init; }

    public required string CallingConvention { get; init; }

    public required string ReturnType { get; init; }

    public required IReadOnlyList<WinmdParameter> Parameters { get; init; }

    public required IReadOnlyList<WinmdAttribute> Attributes { get; init; }
}

internal sealed record WinmdParameter
{
    public required string Name { get; init; }

    public required string Type { get; init; }

    public required string Direction { get; init; }

    public required string Attributes { get; init; }
}

internal sealed record WinmdAttribute
{
    public required string Name { get; init; }

    public required IReadOnlyList<string> Strings { get; init; }
}
