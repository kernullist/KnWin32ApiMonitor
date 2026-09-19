export const maxGeneratedGenericArguments = 17;

const generatedGenericCallingConventions = new Set([
  "stdcall",
  "winapi",
  "ntapi",
  "cdecl"
]);

export function isRuntimeMonitorableDefinition(api)
{
  return api?.hookPolicy !== "definition_only" &&
    api?.hookPolicy !== "unsupported" &&
    api?.coverageStatus !== "unsupported";
}

export function runtimeHookPolicy(api)
{
  if (api?.hookPolicy === "iat")
  {
    return "iat";
  }

  return "generated_iat";
}

export function runtimeCoverageStatus(api)
{
  if (api?.coverageStatus === "smoke_verified" || api?.coverageStatus === "hooked")
  {
    return api.coverageStatus;
  }

  return "generated_generic";
}

export function pointerLikeType(type)
{
  const text = String(type ?? "").toLowerCase();
  return text.includes("*") || text.includes("&");
}

export function unsafeGeneratedGenericAbiType(type)
{
  const text = String(type ?? "").toLowerCase();
  if (pointerLikeType(text))
  {
    return false;
  }

  // Unknown typedefs must not be inferred from spelling or pointer-like prefixes.
  return !/^(void|bool|boolean|winbool|byte|char|short|int|long|word|dword|qword|uint|ulong|ushort|uint32_t|int32_t|uint64_t|int64_t|uintptr_t|intptr_t|size_t|ssize_t|ulong_ptr|long_ptr|dword_ptr|hresult|ntstatus)$/.test(text.trim());
}

export function generatedGenericAbiSafetyReasons(api, parameters = [], options = {})
{
  // A metadata declaration is not a compiler-checked wrapper contract. The old
  // integer dispatcher cannot prove variadic, typedef, or aggregate semantics.
  // Keep it unavailable until a typed generator and differential evidence exist.
  const reasons = ["unverified_generated_abi"];
  const maxArguments = options.maxArguments ?? maxGeneratedGenericArguments;
  const checkRuntimePolicy = options.checkRuntimePolicy ?? true;
  const checkCallingConvention = options.checkCallingConvention ?? true;
  const parameterCount = api?.parameterCount ?? parameters.length;

  if (checkRuntimePolicy && !isRuntimeMonitorableDefinition(api))
  {
    reasons.push("not_runtime_monitorable");
  }

  if (!Number.isInteger(parameterCount) || parameterCount < 0 || parameterCount !== parameters.length)
  {
    reasons.push("invalid_parameter_count");
  }

  if (parameterCount > maxArguments)
  {
    reasons.push("too_many_arguments");
  }

  if (api?.isVariadic === true || api?.variadic === true ||
    parameters.some((parameter) => parameter.type === "..." || parameter.name === "...") ||
    /^(wsprintf[aw]|dbgprint|dbgprintex|sprintf|swprintf|printf)$/i.test(String(api?.name ?? "")))
  {
    reasons.push("variadic_prototype");
  }

  if (/opaque\s+16-slot/i.test(String(api?.minWindowsVersion ?? "")))
  {
    reasons.push("unresolved_prototype");
  }

  if (unsafeGeneratedGenericAbiType(api?.returnType))
  {
    reasons.push("unsafe_return_abi_type");
  }

  if (checkCallingConvention)
  {
    const callingConvention = String(api?.callingConvention ?? "").toLowerCase();
    if (!generatedGenericCallingConventions.has(callingConvention))
    {
      reasons.push("unsupported_calling_convention");
    }
  }

  for (const parameter of parameters)
  {
    if (unsafeGeneratedGenericAbiType(parameter.type))
    {
      reasons.push(`unsafe_parameter_abi_type:${parameter.name ?? ""}`);
    }
  }

  return Array.from(new Set(reasons));
}

export function isGeneratedGenericAbiSafe(api, parameters = [], options = {})
{
  return generatedGenericAbiSafetyReasons(api, parameters, options).length === 0;
}

export function generatedReturnFormat(returnType)
{
  const text = String(returnType ?? "").toLowerCase();
  if (text === "" || text === "void")
  {
    return "Void";
  }

  if (text === "bool" || text === "boolean" || text === "winbool")
  {
    return "Bool";
  }

  if (text === "double")
  {
    return "Double";
  }

  if (
    text.includes("*") ||
    text.includes("handle") ||
    text === "hmodule" ||
    text === "hwnd" ||
    text === "hkey" ||
    text === "hmenu" ||
    text === "hcursor" ||
    text === "hicon" ||
    text === "hdc" ||
    text === "sc_handle" ||
    text === "socket" ||
    text === "bstr" ||
    text === "hstring" ||
    text.startsWith("p"))
  {
    return "Pointer";
  }

  if (
    text.includes("64") ||
    text.includes("ptr") ||
    text === "size_t" ||
    text === "ssize_t" ||
    text === "ulong_ptr" ||
    text === "long_ptr" ||
    text === "dword_ptr")
  {
    return "UInt64";
  }

  return "UInt32";
}

export function generatedErrorSource(errorSourceText)
{
  const text = String(errorSourceText ?? "").toLowerCase();
  if (text === "getlasterror")
  {
    return "GetLastError";
  }

  if (text === "return_ntstatus")
  {
    return "ReturnNtStatus";
  }

  if (text === "hresult")
  {
    return "ReturnHResult";
  }

  if (text === "return_win32" || text === "return_rpc_status")
  {
    return "ReturnWin32";
  }

  return "None";
}
