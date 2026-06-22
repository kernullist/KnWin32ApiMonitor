export const maxGeneratedGenericArguments = 16;

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
  return text.includes("*") || text.includes("&") || /\b(lp|p)[a-z0-9_]+/.test(text);
}

export function unsafeGeneratedGenericAbiType(type)
{
  const text = String(type ?? "").toLowerCase();
  if (pointerLikeType(text))
  {
    return false;
  }

  return /\b(float|double|single)\b/.test(text) ||
    (text.startsWith("struct ") && !text.includes("*"));
}

export function generatedGenericAbiSafetyReasons(api, parameters = [], options = {})
{
  const reasons = [];
  const maxArguments = options.maxArguments ?? maxGeneratedGenericArguments;
  const checkRuntimePolicy = options.checkRuntimePolicy ?? true;
  const checkCallingConvention = options.checkCallingConvention ?? true;
  const parameterCount = Number.isInteger(api?.parameterCount) ? api.parameterCount : parameters.length;

  if (checkRuntimePolicy && !isRuntimeMonitorableDefinition(api))
  {
    reasons.push("not_runtime_monitorable");
  }

  if (parameterCount > maxArguments)
  {
    reasons.push("too_many_arguments");
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
