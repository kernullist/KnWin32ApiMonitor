import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..", "..");
const decoderTablePath = path.join(repoRoot, "generated", "definition-decoder-tables.json");
const agentSourcePath = path.join(repoRoot, "native", "knmon-agent64", "src", "AgentMain.cpp");
const generatedHookPath = path.join(repoRoot, "native", "knmon-agent64", "src", "GeneratedAgentHooks.inc");
const generatedHookSourceDirectory = path.join(repoRoot, "native", "knmon-agent64", "src");
const hookDefinitionChunkSize = 128;
const hookSourceChunkSize = 512;

function readJson(filePath)
{
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function cppString(value)
{
  return JSON.stringify(String(value ?? ""));
}

function symbolName(value)
{
  return String(value ?? "")
    .replace(/[^A-Za-z0-9_]/g, "_")
    .replace(/^([0-9])/, "_$1");
}

function lowerKey(moduleName, apiName)
{
  return `${String(moduleName ?? "").toLowerCase()}!${String(apiName ?? "").toLowerCase()}`;
}

function manualHookKeys()
{
  const source = fs.readFileSync(agentSourcePath, "utf8");
  const keys = new Set();
  const pattern = /HookDefinition\s*\{\s*"([^"]+)",\s*"([^"]+)"/g;
  let match = pattern.exec(source);
  while (match !== null)
  {
    keys.add(lowerKey(match[1], match[2]));
    match = pattern.exec(source);
  }

  return keys;
}

function unsafeScalarType(type)
{
  const text = String(type ?? "").toLowerCase();
  if (pointerLikeType(text))
  {
    return false;
  }

  if (/\b(float|double|single)\b/.test(text))
  {
    return true;
  }

  if (text.startsWith("struct ") && !text.includes("*"))
  {
    return true;
  }

  return false;
}

function pointerLikeType(text)
{
  return text.includes("*") || text.includes("&") || /\b(lp|p)[a-z0-9_]+/.test(text);
}

function returnFormat(returnType)
{
  const text = String(returnType ?? "").toLowerCase();
  if (text === "" || text === "void")
  {
    return "Void";
  }

  if (text === "bool" || text === "boolean" || text === "bool" || text === "winbool")
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

function errorSource(errorSourceText)
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

function runtimeHookPolicy(api)
{
  if (api.hookPolicy === "iat")
  {
    return "iat";
  }

  return "generated_iat";
}

function runtimeCoverageStatus(api)
{
  if (api.coverageStatus === "smoke_verified" || api.coverageStatus === "hooked")
  {
    return api.coverageStatus;
  }

  return "generated_generic";
}

function isGenericSafe(api, parametersByApi)
{
  if (!isRuntimeInstallable(api))
  {
    return false;
  }

  if (api.parameterCount > 16)
  {
    return false;
  }

  if (unsafeScalarType(api.returnType))
  {
    return false;
  }

  const callingConvention = String(api.callingConvention ?? "").toLowerCase();
  if (!["stdcall", "winapi", "ntapi", "cdecl"].includes(callingConvention))
  {
    return false;
  }

  const parameters = parametersByApi.get(api.id) ?? [];
  return parameters.every((parameter) => !unsafeScalarType(parameter.type));
}

function isRuntimeInstallable(api)
{
  return api.hookPolicy !== "unsupported" && api.hookPolicy !== "definition_only" && api.coverageStatus !== "unsupported";
}

function functionSignaturePrefix(api)
{
  if (returnFormat(api.returnType) === "Void")
  {
    return "void WINAPI";
  }

  return "std::uintptr_t WINAPI";
}

function functionPointerTypeName(api)
{
  const prefix = returnFormat(api.returnType) === "Void" ? "GeneratedAgentVoidFunction" : "GeneratedAgentValueFunction";
  return `${prefix}_${api.parameterCount}`;
}

function argumentList(count)
{
  const args = [];
  for (let index = 0; index < count; ++index)
  {
    args.push(`std::uintptr_t arg${index}`);
  }

  return args.join(", ");
}

function argumentNames(count)
{
  const args = [];
  for (let index = 0; index < count; ++index)
  {
    args.push(`arg${index}`);
  }

  return args.join(", ");
}

function paddedArgumentNames(count)
{
  const args = [];
  for (let index = 0; index < 16; ++index)
  {
    args.push(index < count ? `arg${index}` : "0");
  }

  return args.join(", ");
}

function generatedHookName(hook)
{
  return `HookedGeneratedApi${hook.id}_${symbolName(hook.name)}`;
}

function generatedHookChunkPath(index)
{
  return path.join(generatedHookSourceDirectory, `GeneratedAgentHooksChunk${index}.cpp`);
}

function buildHookFile(hooks, coverage, modules, hookable)
{
  const lines = [];
  lines.push("// Generated by tools/def-validator/generate-agent-hook-definitions.mjs. Do not edit manually.");
  lines.push("#pragma once");
  lines.push("");
  lines.push("#if defined(_WIN64)");
  lines.push(`inline constexpr std::size_t GeneratedAgentHookDefinitionCount = ${hooks.length};`);
  lines.push(`inline constexpr std::size_t GeneratedAgentHookCoveredApiCount = ${coverage.covered};`);
  lines.push(`inline constexpr std::size_t GeneratedAgentHookRequiredApiCount = ${coverage.required};`);
  lines.push(`void* g_generatedAgentOriginalFunctions[${hooks.length === 0 ? 1 : hooks.length}] = {};`);
  lines.push("");

  for (let count = 0; count <= 16; ++count)
  {
    const args = Array.from({ length: count }, () => "std::uintptr_t").join(", ");
    lines.push(`using GeneratedAgentValueFunction_${count} = std::uintptr_t(WINAPI*)(${args});`);
    lines.push(`using GeneratedAgentVoidFunction_${count} = void(WINAPI*)(${args});`);
  }

  lines.push("");
  lines.push("struct GeneratedAgentModuleMetadata");
  lines.push("{");
  lines.push("    std::uint16_t Id = 0;");
  lines.push("    const char* Name = \"\";");
  lines.push("};");
  lines.push("");
  lines.push("struct GeneratedAgentResolverMetadata");
  lines.push("{");
  lines.push("    std::uint16_t Id = 0;");
  lines.push("    const char* ModuleName = \"\";");
  lines.push("    const char* Name = \"\";");
  lines.push("    const char* HookPolicy = \"\";");
  lines.push("    const char* CoverageStatus = \"\";");
  lines.push("};");
  lines.push("");
  lines.push(`inline const std::array<GeneratedAgentModuleMetadata, ${modules.length}> GeneratedAgentModules =`);
  lines.push("{{");
  for (const module of modules)
  {
    lines.push(`    { ${module.id}, ${cppString(module.name)} },`);
  }
  lines.push("}};");
  lines.push("");
  lines.push(`inline const std::array<GeneratedAgentResolverMetadata, ${hookable.length}> GeneratedAgentResolverMetadataTable =`);
  lines.push("{{");
  for (const api of hookable)
  {
    lines.push(`    { ${api.id}, ${cppString(api.module)}, ${cppString(api.name)}, ${cppString(runtimeHookPolicy(api))}, ${cppString(runtimeCoverageStatus(api))} },`);
  }
  lines.push("}};");
  lines.push("");

  lines.push("");
  lines.push(`inline const std::array<GeneratedGenericHookMetadata, ${hooks.length}> GeneratedAgentHookMetadata =`);
  lines.push("{{");
  for (const hook of hooks)
  {
    lines.push(`    { ${hook.id}, ${cppString(hook.module)}, ${cppString(hook.name)}, ${cppString(hook.family)}, ${cppString(hook.category)}, ${cppString(hook.risk)}, ${cppString(runtimeHookPolicy(hook))}, ${cppString(runtimeCoverageStatus(hook))}, ${cppString(`${hook.module}!${hook.name}`)}, GenericReturnFormat::${returnFormat(hook.returnType)}, ${hook.parameterCount}, GeneratedGenericErrorSource::${errorSource(hook.errorSource)} },`);
  }
  lines.push("}};");
  lines.push("");

  for (let chunkStart = 0; chunkStart < hooks.length; chunkStart += hookSourceChunkSize)
  {
    const chunkIndex = Math.floor(chunkStart / hookSourceChunkSize);
    lines.push(`extern "C" void* KnMonGetGeneratedHookAddressChunk${chunkIndex}(std::size_t localIndex);`);
  }
  lines.push("");

  for (let chunkStart = 0; chunkStart < hooks.length; chunkStart += hookDefinitionChunkSize)
  {
    const chunkIndex = Math.floor(chunkStart / hookDefinitionChunkSize);
    const chunkHooks = hooks.slice(chunkStart, chunkStart + hookDefinitionChunkSize);
    lines.push(`void AppendGeneratedHookDefinitionsChunk${chunkIndex}(HookDefinition* output)`);
    lines.push("{");
    chunkHooks.forEach((hook, localIndex) =>
    {
      const index = chunkStart + localIndex;
      const sourceChunkIndex = Math.floor(index / hookSourceChunkSize);
      const sourceChunkLocalIndex = index % hookSourceChunkSize;
      lines.push(`    output[${index}] = HookDefinition { ${cppString(hook.module)}, ${cppString(hook.name)}, KnMonGetGeneratedHookAddressChunk${sourceChunkIndex}(${sourceChunkLocalIndex}), reinterpret_cast<void**>(&g_generatedAgentOriginalFunctions[${index}]), false, true, false, 0, 0, true, "generated-abi" };`);
    });
    lines.push("}");
    lines.push("");
  }

  lines.push("void AppendGeneratedHookDefinitions(HookDefinition* output, std::size_t capacity)");
  lines.push("{");
  lines.push("    if (output == nullptr || capacity < GeneratedAgentHookDefinitionCount)");
  lines.push("    {");
  lines.push("        return;");
  lines.push("    }");
  lines.push("");
  for (let chunkStart = 0; chunkStart < hooks.length; chunkStart += hookDefinitionChunkSize)
  {
    const chunkIndex = Math.floor(chunkStart / hookDefinitionChunkSize);
    lines.push(`    AppendGeneratedHookDefinitionsChunk${chunkIndex}(output);`);
  }
  lines.push("}");
  lines.push("#else");
  lines.push("inline constexpr std::size_t GeneratedAgentHookDefinitionCount = 0;");
  lines.push(`inline constexpr std::size_t GeneratedAgentHookCoveredApiCount = ${coverage.manualCovered};`);
  lines.push(`inline constexpr std::size_t GeneratedAgentHookRequiredApiCount = ${coverage.required};`);
  lines.push("struct GeneratedAgentModuleMetadata");
  lines.push("{");
  lines.push("    std::uint16_t Id = 0;");
  lines.push("    const char* Name = \"\";");
  lines.push("};");
  lines.push("");
  lines.push("struct GeneratedAgentResolverMetadata");
  lines.push("{");
  lines.push("    std::uint16_t Id = 0;");
  lines.push("    const char* ModuleName = \"\";");
  lines.push("    const char* Name = \"\";");
  lines.push("    const char* HookPolicy = \"\";");
  lines.push("    const char* CoverageStatus = \"\";");
  lines.push("};");
  lines.push("");
  lines.push("inline const std::array<GeneratedAgentModuleMetadata, 0> GeneratedAgentModules = {};");
  lines.push("inline const std::array<GeneratedAgentResolverMetadata, 0> GeneratedAgentResolverMetadataTable = {};");
  lines.push("");
  lines.push("void AppendGeneratedHookDefinitions(HookDefinition* output, std::size_t capacity)");
  lines.push("{");
  lines.push("    (void)output;");
  lines.push("    (void)capacity;");
  lines.push("}");
  lines.push("#endif");
  lines.push("");
  return lines.join("\n");
}

function buildHookChunkFile(hooks, chunkStart, chunkIndex)
{
  const lines = [];
  lines.push("// Generated by tools/def-validator/generate-agent-hook-definitions.mjs. Do not edit manually.");
  lines.push("#include <Windows.h>");
  lines.push("");
  lines.push("#include <cstddef>");
  lines.push("#include <cstdint>");
  lines.push("");
  lines.push("extern \"C\" std::uintptr_t KnMonInvokeGeneratedValueHookByIndex(");
  lines.push("    std::size_t index,");
  for (let index = 0; index < 16; ++index)
  {
    lines.push(`    std::uintptr_t arg${index}${index === 15 ? "" : ","}`);
  }
  lines.push(");");
  lines.push("");
  lines.push("extern \"C\" void KnMonInvokeGeneratedVoidHookByIndex(");
  lines.push("    std::size_t index,");
  for (let index = 0; index < 16; ++index)
  {
    lines.push(`    std::uintptr_t arg${index}${index === 15 ? "" : ","}`);
  }
  lines.push(");");
  lines.push("");

  hooks.forEach((hook, localIndex) =>
  {
    const index = chunkStart + localIndex;
    const name = generatedHookName(hook);
    const args = argumentList(hook.parameterCount);
    const paddedNames = paddedArgumentNames(hook.parameterCount);
    lines.push(`${functionSignaturePrefix(hook)} ${name}(${args})`);
    lines.push("{");
    if (returnFormat(hook.returnType) === "Void")
    {
      lines.push(`    KnMonInvokeGeneratedVoidHookByIndex(${index}, ${paddedNames});`);
    }
    else
    {
      lines.push(`    return KnMonInvokeGeneratedValueHookByIndex(${index}, ${paddedNames});`);
    }
    lines.push("}");
    lines.push("");
  });

  lines.push(`extern "C" void* KnMonGetGeneratedHookAddressChunk${chunkIndex}(std::size_t localIndex)`);
  lines.push("{");
  lines.push("    switch (localIndex)");
  lines.push("    {");
  hooks.forEach((hook, localIndex) =>
  {
    const name = generatedHookName(hook);
    lines.push(`    case ${localIndex}:`);
    lines.push(`        return reinterpret_cast<void*>(${name});`);
  });
  lines.push("    default:");
  lines.push("        break;");
  lines.push("    }");
  lines.push("");
  lines.push("    return nullptr;");
  lines.push("}");
  lines.push("");

  return lines.join("\n");
}

function buildHookChunkFiles(hooks)
{
  const chunks = [];
  for (let chunkStart = 0; chunkStart < hooks.length; chunkStart += hookSourceChunkSize)
  {
    const chunkIndex = Math.floor(chunkStart / hookSourceChunkSize);
    chunks.push({
      index: chunkIndex,
      filePath: generatedHookChunkPath(chunkIndex),
      text: buildHookChunkFile(hooks.slice(chunkStart, chunkStart + hookSourceChunkSize), chunkStart, chunkIndex)
    });
  }

  return chunks;
}

function listExistingHookChunkFiles()
{
  if (!fs.existsSync(generatedHookSourceDirectory))
  {
    return [];
  }

  return fs.readdirSync(generatedHookSourceDirectory)
    .filter((name) => /^GeneratedAgentHooksChunk\d+\.cpp$/.test(name))
    .map((name) => path.join(generatedHookSourceDirectory, name))
    .sort();
}

function main()
{
  const args = new Set(process.argv.slice(2));
  const write = args.has("--write");
  const check = args.has("--check");
  const tables = readJson(decoderTablePath);
  const parametersByApi = new Map();
  for (const parameter of tables.parameters ?? [])
  {
    if (!parametersByApi.has(parameter.apiId))
    {
      parametersByApi.set(parameter.apiId, []);
    }
    parametersByApi.get(parameter.apiId).push(parameter);
  }

  const manual = manualHookKeys();
  const modules = [...(tables.modules ?? [])].sort((left, right) => left.id - right.id);
  const hookable = (tables.apis ?? []).filter(isRuntimeInstallable);
  const unsafe = hookable.filter((api) => !isGenericSafe(api, parametersByApi) && !manual.has(lowerKey(api.module, api.name)));
  if (unsafe.length > 0)
  {
    throw new Error(`Generated agent hooks cannot safely cover ${unsafe.length} API(s): ${unsafe.slice(0, 5).map((api) => `${api.module}!${api.name}`).join(", ")}`);
  }

  const hooks = hookable
    .filter((api) => !manual.has(lowerKey(api.module, api.name)))
    .sort((left, right) => left.id - right.id);

  const manualCovered = hookable.filter((api) => manual.has(lowerKey(api.module, api.name))).length;
  const coverage = {
    required: hookable.length,
    manualCovered,
    covered: manualCovered + hooks.length
  };
  const resolverApis = [...hookable].sort((left, right) => left.id - right.id);
  const expected = buildHookFile(hooks, coverage, modules, resolverApis);
  const expectedChunks = buildHookChunkFiles(hooks);

  if (write)
  {
    fs.writeFileSync(generatedHookPath, expected, "utf8");
    const expectedChunkPaths = new Set(expectedChunks.map((chunk) => chunk.filePath));
    for (const filePath of listExistingHookChunkFiles())
    {
      if (!expectedChunkPaths.has(filePath))
      {
        fs.rmSync(filePath, { force: true });
      }
    }

    for (const chunk of expectedChunks)
    {
      fs.writeFileSync(chunk.filePath, chunk.text, "utf8");
    }
  }

  if (check)
  {
    if (!fs.existsSync(generatedHookPath))
    {
      throw new Error("Generated agent hook definitions are missing; run npm run agent-hooks:generate.");
    }

    const actual = fs.readFileSync(generatedHookPath, "utf8");
    if (actual !== expected)
    {
      throw new Error("Generated agent hook definitions are stale; run npm run agent-hooks:generate.");
    }

    const expectedChunkPaths = new Set(expectedChunks.map((chunk) => chunk.filePath));
    for (const filePath of listExistingHookChunkFiles())
    {
      if (!expectedChunkPaths.has(filePath))
      {
        throw new Error(`Stale generated agent hook chunk exists: ${path.relative(repoRoot, filePath).replaceAll("\\", "/")}`);
      }
    }

    for (const chunk of expectedChunks)
    {
      if (!fs.existsSync(chunk.filePath))
      {
        throw new Error(`Generated agent hook chunk is missing: ${path.relative(repoRoot, chunk.filePath).replaceAll("\\", "/")}`);
      }

      const actualChunk = fs.readFileSync(chunk.filePath, "utf8");
      if (actualChunk !== chunk.text)
      {
        throw new Error(`Generated agent hook chunk is stale: ${path.relative(repoRoot, chunk.filePath).replaceAll("\\", "/")}`);
      }
    }
  }

  console.log(`Generated agent hook definitions. required=${coverage.required} manual=${coverage.manualCovered} generated=${hooks.length} covered=${coverage.covered} chunks=${expectedChunks.length}`);
}

main();
