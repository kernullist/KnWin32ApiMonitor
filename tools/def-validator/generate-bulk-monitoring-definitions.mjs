import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import {
  apiKey,
  loadApiDefinitionDocuments,
  loadMetadataDocuments,
  normalizeModuleName,
  readJson,
  repoRoot,
  stableStringify,
  writeStableJson
} from "./definition-system.mjs";

const args = new Set(process.argv.slice(2));
const write = args.has("--write");
const targetDefinedApis = Number.parseInt(argumentValue("--target-defined", "700"), 10);
const inventoryPath = path.join(repoRoot, "generated", "api-inventory.json");
const idAssignmentsPath = path.join(repoRoot, "definitions", "metadata", "id-assignments.json");
const bulkDefinitionPath = path.join(repoRoot, "definitions", "win32", "generated-win32metadata-bulk.json");
const ntdllDefinitionPath = path.join(repoRoot, "definitions", "nt", "ntdll-win11-exports.json");
const ntdllEvidencePath = path.join(repoRoot, "generated", "ntdll-win11-export-baseline.json");
const ntdllPath = "C:/Windows/System32/ntdll.dll";

if (!Number.isInteger(targetDefinedApis) || targetDefinedApis < 1)
{
  throw new Error("--target-defined must be a positive integer");
}

const apiDocuments = loadApiDefinitionDocuments().documents;
const existingKeys = new Set();
for (const item of apiDocuments)
{
  const relativePath = path.relative(repoRoot, item.filePath).replaceAll("\\", "/");
  if (relativePath === "definitions/win32/generated-win32metadata-bulk.json" || relativePath === "definitions/nt/ntdll-win11-exports.json")
  {
    continue;
  }

  for (const api of item.document.apis ?? [])
  {
    existingKeys.add(apiKey(api.module, api.name));
  }
}

const inventory = readJson(inventoryPath);
const inventoryRows = inventory.apis ?? [];
const inventoryByKey = new Map(inventoryRows.map((entry) => [apiKey(entry.module, entry.name), entry]));
const ntdllExports = readPeExports(ntdllPath);
const ntdllApis = buildNtdllDefinitions(ntdllExports, inventoryByKey, existingKeys);
const newNtdllKeys = new Set(ntdllApis.map((api) => apiKey(api.module, api.name)));
const definedCountBeforeBulk = existingDefinedCount(apiDocuments) + ntdllApis.filter((api) => api.coverageStatus !== "unsupported").length;
const bulkTarget = Math.max(0, targetDefinedApis - definedCountBeforeBulk);
const bulkApis = buildBulkDefinitions(inventoryRows, existingKeys, newNtdllKeys, bulkTarget);

const generatedDocuments = [
  {
    filePath: bulkDefinitionPath,
    document: {
      schemaVersion: "0.1.0",
      module: "win32metadata-bulk",
      description: "Generated Win32 metadata API expansion with generic field decoding hints.",
      apis: bulkApis
    }
  },
  {
    filePath: ntdllDefinitionPath,
    document: {
      schemaVersion: "0.1.0",
      module: "ntdll",
      description: "Windows 11 ntdll.dll export coverage. Known Win32 metadata rows carry field decoders; prototype-unknown exports are intentionally unsupported until ABI validation.",
      apis: ntdllApis
    }
  }
];

const metadataDocuments = loadMetadataDocuments().documents;
const idAssignments = metadataDocuments.find((item) => item.document.metadataType === "id_assignments")?.document ?? readJson(idAssignmentsPath);
const updatedAssignments = updateIdAssignments(idAssignments, generatedDocuments);
const evidence = buildNtdllEvidence(ntdllExports, ntdllApis, inventoryByKey);

if (write)
{
  writeStableJson(bulkDefinitionPath, generatedDocuments[0].document);
  writeStableJson(ntdllDefinitionPath, generatedDocuments[1].document);
  writeStableJson(ntdllEvidencePath, evidence);
  writeStableJson(idAssignmentsPath, updatedAssignments);
  console.log(`Generated bulk definitions: win32metadata=${bulkApis.length} ntdll=${ntdllApis.length}`);
  console.log(`Updated ID assignments: modules=${updatedAssignments.modules.length} apis=${updatedAssignments.apis.length}`);
}
else
{
  console.log(stableStringify({
    write: false,
    targetDefinedApis,
    definedCountBeforeBulk,
    generated: {
      win32metadataBulk: bulkApis.length,
      ntdllExports: ntdllApis.length,
      ntdllKnownMetadata: ntdllApis.filter((api) => api.coverageStatus !== "unsupported").length,
      ntdllUnsupported: ntdllApis.filter((api) => api.coverageStatus === "unsupported").length
    },
    output: {
      bulkDefinitionPath: relative(bulkDefinitionPath),
      ntdllDefinitionPath: relative(ntdllDefinitionPath),
      ntdllEvidencePath: relative(ntdllEvidencePath)
    }
  }));
}

function argumentValue(name, fallback)
{
  const prefix = `${name}=`;
  for (const arg of process.argv.slice(2))
  {
    if (arg.startsWith(prefix))
    {
      return arg.slice(prefix.length);
    }
  }

  return fallback;
}

function relative(filePath)
{
  return path.relative(repoRoot, filePath).replaceAll("\\", "/");
}

function existingDefinedCount(documents)
{
  let count = 0;
  for (const item of documents)
  {
    const relativePath = relative(item.filePath);
    if (relativePath === "definitions/win32/generated-win32metadata-bulk.json" || relativePath === "definitions/nt/ntdll-win11-exports.json")
    {
      continue;
    }

    for (const api of item.document.apis ?? [])
    {
      if (api.coverageStatus !== "unsupported")
      {
        ++count;
      }
    }
  }

  return count;
}

function buildBulkDefinitions(rows, existing, ntdllKeys, needed)
{
  const output = [];
  if (needed <= 0)
  {
    return output;
  }

  const candidates = rows
    .filter((entry) => entry.hookability?.tier === 1)
    .filter((entry) => (entry.parameters ?? []).length > 0)
    .filter((entry) => (entry.parameters ?? []).length <= 8)
    .filter((entry) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(entry.name))
    .filter((entry) => !existing.has(apiKey(entry.module, entry.name)))
    .filter((entry) => !ntdllKeys.has(apiKey(entry.module, entry.name)))
    .sort(compareInventoryPriority);

  for (const entry of candidates)
  {
    output.push(definitionFromInventory(entry, {
      hookPolicy: "iat",
      coverageStatus: "defined"
    }));

    if (output.length >= needed)
    {
      break;
    }
  }

  return output;
}

function buildNtdllDefinitions(exports, inventoryMap, existing)
{
  const apis = [];

  for (const exported of exports.namedExports)
  {
    const key = apiKey("ntdll.dll", exported.name);
    if (existing.has(key))
    {
      continue;
    }

    const inventoryEntry = inventoryMap.get(key);
    if (inventoryEntry && (inventoryEntry.parameters ?? []).length > 0)
    {
      apis.push(definitionFromInventory(inventoryEntry, {
        ordinal: exported.ordinal,
        hookPolicy: "iat",
        coverageStatus: "defined",
        minWindowsVersion: "Windows 11 24H2 export baseline 10.0.26100"
      }));
      continue;
    }

    apis.push(definitionFromExport(exported));
  }

  return apis.sort((left, right) => left.name.localeCompare(right.name));
}

function definitionFromInventory(entry, overrides = {})
{
  const parameters = (entry.parameters ?? []).map((parameter, index) => parameterFromInventory(parameter, index));
  const definition = {
    module: normalizedModuleForDefinition(entry.module),
    name: entry.name,
    family: entry.family ?? familyFromApiName(entry.name),
    category: entry.category ?? categoryFromApiName(entry.name),
    risk: entry.risk ?? "medium",
    hookPolicy: overrides.hookPolicy ?? "iat",
    coverageStatus: overrides.coverageStatus ?? "defined",
    architectures: ["x64"],
    callingConvention: normalizeCallingConvention(entry.callingConvention),
    returnType: entry.returnType ?? "ULONG_PTR",
    errorSource: normalizeErrorSource(entry.errorSource, entry.returnType),
    parameters
  };

  if (overrides.ordinal !== undefined)
  {
    definition.ordinal = overrides.ordinal;
  }

  if (overrides.minWindowsVersion)
  {
    definition.minWindowsVersion = overrides.minWindowsVersion;
  }
  else if (entry.availability)
  {
    definition.minWindowsVersion = entry.availability;
  }

  return definition;
}

function definitionFromExport(exported)
{
  const family = familyFromApiName(exported.name);
  return {
    module: "ntdll.dll",
    name: exported.name,
    ordinal: exported.ordinal,
    family,
    category: categoryFromApiName(exported.name),
    risk: riskFromExportName(exported.name, family),
    hookPolicy: "unsupported",
    coverageStatus: "unsupported",
    architectures: ["x64"],
    callingConvention: callingConventionFromExportName(exported.name),
    returnType: returnTypeFromExportName(exported.name),
    errorSource: errorSourceFromExportName(exported.name),
    parameters: []
  };
}

function parameterFromInventory(parameter, index)
{
  return {
    name: sanitizeParameterName(parameter.name, index),
    type: parameter.type ?? "ULONG_PTR",
    direction: normalizeDirection(parameter.direction),
    decode: decodeAliasForParameter(parameter),
    ...(isNullableParameter(parameter) ? { nullable: true } : {})
  };
}

function decodeAliasForParameter(parameter)
{
  const type = String(parameter.type ?? "");
  const name = String(parameter.name ?? "");
  const hint = String(parameter.decodeHint ?? "");
  const text = `${name} ${type}`;

  if (/\bUNICODE_STRING\b/i.test(type))
  {
    return "unicode_string";
  }

  if (/\b(ANSI_STRING|STRING)\b/i.test(type))
  {
    return "ansi_string_struct";
  }

  if (/\bOBJECT_ATTRIBUTES\b/i.test(type))
  {
    return "object_attributes";
  }

  if (/\bIO_STATUS_BLOCK\b/i.test(type))
  {
    return "io_status_block";
  }

  if (/\bGUID\b|\bUUID\b/i.test(type))
  {
    return "guid_pointer";
  }

  if (hint === "string" || /(?:^|[PWL])C?STR\b|(?:^|[PWL])C?WSTR\b|wchar_t|WCHAR/i.test(type))
  {
    if (/A$/.test(name) || /P?C?STR\b|char/i.test(type))
    {
      return "ansi_string";
    }

    return "utf16_string";
  }

  if (/\bHANDLE\b|\bH[A-Z0-9_]+\b/.test(type))
  {
    return type.includes("*") ? "handle_pointer" : "handle";
  }

  if (/\*\*/.test(type) || /\bPVOID\*/i.test(type))
  {
    return "pointer_pointer";
  }

  if (hint === "pointer" || type.includes("*") || /^P[A-Z_]/.test(type))
  {
    return "pointer";
  }

  if (/size|length|bytes|count|cb|cch|capacity/i.test(text))
  {
    return "byte_count";
  }

  if (/flags?|mask|access|attributes?|options?/i.test(text))
  {
    return "dword_value";
  }

  return "dword_value";
}

function normalizeDirection(value)
{
  if (value === "out" || value === "inout" || value === "return")
  {
    return value;
  }

  return "in";
}

function normalizeCallingConvention(value)
{
  if (value === "ntapi" || value === "cdecl" || value === "fastcall" || value === "thiscall" || value === "winapi")
  {
    return value;
  }

  return "winapi";
}

function normalizeErrorSource(value, returnType)
{
  if (value === "GetLastError" || value === "return_ntstatus" || value === "HRESULT" || value === "none")
  {
    return value;
  }

  if (returnType === "NTSTATUS")
  {
    return "return_ntstatus";
  }

  if (returnType === "HRESULT")
  {
    return "HRESULT";
  }

  return "none";
}

function isNullableParameter(parameter)
{
  const name = String(parameter.name ?? "");
  const type = String(parameter.type ?? "");
  return /optional|reserved|mustBeNull|canBeNull/i.test(name) || /\bPVOID\b/i.test(type);
}

function normalizedModuleForDefinition(moduleName)
{
  const normalized = normalizeModuleName(moduleName);
  if (normalized === "ntdll.dll")
  {
    return "ntdll.dll";
  }

  return normalized;
}

function sanitizeParameterName(value, index)
{
  let name = String(value ?? "").replace(/[^A-Za-z0-9_]/g, "_");
  if (!/^[A-Za-z_]/.test(name))
  {
    name = `arg${index}`;
  }

  if (name.length === 0)
  {
    name = `arg${index}`;
  }

  return name;
}

function familyFromApiName(name)
{
  if (/^(Nt|Zw)/.test(name))
  {
    return "nt-native";
  }

  if (/^Ldr/.test(name))
  {
    return "loader";
  }

  if (/^Rtl/.test(name))
  {
    return "rtl";
  }

  if (/^Etw/.test(name))
  {
    return "tracing";
  }

  if (/^Alpc/.test(name))
  {
    return "ipc";
  }

  if (/^(Tp|Tpp)/.test(name))
  {
    return "threadpool";
  }

  if (/^(Dbg|DbgUi)/.test(name))
  {
    return "diagnostics";
  }

  if (/^Csr/.test(name))
  {
    return "subsystem";
  }

  if (/^ApiSet/.test(name))
  {
    return "api-set";
  }

  if (/^[A-Za-z_]?_?str|^mem|^wcs|^qsort|^bsearch|^abs$|^labs$/i.test(name))
  {
    return "crt";
  }

  return "ntdll";
}

function categoryFromApiName(name)
{
  const family = familyFromApiName(name);
  if (family === "nt-native")
  {
    return name.startsWith("Zw") ? "ntdll/zw-syscall" : "ntdll/nt-syscall";
  }

  return `ntdll/${family}`;
}

function riskFromExportName(name, family)
{
  if (/^(Nt|Zw)(Open|Create|Set|Write|Protect|Allocate|Map|Unmap|Debug|Adjust|Load|DeviceIoControl|Request|Alpc|Trace)/.test(name))
  {
    return "high";
  }

  if (family === "loader" || family === "ipc" || family === "tracing")
  {
    return "high";
  }

  return "medium";
}

function callingConventionFromExportName(name)
{
  return /^(Nt|Zw|Rtl|Ldr|Alpc|Etw|Tp|Csr|Dbg)/.test(name) ? "ntapi" : "cdecl";
}

function returnTypeFromExportName(name)
{
  if (/^(Nt|Zw)/.test(name) || /^(Ldr|Rtl).*(Ex|String|Unicode|Ansi|Integer|Security|Activation|Resource|Condition|Sid|Acl)/.test(name))
  {
    return "NTSTATUS";
  }

  if (/^(Etw|Alpc|Csr)/.test(name))
  {
    return "NTSTATUS";
  }

  return "ULONG_PTR";
}

function errorSourceFromExportName(name)
{
  return returnTypeFromExportName(name) === "NTSTATUS" ? "return_ntstatus" : "none";
}

function compareInventoryPriority(left, right)
{
  const leftScore = inventoryPriority(left);
  const rightScore = inventoryPriority(right);
  if (leftScore !== rightScore)
  {
    return leftScore - rightScore;
  }

  const moduleCompare = normalizeModuleName(left.module).localeCompare(normalizeModuleName(right.module));
  if (moduleCompare !== 0)
  {
    return moduleCompare;
  }

  return left.name.localeCompare(right.name);
}

function inventoryPriority(entry)
{
  const moduleName = normalizeModuleName(entry.module);
  const family = String(entry.family ?? "");
  const modulePriority = [
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "advapi32.dll",
    "user32.dll",
    "gdi32.dll",
    "rpcrt4.dll",
    "ws2_32.dll",
    "crypt32.dll",
    "bcrypt.dll",
    "winhttp.dll",
    "wininet.dll",
    "ole32.dll",
    "oleaut32.dll",
    "shell32.dll",
    "shlwapi.dll",
    "setupapi.dll",
    "iphlpapi.dll",
    "dbghelp.dll"
  ];

  const moduleIndex = modulePriority.indexOf(moduleName);
  const moduleScore = moduleIndex >= 0 ? moduleIndex : 100;
  const riskScore = entry.risk === "critical" ? 0 : entry.risk === "high" ? 1 : 2;
  const familyScore = /system|security|network|crypto|storage|ui|graphics/.test(family) ? 0 : 10;
  return moduleScore * 100 + familyScore + riskScore;
}

function updateIdAssignments(current, generated)
{
  const modules = [...(current.modules ?? [])];
  const apis = [...(current.apis ?? [])];
  const moduleNames = new Set(modules.map((entry) => entry.name));
  const apiKeys = new Set(apis.map((entry) => apiKey(entry.module, entry.name)));
  const usedSymbols = new Set([
    ...modules.map((entry) => entry.symbol),
    ...apis.map((entry) => entry.symbol)
  ]);
  let nextModuleId = modules.reduce((max, entry) => Math.max(max, entry.id), 0) + 1;
  let nextApiId = apis.reduce((max, entry) => Math.max(max, entry.id), 0) + 1;

  for (const item of generated)
  {
    for (const api of item.document.apis ?? [])
    {
      const moduleName = normalizeModuleName(api.module);
      if (!moduleNames.has(moduleName))
      {
        modules.push({
          id: nextModuleId,
          name: moduleName,
          symbol: uniqueSymbol(moduleSymbol(moduleName), usedSymbols)
        });
        ++nextModuleId;
        moduleNames.add(moduleName);
      }

      const key = apiKey(moduleName, api.name);
      if (!apiKeys.has(key))
      {
        apis.push({
          id: nextApiId,
          module: moduleName,
          name: api.name,
          symbol: uniqueSymbol(apiSymbol(moduleName, api.name), usedSymbols)
        });
        ++nextApiId;
        apiKeys.add(key);
      }
    }
  }

  modules.sort((left, right) => left.id - right.id);
  apis.sort((left, right) => left.id - right.id);

  return {
    schemaVersion: current.schemaVersion ?? "0.1.0",
    metadataType: "id_assignments",
    modules,
    apis
  };
}

function moduleSymbol(moduleName)
{
  const stem = moduleName.replace(/\.dll$/i, "");
  return `Module_${toPascalIdentifier(stem)}`;
}

function apiSymbol(moduleName, apiName)
{
  const moduleStem = moduleName.replace(/\.dll$/i, "");
  return `Api_${toPascalIdentifier(moduleStem)}_${toPascalIdentifier(apiName)}`;
}

function toPascalIdentifier(value)
{
  const words = String(value).split(/[^A-Za-z0-9]+/).filter(Boolean);
  const text = words.length === 0 ? "Generated" : words.map((word) => {
    const safe = word.replace(/[^A-Za-z0-9]/g, "");
    return safe.length === 0 ? "" : safe[0].toUpperCase() + safe.slice(1);
  }).join("");

  return /^[A-Za-z_]/.test(text) ? text : `N${text}`;
}

function uniqueSymbol(candidate, used)
{
  let symbol = candidate.replace(/[^A-Za-z0-9_]/g, "_");
  if (!/^[A-Za-z_]/.test(symbol))
  {
    symbol = `Generated_${symbol}`;
  }

  let result = symbol;
  let suffix = 2;
  while (used.has(result))
  {
    result = `${symbol}_${suffix}`;
    ++suffix;
  }

  used.add(result);
  return result;
}

function buildNtdllEvidence(exports, ntdllApis, inventoryMap)
{
  return {
    schemaVersion: "0.1.0",
    source: {
      path: exports.path,
      fileVersion: exports.fileVersion,
      productVersion: exports.productVersion,
      size: exports.size,
      machine: exports.machine,
      exportRva: exports.exportRva,
      exportSize: exports.exportSize,
      note: "Local Windows 11 24H2 export baseline; Microsoft release health on 2026-06-09 lists 26100.8655 as the latest 24H2 GA build."
    },
    summary: {
      numberOfFunctions: exports.numberOfFunctions,
      numberOfNames: exports.numberOfNames,
      ordinalOnlyCount: exports.ordinalOnlyCount,
      generatedDefinitions: ntdllApis.length,
      withWin32Metadata: ntdllApis.filter((api) => inventoryMap.has(apiKey(api.module, api.name))).length,
      unsupportedPrototypeUnknown: ntdllApis.filter((api) => api.coverageStatus === "unsupported").length
    },
    exports: exports.namedExports
  };
}

function readPeExports(filePath)
{
  const buffer = fs.readFileSync(filePath);
  const stat = fs.statSync(filePath);
  const version = fileVersion(filePath);
  const u16 = (offset) => buffer.readUInt16LE(offset);
  const u32 = (offset) => buffer.readUInt32LE(offset);
  const peOffset = u32(0x3c);
  const machine = u16(peOffset + 4);
  const sectionCount = u16(peOffset + 6);
  const optionalHeaderSize = u16(peOffset + 20);
  const optionalHeaderOffset = peOffset + 24;
  const magic = u16(optionalHeaderOffset);
  const dataDirectoryOffset = magic === 0x20b ? optionalHeaderOffset + 112 : optionalHeaderOffset + 96;
  const exportRva = u32(dataDirectoryOffset);
  const exportSize = u32(dataDirectoryOffset + 4);
  const sectionOffset = optionalHeaderOffset + optionalHeaderSize;
  const sections = [];

  for (let index = 0; index < sectionCount; ++index)
  {
    const offset = sectionOffset + index * 40;
    sections.push({
      name: buffer.slice(offset, offset + 8).toString("ascii").replace(/\0.*$/, ""),
      virtualSize: u32(offset + 8),
      virtualAddress: u32(offset + 12),
      rawSize: u32(offset + 16),
      rawAddress: u32(offset + 20)
    });
  }

  const rvaToOffset = (rva) => {
    for (const section of sections)
    {
      const size = Math.max(section.virtualSize, section.rawSize);
      if (rva >= section.virtualAddress && rva < section.virtualAddress + size)
      {
        return section.rawAddress + (rva - section.virtualAddress);
      }
    }

    throw new Error(`unmapped PE RVA 0x${rva.toString(16)}`);
  };
  const readString = (rva) => {
    const offset = rvaToOffset(rva);
    let end = offset;
    while (end < buffer.length && buffer[end] !== 0)
    {
      ++end;
    }

    return buffer.slice(offset, end).toString("ascii");
  };

  const exportDirectoryOffset = rvaToOffset(exportRva);
  const ordinalBase = u32(exportDirectoryOffset + 16);
  const numberOfFunctions = u32(exportDirectoryOffset + 20);
  const numberOfNames = u32(exportDirectoryOffset + 24);
  const functionsRva = u32(exportDirectoryOffset + 28);
  const namesRva = u32(exportDirectoryOffset + 32);
  const ordinalsRva = u32(exportDirectoryOffset + 36);
  const namedExports = [];

  for (let index = 0; index < numberOfNames; ++index)
  {
    const nameRva = u32(rvaToOffset(namesRva) + index * 4);
    const ordinalIndex = u16(rvaToOffset(ordinalsRva) + index * 2);
    const functionRva = u32(rvaToOffset(functionsRva) + ordinalIndex * 4);
    namedExports.push({
      name: readString(nameRva),
      ordinal: ordinalBase + ordinalIndex,
      rva: `0x${functionRva.toString(16).padStart(8, "0")}`,
      forwarder: functionRva >= exportRva && functionRva < exportRva + exportSize ? readString(functionRva) : null
    });
  }

  namedExports.sort((left, right) => left.name.localeCompare(right.name));

  return {
    path: filePath,
    fileVersion: version.fileVersion,
    productVersion: version.productVersion,
    size: stat.size,
    machine: `0x${machine.toString(16)}`,
    exportRva,
    exportSize,
    numberOfFunctions,
    numberOfNames,
    ordinalOnlyCount: numberOfFunctions - numberOfNames,
    namedExports
  };
}

function fileVersion(filePath)
{
  if (process.platform !== "win32")
  {
    return {
      fileVersion: null,
      productVersion: null
    };
  }

  const command = [
    "$item = Get-Item -LiteralPath ",
    powerShellString(filePath),
    "; [pscustomobject]@{ fileVersion = $item.VersionInfo.FileVersion; productVersion = $item.VersionInfo.ProductVersion } | ConvertTo-Json -Compress"
  ].join("");
  const output = childProcess.execFileSync(
    "powershell",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
    {
      encoding: "utf8",
      maxBuffer: 1024 * 1024
    });

  return JSON.parse(output);
}

function powerShellString(value)
{
  return `'${String(value).replaceAll("'", "''")}'`;
}
