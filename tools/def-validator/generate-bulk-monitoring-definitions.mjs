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
const systemExportDefinitionPath = path.join(repoRoot, "definitions", "win32", "generated-system32-exports-bulk.json");
const ntdllDefinitionPath = path.join(repoRoot, "definitions", "nt", "ntdll-win11-exports.json");
const ntdllEvidencePath = path.join(repoRoot, "generated", "ntdll-win11-export-baseline.json");
const ntdllLatestOverlayPath = path.join(repoRoot, "generated", "ntdll-win11-latest-export-overlay.json");
const phntPrototypeIndexPath = path.join(repoRoot, "generated", "phnt-ntdll-prototype-index.json");
const sdkPrototypeIndexPath = path.join(repoRoot, "generated", "ntdll-sdk-prototype-index.json");
const supplementalSpecIndexPath = path.join(repoRoot, "generated", "ntdll-supplemental-spec-index.json");
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
  if (
    relativePath === "definitions/win32/generated-win32metadata-bulk.json" ||
    relativePath === "definitions/win32/generated-system32-exports-bulk.json" ||
    relativePath === "definitions/nt/ntdll-win11-exports.json")
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
const phntPrototypeIndex = fs.existsSync(phntPrototypeIndexPath) ? readJson(phntPrototypeIndexPath) : null;
const phntPrototypesByName = new Map((phntPrototypeIndex?.prototypes ?? []).map((prototype) => [prototype.name, prototype]));
const sdkPrototypeIndex = fs.existsSync(sdkPrototypeIndexPath) ? readJson(sdkPrototypeIndexPath) : null;
const sdkPrototypesByName = new Map((sdkPrototypeIndex?.prototypes ?? []).map((prototype) => [prototype.name, prototype]));
const supplementalSpecIndex = fs.existsSync(supplementalSpecIndexPath) ? readJson(supplementalSpecIndexPath) : null;
const supplementalSpecPrototypesByName = new Map((supplementalSpecIndex?.prototypes ?? []).map((prototype) => [prototype.name, prototype]));
const ntdllLatestOverlay = fs.existsSync(ntdllLatestOverlayPath) ? readJson(ntdllLatestOverlayPath) : null;
const ntdllExports = mergeLatestOverlayExports(readPeExports(ntdllPath), ntdllLatestOverlay);
const ntdllApis = buildNtdllDefinitions(ntdllExports, inventoryByKey, existingKeys, phntPrototypesByName, sdkPrototypesByName, supplementalSpecPrototypesByName);
const newNtdllKeys = new Set(ntdllApis.map((api) => apiKey(api.module, api.name)));
const previousBulkCount = fs.existsSync(bulkDefinitionPath) ? ((readJson(bulkDefinitionPath).apis ?? []).length) : 0;
const previousSystemExportCount = fs.existsSync(systemExportDefinitionPath) ? ((readJson(systemExportDefinitionPath).apis ?? []).length) : 0;
const definedCountBeforeBulk = existingRuntimeHookableCount(apiDocuments) + ntdllApis.filter(isRuntimeHookableDefinition).length;
const bulkTarget = Math.max(previousBulkCount, targetDefinedApis - definedCountBeforeBulk);
const bulkApis = buildBulkDefinitions(inventoryRows, existingKeys, newNtdllKeys, bulkTarget);
const newBulkKeys = new Set(bulkApis.map((api) => apiKey(api.module, api.name)));
const remainingAfterMetadata = targetDefinedApis - definedCountBeforeBulk - bulkApis.filter(isRuntimeHookableDefinition).length;
const systemExportTarget = Math.max(previousSystemExportCount, remainingAfterMetadata);
const systemExportApis = buildSystemExportDefinitions(systemExportTarget, existingKeys, newNtdllKeys, newBulkKeys);

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
    filePath: systemExportDefinitionPath,
    document: {
      schemaVersion: "0.1.0",
      module: "system32-export-bulk",
      description: "Generated Microsoft System32 executable export coverage with opaque x64 ABI decoding. Data exports and forwarders are excluded.",
      apis: systemExportApis
    }
  },
  {
    filePath: ntdllDefinitionPath,
    document: {
      schemaVersion: "0.1.0",
      module: "ntdll",
      description: "Windows 11 ntdll.dll executable export coverage. Data exports are excluded because they are not callable APIs.",
      apis: ntdllApis
    }
  }
];

const metadataDocuments = loadMetadataDocuments().documents;
const idAssignments = metadataDocuments.find((item) => item.document.metadataType === "id_assignments")?.document ?? readJson(idAssignmentsPath);
const updatedAssignments = updateIdAssignments(idAssignments, generatedDocuments, apiDocuments);
const evidence = buildNtdllEvidence(ntdllExports, ntdllApis, inventoryByKey);

if (write)
{
  writeStableJson(bulkDefinitionPath, generatedDocuments[0].document);
  writeStableJson(systemExportDefinitionPath, generatedDocuments[1].document);
  writeStableJson(ntdllDefinitionPath, generatedDocuments[2].document);
  writeStableJson(ntdllEvidencePath, evidence);
  writeStableJson(idAssignmentsPath, updatedAssignments);
  console.log(`Generated bulk definitions: win32metadata=${bulkApis.length} system32exports=${systemExportApis.length} ntdll=${ntdllApis.length}`);
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
      system32Exports: systemExportApis.length,
      ntdllExports: ntdllApis.length,
      ntdllKnownMetadata: ntdllApis.filter((api) => api.coverageStatus !== "unsupported").length,
      ntdllUnsupported: ntdllApis.filter((api) => api.coverageStatus === "unsupported").length,
      phntPrototypeMatches: ntdllApis.filter((api) => String(api.minWindowsVersion ?? "").includes("prototype source PHNT")).length,
      sdkPrototypeMatches: ntdllApis.filter((api) => String(api.minWindowsVersion ?? "").includes("prototype source Windows SDK")).length,
      supplementalSpecMatches: ntdllApis.filter((api) => String(api.minWindowsVersion ?? "").includes("prototype source supplemental")).length
    },
    output: {
      bulkDefinitionPath: relative(bulkDefinitionPath),
      systemExportDefinitionPath: relative(systemExportDefinitionPath),
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

function existingRuntimeHookableCount(documents)
{
  let count = 0;
  for (const item of documents)
  {
    const relativePath = relative(item.filePath);
    if (
      relativePath === "definitions/win32/generated-win32metadata-bulk.json" ||
      relativePath === "definitions/win32/generated-system32-exports-bulk.json" ||
      relativePath === "definitions/nt/ntdll-win11-exports.json")
    {
      continue;
    }

    for (const api of item.document.apis ?? [])
    {
      if (isRuntimeHookableDefinition(api))
      {
        ++count;
      }
    }
  }

  return count;
}

function isRuntimeHookableDefinition(api)
{
  return api.hookPolicy !== "unsupported" && api.hookPolicy !== "definition_only" && api.coverageStatus !== "unsupported";
}

function buildBulkDefinitions(rows, existing, ntdllKeys, needed)
{
  const output = [];
  if (needed <= 0)
  {
    return output;
  }

  const candidates = rows
    .filter((entry) => inventoryEntryIsRuntimeCandidate(entry))
    .filter(inventoryEntryIsRuntimeSafe)
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

function inventoryEntryIsRuntimeCandidate(entry)
{
  const tier = Number(entry.hookability?.tier ?? 99);
  return tier >= 1 && tier <= 3;
}

function buildSystemExportDefinitions(needed, existing, ntdllKeys, bulkKeys)
{
  if (needed <= 0)
  {
    return [];
  }

  const candidates = [];
  for (const dll of microsoftSystemDlls())
  {
    let exports = null;
    try
    {
      exports = readPeExports(dll.path, {
        fileVersion: dll.fileVersion ?? null,
        productVersion: dll.productVersion ?? null
      });
    }
    catch (error)
    {
      continue;
    }

    for (const exported of exports.namedExports)
    {
      if (!systemExportIsRuntimeCandidate(exported))
      {
        continue;
      }

      const moduleName = normalizeModuleName(dll.name);
      const key = apiKey(moduleName, exported.name);
      if (existing.has(key) || ntdllKeys.has(key) || bulkKeys.has(key))
      {
        continue;
      }

      candidates.push({
        dll,
        exported,
        moduleName,
        key
      });
    }
  }

  candidates.sort(compareSystemExportPriority);

  const output = [];
  const emitted = new Set();
  for (const candidate of candidates)
  {
    if (emitted.has(candidate.key))
    {
      continue;
    }

    output.push(definitionFromSystemExport(candidate.dll, candidate.exported));
    emitted.add(candidate.key);

    if (output.length >= needed)
    {
      break;
    }
  }

  if (output.length < needed)
  {
    throw new Error(`Only ${output.length} Microsoft System32 executable export APIs were available; ${needed} were required.`);
  }

  return output;
}

function microsoftSystemDlls()
{
  if (process.platform !== "win32")
  {
    return [];
  }

  const command = [
    "$items = @(Get-ChildItem -Path $env:SystemRoot\\System32 -Filter *.dll -File | ForEach-Object {",
    "$vi = $_.VersionInfo;",
    "if (($vi.CompanyName -like '*Microsoft*') -or ($vi.FileDescription -like '*Microsoft*')) {",
    "[pscustomobject]@{ name = $_.Name; path = $_.FullName; fileVersion = $vi.FileVersion; productVersion = $vi.ProductVersion; companyName = $vi.CompanyName; fileDescription = $vi.FileDescription }",
    "}",
    "});",
    "$items | ConvertTo-Json -Compress"
  ].join(" ");
  const output = childProcess.execFileSync(
    "powershell",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
    {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024
    });
  const parsed = JSON.parse(output || "[]");
  return (Array.isArray(parsed) ? parsed : [parsed])
    .filter((entry) => entry && /^[A-Za-z0-9_.-]+\.dll$/i.test(entry.name))
    .sort((left, right) => normalizeModuleName(left.name).localeCompare(normalizeModuleName(right.name)));
}

function systemExportIsRuntimeCandidate(exported)
{
  return exported.executable === true &&
    exported.forwarder === null &&
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(exported.name);
}

function definitionFromSystemExport(dll, exported)
{
  const moduleName = normalizeModuleName(dll.name);
  const family = familyFromSystemExport(moduleName, exported.name);
  return {
    module: moduleName,
    name: exported.name,
    ordinal: exported.ordinal,
    family,
    category: categoryFromSystemExport(moduleName, family),
    risk: riskFromSystemExport(moduleName, exported.name, family),
    hookPolicy: "iat",
    coverageStatus: "defined",
    minWindowsVersion: systemExportSourceText(dll, exported),
    architectures: ["x64"],
    callingConvention: callingConventionFromSystemExport(exported.name),
    returnType: returnTypeFromSystemExport(exported.name),
    errorSource: errorSourceFromSystemExport(exported.name),
    parameters: opaqueParameters(exported.name)
  };
}

function systemExportSourceText(dll, exported)
{
  const version = dll.fileVersion ? ` version ${dll.fileVersion}` : "";
  return `Microsoft System32 executable export${version}; ordinal ${exported.ordinal}; opaque 16-slot x64 ABI fallback; data exports and forwarders excluded`;
}

function familyFromSystemExport(moduleName, apiName)
{
  const stem = moduleName.replace(/\.dll$/i, "");
  if (/^(ntdll|kernel32|kernelbase|win32u|api-ms-win-core|ext-ms-win-core)/i.test(stem))
  {
    return "system";
  }

  if (/^(advapi32|authz|credssp|crypt32|bcrypt|ncrypt|secur32|security|wintrust|cryptnet|cryptui|samcli|netapi32|ntdsapi)/i.test(stem))
  {
    return "security";
  }

  if (/^(ws2_32|mswsock|winhttp|wininet|dnsapi|iphlpapi|netiohlp|rasapi32|rtutils|websocket|httpapi)/i.test(stem))
  {
    return "network";
  }

  if (/^(user32|comctl32|uxtheme|dwmapi|windows\.ui|twinapi|input|imm32)/i.test(stem))
  {
    return "ui";
  }

  if (/^(gdi32|gdi32full|gdiplus|dwrite|d2d1|d3d|dxgi|opengl32|glu32|windowscodecs)/i.test(stem))
  {
    return "graphics";
  }

  if (/^(ole32|oleaut32|combase|rpcrt4|actxprxy)/i.test(stem))
  {
    return "com-rpc";
  }

  if (/^(shell32|shlwapi|windows\.storage|propsys|thumbcache|apphelp)/i.test(stem))
  {
    return "shell-storage";
  }

  if (/^(setupapi|cfgmgr32|devobj|newdev|wlanapi|bluetoothapis|hid|winusb)/i.test(stem))
  {
    return "device";
  }

  if (/^(dbghelp|dbgcore|wer|faultrep|tdh|evntrace|wevtapi|pdh)/i.test(stem))
  {
    return "diagnostics";
  }

  if (/^(msvcrt|ucrt|vcruntime|msvcp|concrt)/i.test(stem) || /^[A-Za-z_]?_?str|^mem|^wcs|^qsort|^bsearch|^abs$|^labs$/i.test(apiName))
  {
    return "crt";
  }

  if (/^(clfsw32|esent|vssapi|virtdisk|cabinet|archive)/i.test(stem))
  {
    return "storage";
  }

  return "system-export";
}

function categoryFromSystemExport(moduleName, family)
{
  return `system32-exports/${family}/${moduleName.replace(/\.dll$/i, "")}`;
}

function riskFromSystemExport(moduleName, apiName, family)
{
  const text = `${moduleName}!${apiName}`;
  if (/(Token|Privilege|Credential|Password|Secret|PrivateKey|Cert|Crypt|Protect|Security|Acl|Sid|Logon|Impersonat|Remote|Inject|Debug|WriteProcess|VirtualAlloc|VirtualProtect|MapView|Service|SCManager|Firewall)/i.test(text))
  {
    return "high";
  }

  if (family === "security" || family === "network" || family === "com-rpc")
  {
    return "high";
  }

  if (family === "crt")
  {
    return "low";
  }

  return "medium";
}

function callingConventionFromSystemExport(apiName)
{
  if (/^(Nt|Zw|Rtl|Ldr|Alpc|Etw|Tp|Csr|Dbg)/.test(apiName))
  {
    return "ntapi";
  }

  if (/^[A-Za-z_]?_/.test(apiName) || /^(mem|str|wcs|qsort|bsearch|abs|labs)/i.test(apiName))
  {
    return "cdecl";
  }

  return "winapi";
}

function returnTypeFromSystemExport(apiName)
{
  if (/^(Nt|Zw|Etw|Alpc|Csr)/.test(apiName))
  {
    return "NTSTATUS";
  }

  if (/^(DllRegisterServer|DllUnregisterServer|DllGetClassObject|DllCanUnloadNow|Ro[A-Z])/.test(apiName))
  {
    return "HRESULT";
  }

  return "ULONG_PTR";
}

function errorSourceFromSystemExport(apiName)
{
  const returnType = returnTypeFromSystemExport(apiName);
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

function compareSystemExportPriority(left, right)
{
  const leftScore = systemExportPriority(left);
  const rightScore = systemExportPriority(right);
  if (leftScore !== rightScore)
  {
    return leftScore - rightScore;
  }

  const moduleCompare = left.moduleName.localeCompare(right.moduleName);
  if (moduleCompare !== 0)
  {
    return moduleCompare;
  }

  return left.exported.name.localeCompare(right.exported.name);
}

function systemExportPriority(candidate)
{
  const moduleName = candidate.moduleName;
  const family = familyFromSystemExport(moduleName, candidate.exported.name);
  const modulePriority = [
    "kernel32.dll",
    "kernelbase.dll",
    "ntdll.dll",
    "win32u.dll",
    "advapi32.dll",
    "user32.dll",
    "gdi32.dll",
    "gdi32full.dll",
    "rpcrt4.dll",
    "combase.dll",
    "ole32.dll",
    "oleaut32.dll",
    "shell32.dll",
    "shlwapi.dll",
    "setupapi.dll",
    "cfgmgr32.dll",
    "ws2_32.dll",
    "winhttp.dll",
    "wininet.dll",
    "dnsapi.dll",
    "iphlpapi.dll",
    "crypt32.dll",
    "bcrypt.dll",
    "ncrypt.dll",
    "wintrust.dll",
    "secur32.dll",
    "dbghelp.dll",
    "dbgcore.dll",
    "esent.dll",
    "windows.storage.dll",
    "gdiplus.dll",
    "dwrite.dll",
    "opengl32.dll"
  ];
  const moduleIndex = modulePriority.indexOf(moduleName);
  const moduleScore = moduleIndex >= 0 ? moduleIndex : 1000;
  const familyScore = family === "crt" ? 200 : family === "system-export" ? 100 : 0;
  const debugScore = /d\.dll$|debug|checked/i.test(moduleName) ? 500 : 0;
  return moduleScore * 1000 + familyScore + debugScore;
}

function buildNtdllDefinitions(exports, inventoryMap, existing, phntMap, sdkMap, supplementalSpecMap)
{
  const apis = [];

  for (const exported of exports.namedExports)
  {
    if (!exported.executable)
    {
      continue;
    }

    const key = apiKey("ntdll.dll", exported.name);
    if (existing.has(key))
    {
      continue;
    }

    const inventoryEntry = inventoryMap.get(key);
    if (inventoryEntryIsExternalNtdllMetadata(inventoryEntry))
    {
      const runtimeSafe = inventoryEntryIsRuntimeSafe(inventoryEntry);
      apis.push(definitionFromInventory(inventoryEntry, {
        ordinal: exported.ordinal,
        hookPolicy: runtimeSafe ? "iat" : "definition_only",
        coverageStatus: "defined",
        minWindowsVersion: exportSourceText(exported)
      }));
      continue;
    }

    const phntPrototype = phntMap.get(exported.name);
    if (phntPrototype)
    {
      apis.push(definitionFromPhntPrototype(exported, phntPrototype));
      continue;
    }

    const sdkPrototype = sdkMap.get(exported.name);
    if (sdkPrototype)
    {
      apis.push(definitionFromSdkPrototype(exported, sdkPrototype));
      continue;
    }

    const supplementalSpecPrototype = supplementalSpecMap.get(exported.name);
    if (supplementalSpecPrototype)
    {
      apis.push(definitionFromSupplementalSpecPrototype(exported, supplementalSpecPrototype));
      continue;
    }

    apis.push(definitionFromExport(exported));
  }

  return apis.sort((left, right) => left.name.localeCompare(right.name));
}

function mergeLatestOverlayExports(localExports, overlay)
{
  if (!overlay || (overlay.addedExports ?? []).length === 0)
  {
    return localExports;
  }

  const byName = new Map(localExports.namedExports.map((entry) => [entry.name, entry]));
  for (const exported of overlay.addedExports ?? [])
  {
    if (!byName.has(exported.name))
    {
      byName.set(exported.name, {
        ...exported,
        latestOverlay: true,
        latestOverlaySource: overlay.source ?? null
      });
    }
  }

  return {
    ...localExports,
    latestOverlay: {
      source: overlay.source ?? null,
      latest: overlay.latest ?? null,
      addedExports: overlay.addedExports?.length ?? 0
    },
    namedExports: [...byName.values()].sort((left, right) => left.name.localeCompare(right.name)),
    numberOfNames: Math.max(localExports.numberOfNames, overlay.latest?.numberOfNames ?? localExports.numberOfNames),
    numberOfFunctions: Math.max(localExports.numberOfFunctions, overlay.latest?.numberOfFunctions ?? localExports.numberOfFunctions),
    ordinalOnlyCount: Math.max(localExports.ordinalOnlyCount, overlay.latest?.ordinalOnlyCount ?? localExports.ordinalOnlyCount)
  };
}

function inventoryEntryIsExternalNtdllMetadata(entry)
{
  if (!entry || (entry.parameters ?? []).length === 0)
  {
    return false;
  }

  if (entry.definition?.source === "definitions/nt/ntdll-win11-exports.json")
  {
    return false;
  }

  return entry.sourceKind === "win32metadata";
}

function definitionFromPhntPrototype(exported, prototype)
{
  return definitionFromPrototype(exported, prototype, {
    label: "PHNT",
    detail: prototype.source?.file ?? "",
    forceDefinitionOnly: false
  });
}

function definitionFromSupplementalSpecPrototype(exported, prototype)
{
  return definitionFromPrototype(exported, prototype, {
    label: `supplemental ${prototype.source?.name ?? prototype.source?.id ?? "spec"}`,
    detail: `${prototype.source?.file ?? ""}:${prototype.source?.line ?? ""}`,
    forceDefinitionOnly: Boolean(prototype.stub || prototype.dataExport)
  });
}

function definitionFromSdkPrototype(exported, prototype)
{
  return definitionFromPrototype(exported, prototype, {
    label: "Windows SDK",
    detail: prototype.source?.file ?? "",
    forceDefinitionOnly: false
  });
}

function definitionFromPrototype(exported, prototype, source)
{
  const family = familyFromApiName(exported.name);
  const runtimeSafe = !source.forceDefinitionOnly && prototypeIsRuntimeSafe(prototype);
  return {
    module: "ntdll.dll",
    name: exported.name,
    ordinal: exported.ordinal,
    family,
    category: categoryFromApiName(exported.name),
    risk: riskFromExportName(exported.name, family),
    hookPolicy: runtimeSafe ? "iat" : "definition_only",
    coverageStatus: "defined",
    minWindowsVersion: `${exportSourceText(exported)}; prototype source ${source.label} ${source.detail}`,
    architectures: ["x64"],
    callingConvention: normalizeCallingConvention(prototype.callingConvention),
    returnType: normalizePrototypeType(prototype.returnType),
    errorSource: normalizeErrorSource(undefined, normalizePrototypeType(prototype.returnType)),
    parameters: (prototype.parameters ?? []).map((parameter, index) => parameterFromPrototype(parameter, index))
  };
}

function prototypeIsRuntimeSafe(prototype)
{
  if ((prototype.parameters ?? []).length > 16)
  {
    return false;
  }

  if (unsafeGenericAbiType(prototype.returnType))
  {
    return false;
  }

  for (const parameter of prototype.parameters ?? [])
  {
    if (parameter.variadic || unsafeGenericAbiType(parameter.type))
    {
      return false;
    }
  }

  return true;
}

function inventoryEntryIsRuntimeSafe(entry)
{
  if ((entry.parameters ?? []).length > 16)
  {
    return false;
  }

  if (unsafeGenericAbiType(entry.returnType))
  {
    return false;
  }

  for (const parameter of entry.parameters ?? [])
  {
    if (unsafeGenericAbiType(parameter.type))
    {
      return false;
    }
  }

  return true;
}

function unsafeGenericAbiType(type)
{
  const text = String(type ?? "").toLowerCase();
  if (pointerLikeType(text))
  {
    return false;
  }

  return /\b(float|double|single)\b/.test(text) || (text.startsWith("struct ") && !text.includes("*"));
}

function pointerLikeType(text)
{
  return text.includes("*") || text.includes("&") || /\b(lp|p)[a-z0-9_]+/.test(text);
}

function parameterFromPrototype(parameter, index)
{
  const normalized = {
    name: sanitizeParameterName(parameter.name, index),
    type: normalizePrototypeType(parameter.type ?? "ULONG_PTR"),
    direction: normalizeDirection(parameter.direction),
    decodeHint: parameter.variadic ? "scalar" : undefined
  };

  const output = {
    name: normalized.name,
    type: normalized.type,
    direction: normalized.direction,
    decode: decodeAliasForParameter(normalized)
  };

  if (parameter.nullable || isNullableParameter(normalized))
  {
    output.nullable = true;
  }

  if (normalized.direction === "out" || normalized.direction === "inout")
  {
    output.captureTiming = "post";
  }

  return output;
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
  const exportSource = exportSourceText(exported);
  return {
    module: "ntdll.dll",
    name: exported.name,
    ordinal: exported.ordinal,
    family,
    category: categoryFromApiName(exported.name),
    risk: riskFromExportName(exported.name, family),
    hookPolicy: "iat",
    coverageStatus: "defined",
    minWindowsVersion: `${exportSource}; opaque 16-slot x64 ABI fallback; prototype source unresolved`,
    architectures: ["x64"],
    callingConvention: callingConventionFromExportName(exported.name),
    returnType: returnTypeFromExportName(exported.name),
    errorSource: errorSourceFromExportName(exported.name),
    parameters: opaqueParameters(exported.name)
  };
}

function exportSourceText(exported)
{
  const source = exported.latestOverlaySource;
  if (source)
  {
    return `Windows 11 latest overlay ${source.update ?? source.version ?? ""}`.trim();
  }

  return "Windows 11 24H2 export baseline 10.0.26100";
}

function opaqueParameters(name)
{
  return Array.from({ length: 16 }, (_, index) => ({
    name: `arg${index}`,
    type: "ULONG_PTR",
    direction: "in",
    decode: opaqueDecodeForArgument(name, index),
    nullable: true
  }));
}

function opaqueDecodeForArgument(name, index)
{
  if (/String|Path|Name|Dll|File|Wnf|Feature|Sqm|Event|Message|Notification|Resource|Thread|Process|Pool|Callback/i.test(name) && index < 4)
  {
    return "pointer";
  }

  return "dword_value";
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

function normalizePrototypeType(value)
{
  let type = String(value ?? "ULONG_PTR")
    .replace(/\bCONST\b/g, "const")
    .replace(/\s+/g, " ")
    .trim();

  if (type.length === 0)
  {
    type = "ULONG_PTR";
  }

  if (type === "VOID")
  {
    type = "void";
  }

  return type;
}

function normalizeErrorSource(value, returnType)
{
  if (value === "GetLastError" || value === "return_ntstatus" || value === "HRESULT" || value === "none")
  {
    return value;
  }

  if (String(returnType ?? "").toUpperCase() === "NTSTATUS")
  {
    return "return_ntstatus";
  }

  if (String(returnType ?? "").toUpperCase() === "HRESULT")
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
  const tierScore = Number(entry.hookability?.tier ?? 9) * 10000;
  const riskScore = entry.risk === "critical" ? 0 : entry.risk === "high" ? 1 : 2;
  const familyScore = /system|security|network|crypto|storage|ui|graphics/.test(family) ? 0 : 10;
  const parameterScore = (entry.parameters ?? []).length === 0 ? 5 : 0;
  return tierScore + moduleScore * 100 + familyScore + riskScore + parameterScore;
}

function updateIdAssignments(current, generated, sourceDocuments)
{
  const targetApiKeys = new Set();
  for (const item of sourceDocuments)
  {
    const itemPath = relative(item.filePath);
    if (
      itemPath === "definitions/win32/generated-win32metadata-bulk.json" ||
      itemPath === "definitions/win32/generated-system32-exports-bulk.json" ||
      itemPath === "definitions/nt/ntdll-win11-exports.json")
    {
      continue;
    }

    for (const api of item.document.apis ?? [])
    {
      targetApiKeys.add(apiKey(api.module, api.name));
    }
  }

  for (const item of generated)
  {
    for (const api of item.document.apis ?? [])
    {
      targetApiKeys.add(apiKey(api.module, api.name));
    }
  }

  const modules = [...(current.modules ?? [])];
  const apis = [...(current.apis ?? [])].filter((entry) => targetApiKeys.has(apiKey(entry.module, entry.name)));
  const moduleNames = new Set(modules.map((entry) => entry.name));
  const apiKeys = new Set(apis.map((entry) => apiKey(entry.module, entry.name)));
  const usedSymbols = new Set([
    ...modules.map((entry) => entry.symbol),
    ...(current.apis ?? []).map((entry) => entry.symbol)
  ]);
  let nextModuleId = modules.reduce((max, entry) => Math.max(max, entry.id), 0) + 1;
  let nextApiId = (current.apis ?? []).reduce((max, entry) => Math.max(max, entry.id), 0) + 1;

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
      latestOverlay: exports.latestOverlay ?? null,
      note: "Local Windows 11 24H2 export baseline; Microsoft release health on 2026-06-09 lists 26100.8655 as the latest 24H2 GA build."
    },
    summary: {
      numberOfFunctions: exports.numberOfFunctions,
      numberOfNames: exports.numberOfNames,
      ordinalOnlyCount: exports.ordinalOnlyCount,
      latestOverlayAddedExports: exports.latestOverlay?.addedExports ?? 0,
      generatedDefinitions: ntdllApis.length,
      withWin32Metadata: ntdllApis.filter((api) => inventoryEntryIsExternalNtdllMetadata(inventoryMap.get(apiKey(api.module, api.name)))).length,
      withPhntPrototype: ntdllApis.filter((api) => String(api.minWindowsVersion ?? "").includes("prototype source PHNT")).length,
      withSdkPrototype: ntdllApis.filter((api) => String(api.minWindowsVersion ?? "").includes("prototype source Windows SDK")).length,
      withSupplementalSpecPrototype: ntdllApis.filter((api) => String(api.minWindowsVersion ?? "").includes("prototype source supplemental")).length,
      withOpaqueAbiFallback: ntdllApis.filter((api) => String(api.minWindowsVersion ?? "").includes("opaque 16-slot x64 ABI fallback")).length,
      dataExportsSkipped: exports.namedExports.filter((api) => api.dataExport === true).length,
      unsupportedPrototypeUnknown: ntdllApis.filter((api) => api.coverageStatus === "unsupported").length
    },
    exports: exports.namedExports
  };
}

function readPeExports(filePath, versionOverride = null)
{
  const buffer = fs.readFileSync(filePath);
  const stat = fs.statSync(filePath);
  const version = versionOverride ?? fileVersion(filePath);
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
      rawAddress: u32(offset + 20),
      characteristics: u32(offset + 36)
    });
  }

  const rvaToSection = (rva) => {
    for (const section of sections)
    {
      const size = Math.max(section.virtualSize, section.rawSize);
      if (rva >= section.virtualAddress && rva < section.virtualAddress + size)
      {
        return section;
      }
    }

    return null;
  };

  const rvaToOffset = (rva) => {
    const section = rvaToSection(rva);
    if (section)
    {
      return section.rawAddress + (rva - section.virtualAddress);
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
    const section = rvaToSection(functionRva);
    const forwarder = functionRva >= exportRva && functionRva < exportRva + exportSize ? readString(functionRva) : null;
    const executable = Boolean((section?.characteristics ?? 0) & 0x20000000);
    namedExports.push({
      name: readString(nameRva),
      ordinal: ordinalBase + ordinalIndex,
      rva: `0x${functionRva.toString(16).padStart(8, "0")}`,
      sectionName: section?.name ?? null,
      executable,
      forwarder,
      dataExport: !executable && forwarder === null
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
