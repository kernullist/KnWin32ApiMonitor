import childProcess from "node:child_process";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";

import {
  apiKey,
  collectApiRecords,
  generatedDecoderJsonPath,
  normalizeModuleName,
  readJson,
  relativePath,
  repoRoot,
  stableStringify,
  writeStableJson
} from "./definition-system.mjs";

export const generatedApiInventoryPath = path.join(repoRoot, "generated", "api-inventory.json");
export const generatedApiInventoryReportPath = path.join(repoRoot, "generated", "api-inventory-coverage.json");

export const win32MetadataPackageId = "Microsoft.Windows.SDK.Win32Metadata";
export const win32MetadataFlatContainerId = "microsoft.windows.sdk.win32metadata";
export const win32MetadataIndexUrl = `https://api.nuget.org/v3-flatcontainer/${win32MetadataFlatContainerId}/index.json`;
export const microsoftLearnFeatureIndexUrl = "https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list";
export const microsoftLearnHeaderReferenceUrl = "https://learn.microsoft.com/en-us/windows/win32/api/";

const modulePattern = /^[a-z0-9_.-]+\.dll$/;
const primitiveTypes = new Set([
  "BOOL",
  "BOOLEAN",
  "BYTE",
  "CHAR",
  "DWORD",
  "FLOAT",
  "HANDLE",
  "HRESULT",
  "INT",
  "INT16",
  "INT32",
  "INT64",
  "INT_PTR",
  "LONG",
  "LONGLONG",
  "NTSTATUS",
  "PSTR",
  "PWSTR",
  "PCSTR",
  "PCWSTR",
  "SHORT",
  "SIZE_T",
  "UINT",
  "UINT16",
  "UINT32",
  "UINT64",
  "UINT_PTR",
  "ULONG",
  "ULONGLONG",
  "USHORT",
  "void"
]);

export function loadApiInventory()
{
  if (!fs.existsSync(generatedApiInventoryPath))
  {
    return null;
  }

  return readJson(generatedApiInventoryPath);
}

export function loadApiInventoryReport()
{
  if (!fs.existsSync(generatedApiInventoryReportPath))
  {
    return null;
  }

  return readJson(generatedApiInventoryReportPath);
}

export async function resolveLatestWin32MetadataVersion()
{
  const payload = JSON.parse(await downloadText(win32MetadataIndexUrl));
  const versions = payload.versions ?? [];
  if (versions.length === 0)
  {
    throw new Error("Win32Metadata NuGet package index did not return versions.");
  }

  return versions[versions.length - 1];
}

export async function ensureWin32MetadataPackage(version)
{
  const cacheRoot = path.join(os.tmpdir(), "knmon-win32metadata-cache");
  fs.mkdirSync(cacheRoot, { recursive: true });

  const packageFileName = `${win32MetadataFlatContainerId}.${version}.nupkg`;
  const packagePath = path.join(cacheRoot, packageFileName);
  if (fs.existsSync(packagePath))
  {
    return packagePath;
  }

  const packageUrl = `https://api.nuget.org/v3-flatcontainer/${win32MetadataFlatContainerId}/${version}/${packageFileName}`;
  await downloadFile(packageUrl, packagePath);
  return packagePath;
}

export function runWinmdDump(inputPath)
{
  const projectPath = path.join(repoRoot, "tools", "def-validator", "KnMon.WinmdDump", "KnMon.WinmdDump.csproj");
  const output = childProcess.execFileSync(
    "dotnet",
    ["run", "--project", projectPath, "--", inputPath],
    {
      cwd: repoRoot,
      encoding: "utf8",
      maxBuffer: 256 * 1024 * 1024
    }
  );

  return JSON.parse(output);
}

export async function collectMicrosoftLearnSourceStats()
{
  const featureIndex = await fetchLearnPageStats(microsoftLearnFeatureIndexUrl);
  const headerReference = await fetchLearnPageStats(microsoftLearnHeaderReferenceUrl);

  return {
    featureIndex,
    headerReference
  };
}

export function collectWindowsSdkHeaderStats()
{
  const includeRoot = "C:\\Program Files (x86)\\Windows Kits\\10\\Include";
  const versions = [];

  if (fs.existsSync(includeRoot))
  {
    for (const entry of fs.readdirSync(includeRoot, { withFileTypes: true }))
    {
      if (entry.isDirectory() && /^\d+\.\d+\.\d+\.\d+$/.test(entry.name))
      {
        versions.push(entry.name);
      }
    }
  }

  versions.sort(compareSdkVersions);
  const selectedVersion = versions[versions.length - 1] ?? null;
  const headerNames = new Set();
  const scannedRoots = [];

  if (selectedVersion !== null)
  {
    for (const leaf of ["um", "shared", "ucrt", "winrt"])
    {
      const headerRoot = path.join(includeRoot, selectedVersion, leaf);
      if (!fs.existsSync(headerRoot))
      {
        continue;
      }

      scannedRoots.push(headerRoot);
      for (const filePath of listFiles(headerRoot))
      {
        if (filePath.toLowerCase().endsWith(".h"))
        {
          headerNames.add(path.basename(filePath).toLowerCase());
        }
      }
    }
  }

  return {
    includeRoot,
    selectedVersion,
    scannedRoots,
    headerCount: headerNames.size,
    headerNames
  };
}

export function buildApiInventory(options)
{
  const {
    winmdDump,
    win32MetadataVersion,
    packagePath,
    learnStats,
    sdkStats,
    apiDocuments,
    metadataIndex
  } = options;

  const definitionRecords = collectApiRecords(apiDocuments, metadataIndex);
  const definitionsByKey = new Map();
  for (const record of definitionRecords)
  {
    definitionsByKey.set(record.key, record);
  }

  const methods = normalizeWinmdMethods(winmdDump.methods ?? []);
  const methodKeys = new Set(methods.map((method) => apiKey(method.module, method.name)));
  const entries = [];

  for (const method of methods)
  {
    const key = apiKey(method.module, method.name);
    const definition = definitionsByKey.get(key) ?? null;
    entries.push(buildInventoryEntryFromMethod(method, definition, sdkStats));
  }

  for (const record of definitionRecords)
  {
    const key = record.key;
    if (methodKeys.has(key))
    {
      continue;
    }

    entries.push(buildInventoryEntryFromDefinition(record, sdkStats));
  }

  const aliasIndex = buildAnsiUnicodeIndex(entries);
  for (const entry of entries)
  {
    entry.characterSet = characterSetInfo(entry, aliasIndex);
    entry.hookability = classifyHookability(entry);
    const risk = classifyRisk(entry);
    entry.risk = risk.level;
    entry.riskSignals = risk.signals;
    delete entry.attributeTags;
  }

  entries.sort(compareInventoryEntries);

  const summary = summarizeInventory(entries);
  const report = buildApiInventoryCoverageReport(entries, summary);

  return {
    inventory: {
      schemaVersion: "0.1.0",
      sources: {
        win32Metadata: {
          packageId: win32MetadataPackageId,
          version: win32MetadataVersion,
          packagePath: packagePath ? relativePathIfInsideRepo(packagePath) : null,
          packageUrl: `https://www.nuget.org/packages/${win32MetadataPackageId}/${win32MetadataVersion}`,
          methodCount: winmdDump.methodCount ?? methods.length,
          canonicalApiCount: methods.length,
          filteredDuplicateOrInvalidCount: Math.max(0, (winmdDump.methodCount ?? methods.length) - methods.length),
          source: winmdDump.source ?? "Windows.Win32.winmd"
        },
        microsoftLearn: {
          featureIndexUrl: microsoftLearnFeatureIndexUrl,
          featureIndexLinkCount: learnStats?.featureIndex?.linkCount ?? 0,
          headerReferenceUrl: microsoftLearnHeaderReferenceUrl,
          headerReferenceLinkCount: learnStats?.headerReference?.linkCount ?? 0
        },
        windowsSdk: {
          includeRoot: sdkStats.includeRoot,
          selectedVersion: sdkStats.selectedVersion,
          headerCount: sdkStats.headerCount
        },
        existingDefinitions: {
          definitionCount: definitionRecords.length,
          decoderTable: relativePath(generatedDecoderJsonPath)
        }
      },
      summary,
      nextFamilies: report.nextFamilies,
      apis: entries
    },
    report
  };
}

export function writeApiInventoryArtifacts(inventory, report)
{
  writeStableJson(generatedApiInventoryPath, inventory);
  writeStableJson(generatedApiInventoryReportPath, report);
}

export function buildApiInventoryCoverageReport(entries, summary)
{
  const families = new Map();

  for (const entry of entries)
  {
    const tier = entry.hookability.tier;
    if (tier === 0 || tier === 3)
    {
      continue;
    }

    const family = entry.family;
    const current = families.get(family) ?? {
      family,
      tier1: 0,
      tier2: 0,
      withParameters: 0,
      withSdkHeader: 0,
      examples: []
    };

    if (tier === 1)
    {
      current.tier1 += 1;
    }
    else if (tier === 2)
    {
      current.tier2 += 1;
    }

    if (entry.parameters.length > 0)
    {
      current.withParameters += 1;
    }

    if (entry.sdkHeaderPresent)
    {
      current.withSdkHeader += 1;
    }

    if (current.examples.length < 8)
    {
      current.examples.push(`${entry.module}!${entry.name}`);
    }

    families.set(family, current);
  }

  const nextFamilies = Array.from(families.values())
    .map((family) => ({
      ...family,
      impact: family.tier1 * 2 + family.tier2
    }))
    .sort((left, right) => {
      if (right.impact !== left.impact)
      {
        return right.impact - left.impact;
      }

      return left.family.localeCompare(right.family);
    })
    .slice(0, 20);

  return {
    schemaVersion: "0.1.0",
    summary,
    nextFamilies,
    blockedByMissingDecoderOrHookStrategy: entries
      .filter((entry) => entry.hookability.tier === 1 || entry.hookability.tier === 2 || entry.hookability.tier === 3)
      .length
  };
}

export function apiInventoryReportToMarkdown(inventory)
{
  const lines = [
    "# Microsoft Source API Inventory",
    "",
    `Win32Metadata version: ${inventory.sources.win32Metadata.version}`,
    `Discovered APIs: ${inventory.summary.totalApis}`,
    `Win32Metadata APIs: ${inventory.summary.bySource.win32Metadata}`,
    `Existing-definition-only APIs: ${inventory.summary.bySource.existingDefinitionOnly}`,
    `APIs with DLL/module mapping: ${inventory.summary.withModuleMapping}`,
    `APIs with parameter metadata: ${inventory.summary.withParameterMetadata}`,
    `APIs with Microsoft Learn docs: ${inventory.summary.withMicrosoftLearnDocs}`,
    `APIs with SDK header validation: ${inventory.summary.withSdkHeaderValidation}`,
    `APIs currently emitted by agent hooks: ${inventory.summary.currentlyEmittedByAgentHooks}`,
    "",
    "## Hook Tiers",
    ""
  ];

  for (const [tier, count] of Object.entries(inventory.summary.byHookTier))
  {
    lines.push(`- tier ${tier}: ${count}`);
  }

  lines.push("", "## Risk", "");
  for (const [risk, count] of Object.entries(inventory.summary.byRisk ?? {}))
  {
    lines.push(`- ${risk}: ${count}`);
  }

  lines.push("", "## Next API Families", "");
  lines.push("| Family | Tier 1 | Tier 2 | Impact | Examples |");
  lines.push("| --- | ---: | ---: | ---: | --- |");

  for (const family of inventory.nextFamilies ?? [])
  {
    lines.push(`| ${family.family} | ${family.tier1} | ${family.tier2} | ${family.impact} | ${family.examples.join(", ")} |`);
  }

  lines.push("");
  return lines.join("\n");
}

export function validateApiInventory(inventory, apiDocuments, metadataIndex)
{
  const errors = [];

  if (inventory === null)
  {
    return [`${relativePath(generatedApiInventoryPath)} is missing; run npm run defs:inventory`];
  }

  if (inventory.schemaVersion !== "0.1.0")
  {
    errors.push(`generated API inventory has unsupported schema version ${inventory.schemaVersion}`);
  }

  const stableText = stableStringify(inventory);
  const actualText = fs.readFileSync(generatedApiInventoryPath, "utf8");
  if (actualText !== stableText)
  {
    errors.push(`${relativePath(generatedApiInventoryPath)} is not stable-sorted; run npm run defs:inventory`);
  }

  const apis = inventory.apis ?? [];
  if (inventory.summary?.totalApis !== apis.length)
  {
    errors.push(`generated API inventory total mismatch: summary=${inventory.summary?.totalApis} apis=${apis.length}`);
  }

  const keys = new Set();
  const aliasVariants = new Map();
  const validRisks = new Set(["low", "medium", "high", "critical"]);
  for (const api of apis)
  {
    const moduleName = normalizeModuleName(api.module);
    const key = apiKey(moduleName, api.name);
    if (keys.has(key))
    {
      errors.push(`generated API inventory duplicate API ${key}`);
    }
    keys.add(key);

    if (!modulePattern.test(moduleName))
    {
      errors.push(`generated API inventory invalid module name ${api.module}`);
    }

    if (!validRisks.has(api.risk))
    {
      errors.push(`generated API inventory invalid risk ${api.risk} for ${key}`);
    }

    if (!Array.isArray(api.riskSignals))
    {
      errors.push(`generated API inventory missing risk signals for ${key}`);
    }

    const aliasBase = api.characterSet?.aliasBase;
    const variant = api.characterSet?.variant;
    if (aliasBase && (variant === "ansi" || variant === "unicode"))
    {
      const aliasKey = `${moduleName}!${aliasBase}`;
      const variants = aliasVariants.get(aliasKey) ?? new Set();
      if (variants.has(variant))
      {
        errors.push(`generated API inventory duplicate ${variant} alias for ${aliasKey}`);
      }

      variants.add(variant);
      aliasVariants.set(aliasKey, variants);
    }
  }

  const records = collectApiRecords(apiDocuments, metadataIndex);
  for (const record of records)
  {
    const api = record.api;
    if (api.coverageStatus !== "smoke_verified")
    {
      continue;
    }

    const key = apiKey(api.module, api.name);
    const entry = apis.find((candidate) => apiKey(candidate.module, candidate.name) === key);
    if (!entry)
    {
      errors.push(`generated API inventory is missing smoke-verified API ${key}`);
      continue;
    }

    if (entry.hookability?.tier !== 0)
    {
      errors.push(`generated API inventory regressed smoke-verified API ${key} to tier ${entry.hookability?.tier}`);
    }
  }

  if ((inventory.summary?.currentlyEmittedByAgentHooks ?? 0) <= 0)
  {
    errors.push("generated API inventory does not report any currently emitted agent hooks");
  }

  if (!Array.isArray(inventory.nextFamilies) || inventory.nextFamilies.length === 0)
  {
    errors.push("generated API inventory does not identify next API families");
  }

  return errors;
}

async function fetchLearnPageStats(url)
{
  try
  {
    const html = await downloadText(url);
    const links = extractLinks(html);
    return {
      url,
      linkCount: links.length
    };
  }
  catch (error)
  {
    return {
      url,
      linkCount: 0,
      error: error.message
    };
  }
}

function normalizeWinmdMethods(methods)
{
  const normalized = methods
    .map((method) => {
      const moduleName = normalizeModuleName(method.module);
      const docUrl = docUrlFromAttributes(method.attributes ?? []);
      const header = headerFromDocUrl(docUrl);

      return {
        name: method.name,
        entryPoint: method.entryPoint || method.name,
        module: moduleName,
        namespace: method.namespace,
        family: familyFromNamespace(method.namespace),
        category: categoryFromNamespace(method.namespace),
        header,
        docUrl,
        availability: availabilityFromAttributes(method.attributes ?? []),
        callingConvention: method.callingConvention ?? "winapi",
        returnType: method.returnType ?? "void",
        errorSource: String(method.importAttributes ?? "").includes("SetLastError") ? "GetLastError" : errorSourceFromReturnType(method.returnType),
        parameters: (method.parameters ?? []).map(normalizeInventoryParameter),
        sourceKind: "win32metadata",
        attributeTags: attributeTags(method.attributes ?? [])
      };
    })
    .filter((method) => modulePattern.test(method.module) && /^[A-Za-z_][A-Za-z0-9_]*$/.test(method.name));

  const byKey = new Map();
  for (const method of normalized)
  {
    const key = apiKey(method.module, method.name);
    const current = byKey.get(key);
    byKey.set(key, current ? preferredMethod(current, method) : method);
  }

  return Array.from(byKey.values());
}

function buildInventoryEntryFromMethod(method, definition, sdkStats)
{
  const definitionApi = definition?.api ?? null;
  const headerName = method.header ? `${method.header.toLowerCase()}.h` : null;

  return {
    sourceKind: method.sourceKind,
    module: method.module,
    name: method.name,
    entryPoint: method.entryPoint,
    header: method.header,
    sdkHeaderPresent: headerName ? sdkStats.headerNames.has(headerName) : false,
    microsoftLearnUrl: method.docUrl,
    namespace: method.namespace,
    family: definitionApi?.family ?? method.family,
    category: definitionApi?.category ?? method.category,
    availability: method.availability,
    risk: definitionApi?.risk ?? null,
    callingConvention: normalizeCallingConvention(definitionApi?.callingConvention ?? method.callingConvention),
    returnType: definitionApi?.returnType ?? method.returnType,
    errorSource: definitionApi?.errorSource ?? method.errorSource,
    parameters: definitionApi?.parameters ?? method.parameters,
    definition: definition ? definitionSummary(definition) : null,
    attributeTags: method.attributeTags
  };
}

function buildInventoryEntryFromDefinition(record, sdkStats)
{
  const api = record.api;
  const moduleName = normalizeModuleName(api.module);

  return {
    sourceKind: "existing_definition",
    module: moduleName,
    name: api.name,
    entryPoint: api.name,
    header: null,
    sdkHeaderPresent: false,
    microsoftLearnUrl: null,
    namespace: null,
    family: api.family ?? "existing-definition",
    category: api.category ?? "existing-definition",
    availability: api.minWindowsVersion ?? null,
    risk: api.risk ?? "medium",
    callingConvention: normalizeCallingConvention(api.callingConvention),
    returnType: api.returnType,
    errorSource: api.errorSource,
    parameters: api.parameters ?? [],
    definition: definitionSummary(record),
    attributeTags: []
  };
}

function definitionSummary(record)
{
  return {
    id: record.assignment?.id ?? null,
    source: relativePath(record.filePath),
    hookPolicy: record.api.hookPolicy ?? "definition_only",
    coverageStatus: record.api.coverageStatus ?? "defined",
    family: record.api.family ?? "uncategorized",
    category: record.api.category ?? "uncategorized",
    risk: record.api.risk ?? "medium",
    parameterCount: (record.api.parameters ?? []).length
  };
}

function classifyHookability(entry)
{
  const definition = entry.definition;
  if (definition?.coverageStatus === "smoke_verified" || definition?.coverageStatus === "hooked")
  {
    return {
      tier: 0,
      label: "currently_hookable_decoded",
      reason: "existing agent hook emits decoded events"
    };
  }

  if (definition?.hookPolicy === "unsupported" || definition?.coverageStatus === "unsupported")
  {
    return {
      tier: 3,
      label: "unsupported_current_path",
      reason: "existing definition marks this API unsupported"
    };
  }

  if (!modulePattern.test(entry.module))
  {
    return {
      tier: 3,
      label: "unsupported_current_path",
      reason: "missing or invalid DLL module mapping"
    };
  }

  if (entry.module.startsWith("api-ms-") || entry.module.startsWith("ext-ms-"))
  {
    return {
      tier: 2,
      label: "dynamic_resolver_or_export_hook",
      reason: "API-set forwarder needs resolved host module strategy"
    };
  }

  const unsupportedSignal = unsupportedSignatureSignal(entry);
  if (unsupportedSignal)
  {
    return {
      tier: 3,
      label: "unsupported_current_path",
      reason: unsupportedSignal
    };
  }

  if (entry.parameters.length > 0)
  {
    return {
      tier: 1,
      label: "hookable_needs_decoder",
      reason: "DLL export and parameter metadata are present, but no decoded agent hook exists"
    };
  }

  return {
    tier: 2,
    label: "dynamic_resolver_or_export_hook",
    reason: "DLL export is known, but parameter metadata is missing or incomplete"
  };
}

function unsupportedSignatureSignal(entry)
{
  const text = [
    entry.name,
    entry.namespace ?? "",
    entry.returnType,
    ...entry.parameters.flatMap((parameter) => [parameter.name, parameter.type])
  ].join(" ");

  if (/\b(function_pointer|HOOKPROC|WNDPROC|TIMERPROC|APC_CALLBACK|PFN[A-Za-z0-9_]*)\b/.test(text))
  {
    return "callback or function-pointer signature needs a separate strategy";
  }

  if (/\b(MSG|WNDCLASSEX|CREATESTRUCT|HHOOK)\b/.test(text))
  {
    return "message or window-hook payloads are unsupported by the current decoder path";
  }

  for (const parameter of entry.parameters)
  {
    const bareType = String(parameter.type ?? "").replace(/[&*]+$/g, "");
    if (bareType.startsWith("I") && !primitiveTypes.has(bareType) && /^I[A-Z][A-Za-z0-9_]*$/.test(bareType))
    {
      return "COM interface payloads need a separate object strategy";
    }
  }

  return null;
}

function classifyRisk(entry)
{
  if (entry.risk)
  {
    return {
      level: entry.risk,
      signals: ["existing_definition"]
    };
  }

  const text = [
    entry.name,
    entry.namespace ?? "",
    entry.returnType,
    ...entry.parameters.flatMap((parameter) => [parameter.name, parameter.type])
  ].join(" ");
  const signals = [];

  if (/(Remote(Thread|Process)|ProcessMemory|Virtual[A-Za-z0-9_]*Ex|Queue[A-Za-z0-9_]*APC|WindowsHook|Debug[A-Za-z0-9_]*Process|TokenPrivileges|[A-Za-z0-9_]*(Service|SCManager)[A-Za-z0-9_]*)/.test(text))
  {
    signals.push("remote_mutation_or_privileged_control_pattern");
  }

  if (/\b(Security|Authorization|Authentication|Credentials|Cryptography|Certificate)\b/.test(text))
  {
    signals.push("security_or_crypto_namespace");
  }

  if (/\b(Password|Credential|Secret|PrivateKey|TOKEN_PRIVILEGES|SECURITY_DESCRIPTOR|SID|ACL)\b/.test(text))
  {
    signals.push("sensitive_payload_type");
  }

  if (signals.includes("remote_mutation_or_privileged_control_pattern") || signals.includes("sensitive_payload_type"))
  {
    return {
      level: "critical",
      signals
    };
  }

  if (signals.length > 0)
  {
    return {
      level: "high",
      signals
    };
  }

  if (entry.hookability.tier === 3)
  {
    return {
      level: "medium",
      signals: ["unsupported_signature_review"]
    };
  }

  return {
    level: "medium",
    signals: []
  };
}

function summarizeInventory(entries)
{
  const summary = {
    totalApis: entries.length,
    withModuleMapping: 0,
    withParameterMetadata: 0,
    withMicrosoftLearnDocs: 0,
    withSdkHeaderValidation: 0,
    currentlyEmittedByAgentHooks: 0,
    blockedByMissingDecoder: 0,
    blockedByMissingHookStrategy: 0,
    bySource: {
      win32Metadata: 0,
      existingDefinitionOnly: 0
    },
    byHookTier: {
      0: 0,
      1: 0,
      2: 0,
      3: 0
    },
    byCoverageStatus: {},
    byRisk: {},
    byModule: {},
    byFamily: {}
  };

  for (const entry of entries)
  {
    if (modulePattern.test(entry.module))
    {
      summary.withModuleMapping += 1;
    }

    if (entry.parameters.length > 0)
    {
      summary.withParameterMetadata += 1;
    }

    if (entry.microsoftLearnUrl)
    {
      summary.withMicrosoftLearnDocs += 1;
    }

    if (entry.sdkHeaderPresent)
    {
      summary.withSdkHeaderValidation += 1;
    }

    if (entry.sourceKind === "win32metadata")
    {
      summary.bySource.win32Metadata += 1;
    }
    else if (entry.sourceKind === "existing_definition")
    {
      summary.bySource.existingDefinitionOnly += 1;
    }

    const tier = entry.hookability.tier;
    summary.byHookTier[tier] = (summary.byHookTier[tier] ?? 0) + 1;
    if (tier === 0)
    {
      summary.currentlyEmittedByAgentHooks += 1;
    }
    else if (tier === 1)
    {
      summary.blockedByMissingDecoder += 1;
    }
    else
    {
      summary.blockedByMissingHookStrategy += 1;
    }

    const coverageStatus = entry.definition?.coverageStatus ?? "not_defined";
    summary.byCoverageStatus[coverageStatus] = (summary.byCoverageStatus[coverageStatus] ?? 0) + 1;
    summary.byRisk[entry.risk] = (summary.byRisk[entry.risk] ?? 0) + 1;
    summary.byModule[entry.module] = (summary.byModule[entry.module] ?? 0) + 1;
    summary.byFamily[entry.family] = (summary.byFamily[entry.family] ?? 0) + 1;
  }

  summary.byCoverageStatus = sortObject(summary.byCoverageStatus);
  summary.byRisk = sortObject(summary.byRisk);
  summary.byModule = sortObject(summary.byModule);
  summary.byFamily = sortObject(summary.byFamily);

  return summary;
}

function buildAnsiUnicodeIndex(entries)
{
  const namesByModule = new Map();
  for (const entry of entries)
  {
    const set = namesByModule.get(entry.module) ?? new Set();
    set.add(entry.name);
    namesByModule.set(entry.module, set);
  }

  return namesByModule;
}

function characterSetInfo(entry, namesByModule)
{
  const names = namesByModule.get(entry.module) ?? new Set();
  const name = entry.name;
  const hasAnsiAttribute = entry.attributeTags.includes("ansi");
  const hasUnicodeAttribute = entry.attributeTags.includes("unicode");
  const suffix = name.endsWith("A") ? "A" : name.endsWith("W") ? "W" : "";
  const aliasBase = suffix ? name.slice(0, -1) : null;
  const counterpart = suffix === "A" ? `${aliasBase}W` : suffix === "W" ? `${aliasBase}A` : null;
  const hasCounterpart = counterpart ? names.has(counterpart) : false;

  if (suffix === "A" && (hasCounterpart || hasAnsiAttribute))
  {
    return {
      variant: "ansi",
      aliasBase: aliasBase ?? name,
      counterpart: hasCounterpart ? counterpart : null
    };
  }

  if (suffix === "W" && (hasCounterpart || hasUnicodeAttribute))
  {
    return {
      variant: "unicode",
      aliasBase: aliasBase ?? name,
      counterpart: hasCounterpart ? counterpart : null
    };
  }

  return {
    variant: hasAnsiAttribute ? "ansi" : hasUnicodeAttribute ? "unicode" : "neutral",
    aliasBase: null,
    counterpart: null
  };
}

function preferredMethod(left, right)
{
  const leftScore = methodCompletenessScore(left);
  const rightScore = methodCompletenessScore(right);
  if (leftScore !== rightScore)
  {
    return rightScore > leftScore ? mergeDuplicateMethod(right, left) : mergeDuplicateMethod(left, right);
  }

  const leftSignature = signatureKey(left);
  const rightSignature = signatureKey(right);
  return leftSignature.localeCompare(rightSignature) <= 0 ? mergeDuplicateMethod(left, right) : mergeDuplicateMethod(right, left);
}

function methodCompletenessScore(method)
{
  let score = method.parameters.length * 10;
  if (method.docUrl)
  {
    score += 5;
  }

  if (method.header)
  {
    score += 3;
  }

  if (method.availability)
  {
    score += 1;
  }

  return score;
}

function mergeDuplicateMethod(primary, secondary)
{
  return {
    ...primary,
    docUrl: primary.docUrl ?? secondary.docUrl,
    header: primary.header ?? secondary.header,
    availability: primary.availability ?? secondary.availability,
    attributeTags: Array.from(new Set([...(primary.attributeTags ?? []), ...(secondary.attributeTags ?? [])])).sort(),
    metadataDuplicateCount: (primary.metadataDuplicateCount ?? 1) + (secondary.metadataDuplicateCount ?? 1)
  };
}

function signatureKey(method)
{
  return [
    method.returnType,
    ...method.parameters.map((parameter) => `${parameter.type}:${parameter.direction}`)
  ].join("|");
}

function normalizeInventoryParameter(parameter)
{
  return {
    name: sanitizeParameterName(parameter.name),
    type: parameter.type ?? "unknown",
    direction: normalizeDirection(parameter.direction),
    decodeHint: decodeHintForType(parameter.type)
  };
}

function sanitizeParameterName(name)
{
  const value = String(name ?? "").trim();
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(value))
  {
    return value;
  }

  return "parameter";
}

function normalizeDirection(direction)
{
  if (direction === "out" || direction === "inout")
  {
    return direction;
  }

  return "in";
}

function decodeHintForType(type)
{
  const value = String(type ?? "");
  if (/\b(PWSTR|PCWSTR|PSTR|PCSTR|BSTR)\b/.test(value))
  {
    return "string";
  }

  if (/\bHANDLE\b|^H[A-Z0-9_]+$/.test(value.replace(/[&*]+$/g, "")))
  {
    return "handle";
  }

  if (value.endsWith("*") || value.endsWith("&"))
  {
    return "pointer";
  }

  if (/\b(DWORD|UINT|INT|ULONG|SIZE_T|BOOL|HRESULT|NTSTATUS)\b/.test(value))
  {
    return "raw";
  }

  return "object";
}

function docUrlFromAttributes(attributes)
{
  for (const attribute of attributes)
  {
    if (!attribute.name.endsWith(".DocumentationAttribute"))
    {
      continue;
    }

    const url = (attribute.strings ?? []).find((value) => value.startsWith("https://learn.microsoft.com/"));
    if (url)
    {
      return url;
    }
  }

  return null;
}

function availabilityFromAttributes(attributes)
{
  for (const attribute of attributes)
  {
    if (!attribute.name.endsWith(".SupportedOSPlatformAttribute"))
    {
      continue;
    }

    const version = (attribute.strings ?? []).find((value) => /^windows\d/i.test(value));
    if (version)
    {
      return version;
    }
  }

  return null;
}

function attributeTags(attributes)
{
  const tags = [];
  for (const attribute of attributes)
  {
    if (attribute.name.endsWith(".AnsiAttribute"))
    {
      tags.push("ansi");
    }
    else if (attribute.name.endsWith(".UnicodeAttribute"))
    {
      tags.push("unicode");
    }
  }

  return tags;
}

function headerFromDocUrl(docUrl)
{
  if (!docUrl)
  {
    return null;
  }

  const match = docUrl.match(/\/windows\/win32\/api\/([^/]+)\//i);
  return match ? match[1].toLowerCase() : null;
}

function familyFromNamespace(namespaceName)
{
  return namespaceName
    .replace(/^Windows\.Win32\./, "")
    .split(".")[0]
    .replace(/([a-z0-9])([A-Z])/g, "$1-$2")
    .toLowerCase();
}

function categoryFromNamespace(namespaceName)
{
  return namespaceName
    .replace(/^Windows\.Win32\./, "")
    .split(".")
    .map((part) => part.replace(/([a-z0-9])([A-Z])/g, "$1-$2").toLowerCase())
    .join("/");
}

function errorSourceFromReturnType(returnType)
{
  if (returnType === "HRESULT")
  {
    return "HRESULT";
  }

  if (returnType === "NTSTATUS")
  {
    return "return_ntstatus";
  }

  return "none";
}

function normalizeCallingConvention(value)
{
  if (["stdcall", "ntapi", "cdecl", "fastcall", "thiscall", "winapi"].includes(value))
  {
    return value;
  }

  return "winapi";
}

function compareInventoryEntries(left, right)
{
  const moduleCompare = left.module.localeCompare(right.module);
  if (moduleCompare !== 0)
  {
    return moduleCompare;
  }

  return left.name.localeCompare(right.name);
}

function compareSdkVersions(left, right)
{
  const leftParts = left.split(".").map((value) => Number.parseInt(value, 10));
  const rightParts = right.split(".").map((value) => Number.parseInt(value, 10));
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index++)
  {
    const diff = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (diff !== 0)
    {
      return diff;
    }
  }

  return 0;
}

function sortObject(value)
{
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)));
}

function relativePathIfInsideRepo(filePath)
{
  const relative = path.relative(repoRoot, filePath);
  if (!relative.startsWith("..") && !path.isAbsolute(relative))
  {
    return relative.replaceAll("\\", "/");
  }

  return null;
}

function listFiles(directory)
{
  const results = [];
  const entries = fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));

  for (const entry of entries)
  {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory())
    {
      results.push(...listFiles(fullPath));
    }
    else if (entry.isFile())
    {
      results.push(fullPath);
    }
  }

  return results;
}

function extractLinks(html)
{
  const links = [];
  const regex = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>/gi;
  let match = null;

  while ((match = regex.exec(html)) !== null)
  {
    links.push(match[1]);
  }

  return Array.from(new Set(links)).sort();
}

function downloadText(url)
{
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { "User-Agent": "knmon-api-inventory/0.1" } }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location)
      {
        resolve(downloadText(new URL(response.headers.location, url).toString()));
        response.resume();
        return;
      }

      if (response.statusCode !== 200)
      {
        reject(new Error(`GET ${url} failed with HTTP ${response.statusCode}`));
        response.resume();
        return;
      }

      response.setEncoding("utf8");
      let body = "";
      response.on("data", (chunk) => {
        body += chunk;
      });
      response.on("end", () => {
        resolve(body);
      });
    }).on("error", reject);
  });
}

function downloadFile(url, outputPath)
{
  return new Promise((resolve, reject) => {
    const tempPath = `${outputPath}.tmp`;
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    const file = fs.createWriteStream(tempPath);

    https.get(url, { headers: { "User-Agent": "knmon-api-inventory/0.1" } }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location)
      {
        file.close();
        fs.rmSync(tempPath, { force: true });
        resolve(downloadFile(new URL(response.headers.location, url).toString(), outputPath));
        response.resume();
        return;
      }

      if (response.statusCode !== 200)
      {
        file.close();
        fs.rmSync(tempPath, { force: true });
        reject(new Error(`GET ${url} failed with HTTP ${response.statusCode}`));
        response.resume();
        return;
      }

      response.pipe(file);
      file.on("finish", () => {
        file.close();
        fs.renameSync(tempPath, outputPath);
        resolve(outputPath);
      });
    }).on("error", (error) => {
      file.close();
      fs.rmSync(tempPath, { force: true });
      reject(error);
    });
  });
}
