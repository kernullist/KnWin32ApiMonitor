import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  apiKey,
  normalizeModuleName,
  readJson,
  relativePath,
  repoRoot,
  stableStringify,
  writeStableJson
} from "./definition-system.mjs";
import {
  generatedApiInventoryPath,
  loadApiInventory
} from "./api-inventory-system.mjs";

export const generatedTier2HookPlanPath = path.join(repoRoot, "generated", "tier2-hook-plan.json");

const validStrategyClasses = new Set([
  "api_set_forwarder",
  "missing_parameter_metadata",
  "ordinal_or_export_probe_candidate",
  "blocked_requires_manual_definition"
]);

const validDecoderReadiness = new Set([
  "api_set_resolved_generic",
  "generic_return_only",
  "blocked_api_set_unresolved",
  "blocked_export_probe_candidate",
  "blocked_requires_manual_definition"
]);

const validRisks = new Set(["low", "medium", "high", "critical"]);
const apiSetModulePattern = /^(api-ms-|ext-ms-)/i;

export function loadTier2HookPlan()
{
  if (!fs.existsSync(generatedTier2HookPlanPath))
  {
    return null;
  }

  return readJson(generatedTier2HookPlanPath);
}

export function writeTier2HookPlan(plan)
{
  writeStableJson(generatedTier2HookPlanPath, plan);
}

export function buildTier2HookPlan(inventory = loadApiInventory(), options = {})
{
  if (inventory === null)
  {
    throw new Error(`${relativePath(generatedApiInventoryPath)} is missing; run npm run defs:inventory.`);
  }

  const tier2Apis = (inventory.apis ?? [])
    .filter((entry) => entry.hookability?.tier === 2)
    .sort(comparePlanEntries);
  const apiSetEntries = tier2Apis.filter((entry) => isApiSetModule(entry.module));
  const apiSetResolutions = resolveApiSetForwarders(apiSetEntries, options);
  const apis = tier2Apis.map((entry, index) => buildPlanEntry(entry, index + 1, apiSetResolutions.get(apiKey(entry.module, entry.name))));
  const summary = summarizePlanEntries(apis, inventory);

  return {
    schemaVersion: "0.1.0",
    source: {
      inventory: relativePath(generatedApiInventoryPath),
      inventorySchemaVersion: inventory.schemaVersion ?? null,
      microsoftSourceVersion: inventory.sources?.win32Metadata?.version ?? null
    },
    policy: {
      defaultTier2HookCount: 0,
      installMode: "opt_in",
      broadCoverageRequiresProfile: true,
      broadCoverageProfiles: [
        "tier2-all",
        "strategy:<strategyClass>",
        "family:<name>",
        "module:<dll>",
        "host:<resolvedHostDll>",
        "risk:<level>"
      ],
      apiSetPolicy: "resolved_host_iat_only",
      missingParameterPolicy: "return_only_when_no_arguments",
      highRiskPolicy: "explicit_allowlist_required",
      rawPayloadCapture: "disabled"
    },
    representativeProfiles: {
      "api-set-safe": {
        strategyClass: "api_set_forwarder",
        risks: ["low", "medium"],
        runtimeSmokeApi: "api-ms-win-core-winrt-string-l1-1-0.dll!WindowsGetStringLen"
      },
      "missing-metadata-safe": {
        strategyClass: "missing_parameter_metadata",
        parameterCount: 0,
        runtimeSmokeApi: "advapi32.dll!RevertToSelf"
      }
    },
    summary,
    apis
  };
}

export function validateTier2HookPlan(plan = loadTier2HookPlan(), inventory = loadApiInventory())
{
  const errors = [];

  if (inventory === null)
  {
    return [`${relativePath(generatedApiInventoryPath)} is missing; run npm run defs:inventory`];
  }

  if (plan === null)
  {
    return [`${relativePath(generatedTier2HookPlanPath)} is missing; run npm run defs:tier2-plan:generate`];
  }

  if (plan.schemaVersion !== "0.1.0")
  {
    errors.push(`tier 2 hook plan has unsupported schema version ${plan.schemaVersion}`);
  }

  const actualText = fs.existsSync(generatedTier2HookPlanPath) ? fs.readFileSync(generatedTier2HookPlanPath, "utf8") : "";
  const expectedText = stableStringify(plan);
  if (actualText !== expectedText)
  {
    errors.push(`${relativePath(generatedTier2HookPlanPath)} is not stable-sorted; run npm run defs:tier2-plan:generate`);
  }

  const tier2Entries = (inventory.apis ?? []).filter((entry) => entry.hookability?.tier === 2);
  const expectedTier2Keys = new Set(tier2Entries.map((entry) => apiKey(entry.module, entry.name)));
  const nonTier2Keys = new Set((inventory.apis ?? [])
    .filter((entry) => entry.hookability?.tier !== 2)
    .map((entry) => apiKey(entry.module, entry.name)));
  const planEntries = plan.apis ?? [];
  const planKeys = new Set();

  if (plan.summary?.tier2Total !== tier2Entries.length)
  {
    errors.push(`tier 2 hook plan total mismatch: summary=${plan.summary?.tier2Total} inventory=${tier2Entries.length}`);
  }

  if (plan.summary?.planned !== planEntries.length)
  {
    errors.push(`tier 2 hook plan planned mismatch: summary=${plan.summary?.planned} apis=${planEntries.length}`);
  }

  if ((plan.summary?.enabledByDefault ?? -1) !== 0)
  {
    errors.push("tier 2 hook plan must not enable tier 2 hooks by default");
  }

  if ((plan.summary?.apiSetForwarders ?? 0) > 0 && (plan.summary?.apiSetResolved ?? 0) <= 0)
  {
    errors.push("tier 2 hook plan has API-set rows but no resolved host evidence");
  }

  for (const entry of planEntries)
  {
    const key = apiKey(entry.module, entry.apiName);
    if (planKeys.has(key))
    {
      errors.push(`tier 2 hook plan duplicate API row ${key}`);
    }
    planKeys.add(key);

    if (!expectedTier2Keys.has(key))
    {
      errors.push(`tier 2 hook plan contains non-tier2 API ${key}`);
    }

    if (nonTier2Keys.has(key))
    {
      errors.push(`tier 2 hook plan accidentally includes non-tier2 API ${key}`);
    }

    if (!entry.planId || !/^tier2-\d{5}$/.test(entry.planId))
    {
      errors.push(`tier 2 hook plan invalid planId for ${key}`);
    }

    if (entry.inventoryKey !== key)
    {
      errors.push(`tier 2 hook plan inventoryKey mismatch for ${key}: ${entry.inventoryKey}`);
    }

    if (entry.enabledByDefault !== false)
    {
      errors.push(`tier 2 hook plan default-enabled API is not allowed: ${key}`);
    }

    if (entry.installPolicy !== "opt_in")
    {
      errors.push(`tier 2 hook plan invalid install policy for ${key}: ${entry.installPolicy}`);
    }

    if (!validStrategyClasses.has(entry.strategyClass))
    {
      errors.push(`tier 2 hook plan invalid strategy class for ${key}: ${entry.strategyClass}`);
    }

    if (!validDecoderReadiness.has(entry.decoderReadiness))
    {
      errors.push(`tier 2 hook plan invalid decoder readiness for ${key}: ${entry.decoderReadiness}`);
    }

    if (!validRisks.has(entry.risk))
    {
      errors.push(`tier 2 hook plan invalid risk for ${key}: ${entry.risk}`);
    }

    if (!Array.isArray(entry.parameters) || entry.parameters.length !== entry.parameterCount)
    {
      errors.push(`tier 2 hook plan parameter count mismatch for ${key}`);
    }

    if (entry.strategyClass === "api_set_forwarder")
    {
      if (!entry.apiSetResolution || entry.apiSetResolution.requestedModule !== entry.module)
      {
        errors.push(`tier 2 API-set row missing resolution evidence for ${key}`);
      }

      if (entry.apiSetResolution?.status === "resolver_failed")
      {
        errors.push(`tier 2 API-set resolver failed for ${key}`);
      }

      if (entry.apiSetResolution?.status === "resolved")
      {
        if (!entry.resolvedHostModule)
        {
          errors.push(`tier 2 API-set row missing resolved host for ${key}`);
        }

        if (entry.hookStrategy !== "resolved_iat")
        {
          errors.push(`tier 2 API-set row must use resolved_iat for ${key}`);
        }
      }
      else if (entry.decoderReadiness !== "blocked_api_set_unresolved")
      {
        errors.push(`tier 2 unresolved API-set row must be blocked for ${key}`);
      }
    }

    if (entry.strategyClass === "missing_parameter_metadata")
    {
      if (entry.parameterCount !== 0 || entry.parameters.length !== 0)
      {
        errors.push(`tier 2 missing-parameter row must be return-only for ${key}`);
      }

      if (entry.decoderReadiness !== "generic_return_only")
      {
        errors.push(`tier 2 missing-parameter row must use generic_return_only for ${key}`);
      }
    }
  }

  for (const expectedKey of expectedTier2Keys)
  {
    if (!planKeys.has(expectedKey))
    {
      errors.push(`tier 2 hook plan missing API ${expectedKey}`);
    }
  }

  return errors;
}

export function selectTier2HookPlan(plan, options = {})
{
  const allowlist = new Set((options.allowlist ?? []).map(normalizeAllowlistKey));
  const profiles = new Set(options.profiles ?? []);
  const modules = new Set((options.modules ?? []).map(normalizeModuleName));
  const families = new Set(options.families ?? []);
  const risks = new Set(options.risks ?? []);
  const strategyClasses = new Set(options.strategyClasses ?? []);
  const resolvedHosts = new Set((options.resolvedHosts ?? []).map(normalizeModuleName));
  const includeRiskBlocked = options.includeRiskBlocked === true;
  const includeUnresolved = options.includeUnresolved === true;
  const includeManualBlocked = options.includeManualBlocked === true;
  const limit = options.limit ?? 0;
  const hooks = [];

  for (const entry of plan.apis ?? [])
  {
    const key = normalizeAllowlistKey(entry.inventoryKey);
    const explicitlyAllowed = allowlist.has(key);
    let selected = explicitlyAllowed;

    if (!selected && profiles.size > 0)
    {
      selected = (entry.eligibleProfiles ?? []).some((profile) => profiles.has(profile));
    }

    if (selected && modules.size > 0 && !modules.has(normalizeModuleName(entry.module)))
    {
      selected = false;
    }

    if (selected && families.size > 0 && !families.has(entry.family))
    {
      selected = false;
    }

    if (selected && risks.size > 0 && !risks.has(entry.risk))
    {
      selected = false;
    }

    if (selected && strategyClasses.size > 0 && !strategyClasses.has(entry.strategyClass))
    {
      selected = false;
    }

    if (selected && resolvedHosts.size > 0 && !resolvedHosts.has(normalizeModuleName(entry.resolvedHostModule)))
    {
      selected = false;
    }

    if (!selected)
    {
      continue;
    }

    const riskBlocked = entry.riskPolicy === "explicit_allowlist_required" && !explicitlyAllowed && !includeRiskBlocked;
    const unresolvedBlocked = entry.decoderReadiness === "blocked_api_set_unresolved" && !includeUnresolved;
    const manualBlocked = entry.decoderReadiness === "blocked_requires_manual_definition" && !includeManualBlocked;
    const exportProbeBlocked = entry.decoderReadiness === "blocked_export_probe_candidate" && !includeManualBlocked;
    const installable = !riskBlocked && !unresolvedBlocked && !manualBlocked && !exportProbeBlocked;

    hooks.push({
      inventoryKey: entry.inventoryKey,
      module: entry.module,
      resolvedHostModule: entry.resolvedHostModule,
      apiName: entry.apiName,
      entryPoint: entry.entryPoint,
      family: entry.family,
      risk: entry.risk,
      strategyClass: entry.strategyClass,
      hookStrategy: entry.hookStrategy,
      decoderReadiness: entry.decoderReadiness,
      installable,
      blockedReasons: [
        riskBlocked ? "risk_policy" : null,
        unresolvedBlocked ? "api_set_unresolved" : null,
        manualBlocked ? "manual_definition_required" : null,
        exportProbeBlocked ? "export_probe_not_enabled" : null
      ].filter(Boolean)
    });

    if (limit > 0 && hooks.length >= limit)
    {
      break;
    }
  }

  return {
    schemaVersion: "0.1.0",
    selection: {
      profiles: Array.from(profiles).sort(),
      modules: Array.from(modules).sort(),
      families: Array.from(families).sort(),
      risks: Array.from(risks).sort(),
      strategyClasses: Array.from(strategyClasses).sort(),
      resolvedHosts: Array.from(resolvedHosts).sort(),
      allowlist: Array.from(allowlist).sort(),
      includeRiskBlocked,
      includeUnresolved,
      includeManualBlocked,
      limit
    },
    summary: {
      selected: hooks.length,
      installable: hooks.filter((hook) => hook.installable).length,
      blocked: hooks.filter((hook) => !hook.installable).length
    },
    hooks
  };
}

export function tier2HookPlanToMarkdown(plan)
{
  if (plan === null)
  {
    return "# Tier 2 Hook Plan\n\nNot generated. Run `npm run defs:tier2-plan:generate`.\n";
  }

  const lines = [
    "# Tier 2 Hook Plan",
    "",
    `Tier 2 total: ${plan.summary.tier2Total}`,
    `Tier 2 planned: ${plan.summary.planned}`,
    `Tier 2 enabled by default: ${plan.summary.enabledByDefault}`,
    `API-set forwarders: ${plan.summary.apiSetForwarders}`,
    `API-set resolved: ${plan.summary.apiSetResolved}`,
    `Missing-parameter return-only: ${plan.summary.genericReturnOnly}`,
    `Blocked manual definitions: ${plan.summary.blockedManualDefinitions}`,
    "",
    "## Strategy Classes",
    ""
  ];

  for (const [strategyClass, count] of Object.entries(plan.summary.byStrategyClass ?? {}))
  {
    lines.push(`- ${strategyClass}: ${count}`);
  }

  lines.push("", "## Resolved Host Modules", "");
  for (const [hostModule, count] of Object.entries(plan.summary.byResolvedHostModule ?? {}))
  {
    lines.push(`- ${hostModule}: ${count}`);
  }

  lines.push("");
  return lines.join("\n");
}

function buildPlanEntry(entry, ordinal, apiSetResolution)
{
  const key = apiKey(entry.module, entry.name);
  const strategyClass = strategyClassForEntry(entry);
  const resolvedHostModule = apiSetResolution?.resolvedHostModule ?? null;
  const decoderReadiness = decoderReadinessForEntry(strategyClass, apiSetResolution);
  const riskPolicy = entry.risk === "critical" || entry.risk === "high" ? "explicit_allowlist_required" : "profile_opt_in";
  const defaultHookProfile = defaultProfileForEntry(entry, strategyClass, riskPolicy);
  const parameters = (entry.parameters ?? []).map((parameter, index) => ({
    index,
    name: parameter.name,
    type: parameter.type,
    direction: parameter.direction,
    decodeHint: parameter.decodeHint,
    capturePolicy: "metadata_pending"
  }));

  return {
    planId: `tier2-${String(ordinal).padStart(5, "0")}`,
    inventoryKey: key,
    module: normalizeModuleName(entry.module),
    resolvedHostModule,
    apiName: entry.name,
    entryPoint: entry.entryPoint ?? entry.name,
    header: entry.header ?? null,
    family: entry.family ?? "uncategorized",
    category: entry.category ?? "uncategorized",
    callingConvention: entry.callingConvention ?? "winapi",
    returnType: entry.returnType ?? "void",
    returnCapturePolicy: capturePolicyForReturn(entry.returnType),
    errorSource: entry.errorSource ?? "none",
    parameterCount: parameters.length,
    parameters,
    characterSet: entry.characterSet ?? { variant: "neutral", aliasBase: null, counterpart: null },
    risk: entry.risk,
    riskSignals: entry.riskSignals ?? [],
    strategyClass,
    apiSetResolution: apiSetResolution ?? null,
    defaultHookProfile,
    eligibleProfiles: eligibleProfilesForEntry(entry, strategyClass, defaultHookProfile, resolvedHostModule),
    enabledByDefault: false,
    installPolicy: "opt_in",
    hookStrategy: hookStrategyForEntry(strategyClass, apiSetResolution),
    runtimeStatus: runtimeStatusForEntry(strategyClass, apiSetResolution),
    decoderReadiness,
    riskPolicy,
    genericDecoder: genericDecoderPolicy(strategyClass, decoderReadiness),
    blockedReason: blockedReasonForEntry(decoderReadiness, riskPolicy)
  };
}

function resolveApiSetForwarders(entries, options = {})
{
  const results = new Map();

  for (const entry of entries)
  {
    results.set(apiKey(entry.module, entry.name), unresolvedApiSetResolution(entry, "not_probed"));
  }

  if (entries.length === 0)
  {
    return results;
  }

  if (options.resolveApiSets === false)
  {
    return results;
  }

  if (process.platform !== "win32")
  {
    for (const entry of entries)
    {
      results.set(apiKey(entry.module, entry.name), unresolvedApiSetResolution(entry, "skipped_non_windows"));
    }
    return results;
  }

  const probeRows = entries.map((entry) => ({
    key: apiKey(entry.module, entry.name),
    module: normalizeModuleName(entry.module),
    apiName: entry.name
  }));
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "knmon-tier2-api-set-"));
  const inputPath = path.join(tempRoot, "input.json");

  try
  {
    fs.writeFileSync(inputPath, JSON.stringify(probeRows), "utf8");
    const output = childProcess.execFileSync(
      "powershell",
      ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", apiSetResolverScript(inputPath)],
      {
        cwd: repoRoot,
        encoding: "utf8",
        env: {
          ...process.env,
          TMP: tempRoot,
          TEMP: tempRoot
        },
        maxBuffer: 32 * 1024 * 1024
      });

    const resolvedRows = JSON.parse(output.length === 0 ? "[]" : output);
    for (const row of Array.isArray(resolvedRows) ? resolvedRows : [resolvedRows])
    {
      const key = normalizeAllowlistKey(row.key);
      results.set(key, {
        evidenceMethod: "LoadLibraryW+GetProcAddress+GetModuleHandleExW(FROM_ADDRESS)",
        requestedModule: normalizeModuleName(row.module),
        requestedApi: row.apiName,
        status: row.status,
        resolvedHostModule: row.resolvedHostModule ?? null,
        loaderErrorCode: row.loaderErrorCode ?? 0
      });
    }
  }
  catch (error)
  {
    for (const entry of entries)
    {
      results.set(apiKey(entry.module, entry.name), unresolvedApiSetResolution(entry, "resolver_failed", String(error?.message ?? error)));
    }
  }
  finally
  {
    fs.rmSync(tempRoot, { force: true, recursive: true });
  }

  return results;
}

function apiSetResolverScript(inputPath)
{
  return `
$ErrorActionPreference = "Stop"
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class KnMonApiSetResolver
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibraryW(string lpLibFileName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool GetModuleHandleExW(uint dwFlags, IntPtr lpModuleName, out IntPtr phModule);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint GetModuleFileNameW(IntPtr hModule, StringBuilder lpFilename, uint nSize);
}
"@

$items = Get-Content -Raw -LiteralPath ${powerShellString(inputPath)} | ConvertFrom-Json
$results = New-Object System.Collections.Generic.List[object]

foreach ($item in @($items))
{
    $status = "unresolved"
    $hostModule = $null
    $errorCode = 0
    $module = [string]$item.module
    $apiName = [string]$item.apiName
    $loaded = [KnMonApiSetResolver]::LoadLibraryW($module)

    if ($loaded -eq [IntPtr]::Zero)
    {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }
    else
    {
        $proc = [KnMonApiSetResolver]::GetProcAddress($loaded, $apiName)
        if ($proc -eq [IntPtr]::Zero)
        {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $status = "export_missing"
        }
        else
        {
            $hostHandle = [IntPtr]::Zero
            $ok = [KnMonApiSetResolver]::GetModuleHandleExW(6, $proc, [ref]$hostHandle)
            if ($ok -and $hostHandle -ne [IntPtr]::Zero)
            {
                $buffer = New-Object System.Text.StringBuilder 32768
                $length = [KnMonApiSetResolver]::GetModuleFileNameW($hostHandle, $buffer, [uint32]$buffer.Capacity)
                if ($length -gt 0)
                {
                    $hostModule = [IO.Path]::GetFileName($buffer.ToString()).ToLowerInvariant()
                    $status = "resolved"
                }
                else
                {
                    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $status = "host_path_failed"
                }
            }
            else
            {
                $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                $status = "host_lookup_failed"
            }
        }
    }

    $results.Add([pscustomobject]@{
        key = [string]$item.key
        module = $module
        apiName = $apiName
        status = $status
        resolvedHostModule = $hostModule
        loaderErrorCode = $errorCode
    })
}

$results | ConvertTo-Json -Depth 4 -Compress
`;
}

function unresolvedApiSetResolution(entry, status, message = null)
{
  return {
    evidenceMethod: "LoadLibraryW+GetProcAddress+GetModuleHandleExW(FROM_ADDRESS)",
    requestedModule: normalizeModuleName(entry.module),
    requestedApi: entry.name,
    status,
    resolvedHostModule: null,
    loaderErrorCode: 0,
    message
  };
}

function strategyClassForEntry(entry)
{
  if (isApiSetModule(entry.module))
  {
    return "api_set_forwarder";
  }

  if (entry.hookability?.reason === "DLL export is known, but parameter metadata is missing or incomplete" && (entry.parameters ?? []).length === 0)
  {
    return "missing_parameter_metadata";
  }

  if (String(entry.entryPoint ?? "").startsWith("#") || Number.isInteger(entry.entryPoint))
  {
    return "ordinal_or_export_probe_candidate";
  }

  return "blocked_requires_manual_definition";
}

function decoderReadinessForEntry(strategyClass, apiSetResolution)
{
  if (strategyClass === "api_set_forwarder")
  {
    return apiSetResolution?.status === "resolved" ? "api_set_resolved_generic" : "blocked_api_set_unresolved";
  }

  if (strategyClass === "missing_parameter_metadata")
  {
    return "generic_return_only";
  }

  if (strategyClass === "ordinal_or_export_probe_candidate")
  {
    return "blocked_export_probe_candidate";
  }

  return "blocked_requires_manual_definition";
}

function hookStrategyForEntry(strategyClass, apiSetResolution)
{
  if (strategyClass === "api_set_forwarder")
  {
    return apiSetResolution?.status === "resolved" ? "resolved_iat" : "blocked";
  }

  if (strategyClass === "missing_parameter_metadata")
  {
    return "return_only_iat";
  }

  if (strategyClass === "ordinal_or_export_probe_candidate")
  {
    return "export_probe_candidate";
  }

  return "manual_definition_required";
}

function runtimeStatusForEntry(strategyClass, apiSetResolution)
{
  if (strategyClass === "api_set_forwarder")
  {
    return apiSetResolution?.status === "resolved" ? "planned_resolved_host" : "blocked_unresolved_host";
  }

  if (strategyClass === "missing_parameter_metadata")
  {
    return "planned_return_only";
  }

  return "blocked";
}

function defaultProfileForEntry(entry, strategyClass, riskPolicy)
{
  if (riskPolicy === "explicit_allowlist_required")
  {
    return "explicit-allowlist";
  }

  if (strategyClass === "api_set_forwarder")
  {
    return "api-set-safe";
  }

  if (strategyClass === "missing_parameter_metadata")
  {
    return "missing-metadata-safe";
  }

  return "manual-definition-required";
}

function eligibleProfilesForEntry(entry, strategyClass, defaultHookProfile, resolvedHostModule)
{
  const profiles = new Set([
    defaultHookProfile,
    "tier2-all",
    `strategy:${strategyClass}`,
    `family:${entry.family}`,
    `module:${normalizeModuleName(entry.module)}`,
    `risk:${entry.risk}`
  ]);

  if (strategyClass === "api_set_forwarder")
  {
    profiles.add("api-set-safe");
  }

  if (strategyClass === "missing_parameter_metadata")
  {
    profiles.add("missing-metadata-safe");
  }

  if (resolvedHostModule)
  {
    profiles.add(`host:${normalizeModuleName(resolvedHostModule)}`);
  }

  if (entry.risk === "critical" || entry.risk === "high")
  {
    profiles.add("explicit-allowlist");
  }

  return Array.from(profiles).sort();
}

function genericDecoderPolicy(strategyClass, decoderReadiness)
{
  if (strategyClass === "missing_parameter_metadata")
  {
    return {
      argumentCapture: "none",
      returnCapture: "scalar_or_pointer_only",
      rawPayloadCapture: "disabled"
    };
  }

  if (decoderReadiness === "api_set_resolved_generic")
  {
    return {
      argumentCapture: "scalar_handle_pointer_only",
      returnCapture: "scalar_or_pointer_only",
      rawPayloadCapture: "disabled"
    };
  }

  return {
    argumentCapture: "blocked",
    returnCapture: "blocked",
    rawPayloadCapture: "disabled"
  };
}

function blockedReasonForEntry(decoderReadiness, riskPolicy)
{
  if (decoderReadiness === "blocked_api_set_unresolved")
  {
    return "API-set host module could not be resolved on this Windows runtime";
  }

  if (decoderReadiness === "blocked_export_probe_candidate")
  {
    return "export probe strategy requires manual ABI validation";
  }

  if (decoderReadiness === "blocked_requires_manual_definition")
  {
    return "manual definition is required before hook installation";
  }

  if (riskPolicy === "explicit_allowlist_required")
  {
    return "risk policy requires explicit allowlist before hook installation";
  }

  return null;
}

function capturePolicyForReturn(returnType)
{
  const value = String(returnType ?? "void");
  if (value === "void")
  {
    return "void";
  }

  if (value.endsWith("*") || value.includes("HANDLE") || /^H[A-Z0-9_]+$/.test(value))
  {
    return "pointer_or_handle";
  }

  return "scalar";
}

function summarizePlanEntries(entries, inventory)
{
  return {
    inventoryTotal: inventory.summary?.totalApis ?? 0,
    tier2Total: entries.length,
    planned: entries.length,
    enabledByDefault: entries.filter((entry) => entry.enabledByDefault).length,
    apiSetForwarders: entries.filter((entry) => entry.strategyClass === "api_set_forwarder").length,
    apiSetResolved: entries.filter((entry) => entry.strategyClass === "api_set_forwarder" && entry.apiSetResolution?.status === "resolved").length,
    apiSetUnresolved: entries.filter((entry) => entry.strategyClass === "api_set_forwarder" && entry.apiSetResolution?.status !== "resolved").length,
    missingParameterMetadata: entries.filter((entry) => entry.strategyClass === "missing_parameter_metadata").length,
    ordinalOrExportProbeCandidate: entries.filter((entry) => entry.strategyClass === "ordinal_or_export_probe_candidate").length,
    blockedManualDefinitions: entries.filter((entry) => entry.decoderReadiness === "blocked_requires_manual_definition").length,
    genericReturnOnly: entries.filter((entry) => entry.decoderReadiness === "generic_return_only").length,
    blockedByRiskPolicy: entries.filter((entry) => entry.riskPolicy === "explicit_allowlist_required").length,
    byStrategyClass: countBy(entries, (entry) => entry.strategyClass),
    byDecoderReadiness: countBy(entries, (entry) => entry.decoderReadiness),
    byFamily: countBy(entries, (entry) => entry.family),
    byModule: countBy(entries, (entry) => entry.module),
    byResolvedHostModule: countBy(entries.filter((entry) => entry.resolvedHostModule), (entry) => entry.resolvedHostModule),
    byRisk: countBy(entries, (entry) => entry.risk),
    byRuntimeStatus: countBy(entries, (entry) => entry.runtimeStatus)
  };
}

function comparePlanEntries(left, right)
{
  const moduleCompare = normalizeModuleName(left.module).localeCompare(normalizeModuleName(right.module));
  if (moduleCompare !== 0)
  {
    return moduleCompare;
  }

  return String(left.name).localeCompare(String(right.name));
}

function countBy(entries, selector)
{
  const counts = {};
  for (const entry of entries)
  {
    const key = selector(entry);
    counts[key] = (counts[key] ?? 0) + 1;
  }

  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

function isApiSetModule(moduleName)
{
  return apiSetModulePattern.test(String(moduleName ?? ""));
}

function normalizeAllowlistKey(value)
{
  const text = String(value ?? "");
  const parts = text.split("!");
  if (parts.length !== 2)
  {
    return text;
  }

  return `${normalizeModuleName(parts[0])}!${parts[1]}`;
}

function powerShellString(value)
{
  return `'${String(value).replaceAll("'", "''")}'`;
}
