import fs from "node:fs";
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

export const generatedTier1HookPlanPath = path.join(repoRoot, "generated", "tier1-hook-plan.json");

const highImpactFamilies = new Set([
  "system",
  "devices",
  "ui",
  "network-management",
  "graphics"
]);

const validDecoderReadiness = new Set([
  "custom_decoder",
  "generic_pointer_scalar",
  "generic_string_pointer",
  "blocked_abi_slot_limit"
]);

const validRisks = new Set(["low", "medium", "high", "critical"]);

export function loadTier1HookPlan()
{
  if (!fs.existsSync(generatedTier1HookPlanPath))
  {
    return null;
  }

  return readJson(generatedTier1HookPlanPath);
}

export function writeTier1HookPlan(plan)
{
  writeStableJson(generatedTier1HookPlanPath, plan);
}

export function buildTier1HookPlan(inventory = loadApiInventory())
{
  if (inventory === null)
  {
    throw new Error(`${relativePath(generatedApiInventoryPath)} is missing; run npm run defs:inventory.`);
  }

  const tier1Apis = (inventory.apis ?? [])
    .filter((entry) => entry.hookability?.tier === 1)
    .sort(comparePlanEntries);

  const apis = tier1Apis.map((entry, index) => buildPlanEntry(entry, index + 1));
  const summary = summarizePlanEntries(apis, inventory);

  return {
    schemaVersion: "0.1.0",
    source: {
      inventory: relativePath(generatedApiInventoryPath),
      inventorySchemaVersion: inventory.schemaVersion ?? null,
      microsoftSourceVersion: inventory.sources?.win32Metadata?.version ?? null
    },
    policy: {
      defaultProfile: "default",
      defaultTier1HookCount: 0,
      installMode: "opt_in",
      broadCoverageRequiresProfile: true,
      broadCoverageProfiles: ["tier1-all", "family:<name>", "module:<dll>", "risk:<level>"],
      highRiskPolicy: "explicit_allowlist_required",
      genericCapturePolicy: "scalar_handle_pointer_only",
      rawPayloadCapture: "disabled"
    },
    summary,
    representativeProfiles: {
      "system-safe": {
        family: "system",
        risks: ["low", "medium"],
        runtimeSmokeApi: "kernel32.dll!GetSystemTime"
      },
      "devices-safe": {
        family: "devices",
        risks: ["low", "medium"]
      },
      "ui-safe": {
        family: "ui",
        risks: ["low", "medium"]
      },
      "network-management-safe": {
        family: "network-management",
        risks: ["low", "medium"]
      },
      "graphics-safe": {
        family: "graphics",
        risks: ["low", "medium"]
      }
    },
    apis
  };
}

export function validateTier1HookPlan(plan = loadTier1HookPlan(), inventory = loadApiInventory())
{
  const errors = [];

  if (inventory === null)
  {
    return [`${relativePath(generatedApiInventoryPath)} is missing; run npm run defs:inventory`];
  }

  if (plan === null)
  {
    return [`${relativePath(generatedTier1HookPlanPath)} is missing; run npm run defs:tier1-plan:generate`];
  }

  if (plan.schemaVersion !== "0.1.0")
  {
    errors.push(`tier 1 hook plan has unsupported schema version ${plan.schemaVersion}`);
  }

  const actualText = fs.existsSync(generatedTier1HookPlanPath) ? fs.readFileSync(generatedTier1HookPlanPath, "utf8") : "";
  const expectedText = stableStringify(plan);
  if (actualText !== expectedText)
  {
    errors.push(`${relativePath(generatedTier1HookPlanPath)} is not stable-sorted; run npm run defs:tier1-plan:generate`);
  }

  const tier1Entries = (inventory.apis ?? []).filter((entry) => entry.hookability?.tier === 1);
  const tier0Entries = (inventory.apis ?? []).filter((entry) => entry.hookability?.tier === 0);
  const tier3Keys = new Set((inventory.apis ?? [])
    .filter((entry) => entry.hookability?.tier === 3)
    .map((entry) => apiKey(entry.module, entry.name)));
  const expectedTier1Keys = new Set(tier1Entries.map((entry) => apiKey(entry.module, entry.name)));
  const planEntries = plan.apis ?? [];
  const planKeys = new Set();
  const aliasVariants = new Map();

  if (plan.summary?.tier1Total !== tier1Entries.length)
  {
    errors.push(`tier 1 hook plan total mismatch: summary=${plan.summary?.tier1Total} inventory=${tier1Entries.length}`);
  }

  if (plan.summary?.planned !== planEntries.length)
  {
    errors.push(`tier 1 hook plan planned mismatch: summary=${plan.summary?.planned} apis=${planEntries.length}`);
  }

  if ((plan.summary?.enabledByDefault ?? -1) !== 0)
  {
    errors.push("tier 1 hook plan must not enable tier 1 hooks by default");
  }

  for (const entry of planEntries)
  {
    const key = apiKey(entry.module, entry.apiName);
    if (planKeys.has(key))
    {
      errors.push(`tier 1 hook plan duplicate API row ${key}`);
    }
    planKeys.add(key);

    if (!expectedTier1Keys.has(key))
    {
      errors.push(`tier 1 hook plan contains non-tier1 API ${key}`);
    }

    if (tier3Keys.has(key))
    {
      errors.push(`tier 1 hook plan accidentally promoted tier3 API ${key}`);
    }

    if (!entry.planId || !/^tier1-\d{5}$/.test(entry.planId))
    {
      errors.push(`tier 1 hook plan invalid planId for ${key}`);
    }

    if (entry.inventoryKey !== key)
    {
      errors.push(`tier 1 hook plan inventoryKey mismatch for ${key}: ${entry.inventoryKey}`);
    }

    if (entry.enabledByDefault !== false)
    {
      errors.push(`tier 1 hook plan default-enabled API is not allowed: ${key}`);
    }

    if (entry.installPolicy !== "opt_in")
    {
      errors.push(`tier 1 hook plan invalid install policy for ${key}: ${entry.installPolicy}`);
    }

    if (entry.hookStrategy !== "iat")
    {
      errors.push(`tier 1 hook plan invalid hook strategy for ${key}: ${entry.hookStrategy}`);
    }

    if (!validDecoderReadiness.has(entry.decoderReadiness))
    {
      errors.push(`tier 1 hook plan invalid decoder readiness for ${key}: ${entry.decoderReadiness}`);
    }

    if (!validRisks.has(entry.risk))
    {
      errors.push(`tier 1 hook plan invalid risk for ${key}: ${entry.risk}`);
    }

    if (!Array.isArray(entry.parameters) || entry.parameters.length !== entry.parameterCount)
    {
      errors.push(`tier 1 hook plan parameter count mismatch for ${key}`);
    }

    const aliasBase = entry.characterSet?.aliasBase;
    const variant = entry.characterSet?.variant;
    if (aliasBase && (variant === "ansi" || variant === "unicode"))
    {
      const aliasKey = `${normalizeModuleName(entry.module)}!${aliasBase}`;
      if (entry.aliasFamilyKey !== aliasKey)
      {
        errors.push(`tier 1 hook plan alias family mismatch for ${key}`);
      }

      const variants = aliasVariants.get(aliasKey) ?? new Set();
      if (variants.has(variant))
      {
        errors.push(`tier 1 hook plan duplicate ${variant} alias family row for ${aliasKey}`);
      }
      variants.add(variant);
      aliasVariants.set(aliasKey, variants);
    }
  }

  for (const expectedKey of expectedTier1Keys)
  {
    if (!planKeys.has(expectedKey))
    {
      errors.push(`tier 1 hook plan missing API ${expectedKey}`);
    }
  }

  for (const entry of tier0Entries)
  {
    const key = apiKey(entry.module, entry.name);
    if (planKeys.has(key))
    {
      errors.push(`tier 1 hook plan must not include tier0 API ${key}`);
    }

    if (entry.definition?.id == null || !["hooked", "smoke_verified"].includes(entry.definition?.coverageStatus))
    {
      errors.push(`tier0 metadata regression for ${key}`);
    }
  }

  return errors;
}

export function selectTier1HookPlan(plan, options = {})
{
  const allowlist = new Set((options.allowlist ?? []).map(normalizeAllowlistKey));
  const profiles = new Set(options.profiles ?? []);
  const modules = new Set((options.modules ?? []).map(normalizeModuleName));
  const families = new Set(options.families ?? []);
  const risks = new Set(options.risks ?? []);
  const includeRiskBlocked = options.includeRiskBlocked === true;
  const includeAbiBlocked = options.includeAbiBlocked === true;
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

    if (!selected)
    {
      continue;
    }

    const riskBlocked = entry.riskPolicy === "explicit_allowlist_required" && !explicitlyAllowed && !includeRiskBlocked;
    const abiBlocked = entry.decoderReadiness === "blocked_abi_slot_limit" && !includeAbiBlocked;
    const installable = !riskBlocked && !abiBlocked;
    hooks.push({
      inventoryKey: entry.inventoryKey,
      module: entry.module,
      apiName: entry.apiName,
      entryPoint: entry.entryPoint,
      family: entry.family,
      risk: entry.risk,
      hookStrategy: entry.hookStrategy,
      decoderReadiness: entry.decoderReadiness,
      installable,
      blockedReasons: [
        riskBlocked ? "risk_policy" : null,
        abiBlocked ? "abi_slot_limit" : null
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
      allowlist: Array.from(allowlist).sort(),
      includeRiskBlocked,
      includeAbiBlocked,
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

export function tier1HookPlanToMarkdown(plan)
{
  if (plan === null)
  {
    return "# Tier 1 Hook Plan\n\nNot generated. Run `npm run defs:tier1-plan:generate`.\n";
  }

  const lines = [
    "# Tier 1 Hook Plan",
    "",
    `Tier 1 total: ${plan.summary.tier1Total}`,
    `Tier 1 planned: ${plan.summary.planned}`,
    `Tier 1 enabled by default: ${plan.summary.enabledByDefault}`,
    `Generic decoder fallback ready: ${plan.summary.genericDecoded}`,
    `Custom decoded: ${plan.summary.customDecoded}`,
    `Blocked by ABI slot policy: ${plan.summary.blockedByAbiPolicy}`,
    `Blocked by risk policy: ${plan.summary.blockedByRiskPolicy}`,
    "",
    "## Profile Coverage",
    "",
    "| Profile | APIs |",
    "| --- | ---: |"
  ];

  for (const [profile, count] of Object.entries(plan.summary.byDefaultHookProfile ?? {}))
  {
    lines.push(`| ${profile} | ${count} |`);
  }

  lines.push("", "## Decoder Readiness", "");
  for (const [readiness, count] of Object.entries(plan.summary.byDecoderReadiness ?? {}))
  {
    lines.push(`- ${readiness}: ${count}`);
  }

  lines.push("");
  return lines.join("\n");
}

function buildPlanEntry(entry, ordinal)
{
  const key = apiKey(entry.module, entry.name);
  const defaultHookProfile = defaultProfileForEntry(entry);
  const decoderReadiness = decoderReadinessForEntry(entry);
  const riskPolicy = entry.risk === "critical" || entry.risk === "high" ? "explicit_allowlist_required" : "profile_opt_in";
  const parameters = entry.parameters.map((parameter, index) => ({
    index,
    name: parameter.name,
    type: parameter.type,
    direction: parameter.direction,
    decodeHint: parameter.decodeHint,
    capturePolicy: capturePolicyForParameter(parameter)
  }));

  return {
    planId: `tier1-${String(ordinal).padStart(5, "0")}`,
    inventoryKey: key,
    module: normalizeModuleName(entry.module),
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
    aliasFamilyKey: aliasFamilyKey(entry),
    risk: entry.risk,
    riskSignals: entry.riskSignals ?? [],
    defaultHookProfile,
    eligibleProfiles: eligibleProfilesForEntry(entry, defaultHookProfile),
    enabledByDefault: false,
    installPolicy: "opt_in",
    hookStrategy: "iat",
    runtimeStatus: "planned",
    decoderReadiness,
    riskPolicy,
    genericDecoder: {
      argumentCapture: "scalar_handle_pointer_only",
      stringCapture: "bounded_only_when_explicitly_safe",
      outputPointerCapture: "pointer_evidence_only",
      rawPayloadCapture: "disabled"
    },
    blockedReason: blockedReasonForEntry(entry, decoderReadiness, riskPolicy)
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

function defaultProfileForEntry(entry)
{
  if (entry.risk === "critical" || entry.risk === "high")
  {
    return "explicit-allowlist";
  }

  if (highImpactFamilies.has(entry.family))
  {
    return `${entry.family}-safe`;
  }

  return `${entry.family}-opt-in`;
}

function eligibleProfilesForEntry(entry, defaultHookProfile)
{
  const profiles = new Set([
    defaultHookProfile,
    "tier1-all",
    `family:${entry.family}`,
    `module:${normalizeModuleName(entry.module)}`,
    `risk:${entry.risk}`
  ]);

  if (entry.risk === "critical" || entry.risk === "high")
  {
    profiles.add("explicit-allowlist");
  }

  return Array.from(profiles).sort();
}

function decoderReadinessForEntry(entry)
{
  if ((entry.parameters ?? []).length > 8)
  {
    return "blocked_abi_slot_limit";
  }

  if ((entry.parameters ?? []).some((parameter) => parameter.decodeHint === "string"))
  {
    return "generic_string_pointer";
  }

  return "generic_pointer_scalar";
}

function blockedReasonForEntry(entry, decoderReadiness, riskPolicy)
{
  if (decoderReadiness === "blocked_abi_slot_limit")
  {
    return "parameter count exceeds current generic transport slot policy";
  }

  if (riskPolicy === "explicit_allowlist_required")
  {
    return "risk policy requires explicit allowlist before hook installation";
  }

  return null;
}

function capturePolicyForParameter(parameter)
{
  if (parameter.decodeHint === "raw" || parameter.decodeHint === "handle")
  {
    return "scalar";
  }

  if (parameter.decodeHint === "string")
  {
    return "pointer_or_bounded_safe_string";
  }

  return "pointer_evidence_only";
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

function aliasFamilyKey(entry)
{
  const aliasBase = entry.characterSet?.aliasBase;
  const variant = entry.characterSet?.variant;
  if (aliasBase && (variant === "ansi" || variant === "unicode"))
  {
    return `${normalizeModuleName(entry.module)}!${aliasBase}`;
  }

  return apiKey(entry.module, entry.name);
}

function summarizePlanEntries(entries, inventory)
{
  const summary = {
    inventoryTotal: inventory.summary?.totalApis ?? 0,
    tier1Total: entries.length,
    planned: entries.length,
    enabledByDefault: entries.filter((entry) => entry.enabledByDefault).length,
    genericDecoded: entries.filter((entry) => entry.decoderReadiness.startsWith("generic_")).length,
    customDecoded: entries.filter((entry) => entry.decoderReadiness === "custom_decoder").length,
    blockedByAbiPolicy: entries.filter((entry) => entry.decoderReadiness === "blocked_abi_slot_limit").length,
    blockedByDecoderPolicy: 0,
    blockedByRiskPolicy: entries.filter((entry) => entry.riskPolicy === "explicit_allowlist_required").length,
    byDefaultHookProfile: countBy(entries, (entry) => entry.defaultHookProfile),
    byDecoderReadiness: countBy(entries, (entry) => entry.decoderReadiness),
    byFamily: countBy(entries, (entry) => entry.family),
    byModule: countBy(entries, (entry) => entry.module),
    byRisk: countBy(entries, (entry) => entry.risk),
    byRuntimeStatus: countBy(entries, (entry) => entry.runtimeStatus)
  };

  return summary;
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
