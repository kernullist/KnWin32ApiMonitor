import fs from "node:fs";
import path from "node:path";

import {
  apiKey,
  normalizeModuleName,
  relativePath,
  repoRoot,
  stableStringify,
  writeStableJson
} from "./definition-system.mjs";
import {
  generatedTier2HookPlanPath,
  loadTier2HookPlan
} from "./tier2-hook-plan-system.mjs";

export const generatedTier2ProfileBatchPlanPath = path.join(repoRoot, "generated", "tier2-profile-batch-plan.json");

const validBatchKinds = new Set([
  "api_set_resolved_host",
  "missing_parameter_return_only_module",
  "blocked_api_set_unresolved",
  "blocked_manual_definition",
  "blocked_export_probe"
]);

export function loadTier2ProfileBatchPlan()
{
  if (!fs.existsSync(generatedTier2ProfileBatchPlanPath))
  {
    return null;
  }

  return JSON.parse(fs.readFileSync(generatedTier2ProfileBatchPlanPath, "utf8"));
}

export function writeTier2ProfileBatchPlan(plan)
{
  writeStableJson(generatedTier2ProfileBatchPlanPath, plan);
}

export function buildTier2ProfileBatchPlan(tier2Plan = loadTier2HookPlan())
{
  if (tier2Plan === null)
  {
    throw new Error(`${relativePath(generatedTier2HookPlanPath)} is missing; run npm run defs:tier2-plan:generate.`);
  }

  const apis = tier2Plan.apis ?? [];
  const apiSetBatches = buildApiSetHostBatches(apis);
  const returnOnlyBatches = buildReturnOnlyModuleBatches(apis);
  const blockedBatches = buildBlockedBatches(apis);
  const batches = [
    ...apiSetBatches,
    ...returnOnlyBatches,
    ...blockedBatches
  ].map((batch, index) => ({
    ...batch,
    batchId: `tier2-batch-${String(index + 1).padStart(4, "0")}`
  }));
  const summary = summarizeBatches(batches, tier2Plan);

  return {
    schemaVersion: "0.1.0",
    source: {
      tier2HookPlan: relativePath(generatedTier2HookPlanPath),
      tier2HookPlanSchemaVersion: tier2Plan.schemaVersion ?? null
    },
    policy: {
      installMode: "profile_batch_review",
      runtimeHooksEnabledByDefault: false,
      apiSetBoundary: "resolved_host_iat_only",
      returnOnlyBoundary: "no_argument_return_only",
      highRiskPolicy: "explicit_allowlist_required",
      rawPayloadCapture: "disabled",
      batchRule: "Review Tier 2 expansion by resolved host DLL for API-set rows and by source DLL for missing-parameter return-only rows."
    },
    representativeSmokeApis: representativeSmokeApis(tier2Plan),
    summary,
    batches
  };
}

export function validateTier2ProfileBatchPlan(plan = loadTier2ProfileBatchPlan(), tier2Plan = loadTier2HookPlan())
{
  const errors = [];

  if (tier2Plan === null)
  {
    return [`${relativePath(generatedTier2HookPlanPath)} is missing; run npm run defs:tier2-plan:generate`];
  }

  if (plan === null)
  {
    return [`${relativePath(generatedTier2ProfileBatchPlanPath)} is missing; run npm run defs:tier2-profile-batch-plan:generate`];
  }

  if (plan.schemaVersion !== "0.1.0")
  {
    errors.push(`Tier 2 profile batch plan has unsupported schema version ${plan.schemaVersion}`);
  }

  const actualText = fs.existsSync(generatedTier2ProfileBatchPlanPath) ? fs.readFileSync(generatedTier2ProfileBatchPlanPath, "utf8") : "";
  const expectedText = stableStringify(buildTier2ProfileBatchPlan(tier2Plan));
  if (actualText !== expectedText)
  {
    errors.push(`${relativePath(generatedTier2ProfileBatchPlanPath)} is stale; run npm run defs:tier2-profile-batch-plan:generate`);
  }

  if (plan.policy?.runtimeHooksEnabledByDefault !== false)
  {
    errors.push("Tier 2 profile batch plan must keep runtime hooks disabled by default");
  }

  const sourceEntries = new Map((tier2Plan.apis ?? []).map((entry) => [entry.inventoryKey, entry]));
  const seenApis = new Set();
  const batches = plan.batches ?? [];
  const counted = {
    apiSetHostBatches: 0,
    apiSetResolvedApis: 0,
    blockedApis: 0,
    blockedBatches: 0,
    explicitAllowlistRequiredApis: 0,
    returnOnlyApis: 0,
    returnOnlyModuleBatches: 0,
    totalApis: 0,
    totalBatches: batches.length
  };

  for (const batch of batches)
  {
    if (!validBatchKinds.has(batch.kind))
    {
      errors.push(`Tier 2 profile batch ${batch.batchId} has invalid kind ${batch.kind}`);
    }

    if (batch.runtimeHooksEnabledByDefault !== false)
    {
      errors.push(`Tier 2 profile batch ${batch.batchId} enables runtime hooks by default`);
    }

    const apis = batch.apis ?? [];
    if (batch.totalApis !== apis.length)
    {
      errors.push(`Tier 2 profile batch ${batch.batchId} totalApis mismatch: total=${batch.totalApis} apis=${apis.length}`);
    }

    const actualRisk = countBy(apis, (entry) => entry.risk);
    if (stableStringify(actualRisk) !== stableStringify(batch.byRisk ?? {}))
    {
      errors.push(`Tier 2 profile batch ${batch.batchId} byRisk mismatch`);
    }

    const actualFamily = countBy(apis, (entry) => entry.family);
    if (stableStringify(actualFamily) !== stableStringify(batch.byFamily ?? {}))
    {
      errors.push(`Tier 2 profile batch ${batch.batchId} byFamily mismatch`);
    }

    for (const api of apis)
    {
      const key = api.inventoryKey ?? apiKey(api.module, api.apiName);
      const source = sourceEntries.get(key);
      if (!source)
      {
        errors.push(`Tier 2 profile batch ${batch.batchId} contains unknown API ${key}`);
        continue;
      }

      if (seenApis.has(key))
      {
        errors.push(`Tier 2 profile batch plan duplicates API ${key}`);
      }
      seenApis.add(key);

      validateApiPlacement(errors, batch, api, source);
      counted.totalApis += 1;

      if (api.explicitAllowlistRequired)
      {
        counted.explicitAllowlistRequiredApis += 1;
      }
    }

    if (batch.kind === "api_set_resolved_host")
    {
      counted.apiSetHostBatches += 1;
      counted.apiSetResolvedApis += apis.length;
    }
    else if (batch.kind === "missing_parameter_return_only_module")
    {
      counted.returnOnlyModuleBatches += 1;
      counted.returnOnlyApis += apis.length;
    }
    else
    {
      counted.blockedBatches += 1;
      counted.blockedApis += apis.length;
    }
  }

  for (const key of sourceEntries.keys())
  {
    if (!seenApis.has(key))
    {
      errors.push(`Tier 2 profile batch plan missing API ${key}`);
    }
  }

  const summary = plan.summary ?? {};
  for (const [field, value] of Object.entries(counted))
  {
    if (summary[field] !== value)
    {
      errors.push(`Tier 2 profile batch summary ${field} mismatch: summary=${summary[field]} actual=${value}`);
    }
  }

  if (summary.runtimeHooksEnabledByDefault !== 0)
  {
    errors.push("Tier 2 profile batch plan summary must keep runtimeHooksEnabledByDefault at 0");
  }

  return errors;
}

export function selectTier2ProfileBatches(plan, options = {})
{
  const includeAll = options.includeAll === true;
  const batchIds = new Set(options.batchIds ?? []);
  const kinds = new Set(options.kinds ?? []);
  const profiles = new Set(options.profiles ?? []);
  const resolvedHosts = new Set((options.resolvedHosts ?? []).map(normalizeModuleName));
  const modules = new Set((options.modules ?? []).map(normalizeModuleName));
  const families = new Set(options.families ?? []);
  const risks = new Set(options.risks ?? []);
  const includeBlocked = options.includeBlocked === true;
  const limit = options.limit ?? 0;
  const selectedBatches = [];

  for (const batch of plan.batches ?? [])
  {
    let selected = includeAll;

    if (!selected && batchIds.has(batch.batchId))
    {
      selected = true;
    }

    if (!selected && kinds.has(batch.kind))
    {
      selected = true;
    }

    if (!selected && arraysIntersect(batch.profileSelectors ?? [], profiles))
    {
      selected = true;
    }

    if (!selected && resolvedHosts.has(normalizeModuleName(batch.resolvedHostModule)))
    {
      selected = true;
    }

    if (!selected && (modules.has(normalizeModuleName(batch.sourceModule)) || arraysIntersect(batch.sourceModules ?? [], modules, normalizeModuleName)))
    {
      selected = true;
    }

    if (!selected && arraysIntersect(Object.keys(batch.byFamily ?? {}), families))
    {
      selected = true;
    }

    if (!selected && arraysIntersect(Object.keys(batch.byRisk ?? {}), risks))
    {
      selected = true;
    }

    if (!selected)
    {
      continue;
    }

    if (!includeBlocked && batch.kind.startsWith("blocked_"))
    {
      continue;
    }

    selectedBatches.push(batch);

    if (limit > 0 && selectedBatches.length >= limit)
    {
      break;
    }
  }

  const selectedApis = selectedBatches.flatMap((batch) => batch.apis ?? []);

  return {
    schemaVersion: "0.1.0",
    selection: {
      includeAll,
      batchIds: Array.from(batchIds).sort(),
      kinds: Array.from(kinds).sort(),
      profiles: Array.from(profiles).sort(),
      resolvedHosts: Array.from(resolvedHosts).sort(),
      modules: Array.from(modules).sort(),
      families: Array.from(families).sort(),
      risks: Array.from(risks).sort(),
      includeBlocked,
      limit
    },
    summary: {
      selectedBatches: selectedBatches.length,
      selectedApis: selectedApis.length,
      installableWithoutAllowlistApis: selectedApis.filter((api) => api.installableWithoutAllowlist).length,
      explicitAllowlistRequiredApis: selectedApis.filter((api) => api.explicitAllowlistRequired).length,
      blockedApis: selectedApis.filter((api) => api.blockedReason !== null).length,
      runtimeHooksEnabledByDefault: 0,
      byBatchKind: countBy(selectedBatches, (batch) => batch.kind),
      byRisk: countBy(selectedApis, (api) => api.risk),
      byFamily: countBy(selectedApis, (api) => api.family),
      byResolvedHostModule: countBy(selectedApis.filter((api) => api.resolvedHostModule), (api) => api.resolvedHostModule),
      bySourceModule: countBy(selectedApis, (api) => api.module)
    },
    batches: selectedBatches
  };
}

function buildApiSetHostBatches(apis)
{
  const grouped = groupBy(
    apis.filter((entry) => entry.strategyClass === "api_set_forwarder" && entry.decoderReadiness === "api_set_resolved_generic"),
    (entry) => normalizeModuleName(entry.resolvedHostModule)
  );

  return Array.from(grouped.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([hostModule, entries]) => buildBatch({
      kind: "api_set_resolved_host",
      title: `API-set resolved host: ${hostModule}`,
      resolvedHostModule: hostModule,
      sourceModule: null,
      profileSelectors: [
        "api-set-safe",
        `host:${hostModule}`,
        "strategy:api_set_forwarder"
      ],
      requiredEvidence: [
        "LoadLibraryW/GetProcAddress/GetModuleHandleExW(FROM_ADDRESS) host resolution",
        "target import provider verification for the selected API-set DLL",
        "x64 and x86 native smoke before runtime profile expansion",
        "shared-memory drop and hook-overhead gates",
        "no raw payload, string body, credential, or arbitrary pointer-memory capture"
      ],
      entries
    }));
}

function buildReturnOnlyModuleBatches(apis)
{
  const grouped = groupBy(
    apis.filter((entry) => entry.strategyClass === "missing_parameter_metadata" && entry.decoderReadiness === "generic_return_only"),
    (entry) => normalizeModuleName(entry.module)
  );

  return Array.from(grouped.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([moduleName, entries]) => buildBatch({
      kind: "missing_parameter_return_only_module",
      title: `Missing-parameter return-only module: ${moduleName}`,
      resolvedHostModule: null,
      sourceModule: moduleName,
      profileSelectors: [
        "missing-metadata-safe",
        `module:${moduleName}`,
        "strategy:missing_parameter_metadata"
      ],
      requiredEvidence: [
        "zero-argument metadata evidence from Microsoft inventory",
        "return-only event rendering without argument slots",
        "x64 and x86 native smoke before runtime profile expansion",
        "shared-memory drop and hook-overhead gates",
        "no raw payload, string body, credential, or arbitrary pointer-memory capture"
      ],
      entries
    }));
}

function buildBlockedBatches(apis)
{
  const grouped = groupBy(
    apis.filter((entry) => isBlockedEntry(entry)),
    (entry) => blockedBatchKind(entry)
  );

  return Array.from(grouped.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([kind, entries]) => buildBatch({
      kind,
      title: blockedBatchTitle(kind),
      resolvedHostModule: null,
      sourceModule: null,
      profileSelectors: [],
      requiredEvidence: [
        "manual ABI review before runtime hook installation",
        "explicit allowlist and smoke evidence before promotion",
        "payload absence and hook-overhead gates"
      ],
      entries
    }));
}

function buildBatch(options)
{
  const entries = options.entries
    .slice()
    .sort(compareTier2Entries);
  const apis = entries.map(projectApi);

  return {
    batchId: "",
    kind: options.kind,
    title: options.title,
    runtimeHooksEnabledByDefault: false,
    installMode: options.kind.startsWith("blocked_") ? "blocked_until_review" : "opt_in_profile",
    resolvedHostModule: options.resolvedHostModule,
    sourceModule: options.sourceModule,
    profileSelectors: options.profileSelectors,
    requiredEvidence: options.requiredEvidence,
    totalApis: apis.length,
    installableWithoutAllowlist: apis.filter((entry) => entry.installableWithoutAllowlist).length,
    explicitAllowlistRequired: apis.filter((entry) => entry.explicitAllowlistRequired).length,
    blockedApis: apis.filter((entry) => entry.blockedReason !== null).length,
    byRisk: countBy(apis, (entry) => entry.risk),
    byFamily: countBy(apis, (entry) => entry.family),
    sourceModules: Array.from(new Set(apis.map((entry) => entry.module))).sort(),
    apis
  };
}

function projectApi(entry)
{
  const explicitAllowlistRequired = entry.riskPolicy === "explicit_allowlist_required";
  const blockedByDecoder = isBlockedEntry(entry);

  return {
    inventoryKey: entry.inventoryKey,
    module: entry.module,
    resolvedHostModule: entry.resolvedHostModule ?? null,
    apiName: entry.apiName,
    entryPoint: entry.entryPoint,
    family: entry.family,
    category: entry.category,
    risk: entry.risk,
    strategyClass: entry.strategyClass,
    hookStrategy: entry.hookStrategy,
    decoderReadiness: entry.decoderReadiness,
    runtimeStatus: entry.runtimeStatus,
    riskPolicy: entry.riskPolicy,
    returnCapturePolicy: entry.returnCapturePolicy,
    parameterCount: entry.parameterCount,
    installableWithoutAllowlist: !explicitAllowlistRequired && !blockedByDecoder,
    explicitAllowlistRequired,
    blockedReason: blockedByDecoder ? entry.blockedReason : null
  };
}

function summarizeBatches(batches, tier2Plan)
{
  const allApis = batches.flatMap((batch) => batch.apis ?? []);

  return {
    tier2PlanTotal: tier2Plan.summary?.tier2Total ?? 0,
    totalApis: allApis.length,
    totalBatches: batches.length,
    runtimeHooksEnabledByDefault: 0,
    apiSetHostBatches: batches.filter((batch) => batch.kind === "api_set_resolved_host").length,
    apiSetResolvedApis: allApis.filter((entry) => entry.decoderReadiness === "api_set_resolved_generic").length,
    returnOnlyModuleBatches: batches.filter((batch) => batch.kind === "missing_parameter_return_only_module").length,
    returnOnlyApis: allApis.filter((entry) => entry.decoderReadiness === "generic_return_only").length,
    blockedBatches: batches.filter((batch) => batch.kind.startsWith("blocked_")).length,
    blockedApis: allApis.filter((entry) => entry.blockedReason !== null).length,
    explicitAllowlistRequiredApis: allApis.filter((entry) => entry.explicitAllowlistRequired).length,
    installableWithoutAllowlistApis: allApis.filter((entry) => entry.installableWithoutAllowlist).length,
    byBatchKind: countBy(batches, (batch) => batch.kind),
    byRisk: countBy(allApis, (entry) => entry.risk),
    byFamily: countBy(allApis, (entry) => entry.family),
    byResolvedHostModule: countBy(allApis.filter((entry) => entry.resolvedHostModule), (entry) => entry.resolvedHostModule),
    bySourceModule: countBy(allApis, (entry) => entry.module)
  };
}

function representativeSmokeApis(tier2Plan)
{
  return Object.fromEntries(Object.entries(tier2Plan.representativeProfiles ?? {})
    .map(([profile, details]) => [profile, details.runtimeSmokeApi ?? null])
    .sort(([left], [right]) => left.localeCompare(right)));
}

function validateApiPlacement(errors, batch, api, source)
{
  if (api.module !== source.module || api.apiName !== source.apiName)
  {
    errors.push(`Tier 2 profile batch API projection mismatch for ${api.inventoryKey}`);
  }

  if (batch.kind === "api_set_resolved_host")
  {
    if (source.strategyClass !== "api_set_forwarder" || source.decoderReadiness !== "api_set_resolved_generic")
    {
      errors.push(`API-set host batch contains non-resolved API-set row ${source.inventoryKey}`);
    }

    if (normalizeModuleName(source.resolvedHostModule) !== normalizeModuleName(batch.resolvedHostModule))
    {
      errors.push(`API-set host batch resolved-host mismatch for ${source.inventoryKey}`);
    }
  }
  else if (batch.kind === "missing_parameter_return_only_module")
  {
    if (source.strategyClass !== "missing_parameter_metadata" || source.decoderReadiness !== "generic_return_only")
    {
      errors.push(`return-only batch contains non-return-only row ${source.inventoryKey}`);
    }

    if (source.parameterCount !== 0)
    {
      errors.push(`return-only batch contains argument-bearing row ${source.inventoryKey}`);
    }

    if (normalizeModuleName(source.module) !== normalizeModuleName(batch.sourceModule))
    {
      errors.push(`return-only batch source-module mismatch for ${source.inventoryKey}`);
    }
  }
  else if (!isBlockedEntry(source))
  {
    errors.push(`blocked batch contains installable row ${source.inventoryKey}`);
  }
}

function isBlockedEntry(entry)
{
  return entry.decoderReadiness === "blocked_api_set_unresolved" ||
    entry.decoderReadiness === "blocked_requires_manual_definition" ||
    entry.decoderReadiness === "blocked_export_probe_candidate";
}

function blockedBatchKind(entry)
{
  if (entry.decoderReadiness === "blocked_api_set_unresolved")
  {
    return "blocked_api_set_unresolved";
  }

  if (entry.decoderReadiness === "blocked_export_probe_candidate")
  {
    return "blocked_export_probe";
  }

  return "blocked_manual_definition";
}

function blockedBatchTitle(kind)
{
  if (kind === "blocked_api_set_unresolved")
  {
    return "Blocked API-set rows without resolved host evidence";
  }

  if (kind === "blocked_export_probe")
  {
    return "Blocked ordinal/export-probe candidates";
  }

  return "Blocked rows requiring manual definitions";
}

function compareTier2Entries(left, right)
{
  const moduleCompare = normalizeModuleName(left.module).localeCompare(normalizeModuleName(right.module));
  if (moduleCompare !== 0)
  {
    return moduleCompare;
  }

  return String(left.apiName).localeCompare(String(right.apiName));
}

function groupBy(entries, selector)
{
  const grouped = new Map();
  for (const entry of entries)
  {
    const key = selector(entry);
    if (!grouped.has(key))
    {
      grouped.set(key, []);
    }

    grouped.get(key).push(entry);
  }

  return grouped;
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

function arraysIntersect(values, filters, normalizer = (value) => value)
{
  if (filters.size === 0)
  {
    return false;
  }

  for (const value of values)
  {
    if (filters.has(normalizer(value)))
    {
      return true;
    }
  }

  return false;
}
