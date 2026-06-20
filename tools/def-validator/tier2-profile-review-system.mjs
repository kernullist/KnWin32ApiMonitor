import fs from "node:fs";
import path from "node:path";

import {
  relativePath,
  repoRoot,
  stableStringify,
  writeStableJson
} from "./definition-system.mjs";
import {
  generatedTier2ProfileBatchPlanPath,
  loadTier2ProfileBatchPlan
} from "./tier2-profile-batch-system.mjs";

export const generatedTier2ProfileReviewManifestPath = path.join(repoRoot, "generated", "tier2-profile-review-manifest.json");

const initialCandidateMaxApisPerBatch = 2;
const validReviewClasses = new Set([
  "initial_candidate",
  "review_ready",
  "explicit_allowlist_required",
  "blocked"
]);

export function loadTier2ProfileReviewManifest()
{
  if (!fs.existsSync(generatedTier2ProfileReviewManifestPath))
  {
    return null;
  }

  return JSON.parse(fs.readFileSync(generatedTier2ProfileReviewManifestPath, "utf8"));
}

export function writeTier2ProfileReviewManifest(manifest)
{
  writeStableJson(generatedTier2ProfileReviewManifestPath, manifest);
}

export function buildTier2ProfileReviewManifest(batchPlan = loadTier2ProfileBatchPlan())
{
  if (batchPlan === null)
  {
    throw new Error(`${relativePath(generatedTier2ProfileBatchPlanPath)} is missing; run npm run defs:tier2-profile-batch-plan:generate.`);
  }

  const batches = (batchPlan.batches ?? [])
    .map(buildReviewBatch)
    .sort(compareReviewBatches);
  const summary = summarizeReviewBatches(batches, batchPlan);

  return {
    schemaVersion: "0.1.0",
    source: {
      tier2ProfileBatchPlan: relativePath(generatedTier2ProfileBatchPlanPath),
      tier2ProfileBatchPlanSchemaVersion: batchPlan.schemaVersion ?? null
    },
    policy: {
      installMode: "review_manifest_only",
      runtimeHooksEnabledByDefault: false,
      initialCandidateMaxApisPerBatch,
      initialCandidateRule: "No blocked APIs, no explicit allowlist requirements, and no more than two APIs in the resolved-host/source-DLL batch.",
      profileExpansionRule: "Promote only one reviewed batch at a time with target import/provider evidence, x64 and x86 native smoke, zero healthy-path drops, and hook-overhead review.",
      broadSelectionRule: "Do not install raw all-Tier-2 selectors from this manifest."
    },
    summary,
    batches
  };
}

export function validateTier2ProfileReviewManifest(manifest = loadTier2ProfileReviewManifest(), batchPlan = loadTier2ProfileBatchPlan())
{
  const errors = [];

  if (batchPlan === null)
  {
    return [`${relativePath(generatedTier2ProfileBatchPlanPath)} is missing; run npm run defs:tier2-profile-batch-plan:generate`];
  }

  if (manifest === null)
  {
    return [`${relativePath(generatedTier2ProfileReviewManifestPath)} is missing; run npm run defs:tier2-profile-review:generate`];
  }

  if (manifest.schemaVersion !== "0.1.0")
  {
    errors.push(`Tier 2 profile review manifest has unsupported schema version ${manifest.schemaVersion}`);
  }

  const actualText = fs.existsSync(generatedTier2ProfileReviewManifestPath) ? fs.readFileSync(generatedTier2ProfileReviewManifestPath, "utf8") : "";
  const expectedText = stableStringify(buildTier2ProfileReviewManifest(batchPlan));
  if (actualText !== expectedText)
  {
    errors.push(`${relativePath(generatedTier2ProfileReviewManifestPath)} is stale; run npm run defs:tier2-profile-review:generate`);
  }

  if (manifest.policy?.runtimeHooksEnabledByDefault !== false)
  {
    errors.push("Tier 2 profile review manifest must keep runtime hooks disabled by default");
  }

  if (manifest.policy?.initialCandidateMaxApisPerBatch !== initialCandidateMaxApisPerBatch)
  {
    errors.push("Tier 2 profile review manifest has unexpected initial candidate batch-size policy");
  }

  const expectedBatchIds = new Set((batchPlan.batches ?? []).map((batch) => batch.batchId));
  const seenBatchIds = new Set();

  for (const batch of manifest.batches ?? [])
  {
    if (!expectedBatchIds.has(batch.batchId))
    {
      errors.push(`Tier 2 profile review manifest contains unknown batch ${batch.batchId}`);
    }

    if (seenBatchIds.has(batch.batchId))
    {
      errors.push(`Tier 2 profile review manifest contains duplicate batch ${batch.batchId}`);
    }
    seenBatchIds.add(batch.batchId);

    if (!validReviewClasses.has(batch.reviewClass))
    {
      errors.push(`Tier 2 profile review manifest batch ${batch.batchId} has invalid review class ${batch.reviewClass}`);
    }

    if (batch.runtimeHooksEnabledByDefault !== false)
    {
      errors.push(`Tier 2 profile review manifest batch ${batch.batchId} enables runtime hooks by default`);
    }

    if (batch.reviewClass === "initial_candidate")
    {
      if (batch.blockedApis !== 0 || batch.explicitAllowlistRequired !== 0 || batch.totalApis > initialCandidateMaxApisPerBatch)
      {
        errors.push(`Tier 2 profile review manifest batch ${batch.batchId} violates initial candidate policy`);
      }
    }

    if (batch.reviewClass === "blocked" && batch.blockedApis <= 0)
    {
      errors.push(`Tier 2 profile review manifest batch ${batch.batchId} is blocked without blocked APIs`);
    }

    if (batch.reviewClass === "explicit_allowlist_required" && batch.explicitAllowlistRequired <= 0)
    {
      errors.push(`Tier 2 profile review manifest batch ${batch.batchId} is allowlist-gated without allowlist APIs`);
    }
  }

  for (const expectedBatchId of expectedBatchIds)
  {
    if (!seenBatchIds.has(expectedBatchId))
    {
      errors.push(`Tier 2 profile review manifest missing batch ${expectedBatchId}`);
    }
  }

  const expectedSummary = summarizeReviewBatches(manifest.batches ?? [], batchPlan);
  if (stableStringify(manifest.summary ?? {}) !== stableStringify(expectedSummary))
  {
    errors.push("Tier 2 profile review manifest summary is stale");
  }

  if ((manifest.summary?.runtimeHooksEnabledByDefault ?? -1) !== 0)
  {
    errors.push("Tier 2 profile review manifest summary must keep runtimeHooksEnabledByDefault at 0");
  }

  return errors;
}

function buildReviewBatch(batch)
{
  const reviewClass = reviewClassForBatch(batch);
  const targetModule = batch.resolvedHostModule ?? batch.sourceModule ?? null;

  return {
    batchId: batch.batchId,
    reviewClass,
    priority: priorityForBatch(batch, reviewClass),
    kind: batch.kind,
    targetModule,
    resolvedHostModule: batch.resolvedHostModule ?? null,
    sourceModule: batch.sourceModule ?? null,
    totalApis: batch.totalApis,
    installableWithoutAllowlist: batch.installableWithoutAllowlist,
    explicitAllowlistRequired: batch.explicitAllowlistRequired,
    blockedApis: batch.blockedApis,
    runtimeHooksEnabledByDefault: false,
    byRisk: batch.byRisk ?? {},
    byFamily: batch.byFamily ?? {},
    profileSelectors: batch.profileSelectors ?? [],
    requiredEvidence: batch.requiredEvidence ?? [],
    representativeApis: (batch.apis ?? []).slice(0, 5).map((api) => api.inventoryKey)
  };
}

function reviewClassForBatch(batch)
{
  if ((batch.blockedApis ?? 0) > 0 || String(batch.kind ?? "").startsWith("blocked_"))
  {
    return "blocked";
  }

  if ((batch.explicitAllowlistRequired ?? 0) > 0)
  {
    return "explicit_allowlist_required";
  }

  if ((batch.totalApis ?? 0) <= initialCandidateMaxApisPerBatch)
  {
    return "initial_candidate";
  }

  return "review_ready";
}

function priorityForBatch(batch, reviewClass)
{
  const basePriority = {
    initial_candidate: 10,
    review_ready: 40,
    explicit_allowlist_required: 70,
    blocked: 100
  }[reviewClass] ?? 100;

  const kindPenalty = batch.kind === "api_set_resolved_host" ? 0 : 5;
  const sizePenalty = Math.min(batch.totalApis ?? 0, 99);
  const allowlistPenalty = (batch.explicitAllowlistRequired ?? 0) * 10;
  const blockedPenalty = (batch.blockedApis ?? 0) * 20;

  return basePriority + kindPenalty + sizePenalty + allowlistPenalty + blockedPenalty;
}

function compareReviewBatches(left, right)
{
  return (left.priority - right.priority)
    || left.reviewClass.localeCompare(right.reviewClass)
    || left.kind.localeCompare(right.kind)
    || String(left.targetModule ?? "").localeCompare(String(right.targetModule ?? ""))
    || left.batchId.localeCompare(right.batchId);
}

function summarizeReviewBatches(batches, batchPlan)
{
  const summary = emptySummary(batchPlan);

  for (const batch of batches)
  {
    addBatchToSummary(summary, batch);
  }

  summary.byReviewClass = stableObject(summary.byReviewClass);
  summary.apisByReviewClass = stableObject(summary.apisByReviewClass);
  summary.byKind = stableObject(summary.byKind);
  summary.byRisk = stableObject(summary.byRisk);
  summary.byFamily = stableObject(summary.byFamily);

  return summary;
}

function emptySummary(batchPlan)
{
  return {
    sourceBatches: (batchPlan.batches ?? []).length,
    sourceApis: batchPlan.summary?.totalApis ?? 0,
    manifestBatches: 0,
    manifestApis: 0,
    initialCandidateBatches: 0,
    initialCandidateApis: 0,
    reviewReadyBatches: 0,
    reviewReadyApis: 0,
    allowlistGatedBatches: 0,
    allowlistGatedBatchApis: 0,
    explicitAllowlistRequiredApis: 0,
    blockedBatches: 0,
    blockedApis: 0,
    blockedBatchApis: 0,
    runtimeHooksEnabledByDefault: 0,
    byReviewClass: {},
    apisByReviewClass: {},
    byKind: {},
    byRisk: {},
    byFamily: {}
  };
}

function addBatchToSummary(summary, batch)
{
  summary.manifestBatches += 1;
  summary.manifestApis += batch.totalApis ?? 0;

  if (batch.reviewClass === "initial_candidate")
  {
    summary.initialCandidateBatches += 1;
    summary.initialCandidateApis += batch.totalApis ?? 0;
  }
  else if (batch.reviewClass === "review_ready")
  {
    summary.reviewReadyBatches += 1;
    summary.reviewReadyApis += batch.totalApis ?? 0;
  }
  else if (batch.reviewClass === "explicit_allowlist_required")
  {
    summary.allowlistGatedBatches += 1;
    summary.allowlistGatedBatchApis += batch.totalApis ?? 0;
    summary.explicitAllowlistRequiredApis += batch.explicitAllowlistRequired ?? 0;
  }
  else if (batch.reviewClass === "blocked")
  {
    summary.blockedBatches += 1;
    summary.blockedApis += batch.blockedApis ?? 0;
    summary.blockedBatchApis += batch.totalApis ?? 0;
  }

  increment(summary.byReviewClass, batch.reviewClass, 1);
  increment(summary.apisByReviewClass, batch.reviewClass, batch.totalApis ?? 0);
  increment(summary.byKind, batch.kind, 1);

  for (const [risk, count] of Object.entries(batch.byRisk ?? {}))
  {
    increment(summary.byRisk, risk, count);
  }

  for (const [family, count] of Object.entries(batch.byFamily ?? {}))
  {
    increment(summary.byFamily, family, count);
  }
}

function increment(target, key, value)
{
  target[key] = (target[key] ?? 0) + value;
}

function stableObject(value)
{
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)));
}
