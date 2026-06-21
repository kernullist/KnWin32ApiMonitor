import {
  apiInventoryReportToMarkdown,
  loadApiInventory
} from "./api-inventory-system.mjs";
import {
  loadTier1HookPlan,
  tier1HookPlanToMarkdown,
  validateTier1HookPlan
} from "./tier1-hook-plan-system.mjs";
import {
  loadTier2HookPlan,
  tier2HookPlanToMarkdown,
  validateTier2HookPlan
} from "./tier2-hook-plan-system.mjs";
import {
  loadTier3HookPlan,
  tier3HookPlanToMarkdown,
  validateTier3HookPlan
} from "./tier3-hook-plan-system.mjs";
import {
  dllBatchPromotionPlanToMarkdown,
  loadDllBatchPromotionPlan,
  validateDllBatchPromotionPlan
} from "./dll-batch-promotion-system.mjs";
import {
  loadManualDecoderBatchPlan,
  manualDecoderBatchPlanToMarkdown,
  validateManualDecoderBatchPlan
} from "./manual-decoder-batch-system.mjs";
import {
  buildCoverageReport,
  coverageReportToMarkdown,
  stableStringify,
  validateRepositoryDefinitions
} from "./definition-system.mjs";

const args = new Set(process.argv.slice(2));
const result = validateRepositoryDefinitions();

if (result.errors.length > 0) {
  console.error("Definition coverage report failed:");
  for (const error of result.errors) {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

const report = buildCoverageReport(result.apiDocuments, result.metadataIndex);
const inventory = loadApiInventory();
const tier1HookPlan = loadTier1HookPlan();
const tier2HookPlan = loadTier2HookPlan();
const tier3HookPlan = loadTier3HookPlan();
const dllBatchPromotionPlan = loadDllBatchPromotionPlan();
const manualDecoderBatchPlan = loadManualDecoderBatchPlan();

if (args.has("--check")) {
  const requiredRuntimeHookableApis = 10000;
  if ((report.summary.runtimeHookableApis ?? 0) < requiredRuntimeHookableApis) {
    console.error(`Definition coverage report has only ${report.summary.runtimeHookableApis ?? 0} runtime-hookable APIs; expected at least ${requiredRuntimeHookableApis}.`);
    process.exit(1);
  }

  const requiredStatuses = ["definition_only", "hooked", "smoke_verified"];
  for (const status of requiredStatuses) {
    if (!Object.prototype.hasOwnProperty.call(report.summary.byCoverageStatus, status)) {
      console.error(`Definition coverage report is missing status bucket ${status}`);
      process.exit(1);
    }
  }

  const coverageTotal = Object.values(report.summary.byCoverageStatus).reduce((sum, count) => sum + count, 0);
  if (coverageTotal !== report.summary.totalApis) {
    console.error(`Definition coverage report total mismatch: total=${report.summary.totalApis} buckets=${coverageTotal}`);
    process.exit(1);
  }

  const implementedCoverage = (report.summary.byCoverageStatus.hooked ?? 0) + (report.summary.byCoverageStatus.smoke_verified ?? 0);
  if (implementedCoverage <= 0) {
    console.error("Definition coverage report has no hooked or smoke_verified APIs.");
    process.exit(1);
  }

  if (inventory === null) {
    console.error("Microsoft-source API inventory is missing; run npm run defs:inventory.");
    process.exit(1);
  }

  if ((inventory.summary?.totalApis ?? 0) <= report.summary.totalApis) {
    console.error("Microsoft-source API inventory does not expand beyond existing definitions.");
    process.exit(1);
  }

  if (!Array.isArray(inventory.nextFamilies) || inventory.nextFamilies.length === 0) {
    console.error("Microsoft-source API inventory does not report next API families.");
    process.exit(1);
  }

  const tier1PlanErrors = validateTier1HookPlan(tier1HookPlan, inventory);
  if (tier1PlanErrors.length > 0) {
    console.error("Tier 1 hook plan report check failed:");
    for (const error of tier1PlanErrors) {
      console.error(`- ${error}`);
    }
    process.exit(1);
  }

  const tier2PlanErrors = validateTier2HookPlan(tier2HookPlan, inventory);
  if (tier2PlanErrors.length > 0) {
    console.error("Tier 2 hook plan report check failed:");
    for (const error of tier2PlanErrors) {
      console.error(`- ${error}`);
    }
    process.exit(1);
  }

  const tier3PlanErrors = validateTier3HookPlan(tier3HookPlan, inventory);
  if (tier3PlanErrors.length > 0) {
    console.error("Tier 3 hook plan report check failed:");
    for (const error of tier3PlanErrors) {
      console.error(`- ${error}`);
    }
    process.exit(1);
  }

  const dllBatchPlanErrors = validateDllBatchPromotionPlan(dllBatchPromotionPlan, result.apiDocuments, result.metadataIndex);
  if (dllBatchPlanErrors.length > 0) {
    console.error("DLL batch promotion plan report check failed:");
    for (const error of dllBatchPlanErrors) {
      console.error(`- ${error}`);
    }
    process.exit(1);
  }

  const manualDecoderPlanErrors = validateManualDecoderBatchPlan(manualDecoderBatchPlan, dllBatchPromotionPlan);
  if (manualDecoderPlanErrors.length > 0) {
    console.error("Manual decoder batch plan report check failed:");
    for (const error of manualDecoderPlanErrors) {
      console.error(`- ${error}`);
    }
    process.exit(1);
  }

  console.log("Definition coverage report check passed.");
} else if (args.has("--json")) {
  process.stdout.write(stableStringify({
    definitions: report,
    microsoftSourceInventory: inventory,
    tier1HookPlan,
    tier2HookPlan,
    tier3HookPlan,
    dllBatchPromotionPlan,
    manualDecoderBatchPlan
  }));
} else {
  process.stdout.write(coverageReportToMarkdown(report));
  if (inventory === null) {
    process.stdout.write("\n# Microsoft Source API Inventory\n\nNot generated. Run `npm run defs:inventory`.\n");
  } else {
    process.stdout.write(`\n${apiInventoryReportToMarkdown(inventory)}`);
  }
  process.stdout.write(`\n${tier1HookPlanToMarkdown(tier1HookPlan)}`);
  process.stdout.write(`\n${tier2HookPlanToMarkdown(tier2HookPlan)}`);
  process.stdout.write(`\n${tier3HookPlanToMarkdown(tier3HookPlan)}`);
  process.stdout.write(`\n${dllBatchPromotionPlanToMarkdown(dllBatchPromotionPlan)}`);
  process.stdout.write(`\n${manualDecoderBatchPlanToMarkdown(manualDecoderBatchPlan)}`);
}
