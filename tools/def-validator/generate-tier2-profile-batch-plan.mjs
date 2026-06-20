import fs from "node:fs";
import process from "node:process";

import {
  stableStringify
} from "./definition-system.mjs";
import {
  buildTier2ProfileBatchPlan,
  generatedTier2ProfileBatchPlanPath,
  writeTier2ProfileBatchPlan
} from "./tier2-profile-batch-system.mjs";

const args = new Set(process.argv.slice(2));

if (!args.has("--write") && !args.has("--check"))
{
  console.error("Usage: node tools/def-validator/generate-tier2-profile-batch-plan.mjs --write|--check");
  process.exit(2);
}

const plan = buildTier2ProfileBatchPlan();
const expected = stableStringify(plan);

if (args.has("--write"))
{
  writeTier2ProfileBatchPlan(plan);
  console.log(`Generated Tier 2 profile batch plan. batches=${plan.summary.totalBatches} apiSetHosts=${plan.summary.apiSetHostBatches} returnOnlyModules=${plan.summary.returnOnlyModuleBatches} blocked=${plan.summary.blockedApis}`);
}
else
{
  const actual = fs.existsSync(generatedTier2ProfileBatchPlanPath) ? fs.readFileSync(generatedTier2ProfileBatchPlanPath, "utf8") : "";
  if (actual !== expected)
  {
    console.error("Generated Tier 2 profile batch plan is stale; run npm run defs:tier2-profile-batch-plan:generate.");
    process.exit(1);
  }

  console.log(`Tier 2 profile batch plan generation check passed. batches=${plan.summary.totalBatches}`);
}
