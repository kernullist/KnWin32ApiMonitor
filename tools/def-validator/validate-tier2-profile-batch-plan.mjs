import process from "node:process";

import {
  loadTier2HookPlan
} from "./tier2-hook-plan-system.mjs";
import {
  loadTier2ProfileBatchPlan,
  validateTier2ProfileBatchPlan
} from "./tier2-profile-batch-system.mjs";

const errors = validateTier2ProfileBatchPlan(loadTier2ProfileBatchPlan(), loadTier2HookPlan());

if (errors.length > 0)
{
  console.error("Tier 2 profile batch plan validation failed:");
  for (const error of errors)
  {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

const plan = loadTier2ProfileBatchPlan();
console.log(`Tier 2 profile batch plan validation passed. batches=${plan.summary.totalBatches} apiSetHosts=${plan.summary.apiSetHostBatches} returnOnlyModules=${plan.summary.returnOnlyModuleBatches} blocked=${plan.summary.blockedApis}`);
