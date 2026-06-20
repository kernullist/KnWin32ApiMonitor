import process from "node:process";

import {
  loadApiInventory
} from "./api-inventory-system.mjs";
import {
  loadTier2HookPlan,
  validateTier2HookPlan
} from "./tier2-hook-plan-system.mjs";

const inventory = loadApiInventory();
const plan = loadTier2HookPlan();
const errors = validateTier2HookPlan(plan, inventory);

if (errors.length > 0)
{
  console.error("Tier 2 hook plan validation failed:");
  for (const error of errors)
  {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

console.log(`Tier 2 hook plan validation passed. tier2=${plan.summary.tier2Total} apiSet=${plan.summary.apiSetForwarders} resolved=${plan.summary.apiSetResolved} returnOnly=${plan.summary.genericReturnOnly} riskBlocked=${plan.summary.blockedByRiskPolicy}`);
