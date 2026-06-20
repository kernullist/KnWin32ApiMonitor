import process from "node:process";

import {
  loadApiInventory
} from "./api-inventory-system.mjs";
import {
  loadTier1HookPlan,
  validateTier1HookPlan
} from "./tier1-hook-plan-system.mjs";

const inventory = loadApiInventory();
const plan = loadTier1HookPlan();
const errors = validateTier1HookPlan(plan, inventory);

if (errors.length > 0)
{
  console.error("Tier 1 hook plan validation failed:");
  for (const error of errors)
  {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

console.log(`Tier 1 hook plan validation passed. tier1=${plan.summary.tier1Total} planned=${plan.summary.planned} generic=${plan.summary.genericDecoded} abiBlocked=${plan.summary.blockedByAbiPolicy} riskBlocked=${plan.summary.blockedByRiskPolicy}`);
