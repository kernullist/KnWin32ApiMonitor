import process from "node:process";

import {
  loadApiInventory
} from "./api-inventory-system.mjs";
import {
  loadTier3HookPlan,
  validateTier3HookPlan
} from "./tier3-hook-plan-system.mjs";

const inventory = loadApiInventory();
const plan = loadTier3HookPlan();
const errors = validateTier3HookPlan(plan, inventory);

if (errors.length > 0)
{
  console.error("Tier 3 hook plan validation failed:");
  for (const error of errors)
  {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

console.log(`Tier 3 hook plan validation passed. tier3=${plan.summary.tier3Total} planned=${plan.summary.planned} defaultInstallable=${plan.summary.defaultInstallable} designReview=${plan.summary.requiredDesignReview}`);
