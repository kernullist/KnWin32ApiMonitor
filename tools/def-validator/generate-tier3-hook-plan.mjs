import fs from "node:fs";
import process from "node:process";

import {
  buildTier3HookPlan,
  generatedTier3HookPlanPath,
  writeTier3HookPlan
} from "./tier3-hook-plan-system.mjs";
import {
  stableStringify
} from "./definition-system.mjs";

const args = new Set(process.argv.slice(2));

if (!args.has("--write") && !args.has("--check"))
{
  console.error("Usage: node tools/def-validator/generate-tier3-hook-plan.mjs --write|--check");
  process.exit(2);
}

const plan = buildTier3HookPlan();
const expected = stableStringify(plan);

if (args.has("--write"))
{
  writeTier3HookPlan(plan);
  console.log(`Generated tier 3 hook plan. tier3=${plan.summary.tier3Total} planned=${plan.summary.planned} defaultInstallable=${plan.summary.defaultInstallable} designReview=${plan.summary.requiredDesignReview}`);
}
else
{
  const actual = fs.existsSync(generatedTier3HookPlanPath) ? fs.readFileSync(generatedTier3HookPlanPath, "utf8") : "";
  if (actual !== expected)
  {
    console.error("Generated tier 3 hook plan is stale; run npm run defs:tier3-plan:generate.");
    process.exit(1);
  }

  console.log(`Tier 3 hook plan generation check passed. tier3=${plan.summary.tier3Total}`);
}
