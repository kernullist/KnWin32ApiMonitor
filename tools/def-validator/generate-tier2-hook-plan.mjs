import fs from "node:fs";
import process from "node:process";

import {
  buildTier2HookPlan,
  generatedTier2HookPlanPath,
  writeTier2HookPlan
} from "./tier2-hook-plan-system.mjs";
import {
  stableStringify
} from "./definition-system.mjs";

const args = new Set(process.argv.slice(2));

if (!args.has("--write") && !args.has("--check"))
{
  console.error("Usage: node tools/def-validator/generate-tier2-hook-plan.mjs --write|--check");
  process.exit(2);
}

const plan = buildTier2HookPlan();
const expected = stableStringify(plan);

if (args.has("--write"))
{
  writeTier2HookPlan(plan);
  console.log(`Generated tier 2 hook plan. tier2=${plan.summary.tier2Total} apiSet=${plan.summary.apiSetForwarders} resolved=${plan.summary.apiSetResolved} returnOnly=${plan.summary.genericReturnOnly}`);
}
else
{
  const actual = fs.existsSync(generatedTier2HookPlanPath) ? fs.readFileSync(generatedTier2HookPlanPath, "utf8") : "";
  if (actual !== expected)
  {
    console.error("Generated tier 2 hook plan is stale; run npm run defs:tier2-plan:generate.");
    process.exit(1);
  }

  console.log(`Tier 2 hook plan generation check passed. tier2=${plan.summary.tier2Total}`);
}
