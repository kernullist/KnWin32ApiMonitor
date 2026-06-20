import fs from "node:fs";
import process from "node:process";

import {
  buildTier1HookPlan,
  generatedTier1HookPlanPath,
  writeTier1HookPlan
} from "./tier1-hook-plan-system.mjs";
import {
  stableStringify
} from "./definition-system.mjs";

const args = new Set(process.argv.slice(2));

if (!args.has("--write") && !args.has("--check"))
{
  console.error("Usage: node tools/def-validator/generate-tier1-hook-plan.mjs --write|--check");
  process.exit(2);
}

const plan = buildTier1HookPlan();
const expected = stableStringify(plan);

if (args.has("--write"))
{
  writeTier1HookPlan(plan);
  console.log(`Generated tier 1 hook plan. tier1=${plan.summary.tier1Total} planned=${plan.summary.planned} generic=${plan.summary.genericDecoded} abiBlocked=${plan.summary.blockedByAbiPolicy}`);
}
else
{
  const actual = fs.existsSync(generatedTier1HookPlanPath) ? fs.readFileSync(generatedTier1HookPlanPath, "utf8") : "";
  if (actual !== expected)
  {
    console.error("Generated tier 1 hook plan is stale; run npm run defs:tier1-plan:generate.");
    process.exit(1);
  }

  console.log(`Tier 1 hook plan generation check passed. tier1=${plan.summary.tier1Total}`);
}
