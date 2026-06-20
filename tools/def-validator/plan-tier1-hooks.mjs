import process from "node:process";

import {
  loadTier1HookPlan,
  selectTier1HookPlan
} from "./tier1-hook-plan-system.mjs";
import {
  stableStringify
} from "./definition-system.mjs";

const args = process.argv.slice(2);
const plan = loadTier1HookPlan();

if (plan === null)
{
  console.error("Tier 1 hook plan is missing; run npm run defs:tier1-plan:generate.");
  process.exit(1);
}

const selection = selectTier1HookPlan(plan, {
  profiles: valuesFor("--profile"),
  modules: valuesFor("--module"),
  families: valuesFor("--family"),
  risks: valuesFor("--risk"),
  allowlist: valuesFor("--allowlist"),
  includeRiskBlocked: hasFlag("--include-risk-blocked"),
  includeAbiBlocked: hasFlag("--include-abi-blocked"),
  limit: numberValue("--limit")
});

if (hasFlag("--json"))
{
  process.stdout.write(stableStringify(selection));
}
else
{
  console.log(`Tier 1 hook selection: selected=${selection.summary.selected} installable=${selection.summary.installable} blocked=${selection.summary.blocked}`);
  for (const hook of selection.hooks.slice(0, 20))
  {
    const suffix = hook.installable ? "" : ` blocked=${hook.blockedReasons.join(",")}`;
    console.log(`- ${hook.module}!${hook.apiName} profile=${hook.family} risk=${hook.risk} decoder=${hook.decoderReadiness}${suffix}`);
  }
}

function valuesFor(name)
{
  const values = [];
  for (let index = 0; index < args.length; ++index)
  {
    if (args[index] !== name || index + 1 >= args.length)
    {
      continue;
    }

    for (const value of args[index + 1].split(","))
    {
      const trimmed = value.trim();
      if (trimmed.length > 0)
      {
        values.push(trimmed);
      }
    }
  }

  return values;
}

function hasFlag(name)
{
  return args.includes(name);
}

function numberValue(name)
{
  const index = args.indexOf(name);
  if (index < 0 || index + 1 >= args.length)
  {
    return 0;
  }

  const parsed = Number.parseInt(args[index + 1], 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}
