import process from "node:process";

import {
  loadTier3HookPlan,
  selectTier3HookPlan
} from "./tier3-hook-plan-system.mjs";
import {
  stableStringify
} from "./definition-system.mjs";

const args = process.argv.slice(2);
const plan = loadTier3HookPlan();

if (plan === null)
{
  console.error("Tier 3 hook plan is missing; run npm run defs:tier3-plan:generate.");
  process.exit(1);
}

const selection = selectTier3HookPlan(plan, {
  modules: valuesFor("--module"),
  families: valuesFor("--family"),
  risks: valuesFor("--risk"),
  classifications: valuesFor("--classification"),
  allowlist: valuesFor("--allowlist"),
  limit: numberValue("--limit")
});

if (hasFlag("--json"))
{
  process.stdout.write(stableStringify(selection));
}
else
{
  console.log(`Tier 3 hook planning report: selected=${selection.summary.selected} installable=${selection.summary.installable} blocked=${selection.summary.blocked}`);
  console.log("Default runtime enablement: blocked; Tier 3 APIs require explicit allowlist plus design review before any runtime hook work.");
  printCounts("Classification", selection.groupedCounts.byClassification);
  printCounts("Family", selection.groupedCounts.byFamily);
  printCounts("Risk", selection.groupedCounts.byRisk);
  printCounts("Module", topCounts(selection.groupedCounts.byModule, 20));

  const examples = selection.hooks.slice(0, 20);
  if (examples.length > 0)
  {
    console.log("Examples:");
    for (const hook of examples)
    {
      console.log(`- ${hook.module}!${hook.apiName} classification=${hook.classification} risk=${hook.risk} blocked=${hook.blockedReasons.join(",")}`);
    }
  }
}

function printCounts(title, counts)
{
  console.log(`${title}:`);
  for (const [key, count] of Object.entries(counts ?? {}))
  {
    console.log(`- ${key}: ${count}`);
  }
}

function topCounts(counts, limit)
{
  return Object.fromEntries(Object.entries(counts ?? {})
    .sort((left, right) => {
      const countCompare = right[1] - left[1];
      if (countCompare !== 0)
      {
        return countCompare;
      }

      return left[0].localeCompare(right[0]);
    })
    .slice(0, limit)
    .sort(([left], [right]) => left.localeCompare(right)));
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
