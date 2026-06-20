import process from "node:process";

import {
  stableStringify
} from "./definition-system.mjs";
import {
  loadTier2ProfileBatchPlan,
  selectTier2ProfileBatches
} from "./tier2-profile-batch-system.mjs";

const args = process.argv.slice(2);
const plan = loadTier2ProfileBatchPlan();

if (plan === null)
{
  console.error("Tier 2 profile batch plan is missing; run npm run defs:tier2-profile-batch-plan:generate.");
  process.exit(1);
}

const selection = selectTier2ProfileBatches(plan, {
  includeAll: hasFlag("--all"),
  batchIds: valuesFor("--batch"),
  kinds: valuesFor("--kind"),
  profiles: valuesFor("--profile"),
  resolvedHosts: valuesFor("--host"),
  modules: valuesFor("--module"),
  families: valuesFor("--family"),
  risks: valuesFor("--risk"),
  includeBlocked: hasFlag("--include-blocked"),
  limit: numberValue("--limit")
});

if (hasFlag("--json"))
{
  process.stdout.write(stableStringify(selection));
}
else
{
  console.log(`Tier 2 profile batch selection: batches=${selection.summary.selectedBatches} apis=${selection.summary.selectedApis} installableWithoutAllowlist=${selection.summary.installableWithoutAllowlistApis} explicitAllowlist=${selection.summary.explicitAllowlistRequiredApis} blocked=${selection.summary.blockedApis}`);
  for (const batch of selection.batches.slice(0, 20))
  {
    const host = batch.resolvedHostModule ? ` host=${batch.resolvedHostModule}` : "";
    const source = batch.sourceModule ? ` module=${batch.sourceModule}` : "";
    const blocked = batch.blockedApis > 0 ? ` blocked=${batch.blockedApis}` : "";
    const allowlist = batch.explicitAllowlistRequired > 0 ? ` allowlist=${batch.explicitAllowlistRequired}` : "";
    console.log(`- ${batch.batchId} ${batch.kind}${host}${source} apis=${batch.totalApis}${allowlist}${blocked}`);
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
