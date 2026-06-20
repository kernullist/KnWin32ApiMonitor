import fs from "node:fs";
import process from "node:process";

import {
  buildApiInventory,
  collectMicrosoftLearnSourceStats,
  collectWindowsSdkHeaderStats,
  ensureWin32MetadataPackage,
  generatedApiInventoryPath,
  generatedApiInventoryReportPath,
  resolveLatestWin32MetadataVersion,
  runWinmdDump,
  writeApiInventoryArtifacts
} from "./api-inventory-system.mjs";
import {
  buildMetadataIndex,
  loadApiDefinitionDocuments,
  loadMetadataDocuments,
  stableStringify,
  validateApiDefinitionSemantics,
  validateMetadataSemantics
} from "./definition-system.mjs";

const args = process.argv.slice(2);
const argSet = new Set(args);

if (!argSet.has("--write") && !argSet.has("--check"))
{
  console.error("Usage: node tools/def-validator/generate-api-inventory.mjs --write|--check [--metadata-version version] [--package path]");
  process.exit(2);
}

const metadataVersionArg = valueAfter("--metadata-version");
const packageArg = valueAfter("--package");
const metadataVersion = metadataVersionArg ?? await resolveLatestWin32MetadataVersion();
const packagePath = packageArg ?? await ensureWin32MetadataPackage(metadataVersion);

if (!fs.existsSync(packagePath))
{
  console.error(`Win32Metadata package not found: ${packagePath}`);
  process.exit(1);
}

const metadataLoad = loadMetadataDocuments();
const apiLoad = loadApiDefinitionDocuments();
const metadataIndex = buildMetadataIndex(metadataLoad.documents);
const definitionErrors = [
  ...metadataLoad.errors,
  ...validateMetadataSemantics(metadataLoad.documents),
  ...apiLoad.errors,
  ...validateApiDefinitionSemantics(apiLoad.documents, metadataIndex, { requireIdAssignments: true })
];

if (definitionErrors.length > 0)
{
  console.error("API inventory generation failed because definitions are invalid:");
  for (const error of definitionErrors)
  {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

const winmdDump = runWinmdDump(packagePath);
const learnStats = await collectMicrosoftLearnSourceStats();
const sdkStats = collectWindowsSdkHeaderStats();
const { inventory, report } = buildApiInventory({
  winmdDump,
  win32MetadataVersion: metadataVersion,
  packagePath,
  learnStats,
  sdkStats,
  apiDocuments: apiLoad.documents,
  metadataIndex
});

if (argSet.has("--write"))
{
  writeApiInventoryArtifacts(inventory, report);
  console.log(`Generated API inventory. apis=${inventory.summary.totalApis} win32metadata=${inventory.summary.bySource.win32Metadata} tier0=${inventory.summary.byHookTier[0]} tier1=${inventory.summary.byHookTier[1]} tier2=${inventory.summary.byHookTier[2]} tier3=${inventory.summary.byHookTier[3]}`);
}
else
{
  const expectedInventory = stableStringify(inventory);
  const expectedReport = stableStringify(report);
  const actualInventory = fs.existsSync(generatedApiInventoryPath) ? fs.readFileSync(generatedApiInventoryPath, "utf8") : "";
  const actualReport = fs.existsSync(generatedApiInventoryReportPath) ? fs.readFileSync(generatedApiInventoryReportPath, "utf8") : "";

  if (actualInventory !== expectedInventory || actualReport !== expectedReport)
  {
    console.error("Generated API inventory artifacts are stale; run npm run defs:inventory.");
    process.exit(1);
  }

  console.log(`API inventory generation check passed. apis=${inventory.summary.totalApis}`);
}

function valueAfter(name)
{
  const index = args.indexOf(name);
  if (index < 0)
  {
    return null;
  }

  return args[index + 1] ?? null;
}
