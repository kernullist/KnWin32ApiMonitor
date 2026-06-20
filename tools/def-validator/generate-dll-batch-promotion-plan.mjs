import fs from "node:fs";
import process from "node:process";

import {
  buildMetadataIndex,
  loadApiDefinitionDocuments,
  loadMetadataDocuments,
  stableStringify
} from "./definition-system.mjs";
import {
  buildDllBatchPromotionPlan,
  generatedDllBatchPromotionPlanPath,
  writeDllBatchPromotionPlan
} from "./dll-batch-promotion-system.mjs";

const args = new Set(process.argv.slice(2));

if (!args.has("--write") && !args.has("--check"))
{
  console.error("Usage: node tools/def-validator/generate-dll-batch-promotion-plan.mjs --write|--check");
  process.exit(2);
}

const metadataLoad = loadMetadataDocuments();
const apiLoad = loadApiDefinitionDocuments();
const loadErrors = [...metadataLoad.errors, ...apiLoad.errors];
if (loadErrors.length > 0)
{
  console.error("Cannot generate DLL batch promotion plan because definitions are invalid:");
  for (const error of loadErrors)
  {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

const metadataIndex = buildMetadataIndex(metadataLoad.documents);
const plan = buildDllBatchPromotionPlan(apiLoad.documents, metadataIndex);
const expected = stableStringify(plan);

if (args.has("--write"))
{
  writeDllBatchPromotionPlan(plan);
  console.log(`Generated DLL batch promotion plan. dlls=${plan.summary.totalDlls} auto=${plan.summary.autoPromotable} manual=${plan.summary.manualDecoderRequired} blocked=${plan.summary.blockedByPayloadPolicy}`);
}
else
{
  const actual = fs.existsSync(generatedDllBatchPromotionPlanPath) ? fs.readFileSync(generatedDllBatchPromotionPlanPath, "utf8") : "";
  if (actual !== expected)
  {
    console.error("Generated DLL batch promotion plan is stale; run npm run defs:dll-batch-plan:generate.");
    process.exit(1);
  }

  console.log(`DLL batch promotion plan generation check passed. dlls=${plan.summary.totalDlls} auto=${plan.summary.autoPromotable}`);
}
