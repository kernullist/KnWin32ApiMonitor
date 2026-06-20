import fs from "node:fs";
import process from "node:process";

import {
  buildMetadataIndex,
  loadApiDefinitionDocuments,
  loadMetadataDocuments,
  stableStringify
} from "./definition-system.mjs";
import {
  buildDllBatchPromotionPlan
} from "./dll-batch-promotion-system.mjs";
import {
  buildManualDecoderBatchPlan,
  generatedManualDecoderBatchPlanPath,
  writeManualDecoderBatchPlan
} from "./manual-decoder-batch-system.mjs";

const args = new Set(process.argv.slice(2));

if (!args.has("--write") && !args.has("--check"))
{
  console.error("Usage: node tools/def-validator/generate-manual-decoder-batch-plan.mjs --write|--check");
  process.exit(2);
}

const metadataLoad = loadMetadataDocuments();
const apiLoad = loadApiDefinitionDocuments();
const loadErrors = [...metadataLoad.errors, ...apiLoad.errors];
if (loadErrors.length > 0)
{
  console.error("Cannot generate manual decoder batch plan because definitions are invalid:");
  for (const error of loadErrors)
  {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

const metadataIndex = buildMetadataIndex(metadataLoad.documents);
const dllBatchPromotionPlan = buildDllBatchPromotionPlan(apiLoad.documents, metadataIndex);
const plan = buildManualDecoderBatchPlan(dllBatchPromotionPlan);
const expected = stableStringify(plan);

if (args.has("--write"))
{
  writeManualDecoderBatchPlan(plan);
  console.log(`Generated manual decoder batch plan. dlls=${plan.summary.totalDlls} manual=${plan.summary.manualDecoderRequired} payloadBlocked=${plan.summary.payloadBlockedInManualDlls}`);
}
else
{
  const actual = fs.existsSync(generatedManualDecoderBatchPlanPath) ? fs.readFileSync(generatedManualDecoderBatchPlanPath, "utf8") : "";
  if (actual !== expected)
  {
    console.error("Generated manual decoder batch plan is stale; run npm run defs:manual-decoder-plan:generate.");
    process.exit(1);
  }

  console.log(`Manual decoder batch plan generation check passed. dlls=${plan.summary.totalDlls} manual=${plan.summary.manualDecoderRequired}`);
}
