import process from "node:process";

import {
  buildMetadataIndex,
  loadApiDefinitionDocuments,
  loadMetadataDocuments
} from "./definition-system.mjs";
import {
  buildDllBatchPromotionPlan
} from "./dll-batch-promotion-system.mjs";
import {
  loadManualDecoderBatchPlan,
  validateManualDecoderBatchPlan
} from "./manual-decoder-batch-system.mjs";

const metadataLoad = loadMetadataDocuments();
const apiLoad = loadApiDefinitionDocuments();
const loadErrors = [...metadataLoad.errors, ...apiLoad.errors];
if (loadErrors.length > 0)
{
  console.error("Cannot validate manual decoder batch plan because definitions are invalid:");
  for (const error of loadErrors)
  {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

const metadataIndex = buildMetadataIndex(metadataLoad.documents);
const dllBatchPromotionPlan = buildDllBatchPromotionPlan(apiLoad.documents, metadataIndex);
const plan = loadManualDecoderBatchPlan();
const errors = validateManualDecoderBatchPlan(plan, dllBatchPromotionPlan);
if (errors.length > 0)
{
  console.error("Manual decoder batch plan validation failed:");
  for (const error of errors)
  {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

console.log(`Manual decoder batch plan validation passed. dlls=${plan.summary.totalDlls} manual=${plan.summary.manualDecoderRequired} runtimeDefault=${plan.summary.runtimeHooksEnabledByDefault}`);
