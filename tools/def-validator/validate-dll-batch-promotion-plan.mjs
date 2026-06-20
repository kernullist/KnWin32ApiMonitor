import process from "node:process";

import {
  buildMetadataIndex,
  loadApiDefinitionDocuments,
  loadMetadataDocuments
} from "./definition-system.mjs";
import {
  loadDllBatchPromotionPlan,
  validateDllBatchPromotionPlan
} from "./dll-batch-promotion-system.mjs";

const metadataLoad = loadMetadataDocuments();
const apiLoad = loadApiDefinitionDocuments();
const loadErrors = [...metadataLoad.errors, ...apiLoad.errors];
if (loadErrors.length > 0)
{
  console.error("Cannot validate DLL batch promotion plan because definitions are invalid:");
  for (const error of loadErrors)
  {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

const metadataIndex = buildMetadataIndex(metadataLoad.documents);
const errors = validateDllBatchPromotionPlan(loadDllBatchPromotionPlan(), apiLoad.documents, metadataIndex);
if (errors.length > 0)
{
  console.error("DLL batch promotion plan validation failed:");
  for (const error of errors)
  {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

console.log("DLL batch promotion plan validation passed.");
