import process from "node:process";

import {
  loadApiInventory,
  validateApiInventory
} from "./api-inventory-system.mjs";
import {
  buildMetadataIndex,
  loadApiDefinitionDocuments,
  loadMetadataDocuments,
  validateApiDefinitionSemantics,
  validateMetadataSemantics
} from "./definition-system.mjs";

const metadataLoad = loadMetadataDocuments();
const apiLoad = loadApiDefinitionDocuments();
const metadataIndex = buildMetadataIndex(metadataLoad.documents);
const definitionErrors = [
  ...metadataLoad.errors,
  ...validateMetadataSemantics(metadataLoad.documents),
  ...apiLoad.errors,
  ...validateApiDefinitionSemantics(apiLoad.documents, metadataIndex, { requireIdAssignments: true })
];
const inventory = loadApiInventory();
const inventoryErrors = validateApiInventory(inventory, apiLoad.documents, metadataIndex);
const errors = [...definitionErrors, ...inventoryErrors];

if (errors.length > 0)
{
  console.error("API inventory validation failed:");
  for (const error of errors)
  {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

console.log(`API inventory validation passed. APIs=${inventory.summary.totalApis} tier0=${inventory.summary.byHookTier[0]} tier1=${inventory.summary.byHookTier[1]} tier2=${inventory.summary.byHookTier[2]} tier3=${inventory.summary.byHookTier[3]}`);
