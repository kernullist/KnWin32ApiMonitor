import {
  buildMetadataIndex,
  loadMetadataDocuments,
  validateMetadataSemantics,
  writeGeneratedArtifacts
} from "./definition-system.mjs";

const args = new Set(process.argv.slice(2));

if (!args.has("--write")) {
  console.error("Usage: node tools/def-validator/generate-definition-ids.mjs --write");
  process.exit(2);
}

const metadataLoad = loadMetadataDocuments();
const metadataIndex = buildMetadataIndex(metadataLoad.documents);
const errors = [
  ...metadataLoad.errors,
  ...validateMetadataSemantics(metadataLoad.documents)
];

if (errors.length > 0) {
  console.error("Definition ID generation failed:");
  for (const error of errors) {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

writeGeneratedArtifacts(metadataIndex);
console.log("Generated definition ID artifacts.");
