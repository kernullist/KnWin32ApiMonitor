import fs from "node:fs";
import path from "node:path";
import { importRohitabXml, stringifyImportedDefinition } from "./rohitab-importer.mjs";

function usage() {
  console.error("Usage: node tools/rohitab-importer/import-rohitab-xml.mjs --input <xml> [--output <json>]");
}

const args = process.argv.slice(2);
let inputPath = "";
let outputPath = "";

for (let index = 0; index < args.length; index += 1) {
  const arg = args[index];
  if (arg === "--input") {
    inputPath = args[index + 1] ?? "";
    index += 1;
  } else if (arg === "--output") {
    outputPath = args[index + 1] ?? "";
    index += 1;
  }
}

if (!inputPath) {
  usage();
  process.exit(2);
}

const xmlText = fs.readFileSync(inputPath, "utf8");
const output = stringifyImportedDefinition(importRohitabXml(xmlText));

if (outputPath) {
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, output, "utf8");
} else {
  process.stdout.write(output);
}
