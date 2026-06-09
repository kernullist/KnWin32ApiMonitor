import fs from "node:fs";
import path from "node:path";
import { repoRoot, readJson, stableStringify } from "../def-validator/definition-system.mjs";
import { importRohitabXml } from "./rohitab-importer.mjs";

const fixtureRoot = path.join(repoRoot, "tests", "fixtures", "definition", "rohitab");
const inputPath = path.join(fixtureRoot, "sample.xml");
const expectedPath = path.join(fixtureRoot, "expected.json");

const actual = importRohitabXml(fs.readFileSync(inputPath, "utf8"));
const expected = readJson(expectedPath);

if (stableStringify(actual) !== stableStringify(expected)) {
  console.error("Rohitab importer fixture output mismatch.");
  console.error("Expected:");
  process.stderr.write(stableStringify(expected));
  console.error("Actual:");
  process.stderr.write(stableStringify(actual));
  process.exit(1);
}

console.log("Rohitab importer fixture passed.");
