import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const repoRoot = process.cwd();
const definitionsRoot = path.join(repoRoot, "definitions");
const requiredApis = new Set([
  "CreateFileW",
  "CreateFileA",
  "NtCreateFile",
  "ReadFile",
  "WriteFile",
  "CloseHandle"
]);

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function walkJsonFiles(directory) {
  const results = [];

  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);

    if (entry.isDirectory()) {
      results.push(...walkJsonFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith(".json")) {
      results.push(fullPath);
    }
  }

  return results;
}

function validateApi(api, sourceFile, errors) {
  const requiredFields = ["module", "name", "callingConvention", "returnType", "errorSource", "parameters"];

  for (const field of requiredFields) {
    if (!(field in api)) {
      errors.push(`${sourceFile}: API entry missing ${field}`);
    }
  }

  if (!Array.isArray(api.parameters) || api.parameters.length === 0) {
    errors.push(`${sourceFile}: ${api.name ?? "<unknown>"} must define at least one parameter`);
    return;
  }

  for (const [index, parameter] of api.parameters.entries()) {
    for (const field of ["name", "type", "direction", "decode"]) {
      if (!(field in parameter)) {
        errors.push(`${sourceFile}: ${api.name}.${index} missing ${field}`);
      }
    }
  }
}

const errors = [];
const seenApis = new Set();

if (!fs.existsSync(definitionsRoot)) {
  errors.push("definitions directory is missing");
} else {
  for (const filePath of walkJsonFiles(definitionsRoot)) {
    const relativePath = path.relative(repoRoot, filePath);
    const document = readJson(filePath);

    if (!document.schemaVersion) {
      errors.push(`${relativePath}: missing schemaVersion`);
    }

    if (!Array.isArray(document.apis)) {
      errors.push(`${relativePath}: missing apis array`);
      continue;
    }

    for (const api of document.apis) {
      validateApi(api, relativePath, errors);
      if (api.name) {
        seenApis.add(api.name);
      }
    }
  }
}

for (const api of requiredApis) {
  if (!seenApis.has(api)) {
    errors.push(`required File I/O API definition missing: ${api}`);
  }
}

if (errors.length > 0) {
  console.error("Definition validation failed:");
  for (const error of errors) {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

console.log(`Definition validation passed. APIs: ${Array.from(seenApis).sort().join(", ")}`);
