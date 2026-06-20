import fs from "node:fs";

import {
  buildGeneratedDecoderTables,
  generatedDecoderJsonPath,
  validateRepositoryDefinitions
} from "./definition-system.mjs";

const result = validateRepositoryDefinitions();
const errors = [...result.errors];

if (errors.length === 0) {
  const expected = buildGeneratedDecoderTables(result.apiDocuments, result.metadataIndex);
  const actual = JSON.parse(fs.readFileSync(generatedDecoderJsonPath, "utf8"));

  if (actual.apis.length !== expected.apis.length) {
    errors.push(`generated decoder API count mismatch: expected ${expected.apis.length}, got ${actual.apis.length}`);
  }

  if (actual.parameters.length !== expected.parameters.length) {
    errors.push(`generated decoder parameter count mismatch: expected ${expected.parameters.length}, got ${actual.parameters.length}`);
  }

  if (actual.decodeAliases.length !== expected.decodeAliases.length) {
    errors.push(`generated decoder alias count mismatch: expected ${expected.decodeAliases.length}, got ${actual.decodeAliases.length}`);
  }

  const apiIds = new Set(actual.apis.map((api) => api.id));
  for (let id = 1; id <= 179; ++id) {
    if (!apiIds.has(id)) {
      errors.push(`generated decoder metadata is missing API id ${id}`);
    }
  }

  for (const api of actual.apis) {
    const parameters = actual.parameters.filter((parameter) => parameter.apiId === api.id);
    if (parameters.length !== api.parameterCount) {
      errors.push(`generated decoder API ${api.id} parameter count mismatch: expected ${api.parameterCount}, got ${parameters.length}`);
    }

    for (const parameter of parameters) {
      if (parameter.lengthFrom && parameter.lengthFromIndex < 0) {
        errors.push(`generated decoder API ${api.id} parameter ${parameter.name} has unresolved lengthFrom ${parameter.lengthFrom}`);
      }
    }
  }
}

if (errors.length > 0) {
  console.error("Generated decoder table validation failed:");
  for (const error of errors) {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

const decoder = JSON.parse(fs.readFileSync(generatedDecoderJsonPath, "utf8"));
console.log(`Generated decoder tables valid. APIs=${decoder.apis.length} parameters=${decoder.parameters.length} aliases=${decoder.decodeAliases.length}`);
