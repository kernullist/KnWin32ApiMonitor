import fs from "node:fs";

import {
  buildGeneratedDecoderTables,
  generatedDecoderJsonPath,
  stableStringify,
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

  if (!Array.isArray(actual.valueSets)) {
    errors.push("generated decoder valueSets metadata is missing");
  } else {
    if (actual.valueSets.length !== expected.valueSets.length) {
      errors.push(`generated decoder value set count mismatch: expected ${expected.valueSets.length}, got ${actual.valueSets.length}`);
    }

    if (stableStringify(actual.valueSets) !== stableStringify(expected.valueSets)) {
      errors.push("generated decoder value set metadata mismatch; rerun npm run defs:generate");
    }
  }

  const enumSets = new Set();
  const flagSets = new Set();
  const constantKeys = new Set();
  for (const value of actual.valueSets ?? []) {
    const key = `${value.kind}:${value.set}:${value.value}`;
    if (constantKeys.has(key)) {
      errors.push(`generated decoder duplicate constant value: ${key}`);
    }
    constantKeys.add(key);

    if (value.kind === "enum") {
      enumSets.add(value.set);
    } else if (value.kind === "flags") {
      flagSets.add(value.set);
    } else {
      errors.push(`generated decoder constant ${value.set}.${value.name} has invalid kind ${value.kind}`);
    }
  }

  const apiIds = new Set(actual.apis.map((api) => api.id));
  for (const api of expected.apis) {
    if (!apiIds.has(api.id)) {
      errors.push(`generated decoder metadata is missing API id ${api.id}`);
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

      if (parameter.enum && !enumSets.has(parameter.enum)) {
        errors.push(`generated decoder API ${api.id} parameter ${parameter.name} references unknown enum set ${parameter.enum}`);
      }

      if (parameter.flags && !flagSets.has(parameter.flags)) {
        errors.push(`generated decoder API ${api.id} parameter ${parameter.name} references unknown flags set ${parameter.flags}`);
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
console.log(
  `Generated decoder tables valid. APIs=${decoder.apis.length} parameters=${decoder.parameters.length} aliases=${decoder.decodeAliases.length} constants=${decoder.valueSets.length}`
);
