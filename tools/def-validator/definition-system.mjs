import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import Ajv2020 from "ajv/dist/2020.js";

export const repoRoot = process.cwd();

export const apiDefinitionSchemaPath = path.join(repoRoot, "contracts", "api-definition.schema.json");
export const metadataSchemaPath = path.join(repoRoot, "contracts", "definition-metadata.schema.json");
export const definitionsRoot = path.join(repoRoot, "definitions");
export const metadataRoot = path.join(definitionsRoot, "metadata");
export const positiveFixtureRoot = path.join(repoRoot, "tests", "fixtures", "definition", "positive");
export const negativeFixtureRoot = path.join(repoRoot, "tests", "fixtures", "definition", "negative");
export const negativeMetadataFixtureRoot = path.join(repoRoot, "tests", "fixtures", "definition", "negative-metadata");
export const generatedIdJsonPath = path.join(repoRoot, "generated", "definition-ids.json");
export const generatedApiHeaderPath = path.join(repoRoot, "native", "knmon-common", "include", "knmon", "common", "GeneratedApiIds.h");

const stableApiIds = new Map([
  ["kernel32.dll!CreateFileW", 1],
  ["kernel32.dll!CreateFileA", 2],
  ["ntdll.dll!NtCreateFile", 3],
  ["kernel32.dll!ReadFile", 4],
  ["kernel32.dll!WriteFile", 5],
  ["kernel32.dll!CloseHandle", 6],
  ["kernel32.dll!LoadLibraryW", 7],
  ["kernel32.dll!LoadLibraryA", 8],
  ["kernel32.dll!LoadLibraryExW", 9],
  ["kernel32.dll!LoadLibraryExA", 10],
  ["ntdll.dll!LdrLoadDll", 11]
]);

const stableModuleIds = new Map([
  ["kernel32.dll", 1],
  ["ntdll.dll", 2],
  ["kernelbase.dll", 3]
]);

const validCoverageStatuses = ["defined", "id_generated", "hooked", "smoke_verified", "definition_only", "unsupported"];

export function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

export function ensureDirectoryForFile(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

export function stableSortObject(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => stableSortObject(entry));
  }

  if (value !== null && typeof value === "object") {
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      sorted[key] = stableSortObject(value[key]);
    }
    return sorted;
  }

  return value;
}

export function stableStringify(value) {
  return `${JSON.stringify(stableSortObject(value), null, 2)}\n`;
}

export function writeStableJson(filePath, value) {
  ensureDirectoryForFile(filePath);
  fs.writeFileSync(filePath, stableStringify(value), "utf8");
}

export function relativePath(filePath) {
  return path.relative(repoRoot, filePath).replaceAll("\\", "/");
}

export function normalizeModuleName(moduleName) {
  return String(moduleName ?? "").trim().toLowerCase();
}

export function apiKey(moduleName, apiName) {
  return `${normalizeModuleName(moduleName)}!${apiName ?? ""}`;
}

export function listJsonFiles(directory) {
  const results = [];

  if (!fs.existsSync(directory)) {
    return results;
  }

  const entries = fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      results.push(...listJsonFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith(".json")) {
      results.push(fullPath);
    }
  }

  return results;
}

export function listApiDefinitionFiles(root = definitionsRoot) {
  return listJsonFiles(root).filter((filePath) => {
    const relative = relativePath(filePath);
    return !relative.startsWith("definitions/metadata/");
  });
}

export function listMetadataFiles(root = metadataRoot) {
  return listJsonFiles(root);
}

export function loadSchemaValidators() {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const apiSchema = readJson(apiDefinitionSchemaPath);
  const metadataSchema = readJson(metadataSchemaPath);

  return {
    api: ajv.compile(apiSchema),
    metadata: ajv.compile(metadataSchema)
  };
}

export function formatSchemaErrors(filePath, errors) {
  return (errors ?? []).map((error) => {
    const location = error.instancePath && error.instancePath.length > 0 ? error.instancePath : "/";
    return `${relativePath(filePath)}: schema ${location} ${error.message}`;
  });
}

export function validateSchemaForFile(filePath, validate) {
  const document = readJson(filePath);
  const ok = validate(document);
  const errors = ok ? [] : formatSchemaErrors(filePath, validate.errors);
  return { document, errors };
}

export function loadMetadataDocuments() {
  const validators = loadSchemaValidators();
  const files = listMetadataFiles();
  const documents = [];
  const errors = [];

  for (const filePath of files) {
    const result = validateSchemaForFile(filePath, validators.metadata);
    errors.push(...result.errors);
    documents.push({ filePath, document: result.document });
  }

  return { documents, errors };
}

export function loadApiDefinitionDocuments(root = definitionsRoot) {
  const validators = loadSchemaValidators();
  const files = listApiDefinitionFiles(root);
  const documents = [];
  const errors = [];

  for (const filePath of files) {
    const result = validateSchemaForFile(filePath, validators.api);
    errors.push(...result.errors);
    documents.push({ filePath, document: result.document });
  }

  return { documents, errors };
}

export function loadFixtureApiDocuments(root) {
  const validators = loadSchemaValidators();
  const files = listJsonFiles(root);
  const documents = [];
  const errors = [];

  for (const filePath of files) {
    const result = validateSchemaForFile(filePath, validators.api);
    errors.push(...result.errors);
    documents.push({ filePath, document: result.document });
  }

  return { documents, errors };
}

function parseNumericValue(rawValue) {
  if (typeof rawValue === "number" && Number.isInteger(rawValue)) {
    return rawValue;
  }

  if (typeof rawValue !== "string") {
    return NaN;
  }

  if (/^0x[0-9a-f]+$/i.test(rawValue)) {
    return Number.parseInt(rawValue.slice(2), 16);
  }

  if (/^\d+$/.test(rawValue)) {
    return Number.parseInt(rawValue, 10);
  }

  return NaN;
}

function indexByName(entries) {
  const map = new Map();
  for (const entry of entries) {
    map.set(entry.name, entry);
  }

  return map;
}

export function buildMetadataIndex(metadataDocuments) {
  const aliases = [];
  const enums = [];
  const flags = [];
  let idAssignments = null;

  for (const item of metadataDocuments) {
    const document = item.document;
    if (document.metadataType === "decode_aliases") {
      aliases.push(...(document.aliases ?? []));
    } else if (document.metadataType === "enums") {
      enums.push(...(document.enums ?? []));
    } else if (document.metadataType === "flags") {
      flags.push(...(document.flags ?? []));
    } else if (document.metadataType === "id_assignments") {
      idAssignments = document;
    }
  }

  return {
    aliases,
    aliasByName: indexByName(aliases),
    enums,
    enumByName: indexByName(enums),
    flags,
    flagByName: indexByName(flags),
    idAssignments
  };
}

function pushDuplicateError(errors, seen, key, message) {
  if (seen.has(key)) {
    errors.push(message);
    return;
  }

  seen.add(key);
}

export function validateMetadataSemantics(metadataDocuments) {
  const errors = [];
  const index = buildMetadataIndex(metadataDocuments);
  const aliasNames = new Set();
  const enumNames = new Set();
  const flagNames = new Set();
  const metadataTypes = new Set();

  for (const item of metadataDocuments) {
    const type = item.document.metadataType;
    if (metadataTypes.has(type) && type === "id_assignments") {
      errors.push(`${relativePath(item.filePath)}: duplicate id_assignments metadata document`);
    }
    metadataTypes.add(type);
  }

  for (const alias of index.aliases) {
    pushDuplicateError(errors, aliasNames, alias.name, `definitions/metadata: duplicate decode alias ${alias.name}`);

    if (alias.enum && !index.enumByName.has(alias.enum)) {
      errors.push(`definitions/metadata: decode alias ${alias.name} references unknown enum ${alias.enum}`);
    }

    if (alias.flags && !index.flagByName.has(alias.flags)) {
      errors.push(`definitions/metadata: decode alias ${alias.name} references unknown flags ${alias.flags}`);
    }
  }

  for (const valueSet of index.enums) {
    pushDuplicateError(errors, enumNames, valueSet.name, `definitions/metadata: duplicate enum ${valueSet.name}`);
    validateValueSet(errors, valueSet, "enum");
  }

  for (const valueSet of index.flags) {
    pushDuplicateError(errors, flagNames, valueSet.name, `definitions/metadata: duplicate flags ${valueSet.name}`);
    validateValueSet(errors, valueSet, "flags");
  }

  if (!index.idAssignments) {
    errors.push("definitions/metadata: missing id_assignments metadata");
  } else {
    errors.push(...validateIdAssignmentSemantics(index.idAssignments, true));
  }

  return errors;
}

export function validateIdAssignmentSemantics(idAssignments, enforceStableIds = false) {
  const errors = [];
  const moduleIds = new Set();
  const moduleNames = new Set();
  const moduleSymbols = new Set();
  const apiIds = new Set();
  const apiKeys = new Set();
  const apiSymbols = new Set();

  for (const module of idAssignments.modules ?? []) {
    pushDuplicateError(errors, moduleIds, module.id, `definitions/metadata: duplicate module id ${module.id}`);
    pushDuplicateError(errors, moduleNames, module.name, `definitions/metadata: duplicate module assignment ${module.name}`);
    pushDuplicateError(errors, moduleSymbols, module.symbol, `definitions/metadata: duplicate module symbol ${module.symbol}`);

    if (enforceStableIds && stableModuleIds.has(module.name) && stableModuleIds.get(module.name) !== module.id) {
      errors.push(`definitions/metadata: stable module id changed for ${module.name}; expected ${stableModuleIds.get(module.name)}, got ${module.id}`);
    }
  }

  for (const api of idAssignments.apis ?? []) {
    const key = apiKey(api.module, api.name);
    pushDuplicateError(errors, apiIds, api.id, `definitions/metadata: duplicate API id ${api.id}`);
    pushDuplicateError(errors, apiKeys, key, `definitions/metadata: duplicate API assignment ${key}`);
    pushDuplicateError(errors, apiSymbols, api.symbol, `definitions/metadata: duplicate API symbol ${api.symbol}`);

    if (!moduleNames.has(api.module)) {
      errors.push(`definitions/metadata: API assignment ${key} references unknown module id assignment ${api.module}`);
    }

    if (enforceStableIds && stableApiIds.has(key) && stableApiIds.get(key) !== api.id) {
      errors.push(`definitions/metadata: stable API id changed for ${key}; expected ${stableApiIds.get(key)}, got ${api.id}`);
    }
  }

  return errors;
}

function validateValueSet(errors, valueSet, label) {
  const names = new Set();
  const values = new Set();

  for (const value of valueSet.values ?? []) {
    const numeric = parseNumericValue(value.value);
    if (!Number.isInteger(numeric)) {
      errors.push(`definitions/metadata: ${label} ${valueSet.name}.${value.name} has invalid numeric value ${value.value}`);
    }

    pushDuplicateError(errors, names, value.name, `definitions/metadata: duplicate ${label} value name ${valueSet.name}.${value.name}`);
    pushDuplicateError(errors, values, numeric, `definitions/metadata: duplicate ${label} numeric value ${valueSet.name}.${value.value}`);
  }
}

function tokenizeLengthExpression(expression) {
  const tokens = [];
  let offset = 0;

  while (offset < expression.length) {
    const rest = expression.slice(offset);
    const whitespace = rest.match(/^\s+/);
    if (whitespace) {
      offset += whitespace[0].length;
      continue;
    }

    const identifier = rest.match(/^[A-Za-z_][A-Za-z0-9_]*/);
    if (identifier) {
      tokens.push({ type: "identifier", value: identifier[0] });
      offset += identifier[0].length;
      continue;
    }

    const integer = rest.match(/^\d+/);
    if (integer) {
      tokens.push({ type: "integer", value: integer[0] });
      offset += integer[0].length;
      continue;
    }

    const character = expression[offset];
    if ("+-*(),".includes(character)) {
      tokens.push({ type: character, value: character });
      offset += 1;
      continue;
    }

    throw new Error(`unsupported token '${character}'`);
  }

  tokens.push({ type: "end", value: "" });
  return tokens;
}

export function parseLengthExpression(expression) {
  const tokens = tokenizeLengthExpression(expression);
  let index = 0;
  const identifiers = new Set();

  function peek() {
    return tokens[index];
  }

  function consume(type) {
    if (peek().type !== type) {
      throw new Error(`expected ${type}, got ${peek().type}`);
    }

    const token = peek();
    index += 1;
    return token;
  }

  function parsePrimary() {
    if (peek().type === "integer") {
      return { type: "integer", value: consume("integer").value };
    }

    if (peek().type === "identifier") {
      const name = consume("identifier").value;

      if ((name === "min" || name === "max") && peek().type === "(") {
        consume("(");
        const left = parseExpression();
        consume(",");
        const right = parseExpression();
        consume(")");
        return { type: "call", name, args: [left, right] };
      }

      identifiers.add(name);
      return { type: "identifier", name };
    }

    if (peek().type === "(") {
      consume("(");
      const value = parseExpression();
      consume(")");
      return value;
    }

    throw new Error(`unexpected ${peek().type}`);
  }

  function parseMultiply() {
    let left = parsePrimary();
    while (peek().type === "*") {
      const operator = consume("*").value;
      const right = parsePrimary();
      left = { type: "binary", operator, left, right };
    }

    return left;
  }

  function parseExpression() {
    let left = parseMultiply();
    while (peek().type === "+" || peek().type === "-") {
      const operator = consume(peek().type).value;
      const right = parseMultiply();
      left = { type: "binary", operator, left, right };
    }

    return left;
  }

  const ast = parseExpression();
  consume("end");

  return { ast, identifiers: Array.from(identifiers).sort() };
}

export function normalizeLengthExpression(expression) {
  return expression.replace(/\s+/g, " ").trim();
}

export function validateApiDefinitionSemantics(documents, metadataIndex, options = {}) {
  const errors = [];
  const apiKeys = new Set();
  const explicitApiIds = new Set();
  const definitionKeys = new Set();
  const idByKey = new Map();

  for (const assignment of metadataIndex.idAssignments?.apis ?? []) {
    idByKey.set(apiKey(assignment.module, assignment.name), assignment);
  }

  for (const item of documents) {
    const document = item.document;
    for (const api of document.apis ?? []) {
      const key = apiKey(api.module, api.name);
      definitionKeys.add(key);
      pushDuplicateError(errors, apiKeys, key, `${relativePath(item.filePath)}: duplicate API definition ${key}`);

      if (api.apiId !== undefined) {
        pushDuplicateError(errors, explicitApiIds, api.apiId, `${relativePath(item.filePath)}: duplicate explicit API id ${api.apiId}`);
      }

      if (options.requireIdAssignments) {
        const assignment = idByKey.get(key);
        if (!assignment) {
          errors.push(`${relativePath(item.filePath)}: missing stable API id assignment for ${key}`);
        } else if (api.apiId !== undefined && api.apiId !== assignment.id) {
          errors.push(`${relativePath(item.filePath)}: explicit API id for ${key} does not match stable assignment ${assignment.id}`);
        }
      }

      const parameterNames = new Set();
      for (const parameter of api.parameters ?? []) {
        pushDuplicateError(errors, parameterNames, parameter.name, `${relativePath(item.filePath)}: duplicate parameter ${api.name}.${parameter.name}`);
      }

      for (const parameter of api.parameters ?? []) {
        if (!metadataIndex.aliasByName.has(parameter.decode)) {
          errors.push(`${relativePath(item.filePath)}: ${api.name}.${parameter.name} references unknown decode alias ${parameter.decode}`);
        }

        const alias = metadataIndex.aliasByName.get(parameter.decode);
        if (parameter.enum && !metadataIndex.enumByName.has(parameter.enum)) {
          errors.push(`${relativePath(item.filePath)}: ${api.name}.${parameter.name} references unknown enum ${parameter.enum}`);
        }

        if (parameter.flags && !metadataIndex.flagByName.has(parameter.flags)) {
          errors.push(`${relativePath(item.filePath)}: ${api.name}.${parameter.name} references unknown flags ${parameter.flags}`);
        }

        if (alias?.enum && parameter.enum && alias.enum !== parameter.enum) {
          errors.push(`${relativePath(item.filePath)}: ${api.name}.${parameter.name} enum ${parameter.enum} does not match decode alias enum ${alias.enum}`);
        }

        if (alias?.flags && parameter.flags && alias.flags !== parameter.flags) {
          errors.push(`${relativePath(item.filePath)}: ${api.name}.${parameter.name} flags ${parameter.flags} does not match decode alias flags ${alias.flags}`);
        }

        if (parameter.lengthFrom && !parameterNames.has(parameter.lengthFrom)) {
          errors.push(`${relativePath(item.filePath)}: ${api.name}.${parameter.name} lengthFrom references unknown parameter ${parameter.lengthFrom}`);
        }

        if (parameter.lengthExpression) {
          try {
            const parsed = parseLengthExpression(parameter.lengthExpression);
            for (const identifier of parsed.identifiers) {
              if (!parameterNames.has(identifier)) {
                errors.push(`${relativePath(item.filePath)}: ${api.name}.${parameter.name} lengthExpression references unknown parameter ${identifier}`);
              }
            }
          } catch (error) {
            errors.push(`${relativePath(item.filePath)}: ${api.name}.${parameter.name} invalid lengthExpression: ${error.message}`);
          }
        }
      }
    }
  }

  if (options.requireIdAssignments) {
    for (const assignment of metadataIndex.idAssignments?.apis ?? []) {
      const key = apiKey(assignment.module, assignment.name);
      if (!definitionKeys.has(key)) {
        errors.push(`definitions/metadata: API id assignment ${key} has no matching definition`);
      }
    }
  }

  return errors;
}

export function collectApiRecords(documents, metadataIndex) {
  const idByKey = new Map();
  for (const assignment of metadataIndex.idAssignments?.apis ?? []) {
    idByKey.set(apiKey(assignment.module, assignment.name), assignment);
  }

  const records = [];
  for (const item of documents) {
    for (const api of item.document.apis ?? []) {
      const key = apiKey(api.module, api.name);
      records.push({
        filePath: item.filePath,
        key,
        assignment: idByKey.get(key) ?? null,
        api
      });
    }
  }

  records.sort((left, right) => {
    const leftId = left.assignment?.id ?? Number.MAX_SAFE_INTEGER;
    const rightId = right.assignment?.id ?? Number.MAX_SAFE_INTEGER;
    if (leftId !== rightId) {
      return leftId - rightId;
    }

    return left.key.localeCompare(right.key);
  });

  return records;
}

export function buildGeneratedIds(metadataIndex) {
  const modules = [...(metadataIndex.idAssignments?.modules ?? [])]
    .sort((left, right) => left.id - right.id)
    .map((module) => ({
      id: module.id,
      name: module.name,
      symbol: module.symbol
    }));

  const apis = [...(metadataIndex.idAssignments?.apis ?? [])]
    .sort((left, right) => left.id - right.id)
    .map((api) => ({
      id: api.id,
      module: api.module,
      name: api.name,
      symbol: api.symbol
    }));

  return {
    schemaVersion: "0.1.0",
    source: "definitions/metadata/id-assignments.json",
    modules,
    apis
  };
}

export function buildGeneratedApiHeader(generatedIds) {
  const lines = [
    "#pragma once",
    "",
    "#include <cstdint>",
    "",
    "namespace knmon",
    "{",
    "enum class KnMonTransportApiId : std::uint16_t",
    "{",
    "    Unknown = 0,"
  ];

  for (const api of generatedIds.apis) {
    lines.push(`    ${api.symbol} = ${api.id},`);
  }

  lines.push(
    "};",
    "",
    "enum class KnMonTransportModuleId : std::uint16_t",
    "{",
    "    Unknown = 0,"
  );

  for (const module of generatedIds.modules) {
    lines.push(`    ${module.symbol} = ${module.id},`);
  }

  lines.push(
    "};",
    "}",
    ""
  );

  return lines.join("\n");
}

export function expectedGeneratedArtifacts(metadataIndex) {
  const generatedIds = buildGeneratedIds(metadataIndex);
  return {
    json: stableStringify(generatedIds),
    header: buildGeneratedApiHeader(generatedIds)
  };
}

export function checkGeneratedArtifacts(metadataIndex) {
  const errors = [];
  const expected = expectedGeneratedArtifacts(metadataIndex);

  if (!fs.existsSync(generatedIdJsonPath)) {
    errors.push(`${relativePath(generatedIdJsonPath)} is missing; run npm run defs:generate`);
  } else {
    const actual = fs.readFileSync(generatedIdJsonPath, "utf8");
    if (actual !== expected.json) {
      errors.push(`${relativePath(generatedIdJsonPath)} is stale; run npm run defs:generate`);
    }
  }

  if (!fs.existsSync(generatedApiHeaderPath)) {
    errors.push(`${relativePath(generatedApiHeaderPath)} is missing; run npm run defs:generate`);
  } else {
    const actual = fs.readFileSync(generatedApiHeaderPath, "utf8");
    if (actual !== expected.header) {
      errors.push(`${relativePath(generatedApiHeaderPath)} is stale; run npm run defs:generate`);
    }
  }

  return errors;
}

export function writeGeneratedArtifacts(metadataIndex) {
  const expected = expectedGeneratedArtifacts(metadataIndex);
  ensureDirectoryForFile(generatedIdJsonPath);
  fs.writeFileSync(generatedIdJsonPath, expected.json, "utf8");
  ensureDirectoryForFile(generatedApiHeaderPath);
  fs.writeFileSync(generatedApiHeaderPath, expected.header, "utf8");
}

export function decodeQualityForParameter(parameter, metadataIndex) {
  if (parameter.flags) {
    return "flags";
  }

  if (parameter.enum) {
    return "enum";
  }

  const alias = metadataIndex.aliasByName.get(parameter.decode);
  if (!alias) {
    return "unknown";
  }

  if (alias.kind === "string") {
    return "string";
  }

  if (alias.kind === "buffer") {
    return "buffer";
  }

  if (alias.kind === "handle") {
    return "handle";
  }

  if (alias.kind === "object") {
    return "object";
  }

  if (alias.kind === "flags") {
    return "flags";
  }

  if (alias.kind === "enum") {
    return "enum";
  }

  if (alias.kind === "pointer") {
    return "pointer";
  }

  if (alias.kind === "count") {
    return "raw";
  }

  return alias.kind;
}

function incrementCounter(target, key, amount = 1) {
  target[key] = (target[key] ?? 0) + amount;
}

export function buildCoverageReport(documents, metadataIndex) {
  const records = collectApiRecords(documents, metadataIndex);
  const statusCounts = Object.fromEntries(validCoverageStatuses.map((status) => [status, 0]));
  const byModule = {};
  const byFamily = {};
  const byRisk = {};
  const byDecodeQuality = {
    raw: 0,
    string: 0,
    buffer: 0,
    handle: 0,
    object: 0,
    pointer: 0,
    enum: 0,
    flags: 0,
    unknown: 0
  };

  const apis = records.map((record) => {
    const api = record.api;
    const moduleName = normalizeModuleName(api.module);
    const family = api.family ?? "uncategorized";
    const risk = api.risk ?? "medium";
    const coverageStatus = api.coverageStatus ?? "defined";
    const decodeQualities = Array.from(new Set((api.parameters ?? []).map((parameter) => decodeQualityForParameter(parameter, metadataIndex)))).sort();

    incrementCounter(statusCounts, coverageStatus);
    incrementCounter(byModule, moduleName);
    incrementCounter(byFamily, family);
    incrementCounter(byRisk, risk);
    for (const quality of decodeQualities) {
      incrementCounter(byDecodeQuality, quality);
    }

    return {
      id: record.assignment?.id ?? null,
      module: moduleName,
      name: api.name,
      family,
      category: api.category ?? "uncategorized",
      risk,
      hookPolicy: api.hookPolicy ?? "definition_only",
      coverageStatus,
      decodeQualities
    };
  });

  return {
    schemaVersion: "0.1.0",
    summary: {
      totalApis: apis.length,
      byModule,
      byFamily,
      byRisk,
      byCoverageStatus: statusCounts,
      byDecodeQuality
    },
    apis
  };
}

export function coverageReportToMarkdown(report) {
  const lines = [
    "# Definition Coverage Report",
    "",
    `Total APIs: ${report.summary.totalApis}`,
    "",
    "## Coverage Status",
    ""
  ];

  for (const status of validCoverageStatuses) {
    lines.push(`- ${status}: ${report.summary.byCoverageStatus[status] ?? 0}`);
  }

  lines.push("", "## APIs", "");
  lines.push("| ID | Module | API | Family | Risk | Hook Policy | Coverage | Decode |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- |");

  for (const api of report.apis) {
    lines.push(`| ${api.id ?? ""} | ${api.module} | ${api.name} | ${api.family} | ${api.risk} | ${api.hookPolicy} | ${api.coverageStatus} | ${api.decodeQualities.join(", ")} |`);
  }

  lines.push("");
  return lines.join("\n");
}

export function validateRepositoryDefinitions() {
  const metadataLoad = loadMetadataDocuments();
  const apiLoad = loadApiDefinitionDocuments();
  const metadataIndex = buildMetadataIndex(metadataLoad.documents);
  const errors = [
    ...metadataLoad.errors,
    ...validateMetadataSemantics(metadataLoad.documents),
    ...apiLoad.errors,
    ...validateApiDefinitionSemantics(apiLoad.documents, metadataIndex, { requireIdAssignments: true }),
    ...checkGeneratedArtifacts(metadataIndex)
  ];

  return {
    errors,
    apiDocuments: apiLoad.documents,
    metadataDocuments: metadataLoad.documents,
    metadataIndex
  };
}

export function validateDefinitionFixtureSet() {
  const errors = [];
  const metadataLoad = loadMetadataDocuments();
  const metadataIndex = buildMetadataIndex(metadataLoad.documents);
  const positive = loadFixtureApiDocuments(positiveFixtureRoot);
  const positiveErrors = [
    ...positive.errors,
    ...validateApiDefinitionSemantics(positive.documents, metadataIndex, { requireIdAssignments: false })
  ];

  for (const error of positiveErrors) {
    errors.push(`positive fixture failed: ${error}`);
  }

  const validators = loadSchemaValidators();
  for (const filePath of listJsonFiles(negativeFixtureRoot)) {
    const result = validateSchemaForFile(filePath, validators.api);
    const semanticErrors = validateApiDefinitionSemantics([{ filePath, document: result.document }], metadataIndex, { requireIdAssignments: false });
    const fixtureErrors = [...result.errors, ...semanticErrors];

    if (fixtureErrors.length === 0) {
      errors.push(`${relativePath(filePath)}: negative fixture unexpectedly passed`);
    }
  }

  for (const filePath of listJsonFiles(negativeMetadataFixtureRoot)) {
    const result = validateSchemaForFile(filePath, validators.metadata);
    const semanticErrors = validateIdAssignmentSemantics(result.document, false);
    const fixtureErrors = [...result.errors, ...semanticErrors];

    if (fixtureErrors.length === 0) {
      errors.push(`${relativePath(filePath)}: negative metadata fixture unexpectedly passed`);
    }
  }

  return errors;
}
