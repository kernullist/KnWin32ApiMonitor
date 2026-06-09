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
export const generatedDecoderJsonPath = path.join(repoRoot, "generated", "definition-decoder-tables.json");
export const generatedApiHeaderPath = path.join(repoRoot, "native", "knmon-common", "include", "knmon", "common", "GeneratedApiIds.h");
export const generatedApiMetadataHeaderPath = path.join(repoRoot, "native", "knmon-common", "include", "knmon", "common", "GeneratedApiMetadata.h");

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
  ["ntdll.dll!LdrLoadDll", 11],
  ["kernel32.dll!GetProcAddress", 12],
  ["ntdll.dll!LdrGetProcedureAddress", 13],
  ["advapi32.dll!RegOpenKeyExW", 14],
  ["advapi32.dll!RegCreateKeyExW", 15],
  ["advapi32.dll!RegQueryValueExW", 16],
  ["advapi32.dll!RegSetValueExW", 17],
  ["advapi32.dll!RegDeleteValueW", 18],
  ["advapi32.dll!RegCloseKey", 19],
  ["advapi32.dll!OpenProcessToken", 20],
  ["advapi32.dll!AdjustTokenPrivileges", 21],
  ["advapi32.dll!LookupPrivilegeValueW", 22],
  ["advapi32.dll!OpenSCManagerW", 23],
  ["advapi32.dll!OpenServiceW", 24],
  ["advapi32.dll!CreateServiceW", 25],
  ["advapi32.dll!StartServiceW", 26],
  ["advapi32.dll!ControlService", 27],
  ["advapi32.dll!DeleteService", 28],
  ["bcrypt.dll!BCryptOpenAlgorithmProvider", 29],
  ["bcrypt.dll!BCryptCloseAlgorithmProvider", 30],
  ["bcrypt.dll!BCryptGetProperty", 31],
  ["bcrypt.dll!BCryptSetProperty", 32],
  ["bcrypt.dll!BCryptGenerateSymmetricKey", 33],
  ["bcrypt.dll!BCryptDestroyKey", 34],
  ["bcrypt.dll!BCryptEncrypt", 35],
  ["bcrypt.dll!BCryptDecrypt", 36],
  ["bcrypt.dll!BCryptGenRandom", 37],
  ["bcrypt.dll!BCryptHashData", 38],
  ["crypt32.dll!CertOpenStore", 39],
  ["crypt32.dll!CertCloseStore", 40],
  ["crypt32.dll!CertFindCertificateInStore", 41],
  ["crypt32.dll!CertFreeCertificateContext", 42],
  ["crypt32.dll!CertGetCertificateChain", 43],
  ["crypt32.dll!CertVerifyCertificateChainPolicy", 44],
  ["crypt32.dll!CryptQueryObject", 45],
  ["crypt32.dll!CryptMsgOpenToDecode", 46],
  ["crypt32.dll!CryptMsgUpdate", 47],
  ["crypt32.dll!CryptMsgClose", 48],
  ["rpcrt4.dll!RpcStringBindingComposeW", 49],
  ["rpcrt4.dll!RpcBindingFromStringBindingW", 50],
  ["rpcrt4.dll!RpcStringFreeW", 51],
  ["rpcrt4.dll!RpcBindingFree", 52],
  ["rpcrt4.dll!RpcBindingSetAuthInfoW", 53],
  ["rpcrt4.dll!RpcBindingSetOption", 54],
  ["rpcrt4.dll!RpcMgmtEpEltInqBegin", 55],
  ["rpcrt4.dll!RpcMgmtEpEltInqNextW", 56],
  ["rpcrt4.dll!RpcMgmtEpEltInqDone", 57],
  ["rpcrt4.dll!UuidCreate", 58],
  ["ws2_32.dll!WSAStartup", 59],
  ["ws2_32.dll!WSACleanup", 60],
  ["ws2_32.dll!socket", 61],
  ["ws2_32.dll!closesocket", 62],
  ["ws2_32.dll!connect", 63],
  ["ws2_32.dll!send", 64],
  ["ws2_32.dll!recv", 65],
  ["ws2_32.dll!sendto", 66],
  ["ws2_32.dll!recvfrom", 67],
  ["ws2_32.dll!getaddrinfo", 68],
  ["ws2_32.dll!freeaddrinfo", 69],
  ["ws2_32.dll!WSAGetLastError", 70],
  ["wininet.dll!InternetOpenW", 71],
  ["wininet.dll!InternetCloseHandle", 72],
  ["wininet.dll!InternetConnectW", 73],
  ["wininet.dll!InternetOpenUrlW", 74],
  ["wininet.dll!HttpOpenRequestW", 75],
  ["wininet.dll!HttpSendRequestW", 76],
  ["wininet.dll!InternetReadFile", 77],
  ["wininet.dll!InternetWriteFile", 78],
  ["wininet.dll!InternetSetOptionW", 79],
  ["wininet.dll!InternetQueryOptionW", 80],
  ["winhttp.dll!WinHttpOpen", 81],
  ["winhttp.dll!WinHttpCloseHandle", 82],
  ["winhttp.dll!WinHttpConnect", 83],
  ["winhttp.dll!WinHttpOpenRequest", 84],
  ["winhttp.dll!WinHttpSendRequest", 85],
  ["winhttp.dll!WinHttpReceiveResponse", 86],
  ["winhttp.dll!WinHttpReadData", 87],
  ["winhttp.dll!WinHttpWriteData", 88],
  ["winhttp.dll!WinHttpSetOption", 89],
  ["winhttp.dll!WinHttpQueryHeaders", 90]
]);

const stableModuleIds = new Map([
  ["kernel32.dll", 1],
  ["ntdll.dll", 2],
  ["kernelbase.dll", 3],
  ["advapi32.dll", 4],
  ["bcrypt.dll", 5],
  ["crypt32.dll", 6],
  ["rpcrt4.dll", 7],
  ["ws2_32.dll", 8],
  ["wininet.dll", 9],
  ["winhttp.dll", 10]
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

function defaultCaptureTiming(direction) {
  if (direction === "out") {
    return "post";
  }

  if (direction === "inout") {
    return "pre_post";
  }

  return "pre";
}

function moduleIdMap(metadataIndex) {
  const map = new Map();
  for (const module of metadataIndex.idAssignments?.modules ?? []) {
    map.set(normalizeModuleName(module.name), module);
  }

  return map;
}

function stableJsonText(value) {
  return JSON.stringify(stableSortObject(value ?? {}));
}

function cppString(value) {
  return JSON.stringify(String(value ?? ""));
}

function cppBool(value) {
  return value ? "true" : "false";
}

function buildGeneratedParameters(apiId, parameters, metadataIndex, firstParameterIndex) {
  const generated = [];
  const parameterIndexByName = new Map();

  for (const [index, parameter] of parameters.entries()) {
    parameterIndexByName.set(parameter.name, index);
  }

  for (const [index, parameter] of parameters.entries()) {
    const alias = metadataIndex.aliasByName.get(parameter.decode);
    const lengthFromIndex = parameter.lengthFrom ? parameterIndexByName.get(parameter.lengthFrom) : undefined;
    generated.push({
      apiId,
      index,
      absoluteIndex: firstParameterIndex + index,
      name: parameter.name,
      type: parameter.type,
      direction: parameter.direction,
      decode: parameter.decode,
      captureTiming: parameter.captureTiming ?? defaultCaptureTiming(parameter.direction),
      nullable: parameter.nullable ?? false,
      maxBytes: parameter.maxBytes ?? alias?.maxPreviewBytes ?? 0,
      enum: parameter.enum ?? "",
      flags: parameter.flags ?? "",
      lengthFrom: parameter.lengthFrom ?? "",
      lengthFromIndex: Number.isInteger(lengthFromIndex) ? lengthFromIndex : -1,
      lengthExpression: parameter.lengthExpression ? normalizeLengthExpression(parameter.lengthExpression) : ""
    });
  }

  return generated;
}

export function buildGeneratedDecoderTables(apiDocuments, metadataIndex) {
  const modulesByName = moduleIdMap(metadataIndex);
  const apiRecords = collectApiRecords(apiDocuments, metadataIndex);
  const definitionFiles = Array.from(new Set(apiDocuments.map((item) => relativePath(item.filePath)))).sort();
  const metadataFiles = listMetadataFiles().map((filePath) => relativePath(filePath)).sort();

  const modules = [...(metadataIndex.idAssignments?.modules ?? [])]
    .sort((left, right) => left.id - right.id)
    .map((module) => ({
      id: module.id,
      name: normalizeModuleName(module.name),
      symbol: module.symbol
    }));

  const apis = [];
  const parameters = [];

  for (const record of apiRecords) {
    const api = record.api;
    const assignment = record.assignment;
    const moduleName = normalizeModuleName(api.module);
    const moduleAssignment = modulesByName.get(moduleName);
    const firstParameterIndex = parameters.length;
    const generatedParameters = buildGeneratedParameters(assignment?.id ?? 0, api.parameters ?? [], metadataIndex, firstParameterIndex);

    apis.push({
      id: assignment?.id ?? 0,
      moduleId: moduleAssignment?.id ?? 0,
      module: moduleName,
      name: api.name,
      symbol: assignment?.symbol ?? api.name,
      family: api.family ?? "uncategorized",
      category: api.category ?? "uncategorized",
      risk: api.risk ?? "medium",
      hookPolicy: api.hookPolicy ?? "definition_only",
      coverageStatus: api.coverageStatus ?? "defined",
      callingConvention: api.callingConvention,
      returnType: api.returnType,
      errorSource: api.errorSource,
      success: api.success ?? {},
      failure: api.failure ?? {},
      firstParameterIndex,
      parameterCount: generatedParameters.length,
      source: relativePath(record.filePath)
    });

    parameters.push(...generatedParameters);
  }

  const decodeAliases = [...metadataIndex.aliases]
    .sort((left, right) => left.name.localeCompare(right.name))
    .map((alias) => ({
      name: alias.name,
      kind: alias.kind,
      preview: alias.preview,
      readsTargetMemory: alias.readsTargetMemory,
      maxPreviewBytes: alias.maxPreviewBytes,
      enum: alias.enum ?? "",
      flags: alias.flags ?? ""
    }));

  return {
    schemaVersion: "0.1.0",
    sources: {
      definitions: definitionFiles,
      metadata: metadataFiles
    },
    modules,
    apis,
    parameters,
    decodeAliases
  };
}

export function buildGeneratedApiMetadataHeader(decoderTables) {
  const lines = [
    "#pragma once",
    "",
    "#include <array>",
    "#include <cstdint>",
    "#include <string_view>",
    "",
    "namespace knmon",
    "{",
    "struct KnMonGeneratedModuleMetadata",
    "{",
    "    std::uint16_t Id;",
    "    std::string_view Name;",
    "    std::string_view Symbol;",
    "};",
    "",
    "struct KnMonGeneratedApiMetadata",
    "{",
    "    std::uint16_t Id;",
    "    std::uint16_t ModuleId;",
    "    std::string_view ModuleName;",
    "    std::string_view Name;",
    "    std::string_view Symbol;",
    "    std::string_view Family;",
    "    std::string_view Category;",
    "    std::string_view Risk;",
    "    std::string_view HookPolicy;",
    "    std::string_view CoverageStatus;",
    "    std::string_view CallingConvention;",
    "    std::string_view ReturnType;",
    "    std::string_view ErrorSource;",
    "    std::string_view SuccessJson;",
    "    std::string_view FailureJson;",
    "    std::uint16_t FirstParameterIndex;",
    "    std::uint16_t ParameterCount;",
    "};",
    "",
    "struct KnMonGeneratedParameterMetadata",
    "{",
    "    std::uint16_t ApiId;",
    "    std::uint16_t Index;",
    "    std::uint16_t AbsoluteIndex;",
    "    std::string_view Name;",
    "    std::string_view Type;",
    "    std::string_view Direction;",
    "    std::string_view Decode;",
    "    std::string_view CaptureTiming;",
    "    bool Nullable;",
    "    std::uint32_t MaxBytes;",
    "    std::string_view Enum;",
    "    std::string_view Flags;",
    "    std::string_view LengthFrom;",
    "    std::int32_t LengthFromIndex;",
    "    std::string_view LengthExpression;",
    "};",
    ""
  ];

  lines.push(`inline constexpr std::array<KnMonGeneratedModuleMetadata, ${decoderTables.modules.length}> KnMonGeneratedModules =`);
  lines.push("{{");
  for (const module of decoderTables.modules) {
    lines.push("    {");
    lines.push(`        ${module.id},`);
    lines.push(`        ${cppString(module.name)},`);
    lines.push(`        ${cppString(module.symbol)}`);
    lines.push("    },");
  }
  lines.push("}};");
  lines.push("");

  lines.push(`inline constexpr std::array<KnMonGeneratedApiMetadata, ${decoderTables.apis.length}> KnMonGeneratedApis =`);
  lines.push("{{");
  for (const api of decoderTables.apis) {
    lines.push("    {");
    lines.push(`        ${api.id},`);
    lines.push(`        ${api.moduleId},`);
    lines.push(`        ${cppString(api.module)},`);
    lines.push(`        ${cppString(api.name)},`);
    lines.push(`        ${cppString(api.symbol)},`);
    lines.push(`        ${cppString(api.family)},`);
    lines.push(`        ${cppString(api.category)},`);
    lines.push(`        ${cppString(api.risk)},`);
    lines.push(`        ${cppString(api.hookPolicy)},`);
    lines.push(`        ${cppString(api.coverageStatus)},`);
    lines.push(`        ${cppString(api.callingConvention)},`);
    lines.push(`        ${cppString(api.returnType)},`);
    lines.push(`        ${cppString(api.errorSource)},`);
    lines.push(`        ${cppString(stableJsonText(api.success))},`);
    lines.push(`        ${cppString(stableJsonText(api.failure))},`);
    lines.push(`        ${api.firstParameterIndex},`);
    lines.push(`        ${api.parameterCount}`);
    lines.push("    },");
  }
  lines.push("}};");
  lines.push("");

  lines.push(`inline constexpr std::array<KnMonGeneratedParameterMetadata, ${decoderTables.parameters.length}> KnMonGeneratedParameters =`);
  lines.push("{{");
  for (const parameter of decoderTables.parameters) {
    lines.push("    {");
    lines.push(`        ${parameter.apiId},`);
    lines.push(`        ${parameter.index},`);
    lines.push(`        ${parameter.absoluteIndex},`);
    lines.push(`        ${cppString(parameter.name)},`);
    lines.push(`        ${cppString(parameter.type)},`);
    lines.push(`        ${cppString(parameter.direction)},`);
    lines.push(`        ${cppString(parameter.decode)},`);
    lines.push(`        ${cppString(parameter.captureTiming)},`);
    lines.push(`        ${cppBool(parameter.nullable)},`);
    lines.push(`        ${parameter.maxBytes},`);
    lines.push(`        ${cppString(parameter.enum)},`);
    lines.push(`        ${cppString(parameter.flags)},`);
    lines.push(`        ${cppString(parameter.lengthFrom)},`);
    lines.push(`        ${parameter.lengthFromIndex},`);
    lines.push(`        ${cppString(parameter.lengthExpression)}`);
    lines.push("    },");
  }
  lines.push("}};");
  lines.push("");

  lines.push(
    "inline constexpr const KnMonGeneratedModuleMetadata* FindGeneratedModuleMetadata(std::uint16_t id)",
    "{",
    "    for (const auto& entry : KnMonGeneratedModules)",
    "    {",
    "        if (entry.Id == id)",
    "        {",
    "            return &entry;",
    "        }",
    "    }",
    "",
    "    return nullptr;",
    "}",
    "",
    "inline constexpr const KnMonGeneratedApiMetadata* FindGeneratedApiMetadata(std::uint16_t id)",
    "{",
    "    for (const auto& entry : KnMonGeneratedApis)",
    "    {",
    "        if (entry.Id == id)",
    "        {",
    "            return &entry;",
    "        }",
    "    }",
    "",
    "    return nullptr;",
    "}",
    "",
    "inline constexpr const KnMonGeneratedParameterMetadata* FindGeneratedParameterMetadata(std::uint16_t apiId, std::uint16_t index)",
    "{",
    "    const KnMonGeneratedApiMetadata* api = FindGeneratedApiMetadata(apiId);",
    "    if (api == nullptr)",
    "    {",
    "        return nullptr;",
    "    }",
    "",
    "    if (index >= api->ParameterCount)",
    "    {",
    "        return nullptr;",
    "    }",
    "",
    "    const std::uint16_t absoluteIndex = static_cast<std::uint16_t>(api->FirstParameterIndex + index);",
    "    if (absoluteIndex >= KnMonGeneratedParameters.size())",
    "    {",
    "        return nullptr;",
    "    }",
    "",
    "    const KnMonGeneratedParameterMetadata& parameter = KnMonGeneratedParameters[absoluteIndex];",
    "    if (parameter.ApiId != apiId || parameter.Index != index)",
    "    {",
    "        return nullptr;",
    "    }",
    "",
    "    return &parameter;",
    "}",
    "}",
    ""
  );

  return lines.join("\n");
}

export function expectedGeneratedArtifacts(apiDocuments, metadataIndex) {
  const generatedIds = buildGeneratedIds(metadataIndex);
  const decoderTables = buildGeneratedDecoderTables(apiDocuments, metadataIndex);
  return {
    json: stableStringify(generatedIds),
    header: buildGeneratedApiHeader(generatedIds),
    decoderJson: stableStringify(decoderTables),
    metadataHeader: buildGeneratedApiMetadataHeader(decoderTables)
  };
}

function checkGeneratedArtifact(errors, filePath, expectedText) {
  if (!fs.existsSync(filePath)) {
    errors.push(`${relativePath(filePath)} is missing; run npm run defs:generate`);
    return;
  }

  const actual = fs.readFileSync(filePath, "utf8");
  if (actual !== expectedText) {
    errors.push(`${relativePath(filePath)} is stale; run npm run defs:generate`);
  }
}

export function checkGeneratedArtifacts(apiDocuments, metadataIndex) {
  const errors = [];
  const expected = expectedGeneratedArtifacts(apiDocuments, metadataIndex);

  checkGeneratedArtifact(errors, generatedIdJsonPath, expected.json);
  checkGeneratedArtifact(errors, generatedApiHeaderPath, expected.header);
  checkGeneratedArtifact(errors, generatedDecoderJsonPath, expected.decoderJson);
  checkGeneratedArtifact(errors, generatedApiMetadataHeaderPath, expected.metadataHeader);

  return errors;
}

export function writeGeneratedArtifacts(apiDocuments, metadataIndex) {
  const expected = expectedGeneratedArtifacts(apiDocuments, metadataIndex);
  ensureDirectoryForFile(generatedIdJsonPath);
  fs.writeFileSync(generatedIdJsonPath, expected.json, "utf8");
  ensureDirectoryForFile(generatedApiHeaderPath);
  fs.writeFileSync(generatedApiHeaderPath, expected.header, "utf8");
  ensureDirectoryForFile(generatedDecoderJsonPath);
  fs.writeFileSync(generatedDecoderJsonPath, expected.decoderJson, "utf8");
  ensureDirectoryForFile(generatedApiMetadataHeaderPath);
  fs.writeFileSync(generatedApiMetadataHeaderPath, expected.metadataHeader, "utf8");
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
    ...checkGeneratedArtifacts(apiLoad.documents, metadataIndex)
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
