import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const repoRoot = process.cwd();
const fixtureRoot = path.join(repoRoot, "tests", "fixtures", "session");

const expectedFiles = {
  audit: "audit.jsonl",
  agentEvents: "agent-events.jsonl",
  traceEvents: "trace-events.jsonl"
};

const supportedArchitectures = new Set(["x86", "x64"]);

function readJson(filePath, errors) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    errors.push(`${path.relative(repoRoot, filePath)}: failed to parse JSON: ${error.message}`);
    return null;
  }
}

function readJsonl(filePath, errors) {
  let text = "";

  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    errors.push(`${path.relative(repoRoot, filePath)}: failed to read: ${error.message}`);
    return [];
  }

  return text
    .split(/\r?\n/u)
    .filter((line) => line.trim().length > 0)
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        errors.push(`${path.relative(repoRoot, filePath)}:${index + 1}: failed to parse JSONL row: ${error.message}`);
        return null;
      }
    })
    .filter((row) => row !== null);
}

function requireString(value, fieldName, label, errors) {
  if (typeof value !== "string" || value.length === 0) {
    errors.push(`${label}: missing string ${fieldName}`);
  }
}

function requireNumber(value, fieldName, label, errors) {
  if (!Number.isInteger(value) || value < 0) {
    errors.push(`${label}: missing non-negative integer ${fieldName}`);
  }
}

function requireArchitecture(value, fieldName, label, errors) {
  if (!supportedArchitectures.has(value)) {
    errors.push(`${label}: ${fieldName} must be x86 or x64`);
  }
}

function validateManifest(sessionPath, errors) {
  const label = path.relative(repoRoot, path.join(sessionPath, "manifest.json"));
  const manifest = readJson(path.join(sessionPath, "manifest.json"), errors);

  if (!manifest) {
    return null;
  }

  requireString(manifest.schemaVersion, "schemaVersion", label, errors);
  requireString(manifest.sessionId, "sessionId", label, errors);
  requireString(manifest.createdUtc, "createdUtc", label, errors);
  requireString(manifest.operationId, "operationId", label, errors);

  if (manifest.schemaVersion !== "0.1.0") {
    errors.push(`${label}: unsupported schemaVersion ${manifest.schemaVersion}`);
  }

  if (manifest.backendMode !== "native-capture") {
    errors.push(`${label}: backendMode must be native-capture`);
  }

  if (manifest.captureMode !== "bounded-native-capture") {
    errors.push(`${label}: captureMode must be bounded-native-capture`);
  }

  if (!manifest.files || typeof manifest.files !== "object") {
    errors.push(`${label}: files block is missing`);
  } else {
    for (const [key, expectedName] of Object.entries(expectedFiles)) {
      if (manifest.files[key] !== expectedName) {
        errors.push(`${label}: files.${key} must be ${expectedName}`);
      }
    }
  }

  if (!manifest.target || typeof manifest.target !== "object") {
    errors.push(`${label}: target block is missing`);
  } else {
    requireString(manifest.target.path, "target.path", label, errors);
    requireNumber(manifest.target.pid, "target.pid", label, errors);
    requireNumber(manifest.target.tid, "target.tid", label, errors);
    requireArchitecture(manifest.target.architecture, "target.architecture", label, errors);
  }

  if (!manifest.agent || typeof manifest.agent !== "object") {
    errors.push(`${label}: agent block is missing`);
  } else {
    requireString(manifest.agent.path, "agent.path", label, errors);
    requireArchitecture(manifest.agent.architecture, "agent.architecture", label, errors);
    requireString(manifest.agent.version, "agent.version", label, errors);
  }

  if (
    supportedArchitectures.has(manifest.target?.architecture) &&
    supportedArchitectures.has(manifest.agent?.architecture) &&
    manifest.target.architecture !== manifest.agent.architecture
  ) {
    errors.push(`${label}: target.architecture and agent.architecture must match`);
  }

  if (!manifest.eventCounts || typeof manifest.eventCounts !== "object") {
    errors.push(`${label}: eventCounts block is missing`);
  } else {
    for (const field of ["audit", "agentEvents", "traceEvents", "capturedEvents"]) {
      requireNumber(manifest.eventCounts[field], `eventCounts.${field}`, label, errors);
    }
  }

  requireNumber(manifest.droppedEvents, "droppedEvents", label, errors);
  return manifest;
}

function validateAgentEvents(sessionPath, errors, manifest) {
  const rows = readJsonl(path.join(sessionPath, expectedFiles.agentEvents), errors);
  let helloCount = 0;
  let hasDropped = false;
  let hasShutdown = false;

  for (const [index, row] of rows.entries()) {
    const label = `${path.relative(repoRoot, path.join(sessionPath, expectedFiles.agentEvents))}:${index + 1}`;
    requireString(row.schemaVersion, "schemaVersion", label, errors);
    requireString(row.messageType, "messageType", label, errors);
    requireString(row.operationId, "operationId", label, errors);
    requireNumber(row.pid, "pid", label, errors);
    requireNumber(row.tid, "tid", label, errors);
    requireNumber(row.sequence, "sequence", label, errors);

    if (manifest?.operationId && row.operationId !== manifest.operationId) {
      errors.push(`${label}: operationId must match manifest operationId`);
    }

    if (row.messageType === "agent_hello") {
      helloCount += 1;
      requireArchitecture(row.architecture, "architecture", label, errors);
      requireString(row.agentVersion, "agentVersion", label, errors);
      requireString(row.message, "message", label, errors);

      if (supportedArchitectures.has(manifest?.agent?.architecture) && row.architecture !== manifest.agent.architecture) {
        errors.push(`${label}: HELLO architecture must match manifest agent.architecture`);
      }

      if (typeof manifest?.agent?.version === "string" && manifest.agent.version.length > 0 && row.agentVersion !== manifest.agent.version) {
        errors.push(`${label}: HELLO agentVersion must match manifest agent.version`);
      }
    }

    hasDropped = hasDropped || row.messageType === "dropped_events";
    hasShutdown = hasShutdown || row.messageType === "agent_shutdown";

    if (row.messageType === "agent_shutdown") {
      requireString(row.reason, "reason", label, errors);
      requireString(row.lifecycleState, "lifecycleState", label, errors);
      requireNumber(row.installedHooks, "installedHooks", label, errors);
      requireNumber(row.restoredHooks, "restoredHooks", label, errors);
      requireNumber(row.failedHooks, "failedHooks", label, errors);
      requireNumber(row.droppedCount, "droppedCount", label, errors);

      if (Number.isInteger(row.installedHooks) && Number.isInteger(row.restoredHooks) && row.restoredHooks < row.installedHooks) {
        errors.push(`${label}: restoredHooks must be greater than or equal to installedHooks`);
      }

      if (row.failedHooks !== 0) {
        errors.push(`${label}: failedHooks must be 0 for committed healthy fixtures`);
      }
    }
  }

  if (helloCount === 0) {
    errors.push(`${expectedFiles.agentEvents}: agent_hello is missing`);
  }

  if (helloCount > 1) {
    errors.push(`${expectedFiles.agentEvents}: exactly one agent_hello is expected`);
  }

  if (!hasDropped) {
    errors.push(`${expectedFiles.agentEvents}: dropped_events is missing`);
  }

  if (!hasShutdown) {
    errors.push(`${expectedFiles.agentEvents}: agent_shutdown is missing`);
  }

  return rows;
}

function validateTraceEvents(sessionPath, errors) {
  const rows = readJsonl(path.join(sessionPath, expectedFiles.traceEvents), errors);

  if (rows.length === 0) {
    errors.push(`${expectedFiles.traceEvents}: at least one trace event is required`);
  }

  for (const [index, row] of rows.entries()) {
    const label = `${path.relative(repoRoot, path.join(sessionPath, expectedFiles.traceEvents))}:${index + 1}`;
    requireString(row.schemaVersion, "schemaVersion", label, errors);
    requireNumber(row.eventId, "eventId", label, errors);
    requireNumber(row.pid, "pid", label, errors);
    requireNumber(row.tid, "tid", label, errors);
    requireString(row.process, "process", label, errors);
    requireString(row.module, "module", label, errors);
    requireString(row.api, "api", label, errors);

    if (!Array.isArray(row.arguments)) {
      errors.push(`${label}: arguments must be an array`);
    }

    if (!Array.isArray(row.tags)) {
      errors.push(`${label}: tags must be an array`);
    }

    if (!Array.isArray(row.stack)) {
      errors.push(`${label}: stack must be an array`);
    }
  }

  return rows;
}

function validateSessionFixture(name, expectedSuccess) {
  const sessionPath = path.join(fixtureRoot, name);
  const errors = [];
  const manifest = validateManifest(sessionPath, errors);
  const auditRows = readJsonl(path.join(sessionPath, expectedFiles.audit), errors);
  const agentRows = validateAgentEvents(sessionPath, errors, manifest);
  const traceRows = validateTraceEvents(sessionPath, errors);

  if (manifest?.eventCounts) {
    if (manifest.eventCounts.audit !== auditRows.length) {
      errors.push(`${name}: manifest audit count does not match audit.jsonl`);
    }

    if (manifest.eventCounts.agentEvents !== agentRows.length) {
      errors.push(`${name}: manifest agentEvents count does not match agent-events.jsonl`);
    }

    if (manifest.eventCounts.traceEvents !== traceRows.length) {
      errors.push(`${name}: manifest traceEvents count does not match trace-events.jsonl`);
    }
  }

  const success = errors.length === 0;

  if (success !== expectedSuccess) {
    console.error(`Session fixture ${name} ${success ? "unexpectedly passed" : "unexpectedly failed"}.`);
    for (const error of errors) {
      console.error(`- ${error}`);
    }
    return false;
  }

  console.log(`Session fixture ${name}: ${success ? "valid" : "invalid as expected"}`);
  return true;
}

const results = [
  validateSessionFixture("valid-sample", true),
  validateSessionFixture("malformed-missing-session-id", false)
];

if (results.some((result) => !result)) {
  process.exit(1);
}

console.log("Session fixture validation passed.");
