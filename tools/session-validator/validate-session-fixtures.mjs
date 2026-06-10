import fs from "node:fs";
import crypto from "node:crypto";
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
const supportedSources = new Set(["knmon-native-helper capture-sample", "knmon-native-helper attach-capture"]);
const supportedCaptureModes = new Set(["bounded-native-capture", "bounded-native-attach"]);

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

  if (!supportedSources.has(manifest.source)) {
    errors.push(`${label}: source must be a supported native helper source`);
  }

  if (!supportedCaptureModes.has(manifest.captureMode)) {
    errors.push(`${label}: captureMode must be a supported native capture mode`);
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

function sha256(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function isSafeKnapmChunkPath(filePath) {
  return typeof filePath === "string" && /^chunks\/trace-[0-9]{6}\.jsonl$/u.test(filePath);
}

const knapmRecoveryStates = new Set(["none", "owned", "stale", "recovery_required", "recovered", "abandoned", "malformed", "legacy"]);
const knapmRecoveryActions = new Set(["none", "wait", "replay_only", "recover_writer", "mark_abandoned", "manual_inspection"]);

function validateKnapmOwnership(manifest, manifestLabel, errors) {
  const hasOwner = manifest.owner && typeof manifest.owner === "object";
  const hasCheckpoint = manifest.checkpoint && typeof manifest.checkpoint === "object";
  const hasRecovery = manifest.recovery && typeof manifest.recovery === "object";

  if (!hasOwner && !hasCheckpoint && !hasRecovery) {
    return;
  }

  if (!hasOwner || !hasCheckpoint || !hasRecovery) {
    errors.push(`${manifestLabel}: owner, checkpoint, and recovery sections must appear together`);
    return;
  }

  const owner = manifest.owner;
  const checkpoint = manifest.checkpoint;
  const recovery = manifest.recovery;

  if (!["bounded-helper", "persistent-daemon"].includes(owner.ownerKind)) {
    errors.push(`${manifestLabel}: owner.ownerKind is unsupported`);
  }

  for (const field of ["hostProcessId", "helperProcessId", "writerProcessId", "writerGeneration", "leaseTimeoutMs"]) {
    requireNumber(owner[field], `owner.${field}`, manifestLabel, errors);
    if (owner[field] === 0) {
      errors.push(`${manifestLabel}: owner.${field} must be greater than zero`);
    }
  }

  for (const field of ["writerInstanceId", "startedUtc", "updatedUtc", "heartbeatUtc", "leaseExpiresUtc"]) {
    requireString(owner[field], `owner.${field}`, manifestLabel, errors);
  }

  if (owner.ownerKind === "persistent-daemon") {
    requireNumber(owner.daemonProcessId, "owner.daemonProcessId", manifestLabel, errors);
    if (owner.daemonProcessId === 0) {
      errors.push(`${manifestLabel}: owner.daemonProcessId must be greater than zero`);
    }

    for (const field of ["daemonInstanceId", "daemonStartedUtc", "daemonHeartbeatUtc", "controlEndpoint"]) {
      requireString(owner[field], `owner.${field}`, manifestLabel, errors);
    }
  }

  for (const field of ["lastCommittedChunkSequence", "lastCommittedBatchSequence", "lastCommittedRecordSequence", "lastCommittedEventId"]) {
    requireNumber(checkpoint[field], `checkpoint.${field}`, manifestLabel, errors);
  }

  for (const field of ["lastManifestUpdateUtc", "lastIndexUpdateUtc"]) {
    requireString(checkpoint[field], `checkpoint.${field}`, manifestLabel, errors);
  }

  if (typeof checkpoint.indexConsistent !== "boolean") {
    errors.push(`${manifestLabel}: checkpoint.indexConsistent must be boolean`);
  }

  if (checkpoint.lastCommittedChunkSequence !== manifest.chunkCount) {
    errors.push(`${manifestLabel}: checkpoint.lastCommittedChunkSequence must match chunkCount`);
  }

  if (checkpoint.lastCommittedBatchSequence !== manifest.lastBatchSequence) {
    errors.push(`${manifestLabel}: checkpoint.lastCommittedBatchSequence must match lastBatchSequence`);
  }

  if (checkpoint.lastCommittedRecordSequence !== manifest.lastRecordSequence) {
    errors.push(`${manifestLabel}: checkpoint.lastCommittedRecordSequence must match lastRecordSequence`);
  }

  if (!knapmRecoveryStates.has(recovery.state)) {
    errors.push(`${manifestLabel}: recovery.state is unsupported`);
  }

  requireString(recovery.reason, "recovery.reason", manifestLabel, errors);

  if (!knapmRecoveryActions.has(recovery.action)) {
    errors.push(`${manifestLabel}: recovery.action is unsupported`);
  }

  requireString(recovery.classifiedUtc, "recovery.classifiedUtc", manifestLabel, errors);

  for (const field of ["ownerAlive", "helperAlive", "writerAlive", "targetAlive", "leaseExpired", "restartEligible"]) {
    if (typeof recovery[field] !== "boolean") {
      errors.push(`${manifestLabel}: recovery.${field} must be boolean`);
    }
  }
}

function validateKnapmFixture(name, expectedSuccess) {
  const sessionPath = path.join(fixtureRoot, name);
  const errors = [];
  const manifestLabel = path.relative(repoRoot, path.join(sessionPath, "manifest.json"));
  const manifest = readJson(path.join(sessionPath, "manifest.json"), errors);
  const index = readJson(path.join(sessionPath, "index.json"), errors);

  if (manifest) {
    requireString(manifest.schemaVersion, "schemaVersion", manifestLabel, errors);
    requireString(manifest.formatVersion, "formatVersion", manifestLabel, errors);
    requireString(manifest.sessionId, "sessionId", manifestLabel, errors);
    requireString(manifest.operationId, "operationId", manifestLabel, errors);
    requireString(manifest.createdUtc, "createdUtc", manifestLabel, errors);
    requireString(manifest.updatedUtc, "updatedUtc", manifestLabel, errors);
    requireNumber(manifest.droppedEvents, "droppedEvents", manifestLabel, errors);
    requireNumber(manifest.transportDroppedEvents, "transportDroppedEvents", manifestLabel, errors);
    requireNumber(manifest.hostDroppedBatches, "hostDroppedBatches", manifestLabel, errors);
    requireNumber(manifest.chunkCount, "chunkCount", manifestLabel, errors);
    requireNumber(manifest.lastBatchSequence, "lastBatchSequence", manifestLabel, errors);
    requireNumber(manifest.lastRecordSequence, "lastRecordSequence", manifestLabel, errors);
    requireString(manifest.writerState, "writerState", manifestLabel, errors);

    if (manifest.format !== "knapm") {
      errors.push(`${manifestLabel}: format must be knapm`);
    }

    if (manifest.source !== "knmon-native-helper attach-session") {
      errors.push(`${manifestLabel}: source must be knmon-native-helper attach-session`);
    }

    if (manifest.backendMode !== "native-capture") {
      errors.push(`${manifestLabel}: backendMode must be native-capture`);
    }

    if (manifest.captureMode !== "bounded-native-attach") {
      errors.push(`${manifestLabel}: captureMode must be bounded-native-attach`);
    }

    if (manifest.injectionMethod !== "remote LoadLibraryW") {
      errors.push(`${manifestLabel}: injectionMethod must be remote LoadLibraryW`);
    }

    if (typeof manifest.finalized !== "boolean") {
      errors.push(`${manifestLabel}: finalized must be boolean`);
    }

    if (manifest.finalized && (typeof manifest.finalizedUtc !== "string" || manifest.finalizedUtc.length === 0)) {
      errors.push(`${manifestLabel}: finalizedUtc is required when finalized`);
    }

    if (!manifest.target || typeof manifest.target !== "object") {
      errors.push(`${manifestLabel}: target block is missing`);
    } else {
      requireString(manifest.target.path, "target.path", manifestLabel, errors);
      requireNumber(manifest.target.pid, "target.pid", manifestLabel, errors);
      requireNumber(manifest.target.tid, "target.tid", manifestLabel, errors);
      requireArchitecture(manifest.target.architecture, "target.architecture", manifestLabel, errors);
    }

    if (!manifest.agent || typeof manifest.agent !== "object") {
      errors.push(`${manifestLabel}: agent block is missing`);
    } else {
      requireString(manifest.agent.path, "agent.path", manifestLabel, errors);
      requireArchitecture(manifest.agent.architecture, "agent.architecture", manifestLabel, errors);
      if (manifest.finalized) {
        requireString(manifest.agent.version, "agent.version", manifestLabel, errors);
      }
    }

    if (!manifest.session || typeof manifest.session !== "object") {
      errors.push(`${manifestLabel}: session block is missing`);
    } else {
      requireString(manifest.session.sessionId, "session.sessionId", manifestLabel, errors);
      requireString(manifest.session.operationId, "session.operationId", manifestLabel, errors);
      requireNumber(manifest.session.recordsStreamed, "session.recordsStreamed", manifestLabel, errors);
      requireNumber(manifest.session.lastTransportSequence, "session.lastTransportSequence", manifestLabel, errors);
      requireNumber(manifest.session.transportDroppedEvents, "session.transportDroppedEvents", manifestLabel, errors);
      requireNumber(manifest.session.hostDroppedBatches, "session.hostDroppedBatches", manifestLabel, errors);
    }

    validateKnapmOwnership(manifest, manifestLabel, errors);

    const auditRows = readJsonl(path.join(sessionPath, "audit.jsonl"), errors);
    const agentRows = readJsonl(path.join(sessionPath, "agent-events.jsonl"), errors);
    if (manifest.eventCounts?.audit !== undefined && manifest.eventCounts.audit !== auditRows.length) {
      errors.push(`${manifestLabel}: audit count must match audit.jsonl`);
    }

    if (manifest.eventCounts?.agentEvents !== undefined && manifest.eventCounts.agentEvents !== agentRows.length) {
      errors.push(`${manifestLabel}: agentEvents count must match agent-events.jsonl`);
    }

    if (manifest.finalized) {
      let hasHello = false;
      let hasDropped = false;
      let hasShutdown = false;
      for (const [index, row] of agentRows.entries()) {
        const rowLabel = `${path.relative(repoRoot, path.join(sessionPath, "agent-events.jsonl"))}:${index + 1}`;
        hasHello = hasHello || row.messageType === "agent_hello";
        hasDropped = hasDropped || row.messageType === "dropped_events";
        if (row.messageType === "agent_shutdown") {
          hasShutdown = true;
          requireString(row.reason, "reason", rowLabel, errors);
          requireNumber(row.installedHooks, "installedHooks", rowLabel, errors);
          requireNumber(row.restoredHooks, "restoredHooks", rowLabel, errors);
          requireNumber(row.failedHooks, "failedHooks", rowLabel, errors);
          if (Number.isInteger(row.installedHooks) && Number.isInteger(row.restoredHooks) && row.restoredHooks < row.installedHooks) {
            errors.push(`${rowLabel}: restoredHooks must be greater than or equal to installedHooks`);
          }

          if (row.failedHooks !== 0) {
            errors.push(`${rowLabel}: failedHooks must be 0`);
          }
        }
      }

      if (!hasHello) {
        errors.push(`${manifestLabel}: finalized agent events must contain agent_hello`);
      }

      if (!hasDropped) {
        errors.push(`${manifestLabel}: finalized agent events must contain dropped_events`);
      }

      if (!hasShutdown) {
        errors.push(`${manifestLabel}: finalized agent events must contain agent_shutdown`);
      }
    }
  }

  if (index) {
    const indexLabel = path.relative(repoRoot, path.join(sessionPath, "index.json"));
    if (index.format !== "knapm-index") {
      errors.push(`${indexLabel}: format must be knapm-index`);
    }

    if (manifest?.sessionId && index.sessionId !== manifest.sessionId) {
      errors.push(`${indexLabel}: sessionId must match manifest`);
    }

    if (manifest?.operationId && index.operationId !== manifest.operationId) {
      errors.push(`${indexLabel}: operationId must match manifest`);
    }

    if (!Array.isArray(index.chunks)) {
      errors.push(`${indexLabel}: chunks must be an array`);
    } else {
      if (manifest && index.chunks.length !== manifest.chunkCount) {
        errors.push(`${indexLabel}: chunk count must match manifest`);
      }

      let expectedChunk = 1;
      let previousBatch = 0;
      let previousRecord = 0;
      let hasPreviousRecord = false;
      let traceCount = 0;
      let indexedLastBatch = 0;
      let indexedLastRecord = 0;
      for (const chunk of index.chunks) {
        const chunkLabel = `${indexLabel}:chunk${expectedChunk}`;
        requireNumber(chunk.chunkSequence, "chunkSequence", chunkLabel, errors);
        requireNumber(chunk.batchSequence, "batchSequence", chunkLabel, errors);
        requireNumber(chunk.eventCount, "eventCount", chunkLabel, errors);
        requireNumber(chunk.firstRecordSequence, "firstRecordSequence", chunkLabel, errors);
        requireNumber(chunk.lastRecordSequence, "lastRecordSequence", chunkLabel, errors);
        requireNumber(chunk.firstEventId, "firstEventId", chunkLabel, errors);
        requireNumber(chunk.lastEventId, "lastEventId", chunkLabel, errors);
        requireNumber(chunk.byteLength, "byteLength", chunkLabel, errors);
        requireString(chunk.file, "file", chunkLabel, errors);
        requireString(chunk.sha256, "sha256", chunkLabel, errors);

        if (chunk.chunkSequence !== expectedChunk) {
          errors.push(`${chunkLabel}: chunkSequence must be contiguous`);
        }

        if (previousBatch !== 0 && chunk.batchSequence !== previousBatch + 1) {
          errors.push(`${chunkLabel}: batchSequence must be contiguous`);
        }

        if (hasPreviousRecord && chunk.firstRecordSequence <= previousRecord) {
          errors.push(`${chunkLabel}: record ranges must be monotonic`);
        }

        if (chunk.compression !== "none") {
          errors.push(`${chunkLabel}: compression must be none`);
        }

        const safeChunkPath = isSafeKnapmChunkPath(chunk.file);
        if (!safeChunkPath) {
          errors.push(`${chunkLabel}: file must match chunks/trace-NNNNNN.jsonl`);
          expectedChunk += 1;
          previousBatch = chunk.batchSequence;
          previousRecord = chunk.lastRecordSequence;
          hasPreviousRecord = true;
          continue;
        }

        const chunkPath = path.join(sessionPath, chunk.file);
        let chunkText = "";
        try {
          chunkText = fs.readFileSync(chunkPath, "utf8");
        } catch (error) {
          errors.push(`${path.relative(repoRoot, chunkPath)}: failed to read: ${error.message}`);
          expectedChunk += 1;
          previousBatch = chunk.batchSequence;
          previousRecord = chunk.lastRecordSequence;
          continue;
        }

        if (chunkText.length !== chunk.byteLength) {
          errors.push(`${path.relative(repoRoot, chunkPath)}: byteLength mismatch`);
        }

        if (sha256(chunkText) !== chunk.sha256) {
          errors.push(`${path.relative(repoRoot, chunkPath)}: sha256 mismatch`);
        }

        const rows = chunkText
          .split(/\r?\n/u)
          .filter((line) => line.trim().length > 0)
          .map((line, index) => {
            try {
              return JSON.parse(line);
            } catch (error) {
              errors.push(`${path.relative(repoRoot, chunkPath)}:${index + 1}: failed to parse JSONL row: ${error.message}`);
              return null;
            }
          })
          .filter((row) => row !== null);

        if (rows.length !== chunk.eventCount) {
          errors.push(`${path.relative(repoRoot, chunkPath)}: eventCount mismatch`);
        }

        for (const [index, row] of rows.entries()) {
          const rowLabel = `${path.relative(repoRoot, chunkPath)}:${index + 1}`;
          requireString(row.schemaVersion, "schemaVersion", rowLabel, errors);
          requireNumber(row.eventId, "eventId", rowLabel, errors);
          requireString(row.api, "api", rowLabel, errors);
        }

        traceCount += rows.length;
        expectedChunk += 1;
        previousBatch = chunk.batchSequence;
        previousRecord = chunk.lastRecordSequence;
        hasPreviousRecord = true;
        indexedLastBatch = chunk.batchSequence;
        indexedLastRecord = chunk.lastRecordSequence;
      }

      if (manifest?.eventCounts?.traceEvents !== undefined && traceCount !== manifest.eventCounts.traceEvents) {
        errors.push(`${indexLabel}: indexed trace count must match manifest`);
      }

      if (manifest && index.chunks.length > 0 && manifest.lastBatchSequence !== indexedLastBatch) {
        errors.push(`${indexLabel}: indexed last batch must match manifest`);
      }

      if (manifest && index.chunks.length > 0 && manifest.lastRecordSequence !== indexedLastRecord) {
        errors.push(`${indexLabel}: indexed last record must match manifest`);
      }
    }
  }

  const success = errors.length === 0;

  if (success !== expectedSuccess) {
    console.error(`KNAPM session fixture ${name} ${success ? "unexpectedly passed" : "unexpectedly failed"}.`);
    for (const error of errors) {
      console.error(`- ${error}`);
    }
    return false;
  }

  console.log(`KNAPM session fixture ${name}: ${success ? "valid" : "invalid as expected"}`);
  return true;
}

const results = [
  validateSessionFixture("valid-sample", true),
  validateSessionFixture("malformed-missing-session-id", false),
  validateKnapmFixture("valid-knapm.knapm", true),
  validateKnapmFixture("valid-knapm-legacy.knapm", true),
  validateKnapmFixture("knapm-partial-unfinalized.knapm", true),
  validateKnapmFixture("knapm-owned-unfinalized.knapm", true),
  validateKnapmFixture("knapm-stale-target-exited.knapm", true),
  validateKnapmFixture("knapm-recovery-required-owner-dead.knapm", true),
  validateKnapmFixture("knapm-lease-expired.knapm", true),
  validateKnapmFixture("knapm-daemon-finalized.knapm", true),
  validateKnapmFixture("knapm-daemon-running.knapm", true),
  validateKnapmFixture("knapm-malformed-owner.knapm", false),
  validateKnapmFixture("knapm-malformed-daemon-owner.knapm", false),
  validateKnapmFixture("knapm-missing-index.knapm", false),
  validateKnapmFixture("knapm-missing-chunk.knapm", false),
  validateKnapmFixture("knapm-bad-hash.knapm", false),
  validateKnapmFixture("knapm-noncontiguous-batch.knapm", false),
  validateKnapmFixture("knapm-overlap-record.knapm", false),
  validateKnapmFixture("knapm-unsafe-chunk-path.knapm", false),
  validateKnapmFixture("knapm-malformed-event.knapm", false)
];

if (results.some((result) => !result)) {
  process.exit(1);
}

console.log("Session fixture validation passed.");
