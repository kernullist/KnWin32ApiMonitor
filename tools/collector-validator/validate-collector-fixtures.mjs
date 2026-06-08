import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";

const repoRoot = process.cwd();
const fixturePath = path.join(repoRoot, "tests", "fixtures", "collector", "drop-newest-capacity4-events10.json");
const helperPath = path.join(repoRoot, "build", "native", "Debug", "knmon-collector.exe");

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function assert(condition, message, errors) {
  if (!condition) {
    errors.push(message);
  }
}

function validateStats(document, label) {
  const errors = [];

  assert(document.schemaVersion === "0.1.0", `${label}: schemaVersion must be 0.1.0`, errors);
  assert(document.success === true, `${label}: success must be true`, errors);
  assert(document.operation === "smoke-backpressure", `${label}: operation must be smoke-backpressure`, errors);
  assert(document.policy === "drop-newest", `${label}: policy must be drop-newest`, errors);

  for (const field of [
    "capacity",
    "eventsRequested",
    "acceptedEvents",
    "drainedEvents",
    "droppedEvents",
    "queueDepth",
    "highWaterMark",
    "backpressureActivations",
    "firstSequence",
    "lastSequence"
  ]) {
    assert(Number.isInteger(document[field]) && document[field] >= 0, `${label}: ${field} must be a non-negative integer`, errors);
  }

  assert(Array.isArray(document.retainedSequences), `${label}: retainedSequences must be an array`, errors);

  const expectedAccepted = Math.min(document.capacity, document.eventsRequested);
  const expectedDropped = Math.max(0, document.eventsRequested - document.capacity);
  assert(document.acceptedEvents === expectedAccepted, `${label}: acceptedEvents mismatch`, errors);
  assert(document.drainedEvents === expectedAccepted, `${label}: drainedEvents mismatch`, errors);
  assert(document.droppedEvents === expectedDropped, `${label}: droppedEvents mismatch`, errors);
  assert(document.backpressureActivations === expectedDropped, `${label}: backpressureActivations mismatch`, errors);
  assert(document.highWaterMark === expectedAccepted, `${label}: highWaterMark mismatch`, errors);
  assert(document.queueDepth === 0, `${label}: queueDepth after drain must be 0`, errors);
  assert(document.retainedSequences.length === expectedAccepted, `${label}: retainedSequences length mismatch`, errors);

  for (let index = 0; index < document.retainedSequences.length; ++index) {
    const expectedSequence = index + 1;
    assert(document.retainedSequences[index] === expectedSequence, `${label}: FIFO sequence mismatch at index ${index}`, errors);
  }

  if (expectedAccepted > 0) {
    assert(document.firstSequence === 1, `${label}: firstSequence must be 1`, errors);
    assert(document.lastSequence === expectedAccepted, `${label}: lastSequence mismatch`, errors);
  } else {
    assert(document.firstSequence === 0, `${label}: firstSequence must be 0 for empty drain`, errors);
    assert(document.lastSequence === 0, `${label}: lastSequence must be 0 for empty drain`, errors);
  }

  return errors;
}

const fixture = readJson(fixturePath);
let errors = validateStats(fixture, path.relative(repoRoot, fixturePath));

if (!fs.existsSync(helperPath)) {
  errors.push(`native collector helper not found: ${path.relative(repoRoot, helperPath)}; run npm run native:build first`);
} else {
  const stdout = execFileSync(helperPath, ["smoke-backpressure", "--capacity", "4", "--events", "10"], {
    cwd: repoRoot,
    encoding: "utf8"
  });
  const smoke = JSON.parse(stdout);
  errors = errors.concat(validateStats(smoke, "knmon-collector smoke-backpressure"));

  for (const field of [
    "policy",
    "capacity",
    "eventsRequested",
    "acceptedEvents",
    "drainedEvents",
    "droppedEvents",
    "queueDepth",
    "highWaterMark",
    "backpressureActivations",
    "firstSequence",
    "lastSequence"
  ]) {
    assert(smoke[field] === fixture[field], `smoke output ${field} does not match fixture`, errors);
  }

  assert(JSON.stringify(smoke.retainedSequences) === JSON.stringify(fixture.retainedSequences), "smoke retainedSequences do not match fixture", errors);
}

if (errors.length > 0) {
  console.error("Collector validation failed:");
  for (const error of errors) {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

console.log("Collector validation passed. Policy=drop-newest capacity=4 events=10 dropped=6 retained=1,2,3,4");
