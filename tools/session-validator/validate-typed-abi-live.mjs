import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import vm from "node:vm";
import ts from "typescript";
import { spawnSync } from "node:child_process";
import { typedAbiSpecs } from "../def-validator/typed-abi-spec.mjs";

const directory = path.resolve(process.argv[2]);
const helper = path.join(directory, "knmon-native-helper.exe");
const target = path.join(directory, "knmon-typed-abi-target.exe");
const root = fs.mkdtempSync(path.resolve("build/typed-abi-live-"));
function run(executable, argumentsList)
{
  const result = spawnSync(executable, argumentsList, { windowsHide: true, encoding: "utf8", timeout: 45000, maxBuffer: 8 * 1024 * 1024 });
  assert.equal(result.error, undefined, result.stderr);
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);
  return result.stdout;
}
const originalReport = path.join(root, "original.bin");
const wrappedReport = path.join(root, "wrapped.bin");
run(target, [originalReport]);
const selection = typedAbiSpecs.map((spec) => `${spec.module}!${spec.name}`).join(";");
const captureText = run(helper, ["capture-sample", "--target", target, "--target-args", `"${wrappedReport}"`,
  "--api-selection", selection, "--timeout-ms", "30000", "--write-session", root]);
fs.writeFileSync(path.join(root, "capture-result.json"), captureText);
const capture = JSON.parse(captureText);
assert.equal(capture.success, true, capture.message);
assert.equal(capture.targetExitCode, 0);
assert.deepEqual(fs.readFileSync(wrappedReport), fs.readFileSync(originalReport), "Instrumentation changed the target report.");
assert.equal(capture.transportDroppedEvents, 0);
const replayText = run(helper, ["replay-session", "--session", root]);
fs.writeFileSync(path.join(root, "replay-result.json"), replayText);
const replay = JSON.parse(replayText);
assert.equal(replay.success, true);
const sandbox = { exports: {} };
vm.runInNewContext(ts.transpileModule(fs.readFileSync("apps/knmon-ui/src/traceConversion.ts", "utf8"),
  { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText, sandbox);
const callIds = new Set();
for (const spec of typedAbiSpecs)
{
  const events = capture.capturedEvents.filter((event) => event.api === spec.name);
  assert.equal(events.length, 1, `${spec.name}: expected exactly one root call; callback nested calls must be suppressed.`);
  const event = events[0];
  assert.equal(event.stackSource, "not_captured");
  assert.deepEqual(event.stack, []);
  assert.match(event.hookContext.agent, /^knmon-agent(32|64)\.dll$/u);
  assert.match(event.callId, /^[1-9][0-9]*$/u);
  assert.equal(callIds.has(event.callId), false);
  callIds.add(event.callId);
  assert.equal(event.parentCallId, "0");
  assert.equal(event.callDepth, 0);
  assert.equal(event.observation.nestedCalls, "suppressed");
  assert.equal(event.arguments.length, spec.parameters.length);
  for (const [index, argument] of event.arguments.entries())
  {
    assert.equal(argument.name, spec.parameters[index].name);
    assert.equal(argument.targetMemoryRead, false);
    assert.equal(argument.valuePhase, "entry");
    assert.ok(BigInt(argument.rawValue) < (1n << BigInt(argument.valueBits)));
  }
  const saved = replay.traceEvents.find((row) => row.recordSequence === event.recordSequence);
  assert.ok(saved);
  const live = JSON.parse(JSON.stringify(sandbox.exports.createTraceEventFromAgentApiCall(event, saved.eventId, [])));
  for (const key of ["callId", "parentCallId", "callDepth", "arguments", "observation", "rawReturnValue", "rawReturnBits",
    "rawReturnBytes", "rawReturnEncoding", "rawLastErrorCode", "errorDomain", "outcome", "timing", "returnValue", "stack", "stackSource", "hookContext"])
  {
    assert.deepEqual(live[key], saved[key], `${spec.name}: ${key} changed during replay/UI conversion.`);
  }
}
const aggregate = capture.capturedEvents.find((event) => event.api === "D2D1ConvertColorSpace");
assert.equal(aggregate.rawReturnValue, undefined);
assert.equal(aggregate.rawReturnBits, 128);
assert.equal(aggregate.rawReturnEncoding, "little_endian_object_bytes");
// The independently written report stores the color after 16 + 12 + 28 bytes.
assert.equal(aggregate.rawReturnBytes, fs.readFileSync(originalReport).subarray(56, 72).toString("hex"));
const narrow = capture.capturedEvents.find((event) => event.api === "VarR4FromR8");
assert.equal(narrow.outcome, "failure");
assert.equal(narrow.errorDomain, "hresult");
assert.equal(capture.capturedEvents.find((event) => event.api === "VarR8FromR4").arguments[0].rawValue, "0x3fa00000");
const sha256 = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
fs.writeFileSync(path.join(root, "evidence.json"), JSON.stringify({ success: true, apis: typedAbiSpecs.map((spec) => spec.name),
  helperSha256: sha256(helper), targetSha256: sha256(target), reportSha256: sha256(originalReport),
  capturedEvents: capture.capturedEvents.length }, null, 2));
console.log(`Live typed ABI A/B and replay PASS: ${root}`);
