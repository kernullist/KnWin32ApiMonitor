import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import stackCases from "../../tests/fixtures/stack-observation.json" with { type: "json" };
import { validateStackObservation } from "./strict-json.mjs";

const argument = process.argv.indexOf("--helper");
assert(argument >= 0, "Pass --helper <knmon-native-helper.exe>.");
const executable = path.resolve(process.argv[argument + 1]);
const fixtures = path.resolve("tests/fixtures/session");
fs.mkdirSync("build", { recursive: true });
const root = fs.mkdtempSync(path.resolve("build/g05-json-session-"));
let checked = 0;
function command(args)
{
    const result = spawnSync(executable, args, { encoding: "utf8", timeout: 10000, maxBuffer: 4 * 1024 * 1024, windowsHide: true });
    assert.equal(result.error, undefined, result.stderr);
    assert.equal(result.signal, null, result.stderr);
    assert.notEqual(result.status, null, result.stderr);
    return JSON.parse(result.stdout);
}
const valid = new Set(["knapm-process-exit.knapm", "valid-sample", "valid-knapm.knapm", "valid-knapm-legacy.knapm", "knapm-partial-unfinalized.knapm",
    "knapm-owned-unfinalized.knapm", "knapm-stale-target-exited.knapm", "knapm-recovery-required-owner-dead.knapm",
    "knapm-lease-expired.knapm", "knapm-daemon-finalized.knapm", "knapm-daemon-running.knapm", "knapm-zstd-valid.knapm"]);
for (const name of fs.readdirSync(fixtures))
{
    const result = command(["validate-session", "--session", path.join(fixtures, name)]);
    assert.equal(result.success, valid.has(name), `${name}: ${JSON.stringify(result)}`);
    ++checked;
}

function mutation(name, mutate, accepted = false)
{
    const target = path.join(root, `${name}.knapm`);
    fs.cpSync(path.join(fixtures, "valid-knapm.knapm"), target, { recursive: true });
    mutate(target);
    const result = command(["validate-session", "--session", target]);
    assert.equal(result.success, accepted, `${name}: ${JSON.stringify(result)}`);
    if (accepted)
    {
        assert.equal(result.sessionId, "fixture-knapm-valid");
        const replay = command(["replay-session", "--session", target]);
        assert.equal(replay.success, true, JSON.stringify(replay));
        assert.equal(replay.traceEvents[0].api, "CreateFileW");
        const stored = JSON.parse(fs.readFileSync(path.join(target, "chunks/trace-000001.jsonl"), "utf8"));
        for (const key of ["stack", "stackSource", "stackCapture", "hookContext"])
        {
            assert.deepEqual(replay.traceEvents[0][key], stored[key], `Replay changed ${key}.`);
        }
        if (name === "trace-qpc-valid")
        {
            assert.equal(replay.traceEvents[0].relativeTimeMs, 0.1);
            const database = path.join(root, "qpc-index.db");
            const indexed = command(["trace-index-build", "--root", target, "--database", database, "--rebuild"]);
            assert.equal(indexed.success, true, JSON.stringify(indexed));
            const queried = command(["trace-index-query", "--database", database, "--limit", "10"]);
            assert.equal(queried.success, true, JSON.stringify(queried));
            assert.equal(queried.events.length, 1);
            assert.equal(queried.events[0].relativeTimeMs, 0.1);
            assert.deepEqual(JSON.parse(queried.events[0].eventJson).timing, replay.traceEvents[0].timing);
            checked += 2;
        }
    }
    ++checked;
}
function editDocument(directory, file, transform)
{
    const location = path.join(directory, file);
    fs.writeFileSync(location, transform(fs.readFileSync(location, "utf8")));
}
function editManifest(directory, transform)
{
    editDocument(directory, "manifest.json", (text) => JSON.stringify(transform(JSON.parse(text))));
}
mutation("nested-shadow", (directory) => editDocument(directory, "manifest.json", (text) =>
    '{"nested":{"sessionId":"wrong","finalized":false},' + text.slice(text.indexOf("{") + 1)), true);
mutation("message-whitespace", (directory) => editDocument(directory, "agent-events.jsonl", (text) =>
    text.split(/\r?\n/u).filter(Boolean).map((line) => JSON.stringify(Object.fromEntries(Object.entries(JSON.parse(line)).reverse())).replaceAll('\":', '\": ')).join("\n") + "\n"), true);
mutation("duplicate-key", (directory) => editDocument(directory, "manifest.json", (text) =>
    '{"sessionId":"shadow",' + text.slice(text.indexOf("{") + 1)));
mutation("escaped-duplicate", (directory) => editDocument(directory, "manifest.json", (text) =>
    '{"session\\u0049d":"shadow",' + text.slice(text.indexOf("{") + 1)));
mutation("wrong-string", (directory) => editManifest(directory, (value) => ({ ...value, sessionId: 123 })));
mutation("null-bool", (directory) => editManifest(directory, (value) => ({ ...value, finalized: null })));
mutation("empty-owner", (directory) => editManifest(directory, (value) => ({ ...value, owner: {} })));
mutation("missing-finalized", (directory) => editManifest(directory, (value) =>
{
    delete value.finalized;
    return value;
}));
mutation("pid-overflow", (directory) => editManifest(directory, (value) => ({ ...value, target: { ...value.target, pid: 4294967296 } })));
mutation("float-count", (directory) => editManifest(directory, (value) => ({ ...value, eventCounts: { ...value.eventCounts, audit: 1.5 } })));
mutation("unicode-surrogate", (directory) => editDocument(directory, "manifest.json", (text) =>
    '{"unknown":"\\ud800",' + text.slice(text.indexOf("{") + 1)));
mutation("utf8-invalid", (directory) => editDocument(directory, "manifest.json", (text) =>
    Buffer.concat([Buffer.from('{"unknown":"'), Buffer.from([0xc0, 0xaf]), Buffer.from('\",' + text.slice(text.indexOf("{") + 1))])));
mutation("depth-limit", (directory) => editDocument(directory, "manifest.json", (text) =>
    '{"unknown":' + "[".repeat(40) + "0" + "]".repeat(40) + "," + text.slice(text.indexOf("{") + 1)));
mutation("document-limit", (directory) => editDocument(directory, "manifest.json", (text) => text + " ".repeat(8 * 1024 * 1024)));
mutation("primitive-chunk", (directory) => editDocument(directory, "index.json", (text) =>
{
    const value = JSON.parse(text);
    value.chunks.push(17);
    return JSON.stringify(value);
}));
mutation("missing-chunk-list", (directory) => editDocument(directory, "index.json", (text) =>
{
    const value = JSON.parse(text);
    delete value.chunks;
    return JSON.stringify(value);
}));
function editTrace(directory, transform)
{
    const file = path.join(directory, "chunks/trace-000001.jsonl");
    const text = transform(fs.readFileSync(file, "utf8"));
    fs.writeFileSync(file, text);
    const bytes = Buffer.byteLength(text);
    const sha256 = crypto.createHash("sha256").update(text).digest("hex");
    editDocument(directory, "index.json", (indexText) =>
    {
        const index = JSON.parse(indexText);
        Object.assign(index.chunks[0], { byteLength: bytes, sha256, uncompressedByteLength: bytes, uncompressedSha256: sha256 });
        return JSON.stringify(index);
    });
    editManifest(directory, (value) => ({ ...value, storedBytes: bytes, uncompressedBytes: bytes }));
}
mutation("trace-null-error", (directory) => editTrace(directory, (text) => text), true);
for (const [name, fields, accepted] of stackCases)
{
    assert.equal((() =>
    {
        try
        {
            validateStackObservation(fields);
            return true;
        }
        catch
        {
            return false;
        }
    })(), accepted, name);
    mutation(`stack-${name.replaceAll(" ", "-")}`, (directory) => editTrace(directory, (text) =>
    {
        const value = { ...JSON.parse(text), ...fields };
        if (!Object.hasOwn(fields, "stack"))
        {
            delete value.stack;
        }
        return JSON.stringify(value) + "\n";
    }), accepted);
}
const typedTrace = (text) => ({ ...JSON.parse(text), callId: "9007199254740993", parentCallId: "0", callDepth: 0,
    rawReturnBits: 128, rawReturnEncoding: "little_endian_object_bytes", rawReturnBytes: "0000003e0000003f0000603f0000403f" });
mutation("typed-aggregate-valid", (directory) => editTrace(directory, (text) => JSON.stringify(typedTrace(text)) + "\n"), true);
for (const [name, change] of [
    ["call-zero", (value) => { value.callId = "0"; }],
    ["call-numeric", (value) => { value.callId = 1; }],
    ["call-overflow", (value) => { value.callId = "9223372036854775808"; }],
    ["call-parent", (value) => { value.parentCallId = "1"; }],
    ["call-depth", (value) => { value.callDepth = 1; }],
    ["aggregate-truncated", (value) => { value.rawReturnBytes = value.rawReturnBytes.slice(0, 16); }],
    ["aggregate-nonhex", (value) => { value.rawReturnBytes = "z".repeat(32); }],
    ["aggregate-endian", (value) => { value.rawReturnEncoding = "big_endian"; }],
    ["aggregate-dual", (value) => { value.rawReturnValue = "0"; }],
    ["aggregate-width", (value) => { value.rawReturnBits = 64; }],
    ["aggregate-missing", (value) => { delete value.rawReturnBytes; }]
])
{
    mutation(name, (directory) => editTrace(directory, (text) =>
    {
        const value = typedTrace(text);
        change(value);
        return JSON.stringify(value) + "\n";
    }));
}
const observedTrace = (text) => ({ ...JSON.parse(text), observation: { eventPhase: "return", nestedCalls: "suppressed",
    exceptionEvents: "not_emitted", completionCorrelation: "not_tracked" }, arguments: [{ index: 1,
        name: "lpBuffer", type: "LPVOID", direction: "out", rawValue: "0x1234", preCallValue: "0x1234",
        postCallValue: "0x1234", decodedValue: "01 02", decodeStatus: "decoded",
        capture: { phase: "exit", readStatus: "complete", requestedBytes: 32, capturedBytes: 16,
            limitBytes: 16, byteCountSource: "transferred_count_after_sync_success", truncationReason: "capture_limit" } }] });
mutation("observation-valid", (directory) => editTrace(directory, (text) => JSON.stringify(observedTrace(text)) + "\n"), true);
for (const [name, change] of [
    ["false-completion-claim", (value) => { value.observation.completionCorrelation = "tracked"; }],
    ["observation-type", (value) => { value.observation = "return"; }],
    ["missing-observation-scope", (value) => { delete value.observation.nestedCalls; }],
    ["capture-type", (value) => { value.arguments[0].capture = []; }],
    ["capture-phase", (value) => { value.arguments[0].capture.phase = "during"; }],
    ["capture-number-type", (value) => { value.arguments[0].capture.capturedBytes = "16"; }],
    ["capture-count-limit", (value) => { value.arguments[0].capture.capturedBytes = 17; }],
    ["capture-short-complete", (value) => { value.arguments[0].capture.capturedBytes = 15; }],
    ["capture-unreadable-nonzero", (value) => { value.arguments[0].capture.readStatus = "unreadable"; }],
    ["capture-none-nonzero", (value) => { value.arguments[0].capture.phase = "none"; }],
    ["capture-missing-source", (value) => { delete value.arguments[0].capture.byteCountSource; }]
])
{
    mutation(name, (directory) => editTrace(directory, (text) =>
    {
        const value = observedTrace(text);
        change(value);
        return JSON.stringify(value) + "\n";
    }));
}
const clockTrace = (text) => ({ ...JSON.parse(text), timeSource: "qpc", relativeTimeMs: 0.1, durationUs: 100000,
    timestampUtc: "2022-06-18T04:26:40.0001000Z", collectedAtUtc: "2026-09-20T00:00:00.0000000Z",
    timing: { qpcFrequency: "10000000", qpcBase: "9007199254740993", utcBaseFileTime: "133000000000000000",
        anchorSpanQpc: "7", startQpc: "9007199254741993", endQpc: "9007199255741993" } });
mutation("trace-qpc-valid", (directory) => editTrace(directory, (text) => JSON.stringify(clockTrace(text)) + "\n"), true);
for (const [name, change] of [
    ["zero-frequency", (value) => { value.timing.qpcFrequency = "0"; }],
    ["numeric-clock", (value) => { value.timing.qpcBase = 9007199254740993; }],
    ["clock-overflow", (value) => { value.timing.startQpc = "18446744073709551616"; }],
    ["clock-leading-zero", (value) => { value.timing.startQpc = "09007199254741993"; }],
    ["reversed-clock", (value) => { value.timing.endQpc = value.timing.qpcBase; }],
    ["relative-mismatch", (value) => { value.relativeTimeMs = 0.2; }],
    ["duration-mismatch", (value) => { value.durationUs = 99999; }],
    ["negative-time", (value) => { value.relativeTimeMs = -1; }],
    ["missing-clock", (value) => { delete value.timing; }],
    ["return-width", (value) => { value.rawReturnValue = "4294967296"; value.rawReturnBits = 32; }],
    ["raw-error-type", (value) => { value.rawLastErrorCode = "5"; }],
    ["domain-type", (value) => { value.errorDomain = "fake"; }],
    ["outcome-invalid", (value) => { value.outcome = "fake"; }],
    ["validity-invalid", (value) => { value.errorValidity = "fake"; }],
    ["contradictory-failure", (value) => { value.hasError = true; value.outcome = "success"; }]
])
{
    mutation(`trace-${name}`, (directory) => editTrace(directory, (text) =>
    {
        const value = clockTrace(text);
        change(value);
        return JSON.stringify(value) + "\n";
    }));
}

for (const [name, overrides, accepted] of [
    ["query-cleanup-valid", {}, true], ["query-cleanup-active", { active: true }, false],
    ["query-cleanup-missing", { active: undefined }, false], ["query-cleanup-foreign", { operationId: "foreign" }, false],
    ["query-cleanup-hooks", { restoredHooks: 0 }, false], ["query-cleanup-overflow", { installedHooks: 4294967296 }, false]
])
{
    mutation(name, (directory) =>
    {
        editDocument(directory, "agent-events.jsonl", (text) => text.split(/\r?\n/).filter(Boolean)
            .filter((line) => JSON.parse(line).messageType !== "agent_shutdown").join("\n") + "\n");
        editManifest(directory, (value) => ({ ...value, eventCounts: { ...value.eventCounts, agentEvents: 2 },
            cleanupState: { source: "controller_query", operationId: value.operationId, lifecycle: "disabled",
                active: false, busy: false, hooksEnabled: 0, installedHooks: 10, restoredHooks: 10,
                failedHooks: 0, droppedEvents: 0, ...overrides } }));
    }, accepted);
}

mutation("trace-string-error-code", (directory) => editTrace(directory, (text) => JSON.stringify({ ...JSON.parse(text),
    error: { kind: "win32", code: "0x00000005", message: "Access is denied." } }) + "\n"), true);
mutation("trace-numeric-error-code", (directory) => editTrace(directory, (text) => JSON.stringify({ ...JSON.parse(text),
    error: { kind: "win32", code: 5, message: "Access is denied." } }) + "\n"));
mutation("trace-type", (directory) => editTrace(directory, (text) => JSON.stringify({ ...JSON.parse(text), arguments: false }) + "\n"));
mutation("trace-pid-overflow", (directory) => editTrace(directory, (text) => JSON.stringify({ ...JSON.parse(text), pid: 4294967296 }) + "\n"));
mutation("trace-error-type", (directory) => editTrace(directory, (text) => JSON.stringify({ ...JSON.parse(text), error: 42 }) + "\n"));
mutation("trace-duplicate", (directory) => editTrace(directory, (text) => '{"api":"shadow",' + text.slice(1)));
mutation("trace-primitive-tag", (directory) => editTrace(directory, (text) => JSON.stringify({ ...JSON.parse(text), tags: [123] }) + "\n"));
mutation("agent-counter-type", (directory) => editDocument(directory, "agent-events.jsonl", (text) =>
    text.replace('"droppedCount":0', '"droppedCount":-1')));
mutation("jsonl-blank-whitespace", (directory) => editDocument(directory, "agent-events.jsonl", (text) =>
    " \t\r\n" + text + " \t\n"), true);
const runtime = path.join(root, "runtime");
fs.mkdirSync(path.join(runtime, "sessions"), { recursive: true });
for (const [name, record] of [["bad-type", '{"sessionId":123}'], ["bad-syntax", '{"sessionId":']])
{
    fs.writeFileSync(path.join(runtime, "sessions", `${name}.json`), record);
}
const registry = command(["daemon-recovery-plan", "--runtime-dir", runtime]);
assert.equal(registry.success, true, JSON.stringify(registry));
assert.equal(registry.sessions.length, 2, JSON.stringify(registry));
assert.equal(registry.mutationAttempted, false);
assert.equal(registry.automaticRecoveryAllowed, false);
checked += 2;
const activeSession = path.join(root, "active-progress.knapm");
fs.cpSync(path.join(fixtures, "valid-knapm.knapm"), activeSession, { recursive: true });
editManifest(activeSession, (value) => ({ ...value, finalized: false, writerState: "streaming",
    target: { ...value.target, pid: process.pid }, session: { ...value.session, sessionState: "running",
        targetProcessId: process.pid, helperProcessId: process.pid, ownerProcessId: process.pid } }));
const activeManifest = JSON.parse(fs.readFileSync(path.join(activeSession, "manifest.json")));
fs.writeFileSync(path.join(runtime, "sessions", "active-progress.json"), JSON.stringify({
    sessionId: activeManifest.sessionId, operationId: activeManifest.operationId, targetProcessId: process.pid,
    daemonProcessId: process.pid, sessionProcessId: process.pid, knapmPath: activeSession }));
// An active progress query cannot claim full integrity for files still being written.
const activeIndex = JSON.parse(fs.readFileSync(path.join(activeSession, "index.json")));
fs.writeFileSync(path.join(activeSession, activeIndex.chunks[0].file), "deliberately invalid pending trace");
const progress = command(["daemon-list-sessions", "--runtime-dir", runtime]).sessions
    .find((value) => value.sessionId === activeManifest.sessionId);
assert.equal(progress.sessionState, "running");
assert.equal(progress.knapmValid, false);
assert.equal(progress.recoveryReason, "writer_active_integrity_pending");
assert.equal(command(["validate-session", "--session", activeSession]).success, false);
editManifest(activeSession, (value) => ({ ...value, operationId: "foreign" }));
const foreign = command(["daemon-list-sessions", "--runtime-dir", runtime]).sessions
    .find((value) => value.sessionId === activeManifest.sessionId);
assert.equal(foreign.sessionState, "failed");
assert.equal(foreign.recoveryReason, "manifest_invalid");
checked += 3;
fs.writeFileSync(path.join(root, "evidence.json"), JSON.stringify({ executable, checked, success: true }, null, 2));
console.log(`Native JSON session fixtures passed: ${checked} cases; evidence ${root}`);
