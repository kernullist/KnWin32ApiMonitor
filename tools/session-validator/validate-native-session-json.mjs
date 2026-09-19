import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

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
const valid = new Set(["valid-sample", "valid-knapm.knapm", "valid-knapm-legacy.knapm", "knapm-partial-unfinalized.knapm",
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
fs.writeFileSync(path.join(root, "evidence.json"), JSON.stringify({ executable, checked, success: true }, null, 2));
console.log(`Native JSON session fixtures passed: ${checked} cases; evidence ${root}`);
