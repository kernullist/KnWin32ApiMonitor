import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import vm from "node:vm";
import ts from "typescript";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";

const executable = path.resolve(process.argv[2]);
const root = fs.mkdtempSync(path.resolve("build/record-identity-"));
const fixture = "tests/fixtures/session/valid-knapm.knapm";
function command(args)
{
  const result = spawnSync(executable, args, { encoding: "utf8", timeout: 15000, maxBuffer: 4 * 1024 * 1024, windowsHide: true });
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  return JSON.parse(result.stdout);
}
const stringify = (value) => JSON.stringify(value, (_, item) => typeof item === "bigint" ? `BIGINT:${item}` : item)
  .replace(/"BIGINT:([0-9]+)"/gu, "$1");
function session(name, sequences, range = sequences.filter((value) => value !== undefined), ids = sequences.map((_, index) => index + 1))
{
  const directory = path.join(root, `${name}.knapm`);
  fs.cpSync(fixture, directory, { recursive: true });
  const read = (file) => JSON.parse(fs.readFileSync(path.join(directory, file), "utf8"));
  const write = (file, value) => fs.writeFileSync(path.join(directory, file), stringify(value));
  const sample = read("chunks/trace-000001.jsonl");
  const trace = sequences.map((recordSequence, index) => stringify({ ...sample, recordSequence, eventId: ids[index] })).join("\n") + "\n";
  fs.writeFileSync(path.join(directory, "chunks/trace-000001.jsonl"), trace);
  const first = BigInt(range[0] ?? 1);
  const last = BigInt(range.at(-1) ?? sequences.length);
  const bytes = Buffer.byteLength(trace);
  const sha256 = crypto.createHash("sha256").update(trace).digest("hex");
  const index = read("index.json");
  Object.assign(index.chunks[0], { firstRecordSequence: first, lastRecordSequence: last, eventCount: sequences.length,
    firstEventId: ids[0], lastEventId: ids.at(-1), byteLength: bytes, sha256, uncompressedByteLength: bytes, uncompressedSha256: sha256 });
  write("index.json", index);
  const manifest = read("manifest.json");
  Object.assign(manifest, { lastRecordSequence: last, storedBytes: bytes, uncompressedBytes: bytes });
  Object.assign(manifest.eventCounts, { traceEvents: sequences.length, capturedEvents: sequences.length });
  Object.assign(manifest.session, { lastTransportSequence: last + 1n, recordsStreamed: sequences.length });
  Object.assign(manifest.checkpoint, { lastCommittedRecordSequence: last, lastCommittedEventId: ids.at(-1) });
  write("manifest.json", manifest);
  return directory;
}
function indexed(directory)
{
  const database = path.join(directory, "trace.db");
  const build = command(["trace-index-build", "--root", directory, "--database", database, "--rebuild"]);
  assert.equal(build.success, true, JSON.stringify(build));
  assert.equal(build.indexSchemaVersion, 2);
  const query = command(["trace-index-query", "--database", database, "--limit", "10"]);
  assert.equal(query.success, true);
  return query.events;
}
const sequences = ["0", "2", "9007199254740993"];
const positive = session("gaps-and-large", sequences);
assert.equal(command(["validate-session", "--session", positive]).success, true);
const replay = command(["replay-session", "--session", positive]);
assert.deepEqual(replay.traceEvents.map((event) => event.recordSequence), sequences);
assert.deepEqual(indexed(positive).map((event) => event.recordSequence), sequences);
const indexFile = path.join(positive, "trace.db");
const downgrade = new DatabaseSync(indexFile);
downgrade.exec("UPDATE metadata SET value='1' WHERE key='schema_version'; UPDATE trace_events SET record_sequence='123'; PRAGMA user_version=1;");
downgrade.close();
assert.equal(command(["trace-index-build", "--root", positive, "--database", indexFile]).success, false);
assert.equal(command(["trace-index-query", "--database", indexFile]).success, false);
assert.deepEqual(indexed(positive).map((event) => event.recordSequence), sequences);
const migrated = new DatabaseSync(indexFile);
assert.equal(migrated.prepare("PRAGMA table_info(trace_events)").all().find((column) => column.name === "record_sequence").type, "TEXT");
assert.equal(migrated.prepare("PRAGMA user_version").get().user_version, 2);
migrated.exec("UPDATE metadata SET value='1' WHERE key='schema_version'; UPDATE metadata SET value='foreign-format' WHERE key='format';");
migrated.close();
assert.equal(command(["trace-index-build", "--root", positive, "--database", indexFile, "--rebuild"]).success, false);
const preserved = new DatabaseSync(indexFile);
assert.equal(preserved.prepare("SELECT COUNT(*) AS count FROM trace_events").get().count, 3);
assert.equal(preserved.prepare("SELECT value FROM metadata WHERE key='schema_version'").get().value, "1");
preserved.close();
const foreignFile = path.join(root, "foreign.db");
const foreign = new DatabaseSync(foreignFile);
foreign.exec("CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES('keep');");
foreign.close();
const beforeForeign = fs.readFileSync(foreignFile);
assert.equal(command(["trace-index-build", "--root", positive, "--database", foreignFile, "--rebuild"]).success, false);
assert.deepEqual(fs.readFileSync(foreignFile), beforeForeign, "A foreign database must remain byte-identical.");
const legacy = session("legacy-unavailable", [undefined]);
assert.equal(indexed(legacy)[0].recordSequence, null);
const bounded = session("query-budget", Array.from({ length: 8 }, (_, index) => String(index + 1)));
indexed(bounded);
const boundedFile = path.join(bounded, "trace.db");
for (const limit of ["0", "5001", "4294967295"])
{
  const result = command(["trace-index-query", "--database", boundedFile, "--limit", limit]);
  assert.equal(result.success, false, `Unbounded query limit ${limit} must be rejected.`);
  assert.deepEqual(result.events, []);
}
const boundedDb = new DatabaseSync(boundedFile);
const nulText = "\0".repeat(256 * 1024);
const unicodeText = "a".repeat(239) + "\uac00".repeat(4);
boundedDb.prepare("UPDATE trace_events SET buffer_preview=?,event_json=?").run(nulText, unicodeText);
boundedDb.close();
const oneRow = command(["trace-index-query", "--database", boundedFile, "--limit", "1"]);
assert.equal(oneRow.success, true);
assert.equal(oneRow.events[0].bufferPreview, nulText, "SQLite text must preserve embedded NUL bytes.");
assert.equal(oneRow.events[0].excerpt, "a".repeat(239) + "...", "An excerpt cannot split a UTF-8 code point.");
const overBudget = command(["trace-index-query", "--database", boundedFile, "--limit", "8"]);
assert.equal(overBudget.success, false);
assert.match(overBudget.message, /byte budget/u);
assert.deepEqual(overBudget.events, [], "A failed query must not expose a partial result.");
const oversizedDb = new DatabaseSync(boundedFile);
oversizedDb.prepare("UPDATE trace_events SET event_json=? WHERE event_id=1").run("z".repeat(9 * 1024 * 1024));
oversizedDb.close();
const oversized = command(["trace-index-query", "--database", boundedFile, "--limit", "1"]);
assert.equal(oversized.success, false);
assert.deepEqual(oversized.events, []);
for (const [name, ids] of [["event-zero", [0, 2, 3]], ["event-duplicate", [1, 1, 3]], ["event-backward", [1, 3, 2]]])
{
  const directory = session(name, ["1", "2", "3"], [1, 3], ids);
  assert.equal(command(["validate-session", "--session", directory]).success, false, name);
  assert.equal(command(["replay-session", "--session", directory]).success, false, name);
}
for (const [name, values, range] of [
  ["duplicate", ["1", "1", "3"], [1, 3]],
  ["backwards", ["1", "3", "2", "4"], [1, 4]],
  ["out-of-range", ["1", "4", "3"], [1, 3]],
  ["missing-first", ["2", "3"], [1, 3]],
  ["missing-last", ["1", "2"], [1, 3]],
  ["mixed", ["1", undefined, "3"], [1, 3]],
  ["numeric", [1], [1]],
  ["leading-zero", ["01"], [1]],
  ["negative", ["-1"], [1]],
  ["signed-overflow", ["9223372036854775808"], [1]],
  ["uint-overflow", ["18446744073709551616"], [1]]
])
{
  const directory = session(name, values, range);
  assert.equal(command(["validate-session", "--session", directory]).success, false, name);
  assert.equal(command(["replay-session", "--session", directory]).success, false, name);
}
const sandbox = { exports: {}, TextEncoder };
const source = fs.readFileSync("apps/knmon-ui/src/session.ts", "utf8");
vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS,
  target: ts.ScriptTarget.ES2022 } }).outputText, sandbox);
const event = { ...replay.traceEvents[0], recordSequence: "9007199254740993", timeSource: "qpc",
  rawReturnValue: "18446744073709551615", rawLastErrorCode: 42, outcome: "pending",
  timing: { qpcBase: "9007199254740993" }, bufferPreview: undefined };
const exported = JSON.parse(sandbox.exports.buildJsonl([event]));
assert.deepEqual(exported, { ...event, bufferPreview: "" });
fs.writeFileSync(path.join(root, "evidence.json"), JSON.stringify({ success: true, sequences,
  rejectedIdentities: 14, rejectedQueryBounds: 5, legacy: "null" }, null, 2));
console.log(`Record identity and lossless export PASS: ${root}`);
