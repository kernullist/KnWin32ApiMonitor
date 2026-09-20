import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { zstdCompressSync, constants } from "node:zlib";

const helper = path.resolve(process.argv[2] ?? "build/native-msvc/Debug/knmon-native-helper.exe");
const root = fs.mkdtempSync(path.resolve("build/large-replay-"));
const session = path.join(root, "large.knapm");
fs.cpSync("tests/fixtures/session/valid-knapm.knapm", session, { recursive: true });
const manifest = JSON.parse(fs.readFileSync(path.join(session, "manifest.json")));
const index = JSON.parse(fs.readFileSync(path.join(session, "index.json")));
const event = JSON.parse(fs.readFileSync(path.join(session, index.chunks[0].file), "utf8"));
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
index.chunks = [];
let stored = 0;
let plain = 0;
const count = 12000;
for (let chunk = 0; chunk < count / 1000; ++chunk)
{
    const lines = Array.from({ length: 1000 }, (_, offset) => JSON.stringify({ ...event,
        eventId: chunk * 1000 + offset + 1, bufferPreview: "payload=" + "abcdefgh".repeat(1024) })).join("\n") + "\n";
    const bytes = Buffer.from(lines);
    const encoded = zstdCompressSync(bytes, { params: { [constants.ZSTD_c_checksumFlag]: 1,
        [constants.ZSTD_c_contentSizeFlag]: chunk % 2 } });
    const file = `chunks/trace-${String(chunk + 1).padStart(6, "0")}.jsonl.zst`;
    fs.writeFileSync(path.join(session, file), encoded);
    stored += encoded.length;
    plain += bytes.length;
    index.chunks.push({ chunkSequence: chunk + 1, batchSequence: chunk + 1, file, compression: "zstd",
        eventCount: 1000, firstRecordSequence: chunk * 1000 + 1, lastRecordSequence: (chunk + 1) * 1000,
        firstEventId: chunk * 1000 + 1, lastEventId: (chunk + 1) * 1000,
        byteLength: encoded.length, sha256: hash(encoded), uncompressedByteLength: bytes.length, uncompressedSha256: hash(bytes) });
}
Object.assign(manifest, { chunkCount: index.chunks.length, lastBatchSequence: index.chunks.length, lastRecordSequence: count,
    storedBytes: stored, uncompressedBytes: plain, compression: "zstd", compressionAlgorithms: ["zstd"] });
Object.assign(manifest.eventCounts, { traceEvents: count, capturedEvents: count });
Object.assign(manifest.session, { recordsStreamed: count, lastTransportSequence: count });
Object.assign(manifest.checkpoint, { lastCommittedChunkSequence: index.chunks.length,
    lastCommittedBatchSequence: index.chunks.length, lastCommittedRecordSequence: count, lastCommittedEventId: count });
fs.writeFileSync(path.join(session, "manifest.json"), JSON.stringify(manifest));
fs.writeFileSync(path.join(session, "index.json"), JSON.stringify(index));
function run(args, success = true)
{
    const started = performance.now();
    const result = spawnSync(helper, ["replay-session", "--session", session, ...args],
        { encoding: "utf8", timeout: 300000, maxBuffer: 8 * 1024 * 1024, windowsHide: true });
    assert.ifError(result.error);
    const reply = JSON.parse(result.stdout);
    assert.equal(reply.success, success, reply.message);
    return { reply, milliseconds: Math.round(performance.now() - started), outputBytes: Buffer.byteLength(result.stdout) };
}
const tail = run(["--window-limit", "5000"]);
assert.equal(tail.reply.session.traceEventCount, count);
assert.equal(tail.reply.traceEvents.at(-1).eventId, count);
assert.ok(tail.reply.traceEvents.length <= 5000 && tail.reply.traceEvents.length > 0);
assert.ok(tail.outputBytes < 7 * 1024 * 1024);
const selected = run(["--window-limit", "100", "--selected-event-id", "1234"]);
assert.equal(selected.reply.traceEvents.length, 100);
assert.equal(selected.reply.traceEvents.at(-1).eventId, 1234);
run(["--window-limit", "100", "--selected-event-id", String(count + 1)], false);
run(["--window-limit", "not-a-number"], false);
run([], false);
const database = path.join(root, "trace.db");
const indexed = spawnSync(helper, ["trace-index-build", "--root", root, "--database", database, "--rebuild"],
    { encoding: "utf8", timeout: 300000, maxBuffer: 4 * 1024 * 1024, windowsHide: true });
assert.ifError(indexed.error);
const indexResult = JSON.parse(indexed.stdout);
assert.equal(indexResult.success, true, indexResult.message);
assert.equal(indexResult.eventCount, count);
const broken = index.chunks.at(-1);
const corrupt = fs.readFileSync(path.join(session, broken.file));
corrupt[corrupt.length - 1] ^= 1;
fs.writeFileSync(path.join(session, broken.file), corrupt);
broken.sha256 = hash(corrupt);
fs.writeFileSync(path.join(session, "index.json"), JSON.stringify(index));
run(["--window-limit", "100", "--selected-event-id", "1"], false);
console.log(JSON.stringify({ passed: true, rows: count, chunks: index.chunks.length, plainBytes: plain, storedBytes: stored,
    indexedRows: indexResult.eventCount,
    retainedRows: tail.reply.traceEvents.length, outputBytes: tail.outputBytes, replayMs: tail.milliseconds,
    selectedReplayMs: selected.milliseconds, evidence: root }));
