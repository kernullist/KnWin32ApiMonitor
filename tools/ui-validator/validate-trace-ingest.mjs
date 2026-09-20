import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import ts from "typescript";

const cache = new Map();
function load(name)
{
    if (!cache.has(name))
    {
        const filename = path.resolve("apps/knmon-ui/src", `${name}.ts`);
        const code = ts.transpileModule(fs.readFileSync(filename, "utf8"), { compilerOptions: {
            target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS
        } }).outputText;
        const module = { exports: {} };
        vm.runInNewContext(code, { module, exports: module.exports, TextEncoder, setTimeout, clearTimeout,
            require: (dependency) => load(dependency.replace(/^\.\//, "")) }, { filename });
        cache.set(name, module.exports);
    }
    return cache.get(name);
}
const { TraceIngestState, TraceIngestClient, traceDisplayByteLimit } = load("traceIngestProtocol");
const { createTraceEventFromAgentApiCall } = load("traceConversion");
const { summarizeTraceCounts } = load("traceCounters");
function source(sequence)
{
    return { schemaVersion: "0.1.0", operationId: "ingest", messageType: "api_call", sequence,
        pid: 10, tid: 20, process: "sample.exe", module: "kernel32.dll", api: "GetCurrentProcessId",
        arguments: [], returnValue: "10", lastErrorCode: 0, lastErrorMessage: "", stack: [], durationUs: 1, tags: [] };
}
let window = [];
const counters = (retained, ingested, nativeStreamed) => JSON.parse(JSON.stringify(summarizeTraceCounts(retained, ingested, nativeStreamed)));
// A real live observation previously mislabeled these ten pending rows as trimmed.
assert.deepEqual(counters(220, 220, 230), { total: 230, trimmed: 0, notIngested: 10 });
assert.deepEqual(counters(250, 250, 250), { total: 250, trimmed: 0, notIngested: 0 });
assert.deepEqual(counters(250, 250, 230), { total: 250, trimmed: 0, notIngested: 0 });
assert.deepEqual(counters(5000, 6000, 6200), { total: 6200, trimmed: 1000, notIngested: 200 });
assert.deepEqual(counters(100, 9000000, 0), { total: 9000000, trimmed: 8999900, notIngested: 0 });
const state = new TraceIngestState();
function apply(request)
{
    const delta = state.apply(request);
    assert.ok(delta);
    window = delta.replace ? Array.from(delta.events) : window.slice(delta.evictCount).concat(Array.from(delta.events));
    assert.ok(window.length <= 5000);
    assert.equal(delta.estimatedSessionBytes, window.reduce((sum, event) => sum + Buffer.byteLength(JSON.stringify(event)), 0));
    return delta;
}
apply({ epoch: 1, sequence: 1, command: { type: "reset" } });
let clonedEvents = 0;
for (let batch = 0; batch < 200; ++batch)
{
    const events = Array.from({ length: 1000 }, (_, index) => source(batch * 1000 + index));
    const delta = apply({ epoch: 1, sequence: batch + 2, command: { type: "enqueue-events", chunks: [{ events, contextTags: ["corpus"] }] } });
    clonedEvents += delta.events.length;
    assert.equal(window.at(-1).eventId, (batch + 1) * 1000);
    assert.equal(delta.totalCapturedEvents, (batch + 1) * 1000);
    const counts = counters(window.length, delta.totalCapturedEvents, delta.totalCapturedEvents + 1000);
    assert.equal(counts.trimmed, Math.max(0, (batch + 1) * 1000 - window.length));
    assert.equal(counts.notIngested, 1000);
}
assert.equal(clonedEvents, 200000);
assert.equal(window[0].eventId, 195001);
assert.equal(state.apply({ epoch: 1, sequence: 201, command: { type: "reset" } }), null);
apply({ epoch: 2, sequence: 1, command: { type: "reset" } });
assert.equal(state.apply({ epoch: 1, sequence: 202, command: { type: "enqueue-events", chunks: [] } }), null);
const selected = createTraceEventFromAgentApiCall(source(0), 900, []);
const stackState = new TraceIngestState();
stackState.apply({ epoch: 1, sequence: 1, command: { type: "reset" } });
const uncaptured = { ...source(1), stackSource: "not_captured", hookContext: { agent: "knmon-agent64.dll", resolvedHostModule: "kernelbase.dll" } };
const oldStack = { ...source(2), stack: ["old-agent!IatHook", "module!Api"] };
const capturedStack = { ...source(3), stack: ["0x0000000012345678"], stackSource: "native_backtrace", stackCapture: {
    method: "rtl_capture_stack_back_trace", phase: "post_call", addressBits: 64, requestedFrames: 8,
    status: "captured", limitReached: false, exceptionCode: 0
} };
const stackDelta = stackState.apply({ epoch: 1, sequence: 2, command: { type: "enqueue-events", chunks: [{ events: [uncaptured, oldStack, capturedStack], contextTags: [] }] } });
for (const [index, original] of [uncaptured, oldStack, capturedStack].entries())
{
    const exported = JSON.parse(JSON.stringify(stackDelta.events[index]));
    assert.deepEqual(exported.stack, original.stack);
    assert.equal(exported.stackSource, original.stackSource ?? "legacy_unverified");
    assert.deepEqual(exported.hookContext, original.hookContext);
    assert.deepEqual(exported.stackCapture, original.stackCapture);
}
let delta = apply({ epoch: 3, sequence: 1, command: { type: "replace", events: [selected], selectedEventId: 900, totalCapturedEvents: 9000000 } });
assert.equal(delta.selectedEventId, 900);
assert.equal(delta.totalCapturedEvents, 9000000);
delta = apply({ epoch: 3, sequence: 2, command: { type: "enqueue-events", chunks: [{ events: [source(1)], contextTags: [] }] } });
assert.equal(window.at(-1).eventId, 901);
const huge = Array.from({ length: 10 }, (_, index) => ({ ...selected, eventId: index + 1, result: "\uD83D\uDE80".repeat(500000) }));
delta = apply({ epoch: 4, sequence: 1, command: { type: "replace", events: huge } });
assert.ok(window.length < 10);
assert.ok(delta.estimatedSessionBytes <= traceDisplayByteLimit);

const messages = [];
const patches = [];
const errors = [];
const worker = new TraceIngestState();
const client = new TraceIngestClient((request) => messages.push(request), (patch) => patches.push(patch), (error) => errors.push(error));
const first = client.submit({ type: "reset" });
const oldEpoch = client.epoch;
let latest;
for (let i = 0; i < 100; ++i)
{
    latest = client.submit({ type: "replace", events: [{ ...selected, eventId: i + 1 }] });
}
assert.equal(messages.length, 1, "reset storms must coalesce behind the outstanding ACK");
assert.equal(await first, false);
assert.equal(await client.submit({ type: "enqueue-events", chunks: [] }), false);
client.receive(worker.apply(messages.shift()));
assert.equal(patches.length, 0, "old epoch must not reach the display");
assert.equal(messages.length, 1);
const finalRequest = messages.shift();
const finalDelta = worker.apply(finalRequest);
client.receive(finalDelta);
assert.equal(await latest, true);
assert.equal(patches.length, 1);
assert.equal(patches[0].events[0].eventId, 100);
client.receive(finalDelta);
assert.equal(patches.length, 1, "duplicate ACK must not duplicate rows");
assert.equal(await client.submit({ type: "enqueue-events", chunks: [] }, oldEpoch), false);
client.abort();
assert.deepEqual(errors, []);
console.log("Trace ingest passed: 200000 rows, bounded delta/bytes, replacement, duplicate/stale ACK, coalesced reset storm.");
