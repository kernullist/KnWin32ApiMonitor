import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import vm from "node:vm";
import ts from "typescript";
import { validateStackObservation } from "./strict-json.mjs";

const directory = process.argv[2];
assert.ok(directory, "Saved live capture directory required.");
const stackFrames = Number(process.argv[3] ?? 0);
assert.ok(Number.isInteger(stackFrames) && stackFrames >= 0 && stackFrames <= 32);
const read = (name) => JSON.parse(fs.readFileSync(path.join(directory, name), "utf8").replace(/^\uFEFF/, ""));
const capture = read("capture-result.json");
const replay = read("replay-result.json");
assert.equal(capture.success, true);
assert.equal(replay.success, true);
assert.ok(capture.capturedEvents.length > 100);
assert.equal(capture.capturedEvents.length, replay.traceEvents.length);
const source = fs.readFileSync("apps/knmon-ui/src/traceConversion.ts", "utf8");
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } });
const sandbox = { exports: {} };
vm.runInNewContext(compiled.outputText, sandbox);
const convert = sandbox.exports.createTraceEventFromAgentApiCall;
const plain = (value) => JSON.parse(JSON.stringify(value));
const decimal = (value) =>
{
    assert.match(value, /^(0|[1-9][0-9]*)$/);
    const integer = BigInt(value);
    assert.ok(integer <= 0xffffffffffffffffn);
    return integer;
};
let fractional = 0;
let errors = 0;
let resolvedHosts = 0;
for (let index = 0; index < capture.capturedEvents.length; ++index)
{
    const event = capture.capturedEvents[index];
    const saved = replay.traceEvents[index];
    const timing = event.timing;
    validateStackObservation(event);
    assert.equal(event.stackSource, stackFrames === 0 ? "not_captured" : "native_backtrace");
    if (stackFrames === 0)
    {
        assert.deepEqual(event.stack, []);
    }
    else
    {
        assert.equal(event.stackCapture.requestedFrames, stackFrames);
        assert.equal(event.stackCapture.addressBits, capture.architecture === "x86" ? 32 : 64);
        assert.equal(event.stackCapture.status, "captured");
        assert.ok(event.stack.length > 0 && event.stack.length <= stackFrames);
    }
    assert.match(event.hookContext.agent, /^knmon-agent(32|64)\.dll$/u);
    if (event.resolvedHostModule)
    {
        assert.equal(event.hookContext.resolvedHostModule, event.resolvedHostModule);
        ++resolvedHosts;
    }
    assert.equal(event.timeSource, "qpc");
    const frequency = decimal(timing.qpcFrequency);
    const base = decimal(timing.qpcBase);
    const start = decimal(timing.startQpc);
    const end = decimal(timing.endQpc);
    assert.ok(frequency > 0n && start >= base && end >= start);
    assert.equal(event.relativeTimeMs, Number((start - base) * 1000000n / frequency) / 1000);
    assert.equal(event.durationUs, Number((end - start) * 1000000n / frequency));
    const utc = decimal(timing.utcBaseFileTime) + (start - base) * 10000000n / frequency;
    const fraction = event.timestampUtc.match(/\.([0-9]{7})Z$/)?.[1];
    assert.ok(fraction);
    const parsedUtc = BigInt(Date.parse(event.timestampUtc)) * 10000n + 116444736000000000n + BigInt(fraction.slice(3));
    assert.equal(parsedUtc, utc);
    const live = plain(convert(event, saved.eventId, []));
    for (const key of ["recordSequence", "observation", "arguments", "callId", "parentCallId", "callDepth", "rawReturnBytes", "rawReturnEncoding",
        "relativeTimeMs", "durationUs", "timeSource", "timing", "timestampUtc", "collectedAtUtc",
        "rawReturnValue", "rawReturnBits", "rawLastErrorCode", "rawWinsockErrorCode", "errorDomain", "outcome",
        "errorValidity", "successPredicate", "winsockErrorSampled", "error", "stack", "stackSource", "stackCapture", "hookContext"])
    {
        assert.deepEqual(live[key], saved[key], `${event.api}: live/replay ${key}`);
    }
    if (event.rawReturnBytes !== undefined)
    {
        assert.match(event.rawReturnBytes, /^[0-9a-f]{32}$/u);
        assert.equal(event.rawReturnValue, undefined);
    }
    else
    {
        decimal(event.rawReturnValue);
    }
    const delayed = plain(convert({ ...event, collectedAtUtc: "2099-01-01T00:00:00Z" }, saved.eventId, []));
    assert.equal(delayed.relativeTimeMs, live.relativeTimeMs);
    assert.equal(delayed.timestampUtc, live.timestampUtc);
    if (!Number.isInteger(live.relativeTimeMs))
    {
        ++fractional;
    }
    if (live.error !== null)
    {
        ++errors;
    }
}
// Late records and another session cannot move an earlier event's origin.
const first = capture.capturedEvents[0];
const before = plain(convert(first, 1, []));
for (const event of [...capture.capturedEvents].reverse())
{
    convert({ ...event, sequence: 999999999, timestampUtc: "1970-01-01T00:00:00Z" }, 2, []);
}
assert.deepEqual(plain(convert(first, 1, [])), before);
const legacy = plain(convert({ ...first, timing: undefined, timeSource: undefined, relativeTimeMs: undefined }, 1, []));
assert.equal(legacy.relativeTimeMs, 0);
assert.equal(legacy.timeSource, "unavailable");
assert.ok(fractional > 0 && errors > 0);
assert.ok(resolvedHosts > 0, "Resolved API-set host context was not exercised.");
for (const api of ["PSRefreshPropertySchema", "WscQueryAntiMalwareUri", "RatingEnabledQuery"])
{
    const event = capture.capturedEvents.find((entry) => entry.api === api);
    assert.equal(event?.errorDomain, "hresult", api);
}
assert.equal(capture.capturedEvents.find((entry) => entry.api === "BCryptDestroyKey")?.errorDomain, "ntstatus");
console.log(`Capture semantics passed: ${capture.capturedEvents.length} events; ${fractional} fractional timestamps; ${errors} errors; ${resolvedHosts} resolved hosts.`);
