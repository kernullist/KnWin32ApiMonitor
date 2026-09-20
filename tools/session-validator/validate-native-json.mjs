import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { inspectStrictJson, typedJsonValue, validateAgentJson } from "./strict-json.mjs";
import stackCases from "../../tests/fixtures/stack-observation.json" with { type: "json" };

const argument = process.argv.indexOf("--probe");
assert(argument >= 0, "Pass --probe <knmon-bounded-json-test.exe>.");
const executable = path.resolve(process.argv[argument + 1]);
const cases = [];
function add(name, text, kind = "", key = "x", extra = {})
{
    const bytes = Buffer.isBuffer(text) ? text : Buffer.from(text);
    cases.push({ name, wireHex: bytes.toString("hex"), kind, key, ...extra });
}

add("nested shadow", '{"nested":{"sessionId":"wrong"},"sessionId":"right"}', "string", "sessionId");
add("wrong string type", '{"sessionId":123,"other":"text"}', "string", "sessionId");
add("whitespace bool", '{"enabled":\n\r\ttrue}', "bool", "enabled");
for (const text of ['{"x":1,"x":2}', '{"x":1,"\\u0078":2}', '{"a":[{"b":1,"b":2}]}',
    '{"x":"\\ud800"}', '{"x":"\\udc00"}', '{"x":"\\ud800x"}', '{"x":"\\u0000"}',
    '{"\\u0000":1}', '{} trailing', '{}{}', '{"x":NaN}', '{"x":Infinity}', '{"x":1e999}',
    '{"x":01}', '{"x":1,}', '/*comment*/{}', '{"x":undefined}', '{"x":"\\v"}', '[]', 'null', 'true', ''])
{
    add(`malformed ${text}`, text);
}
for (const text of ['{}', '{"x":null}', '{"x":true}', '{"x":false}', '{"x":0}', '{"x":-0}', '{"x":-1}',
    '{"x":1.0}', '{"x":1e0}', '{"x":4294967295}', '{"x":4294967296}', '{"x":9007199254740993}',
    '{"x":18446744073709551615}', '{"x":18446744073709551616}', '{"x":"text"}',
    '{"x":"\\ud83d\\ude00"}', '{"x":{"a":"b"}}', '{"x":[{}]}', '{"x":[null]}', '{"x":[{},{}]}',
    '{"x":"한글"}', '{"__proto__":{"x":true},"x":false}'])
{
    for (const kind of ["string", "bool", "u32", "u64", "object", "array", "objects"])
    {
        add(`${kind} ${text}`, text, kind);
        add(`required ${kind} ${text}`, text, kind, "x", { required: true });
    }
}
for (const hex of ["efbbbf7b7d", "7b2278223a22c0af227d", "7b2278223a22eda080227d", "7b7d00", "7b2278223a22ff227d"])
{
    add(`encoding ${hex}`, Buffer.from(hex, "hex"));
}
for (const depth of [1, 2, 16, 32, 33, 1000])
{
    add(`depth ${depth}`, '{"x":'.repeat(depth) + "0" + "}".repeat(depth));
}
for (const count of [0, 1, 2, 3, 4])
{
    add(`container ${count}`, JSON.stringify({ x: Array(count).fill({}) }), "objects", "x", { containerItems: 2 });
    add(`nodes ${count}`, JSON.stringify({ x: Array(count).fill({}) }), "objects", "x", { values: 3 });
}
for (const count of [3, 4, 5])
{
    add(`string bytes ${count}`, JSON.stringify({ x: "a".repeat(count) }), "string", "x", { stringBytes: 4 });
    add(`document bytes ${count}`, '{}'.padEnd(count), "", "x", { documentBytes: 4 });
}
// Deterministic grammar mutations retain the failed case's seed and exact wire bytes.
let seed = 0x4b4e4d4f;
function random(maximum)
{
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed % maximum;
}
const source = Buffer.from('{"x":123,"enabled":true,"nested":{"x":"shadow"},"items":[{},{}]}');
for (let index = 0; index < 1500; ++index)
{
    const bytes = Buffer.from(source);
    for (let mutation = 0, count = 1 + random(4); mutation < count; ++mutation)
    {
        bytes[random(bytes.length)] = random(256);
    }
    add(`mutation ${index}`, bytes, ["string", "u64", "bool", "object"][index % 4]);
}

const envelope = {
    schemaVersion: "0.1.0", messageType: "agent_hello", operationId: "test", pid: 1234, tid: 1235,
    timestampUtc: "2026-09-20T00:00:00Z", sequence: 1, architecture: "x64", agentVersion: "0.3.0"
};
for (const message of [envelope, { ...envelope, messageType: "agent_shutdown", reason: "stopped", installedHooks: 3,
    restoredHooks: 3, failedHooks: 0, droppedCount: 0 }, { ...envelope, messageType: "dropped_events", droppedCount: 0 },
    { ...envelope, messageType: "api_call", module: "kernel32.dll", api: "ReadFile", process: "test.exe", returnValue: "1",
        lastErrorCode: 0, lastErrorMessage: "", durationUs: 1, arguments: [], tags: [], stack: [], bufferPreview: "" }])
{
    add("agent valid", JSON.stringify(message), "agent");
    for (const key of Object.keys(message))
    {
        const missing = { ...message };
        delete missing[key];
        add(`agent missing ${key}`, JSON.stringify(missing), "agent");
        for (const value of [null, {}, [], true, -1, 4294967296, ""])
        {
            add(`agent type ${key}`, JSON.stringify({ ...message, [key]: value }), "agent");
        }
    }
}

const apiArgument = { index: 0, name: "value", type: "DWORD", direction: "in", rawValue: "0", preCallValue: "0",
    postCallValue: "0", decodedValue: "0", decodeStatus: "decoded" };
const apiMessage = { ...envelope, messageType: "api_call", module: "kernel32.dll", api: "ReadFile", process: "test.exe",
    returnValue: "1", lastErrorCode: 0, lastErrorMessage: "", durationUs: 1, arguments: [apiArgument], tags: ["test"], stack: [], bufferPreview: "" };
add("agent argument", JSON.stringify(apiMessage), "agent");
for (const index of ["1.0", "1e0", "-0", "4294967296"])
{
    add(`agent argument integer ${index}`, JSON.stringify(apiMessage).replace('"index":0', `"index":${index}`), "agent");
}
for (const key of ["name", "type", "direction", "rawValue", "preCallValue", "postCallValue", "decodedValue", "decodeStatus"])
{
    add(`agent argument type ${key}`, JSON.stringify({ ...apiMessage, arguments: [{ ...apiArgument, [key]: 42 }] }), "agent");
}
for (const key of ["tags", "stack"])
{
    add(`agent string array ${key}`, JSON.stringify({ ...apiMessage, [key]: [null] }), "agent");
}

for (const [name, fields, accepted] of stackCases)
{
    const message = { ...apiMessage, ...fields };
    if (!Object.hasOwn(fields, "stack"))
    {
        delete message.stack;
    }
    const wire = JSON.stringify(message);
    let nodeAccepted = true;
    try
    {
        validateAgentJson(inspectStrictJson(Buffer.from(wire)));
    }
    catch
    {
        nodeAccepted = false;
    }
    assert.equal(nodeAccepted, accepted, name);
    add(`stack ${name}`, wire, "agent");
}

const nativeStack = stackCases.find(([name]) => name === "native captured x64")[1];
for (const key of ["addressBits", "requestedFrames", "exceptionCode"])
{
    const message = JSON.stringify({ ...apiMessage, ...nativeStack });
    const original = nativeStack.stackCapture[key];
    for (const token of [`${original}.0`, `${original}e0`, "-0"])
    {
        add(`native stack noncanonical ${key} ${token}`, message.replace(`"${key}":${original}`, `"${key}":${token}`), "agent");
    }
}

const expected = cases.map((entry) =>
{
    try
    {
        const limits = entry.kind === "agent" ? { documentBytes: 1024 * 1024, stringBytes: 64 * 1024, depth: 16, containerItems: 4096, values: 16384 } : entry;
        const parsed = inspectStrictJson(Buffer.from(entry.wireHex, "hex"), limits);
        assert.equal(parsed.root.type, "object");
        if (entry.kind === "agent")
        {
            validateAgentJson(parsed);
            return { accepted: true, value: "" };
        }
        return { accepted: true, value: entry.kind ? typedJsonValue(parsed, entry.key, entry.kind, entry.required) : "" };
    }
    catch
    {
        return { accepted: false };
    }
});
const run = spawnSync(executable, ["--probe"], {
    input: cases.map((entry) => JSON.stringify(entry)).join("\n") + "\n",
    encoding: "utf8", timeout: 30000, maxBuffer: 16 * 1024 * 1024, windowsHide: true
});
assert.equal(run.error, undefined);
assert.equal(run.status, 0, run.stderr);
const actual = run.stdout.trim().split(/\r?\n/u).map((line) => JSON.parse(line));
assert.equal(actual.length, cases.length);
for (let index = 0; index < cases.length; ++index)
{
    const context = JSON.stringify(cases[index]);
    assert.equal(actual[index].accepted, expected[index].accepted, context);
    if (actual[index].accepted)
    {
        if (["object", "array"].includes(cases[index].kind))
        {
            assert.deepEqual(JSON.parse(actual[index].value), JSON.parse(expected[index].value), context);
        }
        else
        {
            assert.equal(actual[index].value, expected[index].value, context);
        }
    }
}
const report = { cases: cases.length, accepted: actual.filter((entry) => entry.accepted).length, seed: "0x4b4e4d4f", executable };
fs.mkdirSync("build/world-class", { recursive: true });
fs.writeFileSync(`build/world-class/json-${path.basename(path.dirname(path.dirname(executable)))}.json`, JSON.stringify(report, null, 2));
console.log(`Native/Node JSON differential corpus passed: ${cases.length} cases.`);
