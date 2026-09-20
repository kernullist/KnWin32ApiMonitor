import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";
import Ajv from "ajv/dist/2020.js";
import stackCases from "../../tests/fixtures/stack-observation.json" with { type: "json" };

function load(name)
{
  const source = fs.readFileSync(new URL(`../../apps/knmon-ui/src/${name}.ts`, import.meta.url), "utf8");
  const exports = {};
  vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText,
    { exports }, { filename: `${name}.cjs` });
  return exports;
}

const { describeStackObservation } = load("stackObservation");
const { createTraceEventFromAgentApiCall } = load("traceConversion");
const { buildJsonl } = load("session");

test("stack presentation rejects false capture claims and keeps legacy entries unverified", () =>
{
  for (const [name, fields, accepted] of stackCases)
  {
    const view = describeStackObservation(fields);
    assert.equal(view.source, accepted ? fields.stackSource ?? "legacy_unverified" : "invalid", name);
    assert.deepEqual(Array.from(view.entries), accepted && view.source !== "not_captured" ? fields.stack : [], name);
    if (accepted)
    {
      assert.deepEqual(view.hookContext, fields.hookContext, name);
      assert.match(view.message, view.source === "not_captured" ? /not captured/u :
        view.source === "native_backtrace" ? /post-call|Post-call/u : /no verified capture provenance/u);
    }
    else
    {
      assert.equal(view.hookContext, undefined, name);
      assert.match(view.message, /Invalid/u);
    }
  }
});

test("agent conversion preserves hook metadata and old strings through JSON export", () =>
{
  for (const [name, fields, accepted] of stackCases)
  {
    if (accepted)
    {
      const before = JSON.stringify(fields);
      const event = createTraceEventFromAgentApiCall({ ...fields, tags: [], lastErrorCode: 0 }, 1, []);
      const exported = JSON.parse(buildJsonl([event]));
      assert.deepEqual(exported.stack, fields.stack, name);
      assert.equal(exported.stackSource, fields.stackSource ?? "legacy_unverified", name);
      assert.deepEqual(exported.hookContext, fields.hookContext, name);
      assert.deepEqual(exported.stackCapture, fields.stackCapture, name);
      assert.equal(JSON.stringify(fields), before, name);
    }
    else
    {
      const event = createTraceEventFromAgentApiCall({ ...fields, tags: [], lastErrorCode: 0 }, 1, []);
      assert.equal(describeStackObservation(event).source, "invalid", name);
    }
  }
});

test("all capture commands forward the selected stack limit and default to disabled", async () =>
{
  const source = fs.readFileSync(new URL("../../apps/knmon-ui/src/backend.ts", import.meta.url), "utf8");
  const calls = [];
  const exports = {};
  vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText,
    { exports, window: { __TAURI_INTERNALS__: {} }, require: (name) =>
      {
        assert.equal(name, "@tauri-apps/api/core");
        return { invoke: async (command, args) =>
        {
          calls.push({ command, args });
          return {};
        } };
      }
    });
  const apis = ["kernel32.dll!CloseHandle"];
  await exports.attachTargetProcessCapture(123, 500, apis, 32);
  await exports.startStreamingAttachSession(123, apis, 32);
  await exports.startLaunchMonitorSession("C:\\target.exe", "C:\\", "", apis, 32);
  await exports.startDaemonSupervisedSession(123, apis, 32);
  await exports.superviseProcessTree(123, 500, "attach-supported", apis, 32);
  assert.equal(new Set(calls.map((call) => call.command)).size, 5);
  for (const call of calls)
  {
    assert.equal(call.args.stackFrames, 32);
    assert.deepEqual(call.args.selectedApis, apis);
  }
  await exports.startStreamingAttachSession(123);
  assert.equal(calls.at(-1).args.stackFrames, 0);
});

test("published stack schemas match native observation and frame-limit contracts", () =>
{
  const ajv = new Ajv({ strict: false, allErrors: false, validateFormats: false });
  for (const name of ["argument", "stack-observation", "capture-detail", "event", "agent-event", "launch-request"])
  {
    ajv.addSchema(JSON.parse(fs.readFileSync(new URL(`../../contracts/${name}.schema.json`, import.meta.url), "utf8")));
  }
  const schema = (name) => ajv.getSchema(`https://kernullist.local/knmon/${name}.schema.json`);
  const trace = schema("event");
  const agent = schema("agent-event");
  const observation = schema("stack-observation");
  const launch = schema("launch-request");
  const base = { schemaVersion: "0.1.0", eventId: 1, relativeTimeMs: 0, pid: 1, tid: 1,
    process: "test.exe", module: "kernel32.dll", api: "CloseHandle", arguments: [], returnValue: "1", durationUs: 1,
    tags: [], messageType: "api_call", operationId: "test", timestampUtc: "2026-09-21T00:00:00Z", sequence: 1 };
  for (const [name, fields, accepted] of stackCases)
  {
    for (const validate of [trace, agent])
    {
      assert.equal(validate({ ...base, ...fields }), accepted, name + ": " + JSON.stringify(validate.errors));
    }
  }
  for (let requestedFrames = 1; requestedFrames <= 32; ++requestedFrames)
  {
    for (const count of new Set([0, 1, requestedFrames - 1, requestedFrames, requestedFrames + 1]))
    {
      for (const limitReached of [false, true])
      {
        const value = { stackSource: "native_backtrace", stack: Array(count).fill("0x0000000012345678"),
          stackCapture: { method: "rtl_capture_stack_back_trace", phase: "post_call", addressBits: 64,
            requestedFrames, status: count === 0 ? "empty" : "captured", limitReached, exceptionCode: 0 } };
        const accepted = count <= requestedFrames && limitReached === (count === requestedFrames);
        assert.equal(observation(value), accepted, `${requestedFrames}/${count}/${limitReached}`);
        assert.equal(describeStackObservation(value).source !== "invalid", accepted);
      }
    }
  }
  assert(agent({ ...base, messageType: "agent_hello", architecture: "x64", agentVersion: "test", message: "hello" }));
  for (const [hookPolicy, coverageStatus] of [["tier1_generic_iat", "generic_decoded"],
    ["tier2_api_set_iat", "api_set_generic"], ["tier2_return_only_iat", "generic_return_only"]])
  {
    assert(agent({ ...base, stack: [], hookPolicy, coverageStatus }));
  }
  assert.equal(agent({ ...base, stack: [], hookPolicy: 1 }), false);
  assert.equal(agent({ ...base, stack: [], coverageStatus: false }), false);
  assert(trace({ ...base, stack: [], error: { kind: "winsock", code: "10061", message: "Connection refused." },
    arguments: [{ index: 0, name: "buffer", type: "void*", direction: "out", rawValue: "0", preCallValue: "0", postCallValue: "0",
      decodedValue: "", decodeStatus: "not_captured" }] }));
  const request = { schemaVersion: "0.1.0", operationId: "test", targetPath: "test.exe", agentPath: "agent.dll",
    architecture: "x64", injectionMethod: "early-bird APC", timeoutMs: 1000 };
  assert(launch(request));
  for (const value of [0, 1, 8, 16, 32, -1, 33, 1.5, true, null, "32"])
  {
    assert.equal(launch({ ...request, stackFrames: value }), Number.isInteger(value) && value >= 0 && value <= 32);
  }
});
