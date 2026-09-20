import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";
import Ajv from "ajv/dist/2020.js";
import cases from "../../tests/fixtures/capture-detail.json" with { type: "json" };

function load(name)
{
  const source = fs.readFileSync(new URL(`../../apps/knmon-ui/src/${name}.ts`, import.meta.url), "utf8");
  const exports = {};
  vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText,
    { exports }, { filename: `${name}.cjs` });
  return exports;
}

test("capture detail contracts reject omitted and contradictory payloads across import and export", () =>
{
  const { describeCaptureDetail, createTraceEventFromAgentApiCall } = load("traceConversion");
  const { buildJsonl } = load("session");
  const ajv = new Ajv({ strict: false, validateFormats: false });
  for (const name of ["argument", "stack-observation", "capture-detail", "event", "agent-event"])
  {
    ajv.addSchema(JSON.parse(fs.readFileSync(new URL(`../../contracts/${name}.schema.json`, import.meta.url), "utf8")));
  }
  const base = { schemaVersion: "0.1.0", eventId: 1, relativeTimeMs: 0, pid: 1, tid: 1, stack: [],
    process: "test.exe", module: "kernel32.dll", api: "CloseHandle", returnValue: "1", durationUs: 1,
    tags: [], lastErrorCode: 0, messageType: "api_call", operationId: "test", timestampUtc: "2026-09-21T00:00:00Z", sequence: 1 };
  for (const [name, fields, accepted] of cases)
  {
    const source = { ...base, ...fields };
    assert.equal(describeCaptureDetail(source).detail !== "invalid", accepted, name);
    for (const schema of ["event", "agent-event"])
    {
      const validate = ajv.getSchema(`https://kernullist.local/knmon/${schema}.schema.json`);
      assert.equal(validate(source), accepted, `${name}: ${JSON.stringify(validate.errors)}`);
    }
    if (accepted)
    {
      const trace = createTraceEventFromAgentApiCall(source, 7, []);
      const exported = JSON.parse(buildJsonl([trace]));
      assert.equal(exported.captureDetail, fields.captureDetail, name);
      assert.deepEqual(exported.arguments, fields.arguments, name);
      assert.equal(exported.bufferPreview, fields.bufferPreview, name);
      assert.notEqual(describeCaptureDetail(exported).detail, "invalid", name);
    }
    else
    {
      assert.throws(() => createTraceEventFromAgentApiCall(source, 7, []), /capture detail/u, name);
    }
  }
});

test("all five capture commands preserve detail and keep preview as the default", async () =>
{
  const source = fs.readFileSync(new URL("../../apps/knmon-ui/src/backend.ts", import.meta.url), "utf8");
  const calls = [];
  const exports = {};
  vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText,
    { exports, window: { __TAURI_INTERNALS__: {} }, require: () => ({ invoke: async (command, args) =>
    {
      calls.push({ command, args });
      return {};
    } }) });
  for (const detail of ["metadata", "arguments", "preview"])
  {
    const apis = ["kernel32.dll!ReadFile"];
    await exports.attachTargetProcessCapture(123, 500, apis, 8, detail);
    await exports.startStreamingAttachSession(123, apis, 8, detail);
    await exports.startLaunchMonitorSession("C:\\target.exe", "C:\\", "", apis, 8, detail);
    await exports.startDaemonSupervisedSession(123, apis, 8, detail);
    await exports.superviseProcessTree(123, 500, "attach-supported", apis, 8, detail);
    for (const call of calls.slice(-5))
    {
      assert.equal(call.args.captureDetail, detail);
      assert.equal(call.args.stackFrames, 8);
    }
  }
  await exports.startStreamingAttachSession(123);
  assert.equal(calls.at(-1).args.captureDetail, "preview");
});

test("uncaptured arguments stay queryable without false decode failures in any view", () =>
{
  const { buildTraceHighlightState } = load("traceHighlights");
  const { buildTraceThreadGroups, buildTraceTimeline } = load("traceViews");
  const { buildTraceIssueGroups, compileTraceQuery } = load("traceQuery");
  const makeArgument = (decodeStatus) => ({ index: 0, name: "lpBuffer", type: "LPVOID", direction: "out",
    rawValue: "0x1234", preCallValue: "", postCallValue: "", decodedValue: "", decodeStatus });
  const event = { schemaVersion: "0.1.0", eventId: 1, relativeTimeMs: 0, pid: 1, tid: 1,
    process: "sample.exe", module: "kernel32.dll", api: "ReadFile", arguments: [],
    returnValue: "TRUE", error: null, durationUs: 1, tags: [], stack: [], captureDetail: "arguments", bufferPreview: "" };
  for (const status of ["decoded", "not_captured", "partial", "invalid_pointer", "unreadable_memory", "definition_missing", "truncated"])
  {
    event.arguments = [makeArgument(status)];
    const expected = status === "decoded" || status === "not_captured" ? 0 : 1;
    const highlights = buildTraceHighlightState([event], 0);
    assert.equal(highlights.summaries.find((row) => row.id === "decode-failure").count, expected, status);
    assert.equal(buildTraceThreadGroups([event], 0)[0].decodeFailureCount, expected, status);
    assert.equal(buildTraceTimeline([event], 0).buckets[0].decodeFailureCount, expected, status);
    assert.equal(buildTraceIssueGroups([event], 0).filter((row) => row.kind === "decode").length, expected, status);
    assert.equal(compileTraceQuery([{ id: "status", field: "decodeStatus", operator: "equals", value: status }], "all").matches(event), true, status);
  }
  event.arguments = [makeArgument("not_captured"), makeArgument("unreadable_memory")];
  const mixed = buildTraceHighlightState([event], 0);
  assert.equal(mixed.eventHighlights[0].matches[0].reason, "decode=unreadable_memory");
  assert.deepEqual(Array.from(mixed.summaries.find((row) => row.id === "decode-failure").clauses, (row) => row.value), ["unreadable_memory"]);
  event.arguments = [makeArgument("not_captured")];
  event.error = { kind: "win32", code: "6", message: "Invalid handle" };
  const failed = buildTraceHighlightState([event], 0);
  assert.equal(failed.summaries.find((row) => row.id === "error-return").count, 1);
  assert.equal(failed.summaries.find((row) => row.id === "decode-failure").count, 0);
});
