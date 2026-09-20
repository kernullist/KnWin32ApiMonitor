import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";
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
    assert.deepEqual(Array.from(view.entries), accepted && view.source === "legacy_unverified" ? fields.stack : [], name);
    if (accepted)
    {
      assert.deepEqual(view.hookContext, fields.hookContext, name);
      assert.match(view.message, view.source === "not_captured" ? /not captured/u : /no verified capture provenance/u);
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
      assert.equal(JSON.stringify(fields), before, name);
    }
    else
    {
      const event = createTraceEventFromAgentApiCall({ ...fields, tags: [], lastErrorCode: 0 }, 1, []);
      assert.equal(describeStackObservation(event).source, "invalid", name);
    }
  }
});
