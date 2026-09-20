import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import Ajv from "ajv/dist/2020.js";
import cases from "../../tests/fixtures/agent-readiness.json" with { type: "json" };

test("published agent readiness schema requires bounded capture policy", () =>
{
  const ajv = new Ajv({ strict: false, validateFormats: false });
  for (const name of ["argument", "stack-observation", "capture-detail", "agent-event"])
  {
    ajv.addSchema(JSON.parse(fs.readFileSync(new URL(`../../contracts/${name}.schema.json`, import.meta.url), "utf8")));
  }
  const validate = ajv.getSchema("https://kernullist.local/knmon/agent-event.schema.json");
  for (const [name, fields, accepted] of cases)
  {
    const message = { schemaVersion: "0.1.0", messageType: "agent_ready", operationId: "test", pid: 1, tid: 1,
      timestampUtc: "2026-09-21T00:00:00Z", sequence: 2, ...fields };
    assert.equal(validate(message), accepted, `${name}: ${JSON.stringify(validate.errors)}`);
  }
});
