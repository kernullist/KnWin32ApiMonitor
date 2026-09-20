import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { proofPath, proofErrors, sourceSnapshot } from "./proof.mjs";

test("ABI promotion requires current source and complete executed architecture evidence", () =>
{
  const proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
  const source = sourceSnapshot();
  assert.deepEqual(proofErrors(proof, source), []);
  for (const [field, replacement] of [
    ["source.sha256", "0".repeat(64)],
    ["source.files", []],
    ["apiKeys", ["user32.dll!wsprintfw"]],
    ["runs", []],
    ["runs.1.architecture", proof.runs[0].architecture],
    ["runs.0.abiDifferential", "not_run"],
    ["runs.0.liveInjectionReplay", "not_run"],
    ["runs.0.binaries", {}],
    ["runs.0.live.capturedEvents", 5],
    ["configuration", "Release"],
    ["windowsRelease", "unknown"]
  ])
  {
    const changed = structuredClone(proof);
    const parts = field.split(".");
    const key = parts.pop();
    let target = changed;
    for (const part of parts)
    {
      target = target[part];
    }
    target[key] = replacement;
    assert.ok(proofErrors(changed, source).length > 0);
  }
  assert.ok(proofErrors(null, source).length > 0);
  assert.ok(proofErrors({ runs: {} }, source).length > 0);
});
