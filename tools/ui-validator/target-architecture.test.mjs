import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";

const source = fs.readFileSync(new URL("../../apps/knmon-ui/src/targetArchitecture.ts", import.meta.url), "utf8");
const exports = {};
vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } }).outputText,
  { exports }, { filename: "targetArchitecture.cjs" });
const { normalizeNativeArchitecture, targetEligibilityReason } = exports;

test("the native WOW64 enumeration label is eligible only in a matching x86 tool", () =>
{
  const target = { architecture: "x86-wow64", status: "available" };
  assert.equal(normalizeNativeArchitecture(target.architecture), "x86");
  assert.equal(targetEligibilityReason(target, "x86"), null);
  assert.match(targetEligibilityReason(target, "x64"), /does not match this x64 build.*Win32\/x86/u);
  assert.equal(target.architecture, "x86-wow64");
});

test("canonical architectures, blocked target status and unsupported labels retain their gates", () =>
{
  for (const architecture of ["x86", "x64"])
  {
    assert.equal(targetEligibilityReason({ architecture, status: "available" }, architecture), null);
    assert.match(targetEligibilityReason({ architecture, status: "unsupported" }, architecture), /status is unsupported/u);
  }
  for (const architecture of ["arm64", "arm64ec", "unknown", "x86-wow64-other", "", "X86-WOW64"])
  {
    assert.equal(normalizeNativeArchitecture(architecture), "unknown");
    assert.match(targetEligibilityReason({ architecture, status: "available" }, "x86"), /unsupported/u);
  }
  assert.match(targetEligibilityReason(null, "x86"), /Select a target/u);
});
