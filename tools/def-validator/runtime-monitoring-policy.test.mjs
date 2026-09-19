import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import vm from "node:vm";
import ts from "typescript";
import { generatedGenericAbiSafetyReasons, unsafeGeneratedGenericAbiType } from "./runtime-monitoring-policy.mjs";

test("unverified prototypes cannot enable the integer dispatcher", () =>
{
  for (const api of [
    { name: "wsprintfW", returnType: "INT", parameterCount: 2 },
    { name: "D2D1ConvertColorSpace", returnType: "D2D1_COLOR_F", parameterCount: 3 },
    { name: "VarR8FromR4", returnType: "ULONG_PTR", parameterCount: 16 },
    { name: "UnknownExport", returnType: "DWORD", parameterCount: 0, abiVerified: true },
    { name: "FloatingPoint", returnType: "double", parameterCount: 1 }
  ])
  {
    const parameters = Array.from({ length: api.parameterCount }, () => ({ type: "ULONG_PTR" }));
    const reasons = generatedGenericAbiSafetyReasons({ hookPolicy: "iat", callingConvention: "winapi", ...api }, parameters);
    assert.ok(reasons.includes("unverified_generated_abi"), api.name);
  }
});

test("unknown aggregate typedefs do not become pointers by name", () =>
{
  for (const type of ["POINT", "POINTL", "PROPVARIANT", "LARGE_INTEGER", "D2D1_COLOR_F", "FLOAT", "DOUBLE"])
  {
    assert.equal(unsafeGeneratedGenericAbiType(type), true, type);
  }
  assert.equal(unsafeGeneratedGenericAbiType("POINT*"), false);
});

test("runtime artifacts exclude the review counterexamples on every architecture", () =>
{
  const manifest = JSON.parse(fs.readFileSync(new URL("../../generated/runtime-support.json", import.meta.url)));
  assert.equal(manifest.generatedWrappers, 0);
  assert.equal(manifest.differentialVerifiedCount, 0);
  for (const keys of Object.values(manifest.architectures))
  {
    assert.ok(keys.includes("kernel32.dll!createfilew"));
    for (const key of ["user32.dll!wsprintfw", "d2d1.dll!d2d1convertcolorspace", "oleaut32.dll!varr8fromr4"])
    {
      assert.equal(keys.includes(key), false, key);
    }
    assert.equal(new Set(keys).size, keys.length);
  }
  assert.equal(manifest.architectures.arm64, undefined);
});

test("malformed parameter counts and variadic metadata are classified explicitly", () =>
{
  for (const parameterCount of [-1, 1.5, "2", 18])
  {
    const reasons = generatedGenericAbiSafetyReasons({ parameterCount }, []);
    assert.ok(reasons.includes("invalid_parameter_count"));
  }
  assert.ok(generatedGenericAbiSafetyReasons({ isVariadic: true }, []).includes("variadic_prototype"));
});

test("every compact selection of the supported subset fits the attach contract", () =>
{
  const manifest = JSON.parse(fs.readFileSync(new URL("../../generated/runtime-support.json", import.meta.url)));
  const groups = new Map();
  for (const key of manifest.supportedKeys)
  {
    const module = key.split("!")[0];
    const entries = groups.get(module) ?? [];
    entries.push(key);
    groups.set(module, entries);
  }
  let maximumLength = 0;
  for (const [module, keys] of groups)
  {
    const largestPartial = keys.map((key) => key.length + 1).sort((left, right) => right - left)
      .slice(0, keys.length - 1).reduce((sum, length) => sum + length, 0);
    maximumLength += Math.max(module.length + 3, largestPartial);
  }
  assert.ok(maximumLength <= 8191, `Compact selection bound exceeds attach capacity: ${maximumLength}`);
});

test("the UI retains blocked definitions but excludes them from every capture profile", () =>
{
  const manifest = JSON.parse(fs.readFileSync(new URL("../../generated/runtime-support.json", import.meta.url)));
  const source = fs.readFileSync(new URL("../../apps/knmon-ui/src/catalogData.ts", import.meta.url), "utf8");
  const compiled = ts.transpileModule(source, { compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true
  } }).outputText;
  const exports = {};
  const apis = [
    { module: "kernel32.dll", name: "CreateFileW", family: "file-io" },
    { module: "kernel32.dll", name: "ReadFile", family: "file-io" },
    { module: "user32.dll", name: "wsprintfW", family: "file-io" },
    { module: "d2d1.dll", name: "D2D1ConvertColorSpace", family: "network" },
    { module: "oleaut32.dll", name: "VarR8FromR4", family: "memory" }
  ];
  vm.runInNewContext(compiled, {
    exports,
    require(name)
    {
      if (name.endsWith("runtime-support.json"))
      {
        return manifest;
      }
      if (name.endsWith("definition-decoder-tables.json"))
      {
        return { apis };
      }
      throw new Error(`Unexpected UI dependency: ${name}`);
    }
  });
  assert.equal(exports.apiCatalogEntries.length, 5);
  for (const profile of exports.captureProfiles)
  {
    for (const key of profile.enabledApis)
    {
      assert.ok(["kernel32.dll!CreateFileW", "kernel32.dll!ReadFile"].includes(key));
    }
  }
  assert.equal(exports.captureProfiles[0].enabledApis.length, 2);
  assert.equal(exports.apiCatalogEntries.filter((entry) => !entry.runtimeSupported).length, 3);
  assert.equal(exports.compactRuntimeApiSelection(new Set(["kernel32.dll!CreateFileW"])).join(";"), "kernel32.dll!CreateFileW");
  assert.equal(exports.compactRuntimeApiSelection(new Set(exports.captureProfiles[0].enabledApis)).join(";"), "kernel32.dll!*");
  assert.equal(exports.compactRuntimeApiSelection(new Set(["user32.dll!wsprintfW"])).length, 0);
});
