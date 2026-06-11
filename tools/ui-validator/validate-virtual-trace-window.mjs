import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import vm from "node:vm";
import ts from "typescript";

const require = createRequire(import.meta.url);
const repoRoot = process.cwd();
const sourcePath = path.join(repoRoot, "apps", "knmon-ui", "src", "virtualTrace.ts");
const source = fs.readFileSync(sourcePath, "utf8");
const transpiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2020,
    strict: true
  }
});

const sandbox = {
  exports: {},
  module: { exports: {} },
  require
};
sandbox.exports = sandbox.module.exports;
vm.runInNewContext(transpiled.outputText, sandbox, {
  filename: "virtualTrace.cjs"
});

const { computeVirtualTraceWindow } = sandbox.module.exports;
if (typeof computeVirtualTraceWindow !== "function") {
  throw new Error("computeVirtualTraceWindow export missing");
}

function assertEqual(actual, expected, label) {
  const actualJson = JSON.stringify(actual);
  const expectedJson = JSON.stringify(expected);
  if (actualJson !== expectedJson) {
    throw new Error(`${label}: expected ${expectedJson}, got ${actualJson}`);
  }
}

assertEqual(
  computeVirtualTraceWindow({
    itemCount: 0,
    rowHeight: 27,
    viewportHeight: 270,
    scrollTop: 0,
    overscan: 4
  }),
  {
    startIndex: 0,
    endIndex: 0,
    offsetTop: 0,
    totalHeight: 0,
    visibleCount: 0
  },
  "empty window"
);

assertEqual(
  computeVirtualTraceWindow({
    itemCount: 1000,
    rowHeight: 27,
    viewportHeight: 270,
    scrollTop: 0,
    overscan: 4
  }),
  {
    startIndex: 0,
    endIndex: 15,
    offsetTop: 0,
    totalHeight: 27000,
    visibleCount: 15
  },
  "top window"
);

assertEqual(
  computeVirtualTraceWindow({
    itemCount: 1000,
    rowHeight: 27,
    viewportHeight: 270,
    scrollTop: 2700,
    overscan: 4
  }),
  {
    startIndex: 96,
    endIndex: 115,
    offsetTop: 2592,
    totalHeight: 27000,
    visibleCount: 19
  },
  "middle window"
);

assertEqual(
  computeVirtualTraceWindow({
    itemCount: 1000,
    rowHeight: 27,
    viewportHeight: 270,
    scrollTop: 999999,
    overscan: 4
  }),
  {
    startIndex: 986,
    endIndex: 1000,
    offsetTop: 26622,
    totalHeight: 27000,
    visibleCount: 14
  },
  "clamped bottom window"
);

console.log("Virtual trace window validation passed.");
