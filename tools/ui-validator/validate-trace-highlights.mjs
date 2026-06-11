import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import vm from "node:vm";
import ts from "typescript";

const require = createRequire(import.meta.url);
const repoRoot = process.cwd();
const sourcePath = path.join(repoRoot, "apps", "knmon-ui", "src", "traceHighlights.ts");
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
  filename: "traceHighlights.cjs"
});

const {
  buildTraceHighlightState,
  compareTraceHighlightSeverity
} = sandbox.module.exports;

function makeArgument(decodeStatus = "decoded") {
  return {
    index: 0,
    type: "LPCWSTR",
    name: "lpFileName",
    direction: "in",
    preCallValue: "\"C:\\\\Temp\\\\a.txt\"",
    postCallValue: "\"C:\\\\Temp\\\\a.txt\"",
    rawValue: "\"C:\\\\Temp\\\\a.txt\"",
    decodedValue: "C:\\Temp\\a.txt",
    decodeStatus
  };
}

function makeEvent(overrides) {
  return {
    schemaVersion: "0.1.0",
    eventId: 1,
    relativeTimeMs: 0,
    pid: 1000,
    tid: 2000,
    process: "sample.exe",
    module: "KERNELBASE.dll",
    api: "CreateFileW",
    arguments: [makeArgument()],
    returnValue: "TRUE",
    error: null,
    durationUs: 90,
    tags: ["file", "io"],
    stack: [],
    ...overrides
  };
}

function assertEqual(actual, expected, label) {
  const actualJson = JSON.stringify(actual);
  const expectedJson = JSON.stringify(expected);
  if (actualJson !== expectedJson) {
    throw new Error(`${label}: expected ${expectedJson}, got ${actualJson}`);
  }
}

function summaryById(state, id) {
  const summary = state.summaries.find((item) => item.id === id);
  if (!summary) {
    throw new Error(`missing summary ${id}`);
  }

  return summary;
}

const emptyState = buildTraceHighlightState([], 100);
assertEqual(emptyState.eventHighlights.length, 0, "empty event highlights");
assertEqual(emptyState.summaries.map((summary) => [summary.id, summary.count]), [
  ["error-return", 0],
  ["decode-failure", 0],
  ["slow-call", 0],
  ["coverage-hint", 0],
  ["metadata-quality", 0]
], "empty summaries");
assertEqual(summaryById(emptyState, "error-return").clauses.map((clause) => clause.field), ["error"], "error clauses");

const cleanState = buildTraceHighlightState([
  makeEvent({ eventId: 1, api: "CreateFileW", module: "KERNELBASE.dll", durationUs: 90 })
], 100);
assertEqual(cleanState.eventHighlights.length, 0, "clean no-match session");
assertEqual(cleanState.summaries.every((summary) => summary.count === 0), true, "clean summary counts");

const events = [
  makeEvent({ eventId: 1, api: "CreateFileW", module: "KERNELBASE.dll", durationUs: 90 }),
  makeEvent({
    eventId: 2,
    api: "NtCreateFile",
    module: "ntdll.dll",
    durationUs: 450,
    returnValue: "0xc0000022",
    error: {
      kind: "ntstatus",
      code: "0xc0000022",
      message: "Access denied"
    },
    arguments: [makeArgument("unreadable_memory")]
  }),
  makeEvent({
    eventId: 3,
    api: "ReadFile",
    module: "KERNELBASE.dll",
    durationUs: 650
  }),
  makeEvent({
    eventId: 4,
    api: "unknown",
    module: "",
    durationUs: 10
  })
];

const state = buildTraceHighlightState(events, 300);
assertEqual(state.eventHighlights.map((highlight) => highlight.eventId), [2, 3, 4], "highlighted event ids");
assertEqual(state.eventHighlightsById.get(2).highestSeverity, "critical", "highest severity");
assertEqual(state.eventHighlightsById.get(2).matches.map((match) => match.ruleId), [
  "error-return",
  "decode-failure",
  "slow-call",
  "coverage-hint"
], "multi-rule severity order");
assertEqual(summaryById(state, "error-return").count, 1, "error count");
assertEqual(summaryById(state, "decode-failure").count, 1, "decode count");
assertEqual(summaryById(state, "slow-call").count, 2, "slow count");
assertEqual(summaryById(state, "coverage-hint").count, 1, "coverage count");
assertEqual(summaryById(state, "metadata-quality").count, 1, "metadata count");
assertEqual(summaryById(state, "decode-failure").clauses, [
  { field: "decodeStatus", operator: "equals", value: "unreadable_memory" }
], "decode clauses");
assertEqual(summaryById(state, "slow-call").clauses, [
  { field: "durationUs", operator: "greater_than", value: "299" }
], "slow clauses");
assertEqual(summaryById(state, "metadata-quality").matchMode, "any", "metadata match mode");
assertEqual(summaryById(state, "metadata-quality").clauses.some((clause) => clause.field === "module" && clause.operator === "missing"), true, "metadata missing clause");
assertEqual(summaryById(state, "metadata-quality").clauses.some((clause) => clause.field === "api" && clause.value === "unknown"), true, "metadata unknown api clause");
assertEqual(summaryById(state, "coverage-hint").matchMode, "any", "coverage match mode");
assertEqual(summaryById(state, "coverage-hint").clauses.some((clause) => clause.field === "api" && clause.operator === "starts_with" && clause.value === "Nt"), true, "coverage query clause");

const highThresholdState = buildTraceHighlightState(events, 500);
assertEqual(summaryById(highThresholdState, "slow-call").count, 1, "slow threshold change");
assertEqual(summaryById(highThresholdState, "slow-call").clauses[0].value, "499", "slow threshold clause change");

assertEqual(compareTraceHighlightSeverity("critical", "warning") < 0, true, "critical sorts before warning");
assertEqual(compareTraceHighlightSeverity("muted", "info") > 0, true, "muted sorts after info");

console.log("Trace highlight validation passed.");
