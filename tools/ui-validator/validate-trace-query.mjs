import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import vm from "node:vm";
import ts from "typescript";

const require = createRequire(import.meta.url);
const repoRoot = process.cwd();
const sourcePath = path.join(repoRoot, "apps", "knmon-ui", "src", "traceQuery.ts");
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
  filename: "traceQuery.cjs"
});

const {
  buildTraceIssueGroups,
  compileTraceQuery,
  matchesFreeTextFilter
} = sandbox.module.exports;

function makeEvent(overrides) {
  return {
    schemaVersion: "0.1.0",
    eventId: 1,
    relativeTimeMs: 10,
    pid: 1000,
    tid: 2000,
    process: "sample.exe",
    module: "KERNELBASE.dll",
    api: "CreateFileW",
    arguments: [
      {
        index: 0,
        type: "LPCWSTR",
        name: "lpFileName",
        direction: "in",
        preCallValue: "\"C:\\\\Temp\\\\a.txt\"",
        postCallValue: "\"C:\\\\Temp\\\\a.txt\"",
        rawValue: "\"C:\\\\Temp\\\\a.txt\"",
        decodedValue: "C:\\Temp\\a.txt",
        decodeStatus: "decoded"
      }
    ],
    returnValue: "TRUE",
    error: null,
    durationUs: 90,
    tags: ["file", "io"],
    stack: [],
    ...overrides
  };
}

const events = [
  makeEvent({ eventId: 1 }),
  makeEvent({
    eventId: 2,
    pid: 13064,
    module: "ntdll.dll",
    api: "NtCreateFile",
    returnValue: "0xc0000022",
    error: {
      kind: "ntstatus",
      code: "0xc0000022",
      message: "Access denied"
    },
    durationUs: 450,
    tags: ["file", "error"],
    arguments: [
      {
        index: 0,
        type: "POBJECT_ATTRIBUTES",
        name: "ObjectAttributes",
        direction: "in",
        preCallValue: "0x1234",
        postCallValue: "0x1234",
        rawValue: "0x1234",
        decodedValue: "unreadable",
        decodeStatus: "unreadable_memory"
      }
    ]
  })
];

function assertEqual(actual, expected, label) {
  const actualJson = JSON.stringify(actual);
  const expectedJson = JSON.stringify(expected);
  if (actualJson !== expectedJson) {
    throw new Error(`${label}: expected ${expectedJson}, got ${actualJson}`);
  }
}

let compiled = compileTraceQuery([
  { id: "api", field: "api", operator: "contains", value: "create" },
  { id: "pid", field: "pid", operator: "greater_than", value: "100" }
], "all");
assertEqual(events.filter(compiled.matches).map((event) => event.eventId), [1, 2], "all query");
assertEqual(compiled.invalidClauses.length, 0, "valid query invalid count");

compiled = compileTraceQuery([
  { id: "error", field: "error", operator: "exists", value: "" },
  { id: "slow", field: "durationUs", operator: "greater_than", value: "300" }
], "all");
assertEqual(events.filter(compiled.matches).map((event) => event.eventId), [2], "error and slow query");

compiled = compileTraceQuery([
  { id: "missing-error", field: "error", operator: "missing", value: "" }
], "all");
assertEqual(events.filter(compiled.matches).map((event) => event.eventId), [1], "missing error query");

compiled = compileTraceQuery([
  { id: "invalid", field: "api", operator: "greater_than", value: "5" },
  { id: "empty", field: "api", operator: "contains", value: "" }
], "any");
assertEqual(compiled.invalidClauses.map((clause) => clause.id), ["invalid", "empty"], "invalid clauses");
assertEqual(events.filter(compiled.matches).map((event) => event.eventId), [1, 2], "invalid clauses ignored");

assertEqual(matchesFreeTextFilter(events[1], "access denied"), true, "free text error");
assertEqual(matchesFreeTextFilter(events[0], "missing token"), false, "free text miss");

const issueGroups = buildTraceIssueGroups(events, 300);
assertEqual(issueGroups.some((group) => group.kind === "error" && group.count === 1), true, "error group");
assertEqual(issueGroups.some((group) => group.kind === "decode" && group.label === "unreadable_memory"), true, "decode group");
assertEqual(issueGroups.some((group) => group.kind === "duration" && group.label.includes("NtCreateFile")), true, "duration group");
assertEqual(issueGroups.some((group) => group.kind === "module_api" && group.label.includes("ntdll.dll!NtCreateFile")), true, "module api group");

console.log("Trace query validation passed.");
