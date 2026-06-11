import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import vm from "node:vm";
import ts from "typescript";

const require = createRequire(import.meta.url);
const repoRoot = process.cwd();
const sourcePath = path.join(repoRoot, "apps", "knmon-ui", "src", "traceViews.ts");
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
  filename: "traceViews.cjs"
});

const {
  buildTraceThreadGroups,
  buildTraceTimeline,
  chooseTimelineBucketSizeMs
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

const emptyThreads = buildTraceThreadGroups([], 100);
assertEqual(emptyThreads.length, 0, "empty threads");
const emptyTimeline = buildTraceTimeline([], 100);
assertEqual(emptyTimeline, {
  bucketSizeMs: 1,
  startRelativeTimeMs: 0,
  endRelativeTimeMs: 0,
  buckets: []
}, "empty timeline");

const singleEvent = makeEvent({
  eventId: 1,
  relativeTimeMs: 42
});
const singleThreads = buildTraceThreadGroups([singleEvent], 100);
assertEqual(singleThreads.length, 1, "single thread count");
assertEqual(singleThreads[0].spanMs, 0, "single thread span");
assertEqual(singleThreads[0].clauses.map((clause) => clause.field), ["process", "pid", "tid"], "thread clauses");
const singleTimeline = buildTraceTimeline([singleEvent], 100);
assertEqual(singleTimeline.bucketSizeMs, 1, "single bucket size");
assertEqual(singleTimeline.buckets.length, 1, "single timeline bucket");
assertEqual(singleTimeline.buckets[0].eventCount, 1, "single bucket events");

const events = [
  makeEvent({
    eventId: 1,
    relativeTimeMs: 0,
    pid: 1000,
    tid: 2000,
    process: "sample.exe",
    module: "KERNELBASE.dll",
    api: "CreateFileW",
    durationUs: 90
  }),
  makeEvent({
    eventId: 2,
    relativeTimeMs: 120,
    pid: 1000,
    tid: 2000,
    process: "sample.exe",
    module: "ntdll.dll",
    api: "NtCreateFile",
    error: {
      kind: "ntstatus",
      code: "0xc0000022",
      message: "Access denied"
    },
    durationUs: 450,
    arguments: [makeArgument("unreadable_memory")]
  }),
  makeEvent({
    eventId: 3,
    relativeTimeMs: 560,
    pid: 1000,
    tid: 2100,
    process: "sample.exe",
    module: "KERNELBASE.dll",
    api: "ReadFile",
    durationUs: 650
  }),
  makeEvent({
    eventId: 4,
    relativeTimeMs: 920,
    pid: 1100,
    tid: 3000,
    process: "helper.exe",
    module: "ws2_32.dll",
    api: "socket",
    durationUs: 40
  })
];

const threads = buildTraceThreadGroups(events, 300);
assertEqual(threads.map((thread) => thread.eventCount), [2, 1, 1], "thread sort by count");
assertEqual(threads[0].pid, 1000, "first thread pid");
assertEqual(threads[0].tid, 2000, "first thread tid");
assertEqual(threads[0].errorCount, 1, "thread error count");
assertEqual(threads[0].decodeFailureCount, 1, "thread decode count");
assertEqual(threads[0].slowCallCount, 1, "thread slow count");
assertEqual(threads[0].topApis[0].count, 1, "thread top api count");

assertEqual(chooseTimelineBucketSizeMs(920, 4), 250, "nice bucket size");
const timeline = buildTraceTimeline(events, 300, 4);
assertEqual(timeline.bucketSizeMs, 250, "timeline bucket size");
assertEqual(timeline.buckets.map((bucket) => bucket.eventCount), [2, 1, 1], "timeline bucket counts");
assertEqual(timeline.buckets[0].errorCount, 1, "timeline error count");
assertEqual(timeline.buckets[0].decodeFailureCount, 1, "timeline decode count");
assertEqual(timeline.buckets[1].slowCallCount, 1, "timeline slow count");
assertEqual(timeline.buckets[0].clauses.map((clause) => clause.field), ["relativeTimeMs", "relativeTimeMs"], "timeline clauses");

console.log("Trace view validation passed.");
