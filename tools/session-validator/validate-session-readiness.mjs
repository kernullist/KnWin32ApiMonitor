import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const option = process.argv.indexOf("--helper");
assert(option >= 0, "Pass --helper <knmon-native-helper.exe>.");
const helper = path.resolve(process.argv[option + 1]);
const binaries = path.dirname(helper);
const root = fs.mkdtempSync(path.resolve("build/session-readiness-"));
for (const mode of ["retained", "streaming", "failed"])
{
  const cwd = path.join(root, mode);
  fs.mkdirSync(cwd);
  const args = ["launch-session", "--own-launch-job", "--target", path.join(binaries, "knmon-sample-fileio.exe"), "--cwd", cwd];
  if (mode === "streaming")
  {
    args.push("--stream-batches");
  }
  if (mode === "failed")
  {
    args.push("--agent", path.join(cwd, "absent-agent.dll"));
  }
  const run = spawnSync(helper, args, { encoding: "utf8", timeout: 25000, maxBuffer: 16 * 1024 * 1024, windowsHide: true });
  fs.writeFileSync(path.join(root, `${mode}.jsonl`), run.stdout ?? "");
  assert.equal(run.error, undefined);
  assert.equal(run.status, 0);
  const frames = run.stdout.trim().split(/\r?\n/u).map((line) => JSON.parse(line));
  assert.equal(frames[0].frameType, "session_started");
  assert.equal(frames[0].session.sessionState, "starting");
  const states = frames.filter((frame) => frame.frameType === "session_state");
  assert.equal(states[0].session.sessionState, "starting");
  assert.equal(states.filter((frame) => frame.session.sessionState === "running").length, mode === "failed" ? 0 : 1);
  const final = frames.filter((frame) => frame.frameType === "capture_result");
  assert.equal(final.length, 1);
  assert.equal(final[0].captureResult.success, mode !== "failed");
  assert.equal(frames.some((frame) => frame.frameType === "trace_batch"), mode === "streaming");
  assert.equal(final[0].session.sessionState, mode === "failed" ? "failed" : "stopped");
}
console.log(`Session readiness PASS: retained, streaming and failed launch; evidence ${root}`);
