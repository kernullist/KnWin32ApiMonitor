import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const option = process.argv.indexOf("--helper");
assert(option >= 0, "Pass --helper <knmon-native-helper.exe>.");
const helper = path.resolve(process.argv[option + 1]);
let checked = 0;
function check(args, accepted, operation = "validate_capture_detail")
{
  const run = spawnSync(helper, ["runtime-support", ...args],
    { encoding: "utf8", timeout: 10000, maxBuffer: 1024 * 1024, windowsHide: true });
  assert.equal(run.error, undefined);
  assert.equal(run.status, accepted ? 0 : 1, JSON.stringify(args));
  const result = JSON.parse(run.stdout);
  assert.equal(result.success, accepted);
  if (!accepted)
  {
    assert.equal(result.operation, operation);
    assert.equal(result.win32ErrorCode, 87);
  }
  ++checked;
}

check([], true);
for (const detail of ["metadata", "arguments", "preview"])
{
  check(["--capture-detail", detail], true);
  check(["--capture-detail", detail, "--stack-frames", "32"], true);
}
for (const detail of ["", "Metadata", "all", "none", "0", " metadata", "preview ", "true"])
{
  check(["--capture-detail", detail], false);
}
check(["--capture-detail"], false);
check(["--capture-detail=metadata"], false);
check(["--capture-detail", "metadata", "--capture-detail", "preview"], false);
check(["--args", "--api-selection", "--capture-detail", "metadata"], true);
const source = fs.readFileSync(new URL("../../native/knmon-native-helper/src/main.cpp", import.meta.url), "utf8");
const values = new Set(Array.from(source.matchAll(/(?:GetOption|GetUInt32Option)\(args, "(--[^"]+)"/gu), (match) => match[1]));
values.delete("--api-selection");
for (const name of values)
{
  check([name, "--capture-detail", "--stack-frames", "8"], true);
  check([name, "--stack-frames", "--capture-detail", "metadata"], true);
}
console.log(`Native capture detail option validation passed: ${checked} cases.`);
