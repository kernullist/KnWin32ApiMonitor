import assert from "node:assert/strict";
import path from "node:path";
import { spawnSync } from "node:child_process";

const argument = process.argv.indexOf("--helper");
assert(argument >= 0, "Pass --helper <knmon-native-helper.exe>.");
const helper = path.resolve(process.argv[argument + 1]);
let checked = 0;

function check(args, accepted)
{
    const run = spawnSync(helper, ["runtime-support", ...args],
        { encoding: "utf8", timeout: 10000, maxBuffer: 1024 * 1024, windowsHide: true });
    assert.equal(run.error, undefined);
    assert.equal(run.status, accepted ? 0 : 1);
    const result = JSON.parse(run.stdout);
    assert.equal(result.success, accepted);
    if (!accepted)
    {
        assert.equal(result.operation, "validate_stack_capture");
        assert.equal(result.win32ErrorCode, 87);
    }
    ++checked;
}

for (const value of ["0", "1", "8", "16", "32"])
{
    check(["--stack-frames", value], true);
}
for (const value of ["", "-1", "33", "4294967296", "1.0", "1e0", "+1", "01", " 1", "1 ", "true", "all"])
{
    check(["--stack-frames", value], false);
}
check([], true);
check(["--stack-frames"], false);
check(["--stack-frames=16"], false);
check(["--stack-frames", "8", "--stack-frames", "16"], false);
check(["--args", "--stack-frames"], true);
check(["--args", "--stack-frames=invalid", "--stack-frames", "32"], true);
check(["--stack-frames", "8", "--args", "--stack-frames"], true);
console.log(`Native stack option validation passed: ${checked} cases.`);
