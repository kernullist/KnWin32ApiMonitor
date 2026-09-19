import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

const probe = process.argv[2];
assert.ok(probe, "Native capture semantics probe path required.");
const max = 0xffffffffffffffffn;
let state = 0x123456789abcdefn;
function random()
{
    state ^= state << 13n;
    state ^= state >> 7n;
    state ^= state << 17n;
    state &= max;
    return state;
}
const bounds = [0n, 1n, 2n, 999999n, 1000000n, 10000000n, 1n << 32n, (1n << 63n) - 1n, 1n << 63n, max - 1n, max];
const cases = [];
for (const ticks of bounds)
{
    for (const frequency of bounds)
    {
        for (const scale of bounds)
        {
            cases.push([ticks, frequency, scale]);
        }
    }
}
for (let index = 0; index < 5000; ++index)
{
    cases.push([random(), random(), index % 2 === 0 ? random() : 10000000n]);
}
const input = cases.map((row) => row.join(" ")).join("\n") + "\n";
const native = spawnSync(probe, ["--scale"], { input, encoding: "utf8", timeout: 20000, maxBuffer: 4 * 1024 * 1024 });
assert.equal(native.status, 0, native.stderr);
const results = native.stdout.trim().split(/\r?\n/);
assert.equal(results.length, cases.length);
cases.forEach(([ticks, frequency, scale], index) =>
{
    const product = frequency === 0n || scale === 0n ? max + 1n : ticks * scale / frequency;
    assert.equal(results[index], product > max ? "overflow" : String(product), cases[index].join("/"));
});
console.log(`QPC arithmetic matched independent BigInt oracle: ${cases.length} cases.`);
