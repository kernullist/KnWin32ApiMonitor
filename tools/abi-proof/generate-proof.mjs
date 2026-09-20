import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { repoRoot, proofPath, sha256, sourceSnapshot, typedKeys, proofErrors } from "./proof.mjs";

assert.equal(process.platform, "win32", "Executed Windows evidence is required.");
process.chdir(repoRoot);
const source = sourceSnapshot();
const output = fs.mkdtempSync(path.resolve("build/typed-abi-proof-"));
function run(executable, args, label)
{
  const result = spawnSync(executable, args, { cwd: repoRoot, windowsHide: true, encoding: "utf8",
    timeout: 180000, maxBuffer: 16 * 1024 * 1024 });
  const text = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  fs.writeFileSync(path.join(output, `${label}.log`), text);
  assert.equal(result.error, undefined, `${label}: ${result.error?.message}`);
  assert.equal(result.status, 0, `${label} failed; see ${output}`);
  return text;
}
function machine(file)
{
  const image = fs.readFileSync(file);
  assert.equal(image.readUInt16LE(0), 0x5a4d);
  const offset = image.readUInt32LE(0x3c);
  assert.equal(image.readUInt32LE(offset), 0x4550);
  return image.readUInt16LE(offset + 4);
}
const runs = [];
run(process.execPath, ["tools/def-validator/generate-sdk-abi.mjs", "--check", "--verify-sdk"], "sdk-provenance");
for (const [architecture, directory] of [["x64", process.argv[2] ?? "build/native-msvc"],
  ["x86", process.argv[3] ?? "build/native-msvc-x86"]])
{
  run("cmake", ["--build", directory, "--config", "Debug", "--parallel", "4"], `${architecture}-build`);
  const binaries = {};
  const configuration = path.join(directory, "Debug");
  const compilerDirectory = fs.readdirSync(path.join(directory, "CMakeFiles")).find((name) =>
    /^\d+\.\d+\.\d+$/u.test(name) && fs.existsSync(path.join(directory, "CMakeFiles", name, "CMakeCXXCompiler.cmake")));
  assert.ok(compilerDirectory, "CMake compiler provenance missing.");
  const compilerFile = fs.readFileSync(path.join(directory, "CMakeFiles", compilerDirectory, "CMakeCXXCompiler.cmake"), "utf8");
  const compiler = { id: compilerFile.match(/set\(CMAKE_CXX_COMPILER_ID "([^"]+)"\)/u)?.[1],
    version: compilerFile.match(/set\(CMAKE_CXX_COMPILER_VERSION "([^"]+)"\)/u)?.[1], cmake: compilerDirectory };
  assert.equal(compiler.id, "MSVC");
  assert.ok(compiler.version);
  for (const file of ["knmon-native-helper.exe", `knmon-agent${architecture === "x86" ? "32" : "64"}.dll`,
    "knmon-lifecycle-test-agent.dll", "knmon-abi-differential-test.exe", "knmon-typed-abi-target.exe"])
  {
    const binary = path.join(configuration, file);
    assert.equal(machine(binary), architecture === "x86" ? 0x14c : 0x8664, `${file}: wrong architecture`);
    binaries[file] = sha256(fs.readFileSync(binary));
  }
  const ctest = run("ctest", ["--test-dir", directory, "-C", "Debug", "-R", "^abi-differential$", "-V"], `${architecture}-ctest`);
  assert.match(ctest, /100% tests passed, 0 tests failed out of 1/u);
  assert.match(ctest, /Typed SDK ABI A\/B PASS: 6 APIs/u);
  const liveText = run(process.execPath, ["tools/session-validator/validate-typed-abi-live.mjs", configuration], `${architecture}-live`);
  const livePath = liveText.match(/Live typed ABI A\/B and replay PASS: ([^\r\n]+)/u)?.[1];
  assert.ok(livePath);
  const live = JSON.parse(fs.readFileSync(path.join(livePath, "evidence.json"), "utf8"));
  assert.equal(live.success, true);
  assert.equal(live.helperSha256, binaries["knmon-native-helper.exe"]);
  assert.equal(live.targetSha256, binaries["knmon-typed-abi-target.exe"]);
  const systemDlls = {};
  for (const dll of ["oleaut32.dll", "d2d1.dll", "user32.dll"])
  {
    const file = path.join(process.env.SystemRoot, architecture === "x86" ? "SysWOW64" : "System32", dll);
    systemDlls[dll] = sha256(fs.readFileSync(file));
  }
  runs.push({ architecture, compiler, abiDifferential: "passed", liveInjectionReplay: "passed", binaries, systemDlls,
    ctestLogSha256: sha256(ctest), live });
}
assert.deepEqual(sourceSnapshot(), source, "Sources changed while the proof was running.");
const proof = { schemaVersion: 1, observedAtUtc: new Date().toISOString(), windowsRelease: os.release(),
  configuration: "Debug", apiKeys: typedKeys(), source, runs,
  scope: "Executed corpus on this Windows build. No Release, other OS, exhaustive input, or nested-call coverage claim." };
assert.deepEqual(proofErrors(proof, source), []);
fs.writeFileSync(proofPath, `${JSON.stringify(proof, null, 2)}\n`);
console.log(`Typed ABI executed proof PASS: ${output}`);
