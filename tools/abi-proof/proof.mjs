import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { typedAbiSpecs } from "../def-validator/typed-abi-spec.mjs";

export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const proofPath = path.join(repoRoot, "generated/typed-abi-proof.json");
export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
export const typedKeys = () => typedAbiSpecs.map((spec) => `${spec.module}!${spec.name.toLowerCase()}`).sort();

export function sourceSnapshot()
{
  const files = [];
  function visit(relative)
  {
    for (const entry of fs.readdirSync(path.join(repoRoot, relative), { withFileTypes: true }))
    {
      const name = `${relative}/${entry.name}`;
      if (entry.isDirectory())
      {
        visit(name);
      }
      else if (/\.(?:h|hpp|inc|c|cpp|mjs|json|ts|rs|toml|txt|def|rc|cmake)$/u.test(name))
      {
        files.push(name);
      }
    }
  }
  for (const root of ["native", "samples/targets", "tools/abi-proof", "tools/session-validator"])
  {
    visit(root);
  }
  files.push("toolchain.json", "package.json", "definitions/win32/typed-abi.json",
    "generated/sdk-abi-ir.json", "generated/sdk-abi-sources.json", "generated/definition-decoder-tables.json",
    "tools/def-validator/typed-abi-spec.mjs", "tools/def-validator/generate-typed-abi.mjs",
    "tools/def-validator/generate-agent-hook-definitions.mjs", "tools/def-validator/generate-sdk-abi.mjs",
    "apps/knmon-ui/src/traceConversion.ts", "apps/knmon-ui/src/types.ts", "crates/knmon-tauri/src/lib.rs");
  const sources = files.sort().map((file) => ({ path: file,
    sha256: sha256(fs.readFileSync(path.join(repoRoot, file), "utf8").replaceAll("\r\n", "\n")) }));
  return { sha256: sha256(JSON.stringify(sources)), files: sources };
}

export function proofErrors(proof, sources = sourceSnapshot())
{
  const errors = [];
  const hash = /^[a-f0-9]{64}$/u;
  if (proof?.schemaVersion !== 1 || proof.source?.sha256 !== sources.sha256 ||
      JSON.stringify(proof.source?.files) !== JSON.stringify(sources.files))
  {
    errors.push("Source fingerprint is missing or stale.");
  }
  if (proof?.configuration !== "Debug" || !/^10\.0\.\d+$/u.test(proof?.windowsRelease ?? "") ||
      JSON.stringify(proof?.apiKeys) !== JSON.stringify(typedKeys()))
  {
    errors.push("Typed ABI proof scope is invalid.");
  }
  if (!Array.isArray(proof?.runs) || proof.runs.length !== 2)
  {
    errors.push("Both x86 and x64 runs are required.");
  }
  const runs = Array.isArray(proof?.runs) ? proof.runs : [];
  for (const architecture of ["x86", "x64"])
  {
    const run = runs.find((value) => value?.architecture === architecture);
    if (!run || run.abiDifferential !== "passed" || run.liveInjectionReplay !== "passed" ||
        !hash.test(run.ctestLogSha256 ?? "") || !hash.test(run.live?.reportSha256 ?? "") ||
        run.live?.capturedEvents !== typedKeys().length ||
        !["knmon-native-helper.exe", `knmon-agent${architecture === "x86" ? "32" : "64"}.dll`,
          "knmon-lifecycle-test-agent.dll", "knmon-abi-differential-test.exe", "knmon-typed-abi-target.exe"]
          .every((file) => hash.test(run.binaries?.[file] ?? "")) ||
        !["oleaut32.dll", "d2d1.dll", "user32.dll"].every((file) => hash.test(run.systemDlls?.[file] ?? "")))
    {
      errors.push(`Incomplete executed evidence for ${architecture}.`);
    }
  }
  return errors;
}

export function verifiedTypedProof()
{
  if (!fs.existsSync(proofPath))
  {
    return { apiKeys: [], status: "missing" };
  }
  const proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
  const errors = proofErrors(proof);
  return errors.length === 0 ? { apiKeys: proof.apiKeys, status: "verified", configuration: proof.configuration,
    windowsRelease: proof.windowsRelease, sourceSha256: proof.source.sha256 } : { apiKeys: [], status: "stale", errors };
}
