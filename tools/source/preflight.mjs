import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { verifyTauriBackport } from "./tauri-backport.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
verifyTauriBackport(root);
const [major, minor] = process.versions.node.split(".").map(Number);
if (!((major === 22 && minor >= 18) || major === 24 || major === 26))
{
    throw new Error("Supported Node lines: 22.18+, 24.x, 26.x. Reproduction baseline: 24.21.0 LTS.");
}
const lfsFiles = fs.readFileSync(path.join(root, ".gitattributes"), "utf8").split(/\r?\n/)
    .filter((line) => line.includes("filter=lfs")).map((line) => line.trim().split(/\s+/)[0]);
function git(args)
{
    const result = spawnSync("git", args, { cwd: root, encoding: "utf8", windowsHide: true });
    if (result.status !== 0)
    {
        throw new Error(`Git failed: ${result.stderr}`);
    }
    return result.stdout;
}
if (process.argv.includes("--hydrate-lfs"))
{
    const origin = git(["remote", "get-url", "origin"]).trim();
    if (!["https://github.com/kernullist/KnWin32ApiMonitor.git", "git@github.com:kernullist/KnWin32ApiMonitor.git"].includes(origin))
    {
        throw new Error("LFS hydration requires the verified kernullist/KnWin32ApiMonitor origin.");
    }
    git(["-c", "lfs.url=https://github.com/kernullist/KnWin32ApiMonitor.git/info/lfs",
        "-c", "remote.origin.lfsurl=https://github.com/kernullist/KnWin32ApiMonitor.git/info/lfs",
        "lfs", "pull", "origin", `--include=${lfsFiles.join(",")}`, "--exclude="]);
}
const sourceManifestPath = path.join(root, "SOURCE-MANIFEST.json");
const sourceManifest = fs.existsSync(sourceManifestPath) ? JSON.parse(fs.readFileSync(sourceManifestPath, "utf8")) : null;
for (const name of lfsFiles)
{
    const bytes = fs.readFileSync(path.join(root, name));
    if (bytes.subarray(0, 100).toString().startsWith("version https://git-lfs.github.com/spec/v1"))
    {
        throw new Error(`Missing LFS content: ${name}. In the verified checkout run npm run source:hydrate; use the generated source ZIP for archive builds.`);
    }
    const digest = crypto.createHash("sha256").update(bytes).digest("hex");
    const expected = sourceManifest?.files[name]?.sha256 ?? git(["show", `:${name}`]).match(/^oid sha256:([a-f0-9]{64})$/m)?.[1];
    if (!expected || digest !== expected)
    {
        throw new Error(`LFS payload hash mismatch: ${name}`);
    }
}
if (sourceManifest)
{
    for (const [name, expected] of Object.entries(sourceManifest.files))
    {
        const target = path.resolve(root, name);
        const relative = path.relative(root, target);
        if (path.isAbsolute(relative) || relative.startsWith("..") || name.includes("\\"))
        {
            throw new Error("Unsafe source manifest path.");
        }
        const bytes = fs.readFileSync(target);
        if (bytes.length !== expected.bytes || crypto.createHash("sha256").update(bytes).digest("hex") !== expected.sha256)
        {
            throw new Error(`Source archive hash mismatch: ${name}`);
        }
    }
}
console.log(`Source preflight passed: Node ${process.versions.node}, ${lfsFiles.length} LFS payloads${sourceManifest ? ", complete archive hashes" : ""}.`);
