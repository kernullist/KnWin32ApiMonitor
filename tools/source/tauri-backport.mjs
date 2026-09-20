import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const provenanceSha256 = "ed1421e1625d70bcb4063d5b7dd24d1d1078ef6eac542698badbc0d8fd499c6a";
const baseName = "crates/third-party";

function requireValue(condition, message)
{
    if (!condition)
    {
        throw new Error(message);
    }
}

function digest(data)
{
    return crypto.createHash("sha256").update(data).digest("hex");
}

function regularFile(root, name, limit)
{
    const parts = name.split("/");
    requireValue(parts.every((part) => part && ![".", ".."].includes(part) && !part.includes(":") && !part.includes("\\")),
        "Unsafe Tauri source path.");
    let target = root;
    for (const part of parts)
    {
        target = path.join(target, part);
        requireValue(!fs.lstatSync(target).isSymbolicLink(), "Reparse point in Tauri source inputs.");
    }
    const relative = path.relative(fs.realpathSync(root), fs.realpathSync(target));
    requireValue(!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`),
        "Tauri source escapes its root.");
    const handle = fs.openSync(target, "r");
    try
    {
        const stat = fs.fstatSync(handle);
        requireValue(stat.isFile() && stat.size <= limit, "Oversized or non-file Tauri source input.");
        const bytes = Buffer.alloc(limit + 1);
        let used = 0;
        while (used < bytes.length)
        {
            const count = fs.readSync(handle, bytes, used, bytes.length - used, null);
            if (count === 0)
            {
                break;
            }
            used += count;
        }
        requireValue(used <= limit, "Tauri source input exceeds its bound.");
        return bytes.subarray(0, used);
    }
    finally
    {
        fs.closeSync(handle);
    }
}

export function verifyTauriBackport(root)
{
    root = path.resolve(root);
    const manifestBytes = regularFile(root, `${baseName}/tauri-utils.provenance.json`, 64 * 1024);
    requireValue(digest(manifestBytes) === provenanceSha256, "Tauri provenance differs from the pinned upstream backport.");
    const manifest = JSON.parse(manifestBytes.toString("utf8"));
    const archive = regularFile(root, `${baseName}/${manifest.upstream.archive}`, 1024 * 1024);
    requireValue(digest(archive) === manifest.upstream.sha256, "Tauri upstream archive checksum differs.");
    const names = Object.keys(manifest.files);
    const directories = new Set(names.flatMap((name) =>
    {
        const parts = name.split("/");
        return parts.slice(1).map((_, index) => parts.slice(0, index + 1).join("/"));
    }));
    const actual = [];
    const pending = ["tauri-utils"];
    let entries = 0;
    while (pending.length > 0)
    {
        const directory = pending.pop();
        const target = path.join(root, baseName, directory);
        requireValue(directories.has(directory) && !fs.lstatSync(target).isSymbolicLink(),
            "Unlisted or linked Tauri source directory.");
        for (const entry of fs.readdirSync(target, { withFileTypes: true }))
        {
            entries += 1;
            requireValue(entries <= 128 && !entry.isSymbolicLink(), "Oversized or linked Tauri vendor tree.");
            const name = `${directory}/${entry.name}`;
            if (entry.isDirectory())
            {
                pending.push(name);
            }
            else
            {
                requireValue(entry.isFile(), "Non-file Tauri source entry.");
                actual.push(name);
            }
        }
    }
    requireValue(JSON.stringify(actual.sort()) === JSON.stringify(names.sort()), "Unlisted or missing Tauri vendor source.");
    for (const name of names)
    {
        const record = manifest.files[name];
        const bytes = regularFile(root, `${baseName}/${name}`, 1024 * 1024);
        requireValue(bytes.length === record.bytes && digest(bytes) === record.sha256, `Tauri vendor payload differs: ${name}`);
    }
    return manifest;
}
