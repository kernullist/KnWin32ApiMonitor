import fs from "node:fs";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const input = fileURLToPath(new URL("../../generated/definition-decoder-tables.json", import.meta.url));
const output = fileURLToPath(new URL("../../generated/ui-catalog.json", import.meta.url));
const bytes = fs.readFileSync(input);
if (bytes.subarray(0, 80).toString().startsWith("version https://git-lfs.github.com/spec/v1"))
{
    throw new Error("Missing Git LFS payload: run git lfs pull from the verified repository checkout.");
}
const source = JSON.parse(bytes);
const fields = ["module", "family", "category", "risk", "hookPolicy", "coverageStatus"];
const defaults = ["", "other", "uncategorized", "unknown", "iat", "available"];
const strings = [];
const indices = new Map();
function intern(value)
{
    if (!indices.has(value))
    {
        indices.set(value, strings.length);
        strings.push(value);
    }
    return indices.get(value);
}
const rows = source.apis.map((row) => [String(row.name ?? "").trim(), ...fields.map((field, index) =>
    intern(String(row[field] ?? "").trim() || defaults[index]))]);
const text = JSON.stringify({ schemaVersion: 1, sourceSha256: crypto.createHash("sha256").update(bytes).digest("hex"), strings, rows }) + "\n";
if (process.argv.includes("--write"))
{
    fs.writeFileSync(output, text);
}
else if (!fs.existsSync(output) || fs.readFileSync(output, "utf8") !== text)
{
    throw new Error("UI catalog is stale; run npm run ui:catalog:generate.");
}
console.log(`UI catalog verified: ${rows.length} rows, ${Buffer.byteLength(text)} bytes.`);
