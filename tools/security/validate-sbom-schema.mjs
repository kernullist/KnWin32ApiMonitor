import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import Ajv from "ajv";

const directory = fileURLToPath(new URL("./cyclonedx/", import.meta.url));
const sums = JSON.parse(fs.readFileSync(path.join(directory, "SHA256SUMS.json"), "utf8"));
const ajv = new Ajv({ strict: false, allErrors: false, validateFormats: false });
for (const [name, expected] of Object.entries(sums))
{
    const bytes = fs.readFileSync(path.join(directory, name));
    assert.equal(createHash("sha256").update(bytes).digest("hex"), expected, `Schema checksum mismatch: ${name}`);
    if (name.endsWith(".schema.json"))
    {
        ajv.addSchema(JSON.parse(bytes));
    }
}
const validator = ajv.getSchema("http://cyclonedx.org/schema/bom-1.7.schema.json");
assert.ok(validator);
const input = process.argv[2];
assert.ok(input, "Expected a CycloneDX JSON file.");
assert.ok(fs.statSync(input).size <= 32 * 1024 * 1024, "SBOM exceeds size bound.");
const bom = JSON.parse(fs.readFileSync(input, "utf8"));
assert.ok(validator(bom), JSON.stringify(validator.errors));
assert.equal(bom.specVersion, "1.7");
console.log("CycloneDX 1.7 structural schema validation PASS.");
