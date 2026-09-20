import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const file = fileURLToPath(import.meta.url);
const root = path.resolve(path.dirname(file), "../..");
if (process.argv[2] !== "--child")
{
    const child = spawnSync(process.execPath, [file, "--child"],
        { cwd: root, encoding: "utf8", timeout: 5000, windowsHide: true });
    assert.equal(child.error, undefined, "Dependency regression timed out or failed to start.");
    assert.equal(child.status, 0, child.stderr);
    process.stdout.write(child.stdout);
}
else
{
    const require = createRequire(path.join(root, "package.json"));
    const uri = require("fast-uri");
    for (const input of ["http://[::not-valid]/private", "http://[fc00::not-hex]/private", "http://[fe80::not-hex]/private"])
    {
        assert.ok(uri.parse(input).error, "Malformed IPv6 authority must not be normalized into a valid host.");
    }
    assert.equal(uri.parse("https://example.com/path").host, "example.com");
    for (const module of ["nanoid", "nanoid/non-secure"])
    {
        const generator = require(module).customAlphabet("abc", 0);
        assert.equal(generator(), "");
        assert.equal(generator(-1), "");
        assert.equal(require(module).customAlphabet("abc", 16)().length, 16);
    }
    const output = fs.mkdtempSync(path.join(root, "build/dependency-regression-"));
    const cssRoot = path.join(output, "css");
    fs.mkdirSync(cssRoot);
    const map = JSON.stringify({ version: 3, sources: ["fixture.txt"], names: [], mappings: "AAAA" });
    fs.writeFileSync(path.join(output, "private.map"), map);
    fs.writeFileSync(path.join(cssRoot, "allowed.map"), map);
    const postcss = require("postcss");
    const absolute = path.join(output, "private.map").replaceAll("\\", "/");
    assert.equal(postcss.parse(`a{}/*# sourceMappingURL=${absolute} */`).source.input.map, undefined,
        "Untrusted map annotation without a source path must not read a file.");
    const from = path.join(cssRoot, "input.css");
    assert.equal(postcss.parse("a{}/*# sourceMappingURL=../private.map */", { from }).source.input.map, undefined,
        "Map annotation must not escape the stylesheet directory.");
    assert.equal(postcss.parse("a{}/*# sourceMappingURL=allowed.map */", { from }).source.input.map.text, map,
        "A map within the stylesheet directory must remain usable.");
    console.log(`Dependency advisory regressions PASS: ${output}`);
}
