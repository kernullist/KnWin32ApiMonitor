import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { zstdCompressSync, zstdDecompressSync, constants } from "node:zlib";

const binary = path.resolve(process.argv[2] ?? "build/native-msvc/Debug/knmon-session-codec-test.exe");
const directory = fs.mkdtempSync(path.resolve("build/zstd-corpus-"));
let count = 0;
function run(mode, input, expected, accepted = true)
{
    const source = path.join(directory, "input");
    const destination = path.join(directory, "output");
    fs.writeFileSync(source, input);
    const result = spawnSync(binary, [mode, source, destination, String(expected), "--test"], { encoding: "utf8", timeout: 15000 });
    assert.equal(result.status === 0, accepted, `case=${count} ${result.stderr}`);
    count += 1;
    return accepted ? fs.readFileSync(destination) : null;
}
const data = [Buffer.alloc(0), Buffer.from("\0unicode \uD83D\uDE80\n"), Buffer.alloc(500000, 65)];
let random = 123456789;
for (const size of [1, 2, 254, 255, 256, 257, 65535, 65536, 131072, 131073, 2000000])
{
    const bytes = Buffer.alloc(size);
    for (let i = 0; i < size; ++i)
    {
        random ^= random << 13;
        random ^= random >>> 17;
        random ^= random << 5;
        bytes[i] = random & 255;
    }
    data.push(bytes);
}
for (const bytes of data)
{
    assert.deepEqual(zstdDecompressSync(run("encode", bytes, bytes.length)), bytes);
    for (const contentSize of [0, 1])
    {
        for (const checksum of [0, 1])
        {
            const frame = zstdCompressSync(bytes, { params: {
                [constants.ZSTD_c_contentSizeFlag]: contentSize,
                [constants.ZSTD_c_checksumFlag]: checksum
            } });
            assert.deepEqual(run("decode", frame, bytes.length), bytes);
            run("decode", frame.subarray(0, frame.length - 1), bytes.length, false);
            run("decode", Buffer.concat([frame, Buffer.from([0])]), bytes.length, false);
            run("decode", frame, bytes.length + 1, false);
            if (checksum)
            {
                const corrupt = Buffer.from(frame);
                corrupt[corrupt.length - 1] ^= 1;
                run("decode", corrupt, bytes.length, false);
            }
        }
    }
    // Legacy KNAPM raw-only framing remains supported, without its old trailing-data bug.
    const header = Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0xa0, 0, 0, 0, 0]);
    header.writeUInt32LE(bytes.length, 5);
    const blocks = [header];
    let offset = 0;
    do
    {
        const size = Math.min(131072, bytes.length - offset);
        const block = Buffer.alloc(3);
        block.writeUIntLE((size << 3) | (offset + size === bytes.length ? 1 : 0), 0, 3);
        blocks.push(block, bytes.subarray(offset, offset + size));
        offset += size;
    }
    while (offset < bytes.length);
    assert.deepEqual(run("decode", Buffer.concat(blocks), bytes.length), bytes);
}
run("decode", Buffer.from([0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0]), 0, false);
run("decode", Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0x00, 0xff, 1, 0, 0]), 0, false);
console.log(`Zstd cross-codec corpus passed: ${count} cases, Node ${process.version}, zstd ${process.versions.zstd}.`);
