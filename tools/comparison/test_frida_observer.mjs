import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

class Pointer
{
    constructor(value)
    {
        this.value = BigInt.asUintN(64, BigInt(value));
    }
    add(value)
    {
        return new Pointer(this.value + BigInt(value));
    }
    compare(other)
    {
        return this.value < other.value ? -1 : this.value === other.value ? 0 : 1;
    }
    isNull()
    {
        return this.value === 0n;
    }
    equals(other)
    {
        return this.value === other.value;
    }
    toUInt32()
    {
        return Number(this.value & 0xffffffffn);
    }
    readU32()
    {
        return 0;
    }
    readByteArray(count)
    {
        return new ArrayBuffer(count);
    }
}
const hooks = new Map();
const messages = [];
const main = { base: new Pointer(1000), size: 4096,
    enumerateExports: () => ["KnMonCorpusBegin", "KnMonCorpusEnd"].map((name) => ({ name, address: name })) };
vm.runInNewContext(fs.readFileSync(new URL("./frida-observer.js", import.meta.url), "utf8"),
{
    Process: { mainModule: main, arch: "x64", getModuleByName: () => ({ getExportByName: (api) => api }) },
    Interceptor: { attach: (address, callbacks) => hooks.set(address, callbacks), detachAll: () => hooks.clear() },
    ptr: (value) => new Pointer(value), send: (message) => messages.push(message)
});
hooks.get("KnMonCorpusBegin").onLeave.call({ threadId: 1 });
const ending = hooks.get("KnMonCorpusEnd");
for (const api of ["ReadFile", "CloseHandle", "VirtualFree", "VirtualAlloc"])
{
    const context = { threadId: 1, returnAddress: new Pointer(1234), lastError: 5 };
    hooks.get(api).onEnter.call(context, Array.from({ length: 5 }, () => new Pointer(0)));
    hooks.get(api).onLeave.call(context, new Pointer(0x100000000n));
}
ending.onEnter();
const result = messages.find((message) => message.kind === "corpus");
assert.deepEqual(Array.from(result.events, (event) => event.success), [false, false, false, true],
    "BOOL uses its low 32 bits; pointer returns retain the full pointer width.");
console.log("Frida observer BOOL-width negative control PASS.");
