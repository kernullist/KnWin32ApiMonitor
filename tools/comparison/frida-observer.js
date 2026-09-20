"use strict";
const main = Process.mainModule;
const upper = main.base.add(main.size);
const events = [];
const errors = [];
let activeThread = 0;
function marker(name)
{
    const found = main.enumerateExports().find((entry) => entry.name.replace(/^_/, "") === name);
    if (found === undefined)
    {
        throw new Error(`Missing corpus marker: ${name}`);
    }
    return found.address;
}
function preview(pointer, count)
{
    return Array.from(new Uint8Array(pointer.readByteArray(Math.min(count, 16))), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
Interceptor.attach(marker("KnMonCorpusBegin"),
{
    onLeave()
    {
        activeThread = this.threadId;
    }
});
Interceptor.attach(marker("KnMonCorpusEnd"),
{
    onEnter()
    {
        activeThread = 0;
        Interceptor.detachAll();
        send({ kind: "corpus", adapter: "javascript", events, errors });
    }
});
for (const api of ["CreateFileW", "WriteFile", "ReadFile", "CloseHandle", "VirtualAlloc", "VirtualFree"])
{
    Interceptor.attach(Process.getModuleByName("kernel32.dll").getExportByName(api),
    {
        onEnter(args)
        {
            this.record = null;
            if (this.threadId !== activeThread || this.returnAddress.compare(main.base) < 0 || this.returnAddress.compare(upper) >= 0)
            {
                return;
            }
            try
            {
                this.record = { api, success: false, error: 0, byteCount: 0, preview: "" };
                if (api === "ReadFile" || api === "WriteFile")
                {
                    this.buffer = args[1];
                    this.requested = args[2].toUInt32();
                    this.count = args[3];
                    if (api === "WriteFile")
                    {
                        this.record.preview = preview(this.buffer, this.requested);
                    }
                }
            }
            catch (error)
            {
                if (errors.length < 16)
                {
                    errors.push(String(error));
                }
            }
        },
        onLeave(result)
        {
            if (this.record === null)
            {
                return;
            }
            try
            {
                const event = this.record;
                event.error = this.lastError >>> 0;
                event.success = api === "CreateFileW" ? !result.equals(ptr(-1)) :
                    api === "VirtualAlloc" ? !result.isNull() : result.toUInt32() !== 0;
                if ((api === "ReadFile" || api === "WriteFile") && event.success)
                {
                    event.byteCount = this.count.readU32();
                    if (event.byteCount > this.requested)
                    {
                        throw new Error("Returned byte count exceeds the caller buffer.");
                    }
                    if (api === "ReadFile")
                    {
                        event.preview = preview(this.buffer, event.byteCount);
                    }
                }
                if (events.length >= 100000)
                {
                    throw new Error("Observer record budget exceeded.");
                }
                events.push(event);
            }
            catch (error)
            {
                if (errors.length < 16)
                {
                    errors.push(String(error));
                }
            }
        }
    });
}
send({ kind: "ready", adapter: "javascript", architecture: Process.arch });
