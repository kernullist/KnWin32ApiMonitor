"use strict";
const main = Process.mainModule;
const apis = ["CreateFileW", "WriteFile", "ReadFile", "CloseHandle", "VirtualAlloc", "VirtualFree"];
const capacity = 100000;
const recordBytes = 36;
const state = Memory.alloc(16 + capacity * recordBytes);
state.writeByteArray(new Uint8Array(16));
const observer = new CModule(`
#include <gum/guminterceptor.h>
#include <gum/gummemory.h>
#include <string.h>

typedef struct
{
    guint api;
    guint success;
    guint error;
    guint byte_count;
    guint preview_bytes;
    guint8 preview[16];
} Record;

typedef struct
{
    gint active;
    guint thread;
    guint count;
    guint errors;
    Record records[100000];
} State;

typedef struct
{
    guint eligible;
    guint requested;
    gpointer buffer;
    gpointer byte_count;
    guint8 preview[16];
} Invocation;

typedef char RecordSizeCheck[sizeof(Record) == 36 ? 1 : -1];
extern State state;
extern guint8 main_base[];
extern guint8 main_end[];

static void failed(void)
{
    if (state.errors < 0xffffffffU)
    {
        state.errors++;
    }
}

static int read_exact(gpointer output, gconstpointer input, guint length)
{
    int success = 1;
    if (length != 0)
    {
        gsize available = 0;
        guint8 *copy = gum_memory_read(input, length, &available);
        success = copy != NULL && available == length;
        if (success)
        {
            memcpy(output, copy, length);
        }
        else
        {
            memset(output, 0, length);
            failed();
        }
        g_free(copy);
    }
    return success;
}

guint is_success(guint api, gpointer result)
{
    guint success = 0;
    if (api == 0)
    {
        success = (guintptr) result != (guintptr) -1;
    }
    else if (api == 4)
    {
        success = result != NULL;
    }
    else
    {
        success = (guint) (guintptr) result != 0;
    }
    return success;
}

void begin(GumInvocationContext *ic)
{
    state.thread = gum_invocation_context_get_thread_id(ic);
    if (g_atomic_int_add(&state.active, 1) != 0)
    {
        failed();
    }
}

void stop(void)
{
    if (g_atomic_int_add(&state.active, -1) != 1)
    {
        failed();
    }
}

void on_enter(GumInvocationContext *ic)
{
    Invocation *call = GUM_IC_GET_INVOCATION_DATA(ic, Invocation);
    guintptr address = (guintptr) gum_invocation_context_get_return_address(ic);
    call->eligible = 0;
    if (address >= (guintptr) main_base && address < (guintptr) main_end &&
        g_atomic_int_add(&state.active, 0) == 1 && gum_invocation_context_get_thread_id(ic) == state.thread)
    {
        guint api = GPOINTER_TO_UINT(GUM_IC_GET_FUNC_DATA(ic, gpointer));
        call->eligible = 1;
        if (api == 1 || api == 2)
        {
            call->buffer = gum_invocation_context_get_nth_argument(ic, 1);
            call->requested = GPOINTER_TO_UINT(gum_invocation_context_get_nth_argument(ic, 2));
            call->byte_count = gum_invocation_context_get_nth_argument(ic, 3);
            if (api == 1)
            {
                guint length = call->requested < 16 ? call->requested : 16;
                read_exact(call->preview, call->buffer, length);
            }
        }
    }
}

void on_leave(GumInvocationContext *ic)
{
    Invocation *call = GUM_IC_GET_INVOCATION_DATA(ic, Invocation);
    if (call->eligible)
    {
        if (state.count < 100000)
        {
            guint api = GPOINTER_TO_UINT(GUM_IC_GET_FUNC_DATA(ic, gpointer));
            Record *record = &state.records[state.count++];
            record->api = api;
            record->success = is_success(api, gum_invocation_context_get_return_value(ic));
            record->error = (guint) ic->system_error;
            record->byte_count = 0;
            record->preview_bytes = 0;
            if (api == 1)
            {
                record->preview_bytes = call->requested < 16 ? call->requested : 16;
                memcpy(record->preview, call->preview, record->preview_bytes);
            }
            if ((api == 1 || api == 2) && record->success &&
                read_exact(&record->byte_count, call->byte_count, sizeof(guint)))
            {
                if (record->byte_count > call->requested)
                {
                    failed();
                }
                else if (api == 2)
                {
                    record->preview_bytes = record->byte_count < 16 ? record->byte_count : 16;
                    read_exact(record->preview, call->buffer, record->preview_bytes);
                }
            }
        }
        else
        {
            failed();
        }
    }
}
`, { state, main_base: main.base, main_end: main.base.add(main.size) }, { toolchain: "internal" });
const stop = new NativeFunction(observer.stop, "void", []);
const success = new NativeFunction(observer.is_success, "uint32", ["uint32", "pointer"]);
if (success(0, ptr(-1)) !== 0 || success(4, ptr(0)) !== 0 ||
    (Process.pointerSize === 8 && (success(2, ptr("0x100000000")) !== 0 || success(4, ptr("0x100000000")) !== 1)))
{
    throw new Error("CModule return-width negative control failed.");
}
function marker(name)
{
    const found = main.enumerateExports().find((entry) => entry.name.replace(/^_/, "") === name);
    if (found === undefined)
    {
        throw new Error(`Missing corpus marker: ${name}`);
    }
    return found.address;
}
Interceptor.attach(marker("KnMonCorpusBegin"), { onLeave: observer.begin });
Interceptor.attach(marker("KnMonCorpusEnd"),
{
    onEnter()
    {
        stop();
        Interceptor.detachAll();
        const count = state.add(8).readU32();
        const errorCount = state.add(12).readU32();
        if (count > capacity)
        {
            throw new Error("CModule record budget exceeded.");
        }
        const events = [];
        for (let index = 0; index < count; index++)
        {
            const record = state.add(16 + index * recordBytes);
            const api = record.readU32();
            const length = record.add(16).readU32();
            if (api >= apis.length || length > 16)
            {
                throw new Error("Invalid CModule record.");
            }
            events.push({ api: apis[api], success: record.add(4).readU32() !== 0,
                error: record.add(8).readU32(), byteCount: record.add(12).readU32(),
                preview: Array.from(new Uint8Array(record.add(20).readByteArray(length)),
                    (byte) => byte.toString(16).padStart(2, "0")).join("") });
        }
        send({ kind: "corpus", adapter: "cmodule", events,
            errors: errorCount === 0 ? [] : [`CModule observation failures: ${errorCount}`] });
    }
});
for (let index = 0; index < apis.length; index++)
{
    Interceptor.attach(Process.getModuleByName("kernel32.dll").getExportByName(apis[index]),
        { onEnter: observer.on_enter, onLeave: observer.on_leave }, ptr(index));
}
send({ kind: "ready", adapter: "cmodule", architecture: Process.arch });
