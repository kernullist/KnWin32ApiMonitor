# Stack observation contract

Native capture can optionally collect a current-thread backtrace after an API
returns. Capture is disabled by default. Select a limit in the desktop's Call
stack control or pass `--stack-frames 0..32` to a native capture command. The UI
offers Off, 8, 16 and 32 frames, and keeps the setting fixed while capture runs.
Launch, attach, process-tree child capture and daemon attach forward the limit.

An agent DLL name or intercepted API name describes the hook; it cannot establish
a caller frame or call order. Hook metadata remains separate from captured
addresses.

With capture disabled, new `api_call` and trace events use this representation:

```json
{
  "stack": [],
  "stackSource": "not_captured",
  "hookContext": {
    "agent": "knmon-agent64.dll",
    "resolvedHostModule": "kernelbase.dll"
  }
}
```

`resolvedHostModule` is optional and appears only when the generic hook path has
resolved it. The event's existing `module` and `api` fields identify the monitored
API. Hook context is separate from the stack array.

| Input | Meaning |
| --- | --- |
| `stackSource: "not_captured"`, empty `stack` | No target stack was collected. |
| `stackSource: "legacy_unverified"` | Preserve the strings without asserting capture provenance. |
| `stackSource: "native_backtrace"` | Raw addresses and required `stackCapture` metadata describe a native capture attempt. |
| Missing `stackSource` | Treat as legacy unverified data. |
| Unknown or null source, non-string entries, nonempty uncaptured stack | Reject the event. |

A successful enabled capture has this shape:

```json
{
  "stack": ["0x00007ff612345678"],
  "stackSource": "native_backtrace",
  "stackCapture": {
    "method": "rtl_capture_stack_back_trace",
    "phase": "post_call",
    "addressBits": 64,
    "requestedFrames": 32,
    "status": "captured",
    "limitReached": false,
    "exceptionCode": 0
  },
  "hookContext": {"agent": "knmon-agent64.dll"}
}
```

Addresses are nonzero, lowercase hexadecimal strings with exactly 8 or 16 digits
for the recorded address width. Duplicate addresses remain in order, including
recursive frames. The current-thread unwind starts inside the Agent's emission
path, so Agent frames may consume part of the requested limit. These are raw
post-call addresses, not symbols, module identities or API-entry frames. No
complete-unwind claim is made even when the limit is not reached.

`requestedFrames` is an integer from 1 to 32 for native attempts. `captured`
requires at least one frame, and the count cannot exceed that limit.
`limitReached` is exactly whether count equals limit; it means the trace may be
incomplete, not that another frame is known to exist. `empty`, `memory_fault`,
`cpp_exception`, `unavailable` and `invalid_result` require an empty array and a
false limit flag. Only `memory_fault` has a nonzero exception code, restricted to
access violation, in-page error or datatype misalignment. Other SEH faults retain
normal exception dispatch. `stackCapture` is required only for `native_backtrace`
and forbidden for the other provenance states, including explicit nulls.

The capture helper uses fixed storage and no heap allocation or symbol engine.
It preserves Win32 last error; the enclosing hook scope also preserves the
original return value, Win32/Winsock errors and original exception behavior.
The existing session lease protects capture through transport commit and stop.
The collector checks the architecture, storage bounds, failure state and exact
requested limit against the controller's trusted session configuration.
Transport ABI 9 and attach configuration ABI 5 require matching binaries.
Frame/storage bounds do not promise a hard execution-time bound for the OS
unwinder, especially with arbitrary target unwind metadata.

If supplied, `hookContext` must be an object with a nonempty string `agent`.
An optional `resolvedHostModule` must also be a nonempty string. Explicit nulls
are invalid, including for optional fields.

Native and Rust ingestion validate these invariants. Live conversion makes a
missing legacy source explicit. Stored legacy events retain their original
strings and fields during replay. The inspector labels old entries `Unverified`
and shows `Call stack was not captured.` when capture is disabled. Enabled
captures show raw addresses, the post-call phase and the possible presence of
Agent frames, or an explicit empty/failure result. JSONL exports
preserve these fields through the worker and session pipeline.

The published event and agent API-call schemas share
`contracts/stack-observation.schema.json`. It validates provenance, address width,
failure metadata and all frame-limit/count combinations. The common fixture
corpus runs against these schemas as well as the runtime validators. JSON Schema
validates numeric values; lexical integer restrictions are enforced by the
native and strict-JSON input parsers.

Before this correction, the controller emitted `agent!IatHook` and `module!API`
labels as stack entries. Existing files containing those labels remain readable;
they do not prove that any stack frames were collected.

Microsoft documents `CaptureStackBackTrace` as walking the stack and returning
captured frame pointers and a frame count. The optional native path retains
those addresses separately from hook context. See the
[Microsoft API reference](https://learn.microsoft.com/en-us/windows/win32/debug/capturestackbacktrace),
checked on 2026-09-21. The native component tests include actual caller addresses,
deep recursion, concurrent collection and injected failure controls. Actual x64
and x86 sample captures are checked with capture disabled and limits of 8 and
32 through live conversion and saved replay. This feature alone does not satisfy
the separate metadata/arguments/preview/stack performance gate.

The same distinction between missing and observed data applies to trace counts.
`Trimmed` counts ingested records removed from the retained display window.
`Not ingested` is the excess of the native streamed count over the UI ingested
count; those records may still be pending or may be unavailable. A newer native
snapshot must not turn this temporary difference into a claim of UI trimming.
The desktop validation requires all counts to reconcile after capture stops.
