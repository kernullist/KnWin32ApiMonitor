# Stack observation contract

The current native capture records API arguments, results and timing. It does not
walk the target call stack. An agent DLL name or an intercepted API name describes
the hook; it cannot establish a caller frame or call order.

New `api_call` and trace events use this representation:

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
| Missing `stackSource` | Treat as legacy unverified data. |
| Unknown or null source, non-string entries, nonempty uncaptured stack | Reject the event. |

If supplied, `hookContext` must be an object with a nonempty string `agent`.
An optional `resolvedHostModule` must also be a nonempty string. Explicit nulls
are invalid, including for optional fields.

Native and Rust ingestion validate these invariants. Live conversion makes a
missing legacy source explicit. Stored legacy events retain their original
strings and fields during replay. The inspector labels old entries `Unverified`
and shows `Call stack was not captured.` for new native events. JSONL exports
preserve these fields through the worker and session pipeline.

Before this correction, the controller emitted `agent!IatHook` and `module!API`
labels as stack entries. Existing files containing those labels remain readable;
they do not prove that any stack frames were collected. A future capture mode
requires an actual unwinding implementation, frame provenance, failure reporting
and measured target overhead before another source value can be accepted.

Microsoft documents `CaptureStackBackTrace` as walking the stack and returning
captured frame pointers and a frame count. That is a distinct observation from
the metadata currently available here. See the
[Microsoft API reference](https://learn.microsoft.com/en-us/windows/win32/debug/capturestackbacktrace),
checked on 2026-09-21. This correction does not satisfy the separate stack capture
or capture profile cost gates.

The same distinction between missing and observed data applies to trace counts.
`Trimmed` counts ingested records removed from the retained display window.
`Not ingested` is the excess of the native streamed count over the UI ingested
count; those records may still be pending or may be unavailable. A newer native
snapshot must not turn this temporary difference into a claim of UI trimming.
The desktop validation requires all counts to reconcile after capture stops.
