# Desktop control polling and trace completion

Local operation/session snapshots and daemon discovery have independent polling
loops. A delayed or failed daemon helper does not hold up local capture state.
The daemon-list command runs its blocking helper work through Tauri's
`spawn_blocking`; [Tauri documents the main-thread behavior of synchronous
commands](https://v2.tauri.app/develop/calling-rust/#async-commands).

| Read | Delay after the previous response |
|---|---|
| Local operations and sessions, while busy or active | 500 ms |
| Daemon sessions, while a known daemon session is active | 500 ms |
| Daemon discovery, otherwise | 5,000 ms |

Each loop has at most one read in flight. Both local commands must settle before
their slot is released, including when one command fails. Disabling and enabling
a loop does not abandon its outstanding request or start a second one. Disposed
loops ignore late results and errors.

Direct start, stop and cancel results invalidate older polls in their own domain.
A successful daemon snapshot replaces daemon rows while preserving local rows;
local snapshots do the reverse. An unsuccessful read retains the last snapshot
and records its error. Equal flat snapshots retain their React state reference.
Idle discovery also finds daemon sessions without requiring a local operation.

Trace draining follows the selected trace's session ID, independently of which
session appears first in the control panel. A terminal attach or launch session
continues to drain until the backend returns an empty batch list. Export and new
capture actions wait while the terminal tail is draining. The displayed total
continues to use that trace session's native record count after native stop.
Repeated drain errors or an ingest-worker failure show `drain_failed`; they are
not reported as a successfully drained trace.

Run the deterministic concurrency and selection regressions with:

```powershell
node --test tools/ui-validator/native-ownership-polling.test.mjs tools/ui-validator/target-architecture.test.mjs
npm run ui:validate
```

The [actual desktop probe](desktop-evidence.md) checks attach, filter, stop,
terminal draining and export against real native events on both architectures.
Its healthy-path consumer rejects ownership and trace-drain errors in retained
UI audit observations. This is separate from the injected read-failure cases in
the deterministic regression suite, which verify that local progress survives a
daemon failure.

On 2026-09-20, one before/after run per architecture used the same hidden-window
file-I/O fixture, Release desktop and Debug native tools. Both runs passed the
native/UI/export checks, with no reported event loss and targets surviving stop.

| Measure | x64 before | x64 after | x86 before | x86 after |
|---|---|---|---|---|
| App Job total processes created | 49 | 31 | 53 | 29 |
| Capture Job CPU seconds / wall second | 0.962 | 0.803 | 0.897 | 0.832 |
| Sampled app-tree peak handles | 4,051 | 4,212 | 4,067 | 4,272 |

The CPU ratio uses the first and last resource samples in the capture phase.
Process counts include the desktop's WebView and helper descendants. Handle peaks
were higher in the later run. These short observations support reduced process
creation in this fixture; they do not establish universal latency, resource-use
or leak-free guarantees. The refreshed runs exported 250/230 events with exact
UI totals after the terminal tail finished.
