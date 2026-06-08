# Integration Tests

Future integration tests for Tauri commands, native helpers, collector sessions, and UI workflows.

Current verification gates include:

1. UI build through `npm run build`.
2. Definition validation through `npm run defs:validate`.
3. Session fixture validation through `npm run sessions:validate`.
4. Native helper smoke runs for `capture-sample`, `validate-session`, and `replay-session`.
5. Repeated native lifecycle smoke through `tools\native-smoke\repeat-capture-sample.ps1`.
6. Collector fixture and native smoke validation through `npm run collector:validate`.

Run repeated lifecycle smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\repeat-capture-sample.ps1 -Count 5
```

The script verifies five consecutive controlled sample captures, the stable File I/O API set, zero dropped events, exactly one `agent_shutdown` event per run, and restored hook counts.

Run collector backpressure smoke:

```powershell
npm run collector:validate
powershell -ExecutionPolicy Bypass -File tools\native-smoke\collector-backpressure-smoke.ps1
```

The collector smoke verifies synthetic intake only. It does not launch, inject, attach, or consume shared memory. The current `drop-newest` fixture expects capacity 4, events 10, retained FIFO sequence `1,2,3,4`, and dropped events `6`.
