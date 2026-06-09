# Integration Tests

Future integration tests for Tauri commands, native helpers, collector sessions, and UI workflows.

Current verification gates include:

1. UI build through `npm run build`.
2. Definition validation through `npm run defs:validate`.
3. Session fixture validation through `npm run sessions:validate`.
4. Native helper smoke runs for `capture-sample`, `validate-session`, and `replay-session`.
5. Repeated native lifecycle smoke through `tools\native-smoke\repeat-capture-sample.ps1`.
6. `NtCreateFile` native capture smoke through `tools\native-smoke\ntcreatefile-capture-smoke.ps1`.
7. Shared-memory transport smoke through `tools\native-smoke\shared-memory-transport-smoke.ps1`.
8. Shared-memory backpressure smoke through `tools\native-smoke\shared-memory-backpressure-smoke.ps1`.
9. Injection preflight negative smoke through `tools\native-smoke\injection-preflight-negative-smoke.ps1`.
10. Optional Win32/x86 capture smoke through `tools\native-smoke\x86-capture-sample-smoke.ps1`.
11. Collector fixture and native smoke validation through `npm run collector:validate`.

Run repeated lifecycle smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\repeat-capture-sample.ps1 -Count 5
```

The script verifies five consecutive controlled sample captures, the stable File I/O API set, zero dropped events, exactly one `agent_shutdown` event per run, and restored hook counts.

Run `NtCreateFile` capture smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\ntcreatefile-capture-smoke.ps1
```

The `NtCreateFile` smoke verifies the controlled `ntdll.dll` event, NTSTATUS return format, decoded sample object path evidence, shared-memory transport mode, zero dropped events, and six restored hooks.

Run shared-memory transport smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\shared-memory-transport-smoke.ps1
```

The shared-memory transport smoke verifies the healthy controlled x64 capture uses `transportMode=shared-memory`, consumes all produced records, reports zero dropped transport events, preserves the six File I/O APIs, and records hook overhead metrics.

Run shared-memory backpressure smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\shared-memory-backpressure-smoke.ps1
```

The shared-memory backpressure smoke forces a tiny transport capacity, verifies capture still completes without target hang, and checks nonzero transport dropped-event accounting.

Run injection preflight negative smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\injection-preflight-negative-smoke.ps1
```

The preflight smoke verifies that missing target, missing agent, and available architecture mismatch cases fail before remote mutation and include `preflight_failed` audit evidence.

Run optional Win32/x86 capture smoke:

```powershell
cmake -S native -B build/native-win32 -A Win32
cmake --build build/native-win32 --config Debug
powershell -ExecutionPolicy Bypass -File tools\native-smoke\x86-capture-sample-smoke.ps1
```

The x86 smoke verifies same-bitness Win32 helper/target/agent capture, HELLO `architecture = "x86"`, shared-memory transport mode, the six File I/O APIs, `NtCreateFile` NTSTATUS evidence, zero dropped events, and six restored hooks.

Run collector backpressure smoke:

```powershell
npm run collector:validate
powershell -ExecutionPolicy Bypass -File tools\native-smoke\collector-backpressure-smoke.ps1
```

The collector smoke verifies synthetic intake only. It does not launch, inject, attach, or consume shared memory. The current `drop-newest` fixture expects capacity 4, events 10, retained FIFO sequence `1,2,3,4`, and dropped events `6`.
