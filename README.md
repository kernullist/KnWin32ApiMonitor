# KN Win32 API Monitor

Modern Win32 API monitor workstation foundation for Windows 10/11 security engineering.

This repository is bootstrapping a new API Monitor inspired by Rohitab API Monitor, with a safer modern architecture:

- Tauri 2 + React/TypeScript desktop UI.
- C++20 native controller and collector skeleton.
- Versioned protocol contracts.
- File I/O MVP model for `CreateFileW`, `CreateFileA`, `NtCreateFile`, `ReadFile`, `WriteFile`, and `CloseHandle`.
- Mock capture stream that exercises the same event shape intended for the future native collector.
- JSONL export for early session artifacts.
- Controlled launch-time early-bird APC agent load foundation for the repository sample target.
- Bounded controlled File I/O capture from the repository sample target through x64 agent IAT hooks.
- Explicit controlled `NtCreateFile` capture from `ntdll.dll` with NTSTATUS return evidence.
- Deterministic x64 agent lifecycle telemetry with hook restore evidence on shutdown.
- Durable helper-written sample sessions with manifest, audit, agent-event, and trace-event JSONL files.
- Session validation and replay without relaunching or reinjecting the sample target.
- Synthetic collector intake with deterministic bounded queue backpressure validation.

## Current Status

Phase 0, Phase 1, and the first controlled native-capture foundations are in progress.

Implemented now:

1. High-density API monitor workstation UI shell.
2. Mock File I/O trace stream with start/stop/clear controls.
3. Target/API/profile panes.
4. Trace table, display filter, inspector tabs, buffer preview, stack preview, return/error panel, output panel.
5. JSONL export from the mock event model.
6. Rust/Tauri command layer skeleton.
7. C++20 native controller/collector skeleton.
8. JSON contracts and File I/O API definitions.
9. Definition validator.
10. Native helper CLI for process enumeration and controlled sample launch.
11. x64 agent DLL that sends a HELLO handshake after controlled early-bird APC load.
12. Sample File I/O target executable.
13. Bounded `capture-sample` helper command that collects real `api_call` events from the sample target.
14. x64 agent IAT hooks for `CreateFileW`, `CreateFileA`, `NtCreateFile`, `ReadFile`, `WriteFile`, and `CloseHandle`.
15. UI action that maps captured native File I/O events into the trace table.
16. `capture-sample --write-session <dir>` session writer.
17. `validate-session --session <dir>` and `replay-session --session <dir>` helper commands.
18. UI actions for `Capture And Save` and `Replay Last`.
19. x64 agent hook lifecycle states, idempotent IAT restore, and structured `agent_shutdown` evidence.
20. `knmon-collector.exe smoke-backpressure` for deterministic collector queue/drop accounting.
21. Controlled `NtCreateFile` capture with bounded `OBJECT_ATTRIBUTES` object-name decoding.

Not implemented yet:

1. Arbitrary already-running process injection.
2. Continuous streaming capture for long-running targets.
3. Shared-memory event transport.
4. Breakpoint mutation.
5. COM monitoring.
6. Kernel-mode helper.
7. x86 agent build.
8. Compressed `.knapm` container chunks and replay indexes.

## Current Native Capture Snapshot

Current native capture is a bounded, controlled sample-target flow:

1. `knmon-native-helper.exe capture-sample` launches `knmon-sample-fileio.exe` suspended.
2. The controller queues an early-bird APC to load `knmon-agent64.dll`.
3. The x64 agent sends `agent_hello`, installs main-module IAT hooks, and emits schema-versioned `api_call` events.
4. On target shutdown, the agent disables new hook events, restores patched IAT slots where possible, and emits `agent_shutdown` with `reason`, lifecycle state, hook counts, and dropped-event count.
5. The helper returns one structured `capture-result` JSON object with audit events, raw agent messages, captured events, lifecycle evidence, and dropped-event accounting.
6. `capture-sample --write-session <dir>` writes `manifest.json`, `audit.jsonl`, `agent-events.jsonl`, and `trace-events.jsonl`.
7. `replay-session --session <dir>` returns trace-compatible events without launching a target or loading an agent.
8. The Tauri commands map captured or replayed File I/O events into the React trace table.

Verified live hook coverage:

1. `CreateFileW`
2. `CreateFileA`
3. `NtCreateFile`
4. `ReadFile`
5. `WriteFile`
6. `CloseHandle`

The current smoke path captures real sample-target File I/O events and reports `droppedEvents=0` on the healthy path. `ReadFile` and `WriteFile` include bounded 16-byte buffer previews. `NtCreateFile` is captured as an explicit `ntdll.dll` event with `returnValue` carrying the NTSTATUS hex value and a bounded `ObjectAttributes` object-name decode.

Healthy lifecycle evidence currently reports `installedHooks=6`, `restoredHooks=6`, `failedHooks=0`, and `reason=process_detach` through `agent_shutdown`.

## Safety Boundary

The first MVP intentionally does not inject into arbitrary already-running processes. The native-capture foundation only supports controlled launch-time early-bird APC loading into the repository sample target or an explicit launch target owned by the controller. Current live File I/O capture is bounded to the repository sample target and x64 agent.

Future dangerous operations such as arbitrary attach, skip-call, forced return values, or memory editing must be explicit, audited, and isolated behind versioned controller commands.

## Prerequisites

- Windows 10/11.
- Node.js 20 or newer.
- Rust toolchain with Cargo.
- CMake 3.24 or newer.
- Visual Studio Build Tools or another CMake-supported C++20 compiler.
- WebView2 runtime for Tauri desktop execution.

## Build And Run

Install dependencies:

```powershell
npm install
```

Run the UI in browser/Vite mode:

```powershell
npm run dev
```

Build the UI:

```powershell
npm run build
```

Run the Tauri desktop shell:

```powershell
npm run tauri:dev
```

Configure and build native skeleton:

```powershell
npm run native:configure
npm run native:build
```

Run native helper smoke tests:

```powershell
build\native\Debug\knmon-native-helper.exe list-targets
build\native\Debug\knmon-native-helper.exe launch-sample
build\native\Debug\knmon-native-helper.exe capture-sample
build\native\Debug\knmon-native-helper.exe capture-sample --write-session captures\latest-sample-fileio
build\native\Debug\knmon-native-helper.exe validate-session --session captures\latest-sample-fileio
build\native\Debug\knmon-native-helper.exe replay-session --session captures\latest-sample-fileio
powershell -ExecutionPolicy Bypass -File tools\native-smoke\repeat-capture-sample.ps1 -Count 5
powershell -ExecutionPolicy Bypass -File tools\native-smoke\ntcreatefile-capture-smoke.ps1
build\native\Debug\knmon-collector.exe smoke-backpressure --capacity 4 --events 10
powershell -ExecutionPolicy Bypass -File tools\native-smoke\collector-backpressure-smoke.ps1
```

`launch-sample` creates `knmon-sample-fileio.exe` suspended, queues an early-bird APC to load `knmon-agent64.dll`, resumes the primary thread, and waits for an agent HELLO handshake.

`capture-sample` uses the same controlled launch path, keeps the event pipe open until the sample target exits, installs x64 IAT hooks for the stable File I/O set, and returns schema-versioned `api_call` events plus dropped-event accounting.

The repeated smoke script verifies five consecutive controlled captures, the stable File I/O API set, zero dropped events, and hook restore counts. The `NtCreateFile` smoke verifies the `ntdll.dll` module, NTSTATUS return format, decoded sample object path, and six restored hooks.

`capture-sample --write-session` persists the bounded capture into a replayable session directory. Replay returns the trace rows from disk and does not relaunch the target.

`knmon-collector.exe smoke-backpressure` exercises the synthetic collector intake path without injection. The current policy is `drop-newest`; with capacity 4 and 10 events, the expected retained FIFO sequence is `1,2,3,4` and `droppedEvents=6`.

Validate API definitions:

```powershell
npm run defs:validate
```

Validate session fixtures:

```powershell
npm run sessions:validate
```

Validate collector fixtures and native smoke output:

```powershell
npm run collector:validate
```

Run available verification:

```powershell
npm run verify
```

## Repository Layout

```text
apps/knmon-ui/          Tauri + React workstation UI
crates/knmon-tauri/     Rust command layer skeleton
native/                 C++20 native controller, collector, and future agents
contracts/              Versioned event/process/session JSON contracts
definitions/            API definition documents
docs/                   Product and architecture documentation
samples/                Future sample targets and sessions
tools/                  Validators and future CLI tools
tests/                  Future integration and definition tests
```

## First Workflow

1. Start the UI with `npm run dev`.
2. Select a process row from the Targets pane.
3. Keep the File I/O MVP capture profile selected.
4. Press Start.
5. Watch mock File I/O events flow into the Live Trace table.
6. Select a row and inspect parameters, buffer preview, call stack, and return/error detail.
7. Press Export JSONL to save a session artifact.

For native enumeration and controlled capture, run the Tauri desktop app after `npm run native:build`, switch Target Source to Native, then use Controlled Launch. `Launch Sample` proves early-bird load and HELLO; `Capture File I/O` runs bounded native sample capture and inserts real hook events into the trace table. `Capture And Save` writes `captures/latest-sample-fileio`; `Replay Last` loads that session back into the trace table without launching or injecting.

## Design Docs

- [Product Design](docs/product-design.md)
- [Architecture](docs/architecture.md)
- [Definition Schema](docs/definition-schema.md)
- [Roadmap](docs/roadmap.md)
