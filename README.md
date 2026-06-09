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
- Bounded controlled File I/O capture from the repository sample target through same-bitness x64/x86 agent IAT hooks.
- Explicit controlled `NtCreateFile` capture from `ntdll.dll` with NTSTATUS return evidence.
- Deterministic x64/x86 agent lifecycle telemetry with hook restore evidence on shutdown.
- Same-bitness injection preflight for target/agent architecture and missing binary failures.
- Shared-memory binary API event transport for the controlled sample capture hot path.
- Definition System V1 with JSON Schema validation, decode metadata registries, deterministic API/module id generation, Rohitab XML importer fixtures, and coverage reporting.
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
11. x64/x86 agent DLLs that send a HELLO handshake after controlled early-bird APC load.
12. Sample File I/O target executable.
13. Bounded `capture-sample` helper command that collects real `api_call` events from the sample target.
14. x64/x86 agent IAT hooks for `CreateFileW`, `CreateFileA`, `NtCreateFile`, `ReadFile`, `WriteFile`, and `CloseHandle`.
15. UI action that maps captured native File I/O events into the trace table.
16. `capture-sample --write-session <dir>` session writer.
17. `validate-session --session <dir>` and `replay-session --session <dir>` helper commands.
18. UI actions for `Capture And Save` and `Replay Last`.
19. x64/x86 agent hook lifecycle states, idempotent IAT restore, and structured `agent_shutdown` evidence.
20. `knmon-collector.exe smoke-backpressure` for deterministic collector queue/drop accounting.
21. Controlled `NtCreateFile` capture with bounded `OBJECT_ATTRIBUTES` object-name decoding.
22. Same-bitness x64/x86 controlled injection preflight with missing binary and architecture mismatch diagnostics.
23. Shared-memory binary API event transport with bounded ring capacity, drop-newest accounting, and hook overhead metrics.
24. Loader-aware PEB module inventory, eligible-module IAT sweep, and dynamic-load re-hooking for the controlled sample path.
25. Repository-owned `knmon-dynamic-probe.dll` sample that proves post-load IAT coverage.
26. Definition System V1 schema validation, fixtures, decode alias metadata, enum/flag metadata, stable generated transport IDs, Rohitab XML importer prototype, and coverage report command.

Not implemented yet:

1. Arbitrary already-running process injection.
2. Continuous streaming capture for long-running targets.
3. Wave 2/3/4 broad system DLL coverage beyond the current loader-aware Wave 1 foundation.
4. Breakpoint mutation.
5. COM monitoring.
6. Kernel-mode helper.
7. Compressed `.knapm` container chunks and replay indexes.

## Current Native Capture Snapshot

Current native capture is a bounded, controlled sample-target flow:

1. `knmon-native-helper.exe capture-sample` launches `knmon-sample-fileio.exe` suspended.
2. The controller runs same-bitness preflight for target and agent binaries before remote mutation.
3. The controller queues an early-bird APC to load `knmon-agent64.dll` in x64 builds or `knmon-agent32.dll` in Win32 builds.
4. The controller creates a bounded shared-memory event transport and passes its mapping name to the agent.
5. The agent sends low-volume `agent_hello` and lifecycle messages through the named pipe, inventories loaded modules from the PEB loader list, sweeps eligible module IATs, and writes API call records into shared memory.
6. The controller drains binary records, normalizes them outside the target process into schema-versioned `api_call` events, and returns one structured `capture-result` JSON object with transport metrics.
7. On target shutdown, the agent disables new hook events, restores patched IAT slots where possible, and emits `agent_shutdown` with `reason`, lifecycle state, hook counts, and dropped-event count.
8. `capture-sample --write-session <dir>` writes `manifest.json`, `audit.jsonl`, `agent-events.jsonl`, and `trace-events.jsonl`.
9. `replay-session --session <dir>` returns trace-compatible events without launching a target or loading an agent.
10. The Tauri commands map captured or replayed File I/O events into the React trace table.

Verified live hook coverage:

1. `CreateFileW`
2. `CreateFileA`
3. `NtCreateFile`
4. `ReadFile`
5. `WriteFile`
6. `CloseHandle`
7. `LoadLibraryW`
8. `GetProcAddress`
9. `LdrGetProcedureAddress`

The current smoke path captures real sample-target File I/O events, a deterministic `LoadLibraryW("knmon-dynamic-probe.dll")` loader event, and resolver calls for `GetProcAddress` and `LdrGetProcedureAddress` through `transportMode=shared-memory`, with `droppedEvents=0` on the healthy path. `ReadFile` and `WriteFile` include bounded 16-byte buffer previews. `NtCreateFile` is captured as an explicit `ntdll.dll` event with `returnValue` carrying the NTSTATUS hex value and a bounded `ObjectAttributes` object-name decode. Resolver events include bounded function-name evidence and return/status values, but calls made through resolver-returned function pointers are not automatically instrumented. Backpressure can be forced with `KNMON_TRANSPORT_CAPACITY`; the current bounded ring uses drop-newest accounting and reports transport produced/consumed/dropped records plus min/average/max hook overhead estimates.

Healthy same-bitness x64 and x86 lifecycle evidence currently reports at least the six required File I/O hooks, `restoredHooks=installedHooks`, `failedHooks=0`, and `reason=process_detach` through `agent_shutdown`.

## Safety Boundary

The first MVP intentionally does not attach to arbitrary already-running processes. The native-capture foundation supports controlled launch-time early-bird APC loading into the repository sample target or an explicit launch target owned by the controller. Current live File I/O capture is bounded to same-bitness helper/target/agent paths: x64 helper to x64 target with `knmon-agent64.dll`, or Win32 helper to x86 target with `knmon-agent32.dll`.

Cross-bitness injection, protected-process bypass, manual mapping, stealth loading, and broad inline detours remain out of scope until separately reviewed.

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

Configure and build the optional Win32/x86 native tree:

```powershell
cmake -S native -B build/native-win32 -A Win32
cmake --build build/native-win32 --config Debug
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
powershell -ExecutionPolicy Bypass -File tools\native-smoke\shared-memory-transport-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\shared-memory-backpressure-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\loader-aware-iat-sweep-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\dynamic-load-rehook-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\resolver-monitoring-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\injection-preflight-negative-smoke.ps1
build\native\Debug\knmon-collector.exe smoke-backpressure --capacity 4 --events 10
powershell -ExecutionPolicy Bypass -File tools\native-smoke\collector-backpressure-smoke.ps1
```

Run optional Win32/x86 smoke after building `build/native-win32`:

```powershell
build\native-win32\Debug\knmon-native-helper.exe launch-sample
build\native-win32\Debug\knmon-native-helper.exe capture-sample
powershell -ExecutionPolicy Bypass -File tools\native-smoke\x86-capture-sample-smoke.ps1
```

`launch-sample` creates `knmon-sample-fileio.exe` suspended, queues an early-bird APC to load the same-bitness agent DLL, resumes the primary thread, and waits for an agent HELLO handshake.

`capture-sample` uses the same controlled launch path, keeps the named pipe open for low-volume control/lifecycle messages, inventories loaded modules, installs same-bitness IAT hooks for the stable File I/O, loader-aware Wave 1, and resolver call set, drains API calls from shared memory, and returns schema-versioned `api_call` events plus dropped-event accounting.

The repeated smoke script verifies five consecutive controlled x64 captures, the stable File I/O API set, zero dropped events, and hook restore counts. The `NtCreateFile` smoke verifies the `ntdll.dll` module, NTSTATUS return format, decoded sample object path, shared-memory transport mode, and clean hook restore. The shared-memory transport smoke verifies healthy x64 transport metrics and hook overhead. The shared-memory backpressure smoke forces a tiny ring capacity and verifies non-blocking dropped-event accounting. The loader-aware smokes verify PEB module inventory, eligible-module IAT sweep evidence, `LoadLibraryW` capture, dynamic-load re-hooking, and post-load `knmon-dynamic-probe.dll` API evidence. The resolver monitoring smoke verifies `GetProcAddress` and `LdrGetProcedureAddress` call visibility, resolver tags, bounded `KnMonDynamicProbe` argument evidence, and clean hook restore. The x86 smoke verifies the same File I/O API set, loader evidence, resolver evidence, shared-memory transport, and hook lifecycle from a Win32 helper/target/agent build. The preflight negative smoke verifies missing target, missing agent, and available architecture mismatch failures before remote mutation.

`capture-sample --write-session` persists the bounded capture into a replayable session directory. Session validation checks manifest architecture, HELLO architecture/version evidence, dropped-event accounting, shutdown hook restore counts, and trace rows before replay returns data from disk without relaunching the target.

`knmon-collector.exe smoke-backpressure` exercises the synthetic collector intake path without injection. The current policy is `drop-newest`; with capacity 4 and 10 events, the expected retained FIFO sequence is `1,2,3,4` and `droppedEvents=6`.

Validate API definitions:

```powershell
npm run defs:generate
npm run defs:validate
npm run defs:coverage
```

`defs:generate` rewrites deterministic definition ID artifacts from `definitions/metadata/id-assignments.json`:

1. `generated/definition-ids.json`
2. `native/knmon-common/include/knmon/common/GeneratedApiIds.h`

`defs:validate` runs JSON Schema validation for committed definition JSON files, semantic checks for decode aliases, enum/flag references, length expressions, duplicate APIs, stable ID assignments, definition fixtures, the Rohitab importer fixture, and a coverage-report bucket check. `defs:coverage` prints a deterministic Markdown report that separates `definition_only`, `hooked`, and `smoke_verified` API coverage.

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
definitions/            API definition documents and decode/id metadata
generated/              Deterministic generated definition artifacts
docs/                   Product and architecture documentation
samples/                Future sample targets and sessions
tools/                  Validators, definition generators, importer prototype, and future CLI tools
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
