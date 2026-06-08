# Roadmap

작성일: 2026-06-08

## Phase 0: Bootstrap

Status: implemented foundation.

Deliverables:

1. Repository layout.
2. Product README.
3. Tauri + React UI shell.
4. Rust/Tauri command skeleton.
5. C++20 native skeleton.
6. Protocol contracts.
7. Definition validator.

## Phase 1: File I/O MVP Foundation

Status: implemented as safe mock/simulated capture.

Deliverables:

1. Target process pane with mock process entries.
2. API Library tree for File I/O APIs.
3. Capture profile list.
4. Mock File I/O event stream.
5. Live trace table.
6. Display filter.
7. Inspector tabs for parameters, buffer, call stack, return/error, and output.
8. JSONL export.
9. C++ controller contract and process enumeration skeleton.

Exit criteria before moving to live capture:

1. UI build is green.
2. Definition validator is green.
3. Native skeleton builds.
4. Tauri shell runs.
5. Event model and contracts are reviewed.

## Phase 2: Native Enumeration Bridge

Status: implemented foundation.

Goal:

Connect Tauri to the C++ controller or a native helper process for real process enumeration.

Deliverables:

1. Native helper process or FFI bridge.
2. Real process list in UI.
3. Access-denied and unsupported target states.
4. Architecture detection.
5. Controller error propagation to UI.

## Phase 3: Controlled Early-Bird Agent Load

Status: implemented foundation.

Goal:

Prove launch-time native agent loading against a repository-owned sample target without arbitrary attach injection.

Deliverables:

1. `knmon-native-helper.exe launch-sample`.
2. `knmon-sample-fileio.exe`.
3. `knmon-agent64.dll`.
4. `CreateProcessW(CREATE_SUSPENDED)`.
5. `VirtualAllocEx` and `WriteProcessMemory` for the absolute agent path.
6. `QueueUserAPC` early-bird load path.
7. `ResumeThread`.
8. Named-pipe HELLO handshake.
9. UI Output audit events and `agent_loaded` trace row support.

## Phase 4: Collector And Session Writer

Status: implemented foundation through bounded helper session output, replay, and synthetic collector backpressure validation.

Goal:

Implement the event collector and a durable session writer without injecting yet.

Deliverables:

1. Collector event intake interface.
2. Append-only JSONL or chunked event writer.
3. Dropped event accounting.
4. Backpressure policy.
5. Replay from saved mock/native test events.

Current implementation notes:

1. `capture-sample` returns a structured bounded `capture-result` object.
2. `capture-sample --write-session <dir>` writes `manifest.json`, `audit.jsonl`, `agent-events.jsonl`, and `trace-events.jsonl`.
3. `validate-session --session <dir>` checks the required manifest fields, event files, HELLO, dropped-event accounting, and trace rows.
4. `replay-session --session <dir>` returns trace-compatible events without launching a target or loading an agent.
5. The UI exposes `Capture And Save` and `Replay Last` for the default `captures/latest-sample-fileio` session.
6. `knmon-collector.exe smoke-backpressure --capacity 4 --events 10` proves bounded synthetic collector intake, FIFO retention, drop-newest overflow, and dropped-event accounting.
7. Durable `.knapm` session chunks, replay indexing, and crash-tolerant high-volume writers remain future work.

## Phase 5: Safe Agent Harness

Status: implemented foundation for x64 controlled sample target with lifecycle hardening.

Goal:

Introduce controlled x86/x64 agent loading only against a sample target.

Deliverables:

1. Sample target executable.
2. Agent load/unload harness.
3. IPC handshake.
4. Protocol version handshake.
5. Emergency detach/self-disable behavior.

Current implementation notes:

1. x64 early-bird APC load is implemented for controller-owned sample launches.
2. The agent sends `agent_hello`, `hook_installed`, `hook_install_failed`, `api_call`, `dropped_events`, and `agent_shutdown` messages.
3. Hook install failure is reported as a precise capture failure.
4. The x64 agent tracks patched IAT slots and restores original entries during shutdown/self-disable where possible.
5. Healthy shutdown reports `installedHooks=5`, `restoredHooks=5`, and `failedHooks=0`.
6. x86 remains a documented skeleton.
7. Arbitrary already-running process detach remains future work.

## Phase 6: File I/O Live Capture

Status: implemented foundation for bounded x64 sample-target capture.

Goal:

Capture the initial File I/O API set from a controlled user-mode target.

Deliverables:

1. `CreateFileW`
2. `CreateFileA`
3. `ReadFile`
4. `WriteFile`
5. `CloseHandle`
6. Pre-call and post-call argument snapshots.
7. Return/error decode.
8. Bounded buffer snapshots.
9. Dropped event accounting.
10. `NtCreateFile` remains deferred until Win32 hook capture is reviewed.

Current verified behavior:

1. `capture-sample` captures real `api_call` events from `knmon-sample-fileio.exe`.
2. Healthy smoke coverage includes `CreateFileW`, `CreateFileA`, `ReadFile`, `WriteFile`, and `CloseHandle`.
3. HELLO arrives before hook status and API call events.
4. `ReadFile` and `WriteFile` include bounded buffer previews.
5. Dropped event accounting is present and currently reports zero on the healthy path.
6. `agent_shutdown` is required for healthy bounded capture success.
7. Repeated capture smoke covers five consecutive runs and hook restore counts.

Next implementation focus:

1. Decide whether `NtCreateFile` should be captured through a separate native hook phase or decoded from higher-level Win32 events first.
2. Start x86 agent parity only after the x64 session path remains stable.
3. Begin high-volume table and replay indexing work after lifecycle evidence remains stable.
4. Move the collector from synthetic intake to shared-memory transport only after a separate review.

## Phase 7: Definition System V1

Goal:

Move from structural definition files to validated and tested decode metadata.

Deliverables:

1. JSON Schema validator.
2. Definition fixtures.
3. Decode alias registry.
4. Enum/flag support.
5. Buffer length expressions.
6. Rohitab XML importer prototype.

## Phase 8: Advanced UX

Goal:

Improve high-volume analysis workflows.

Deliverables:

1. Virtualized trace table at high event counts.
2. Multi-session replay picker and indexed replay.
3. Query builder.
4. Error view.
5. Thread view.
6. Timeline view.
7. Rule-based highlighting.

## Explicit Non-Goals Until Reviewed

1. Kernel-mode helper.
2. PPL bypass.
3. EDR bypass.
4. Breakpoint mutation.
5. Live arbitrary process memory editing.
6. COM monitoring.
7. Full symbol server integration.
8. Arbitrary already-running process injection.
