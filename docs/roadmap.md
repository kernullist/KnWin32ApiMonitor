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

Goal:

Implement the event collector and a durable session writer without injecting yet.

Deliverables:

1. Collector event intake interface.
2. Append-only JSONL or chunked event writer.
3. Dropped event accounting.
4. Backpressure policy.
5. Replay from saved mock/native test events.

## Phase 5: Safe Agent Harness

Goal:

Introduce controlled x86/x64 agent loading only against a sample target.

Deliverables:

1. Sample target executable.
2. Agent load/unload harness.
3. IPC handshake.
4. Protocol version handshake.
5. Emergency detach/self-disable behavior.

## Phase 6: File I/O Live Capture

Goal:

Capture the initial File I/O API set from a controlled user-mode target.

Deliverables:

1. `CreateFileW`
2. `CreateFileA`
3. `NtCreateFile`
4. `ReadFile`
5. `WriteFile`
6. `CloseHandle`
7. Pre-call and post-call argument snapshots.
8. Return/error decode.
9. Bounded buffer snapshots.

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
2. Session replay.
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
