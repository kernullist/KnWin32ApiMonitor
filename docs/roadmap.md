# Roadmap

작성일: 2026-06-08
갱신일: 2026-06-09

## Product-Critical Priorities

The remaining roadmap is now ordered around three product-critical constraints:

1. Injection reliability:
   - The monitor must avoid preventable injection failures.
   - Unsupported targets must fail before mutation with precise diagnostics.
   - Same-bitness helper/target/agent paths come before cross-bitness or protected-process work.
2. Broad system DLL API coverage:
   - The monitor must scale beyond the current File I/O slice.
   - Dynamic loading must be covered through loader-aware module tracking, import re-patching, and resolver monitoring.
   - IAT hooks alone are not enough for APIs resolved through `GetProcAddress` or `LdrGetProcedureAddress`; those paths require separate design and validation.
3. Low target-process overhead:
   - Hook fast paths must avoid JSON serialization, blocking pipe writes, expensive decoding, and unnecessary memory copies.
   - High-volume capture must move to a binary shared-memory transport before broad API coverage is enabled.
   - Expensive decode, symbolization, indexing, and UI shaping should run outside the target process.

Operational interpretation:

1. "Injection without failure" means no silent or avoidable failure for supported targets, plus explicit unsupported states for PPL, architecture mismatch, missing privileges, mitigation-policy conflicts, or unavailable helper/agent binaries.
2. "Almost all system DLL APIs" means staged, definition-driven coverage for common Windows user-mode DLLs, dynamic DLL loads, delay-loaded imports, and resolver-returned function pointers where a reviewed hook method exists.
3. "Minimum performance delay" means target hooks do the smallest possible amount of work and hand events to the collector through bounded non-blocking transport.

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

1. x64 and x86 same-bitness early-bird APC load is implemented for controller-owned sample launches.
2. The agent sends `agent_hello`, `hook_installed`, `hook_install_failed`, `api_call`, `dropped_events`, and `agent_shutdown` messages.
3. Hook install failure is reported as a precise capture failure.
4. The shared agent tracks patched IAT slots and restores original entries during shutdown/self-disable where possible.
5. Healthy shutdown reports at least the six required File I/O hook groups, `restoredHooks=installedHooks`, and `failedHooks=0`.
6. x86 uses `knmon-agent32.dll` from a Win32 helper/target/agent build.
7. Same-bitness preflight rejects missing binaries and available architecture mismatches before remote mutation.
8. Arbitrary already-running process detach remains future work.

## Phase 6: File I/O Live Capture

Status: implemented foundation for bounded x64 sample-target capture.

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
10. Dropped event accounting.
11. `NtCreateFile` uses explicit controlled `ntdll.dll` IAT capture with NTSTATUS return evidence.

Current verified behavior:

1. `capture-sample` captures real `api_call` events from `knmon-sample-fileio.exe`.
2. Healthy smoke coverage includes `CreateFileW`, `CreateFileA`, `NtCreateFile`, `ReadFile`, `WriteFile`, and `CloseHandle`.
3. HELLO arrives before hook status and API call events.
4. `ReadFile` and `WriteFile` include bounded buffer previews.
5. Dropped event accounting is present and currently reports zero on the healthy path.
6. `agent_shutdown` is required for healthy bounded capture success.
7. Repeated capture smoke covers five consecutive runs and hook restore counts.
8. `NtCreateFile` smoke verifies `ntdll.dll`, NTSTATUS format, bounded `ObjectAttributes` object-name decoding, and restored hook counts.

Next implementation focus:

1. Move target-process event emission from JSON/named-pipe fast paths toward shared-memory binary transport before enabling broad API coverage.
2. Add hook overhead measurement and transport backpressure evidence before increasing hook count.
3. Add loader-aware system DLL coverage only after the low-overhead transport is in place:
   - all-loaded-module IAT sweep
   - re-hook on DLL load
   - `LoadLibrary*`, `LdrLoadDll`, `GetProcAddress`, and `LdrGetProcedureAddress` monitoring
4. Start controlled attach and child-process supervision only after same-bitness launch reliability and transport backpressure remain stable.
5. Expand File I/O and system DLL decode metadata after the native trace contract remains stable.

## Phase 7: Injection Reliability Foundation

Status: implemented foundation for same-bitness controlled sample launch/capture.

Goal:

Make supported same-bitness injection paths predictable, diagnosable, and repeatable before broad process support is added.

Deliverables:

1. x86 agent parity for the controlled sample path:
   - x86 helper
   - x86 sample target
   - `knmon-agent32.dll`
   - same six File I/O hooks as x64
2. Helper/target/agent architecture preflight:
   - x86 helper -> x86 target -> x86 agent
   - x64 helper -> x64 target -> x64 agent
   - mismatch is a hard fail before remote mutation
3. Target eligibility checks:
   - process architecture
   - session/elevation boundary
   - protected/PPL state where detectable
   - file existence and DLL loadability
   - mitigation-policy or access-denied hints where available
4. Injection attempt audit model:
   - preflight result
   - selected method
   - remote allocation/write evidence
   - APC queue evidence
   - resume evidence
   - HELLO timeout/failure reason
5. Handshake hardening:
   - version compatibility
   - architecture confirmation
   - operation id confirmation
   - bounded retry or clean failure policy
6. Failure taxonomy:
   - unsupported_architecture
   - unsupported_protected_process
   - missing_target
   - missing_agent
   - access_denied
   - target_open_failed
   - agent_open_failed
   - helper_agent_mismatch
   - loader_failed
   - handshake_timeout
   - target_exited_early
7. Smoke matrix:
   - x64 controlled launch/capture still green
   - x86 controlled launch/capture green when Win32 toolchain is available
   - negative tests for missing agent and architecture mismatch

Exit criteria:

1. Supported same-bitness controlled launches produce HELLO reliably across repeated runs.
2. Unsupported targets fail before remote mutation whenever detectable.
3. x64 regressions remain green.
4. Docs clearly distinguish supported failure-free paths from unsupported Windows security boundaries.

Current verified behavior:

1. x64 helper defaults to `knmon-agent64.dll`; Win32 helper defaults to `knmon-agent32.dll`.
2. x64 and x86 agents share one implementation source with compile-time architecture and DLL labels.
3. HELLO evidence reports the actual agent architecture and version.
4. Controller preflight checks target and agent PE architecture before `CreateProcessW`.
5. Missing target, missing agent, and available architecture mismatch failures report `preflight_failed` without remote mutation.
6. x86 capture smoke covers the same required File I/O hooks as x64, includes loader-aware dynamic-load evidence, and verifies `restoredHooks=installedHooks` with `failedHooks=0`.
7. x86 session write, validation, and replay preserve HELLO architecture/version evidence plus captured `NtCreateFile` trace evidence.

Next implementation focus:

1. Start loader-aware system DLL coverage only on top of the shared-memory transport budget.
2. Keep hook overhead and dropped-event metrics as release gates for every coverage wave.
3. Keep same-bitness preflight as the gate for future attach and child-process monitoring.

## Phase 8: Low-Overhead Event Transport

Status: implemented foundation for controlled sample API events.

Goal:

Remove high-cost work from the target hook path before expanding API coverage.

Deliverables:

1. Shared-memory event transport:
   - fixed-size ring or segmented ring buffer
   - per-process session header
   - producer sequence counters
   - dropped-event counters
   - non-blocking writes from hooks
2. Binary event ABI:
   - compact event header
   - API id/module id/thread id/timestamp
   - bounded argument snapshots
   - deferred string/blob payload blocks
3. Collector reader:
   - drains shared memory
   - normalizes to protocol events outside the target
   - writes session chunks
   - streams UI updates
4. Fast-path constraints:
   - no JSON serialization in hooks
   - no blocking pipe writes in hooks
   - no heap allocation on common hook paths where practical
   - no call stack capture unless explicitly enabled
5. Runtime filters:
   - API allowlist/denylist
   - module filters
   - thread/process filters
   - buffer preview limits
6. Performance smoke:
   - synthetic high-rate producer
   - real sample burst capture
   - p50/p95/p99 hook overhead estimates
   - dropped-event accounting under pressure

Exit criteria:

1. Hook path remains bounded and non-blocking under collector backpressure.
2. Broad API coverage can be enabled without using named-pipe JSON as the hot path.
3. Session writer can consume high-volume events without losing manifest/replay integrity.

Current verified behavior:

1. The controller creates a bounded shared-memory ring before target resume and passes its mapping name to the agent.
2. x64 and x86 controlled sample captures report `transportMode=shared-memory`.
3. API hook fast paths write fixed-size binary records with API id, module id, process/thread id, timing, return/error fields, bounded numeric slots, and bounded text slots.
4. API hook fast paths no longer write API event JSON to the named pipe.
5. Named pipe remains for low-volume HELLO, hook install status, dropped-event summary, and shutdown lifecycle messages.
6. The controller drains binary records and normalizes them into the existing `api_call` JSON shape outside the target process.
7. Healthy x64/x86 captures consume shared-memory API records for File I/O plus loader-aware sample events with zero dropped events.
8. Backpressure smoke with `KNMON_TRANSPORT_CAPACITY=2` completes capture, retains bounded records, and reports dropped transport events.
9. Capture results expose transport capacity, produced/consumed/dropped counts, high-water mark, and min/average/max hook overhead metrics.
10. Session write, validation, and replay remain compatible with shared-memory-normalized `api_call` events.

Next implementation focus:

1. Expand loader-aware coverage beyond the controlled Wave 1 sample.
2. Keep resolver monitoring design separate from returned-pointer instrumentation.
3. Promote the controller-side shared-memory drain into a dedicated collector reader when event volume increases beyond the controlled sample path.

## Phase 9: Loader-Aware System DLL API Coverage

Status: implemented foundation for controlled sample dynamic loading and eligible-module IAT sweep.

Goal:

Expand from the current File I/O slice to broad, loader-aware monitoring across system DLLs and dynamic loading.

Deliverables:

1. Module inventory:
   - initial PEB loader list snapshot
   - loaded module metadata
   - system/user module classification
   - module id registry for compact event transport
2. All-loaded-module IAT hook sweep:
   - patch imports in every eligible loaded module
   - skip self/agent/unsupported modules
   - restore all patched slots on detach/shutdown
3. Loader monitoring:
   - `LdrLoadDll`
   - `LoadLibraryW`
   - `LoadLibraryA`
   - `LoadLibraryExW`
   - `LoadLibraryExA`
   - DLL unload signals where feasible
4. Re-hook policy:
   - hook newly loaded modules
   - re-run import scan after dynamic load
   - avoid duplicate patches
   - handle unload races conservatively
5. Resolver monitoring:
   - `GetProcAddress`
   - `LdrGetProcedureAddress`
   - optional returned-pointer instrumentation design for dynamically resolved APIs
6. System DLL coverage waves:
   - Wave 1: `ntdll.dll`, `kernelbase.dll`, `kernel32.dll`
   - Wave 2: `advapi32.dll`, `bcrypt.dll`, `crypt32.dll`, `rpcrt4.dll`, `ws2_32.dll`, `wininet.dll`, `winhttp.dll`
   - Wave 3: `user32.dll`, `gdi32.dll`, `shell32.dll`, `ole32.dll`, `combase.dll`
   - Wave 4: generated definitions for the remaining common Windows user-mode DLLs
7. Hook safety policy:
   - no inline detours by default
   - inline/hotpatch detours require separate risk review, ABI tests, and performance proof
   - dynamic function-pointer coverage must be explicitly labeled when not complete

Exit criteria:

1. APIs imported by dynamically loaded modules are captured after load.
2. Resolver calls are visible and correlated with later API coverage where possible.
3. Event volume remains within the Phase 8 transport budget.

Current verified behavior:

1. The agent snapshots the PEB loader list after startup and emits `module_inventory`.
2. The initial eligible-module IAT sweep emits `iat_sweep` with scanned, eligible, skipped, patched, duplicate, and failed slot counts.
3. Patch owners exclude the agent and Windows system modules; provider modules for Wave 1 include `kernel32.dll`, `kernelbase.dll`, and `ntdll.dll`.
4. Hook records are keyed by import slot address to suppress duplicate patches.
5. The sample target loads `knmon-dynamic-probe.dll` with `LoadLibraryW`.
6. `LoadLibraryW` is captured as a loader-tagged shared-memory `api_call`.
7. Successful dynamic load triggers a `dynamic_load` IAT re-sweep.
8. Post-load File I/O from `knmon-dynamic-probe.dll` is captured after the re-sweep.
9. `GetProcAddress` and `LdrGetProcedureAddress` resolver calls for `KnMonDynamicProbe` are captured as resolver-tagged shared-memory `api_call` events.
10. Resolver records include bounded function-name evidence and return/status values without claiming returned-pointer instrumentation.
11. Unloaded owner-module restoration races are handled without stale writes and healthy shutdown reports `restoredHooks=installedHooks`.

Next implementation focus:

1. Broaden Wave 2 system DLL API definitions only after generated IDs, definition validation, transport, and hook-overhead gates remain green.
2. Keep generated ID artifacts as the gate before any new transport ABI expansion.
3. Keep returned-pointer instrumentation as a separate reviewed design item.

## Phase 10: Definition System V1

Status: implemented foundation for validated metadata, generated IDs, importer fixtures, and coverage reporting.

Goal:

Move from structural definition files to validated, generated, and performance-aware decode metadata.

Deliverables:

1. JSON Schema validator.
2. Definition fixtures.
3. Decode alias registry.
4. Enum/flag support.
5. Buffer length expressions.
6. Module/API id generation for compact transport.
7. Rohitab XML importer prototype.
8. Coverage reports by DLL, API family, argument decode quality, and risk level.

Current verified behavior:

1. API definition JSON files are validated by `contracts/api-definition.schema.json`.
2. Definition metadata JSON files are validated by `contracts/definition-metadata.schema.json`.
3. `definitions/metadata/decode-aliases.json` centralizes decode alias behavior and target-memory preview guidance.
4. `definitions/metadata/enums.json` and `definitions/metadata/flags.json` provide File I/O and loader enum/flag metadata.
5. `definitions/metadata/id-assignments.json` preserves File I/O API ids `1` through `6`, loader API ids `7` through `11`, and Wave 1 module ids.
6. `npm run defs:generate` writes deterministic ID artifacts:
   - `generated/definition-ids.json`
   - `native/knmon-common/include/knmon/common/GeneratedApiIds.h`
7. `Protocol.h` consumes the generated native ID header.
8. Positive and negative definition fixtures prove schema and semantic validation paths.
9. Restricted buffer length expression validation rejects unsupported tokens and unknown parameter identifiers without arbitrary code execution.
10. The Rohitab XML importer prototype converts a small local XML fixture into deterministic draft definition JSON and marks unknown decodes as `unresolved`.
11. `npm run defs:coverage` reports by DLL, family, risk, hook policy, coverage status, and decode quality.

Next implementation focus:

1. Add Wave 2 definition-only metadata before any Wave 2 hook enablement.
2. Start generated decoder tables for controller-side argument rendering after coverage reports remain stable.
3. Design returned-pointer instrumentation only after the IAT resolver monitoring path remains stable under transport and hook-overhead gates.

## Phase 11: Controlled Attach And Process Tree Supervision

Goal:

Move from repository-owned controlled launch to selected target monitoring without pretending protected-process bypass exists.

Deliverables:

1. Attach preflight for already-running processes.
2. Same-bitness attach method selection.
3. Explicit failure states for access-denied, PPL/protected, architecture mismatch, and target instability.
4. Detach and self-disable protocol.
5. Child process auto-attach policy.
6. Process tree session model.
7. UI controls for attach/detach/child policy with audit output.

Exit criteria:

1. Supported user-mode targets can be attached and detached repeatedly without stale hooks.
2. Unsupported targets fail cleanly before risky mutation where detectable.
3. Child process monitoring does not break target startup latency budgets.

## Phase 12: Advanced UX

Goal:

Improve high-volume analysis workflows after the transport and coverage foundations exist.

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
8. Cross-bitness injection.
9. Stealth/manual-map injection.
10. Inline detours for broad API coverage without a separate ABI, stability, and performance review.
