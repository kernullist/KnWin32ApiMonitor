# Roadmap

작성일: 2026-06-08
갱신일: 2026-06-10

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
7. Phase 11I adds durable directory-backed `.knapm` session chunks and indexed replay for bounded streaming attach sessions, Phase 11J adds explicit `.knapm` restart/recovery ownership classification, Phase 11K adds a host-side persistent daemon supervision foundation, Phase 11L hardens daemon audit/stale registry handling, and Phase 11M adds zstd `.knapm` chunks plus host-side JSON replay catalogs; metadata-database indexing, Windows service mode, and crash-tolerant daemon recovery remain future work.

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
7. Healthy x64/x86 captures consume shared-memory API records for File I/O, loader-aware sample events, resolver events, the selected registry slice, the selected advapi32 token query/privilege lookup slice, the selected Winsock slice, the selected RPCRT4 binding slice, the selected bcrypt CNG provider/RNG slice, the selected crypt32 certificate-store/message-handle slice, the selected WinHTTP session-handle slice, and the selected WinINet session-handle slice with zero dropped events.
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
12. The first Wave 2 live slice captures selected `ws2_32.dll` Winsock bootstrap and address-resolution APIs through the same shared-memory transport:
   - `WSAStartup`
   - `WSACleanup`
   - `socket`
   - `closesocket`
   - `getaddrinfo`
   - `freeaddrinfo`
   - `WSAGetLastError`
13. The registry Wave 2 live slice captures selected HKCU-safe `advapi32.dll` registry APIs through the same shared-memory transport:
   - `RegOpenKeyExW`
   - `RegCreateKeyExW`
   - `RegQueryValueExW`
   - `RegSetValueExW`
   - `RegDeleteValueW`
   - `RegCloseKey`
14. Registry records render generated metadata, architecture-aware `HKEY` values, bounded key/value-name evidence, and small value-data previews outside the target process.
15. The advapi32 token query Wave 2 live slice captures selected current-process token query and privilege lookup APIs through the same shared-memory transport:
   - `OpenProcessToken`
   - `LookupPrivilegeValueW`
16. Token query records render generated metadata, current-process `TOKEN_QUERY` access, post-call token handle evidence, privilege-name text, and LUID numeric evidence outside the target process. They intentionally do not capture token privilege arrays, SID/group/ACL/security descriptor data, credentials, service-control data, or token mutation calls such as `AdjustTokenPrivileges`.
17. The RPCRT4 Wave 2 live slice captures selected local `rpcrt4.dll` RPC binding lifecycle APIs through the same shared-memory transport:
   - `RpcStringBindingComposeW`
   - `RpcBindingFromStringBindingW`
   - `RpcStringFreeW`
   - `RpcBindingFree`
18. RPCRT4 records render generated metadata, `RPC_STATUS` values, pointer-sized binding/string handles, and bounded `ncalrpc`/`KNMonRpcSample` string evidence outside the target process.
19. The bcrypt Wave 2 live slice captures selected low-volume `bcrypt.dll` CNG provider/RNG APIs through the same shared-memory transport:
   - `BCryptOpenAlgorithmProvider`
   - `BCryptCloseAlgorithmProvider`
   - `BCryptGetProperty`
   - `BCryptGenRandom`
20. bcrypt records render generated metadata, NTSTATUS values, provider handles, algorithm/property names, pointer values, and byte counts outside the target process. They intentionally do not copy random, key, plaintext, ciphertext, IV, or hash input bytes.
21. The crypt32 Wave 2 live slice captures selected low-volume `crypt32.dll` certificate-store and cryptographic-message handle APIs through the same shared-memory transport:
   - `CertOpenStore`
   - `CertCloseStore`
   - `CryptMsgOpenToDecode`
   - `CryptMsgClose`
22. crypt32 records render generated metadata, store/message handles, provider ID or bounded provider text, encoding/flag values, and pointer values outside the target process. They intentionally do not copy certificate blobs, private keys, cryptographic message payloads, random bytes, keys, plaintext, ciphertext, IVs, or hash input bytes.
23. The WinHTTP Wave 2 live slice captures selected low-volume `winhttp.dll` session-handle APIs through the same shared-memory transport:
   - `WinHttpOpen`
   - `WinHttpCloseHandle`
24. WinHTTP records render generated metadata, user-agent/access-type/proxy pointer evidence, session handles, and return/status values outside the target process. They intentionally do not make network requests or copy URLs, headers, bodies, cookies, credentials, proxy credentials, or payload bytes.
25. The WinINet Wave 2 live slice captures selected low-volume `wininet.dll` session-handle APIs through the same shared-memory transport:
   - `InternetOpenW`
   - `InternetCloseHandle`
26. WinINet records render generated metadata, user-agent/access-type/proxy pointer evidence, session handles, and return/status values outside the target process. They intentionally do not make network requests or copy URLs, headers, bodies, cookies, credentials, proxy credentials, or payload bytes.
27. `WS2_32.dll` ordinal imports for the selected Winsock APIs are matched only through explicit hook-definition ordinals; broad ordinal patching remains out of scope.

Next implementation focus:

1. Keep the selected Winsock, registry, advapi32 token query/privilege lookup, RPCRT4 binding, bcrypt CNG provider/RNG, crypt32 certificate-store/message-handle, WinHTTP session-handle, and WinINet session-handle slices under shared-memory backpressure and hook-overhead gates.
2. Design payload-heavy network hooks (`send`, `recv`, `sendto`, `recvfrom`) and WinHTTP/WinINet connection, request, transfer, option, header, cookie, credential, and body capture separately before enabling buffer capture at scale.
3. Stage the next Wave 2 DLL/API family only after deterministic smoke evidence and transport-budget checks exist; prefer another low-volume handle/lifecycle slice before payload-heavy or secret-bearing APIs.
4. Keep returned-pointer instrumentation as a separate reviewed design item.

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
12. Wave 2 metadata is committed for `advapi32.dll`, `bcrypt.dll`, `crypt32.dll`, `rpcrt4.dll`, `ws2_32.dll`, `wininet.dll`, and `winhttp.dll`.
13. Stable generated IDs now cover 10 modules and 90 APIs, with Wave 2 API IDs `14` through `90`.
14. The coverage report currently totals 46 `definition_only`, 4 `hooked`, and 40 `smoke_verified` APIs.
15. `npm run defs:generate` emits deterministic controller-side decoder metadata:
   - `generated/definition-decoder-tables.json`
   - `native/knmon-common/include/knmon/common/GeneratedApiMetadata.h`
16. The controller uses generated metadata for API/module names, family/category tags, argument names/types/directions, decode aliases, and capture timing while preserving explicit per-API shared-memory slot interpretation.
17. The selected `advapi32.dll` registry slice, selected `advapi32.dll` token query/privilege lookup slice, `bcrypt.dll` CNG provider/RNG slice, `crypt32.dll` certificate-store/message-handle slice, `rpcrt4.dll` local binding slice, `ws2_32.dll` Winsock slice, `winhttp.dll` session-handle slice, and `wininet.dll` session-handle slice are marked `iat` and `smoke_verified`; unimplemented Wave 2 APIs remain `definition_only`.

Next implementation focus:

1. Expand Wave 2 live hooks only by small DLL/API-family slices with deterministic smoke evidence.
2. Review a dedicated ABI and performance plan before enabling high-volume network payload hooks.
3. Prefer the next low-volume API family before payload-heavy hooks, while keeping token mutation, service-control, crypto key/encrypt/decrypt/hash, certificate chain/query/decode, RPC auth/endpoint/UUID, WinINet connection/request/transfer/option, and WinHTTP request/transfer/header work behind separate smoke and transport-budget gates.
4. Design returned-pointer instrumentation only after the IAT resolver monitoring path remains stable under transport and hook-overhead gates.

## Phase 11: Controlled Attach And Process Tree Supervision

Status: Phase 11A, Phase 11B, Phase 11C, Phase 11D, Phase 11E, Phase 11F, Phase 11G, Phase 11H, Phase 11I, Phase 11J, Phase 11K, Phase 11L, and Phase 11M foundations are implemented. Bounded same-bitness running-process attach, helper-side process-tree supervision, UI controls for selected native target attach/supervision, repeated same-process reattach after self-disable, active loaded-agent rejection, pull-based collector reader foundation for shared transport drain, cancellation-safe operation ownership for bounded attach/process-tree helper commands, durable native session ownership readiness, bounded UI streaming trace batches, durable `.knapm` chunk replay, `.knapm` restart/recovery ownership classification, host-side persistent daemon-owned session supervision, daemon audit/stale-registry hardening, zstd `.knapm` chunks, and host-side JSON replay catalogs are implemented; Windows service mode, automatic daemon crash recovery, orphaned active-agent repair, and database-backed large replay indexing remain future work.

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

Current verified Phase 11A behavior:

1. `knmon-native-helper.exe attach-capture --pid <pid>` attaches to an already-running repository sample target without relaunching it.
2. x64 helper -> x64 target -> `knmon-agent64.dll` and Win32 helper -> x86 target -> `knmon-agent32.dll` paths are smoke-verified.
3. Attach preflight rejects PID `0`, PID `4`, helper self, missing targets, missing agents, helper/agent architecture mismatch, and helper/target architecture mismatch before remote mutation.
4. Protection/access checks run before remote mutation where the current user-mode helper can detect them.
5. Supported attach uses remote `LoadLibraryW`; manual mapping, stealth loading, APC injection into arbitrary existing threads, cross-bitness attach, and protected-process bypass remain out of scope.
6. The running target receives configuration through the versioned `KnMonAttachConfigV1` ABI and exported `KnMonAgentInitialize`; launch-time environment variables are not required for attach.
7. API events use the existing shared-memory binary transport and preserve the current schema-compatible `api_call` event shape.
8. `KnMonAgentStop` proves one-shot self-disable with `agent_shutdown reason=self_disable`, `restoredHooks=installedHooks`, and `failedHooks=0`.
9. `capture-result` and session manifests distinguish attach through `captureMode=bounded-native-attach`, `injectionMethod=remote LoadLibraryW`, `attachProcessId`, and `detachPolicy=self-disable-no-unload`.

Current verified Phase 11B behavior:

1. `knmon-native-helper.exe supervise-tree --pid <pid> --child-policy observe` supervises an already-running sample root through bounded Toolhelp process snapshots.
2. `knmon-sample-fileio.exe --spawn-child-loop` creates deterministic repository sample child processes that run the existing attach loop.
3. Process-tree results include root/child nodes with PID, parent PID, image name/path, architecture, first/last seen timestamps, alive/exited state, eligibility, policy decision, and message.
4. Observe policy classifies same-bitness repository sample children as `eligible` with `observe_only` and never emits attach mutation evidence.
5. `attach-supported` policy reuses the Phase 11A `AttachCapture` path for same-bitness repository sample children and preserves `self-disable-no-unload` detach.
6. x64 and x86 process-tree observe and attach-supported smokes are green.
7. Cross-bitness child smoke verifies `helper_target_mismatch` and `mutationAttempted=false` before attach.
8. Missing root, PID `0`, PID `4`, and helper self supervision failures are typed and audited.

Current verified Phase 11C behavior:

1. The React/Tauri UI has a selected native target panel with PID, image, architecture, status, and explicit eligibility reason.
2. `Attach Capture` invokes `attach_target_process_capture`, which runs helper `attach-capture --pid <pid> --duration-ms <ms>` with a bounded wrapper timeout.
3. Attach results render target PID, attach PID, `bounded-native-attach`, `remote LoadLibraryW`, `self-disable-no-unload`, subsystem/operation/Win32/message, dropped counters, transport counters, and `agent_shutdown` hook restore evidence.
4. Attach `capturedEvents` map into the existing trace table with `ui-attach` and target PID context tags.
5. `Supervise` invokes `supervise_process_tree`, which runs helper `supervise-tree --pid <pid> --duration-ms <ms> --child-policy observe|attach-supported` with a bounded wrapper timeout.
6. Process-tree results render root PID, child policy, process nodes, policy decisions, mutation-attempt count, audit output, and child attach summaries.
7. Attach-supported child attach events map into the trace table with `process-tree` and child PID context tags.
8. The UI renders attach state, attach strategy, and loaded-agent detection evidence without claiming persistent attach, safe DLL unload, cross-bitness attach, protected-process bypass, or broad arbitrary target support.

Current verified Phase 11D behavior:

1. `capture-result` includes additive attach evidence fields: `attachState`, `attachStrategy`, `loadedAgentDetected`, `loadedAgentModuleBase`, `loadedAgentPath`, `agentControlStatus`, and `agentAbiVersion`.
2. `KnMonAgentQueryState` reports lifecycle, active/busy/resettable flags, hook lifecycle counts, dropped-event count, current operation id, packed agent version, and attach ABI version.
3. First attach to an unloaded supported target reports `attachState=not_loaded` and `attachStrategy=load_library_initialize`.
4. A second attach to the same still-running process after `self-disable-no-unload` detects the loaded disabled agent and reports `attachState=loaded_disabled`, `attachStrategy=loaded_agent_reinitialize`, and `loadedAgentDetected=true`.
5. Loaded-agent reattach skips another `LoadLibraryW`, uses the loaded module base plus export RVA resolution, and passes a fresh operation id, named pipe, and shared-memory transport mapping to `KnMonAgentInitialize`.
6. Active or busy loaded agents fail as `already_instrumented` before pipe/transport setup or remote mutation.
7. Agent reinitialization is allowed only from disabled/resettable state after all installed hooks are restored and failed hook count is zero.
8. `tools/native-smoke/repeated-attach-state-smoke.ps1` verifies x64/x86 repeated attach success and x64 active loaded-agent rejection.

Current verified Phase 11E behavior:

1. `knmon-collector-core` provides a reusable `SharedTransportReader` for pull-based shared-memory transport drains.
2. The reader validates header magic, ABI version, header size, record size, architecture, operation id, and capacity before consuming records.
3. The reader consumes only committed records whose sequence matches the current consumer sequence.
4. If the producer is ahead but the next record is not committed, the reader stops without skipping ahead or freeing the partial record.
5. The reader supports bounded max-record drain calls for future incremental streaming.
6. Controlled sample capture and `AttachCapture` use the reader boundary while the controller still owns process lifetime, pipe reads, stop/self-disable, and JSON normalization.
7. Process-tree `attach-supported` child capture remains compatible through the existing `AttachCapture` path.
8. `knmon-collector.exe smoke-shared-transport-reader` and `tools/native-smoke/shared-transport-reader-smoke.ps1` verify FIFO drain, partial commit stop behavior, bounded drain behavior, transport counters, and hook-overhead aggregation.

Current verified Phase 11F behavior:

1. `attach-capture` and `supervise-tree` can run with explicit operation ids and local named cancellation events.
2. `knmon-native-helper.exe cancel-operation --operation-id <id>` signals cancellation without killing the active helper or creating an injected command channel.
3. `AttachCapture` observes cancellation during bounded attach, requests `KnMonAgentStop` after initialization, drains final transport/pipe evidence, and returns `operation=operation_cancelled`, `operationState=cancelled`, `win32ErrorCode=ERROR_CANCELLED`, and cleanup evidence when self-disable succeeds.
4. Post-cancel attach to the same still-running target succeeds through Phase 11D `loaded_agent_reinitialize`, proving the target is not left permanently hooked.
5. `SuperviseProcessTree` observes cancellation between snapshots and before child attach; child attach receives the same cancellation event name.
6. Tauri tracks native operations in an operation registry, exposes operation state/cancel commands, and sends `cancel-operation` before any timeout fallback.
7. The selected-target UI renders active operation state, elapsed time, cancel availability, attach cancellation fields, and process-tree cancellation fields without claiming DLL unload or persistent live attach.
8. `tools/native-smoke/cancellation-operation-state-smoke.ps1` verifies x64 attach cancellation cleanup, post-cancel reattach, and process-tree observe cancellation.

Current verified Phase 11G behavior:

1. `capture-result` and `process-tree-result` accept additive session ownership fields including `sessionId`, `sessionState`, owner/helper PID, timestamps, cancellation event name, streamed-record counters, stale reason, and recovery action.
2. `knmon-native-helper.exe attach-session --pid <pid> --session-id <id> --operation-id <id>` emits JSONL `session_started` and `session_state` frames before final capture output.
3. `ThreadedSharedTransportReader` provides a host-side drain thread over `SharedTransportReader`, preserving committed-sequence consumption and bounded stop/join behavior without target hook-path work.
4. Safe session stop reuses `cancel-operation`, then the existing attach cleanup path requests `KnMonAgentStop`, drains transport/pipe evidence, and proves self-disable before reporting `sessionState=stopped`.
5. Existing Phase 11D/11F reattach smokes continue to prove post-stop loaded-agent reuse after self-disable.
6. `classify-session --session-record <path>` marks orphaned running host records as `stale` or `recovery_required` without target mutation.
7. Tauri exposes native session list/stop commands, and the selected-target UI renders active session state, streamed record count, stale reason, and stop availability.
8. `tools/native-smoke/threaded-collector-session-smoke.ps1` verifies threaded committed-record drain, JSONL running-state visibility, and safe stop cleanup.
9. `tools/native-smoke/session-recovery-state-smoke.ps1` verifies stale and recovery-required classification without remote mutation.

Current verified Phase 11H behavior:

1. `attach-session --stream-batches --batch-size <n> --batch-interval-ms <n>` emits bounded JSONL `trace_batch` frames before final helper completion.
2. `trace_batch` frames carry `sessionId`, `operationId`, contiguous `batchSequence`, monotonic record sequence ranges, `eventCount`, target transport dropped records, host dropped UI batch count, streamed-record count, and normalized API events.
3. The controller emits trace batches from the existing host-side shared-memory drain path without adding JSON, blocking I/O, UI logic, or heap-heavy work to the injected hook fast path.
4. `session_stopping`, `session_stopped`, `session_failed`, and final `capture_result` frames preserve the Phase 11F cancellation and `KnMonAgentStop` cleanup contract.
5. Tauri can start a streaming attach session without waiting for final helper completion, track helper/session ownership, and expose cursor-based batch reads from a bounded in-process queue.
6. Tauri accounts for host-side dropped UI batches separately from target transport dropped records.
7. The selected-target UI can start a stream, poll trace batches, append streamed API events to the existing trace table, display streamed records, target drops, host UI drops, helper PID, and stop availability.
8. `contracts/native-trace-batch.schema.json` and `contracts/native-session-frame.schema.json` define the stream frame contract and future replay chunk boundary.
9. `tools/native-smoke/streaming-session-ui-batch-smoke.ps1` verifies streaming state visibility, non-empty trace batches, monotonic batch/record sequences, safe cancellation, final counter consistency, and `agent_shutdown reason=self_disable`.

Current verified Phase 11I behavior:

1. `attach-session --stream-batches --write-knapm <path.knapm>` writes an inspectable directory-backed `.knapm` container while preserving stdout JSONL streaming frames.
2. Each non-empty `trace_batch` becomes one `chunks/trace-000NNN.jsonl` file with an `index.json` entry containing chunk sequence, batch sequence, record range, event-id range, byte length, compression marker, and SHA-256.
3. `manifest.json` records format, finalization, session ownership, counters, target/agent evidence, writer state, chunk count, last batch sequence, and last indexed record sequence.
4. `validate-session --session <path.knapm>` verifies manifest/index identity, chunk existence, byte length, SHA-256, contiguous batch sequence, monotonic record ranges, trace event shape, final counter consistency, and finalized vs partial writer state without target mutation.
5. `replay-session --session <path.knapm>` validates first and then replays indexed trace chunks into the existing `session-replay` result shape without launching or injecting into a target.
6. Legacy `manifest.json` + JSONL session directories remain compatible with the same validate/replay commands.
7. `contracts/knapm-manifest.schema.json`, `contracts/knapm-index.schema.json`, and additive `session-info.schema.json` fields document the durable format.
8. `tools/session-validator/validate-session-fixtures.mjs` now covers valid `.knapm`, partial unfinalized `.knapm`, missing index, missing chunk, bad hash, non-contiguous batch sequence, and malformed trace event fixtures.
9. `tools/native-smoke/knapm-streaming-replay-smoke.ps1` verifies live x64 streaming `.knapm` write, hash-checked validation, indexed replay, safe cancellation, final counter consistency, and `agent_shutdown reason=self_disable`.

Current verified Phase 11J behavior:

1. New `.knapm` manifests written by `attach-session --stream-batches --write-knapm` include additive `owner`, `checkpoint`, and `recovery` sections.
2. `owner` records bounded-helper writer ownership, host/helper/writer PID, writer instance id, generation, heartbeat, lease timeout, and lease expiry.
3. `checkpoint` records the last durable chunk, batch, record, event id, manifest update, index update, and index consistency flag.
4. `recovery` records read-only classification state, reason, action, liveness booleans, lease expiry, and restart eligibility.
5. `validate-session --session <path.knapm>` classifies finalized, owned, stale, recovery-required, legacy, and malformed sessions without target mutation.
6. Phase 11I `.knapm` files without owner metadata remain valid as legacy-compatible sessions.
7. `session-info.schema.json` exposes additive recovery fields for Tauri/UI consumers.
8. `tools/session-validator/validate-session-fixtures.mjs` covers finalized owner metadata, legacy Phase 11I metadata, owned, stale, recovery-required, lease-expired, malformed owner, and all Phase 11I invalid fixture cases.
9. `tools/native-smoke/knapm-recovery-ownership-smoke.ps1` verifies finalized/owned/stale/recovery-required/lease-expired classification and proves validation does not terminate the live target.

Current verified Phase 11K behavior:

1. `knmon-native-helper.exe daemon-start --runtime-dir <dir>` starts a normal user-mode daemon heartbeat process with daemon PID, instance id, UTC heartbeat, file-registry control endpoint, and runtime directory status.
2. `daemon-start-session --pid <pid> --write-knapm <path.knapm>` starts a daemon-owned same-bitness attach session and returns after the first `persistent-daemon` ownership manifest write is confirmed.
3. Daemon-owned sessions keep using the existing same-bitness preflight, shared-memory API event transport, cancellation event, and `KnMonAgentStop` self-disable cleanup path.
4. `daemon-list-sessions` reports daemon-owned session id, operation id, target PID, daemon PID, helper/session PID, stream counters, `.knapm` path, and stop availability through additive native session fields.
5. `daemon-stop-session --session-id <id>` requests clean stop through the session cancellation event, waits bounded time for finalization, and returns cleanup evidence.
6. Daemon-owned `.knapm` manifests include `ownerKind=persistent-daemon`, daemon process id, daemon instance id, daemon heartbeat, control endpoint, checkpoint consistency, and final recovery `none/finalized/none` after clean stop.
7. Tauri exposes daemon start/status/list/start-session/stop-session wrappers, and the selected-target UI has a compact Daemon action plus daemon PID and `.knapm` path state.
8. `contracts/native-daemon-status.schema.json`, `native-session.schema.json`, `knapm-manifest.schema.json`, and `protocol-version.json` document the Phase 11K daemon fields and command boundary.
9. `tools/native-smoke/persistent-daemon-session-smoke.ps1` verifies daemon start, start-command return while daemon/session processes remain alive, streamed records, clean stop, hash-checked validation, replay, `persistent-daemon` owner metadata, and daemon shutdown.

Current verified Phase 11L behavior:

1. `knmon-native-helper.exe daemon-status --runtime-dir <dir>` reports `daemonState=stale` when a daemon state file exists but the recorded daemon PID is dead.
2. `daemon-audit --runtime-dir <dir>` returns daemon status plus session audit fields for daemon/session/target liveness, `.knapm` existence/validation, recovery state/reason/action, and `pruneEligible`.
3. `daemon-list-sessions` uses the same classifier and surfaces additive audit fields through `native-session.schema.json`.
4. `daemon-prune-stale --runtime-dir <dir> --dry-run` reports only prune-eligible daemon registry records without mutation.
5. `daemon-prune-stale --runtime-dir <dir>` deletes only stale daemon session record JSON files; it does not delete `.knapm` data, recover writers, unload agents, or mutate target processes.
6. `daemon-start-session` rejects duplicate live target PID, live session id, live `.knapm` path, and stale registry conflicts before launching a new attach helper.
7. Audit classifications cover `healthy`, `finalized`, `stale`, `daemon_crashed`, `writer_crashed`, `orphaned_agent_risk`, and `malformed`.
8. Tauri exposes daemon audit/prune wrappers, and the selected-target UI can show daemon liveness, writer/target liveness, audit recovery state, and prune eligibility for daemon sessions.
9. `tools/native-smoke/persistent-daemon-hardening-smoke.ps1` verifies healthy audit, duplicate rejection before mutation, stale daemon status, daemon crash classification, writer crash/orphan-risk evidence, dry-run/actual prune, active-record preservation, and finalized `.knapm` validate/replay after pruning.
10. `tools/session-validator/validate-session-fixtures.mjs` covers deterministic daemon registry fixtures for valid stale registry and malformed registry records.

Current verified Phase 11M behavior:

1. `attach-session --stream-batches --write-knapm <path.knapm> --knapm-compression zstd` writes `.jsonl.zst` chunks while preserving stdout JSONL streaming frames.
2. `daemon-start-session --write-knapm <path.knapm> --knapm-compression zstd` passes the same compression setting into the daemon-owned attach writer.
3. zstd support currently writes standards-compatible raw-block zstd frames without adding an external compression dependency or target hook-path work.
4. `index.json` stores per-chunk `compression`, stored `byteLength`, stored `sha256`, and zstd-required `uncompressedByteLength` plus `uncompressedSha256`.
5. `manifest.json` stores writer compression summary, compression algorithms, stored byte totals, and uncompressed byte totals.
6. `validate-session --session <path.knapm>` rejects unsupported compression as `unsupported_compression`, rejects corrupt zstd frames, verifies stored and uncompressed hashes, and preserves Phase 11I/11J/11K/11L uncompressed session compatibility.
7. `replay-session --session <path.knapm>` validates first, then decodes zstd chunks into the existing `session-replay` result without launching, injecting, attaching, repairing, or mutating targets.
8. `catalog-sessions --root <dir> [--catalog <path>] [--rebuild]` builds a deterministic JSON replay catalog from disk metadata and validation results.
9. `catalog-query --catalog <path> [--limit n] [--state state] [--target pid-or-text]` filters catalog rows without touching session directories.
10. `catalog-remove-missing --catalog <path> [--dry-run]` removes only missing catalog rows; it does not delete `.knapm` data, recover writers, unload agents, launch targets, or attach to targets.
11. Tauri exposes catalog build/query/remove wrappers, and the UI can refresh a compact catalog summary beside the session controls.
12. `contracts/knapm-manifest.schema.json`, `contracts/knapm-index.schema.json`, `contracts/session-info.schema.json`, `contracts/session-catalog.schema.json`, and `protocol-version.json` document the compression/catalog contract.
13. `tools/session-validator/validate-session-fixtures.mjs` covers valid zstd, corrupt zstd frame, bad uncompressed hash, and unsupported compression fixtures.
14. `tools/native-smoke/knapm-compression-catalog-smoke.ps1` verifies live zstd attach, daemon-owned zstd sessions, validate/replay, catalog build/query, dry-run missing detection, and actual missing-row pruning without deleting active `.knapm` data.

Next implementation focus:

1. Start Phase 12 with catalog-backed replay UX and high-event trace virtualization so large `.knapm` sessions stay usable without increasing target-side overhead.
2. Keep database-backed catalog indexing behind a separate scale review after the JSON catalog and replay picker contract are stable.
3. Keep automatic daemon crash recovery and orphaned active-agent repair behind a separate design review with explicit operator runbooks.
4. Keep Windows service mode, protected/PPL, cross-bitness, stealth/manual-map, and privilege-elevation paths as explicit non-goals unless a separate design review changes the boundary.

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
