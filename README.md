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
- Controlled same-bitness running-process attach foundation for already-running non-protected sample targets through `attach-capture`.
- Repeated same-process attach after self-disable, with loaded-agent state detection and no extra `LoadLibraryW` call for resettable disabled agents.
- Controller-side process-tree supervision foundation for deterministic sample child discovery and attach policy evaluation through `supervise-tree`.
- Tauri UI controls for selected native target bounded attach capture and process-tree supervision with explicit eligibility, audit output, self-disable/no-unload wording, and child attach summaries.
- Cancellation-safe operation ownership for bounded attach and process-tree helper commands through explicit operation ids, named cancellation events, Tauri operation state, and attach self-disable cleanup.
- Explicit controlled `NtCreateFile` capture from `ntdll.dll` with NTSTATUS return evidence.
- Deterministic x64/x86 agent lifecycle telemetry with hook restore evidence on shutdown.
- Same-bitness injection preflight for target/agent architecture and missing binary failures.
- Shared-memory binary API event transport for the controlled sample capture hot path.
- Reusable collector-side shared-memory transport reader used by bounded sample capture, attach capture, and process-tree child attach.
- Definition System V1 with JSON Schema validation, decode metadata registries, deterministic API/module id generation, Rohitab XML importer fixtures, and coverage reporting.
- Generated controller-side decoder metadata tables derived from API definitions.
- Durable helper-written sample sessions with manifest, audit, agent-event, and trace-event JSONL files.
- Session validation and replay without relaunching or reinjecting the sample target.
- Synthetic collector intake with deterministic bounded queue backpressure validation.
- Wave 2 metadata for registry, security, crypto, certificate, RPC, Winsock, WinINet, and WinHTTP APIs, with smoke-verified Winsock bootstrap/address-resolution, HKCU-safe registry, selected token query/privilege lookup, local RPCRT4 binding, CNG provider/RNG, `crypt32.dll` certificate-store/message-handle, `wininet.dll` session-handle, and `winhttp.dll` session-handle hook slices.

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
26. Definition System V1 schema validation, fixtures, decode alias metadata, enum/flag metadata, stable generated transport IDs, generated controller-side decoder tables, Rohitab XML importer prototype, and coverage report command.
27. Wave 2 metadata with stable IDs for `advapi32.dll`, `bcrypt.dll`, `crypt32.dll`, `rpcrt4.dll`, `ws2_32.dll`, `wininet.dll`, and `winhttp.dll`.
28. First live Wave 2 Winsock slice for `WSAStartup`, `WSACleanup`, `socket`, `closesocket`, `getaddrinfo`, `freeaddrinfo`, and `WSAGetLastError`.
29. Controlled Wave 2 registry slice for `RegOpenKeyExW`, `RegCreateKeyExW`, `RegQueryValueExW`, `RegSetValueExW`, `RegDeleteValueW`, and `RegCloseKey`.
30. Controlled Wave 2 RPCRT4 binding slice for `RpcStringBindingComposeW`, `RpcBindingFromStringBindingW`, `RpcStringFreeW`, and `RpcBindingFree`.
31. Controlled Wave 2 bcrypt CNG provider/RNG slice for `BCryptOpenAlgorithmProvider`, `BCryptCloseAlgorithmProvider`, `BCryptGetProperty`, and `BCryptGenRandom`.
32. Controlled Wave 2 crypt32 certificate-store/message-handle slice for `CertOpenStore`, `CertCloseStore`, `CryptMsgOpenToDecode`, and `CryptMsgClose`.
33. Controlled Wave 2 WinHTTP session-handle slice for `WinHttpOpen` and `WinHttpCloseHandle`.
34. Controlled Wave 2 WinINet session-handle slice for `InternetOpenW` and `InternetCloseHandle`.
35. Controlled Wave 2 advapi32 token query/privilege lookup slice for `OpenProcessToken` and `LookupPrivilegeValueW`.
36. Phase 11A controlled same-bitness `attach-capture --pid` for already-running non-protected sample targets, using remote `LoadLibraryW`, explicit attach config ABI, shared-memory event transport, and self-disable/no-unload detach evidence.
37. Phase 11B bounded `supervise-tree --pid` process-tree supervision for repository sample roots, with observe-only child discovery, attach-supported policy, x64/x86 smoke evidence, and cross-bitness child skip before mutation.
38. Phase 11C UI controls that let a selected native target run bounded `attach-capture` or `supervise-tree` with duration and child-policy controls, trace-table event mapping, audit output, process-tree nodes, policy decisions, child attach summaries, and explicit self-disable/no-unload detach evidence.
39. Phase 11D repeated same-process attach state detection, including loaded-agent query, `loaded_agent_reinitialize`, active/busy rejection before mutation, and x64/x86 smoke evidence.
40. Phase 11E collector reader foundation that factors shared-memory transport record validation, committed-record consumption, bounded drain, and transport metric snapshots into reusable collector-core code while preserving bounded helper command behavior.
41. Phase 11F cancellation-safe operation ownership for bounded attach and process-tree supervision, including helper `cancel-operation`, controller-side cancellation checks, attach cleanup evidence, Tauri operation state, and UI cancel controls.
42. Phase 11G durable native session ownership readiness, including additive session-state fields, helper `attach-session` JSONL frames, host-side threaded shared-transport reader wrapper, stale/recovery-required session classification, Tauri session state, and UI stop controls.
43. Phase 11H bounded UI streaming session batches, including `attach-session --stream-batches`, `trace_batch` JSONL frames, Tauri bounded batch queues, cursor-based UI batch reads, target-vs-host drop accounting, and replay chunk boundary metadata.

Not implemented yet:

1. Broad arbitrary process attach beyond the explicit Phase 11A same-bitness, non-protected `attach-capture` boundary.
2. Unbounded continuous streaming capture for arbitrary long-running targets.
3. Persistent long-running attach/detach daemon supervision and durable restart/recovery.
4. Broad Wave 2/3/4 system DLL hooks beyond the current Wave 1 foundation and selected Winsock, registry, advapi32 token query/privilege lookup, RPCRT4 binding, bcrypt CNG provider/RNG, crypt32 certificate-store/message-handle, WinHTTP session-handle, and WinINet session-handle slices.
5. Breakpoint mutation.
6. COM monitoring.
7. Kernel-mode helper.
8. Compressed `.knapm` container chunks and replay indexes.

## Current Native Capture Snapshot

Current native capture is bounded to controlled same-bitness sample-target flows:

1. `knmon-native-helper.exe capture-sample` launches `knmon-sample-fileio.exe` suspended.
2. The controller runs same-bitness preflight for target and agent binaries before remote mutation.
3. The controller queues an early-bird APC to load `knmon-agent64.dll` in x64 builds or `knmon-agent32.dll` in Win32 builds.
4. The controller creates a bounded shared-memory event transport and passes its mapping name to the agent.
5. The agent sends low-volume `agent_hello` and lifecycle messages through the named pipe, inventories loaded modules from the PEB loader list, sweeps eligible module IATs, and writes API call records into shared memory.
6. The controller owns capture lifetime while a reusable collector-core reader validates and drains committed shared-memory records; the controller normalizes them outside the target process into schema-versioned `api_call` events and returns one structured `capture-result` JSON object with transport metrics.
7. On target shutdown, the agent disables new hook events, restores patched IAT slots where possible, and emits `agent_shutdown` with `reason`, lifecycle state, hook counts, and dropped-event count.
8. `capture-sample --write-session <dir>` writes `manifest.json`, `audit.jsonl`, `agent-events.jsonl`, and `trace-events.jsonl`.
9. `replay-session --session <dir>` returns trace-compatible events without launching a target or loading an agent.
10. The Tauri commands map captured or replayed File I/O events into the React trace table.

The Phase 11A attach path is separate from launch-time early-bird configuration:

1. `knmon-sample-fileio.exe --attach-loop` starts before injection and emits bounded deterministic File I/O calls.
2. `knmon-native-helper.exe attach-capture --pid <pid>` runs same-bitness, process-existence, agent-architecture, access, and protected-process preflight before remote mutation.
3. The controller creates the named pipe and shared-memory transport, then uses remote `LoadLibraryW` only for a supported non-protected same-bitness target.
4. The agent receives pipe and transport names through a versioned `KnMonAttachConfigV1` export call instead of relying on launch-time environment variables.
5. Detach for Phase 11A means remote `KnMonAgentStop`, hook restore, dropped-event accounting, and `agent_shutdown reason=self_disable`; the DLL remains loaded by design.

The Phase 11B process-tree path is controller/helper-side supervision:

1. `knmon-sample-fileio.exe --spawn-child-loop` starts as an already-running root and creates deterministic child sample processes.
2. `knmon-native-helper.exe supervise-tree --pid <pid> --child-policy observe` snapshots the root tree, records child metadata, and classifies attach eligibility without remote mutation.
3. `--child-policy attach-supported` only attaches same-bitness repository sample children that pass policy evaluation, reusing the Phase 11A attach/self-disable path.
4. Cross-bitness, protected, missing, access-denied, or unsupported children are reported as typed policy decisions before mutation.
5. Process-tree discovery runs in the controller/helper path and does not add agent-side polling or hook fast-path work.

The Phase 11C UI path exposes these bounded helper commands without changing their lifecycle contract:

1. In Tauri desktop mode, select `Native` target source, select a target row, then run `Attach Capture` or `Supervise`.
2. The selected-target panel shows PID, image, architecture, status, and the UI eligibility reason before enabling mutation-backed actions.
3. Attach capture calls `attach-capture --pid <pid> --duration-ms <ms>` through Tauri, maps captured `api_call` events into the trace table, and shows `bounded-native-attach`, `remote LoadLibraryW`, `self-disable-no-unload`, dropped counters, subsystem/operation/error, and `agent_shutdown` hook restore evidence.
4. Process-tree supervision calls `supervise-tree --pid <pid> --duration-ms <ms> --child-policy observe|attach-supported`, renders process nodes, policy decisions, mutation-attempt state, audit events, and child attach summaries.
5. This UI does not keep a persistent attached/live state after the bounded helper returns. A completed attach means the agent self-disabled and the DLL remains loaded by design.

The Phase 11D repeated attach path keeps the same bounded command model:

1. Before attach mutation, the controller checks whether the expected same-bitness agent DLL is already loaded in the target process.
2. `KnMonAgentQueryState` reports lifecycle, resettable state, hook counts, ABI version, and active/busy evidence without adding agent-side polling or hook-path work.
3. First attach uses `attachState=not_loaded` and `attachStrategy=load_library_initialize`.
4. A later attach to a self-disabled/no-unload target uses `attachState=loaded_disabled` and `attachStrategy=loaded_agent_reinitialize`; it skips another blind `LoadLibraryW` call and invokes `KnMonAgentInitialize` from the loaded module base with a fresh operation id, pipe, and shared transport mapping.
5. Active or busy loaded agents are rejected with typed `already_instrumented` evidence before pipe/transport setup or remote mutation.

The Phase 11E collector reader path is a pull-based refactor, not a daemon:

1. `knmon-collector-core` owns `SharedTransportReader`, which validates transport header magic, ABI, sizes, architecture, operation id, and capacity before consuming records.
2. The reader drains only committed records whose sequence matches the current consumer sequence. If the producer is ahead but the next record is not committed, it stops without skipping or freeing partial records.
3. Controlled sample capture, `attach-capture`, and process-tree `attach-supported` child attach use this reader boundary while the controller still owns process lifetime, pipe reads, stop/self-disable, cleanup, and JSON normalization.
4. `knmon-collector.exe smoke-shared-transport-reader` verifies FIFO consumption, partial commit stop behavior, and bounded max-drain behavior without launching or injecting a process.

The Phase 11F operation ownership path keeps cancellation outside the target hot path:

1. `attach-capture` and `supervise-tree` accept explicit operation ids and create local named cancellation events derived from those ids.
2. `knmon-native-helper.exe cancel-operation --operation-id <id>` sets the cancellation event; it does not kill the active helper or talk to the injected agent directly.
3. If attach cancellation is observed after `KnMonAgentInitialize`, the controller requests `KnMonAgentStop`, drains shared transport and pipe shutdown evidence, and returns `operationState=cancelled` only when self-disable cleanup is proven.
4. Tauri tracks native helper operations in an operation registry, exposes operation state to the UI, and uses `cancel-operation` before any timeout fallback.
5. The UI can show running/cancel-requested operation state and request cancellation without claiming DLL unload or persistent live attach.

The Phase 11G session ownership path prepares long-running capture without creating a daemon:

1. Capture and process-tree results accept additive `sessionId`, `sessionState`, owner/helper PID, timestamp, cancellation event, streamed-record, stale reason, and recovery action fields.
2. `knmon-native-helper.exe attach-session --pid <pid> --session-id <id> --operation-id <id>` emits JSONL `session_started` and `session_state` frames before final capture JSON, so host-side ownership is observable before command completion.
3. `knmon-collector-core` provides `ThreadedSharedTransportReader`, a host-side wrapper around the existing committed-record reader. It does not add target hook-path work or agent-side polling.
4. `classify-session --session-record <path>` classifies stale host-side session metadata as `stale` or `recovery_required` without remote mutation.
5. Tauri exposes native session state and safe stop commands, and the selected-target UI shows session state, streamed record count, stale reason, and stop availability without claiming DLL unload or persistent broad daemon attach.

The Phase 11H bounded streaming path makes selected-target traces visible before final helper completion:

1. `knmon-native-helper.exe attach-session --pid <pid> --stream-batches --batch-size <n>` emits `trace_batch` JSONL frames between `session_state` and final `capture_result`.
2. Each batch carries contiguous `batchSequence`, monotonic record sequence range, streamed-record count, target transport dropped records, host dropped UI batch count, and normalized `api_call` events.
3. Tauri starts the helper in the background, stores recent batches in a bounded in-process queue, exposes cursor-based batch reads, and drops oldest host-side batches if the UI falls behind.
4. The selected-target UI can start a bounded stream, append streamed rows to the existing trace table, display target-vs-host drops, and stop through the existing cancellation event path.
5. This is still a bounded helper/session workflow. It is not a persistent daemon, DLL unload support, cross-bitness attach, protected-process bypass, or returned-pointer instrumentation.

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
10. `WSAStartup`
11. `WSACleanup`
12. `socket`
13. `closesocket`
14. `getaddrinfo`
15. `freeaddrinfo`
16. `WSAGetLastError`
17. `RegOpenKeyExW`
18. `RegCreateKeyExW`
19. `RegQueryValueExW`
20. `RegSetValueExW`
21. `RegDeleteValueW`
22. `RegCloseKey`
23. `OpenProcessToken`
24. `LookupPrivilegeValueW`
25. `RpcStringBindingComposeW`
26. `RpcBindingFromStringBindingW`
27. `RpcStringFreeW`
28. `RpcBindingFree`
29. `BCryptOpenAlgorithmProvider`
30. `BCryptCloseAlgorithmProvider`
31. `BCryptGetProperty`
32. `BCryptGenRandom`
33. `CertOpenStore`
34. `CertCloseStore`
35. `CryptMsgOpenToDecode`
36. `CryptMsgClose`
37. `InternetOpenW`
38. `InternetCloseHandle`
39. `WinHttpOpen`
40. `WinHttpCloseHandle`

The current smoke path captures real sample-target File I/O events, a deterministic `LoadLibraryW("knmon-dynamic-probe.dll")` loader event, and resolver calls for `GetProcAddress` and `LdrGetProcedureAddress` through `transportMode=shared-memory`, with `droppedEvents=0` on the healthy path. `ReadFile` and `WriteFile` include bounded 16-byte buffer previews. `NtCreateFile` is captured as an explicit `ntdll.dll` event with `returnValue` carrying the NTSTATUS hex value and a bounded `ObjectAttributes` object-name decode. Resolver events include bounded function-name evidence and return/status values, but calls made through resolver-returned function pointers are not automatically instrumented. Backpressure can be forced with `KNMON_TRANSPORT_CAPACITY`; the current bounded ring uses drop-newest accounting and reports transport produced/consumed/dropped records plus min/average/max hook overhead estimates.

The live Wave 2 slices are intentionally narrow: `ws2_32.dll` Winsock startup, cleanup, socket create/close, localhost address resolution, address-info free, and Winsock error query calls are captured from the controlled sample path; `advapi32.dll` registry open/create/query/set/delete/close calls are captured through HKCU-only sample operations; `advapi32.dll` token query/privilege lookup calls are limited to current-process `TOKEN_QUERY` and `SeChangeNotifyPrivilege` LUID lookup evidence without token mutation, token privilege arrays, SID/group/ACL/security descriptor, credential, or service-control capture; `rpcrt4.dll` local string-binding compose/from/free calls are captured through a no-server `ncalrpc` sample lifecycle; `bcrypt.dll` provider open/close, algorithm-name property query, and RNG generation calls are captured without copying random, key, plaintext, ciphertext, IV, or hash input bytes; `crypt32.dll` certificate-store/message-handle open/close calls are captured without copying certificate blobs, private keys, cryptographic message payloads, random bytes, keys, plaintext, ciphertext, IVs, or hash input bytes; `winhttp.dll` session open/close calls are captured without making network requests or copying URLs, headers, bodies, cookies, credentials, proxy credentials, or payload bytes; and `wininet.dll` session open/close calls are captured without making network requests or copying URLs, headers, bodies, cookies, credentials, proxy credentials, or payload bytes. High-volume network payload hooks such as `send`, `recv`, `sendto`, `recvfrom`, WinHTTP request/transfer/header APIs, WinINet connection/request/transfer/option APIs, `AdjustTokenPrivileges`, service-control APIs, and security descriptor/SID/credential capture remain definition-only until separate transport ABI and overhead reviews.

Healthy same-bitness x64 and x86 lifecycle evidence currently reports at least the six required File I/O hooks, `restoredHooks=installedHooks`, and `failedHooks=0`. Controlled launch shutdown reports `reason=process_detach`; attach self-disable reports `reason=self_disable`.

Wave 2 metadata is committed for 77 additional APIs across `advapi32.dll`, `bcrypt.dll`, `crypt32.dll`, `rpcrt4.dll`, `ws2_32.dll`, `wininet.dll`, and `winhttp.dll`. Seven selected `ws2_32.dll` APIs, six selected `advapi32.dll` registry APIs, two selected `advapi32.dll` token query/privilege lookup APIs, four selected `rpcrt4.dll` RPC binding APIs, four selected `bcrypt.dll` CNG provider/RNG APIs, four selected `crypt32.dll` certificate-store/message-handle APIs, two selected `wininet.dll` session-handle APIs, and two selected `winhttp.dll` session-handle APIs are now smoke-verified IAT hooks; the remaining Wave 2 APIs stay `definition_only`. The current definition coverage report totals 90 APIs: 46 `definition_only`, 4 `hooked`, and 40 `smoke_verified`.

Generated decoder metadata is now emitted for controller-side rendering. The agent still writes compact shared-memory records and does not parse definitions, while the controller uses generated metadata for API/module names, tags, argument labels, decode aliases, and capture timing.

## Safety Boundary

The native-capture foundation supports controlled launch-time early-bird APC loading into the repository sample target and a bounded Phase 11A attach path for already-running non-protected sample targets through explicit `attach-capture --pid`. Current live capture is bounded to same-bitness helper/target/agent paths: x64 helper to x64 target with `knmon-agent64.dll`, or Win32 helper to x86 target with `knmon-agent32.dll`.

Cross-bitness injection, protected-process bypass, manual mapping, stealth loading, and broad inline detours remain out of scope until separately reviewed.

Future dangerous operations such as broad arbitrary attach, skip-call, forced return values, or memory editing must be explicit, audited, and isolated behind versioned controller commands.

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
build\native\Debug\knmon-native-helper.exe attach-capture --pid <pid> --duration-ms 3000
build\native\Debug\knmon-native-helper.exe supervise-tree --pid <pid> --duration-ms 3000 --child-policy observe
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
powershell -ExecutionPolicy Bypass -File tools\native-smoke\generated-decoder-tables-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave2-advapi32-registry-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave2-advapi32-token-query-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave2-winsock-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave2-rpcrt4-binding-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave2-bcrypt-cng-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave2-crypt32-certmsg-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave2-winhttp-session-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave2-wininet-session-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\injection-preflight-negative-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\controlled-attach-capture-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\attach-preflight-negative-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\process-tree-supervision-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\process-tree-attach-supported-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\repeated-attach-state-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\cancellation-operation-state-smoke.ps1
build\native\Debug\knmon-collector.exe smoke-backpressure --capacity 4 --events 10
build\native\Debug\knmon-collector.exe smoke-shared-transport-reader --capacity 4 --records 3
powershell -ExecutionPolicy Bypass -File tools\native-smoke\collector-backpressure-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\shared-transport-reader-smoke.ps1
```

Run optional Win32/x86 smoke after building `build/native-win32`:

```powershell
build\native-win32\Debug\knmon-native-helper.exe launch-sample
build\native-win32\Debug\knmon-native-helper.exe capture-sample
powershell -ExecutionPolicy Bypass -File tools\native-smoke\x86-capture-sample-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\controlled-attach-capture-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\process-tree-supervision-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\process-tree-attach-supported-smoke.ps1
```

`launch-sample` creates `knmon-sample-fileio.exe` suspended, queues an early-bird APC to load the same-bitness agent DLL, resumes the primary thread, and waits for an agent HELLO handshake.

`capture-sample` uses the same controlled launch path, keeps the named pipe open for low-volume control/lifecycle messages, inventories loaded modules, installs same-bitness IAT hooks for the stable File I/O, loader-aware Wave 1, resolver call set, selected registry slice, selected advapi32 token query/privilege lookup slice, selected Winsock slice, selected RPCRT4 binding slice, selected bcrypt CNG provider/RNG slice, selected crypt32 certificate-store/message-handle slice, selected WinHTTP session-handle slice, and selected WinINet session-handle slice, drains API calls through the collector-core shared transport reader, and returns schema-versioned `api_call` events plus dropped-event accounting.

`attach-capture` attaches to an already-running same-bitness non-protected sample target, passes attach configuration through `KnMonAttachConfigV1`, uses the same shared-memory transport for API records, and detaches by self-disabling hooks without unloading the DLL.

`supervise-tree` snapshots an already-running sample root's process tree, returns `processNodes`, `policyDecisions`, and audit events, and supports `observe` and `attach-supported` child policies. Observe policy never mutates children. Attach-supported policy only attaches same-bitness repository sample children and embeds the Phase 11A child attach result.

The Tauri UI exposes the same bounded attach and process-tree commands in the selected native target panel. Browser/Vite mode keeps these actions blocked because native attach requires the Tauri desktop runtime and the built helper executable.

The repeated smoke script verifies five consecutive controlled x64 captures, the stable File I/O API set, zero dropped events, and hook restore counts. The `NtCreateFile` smoke verifies the `ntdll.dll` module, NTSTATUS return format, decoded sample object path, shared-memory transport mode, and clean hook restore. The shared-memory transport smoke verifies healthy x64 transport metrics and hook overhead. The shared-memory backpressure smoke forces a tiny ring capacity and verifies non-blocking dropped-event accounting. The shared transport reader smoke verifies FIFO drain, partial committed-record stop behavior, and bounded max-drain behavior. The repeated attach state smoke verifies x64/x86 same-process reattach after self-disable, first-load vs loaded-agent reinitialize strategy evidence, absence of a second `LoadLibraryW`, fresh shared-memory transport metrics, and active loaded-agent rejection before mutation. The cancellation operation-state smoke verifies x64 attach cancellation through `cancel-operation`, `ERROR_CANCELLED`, self-disable cleanup evidence, post-cancel loaded-agent reattach, and process-tree observe cancellation without child mutation. The threaded collector/session smoke verifies host-side threaded committed-record drain, `attach-session` JSONL running-state visibility, and safe stop cleanup evidence. The streaming session UI batch smoke verifies non-empty `trace_batch` frames, monotonic batch/record sequences, final counter consistency, safe cancellation, and `agent_shutdown reason=self_disable`. The session recovery-state smoke verifies stale and recovery-required host-side classification without target mutation. The loader-aware smokes verify PEB module inventory, eligible-module IAT sweep evidence, `LoadLibraryW` capture, dynamic-load re-hooking, and post-load `knmon-dynamic-probe.dll` API evidence. The resolver monitoring smoke verifies `GetProcAddress` and `LdrGetProcedureAddress` call visibility, resolver tags, bounded `KnMonDynamicProbe` argument evidence, and clean hook restore. The generated decoder tables smoke verifies generated metadata freshness plus controller-rendered API family/category and argument decode metadata. The Wave 2 registry smoke verifies the selected `advapi32.dll` HKCU registry API records, generated registry metadata, key/value evidence, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 2 advapi32 token query smoke verifies `OpenProcessToken` and `LookupPrivilegeValueW` records, generated security metadata, `TOKEN_QUERY`, token-handle, privilege-name, and LUID evidence, absence of token mutation/service-control/credential/byte-preview evidence, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 2 Winsock smoke verifies the selected `ws2_32.dll` bootstrap/address-resolution API records, generated network metadata, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 2 RPCRT4 smoke verifies the selected local RPC binding lifecycle records, generated RPC metadata, `ncalrpc`/`KNMonRpcSample` evidence, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 2 bcrypt smoke verifies selected CNG provider/RNG records, generated crypto metadata, `RNG`/`AlgorithmName` evidence, absence of generated random byte previews, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 2 crypt32 smoke verifies selected certificate-store/message-handle records, generated certificate/message metadata, memory-store provider and X509/PKCS7 encoding evidence, absence of certificate blob/private-key/message-payload previews, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 2 WinHTTP smoke verifies selected session open/close records, generated HTTP metadata, sample user-agent/no-proxy evidence, absence of URL/header/body/cookie/credential/proxy-credential/payload previews, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 2 WinINet smoke verifies selected session open/close records, generated internet metadata, sample user-agent/direct-access evidence, absence of URL/header/body/cookie/credential/proxy-credential/payload previews, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The x86 smoke verifies the same File I/O API set, loader evidence, resolver evidence, selected registry, advapi32 token query, Winsock, RPCRT4, bcrypt, crypt32, WinHTTP, and WinINet evidence, shared-memory transport, and hook lifecycle from a Win32 helper/target/agent build. The launch preflight negative smoke verifies missing target, missing agent, and available architecture mismatch failures before remote mutation. The attach smoke verifies x64 and x86 already-running sample attach, `remote LoadLibraryW`, `self-disable-no-unload`, zero healthy-path drops, required File I/O APIs, and hook restore evidence. The attach preflight negative smoke verifies missing PID, PID 0/4, helper self, missing agent, agent mismatch, and cross-bitness target mismatch cases before remote mutation. The process-tree smoke verifies x64/x86 observe policy child discovery, missing/root PID failures, and cross-bitness child skip before mutation. The process-tree attach-supported smoke verifies x64/x86 child attach through Phase 11A, required File I/O APIs, zero drops, and self-disable hook restore.

`capture-sample --write-session` persists the bounded capture into a replayable session directory. Session validation checks manifest architecture, HELLO architecture/version evidence, dropped-event accounting, shutdown hook restore counts, and trace rows before replay returns data from disk without relaunching the target.

`knmon-collector.exe smoke-backpressure` exercises the synthetic collector intake path without injection. The current policy is `drop-newest`; with capacity 4 and 10 events, the expected retained FIFO sequence is `1,2,3,4` and `droppedEvents=6`.

`knmon-collector.exe smoke-shared-transport-reader` exercises the collector-core shared transport reader without injection. It validates header checks, committed sequence FIFO drain, partial-record stop behavior, bounded max-drain behavior, transport metrics, and hook-overhead aggregation.

Validate API definitions:

```powershell
npm run defs:generate
npm run defs:validate
npm run defs:coverage
```

`defs:generate` rewrites deterministic definition ID artifacts from `definitions/metadata/id-assignments.json`:

1. `generated/definition-ids.json`
2. `native/knmon-common/include/knmon/common/GeneratedApiIds.h`
3. `generated/definition-decoder-tables.json`
4. `native/knmon-common/include/knmon/common/GeneratedApiMetadata.h`

`defs:validate` runs JSON Schema validation for committed definition JSON files, semantic checks for decode aliases, enum/flag references, length expressions, duplicate APIs, stable ID assignments, generated decoder table freshness, definition fixtures, the Rohitab importer fixture, and a coverage-report bucket check. `defs:decoder-tables` is a focused generated-table check. `defs:coverage` prints a deterministic Markdown report that separates `definition_only`, `hooked`, and `smoke_verified` API coverage.

The current committed definition catalog includes 90 APIs. Only the selected Winsock bootstrap/address-resolution APIs, selected HKCU-safe registry APIs, selected advapi32 token query/privilege lookup APIs, selected local RPCRT4 binding APIs, selected bcrypt CNG provider/RNG APIs, selected crypt32 certificate-store/message-handle APIs, selected WinHTTP session-handle APIs, and selected WinINet session-handle APIs have moved to `iat` and `smoke_verified`; remaining Wave 2 APIs are intentionally marked `definition_only` until hook ABI expansion and performance gates are reviewed.

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
