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
- Wave 2/3 metadata for registry, security, crypto, certificate, RPC, Winsock, WinINet, WinHTTP, User32, GDI32, PSAPI, Version, Shell, OLE32, COMBASE-backed WinRT, and KERNEL32 metadata APIs, with smoke-verified Winsock bootstrap/address-resolution, HKCU-safe registry, selected token query/privilege lookup, local RPCRT4 binding and UUID helper, CNG provider/RNG, `crypt32.dll` certificate-store/message-handle, `wininet.dll` session-handle, `winhttp.dll` session-handle, low-payload User32/GDI32 metadata, low-payload PSAPI module-query, low-payload Version resource metadata, allowlisted Shell known-folder metadata, OLE32 COM lifecycle/GUID helper, API-set WinRT lifecycle, KERNEL32 memory protection, KERNEL32 thread lifecycle, KERNEL32 event synchronization, KERNEL32 mutex/semaphore synchronization, KERNEL32 file-mapping, and KERNEL32 process/thread identity hook slices.
- Host-side `.knapm` replay catalog indexing through a local `winsqlite3` database cache that never launches, injects, repairs, or deletes replay data.

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
44. Phase 11I durable `.knapm` chunk writer and indexed replay, including `attach-session --stream-batches --write-knapm`, one chunk per non-empty `trace_batch`, hash-checked `index.json`, finalized/partial validation, replay without target launch, and legacy session compatibility.
45. Phase 11J `.knapm` restart/recovery ownership contract, including owner/checkpoint/recovery manifest sections, heartbeat/lease metadata, finalized/owned/stale/recovery-required/malformed classification, and read-only validate/replay boundaries.
46. Phase 11K host-side persistent daemon supervision foundation, including `daemon-start`, `daemon-start-session`, `daemon-list-sessions`, `daemon-stop-session`, `persistent-daemon` `.knapm` owner metadata, Tauri daemon controls, and smoke-proven clean stop/validate/replay.
47. Phase 11L daemon supervision hardening, including read-only `daemon-audit`, stale registry `daemon-prune-stale`, duplicate target/session/path arbitration before attach mutation, daemon-crash/writer-crash/orphan-risk classification, additive Tauri/UI audit fields, and stale daemon status visibility.
48. Phase 11M `.knapm` compression and host-side replay catalog support, including `--knapm-compression none|zstd`, zstd raw-block frame validation/replay, stored and uncompressed chunk integrity metadata, read-only catalog build/query, catalog missing-row pruning, Tauri catalog wrappers, UI catalog visibility, and regression smoke coverage.
49. Phase 12A catalog-backed replay UX and virtualized trace rendering, including catalog rebuild/query/state-target-limit filters, missing-row dry-run/prune controls, explicit per-row `.knapm` replay by path, replay source/status output, and bounded DOM trace rows while preserving full-session JSONL export.
50. Phase 12B trace query builder and error-focused view, including structured all/any query clauses over trace fields, invalid-clause handling, error/decode/slow-call issue groups, click-to-filter issue triage, and focused UI query validator coverage.
51. Phase 12C thread and timeline views, including deterministic UI-side thread grouping, time-bucket timeline summaries, click-to-query narrowing, relative-time query clauses, representative samples, bounded summary DOM, and focused trace-view validator coverage.
52. Phase 12D rule-based trace highlighting, including deterministic built-in highlight rules for error returns, decode failures, slow calls, coverage hints, and metadata quality, bounded rule summaries, row severity markers, selected-event rule reasons, click-to-query narrowing, and focused highlight validator coverage.
53. Phase 13A database-backed replay catalog index, including versioned `winsqlite3` metadata storage, native `catalog-index-*` commands, Tauri wrappers, compact UI DB index controls, additive catalog contract fields, and focused smoke coverage for build/query/prune/error handling.
54. Phase 13B low-payload Wave 3 User32/GDI32 metadata slice for `GetSystemMetrics`, `GetDesktopWindow`, `GetForegroundWindow`, `GetWindowThreadProcessId`, `CreateCompatibleDC`, `GetDeviceCaps`, and `DeleteDC`, with generated metadata, shared-memory records, no text/pixel/input/clipboard payload capture, and focused smoke coverage.
55. Phase 13C low-payload Wave 3 PSAPI module-query slice for `EnumProcessModules`, `GetModuleInformation`, `GetModuleBaseNameW`, and `GetModuleFileNameExW`, using PSAPI v1 `psapi.dll` imports, generated metadata, shared-memory records, bounded module handle/MODULEINFO/name/path evidence, no module memory/PE/file/hash/signature payload capture, and focused smoke coverage.
56. Phase 13D low-payload Wave 3 Version resource metadata slice for `GetFileVersionInfoSizeW`, `GetFileVersionInfoW`, and `VerQueryValueW`, with generated metadata, shared-memory records, bounded path/size/fixed-file-info/translation evidence, no raw resource/string-table/PE/file/hash/signature payload capture, and focused smoke coverage.
57. Phase 13E low-payload Wave 3 Shell known-folder metadata slice for `SHGetKnownFolderPath` and `SHGetSpecialFolderPathW`, with generated metadata, shared-memory records, bounded GUID/CSIDL/flag/handle/pointer evidence, allowlisted Windows/System/ProgramFiles path evidence only, non-allowlisted path suppression, no ShellExecute/PIDL/file-metadata/user-folder/environment payload capture, and focused smoke coverage.
58. Phase 13F low-payload Wave 3 OLE32 COM lifecycle metadata slice for `CoInitializeEx`, `CoUninitialize`, `CoCreateGuid`, and `StringFromGUID2`, with generated metadata, shared-memory records, bounded COM init flag, pointer, HRESULT/int return, GUID, and GUID-string evidence, no COM activation/object/marshaling/clipboard/drag-drop/storage payload capture, and focused smoke coverage.
59. Phase 13G low-payload Wave 3 RPCRT4 UUID helper metadata slice for `UuidCreate`, `UuidToStringW`, and `UuidFromStringW`, with `UuidCreate` promoted at stable API ID `58`, new generated IDs `111` and `112`, shared-memory records, bounded UUID value/string evidence, no RPC endpoint/auth/network payload capture, and focused smoke coverage.
60. Phase 13H low-payload Wave 3 COMBASE-backed WinRT lifecycle metadata slice for `RoInitialize`, `RoUninitialize`, and `RoGetApartmentIdentifier` through the observed `api-ms-win-core-winrt-l1-1-0.dll` import provider, with stable IDs `113` through `115`, bounded init type/HRESULT/void/apartment-id numeric evidence, no activation/HSTRING/runtime-class/restricted-error-info/COM object/marshaling payload capture, and focused smoke coverage.
61. Phase 13I low-payload Wave 3 KERNEL32 memory allocation/protection/query metadata slice for `VirtualAlloc`, `VirtualFree`, `VirtualProtect`, and `VirtualQuery`, with stable IDs `116` through `119`, bounded pointer/size/flag/old-protection/`MEMORY_BASIC_INFORMATION` evidence, no memory-content/remote-memory/injection payload capture, and focused smoke coverage.
62. Phase 13J low-payload Wave 3 KERNEL32 current-process thread lifecycle metadata slice for `CreateThread`, `OpenThread`, `WaitForSingleObject`, and `GetExitCodeThread`, with stable IDs `120` through `123`, bounded handle/thread-id/wait/exit-code evidence, no remote-thread/APC/context/stack payload capture, and focused smoke coverage.
63. Phase 13K low-payload Wave 3 KERNEL32 current-process event synchronization metadata slice for `CreateEventW`, `OpenEventW`, `SetEvent`, `ResetEvent`, and `WaitForSingleObjectEx`, with stable IDs `124` through `128`, bounded event-handle/BOOL/access/wait evidence, no event-name/object-namespace/security-descriptor/wait-chain/APC payload capture, and focused smoke coverage.
64. Phase 13L low-payload Wave 3 KERNEL32 current-process mutex/semaphore synchronization metadata slice for `CreateMutexW`, `OpenMutexW`, `ReleaseMutex`, `CreateSemaphoreW`, `OpenSemaphoreW`, `ReleaseSemaphore`, and `WaitForMultipleObjectsEx`, with stable IDs `129` through `135`, bounded handle/BOOL/access/count/multi-wait evidence, no object-name/object-namespace/security-descriptor/handle-array/wait-chain/APC payload capture, and focused smoke coverage.
65. Phase 13M low-payload Wave 3 KERNEL32 current-process file-mapping metadata slice for `CreateFileMappingW`, `OpenFileMappingW`, `MapViewOfFile`, and `UnmapViewOfFile`, with stable IDs `136` through `139`, bounded handle/pointer/protection/access/size/offset/view evidence, no mapping-name/object-namespace/mapped-memory/security/PE/file/hash/credential payload capture, and focused x64/x86 smoke coverage.
66. Phase 13N low-payload Wave 3 KERNEL32 process/thread identity metadata slice for `GetCurrentProcess`, `GetCurrentProcessId`, `GetCurrentThread`, `GetCurrentThreadId`, `GetProcessId`, and `GetThreadId`, with stable IDs `140` through `145`, bounded pseudo/current handle and PID/TID evidence, no process enumeration, command-line, environment, token/security, remote-memory, remote-thread, stack, module, file, hash, or byte-preview payload capture, and focused x64/x86 smoke coverage.

Not implemented yet:

1. Broad arbitrary process attach beyond the explicit Phase 11A same-bitness, non-protected `attach-capture` boundary.
2. Unbounded continuous streaming capture for arbitrary long-running targets.
3. Windows service installation, boot-time autostart, automatic daemon crash recovery, or orphaned active-agent repair.
4. Broad Wave 2/3/4 system DLL hooks beyond the current Wave 1 foundation and selected Winsock, registry, advapi32 token query/privilege lookup, RPCRT4 binding/UUID helper, bcrypt CNG provider/RNG, crypt32 certificate-store/message-handle, WinHTTP session-handle, WinINet session-handle, low-payload User32/GDI32 metadata, low-payload PSAPI module-query, low-payload Version resource metadata, allowlisted Shell known-folder metadata, OLE32 COM lifecycle/GUID helper, COMBASE-backed WinRT lifecycle, KERNEL32 memory protection, KERNEL32 thread lifecycle, KERNEL32 event synchronization, KERNEL32 mutex/semaphore synchronization, KERNEL32 file-mapping, and KERNEL32 process/thread identity metadata slices.
5. Breakpoint mutation.
6. Broad COM/WinRT activation, object, interface, vtable, marshaling, storage, HSTRING, runtime-class, or restricted-error-info monitoring beyond the current lifecycle/GUID slices.
7. Kernel-mode helper.
8. Event-level trace payload indexing and full-text replay search beyond session metadata catalogs.

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

The Phase 11I durable `.knapm` path persists bounded streaming batches without adding target hot-path work:

1. `knmon-native-helper.exe attach-session --pid <pid> --stream-batches --write-knapm <path.knapm>` writes an inspectable directory-backed `.knapm` container while still emitting JSONL frames to stdout.
2. Each non-empty `trace_batch` is finalized as `chunks/trace-000NNN.jsonl` with an `index.json` entry containing batch sequence, record range, event-id range, byte length, and SHA-256.
3. The manifest includes `owner`, `checkpoint`, and `recovery` sections that record bounded-helper ownership, writer instance/lease heartbeat, last durable chunk/index checkpoint, and restart eligibility.
4. `validate-session --session <path.knapm>` verifies manifest/index identity, chunk hashes, event counts, batch contiguity, record monotonicity, finalized vs partial writer state, final cleanup evidence, and read-only recovery classification without launching or mutating the target.
5. `replay-session --session <path.knapm>` validates first, then replays indexed trace chunks into the existing `session-replay` result shape without injecting or launching a process.
6. Legacy `manifest.json` + JSONL session directories and Phase 11I `.knapm` manifests without owner metadata remain supported by the same validate/replay commands.

The Phase 11J/11K/11L supervision path separates restart ownership from replay validation and registry cleanup:

1. Phase 11J adds read-only owner/checkpoint/recovery classification for finalized, owned, stale, recovery-required, legacy, and malformed `.knapm` sessions.
2. Phase 11K adds a normal user-mode daemon foundation driven by `daemon-start`, `daemon-status`, `daemon-start-session`, `daemon-list-sessions`, `daemon-stop-session`, and `daemon-stop`.
3. Phase 11L adds `daemon-audit --runtime-dir <dir>` and `daemon-prune-stale --runtime-dir <dir> [--dry-run]` for read-only liveness classification and explicit stale registry cleanup.
4. `daemon-start-session --pid <pid> --write-knapm <path.knapm>` rejects duplicate live target PID, live session id, live `.knapm` path, and stale registry conflicts before launching the attach child.
5. Daemon-owned `.knapm` manifests include daemon PID, daemon instance id, daemon heartbeat, file-registry control endpoint, writer checkpoint, and final recovery state.
6. Clean daemon stop still uses the existing cancellation event and `KnMonAgentStop` self-disable path, then validate/replay remain target-free.
7. Audit states cover `healthy`, `finalized`, `stale`, `daemon_crashed`, `writer_crashed`, `orphaned_agent_risk`, and `malformed`. Prune removes only daemon registry records marked `pruneEligible`; it does not delete `.knapm` data, recover writers, unload agents, or mutate target processes.
8. The daemon is not a Windows service and does not add cross-bitness attach, PPL bypass, manual mapping, stealth loading, automatic crash recovery, or orphaned active-agent repair.

The Phase 11M compression/catalog path and Phase 13A catalog-index path keep replay target-free:

1. `attach-session --write-knapm <path.knapm> --knapm-compression zstd` and `daemon-start-session --write-knapm <path.knapm> --knapm-compression zstd` write `.jsonl.zst` chunks using a standards-compatible zstd raw-block frame.
2. `index.json` records stored `byteLength`/`sha256` and, for zstd chunks, required `uncompressedByteLength`/`uncompressedSha256` integrity fields.
3. `validate-session` and `replay-session` support both `compression=none` and `compression=zstd`; unknown compression fails as `unsupported_compression`.
4. `catalog-sessions --root <dir> --catalog <path>` builds a JSON replay catalog from disk metadata and validation only.
5. `catalog-query --catalog <path>` filters catalog rows by validation/recovery/writer state and target PID or image text.
6. `catalog-remove-missing --catalog <path> [--dry-run]` removes only missing catalog rows; it does not delete `.knapm` data, recover writers, unload agents, launch targets, or attach to targets.
7. Tauri exposes catalog wrappers, and the UI can rebuild/query/prune the catalog, inspect catalog rows, and replay an explicit `.knapm` row by path without target mutation.
8. The trace table uses a local virtual row window so large replay sessions keep the DOM bounded while export and inspector state continue to use the full event set.
9. Structured query and error-focused views run only over the existing UI-side trace model; they add no target process overhead and do not change helper, agent, transport, or `.knapm` contracts.
10. Thread and timeline views reuse the same UI-side trace model and query predicates; they do not add helper calls, target work, or replay-format changes.
11. Rule-based highlighting is computed from the current in-memory trace array and slow-call threshold; it adds no helper calls, target work, injected-agent work, or replay-format changes.
12. `catalog-index-build --root <dir> --database <path> [--rebuild]` builds a versioned `winsqlite3` metadata cache over `.knapm` directories after disk validation.
13. `catalog-index-query --database <path>` filters DB rows by validation/recovery/writer state and target PID or image/path text without touching session directories.
14. `catalog-index-remove-missing --database <path> [--dry-run]` reports or removes only missing DB rows; it never deletes `.knapm` data, recovers writers, unloads agents, launches targets, or attaches to targets.
15. Tauri and the UI expose DB index build/rebuild/query/dry-run/prune controls while preserving explicit replay-by-path behavior.

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
41. `GetSystemMetrics`
42. `GetDesktopWindow`
43. `GetForegroundWindow`
44. `GetWindowThreadProcessId`
45. `CreateCompatibleDC`
46. `GetDeviceCaps`
47. `DeleteDC`
48. `EnumProcessModules`
49. `GetModuleInformation`
50. `GetModuleBaseNameW`
51. `GetModuleFileNameExW`
52. `GetFileVersionInfoSizeW`
53. `GetFileVersionInfoW`
54. `VerQueryValueW`
55. `SHGetKnownFolderPath`
56. `SHGetSpecialFolderPathW`
57. `RoInitialize`
58. `RoUninitialize`
59. `RoGetApartmentIdentifier`
60. `VirtualAlloc`
61. `VirtualFree`
62. `VirtualProtect`
63. `VirtualQuery`
64. `CreateThread`
65. `OpenThread`
66. `WaitForSingleObject`
67. `GetExitCodeThread`
68. `CreateEventW`
69. `OpenEventW`
70. `SetEvent`
71. `ResetEvent`
72. `WaitForSingleObjectEx`
73. `CreateMutexW`
74. `OpenMutexW`
75. `ReleaseMutex`
76. `CreateSemaphoreW`
77. `OpenSemaphoreW`
78. `ReleaseSemaphore`
79. `WaitForMultipleObjectsEx`
80. `CreateFileMappingW`
81. `OpenFileMappingW`
82. `MapViewOfFile`
83. `UnmapViewOfFile`
84. `GetCurrentProcess`
85. `GetCurrentProcessId`
86. `GetCurrentThread`
87. `GetCurrentThreadId`
88. `GetProcessId`
89. `GetThreadId`

The current smoke path captures real sample-target File I/O events, a deterministic `LoadLibraryW("knmon-dynamic-probe.dll")` loader event, and resolver calls for `GetProcAddress` and `LdrGetProcedureAddress` through `transportMode=shared-memory`, with `droppedEvents=0` on the healthy path. `ReadFile` and `WriteFile` include bounded 16-byte buffer previews. `NtCreateFile` is captured as an explicit `ntdll.dll` event with `returnValue` carrying the NTSTATUS hex value and a bounded `ObjectAttributes` object-name decode. Resolver events include bounded function-name evidence and return/status values, but calls made through resolver-returned function pointers are not automatically instrumented. Backpressure can be forced with `KNMON_TRANSPORT_CAPACITY`; the current bounded ring uses drop-newest accounting and reports transport produced/consumed/dropped records plus min/average/max hook overhead estimates.

The live Wave 2/3 slices are intentionally narrow: `ws2_32.dll` Winsock startup, cleanup, socket create/close, localhost address resolution, address-info free, and Winsock error query calls are captured from the controlled sample path; `advapi32.dll` registry open/create/query/set/delete/close calls are captured through HKCU-only sample operations; `advapi32.dll` token query/privilege lookup calls are limited to current-process `TOKEN_QUERY` and `SeChangeNotifyPrivilege` LUID lookup evidence without token mutation, token privilege arrays, SID/group/ACL/security descriptor, credential, or service-control capture; `rpcrt4.dll` local string-binding compose/from/free calls are captured through a no-server `ncalrpc` sample lifecycle, and the RPCRT4 UUID helper slice captures only `UuidCreate`, `UuidToStringW`, and `UuidFromStringW` pointer/status/UUID value/string evidence without endpoint mapper, auth, network payload, or sequential UUID capture; `bcrypt.dll` provider open/close, algorithm-name property query, and RNG generation calls are captured without copying random, key, plaintext, ciphertext, IV, or hash input bytes; `crypt32.dll` certificate-store/message-handle open/close calls are captured without copying certificate blobs, private keys, cryptographic message payloads, random bytes, keys, plaintext, ciphertext, IVs, or hash input bytes; `winhttp.dll` session open/close calls are captured without making network requests or copying URLs, headers, bodies, cookies, credentials, proxy credentials, or payload bytes; `wininet.dll` session open/close calls are captured without making network requests or copying URLs, headers, bodies, cookies, credentials, proxy credentials, or payload bytes; the Wave 3 `user32.dll`/`gdi32.dll` metadata slice captures only system metric indexes/results, HWND/HDC pointer-sized handles, window thread/process numeric evidence, and DC capability indexes/results; the Wave 3 `psapi.dll` module-query slice captures only process/module handles, requested/needed module-array byte counts, one bounded first-module handle sample, `MODULEINFO` base/image-size/entry-point numeric evidence, and bounded module base-name/file-path strings; the Wave 3 `version.dll` resource slice captures only version-info path/size/pointer evidence, fixed-file-info numeric fields, and the first translation language/codepage pair; the Wave 3 `shell32.dll` known-folder slice captures only known-folder GUID, CSIDL, flag, handle, pointer, return/timing evidence, and returned paths for allowlisted Windows/System/ProgramFiles queries, while non-allowlisted folder queries emit `non_allowlisted_no_path` without returned path strings; the Wave 3 `ole32.dll` COM lifecycle slice captures only apartment init flags, pointer values, HRESULT/int return evidence, generated GUID evidence, bounded canonical GUID strings, timing, and hook lifecycle evidence; the Wave 3 API-set WinRT lifecycle slice captures only `RoInitialize` init type/HRESULT, `RoUninitialize` call/timing evidence, and `RoGetApartmentIdentifier` pointer plus decoded `UINT64` apartment id through the observed `api-ms-win-core-winrt-l1-1-0.dll` import provider; the Wave 3 `kernel32.dll` memory protection slice captures only current-process allocation/protection/query pointer, size, flag, return, and `MEMORY_BASIC_INFORMATION` metadata for `VirtualAlloc`, `VirtualFree`, `VirtualProtect`, and `VirtualQuery`; the Wave 3 `kernel32.dll` thread lifecycle slice captures only current-process thread handle, thread ID, access/creation/wait flag, wait-result, and exit-code metadata for `CreateThread`, `OpenThread`, `WaitForSingleObject`, and `GetExitCodeThread`; the Wave 3 `kernel32.dll` event synchronization slice captures only current-process event handles, BOOL flags, desired-access flags, wait timeout/result, return/error evidence, timing, and hook lifecycle metadata for `CreateEventW`, `OpenEventW`, `SetEvent`, `ResetEvent`, and `WaitForSingleObjectEx`; the Wave 3 `kernel32.dll` mutex/semaphore synchronization slice captures only current-process mutex/semaphore handles, BOOL flags, desired-access flags, semaphore counts, handle-array pointer-only evidence, multi-wait timeout/result, return/error evidence, timing, and hook lifecycle metadata for `CreateMutexW`, `OpenMutexW`, `ReleaseMutex`, `CreateSemaphoreW`, `OpenSemaphoreW`, `ReleaseSemaphore`, and `WaitForMultipleObjectsEx`; the Wave 3 `kernel32.dll` file-mapping slice captures only current-process mapping/file handles, protection/access flags, size/offset values, mapped view pointer, pointer-only security/name evidence, return/error evidence, timing, and hook lifecycle metadata for `CreateFileMappingW`, `OpenFileMappingW`, `MapViewOfFile`, and `UnmapViewOfFile`; and the Wave 3 `kernel32.dll` process/thread identity slice captures only pseudo/current process/thread handles, current PID/TID values, PID/TID lookup by handle, return/error evidence, timing, and hook lifecycle metadata for `GetCurrentProcess`, `GetCurrentProcessId`, `GetCurrentThread`, `GetCurrentThreadId`, `GetProcessId`, and `GetThreadId`. Window text, screenshots, pixels, bitmaps/DIBs, clipboard data, keyboard/mouse input, message hooks, credentials, process enumeration, process creation payloads, command lines, environment blocks, synchronization object names, file-mapping object names, object-manager namespace paths, security descriptors, SIDs, ACLs, handle-array contents, mapped memory contents, wait-chain/APC queue evidence, module memory bytes, raw process memory bytes, raw resource bytes, string-table values, PE headers/sections/imports/exports/resources/relocations/debug data, file contents, hashes, signatures, RPC endpoint/auth/network payload evidence, ShellExecute/process-launch evidence, PIDLs, Shell namespace item data, COM/WinRT activation, HSTRING/runtime-class/restricted-error-info, class factory/interface/vtable evidence, marshaled interface payloads, structured storage payloads, user-profile/AppData/Desktop/Documents/Downloads paths, remote-thread/APC/context/stack evidence, and arbitrary payload previews remain out of scope. High-volume network payload hooks such as `send`, `recv`, `sendto`, `recvfrom`, WinHTTP request/transfer/header APIs, WinINet connection/request/transfer/option APIs, `AdjustTokenPrivileges`, service-control APIs, security descriptor/SID/credential capture, RPC auth/endpoint capture, UI/GDI payload capture, raw resource capture, Shell execution/file metadata capture, COM/WinRT activation/object/marshaling/HSTRING/runtime-class/error-info capture, remote process memory APIs, remote thread/APC/context APIs, synchronization object namespace/security/wait-chain payload capture, memory contents, injection helpers, and PE/module-memory payload capture remain definition-only or non-goals until separate transport ABI and overhead reviews.

Healthy same-bitness x64 and x86 lifecycle evidence currently reports at least the six required File I/O hooks, `restoredHooks=installedHooks`, and `failedHooks=0`. Controlled launch shutdown reports `reason=process_detach`; attach self-disable reports `reason=self_disable`.

Wave 2 metadata is committed for 77 additional APIs across `advapi32.dll`, `bcrypt.dll`, `crypt32.dll`, `rpcrt4.dll`, `ws2_32.dll`, `wininet.dll`, and `winhttp.dll`; Phase 13B adds seven Wave 3 APIs across `user32.dll` and `gdi32.dll`; Phase 13C adds four Wave 3 PSAPI module-query APIs in `psapi.dll`; Phase 13D adds three Wave 3 Version resource APIs in `version.dll`; Phase 13E adds two Wave 3 Shell known-folder APIs in `shell32.dll`; Phase 13F adds four Wave 3 OLE32 COM lifecycle APIs in `ole32.dll`; Phase 13G adds two new RPCRT4 UUID helper APIs while promoting existing `UuidCreate` ID `58`; Phase 13H adds three COMBASE-backed WinRT lifecycle APIs through the observed `api-ms-win-core-winrt-l1-1-0.dll` import provider; Phase 13I adds four current-process KERNEL32 memory allocation/protection/query APIs in `kernel32.dll`; Phase 13J adds four current-process KERNEL32 thread lifecycle/wait APIs in `kernel32.dll`; Phase 13K adds five current-process KERNEL32 event synchronization APIs in `kernel32.dll`; Phase 13L adds seven current-process KERNEL32 mutex/semaphore synchronization APIs in `kernel32.dll`; Phase 13M adds four current-process KERNEL32 file-mapping APIs in `kernel32.dll`; and Phase 13N adds six current-process KERNEL32 process/thread identity APIs in `kernel32.dll`. Seven selected `ws2_32.dll` APIs, six selected `advapi32.dll` registry APIs, two selected `advapi32.dll` token query/privilege lookup APIs, seven selected `rpcrt4.dll` RPC binding/UUID helper APIs, four selected `bcrypt.dll` CNG provider/RNG APIs, four selected `crypt32.dll` certificate-store/message-handle APIs, two selected `wininet.dll` session-handle APIs, two selected `winhttp.dll` session-handle APIs, four selected `user32.dll` metadata APIs, three selected `gdi32.dll` DC metadata APIs, four selected `psapi.dll` module-query APIs, three selected `version.dll` resource metadata APIs, two selected `shell32.dll` known-folder metadata APIs, four selected `ole32.dll` COM lifecycle/GUID helper APIs, three selected API-set WinRT lifecycle APIs, four selected `kernel32.dll` memory protection APIs, four selected `kernel32.dll` thread lifecycle APIs, five selected `kernel32.dll` event synchronization APIs, seven selected `kernel32.dll` mutex/semaphore synchronization APIs, four selected `kernel32.dll` file-mapping APIs, and six selected `kernel32.dll` process/thread identity APIs are now smoke-verified IAT hooks; the remaining unselected Wave 2 APIs stay `definition_only`. The current definition coverage report totals 145 APIs: 45 `definition_only`, 4 `hooked`, and 96 `smoke_verified`.

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
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-user32-gdi32-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-psapi-module-query-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-version-resource-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-shell-known-folder-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-ole32-com-lifecycle-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-rpcrt4-uuid-helper-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-combase-winrt-lifecycle-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-memory-protection-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-thread-lifecycle-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-event-sync-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-mutex-semaphore-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-file-mapping-smoke.ps1
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-process-thread-identity-smoke.ps1
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
npm run catalog-index:smoke
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

`capture-sample` uses the same controlled launch path, keeps the named pipe open for low-volume control/lifecycle messages, inventories loaded modules, installs same-bitness IAT hooks for the stable File I/O, loader-aware Wave 1, resolver call set, selected registry slice, selected advapi32 token query/privilege lookup slice, selected Winsock slice, selected RPCRT4 binding and UUID helper slices, selected bcrypt CNG provider/RNG slice, selected crypt32 certificate-store/message-handle slice, selected WinHTTP session-handle slice, selected WinINet session-handle slice, selected User32/GDI32 low-payload metadata slice, selected PSAPI module-query slice, selected Version resource metadata slice, selected Shell known-folder metadata slice, selected OLE32 COM lifecycle/GUID helper slice, selected COMBASE-backed WinRT lifecycle slice, selected KERNEL32 memory protection metadata slice, selected KERNEL32 thread lifecycle metadata slice, selected KERNEL32 event synchronization metadata slice, selected KERNEL32 mutex/semaphore synchronization metadata slice, selected KERNEL32 file-mapping metadata slice, and selected KERNEL32 process/thread identity metadata slice, drains API calls through the collector-core shared transport reader, and returns schema-versioned `api_call` events plus dropped-event accounting.

`attach-capture` attaches to an already-running same-bitness non-protected sample target, passes attach configuration through `KnMonAttachConfigV1`, uses the same shared-memory transport for API records, and detaches by self-disabling hooks without unloading the DLL.

`supervise-tree` snapshots an already-running sample root's process tree, returns `processNodes`, `policyDecisions`, and audit events, and supports `observe` and `attach-supported` child policies. Observe policy never mutates children. Attach-supported policy only attaches same-bitness repository sample children and embeds the Phase 11A child attach result.

The Tauri UI exposes the same bounded attach and process-tree commands in the selected native target panel. Browser/Vite mode keeps these actions blocked because native attach requires the Tauri desktop runtime and the built helper executable.

The repeated smoke script verifies five consecutive controlled x64 captures, the stable File I/O API set, zero dropped events, and hook restore counts. The `NtCreateFile` smoke verifies the `ntdll.dll` module, NTSTATUS return format, decoded sample object path, shared-memory transport mode, and clean hook restore. The shared-memory transport smoke verifies healthy x64 transport metrics and hook overhead. The shared-memory backpressure smoke forces a tiny ring capacity and verifies non-blocking dropped-event accounting. The shared transport reader smoke verifies FIFO drain, partial committed-record stop behavior, and bounded max-drain behavior. The catalog index smoke verifies `winsqlite3` DB build/query, valid/invalid/state/target filters, limit behavior, missing-row dry-run/removal, malformed DB rejection, unsupported schema rejection, and no `.knapm` data deletion. The repeated attach state smoke verifies x64/x86 same-process reattach after self-disable, first-load vs loaded-agent reinitialize strategy evidence, absence of a second `LoadLibraryW`, fresh shared-memory transport metrics, and active loaded-agent rejection before mutation. The cancellation operation-state smoke verifies x64 attach cancellation through `cancel-operation`, `ERROR_CANCELLED`, self-disable cleanup evidence, post-cancel loaded-agent reattach, and process-tree observe cancellation without child mutation. The threaded collector/session smoke verifies host-side threaded committed-record drain, `attach-session` JSONL running-state visibility, and safe stop cleanup evidence. The streaming session UI batch smoke verifies non-empty `trace_batch` frames, monotonic batch/record sequences, final counter consistency, safe cancellation, and `agent_shutdown reason=self_disable`. The KNAPM streaming replay smoke verifies `.knapm` chunk writing from `trace_batch` boundaries, index/hash validation, deterministic replay, final counter consistency, and validate/replay without target mutation. The KNAPM recovery ownership smoke verifies finalized/owned/stale/recovery-required/lease-expired `.knapm` classification and proves validate does not terminate the live target. The KNAPM compression/catalog smoke verifies zstd attach and daemon-owned sessions, zstd integrity validation/replay, catalog build/query, and catalog missing-row pruning without deleting `.knapm` data. The persistent daemon session smoke verifies daemon start, daemon-owned `persistent-daemon` `.knapm` ownership, start-command return while daemon/session processes remain alive, streamed records, clean stop, validation, replay, and daemon shutdown. The persistent daemon hardening smoke verifies daemon audit, duplicate live target/session/path rejection before mutation, stale daemon status, daemon-crash and writer-crash classification, dry-run and actual stale registry pruning, active-record preservation, and finalized `.knapm` validate/replay after pruning. The session recovery-state smoke verifies stale and recovery-required host-side classification without target mutation. The loader-aware smokes verify PEB module inventory, eligible-module IAT sweep evidence, `LoadLibraryW` capture, dynamic-load re-hooking, and post-load `knmon-dynamic-probe.dll` API evidence. The resolver monitoring smoke verifies `GetProcAddress` and `LdrGetProcedureAddress` call visibility, resolver tags, bounded `KnMonDynamicProbe` argument evidence, and clean hook restore. The generated decoder tables smoke verifies generated metadata freshness plus controller-rendered API family/category and argument decode metadata. The Wave 2 registry smoke verifies the selected `advapi32.dll` HKCU registry API records, generated registry metadata, key/value evidence, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 2 advapi32 token query smoke verifies `OpenProcessToken` and `LookupPrivilegeValueW` records, generated security metadata, `TOKEN_QUERY`, token-handle, privilege-name, and LUID evidence, absence of token mutation/service-control/credential/byte-preview evidence, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 2 Winsock smoke verifies the selected `ws2_32.dll` bootstrap/address-resolution API records, generated network metadata, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 2 RPCRT4 smoke verifies the selected local RPC binding lifecycle records, generated RPC metadata, `ncalrpc`/`KNMonRpcSample` evidence, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 3 RPCRT4 UUID smoke verifies selected UUID create/to-string/from-string records, generated RPC metadata, stable API ID `58` promotion plus IDs `111` and `112`, bounded UUID value/string evidence, absence of endpoint/auth/network/COM/credential/byte-preview payloads, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 2 bcrypt smoke verifies selected CNG provider/RNG records, generated crypto metadata, `RNG`/`AlgorithmName` evidence, absence of generated random byte previews, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 2 crypt32 smoke verifies selected certificate-store/message-handle records, generated certificate/message metadata, memory-store provider and X509/PKCS7 encoding evidence, absence of certificate blob/private-key/message-payload previews, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 2 WinHTTP smoke verifies selected session open/close records, generated HTTP metadata, sample user-agent/no-proxy evidence, absence of URL/header/body/cookie/credential/proxy-credential/payload previews, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 2 WinINet smoke verifies selected session open/close records, generated internet metadata, sample user-agent/direct-access evidence, absence of URL/header/body/cookie/credential/proxy-credential/payload previews, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 3 User32/GDI32 smoke verifies selected system metric, window handle/thread-process, and DC lifecycle/capability records, generated UI/GDI metadata, numeric HWND/HDC/PID/TID/metric evidence, absence of window text, pixels, clipboard, input, credential, or byte-preview evidence, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 3 PSAPI smoke verifies selected module enumeration, module information, module base-name, and module file-name records, generated module metadata, bounded first-module handle, MODULEINFO base/image-size/entry-point, name/path evidence, absence of module memory, PE/file/hash/signature/credential/byte-preview payloads, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 3 Version smoke verifies selected file version resource size/load/query records, generated resource metadata, kernel32 path/size evidence, fixed file/product version fields, translation language/codepage evidence, absence of raw resource, string-table, PE/file/hash/signature/credential/byte-preview payloads, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 3 Shell smoke verifies selected known-folder and special-folder records, generated Shell metadata, GUID/CSIDL/flag/handle/pointer evidence, allowlisted Windows/System/ProgramFiles path evidence, non-allowlisted path suppression, absence of user-folder/AppData/command-line/environment/ShellExecute/PIDL/file-content/credential/byte-preview payloads, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 3 OLE32 smoke verifies selected COM apartment lifecycle and GUID helper records, generated COM metadata, COM init flag, pointer, HRESULT/int return, GUID, bounded GUID-string evidence, absence of COM activation/object/marshaling/storage/clipboard/drag-drop/user-path/credential/byte-preview payloads, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 3 COMBASE-backed WinRT lifecycle smoke verifies selected `RoInitialize`, `RoUninitialize`, and `RoGetApartmentIdentifier` records through the observed API-set provider, generated COM metadata, init type/HRESULT/void/apartment-id evidence, absence of activation/HSTRING/runtime-class/restricted-error-info/COM object/marshaling/user-path/credential/byte-preview payloads, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 3 KERNEL32 memory smoke verifies selected `VirtualAlloc`, `VirtualFree`, `VirtualProtect`, and `VirtualQuery` records, generated memory metadata, allocation/free/protection/state/type flag decoding, decoded `MEMORY_BASIC_INFORMATION` metadata, absence of remote-memory/injection/file/PE/hash/credential/byte-preview payloads, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 3 KERNEL32 thread lifecycle smoke verifies selected `CreateThread`, `OpenThread`, `WaitForSingleObject`, and `GetExitCodeThread` records, generated thread metadata, stable API IDs `120` through `123`, thread access/creation/wait decoding, decoded thread ID and exit code evidence, absence of remote-thread/APC/context/stack/injection/credential/byte-preview payloads, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 3 KERNEL32 event synchronization smoke verifies selected `CreateEventW`, `OpenEventW`, `SetEvent`, `ResetEvent`, and `WaitForSingleObjectEx` records, generated synchronization metadata, stable API IDs `124` through `128`, event access/BOOL/wait decoding, non-null event-handle and pointer evidence, absence of event-name/object-namespace/security-descriptor/SID/ACL/wait-chain/APC/context/stack/injection/credential/byte-preview payloads, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 3 KERNEL32 mutex/semaphore smoke verifies selected `CreateMutexW`, `OpenMutexW`, `ReleaseMutex`, `CreateSemaphoreW`, `OpenSemaphoreW`, `ReleaseSemaphore`, and `WaitForMultipleObjectsEx` records, generated synchronization metadata, stable API IDs `129` through `135`, mutex/semaphore access/BOOL/count/multi-wait decoding, non-null handle and pointer-only name/handle-array evidence, absence of object-name/object-namespace/security-descriptor/SID/ACL/handle-array/wait-chain/APC/context/stack/injection/credential/byte-preview payloads, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The x86 smoke verifies the same File I/O API set, loader evidence, resolver evidence, selected registry, advapi32 token query, Winsock, RPCRT4 binding and UUID helper, bcrypt, crypt32, WinHTTP, WinINet, User32/GDI32, PSAPI, Version, Shell, OLE32, COMBASE-backed WinRT lifecycle, KERNEL32 memory protection, KERNEL32 thread lifecycle, KERNEL32 event synchronization, and KERNEL32 mutex/semaphore synchronization evidence, shared-memory transport, and hook lifecycle from a Win32 helper/target/agent build. The launch preflight negative smoke verifies missing target, missing agent, and available architecture mismatch failures before remote mutation. The attach smoke verifies x64 and x86 already-running sample attach, `remote LoadLibraryW`, `self-disable-no-unload`, zero healthy-path drops, required File I/O APIs, and hook restore evidence. The attach preflight negative smoke verifies missing PID, PID 0/4, helper self, missing agent, agent mismatch, and cross-bitness target mismatch cases before remote mutation. The process-tree smoke verifies x64/x86 observe policy child discovery, missing/root PID failures, and cross-bitness child skip before mutation. The process-tree attach-supported smoke verifies x64/x86 child attach through Phase 11A, required File I/O APIs, zero drops, and self-disable hook restore.

The Wave 3 KERNEL32 file-mapping smoke verifies selected `CreateFileMappingW`, `OpenFileMappingW`, `MapViewOfFile`, and `UnmapViewOfFile` records, generated memory metadata, stable API IDs `136` through `139`, file-mapping protection/access/size/offset/view-pointer decoding, pointer-only name/security evidence, absence of mapping-name/object-namespace/mapped-memory/security/stack/injection/PE/file/hash/credential/byte-preview payloads, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The Wave 3 KERNEL32 process/thread identity smoke verifies selected `GetCurrentProcess`, `GetCurrentProcessId`, `GetCurrentThread`, `GetCurrentThreadId`, `GetProcessId`, and `GetThreadId` records, generated process metadata, stable API IDs `140` through `145`, pseudo/current handle evidence, PID/TID decimal+hex values, absence of process enumeration, command-line, environment, token/security, remote-memory, remote-thread, stack, injection, PE/file/hash, credential, or byte-preview payloads, shared-memory transport, zero healthy-path drops, and clean hook lifecycle. The x86 smoke includes the same file-mapping and process/thread identity evidence from a Win32 helper/target/agent build.

`capture-sample --write-session` persists the bounded capture into a replayable legacy session directory. `attach-session --stream-batches --write-knapm` persists streaming attach batches into a `.knapm` directory-backed container, and `daemon-start-session --write-knapm` writes the same durable format with `ownerKind=persistent-daemon`. Both `.knapm` writers accept `--knapm-compression none|zstd`. Session validation checks legacy manifest architecture, `.knapm` manifest/index/chunk integrity, stored and uncompressed chunk hashes, ownership/recovery metadata, daemon owner metadata where present, HELLO architecture/version evidence, dropped-event accounting, shutdown hook restore counts, and trace rows before replay returns data from disk without relaunching the target.

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

The current committed definition catalog includes 145 APIs: 45 `definition_only`, 4 `hooked`, and 96 `smoke_verified`. Only the selected Winsock bootstrap/address-resolution APIs, selected HKCU-safe registry APIs, selected advapi32 token query/privilege lookup APIs, selected local RPCRT4 binding and UUID helper APIs, selected bcrypt CNG provider/RNG APIs, selected crypt32 certificate-store/message-handle APIs, selected WinHTTP session-handle APIs, selected WinINet session-handle APIs, selected User32/GDI32 metadata APIs, selected PSAPI module-query APIs, selected Version resource metadata APIs, selected Shell known-folder metadata APIs, selected OLE32 COM lifecycle/GUID helper APIs, selected COMBASE-backed WinRT lifecycle APIs, selected KERNEL32 memory protection APIs, selected KERNEL32 thread lifecycle APIs, selected KERNEL32 event synchronization APIs, selected KERNEL32 mutex/semaphore synchronization APIs, selected KERNEL32 file-mapping APIs, and selected KERNEL32 process/thread identity APIs have moved to `iat` and `smoke_verified`; remaining unselected APIs are intentionally marked `definition_only` until hook ABI expansion and performance gates are reviewed.

Validate session fixtures:

```powershell
npm run sessions:validate
```

Validate collector fixtures and native smoke output:

```powershell
npm run collector:validate
```

Validate UI trace virtualization, query helpers, trace views, and highlight rules:

```powershell
npm run ui:validate
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
