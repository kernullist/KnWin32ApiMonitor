# Roadmap

작성일: 2026-06-08
갱신일: 2026-06-20

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
7. Phase 11I adds durable directory-backed `.knapm` session chunks and indexed replay for bounded streaming attach sessions, Phase 11J adds explicit `.knapm` restart/recovery ownership classification, Phase 11K adds a host-side persistent daemon supervision foundation, Phase 11L hardens daemon audit/stale registry handling, Phase 11M adds zstd `.knapm` chunks plus host-side JSON replay catalogs, Phase 11N adds dry-run daemon recovery planning and orphan-risk operator runbooks, Phase 11O adds dry-run-by-default recovery apply with registry-only cleanup, Phase 13A adds a host-side database-backed catalog index, and Phase 13R adds host-side event-level trace indexing plus full-text replay search; Windows service mode and automatic crash-tolerant daemon recovery remain future work.

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
7. Healthy x64/x86 captures consume shared-memory API records for File I/O, loader-aware sample events, resolver events, the selected registry slice, the selected advapi32 token query/privilege lookup slice, the selected Winsock bootstrap/address-resolution/connect metadata slice, the selected RPCRT4 binding, binding option, and UUID helper slices, the selected bcrypt CNG provider/RNG/key-destroy slice, the selected crypt32 certificate-store/message-handle slice, the selected WinHTTP session/scalar-option slice, the selected WinINet session-handle slice, and the selected Wave 3/4 low-payload metadata slices with zero dropped events.
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
   - Wave 3: `user32.dll`, `gdi32.dll`, `psapi.dll`, `version.dll`, `shell32.dll`, `ole32.dll`, `combase.dll`/API-set WinRT, and low-payload `kernel32.dll` metadata slices
   - Wave 4: generated definitions for the remaining common Windows user-mode DLLs, with selected OLEAUT32 lifecycle, SECUR32 credential/context cleanup, USERENV environment-block destroy, DNSAPI record-list free, IPHLPAPI adapter/interface metadata, SETUPAPI device-info close, SHLWAPI path-exists query, WINTRUST state-query, and DbgHelp symbol-session hooks
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
11. Resolver-returned pointers are classified through low-volume candidate-ledger agent messages without code mutation:
   - known generated APIs such as `kernel32.dll!GetCurrentProcessId` are reported as `resolver_pointer_candidate` with module/RVA/definition evidence and `instrumented=false`
   - repository-only exports such as `KnMonDynamicProbe` are reported as `resolver_pointer_unsupported` with `unsupported_definition_missing`
   - controller audit events and UI output summaries surface the candidate or unsupported reason before high-volume hook status noise
   - capture results plus legacy and `.knapm` session manifests expose `resolverPointerCandidates` and `resolverPointerUnsupported` counters
   - no `resolver_pointer_call` event is emitted by the candidate-ledger slice
12. Unloaded owner-module restoration races are handled without stale writes and healthy shutdown reports `restoredHooks=installedHooks`.
13. The first Wave 2 live slice captures selected `ws2_32.dll` Winsock bootstrap, connect metadata, and address-resolution APIs through the same shared-memory transport:
   - `WSAStartup`
   - `WSACleanup`
   - `socket`
   - `closesocket`
   - `connect`
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
   - `RpcBindingSetOption`
18. RPCRT4 records render generated metadata, `RPC_STATUS` values, pointer-sized binding/string handles, binding option ID/value metadata, and bounded `ncalrpc`/`KNMonRpcSample` string evidence outside the target process. They intentionally do not capture RPC auth/server-principal data, endpoint mapper enumeration, credentials, binding vectors, network payloads, RPC server communication, or payload previews.
19. The bcrypt Wave 2 live slice captures selected low-volume `bcrypt.dll` CNG provider/RNG/key-destroy APIs through the same shared-memory transport:
   - `BCryptOpenAlgorithmProvider`
   - `BCryptCloseAlgorithmProvider`
   - `BCryptGetProperty`
   - `BCryptGenRandom`
   - `BCryptDestroyKey`
20. bcrypt records render generated metadata, NTSTATUS values, provider handles, algorithm/property names, pointer values, and byte counts outside the target process. They intentionally do not copy random, key, plaintext, ciphertext, IV, or hash input bytes.
21. The crypt32 Wave 2 live slice captures selected low-volume `crypt32.dll` certificate-store and cryptographic-message handle APIs through the same shared-memory transport:
   - `CertOpenStore`
   - `CertCloseStore`
   - `CryptMsgOpenToDecode`
   - `CryptMsgClose`
22. crypt32 records render generated metadata, store/message handles, provider ID or bounded provider text, encoding/flag values, and pointer values outside the target process. They intentionally do not copy certificate blobs, private keys, cryptographic message payloads, random bytes, keys, plaintext, ciphertext, IVs, or hash input bytes.
23. The WinHTTP Wave 2 live slice captures selected low-volume `winhttp.dll` session/scalar-option metadata APIs through the same shared-memory transport:
   - `WinHttpOpen`
   - `WinHttpCloseHandle`
   - `WinHttpSetOption`
24. WinHTTP records render generated metadata, user-agent/access-type/proxy pointer evidence, session handles, option IDs, option-buffer pointer/length evidence, allowlisted DWORD scalar timeout/retry values, and return/status values outside the target process. They intentionally do not make network requests or copy URLs, headers, bodies, cookies, credentials, proxy credentials, raw option-buffer bytes, or payload bytes.
25. The WinINet Wave 2 live slice captures selected low-volume `wininet.dll` session-handle APIs through the same shared-memory transport:
   - `InternetOpenW`
   - `InternetCloseHandle`
26. WinINet records render generated metadata, user-agent/access-type/proxy pointer evidence, session handles, and return/status values outside the target process. They intentionally do not make network requests or copy URLs, headers, bodies, cookies, credentials, proxy credentials, or payload bytes.
27. The Phase 13B Wave 3 live slice captures selected low-payload `user32.dll` and `gdi32.dll` metadata APIs through the same shared-memory transport:
   - `GetSystemMetrics`
   - `GetDesktopWindow`
   - `GetForegroundWindow`
   - `GetWindowThreadProcessId`
   - `CreateCompatibleDC`
   - `GetDeviceCaps`
   - `DeleteDC`
28. User32/GDI32 records render generated metadata, metric/capability indexes and results, HWND/HDC pointer-sized handles, and window thread/process numeric evidence outside the target process. They intentionally do not capture window text, screenshots, pixels, bitmaps/DIBs, clipboard data, keyboard/mouse input, message hooks, credentials, or arbitrary payload previews.
29. The Phase 13C Wave 3 live slice captures selected low-payload `psapi.dll` module-query APIs through the same shared-memory transport:
   - `EnumProcessModules`
   - `GetModuleInformation`
   - `GetModuleBaseNameW`
   - `GetModuleFileNameExW`
30. PSAPI records render generated metadata, process/module handle evidence, module-array requested/needed byte counts, one bounded first-module handle sample, `MODULEINFO` base/image-size/entry-point numeric evidence, and bounded module base-name/file-path strings outside the target process. They intentionally do not capture module memory bytes, PE headers/sections/imports/exports/resources/relocations/debug data, file contents, hashes, signatures, full module-list dumps, credentials, or arbitrary payload previews.
31. The Phase 13D Wave 3 live slice captures selected low-payload `version.dll` resource metadata APIs through the same shared-memory transport:
   - `GetFileVersionInfoSizeW`
   - `GetFileVersionInfoW`
   - `VerQueryValueW`
32. Version records render generated metadata, bounded path/size/pointer evidence, root fixed-file-info numeric fields, and first translation language/codepage evidence outside the target process. They intentionally do not capture raw version resource bytes, arbitrary string-table values, PE/resource table dumps, file contents, hashes, signatures, credentials, or arbitrary payload previews.
33. The Phase 13E Wave 3 live slice captures selected low-payload `shell32.dll` known-folder metadata APIs through the same shared-memory transport:
   - `SHGetKnownFolderPath`
   - `SHGetSpecialFolderPathW`
34. Shell known-folder records render generated metadata, known-folder GUID/CSIDL, flag, handle, pointer, return/timing, allowlist status, and returned paths only for Windows/System/ProgramFiles queries outside the target process. Non-allowlisted successful queries emit `non_allowlisted_no_path` without returned path strings. They intentionally do not capture ShellExecute/process-launch evidence, PIDLs, Shell namespace item data, arbitrary file metadata, user-profile/AppData/Desktop/Documents/Downloads paths, command lines, environment variables, directory listings, file contents, credentials, or arbitrary payload previews.
35. The Phase 13F Wave 3 live slice captures selected low-payload `ole32.dll` COM lifecycle and GUID helper APIs through the same shared-memory transport:
   - `CoInitializeEx`
   - `CoUninitialize`
   - `CoCreateGuid`
   - `StringFromGUID2`
36. OLE32 COM lifecycle records render generated metadata, apartment init flag evidence, pointer values, HRESULT/int returns, generated GUID evidence, bounded canonical GUID strings, return/timing, and hook lifecycle evidence outside the target process. They intentionally do not capture COM activation, class factory/interface/vtable data, object method calls, marshaled interface payloads, monikers, ROT data, structured storage contents, clipboard/drag-drop payloads, Shell namespace data, user paths, credentials, or arbitrary payload previews.
37. The Phase 13G Wave 3 live slice captures selected low-payload `rpcrt4.dll` UUID helper APIs through the same shared-memory transport:
   - `UuidCreate`
   - `UuidToStringW`
   - `UuidFromStringW`
38. RPCRT4 UUID helper records render generated metadata, UUID pointer values, `RPC_STATUS` returns, bounded UUID value/string evidence, return/timing, and hook lifecycle evidence outside the target process. They intentionally do not capture endpoint mapper enumeration, RPC auth/server-principal data, credentials, binding vectors, network payloads, sequential UUID node evidence, COM activation/object/marshaling evidence, user paths, or arbitrary payload previews.
39. The Phase 13H Wave 3 live slice captures selected low-payload COMBASE-backed WinRT lifecycle APIs through the observed `api-ms-win-core-winrt-l1-1-0.dll` import provider:
   - `RoInitialize`
   - `RoUninitialize`
   - `RoGetApartmentIdentifier`
40. COMBASE-backed WinRT lifecycle records render generated metadata, provider choice verified by sample IAT, init type, HRESULT/void return evidence, apartment-id pointer and decoded `UINT64`, return/timing, and hook lifecycle evidence outside the target process. They intentionally do not capture activation factories, runtime class names, HSTRING values, restricted error info, COM object/interface/vtable data, marshaled payloads, user paths, credentials, or arbitrary payload previews.
41. The Phase 13I Wave 3 live slice captures selected low-payload current-process KERNEL32 memory allocation/protection/query APIs through the same shared-memory transport:
   - `VirtualAlloc`
   - `VirtualFree`
   - `VirtualProtect`
   - `VirtualQuery`
42. KERNEL32 memory records render generated metadata, pointer/size/allocation/free/protection flags, old protection, and `MEMORY_BASIC_INFORMATION` metadata outside the target process. They intentionally do not capture memory contents, remote memory APIs, injection helpers, PE/module memory, hashes, credentials, or arbitrary payload previews.
43. The Phase 13J Wave 3 live slice captures selected low-payload current-process KERNEL32 thread lifecycle/wait APIs through the same shared-memory transport:
   - `CreateThread`
   - `OpenThread`
   - `WaitForSingleObject`
   - `GetExitCodeThread`
44. KERNEL32 thread records render generated metadata, pointer-sized inputs, thread IDs, access/creation/wait flags, wait results, and exit-code evidence outside the target process. They intentionally do not capture remote-thread/APC helpers, suspend/resume, thread context, termination, stack walking, disassembly, injection payloads, credentials, or arbitrary payload previews.
45. The Phase 13K Wave 3 live slice captures selected low-payload current-process KERNEL32 event synchronization APIs through the same shared-memory transport:
   - `CreateEventW`
   - `OpenEventW`
   - `SetEvent`
   - `ResetEvent`
   - `WaitForSingleObjectEx`
46. KERNEL32 event synchronization records render generated metadata, event handles, BOOL flags, desired-access flags, wait timeout/result values, return/error evidence, and timing outside the target process. They intentionally do not copy event object names, object-manager namespace paths, security descriptors, SIDs, ACLs, token data, wait-chain evidence, APC queue state, context, stacks, disassembly, injection payloads, credentials, or arbitrary payload previews.
47. The Phase 13L Wave 3 live slice captures selected low-payload current-process KERNEL32 mutex/semaphore synchronization APIs through the same shared-memory transport:
   - `CreateMutexW`
   - `OpenMutexW`
   - `ReleaseMutex`
   - `CreateSemaphoreW`
   - `OpenSemaphoreW`
   - `ReleaseSemaphore`
   - `WaitForMultipleObjectsEx`
48. KERNEL32 mutex/semaphore records render generated metadata, mutex/semaphore handles, BOOL flags, desired-access flags, semaphore count values, handle-array pointer-only evidence, multi-wait timeout/result values, return/error evidence, and timing outside the target process. They intentionally do not copy mutex/semaphore object names, object-manager namespace paths, handle-array contents, security descriptors, SIDs, ACLs, token data, wait-chain evidence, APC queue state, context, stacks, disassembly, injection payloads, credentials, or arbitrary payload previews.
49. The Phase 13M Wave 3 live slice captures selected low-payload current-process KERNEL32 file-mapping APIs through the same shared-memory transport:
   - `CreateFileMappingW`
   - `OpenFileMappingW`
   - `MapViewOfFile`
   - `UnmapViewOfFile`
50. KERNEL32 file-mapping records render generated metadata, file/mapping handles, pointer-only security/name evidence, protection/access flags, size/offset values, mapped view pointers, return/error evidence, and timing outside the target process. They intentionally do not copy mapping object names, object-manager namespace paths, mapped memory contents, security descriptors, SIDs, ACLs, token data, file payloads, PE/module metadata, remote-memory evidence, context, stacks, disassembly, injection payloads, credentials, or arbitrary payload previews.
51. The Phase 13N Wave 3 live slice captures selected low-payload current-process KERNEL32 process/thread identity APIs through the same shared-memory transport:
   - `GetCurrentProcess`
   - `GetCurrentProcessId`
   - `GetCurrentThread`
   - `GetCurrentThreadId`
   - `GetProcessId`
   - `GetThreadId`
52. KERNEL32 process/thread identity records render generated metadata, pseudo/current process/thread handle values, PID/TID values, input handles for ID lookup calls, return/error evidence, and timing outside the target process. They intentionally do not enumerate processes or threads, create processes, duplicate handles, read command lines or environment blocks, expand token/security capture, inspect remote memory, inspect thread context/stacks, dump module/PE/file/hash data, or emit arbitrary payload previews.
53. The Phase 13O Wave 3 live slice captures selected low-payload current-process KERNEL32 handle metadata APIs through the same shared-memory transport:
   - `GetStdHandle`
   - `GetFileType`
   - `GetHandleInformation`
   - `SetHandleInformation`
54. KERNEL32 handle metadata records render generated metadata, standard-handle selector values, handle values, file-type values, handle-information flags, return/error evidence, and timing outside the target process. They intentionally do not duplicate handles, enumerate system handles, query object names or security descriptors, copy file/pipe/console payloads, read command lines or environment blocks, inspect remote memory, inspect thread context/stacks, dump module/PE/file/hash data, or emit arbitrary payload previews.
55. The Phase 13P Wave 3 live slice captures selected low-payload current-process KERNEL32 module lifecycle APIs through the same shared-memory transport:
   - `GetModuleHandleW`
   - `GetModuleHandleExW`
   - `GetModuleFileNameW`
   - `FreeLibrary`
56. KERNEL32 module lifecycle records render generated metadata, module-name input strings, module handles, `GetModuleHandleExW` flags, bounded module file-name output text, return/error evidence, and timing outside the target process. They intentionally do not enumerate remote modules, dump loaded-module lists, inspect module memory, parse PE headers or directories, hash files, validate signatures, capture command lines or environments, force unload/reference-count probe behavior, inspect remote memory, inspect thread context/stacks, or emit arbitrary payload previews.
57. The Phase 13Q Wave 3 live slice captures selected low-payload current-process KERNEL32 file metadata APIs through the same shared-memory transport:
   - `GetFileSizeEx`
   - `GetFileTime`
   - `GetFileInformationByHandle`
58. KERNEL32 file metadata records render generated metadata, file handle values, output pointer values, decoded file size, FILETIME scalar values, file attributes, volume serial, link count, file index, return/error evidence, and timing outside the target process. They intentionally do not copy file contents, enumerate directories, resolve paths or object-manager names, inspect PE metadata, hash files, validate signatures, duplicate handles, query security descriptors, capture command lines or environments, inspect remote memory, inspect thread context/stacks, or emit arbitrary payload previews.
59. `WS2_32.dll` ordinal imports for the selected Winsock APIs are matched only through explicit hook-definition ordinals, including ordinal `4` for `connect`; broad ordinal patching remains out of scope.
60. `generated/tier2-hook-plan.json` plans all 655 Tier 2 APIs with zero hooks enabled by default, including 279 API-set forwarder rows, 277 Windows-loader-resolved host rows, and 376 missing-parameter return-only rows.
61. `generated/tier2-profile-batch-plan.json` groups all 655 Tier 2 APIs into 104 review batches with zero hooks enabled by default: 16 resolved-host API-set batches, 87 missing-parameter return-only source-DLL batches, and 1 blocked unresolved API-set batch.
62. `generated/tier2-profile-review-manifest.json` ranks all 104 Tier 2 batches with zero hooks enabled by default: 42 initial candidates covering 55 APIs, 41 broader review-ready batches covering 452 APIs, 20 allowlist-gated batches covering 146 APIs with 30 explicit-allowlist-required APIs, and 1 blocked batch covering 2 APIs.
63. The Tier 2 generic profile smoke verifies `api-ms-win-core-winrt-string-l1-1-0.dll!WindowsGetStringLen` through resolved host `combase.dll`, verifies `advapi32.dll!RevertToSelf`, verifies 63 representative `tier2-initial-return-only` APIs across `comdlg32.dll`, `dwmapi.dll`, `msacm32.dll`, `winmm.dll`, `uxtheme.dll`, `comctl32.dll`, `d3d9.dll`, `dbghelp.dll`, `gdiplus.dll`, `oleaut32.dll`, `dxgi.dll`, `magnification.dll`, `msi.dll`, `odbc32.dll`, `snmpapi.dll`, `winhttp.dll`, `wldap32.dll`, `advpack.dll`, `dciman32.dll`, `dhcpcsvc6.dll`, `dhcpsapi.dll`, `fwpuclnt.dll`, `ntdll.dll`, `propsys.dll`, `urlmon.dll`, `cfgmgr32.dll`, `imm32.dll`, `uiautomationcore.dll`, `wscapi.dll`, `msrating.dll`, `fxsutility.dll`, and `wsnmp32.dll` as no-argument return-only events, and re-checks resolver visibility for `GetProcAddress` and `LdrGetProcedureAddress`.
64. `generated/tier3-hook-plan.json` plans all 1,370 Tier 3 APIs as design-review-only coverage with zero default-installable runtime hooks, including 1,192 COM/interface/vtable rows, 76 buffer-heavy rows, 67 callback rows, 27 window-message/hook-procedure rows, 5 WinRT/HSTRING rows, and 3 security-sensitive rows.

Next implementation focus:

1. Keep the selected Winsock bootstrap/address-resolution/connect metadata, registry, advapi32 token query/privilege lookup, RPCRT4 binding/option/UUID helper, bcrypt CNG provider/RNG/key-destroy, crypt32 certificate-store/message-handle, WinHTTP session/scalar-option, WinINet session-handle, User32/GDI32 metadata, PSAPI module-query, Version resource metadata, Shell known-folder metadata, OLE32 COM lifecycle/GUID helper, COMBASE-backed WinRT lifecycle, KERNEL32 memory protection, KERNEL32 thread lifecycle, KERNEL32 event synchronization, KERNEL32 mutex/semaphore synchronization, KERNEL32 file-mapping, KERNEL32 process/thread identity, KERNEL32 handle metadata, KERNEL32 module lifecycle, KERNEL32 file metadata, OLEAUT32 lifecycle, SECUR32 credential/context cleanup, USERENV environment-block destroy, DNSAPI record-list free, IPHLPAPI adapter/interface metadata, SETUPAPI device-info close, DbgHelp symbol-session, and gated Tier 2 generic representative DLL batches under shared-memory backpressure and hook-overhead gates.
2. Design payload-heavy network hooks (`send`, `recv`, `sendto`, `recvfrom`), WinHTTP connection/request/transfer/header/body/cookie/credential capture, WinHTTP non-scalar option buffers, and WinINet connection/request/transfer/option/header/cookie/credential/body capture separately before enabling buffer capture at scale.
3. Stage broader Tier 2 coverage only through `generated/tier2-profile-review-manifest.json` initial-candidate batches, backed by `generated/tier2-profile-batch-plan.json` resolved-host/source-DLL review batches and `defs:tier2-profile-batch-plan:select` previews by explicit profile, resolved host DLL, source module, family, risk, or allowlist gate; do not enable broad API-set or missing-parameter hooks by default.
4. Stage Tier 3 work only as reviewed design slices first; do not enable callback, COM/interface/vtable, WinRT/HSTRING, window-message/hook-procedure, buffer-heavy, remote-process-sensitive, security-sensitive, or manual-strategy APIs as runtime hooks from the generated plan alone.
5. Keep returned-pointer instrumentation as a separate reviewed design item.

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
12. Wave 2 metadata is committed for `advapi32.dll`, `bcrypt.dll`, `crypt32.dll`, `rpcrt4.dll`, `ws2_32.dll`, `wininet.dll`, and `winhttp.dll`, with `RpcBindingSetOption` promoted at stable API ID `54` for the selected local RPCRT4 binding option slice, `RpcMgmtEpEltInqDone` promoted at stable API ID `57` for the selected RPCRT4 endpoint inquiry cleanup slice, `BCryptDestroyKey` promoted at stable API ID `34` for the selected bcrypt cleanup slice, and `WinHttpSetOption` promoted at stable API ID `89` for the selected WinHTTP scalar option slice; Phase 13B adds Wave 3 metadata for `user32.dll` and `gdi32.dll`; Phase 13C adds Wave 3 metadata for `psapi.dll`; Phase 13D adds Wave 3 metadata for `version.dll`; Phase 13E adds Wave 3 metadata for `shell32.dll`; Phase 13F adds Wave 3 metadata for `ole32.dll`; Phase 13G promotes `UuidCreate` and adds RPCRT4 UUID helper metadata; Phase 13H adds COMBASE-backed WinRT lifecycle metadata through the observed API-set provider; Phase 13I adds KERNEL32 memory protection metadata; Phase 13J adds KERNEL32 thread lifecycle metadata; Phase 13K adds KERNEL32 event synchronization metadata; Phase 13L adds KERNEL32 mutex/semaphore synchronization metadata; Phase 13M adds KERNEL32 file-mapping metadata; Phase 13N adds KERNEL32 process/thread identity metadata; Phase 13O adds KERNEL32 handle metadata; Phase 13P adds KERNEL32 module lifecycle metadata; Phase 13Q adds KERNEL32 file metadata; Wave 4 adds common-DLL metadata for `oleaut32.dll`, `secur32.dll`, `userenv.dll`, `dnsapi.dll`, `iphlpapi.dll`, `setupapi.dll`, `shlwapi.dll`, `wintrust.dll`, and `dbghelp.dll`, with selected OLEAUT32 BSTR/variant/safe-array lifecycle APIs, SECUR32 credential/context cleanup APIs, USERENV environment-block destroy API, DNSAPI record-list free API, IPHLPAPI adapter/interface metadata APIs, SETUPAPI device-info close API, SHLWAPI path-exists query API, WINTRUST state-query API, and DbgHelp symbol-session APIs promoted to live smoke-verified hooks.
13. Stable generated IDs now cover 26 modules and 179 APIs, with Wave 2 API IDs `14` through `90`, Phase 13B Wave 3 API IDs `91` through `97`, Phase 13C PSAPI API IDs `98` through `101`, Phase 13D Version API IDs `102` through `104`, Phase 13E Shell API IDs `105` through `106`, Phase 13F OLE32 API IDs `107` through `110`, Phase 13G RPCRT4 UUID helper API IDs `111` through `112` while `UuidCreate` preserves stable API ID `58`, Phase 13H WinRT lifecycle API IDs `113` through `115`, Phase 13I KERNEL32 memory API IDs `116` through `119`, Phase 13J KERNEL32 thread lifecycle API IDs `120` through `123`, Phase 13K KERNEL32 event synchronization API IDs `124` through `128`, Phase 13L KERNEL32 mutex/semaphore synchronization API IDs `129` through `135`, Phase 13M KERNEL32 file-mapping API IDs `136` through `139`, Phase 13N KERNEL32 process/thread identity API IDs `140` through `145`, Phase 13O KERNEL32 handle metadata API IDs `146` through `149`, Phase 13P KERNEL32 module lifecycle API IDs `150` through `153`, Phase 13Q KERNEL32 file metadata API IDs `154` through `156`, and Wave 4 common-DLL API IDs `157` through `179`, including smoke-verified OLEAUT32 API IDs `158` through `160`, SECUR32 API IDs `162` and `164`, USERENV API ID `167`, DNSAPI API ID `169`, IPHLPAPI API IDs `170` and `171`, SETUPAPI API ID `173`, SHLWAPI API ID `174`, WINTRUST API ID `177`, plus DbgHelp API IDs `178` and `179`.
14. The coverage report currently totals 49 `definition_only`, 4 `hooked`, and 126 `smoke_verified` APIs.
15. `npm run defs:generate` emits deterministic controller-side decoder metadata:
   - `generated/definition-decoder-tables.json`
   - `native/knmon-common/include/knmon/common/GeneratedApiMetadata.h`
16. The controller uses generated metadata for API/module names, family/category tags, argument names/types/directions, decode aliases, and capture timing while preserving explicit per-API shared-memory slot interpretation.
17. The selected `advapi32.dll` registry slice, selected `advapi32.dll` token query/privilege lookup slice, `bcrypt.dll` CNG provider/RNG/key-destroy slice, `crypt32.dll` certificate-store/message-handle slice, `rpcrt4.dll` local binding/option, endpoint inquiry cleanup, and UUID helper slices, `ws2_32.dll` Winsock bootstrap/address-resolution/connect metadata slice, `winhttp.dll` session/scalar-option slice, `wininet.dll` session-handle slice, Phase 13B `user32.dll`/`gdi32.dll` metadata slice, Phase 13C `psapi.dll` module-query slice, Phase 13D `version.dll` resource metadata slice, Phase 13E `shell32.dll` known-folder metadata slice, Phase 13F `ole32.dll` COM lifecycle/GUID helper slice, Phase 13H `api-ms-win-core-winrt-l1-1-0.dll` WinRT lifecycle slice, Phase 13I KERNEL32 memory protection slice, Phase 13J KERNEL32 thread lifecycle slice, Phase 13K KERNEL32 event synchronization slice, Phase 13L KERNEL32 mutex/semaphore synchronization slice, Phase 13M KERNEL32 file-mapping slice, Phase 13N KERNEL32 process/thread identity slice, Phase 13O KERNEL32 handle metadata slice, Phase 13P KERNEL32 module lifecycle slice, Phase 13Q KERNEL32 file metadata slice, Wave 4 `oleaut32.dll` lifecycle slice, Wave 4 `secur32.dll` credential/context cleanup slice, Wave 4 `userenv.dll` environment-block destroy slice, Wave 4 `dnsapi.dll` record-list free slice, Wave 4 `iphlpapi.dll` adapter/interface metadata slice, Wave 4 `setupapi.dll` device-info close slice, Wave 4 `shlwapi.dll` path-exists query slice, Wave 4 `wintrust.dll` state-query slice, and Wave 4 `dbghelp.dll` symbol-session slice are marked `iat` and `smoke_verified`; unimplemented Wave 2 APIs and unselected Wave 4 additions remain `definition_only`.
18. `generated/tier3-hook-plan.json` is generated and validated as a planning artifact for all 1,370 Tier 3 APIs, keeping every row `blocked_by_default` and requiring explicit allowlist, design review, smoke evidence, and overhead review before any future runtime hook promotion.
19. `generated/dll-batch-promotion-plan.json` is generated and validated as the committed-definition promotion gate. It groups APIs by DLL into already-live, auto-promotable pointer/scalar, manual-decoder-required, payload-policy-blocked, and unsupported buckets so future runtime hook work promotes same-DLL safe APIs together instead of one API at a time.
20. `generated/tier2-profile-batch-plan.json` is generated and validated from the Tier 2 hook plan. It groups all 655 Tier 2 APIs into resolved-host API-set, source-DLL return-only, and blocked batches while keeping runtime hooks disabled by default.
21. `generated/tier2-profile-review-manifest.json` is generated and validated from the Tier 2 profile batch plan. It ranks all 104 Tier 2 batches into initial-candidate, review-ready, allowlist-gated, and blocked classes while keeping runtime hooks disabled by default.
22. `generated/manual-decoder-batch-plan.json` is generated and validated from the DLL batch queue. It now covers zero DLLs and zero APIs because the previous `rpcrt4.dll!RpcMgmtEpEltInqDone` manual candidate has been promoted to a smoke-verified low-payload cleanup hook.

Next implementation focus:

1. Expand live hooks by DLL batch slices from `generated/dll-batch-promotion-plan.json`, with deterministic smoke evidence for every auto-promoted API in that DLL.
2. Review a dedicated ABI and performance plan before enabling high-volume network payload hooks.
3. The auto-promotable and manual-decoder DLL batch queues are currently empty after the recent low-payload lifecycle/query/cleanup promotions; the next live coverage work should start from `generated/tier2-profile-review-manifest.json` initial-candidate batches, explicitly reviewed payload-sensitive families, or Tier 3 design slices. Keep token mutation, service-control, crypto key/encrypt/decrypt/hash, certificate chain/query/decode, RPC auth/endpoint/sequential-UUID, WinTrust verification/provider-data/certificate/catalog/hash capture, WinINet connection/request/transfer/option, and WinHTTP connection/request/transfer/header/body/cookie/credential/non-scalar-option work behind separate smoke and transport-budget gates.
4. Treat Tier 3 callback, COM/interface/vtable, WinRT/HSTRING, window-message/hook-procedure, buffer-heavy, remote-process-sensitive, and security-sensitive rows as design-only until a narrow slice proves ABI shape, payload boundaries, reentrancy behavior, and overhead.
5. Design returned-pointer instrumentation only after the IAT resolver monitoring path remains stable under transport and hook-overhead gates.

## Phase 11: Controlled Attach And Process Tree Supervision

Status: Phase 11A, Phase 11B, Phase 11C, Phase 11D, Phase 11E, Phase 11F, Phase 11G, Phase 11H, Phase 11I, Phase 11J, Phase 11K, Phase 11L, Phase 11M, Phase 11N, Phase 11O, Phase 13A, Phase 13B, Phase 13C, Phase 13D, Phase 13E, Phase 13F, Phase 13G, Phase 13H, Phase 13I, Phase 13J, Phase 13K, Phase 13L, Phase 13M, Phase 13N, Phase 13O, Phase 13P, Phase 13Q, and Phase 13R foundations are implemented. Bounded same-bitness running-process attach, helper-side process-tree supervision, UI controls for selected native target attach/supervision, repeated same-process reattach after self-disable, active loaded-agent rejection, pull-based collector reader foundation for shared transport drain, cancellation-safe operation ownership for bounded attach/process-tree helper commands, durable native session ownership readiness, bounded UI streaming trace batches, durable `.knapm` chunk replay, `.knapm` restart/recovery ownership classification, host-side persistent daemon-owned session supervision, daemon audit/stale-registry hardening, zstd `.knapm` chunks, host-side JSON replay catalogs, dry-run daemon recovery planning, registry-only daemon recovery apply, host-side database-backed catalog indexing, host-side event-level trace indexing and full-text replay search, low-payload User32/GDI32 metadata coverage, low-payload PSAPI module-query coverage, low-payload Version resource metadata coverage, allowlisted Shell known-folder metadata coverage, low-payload OLE32 COM lifecycle/GUID helper metadata coverage, low-payload RPCRT4 binding option metadata coverage, low-payload RPCRT4 UUID helper metadata coverage, low-payload COMBASE-backed WinRT lifecycle metadata coverage, low-payload KERNEL32 memory protection metadata coverage, low-payload KERNEL32 thread lifecycle metadata coverage, low-payload KERNEL32 event synchronization metadata coverage, low-payload KERNEL32 mutex/semaphore synchronization metadata coverage, low-payload KERNEL32 file-mapping metadata coverage, low-payload KERNEL32 process/thread identity metadata coverage, low-payload KERNEL32 handle metadata coverage, low-payload KERNEL32 module lifecycle coverage, low-payload KERNEL32 file metadata coverage, Wave 4 common-DLL metadata expansion, low-payload OLEAUT32 lifecycle coverage, low-payload SECUR32 credential/context cleanup coverage, low-payload USERENV environment-block destroy coverage, low-payload DNSAPI record-list free coverage, low-payload IPHLPAPI adapter/interface metadata coverage, low-payload SETUPAPI device-info close coverage, low-payload SHLWAPI path-exists query coverage, low-payload WINTRUST state-query coverage, low-payload DbgHelp symbol-session coverage, generated DLL batch promotion planning, and generated manual-decoder batch gating are implemented; Windows service mode, automatic daemon crash recovery, orphaned active-agent repair, UI/GDI payload capture, process enumeration/creation payload capture, command-line/environment capture, module memory/PE/file/hash/signature payload capture, raw resource/string-table capture, RPC auth/endpoint/network payload capture, sequential UUID node evidence, Shell execution/namespace/file-metadata/user-folder payload capture, DNS query/record payload capture, network adapter/address/interface payload capture, WinTrust verification/provider-data/certificate/catalog/hash capture, broad file-content/path/name/directory payload capture, remote memory/thread/injection payload capture, synchronization object namespace/security/wait-chain payload capture, mapped memory/object-name/security payload capture, handle duplication/system-handle/object-name/security-descriptor payload capture, file/pipe/console payload capture, OLE Automation BSTR/VARIANT/SAFEARRAY content capture, SSPI credential/principal/auth-data/context-token capture, and COM/WinRT activation/object/marshaling/storage/clipboard/drag-drop/HSTRING/runtime-class/restricted-error-info payload capture remain future work or non-goals until reviewed.

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
3. Attach preflight rejects PID `0`, PID `4`, helper self, missing targets, exited/stale PIDs, missing agents, helper/agent architecture mismatch, helper/target architecture mismatch, and PID creation-time identity changes before remote mutation.
4. Protection, process signature mitigation, and access checks run before remote mutation where the current user-mode helper can detect them.
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
11. Tauri exposes catalog build/query/remove wrappers, and the UI can browse catalog rows, filter by state/target/limit, prune missing catalog rows, and replay an explicit `.knapm` path.
12. `contracts/knapm-manifest.schema.json`, `contracts/knapm-index.schema.json`, `contracts/session-info.schema.json`, `contracts/session-catalog.schema.json`, and `protocol-version.json` document the compression/catalog contract.
13. `tools/session-validator/validate-session-fixtures.mjs` covers valid zstd, corrupt zstd frame, bad uncompressed hash, and unsupported compression fixtures.
14. `tools/native-smoke/knapm-compression-catalog-smoke.ps1` verifies live zstd attach, daemon-owned zstd sessions, validate/replay, catalog build/query, dry-run missing detection, and actual missing-row pruning without deleting active `.knapm` data.

Current verified Phase 11N behavior:

1. `knmon-native-helper.exe daemon-recovery-plan --runtime-dir <dir>` reads daemon registry records through the same classifier used by `daemon-audit`.
2. The command emits `daemon_recovery_plan` JSON with daemon status, audited sessions, session-level `recoveryPlans`, `recoveryPlanCount`, `registryPruneAllowedCount`, and `blockedMutationCount`.
3. Each plan item includes recovery state/reason, recommended operator action, `safetyState=dry_run_only`, allowed registry-prune hint, replay hint, blocked mutation ids, and operator runbook action ids.
4. The global result and every plan item keep `automaticRecoveryAllowed=false` and `targetMutationAllowed=false`.
5. The command always returns `dryRun=true` and `mutationAttempted=false`; it does not stop targets, unload agents, recover writers, reinject, delete `.knapm` data, delete daemon registry records, or mutate target processes.
6. Tauri exposes `plan_daemon_recovery`, and TypeScript/Rust models preserve the dry-run recovery plan contract for later UI wiring.
7. `contracts/native-daemon-recovery-plan.schema.json` and `protocol-version.json` document the Phase 11N command boundary.
8. `tools/native-smoke/daemon-recovery-plan-smoke.ps1` verifies daemon-crashed, writer-crashed, and orphan-risk plan items without mutating the live target fixture or deleting registry records.

Current verified Phase 11O behavior:

1. `knmon-native-helper.exe daemon-recovery-apply --runtime-dir <dir>` is dry-run by default, and `--dry-run` wins over mutation flags.
2. The command returns `daemon_recovery_apply` JSON with daemon status, audited sessions, recovery plan items, pruned session ids, dry-run state, and mutation-attempt state.
3. Non-dry-run mutation requires explicit `--apply-registry-prune` and can remove only registry records whose plan marks `registryPruneAllowed=true`.
4. The command keeps `automaticRecoveryAllowed=false` and `targetMutationAllowed=false`; it does not stop targets, unload agents, recover writers, reinject, delete `.knapm` data, or mutate target processes.
5. Tauri exposes `apply_daemon_recovery`, and TypeScript/Rust models preserve the registry-only apply contract for later UI wiring.
6. `contracts/native-daemon-recovery-apply.schema.json` and `protocol-version.json` document the Phase 11O command boundary.
7. `tools/native-smoke/daemon-recovery-apply-smoke.ps1` verifies dry-run default behavior, explicit writer-crashed/orphan-risk registry pruning, retained daemon-crashed records, preserved `.knapm` fixture data, and no live target mutation.

Current verified Phase 13A behavior:

1. `catalog-index-build --root <dir> --database <path> [--rebuild]` builds a versioned `winsqlite3` catalog index from `.knapm` session metadata and validation results.
2. The database stores rows equivalent to `NativeSessionCatalogRow`, including target identity, owner/recovery/writer state, counters, compression totals, validation status, content identity, and stale identity metadata.
3. Existing JSON catalog commands remain compatible; database-backed output uses the same catalog JSON shape with additive `databasePath`, `indexBackend`, `indexSchemaVersion`, and `staleIdentityCount` fields.
4. `catalog-index-query --database <path> [--limit n] [--state state] [--target pid-or-text]` filters DB rows without touching session directories.
5. `catalog-index-remove-missing --database <path> [--dry-run]` reports or removes only missing DB rows. It does not delete `.knapm` data, recover writers, unload agents, launch targets, attach to targets, or mutate target processes.
6. Tauri exposes DB index build/query/remove wrappers, and the UI adds compact DB index controls while preserving explicit replay-by-path behavior.
7. `contracts/session-catalog.schema.json` and `protocol-version.json` document the Phase 13A commands and additive DB metadata.
8. `tools/native-smoke/catalog-index-smoke.ps1` verifies empty roots, valid/invalid sessions, state filters, target PID/text filters, limit behavior, dry-run missing detection, DB-row removal, malformed DB rejection, unsupported schema rejection, and no `.knapm` data deletion.

Current verified Phase 13R behavior:

1. `trace-index-build --root <dir> --database <path> [--rebuild]` validates discovered `.knapm` sessions, decodes uncompressed and zstd chunks, and indexes normalized replay trace events outside the target process.
2. The trace index uses a separate `winsqlite3` database format from the session catalog index, with schema/version/format metadata and an FTS5 table for full-text search.
3. Indexed event rows include session path/id, operation id, event id, record/chunk/batch sequence, target/event PID/TID, process, module, API, return/error text, duration, relative time, tags, arguments, buffer preview, and bounded event JSON excerpt.
4. `trace-index-query --database <path> [--text text] [--api api] [--module module] [--session id-or-path] [--pid pid] [--limit n]` searches only the DB cache and does not launch, inject, attach, repair, unload, or mutate targets.
5. `trace-index-remove-missing --database <path> [--dry-run]` reports or removes only missing trace-index DB rows. It does not delete `.knapm` data.
6. Tauri exposes trace-index build/query/remove wrappers, and the UI adds compact trace DB controls plus hit rows that replay an explicit `.knapm` path through the existing replay command.
7. `tools/native-smoke/trace-index-smoke.ps1` verifies empty roots, valid/zstd/invalid fixtures, FTS text search, API/module/PID/session filters, limit behavior, catalog-DB format mismatch rejection, malformed DB rejection, missing-row dry-run/removal, and no `.knapm` data deletion.

Current verified Phase 13B behavior:

1. `definitions/win32/user32.json` and `definitions/win32/gdi32.json` add seven low-payload Wave 3 API definitions with stable generated IDs `91` through `97`.
2. Generated metadata now covers `user32.dll = 11`, `gdi32.dll = 12`, and decode aliases for HWND/HDC handles plus metric/capability indexes.
3. The agent installs IAT hooks for `GetSystemMetrics`, `GetDesktopWindow`, `GetForegroundWindow`, `GetWindowThreadProcessId`, `CreateCompatibleDC`, `GetDeviceCaps`, and `DeleteDC` through the existing eligible-module sweep and dynamic re-sweep path.
4. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, capture stacks, or copy arbitrary buffers.
5. The controlled sample calls deterministic system metric, desktop/foreground window, window thread/process, compatible DC, device-capability, and DC-delete operations without visible UI prompts, screenshots, screen pixels, clipboard access, input capture, or window-text reads.
6. `tools/native-smoke/wave3-user32-gdi32-smoke.ps1` verifies shared-memory `api_call` records for all selected APIs, generated UI/GDI metadata, numeric handle/PID/TID/metric evidence, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of text/pixel/clipboard/input/credential/byte-preview payload evidence.
7. The optional x86 smoke expectation now includes the same selected User32/GDI32 API slice after a Win32 helper/target/agent build.

Current verified Phase 13C behavior:

1. `definitions/win32/psapi.json` adds four low-payload Wave 3 PSAPI v1 API definitions with stable generated IDs `98` through `101`.
2. Generated metadata now covers `psapi.dll = 13` plus `module_handle_array_pointer` and `module_info_pointer` decode aliases.
3. The sample links `psapi.lib` with `PSAPI_VERSION=1`, so `EnumProcessModules`, `GetModuleInformation`, `GetModuleBaseNameW`, and `GetModuleFileNameExW` are imported from `psapi.dll` instead of silently mixing `K32*` provider names.
4. The agent installs IAT hooks for the selected PSAPI APIs through the existing eligible-module sweep and dynamic re-sweep path.
5. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, capture stacks, copy arbitrary buffers, parse PE metadata, hash module data, verify signatures, read module files, or dump full module lists.
6. The controlled sample queries only its own process with a tiny fixed module array, one selected module, `MODULEINFO`, and bounded local name/path buffers.
7. `tools/native-smoke/wave3-psapi-module-query-smoke.ps1` verifies shared-memory `api_call` records for all selected APIs, generated module metadata, bounded first-module handle evidence, `MODULEINFO` numeric evidence, module name/path strings, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of PE/module-memory/file/hash/signature/credential/byte-preview payload evidence.
8. The optional x86 smoke expectation now includes the same selected PSAPI module-query slice after a Win32 helper/target/agent build.

Current verified Phase 13D behavior:

1. `definitions/win32/version.json` adds three low-payload Wave 3 Version resource API definitions with stable generated IDs `102` through `104`.
2. Generated metadata now covers `version.dll = 14` plus `dword_value`, `version_info_buffer_pointer`, `version_info_value_pointer`, and `fixed_file_info_pointer` decode aliases.
3. The sample links `version.lib` and imports `GetFileVersionInfoSizeW`, `GetFileVersionInfoW`, and `VerQueryValueW` from `version.dll`.
4. The agent installs IAT hooks for the selected Version APIs through the existing eligible-module sweep and dynamic re-sweep path.
5. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, capture stacks, copy raw resource bytes, parse PE metadata, hash file data, verify signatures, read files directly, or capture string-table values.
6. The controlled sample queries `%SystemRoot%\System32\kernel32.dll` through `GetSystemDirectoryW`, uses a bounded local version-info buffer, calls root `VerQueryValueW`, and calls `\VarFileInfo\Translation` without querying arbitrary `StringFileInfo` values.
7. `tools/native-smoke/wave3-version-resource-smoke.ps1` verifies shared-memory `api_call` records for all selected APIs, generated resource metadata, path/size/pointer evidence, fixed-file-info numeric evidence, translation language/codepage evidence, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of raw-resource/string-table/PE/file/hash/signature/credential/byte-preview payload evidence.
8. The optional x86 smoke expectation now includes the same selected Version resource metadata slice after a Win32 helper/target/agent build.

Current verified Phase 13E behavior:

1. `definitions/win32/shell32.json` adds two low-payload Wave 3 Shell known-folder API definitions with stable generated IDs `105` through `106`.
2. Generated metadata now covers `shell32.dll = 15` plus `known_folder_id_pointer`, `csidl_value`, `shell_folder_path_pointer`, and `shell_folder_path_pointer_pointer` decode aliases.
3. The sample links `shell32.lib` and `ole32.lib`, imports `SHGetKnownFolderPath` and `SHGetSpecialFolderPathW` from `shell32.dll`, and uses `CoTaskMemFree` only to release `SHGetKnownFolderPath` output buffers.
4. The agent installs IAT hooks for the selected Shell APIs through the existing eligible-module sweep and dynamic re-sweep path.
5. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, capture stacks, walk PIDLs, query Shell namespaces, execute shell verbs, read files, expand environment variables, capture command lines, or copy arbitrary path buffers.
6. The controlled sample queries allowlisted `FOLDERID_Windows`, `FOLDERID_System`, `FOLDERID_ProgramFiles`, `CSIDL_WINDOWS`, `CSIDL_SYSTEM`, and `CSIDL_PROGRAM_FILES`, plus non-allowlisted Fonts queries to prove `non_allowlisted_no_path` suppression without printing or capturing returned Fonts paths.
7. `tools/native-smoke/wave3-shell-known-folder-smoke.ps1` verifies shared-memory `api_call` records for all selected APIs, generated Shell metadata, GUID/CSIDL/flag/handle/pointer evidence, allowlisted Windows/System/ProgramFiles path evidence, non-allowlisted path suppression, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of user-folder/AppData/command-line/environment/ShellExecute/PIDL/file-content/credential/byte-preview payload evidence.
8. The optional x86 smoke expectation now includes the same selected Shell known-folder metadata slice after a Win32 helper/target/agent build.

Current verified Phase 13F behavior:

1. `definitions/win32/ole32.json` adds four low-payload Wave 3 OLE32 COM lifecycle and GUID helper API definitions with stable generated IDs `107` through `110`.
2. Generated metadata now covers `ole32.dll = 16` plus `com_init_flags`, `guid_pointer`, and `guid_string_buffer_pointer` decode aliases.
3. The sample links `ole32.lib`, imports `CoInitializeEx`, `CoUninitialize`, `CoCreateGuid`, and `StringFromGUID2` from `ole32.dll`, and runs the COM lifecycle probe on a dedicated sample thread to avoid ambient apartment-state interference.
4. The agent installs IAT hooks for the selected OLE32 APIs through the existing eligible-module sweep and dynamic re-sweep path.
5. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, capture stacks, call COM APIs from inside hook wrappers, activate COM objects, inspect class factories/interfaces/vtables, decode marshaled payloads, enumerate monikers/ROT, read structured storage, capture clipboard/drag-drop data, or copy arbitrary buffers.
6. The controlled sample performs `CoInitializeEx(nullptr, COINIT_MULTITHREADED)`, `CoCreateGuid`, `StringFromGUID2` into a fixed 64-WCHAR stack buffer, and a balanced `CoUninitialize` only after successful initialization.
7. `tools/native-smoke/wave3-ole32-com-lifecycle-smoke.ps1` verifies shared-memory `api_call` records for all selected APIs, generated COM metadata, init flag/pointer/HRESULT/int return/GUID/GUID-string evidence, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of COM activation/object/interface/vtable/marshaling/storage/clipboard/drag-drop/user-path/credential/byte-preview payload evidence.
8. The optional x86 smoke expectation now includes the same selected OLE32 COM lifecycle metadata slice after a Win32 helper/target/agent build.

Current verified Phase 13G behavior:

1. `definitions/win32/rpcrt4.json` promotes existing `UuidCreate` API ID `58` to `iat` and `smoke_verified`, and adds `UuidToStringW` and `UuidFromStringW` with stable generated IDs `111` and `112`.
2. Generated metadata keeps `rpcrt4.dll` at module ID `7` and reuses the existing `guid_pointer`, `rpc_string_pointer`, and `utf16_string` decode aliases without adding a duplicate UUID alias.
3. The sample imports the UUID helpers from `rpcrt4.dll`, calls `UuidCreate`, converts the generated UUID with `UuidToStringW`, converts a fixed canonical string with `UuidFromStringW`, and releases the generated RPC string through the existing `RpcStringFreeW` path.
4. The agent installs IAT hooks for `UuidCreate`, `UuidToStringW`, and `UuidFromStringW` through the existing eligible-module sweep and dynamic re-sweep path.
5. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, call RPC helper APIs from hook wrappers, capture endpoint/auth/network/COM/object/marshaling evidence, capture sequential UUID node evidence, or copy arbitrary buffers.
6. The controller renders UUID pointer/status/value/string evidence in generated-metadata arguments while keeping `bufferPreview` empty for the UUID helper records.
7. `tools/native-smoke/wave3-rpcrt4-uuid-helper-smoke.ps1` verifies shared-memory `api_call` records for all selected UUID helper APIs, generated RPC metadata, stable ID `58` promotion plus IDs `111` and `112`, canonical UUID evidence, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of endpoint/auth/network/COM/credential/path/byte-preview payload evidence.
8. The optional x86 smoke expectation now includes the same selected RPCRT4 UUID helper slice after a Win32 helper/target/agent build.

Current verified Phase 13H behavior:

1. `definitions/win32/api-ms-win-core-winrt-l1-1-0.json` adds three low-payload COMBASE-backed WinRT lifecycle API definitions with stable generated IDs `113` through `115`.
2. Generated metadata now covers `api-ms-win-core-winrt-l1-1-0.dll = 17` plus `ro_init_type` and `uint64_pointer` decode aliases.
3. `dumpbin` provider inspection verified that the controlled sample imports `RoInitialize`, `RoUninitialize`, and `RoGetApartmentIdentifier` through `api-ms-win-core-winrt-l1-1-0.dll`; documentation describes the implementation as COMBASE-backed while hooks target the observed API-set provider.
4. The sample links `runtimeobject.lib`, imports the selected WinRT lifecycle APIs, and runs the WinRT probe on a dedicated sample thread with `RoInitialize(RO_INIT_MULTITHREADED)`, `RoGetApartmentIdentifier`, and balanced `RoUninitialize` without activation factories, HSTRING creation, or runtime class names.
5. The agent installs IAT hooks for the observed API-set provider through the existing eligible-module sweep and dynamic re-sweep path.
6. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, call WinRT/COM helper APIs from hook wrappers, activate classes, inspect HSTRING/runtime-class/error-info data, inspect COM objects/interfaces/vtables, decode marshaled payloads, or copy arbitrary buffers.
7. The controller renders init type, HRESULT/void return semantics, output pointer, and decoded `UINT64` apartment identifier evidence in generated-metadata arguments while keeping `bufferPreview` empty for the selected WinRT lifecycle records.
8. `tools/native-smoke/wave3-combase-winrt-lifecycle-smoke.ps1` verifies shared-memory `api_call` records for all selected WinRT lifecycle APIs, generated COM metadata, provider and stable ID evidence, init type/HRESULT/void/apartment-id evidence, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of activation/HSTRING/runtime-class/restricted-error-info/COM object/marshaling/user-path/credential/byte-preview payload evidence.
9. The optional x86 smoke expectation now includes the same selected COMBASE-backed WinRT lifecycle slice after a Win32 helper/target/agent build.

Current verified Phase 13I behavior:

1. `definitions/win32/memory.json` adds four low-payload KERNEL32 current-process memory allocation/protection/query API definitions with stable generated IDs `116` through `119`.
2. Generated metadata now covers memory allocation/free/protection/state/type flag aliases plus `memory_basic_information_pointer` decode metadata while keeping `kernel32.dll` at module ID `1`.
3. `dumpbin` provider inspection verified that the controlled sample imports `VirtualAlloc`, `VirtualFree`, `VirtualProtect`, and `VirtualQuery` through `kernel32.dll`.
4. The sample reserves and commits a small current-process region, writes a single local byte before protection changes, switches one page to `PAGE_READONLY`, queries `MEMORY_BASIC_INFORMATION`, and releases the region.
5. The agent installs IAT hooks for the selected memory APIs through the existing eligible-module sweep and dynamic re-sweep path.
6. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, capture stacks, copy memory contents, inspect remote process memory, call injection helpers, dump module memory, parse PE data, or emit arbitrary buffers.
7. The controller renders allocation/free/protection flags, old-protection output, state/type flags, and `MEMORY_BASIC_INFORMATION` metadata in generated-metadata arguments while keeping `bufferPreview` empty for the selected memory records.
8. `tools/native-smoke/wave3-kernel32-memory-protection-smoke.ps1` verifies shared-memory `api_call` records for all selected memory APIs, generated memory metadata, stable ID evidence, allocation/free/protection/state/type flag decoding, decoded `MEMORY_BASIC_INFORMATION` metadata, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of remote-memory/injection/file/PE/hash/credential/byte-preview payload evidence.
9. The optional x86 smoke expectation now includes the same selected KERNEL32 memory protection slice after a Win32 helper/target/agent build.

Current verified Phase 13J behavior:

1. `definitions/win32/threading.json` adds four low-payload KERNEL32 current-process thread lifecycle/wait API definitions with stable generated IDs `120` through `123`.
2. Generated metadata now covers `thread_access_flags`, `thread_creation_flags`, `wait_timeout_ms`, `wait_result`, `thread_id_pointer`, `thread_exit_code_pointer`, and `thread_start_routine_pointer` decode metadata while keeping `kernel32.dll` at module ID `1`.
3. `dumpbin` provider inspection verified that the controlled x64/x86 samples import `CreateThread`, `OpenThread`, `WaitForSingleObject`, and `GetExitCodeThread` through `kernel32.dll`; the deterministic thread probe returns `0x2A`.
4. The agent installs IAT hooks for the selected thread lifecycle APIs through the existing eligible-module sweep and dynamic re-sweep path.
5. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, capture stacks, inspect thread context, suspend/resume/terminate threads, queue APCs, create remote threads, or emit arbitrary buffers.
6. The controller renders thread access flags, creation flags, wait timeout/result values, output thread IDs, and output exit-code metadata in generated-metadata arguments while keeping `bufferPreview` empty for the selected thread records.
7. `tools/native-smoke/wave3-kernel32-thread-lifecycle-smoke.ps1` verifies shared-memory `api_call` records for all selected thread APIs, generated thread metadata, stable ID evidence, thread ID/output exit-code decoding, wait-result decoding, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of remote-thread/APC/context/stack/injection/credential/byte-preview payload evidence.
8. The optional x86 smoke expectation now includes the same selected KERNEL32 thread lifecycle slice after a Win32 helper/target/agent build.

Current verified Phase 13K behavior:

1. `definitions/win32/synchronization.json` adds five low-payload KERNEL32 current-process event synchronization API definitions with stable generated IDs `124` through `128`.
2. Generated metadata now covers `event_access_flags`, `event_manual_reset_bool`, `event_initial_state_bool`, `event_name_pointer`, and `wait_alertable_bool` decode metadata, reuses existing wait timeout/result metadata, and keeps `kernel32.dll` at module ID `1`.
3. `dumpbin` provider inspection verified that the controlled x64/x86 samples import `CreateEventW`, `OpenEventW`, `SetEvent`, `ResetEvent`, and `WaitForSingleObjectEx` through `kernel32.dll`.
4. The sample creates a uniquely named manual-reset current-process event, opens it with `EVENT_MODIFY_STATE | SYNCHRONIZE`, signals it, waits for `WAIT_OBJECT_0` with `WaitForSingleObjectEx(..., 1000, FALSE)`, resets it, and closes both handles without logging or capturing the event name.
5. The agent installs IAT hooks for the selected event synchronization APIs through the existing eligible-module sweep and dynamic re-sweep path.
6. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, copy event names, decode object-manager namespaces, inspect security descriptors, query wait chains, inspect APC queues, capture thread context/stacks, call injection helpers, or emit arbitrary buffers.
7. The controller renders event handles, BOOL flags, desired-access flags, wait timeout/result values, return/error evidence, and pointer-only name evidence in generated-metadata arguments while keeping `bufferPreview` empty for the selected event synchronization records.
8. `tools/native-smoke/wave3-kernel32-event-sync-smoke.ps1` verifies shared-memory `api_call` records for all selected event synchronization APIs, generated synchronization metadata, stable ID evidence, event access/BOOL/wait decoding, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of event-name/object-namespace/security/APC/wait-chain/context/stack/injection/credential/byte-preview payload evidence.
9. The optional x86 smoke expectation now includes the same selected KERNEL32 event synchronization slice after a Win32 helper/target/agent build.

Current verified Phase 13L behavior:

1. `definitions/win32/synchronization.json` adds seven low-payload KERNEL32 current-process mutex/semaphore synchronization API definitions with stable generated IDs `129` through `135`.
2. Generated metadata now covers `mutex_access_flags`, `mutex_initial_owner_bool`, `semaphore_access_flags`, `semaphore_count_value`, `semaphore_previous_count_pointer`, `sync_object_name_pointer`, `wait_handle_array_pointer`, and `wait_all_bool` decode metadata while keeping `kernel32.dll` at module ID `1`.
3. `dumpbin` provider inspection verified that the controlled x64/x86 samples import `CreateMutexW`, `OpenMutexW`, `ReleaseMutex`, `CreateSemaphoreW`, `OpenSemaphoreW`, `ReleaseSemaphore`, and `WaitForMultipleObjectsEx` through `kernel32.dll`.
4. The sample creates and opens a uniquely named current-process mutex, waits on it with `WaitForSingleObject(..., 1000)`, releases it, creates and opens a uniquely named semaphore, releases one count with decoded previous-count `0`, waits for `WAIT_OBJECT_0` with `WaitForMultipleObjectsEx(..., 1000, FALSE)`, and closes all handles without logging or capturing object names.
5. The agent installs IAT hooks for the selected mutex/semaphore APIs through the existing eligible-module sweep and dynamic re-sweep path.
6. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, copy object names, decode object-manager namespaces, copy handle-array contents, inspect security descriptors, query wait chains, inspect APC queues, capture thread context/stacks, call injection helpers, or emit arbitrary buffers.
7. The controller renders mutex/semaphore handles, BOOL flags, desired-access flags, semaphore counts, decoded previous count, handle-array pointer-only evidence, multi-wait timeout/result values, return/error evidence, and pointer-only object-name evidence in generated-metadata arguments while keeping `bufferPreview` empty for the selected mutex/semaphore records.
8. `tools/native-smoke/wave3-kernel32-mutex-semaphore-smoke.ps1` verifies shared-memory `api_call` records for all selected mutex/semaphore APIs, generated synchronization metadata, stable ID evidence, mutex/semaphore access/BOOL/count/multi-wait decoding, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of object-name/object-namespace/security/handle-array/APC/wait-chain/context/stack/injection/credential/byte-preview payload evidence.
9. The optional x86 smoke expectation now includes the same selected KERNEL32 mutex/semaphore synchronization slice after a Win32 helper/target/agent build.

Current verified Phase 13M behavior:

1. `definitions/win32/memory.json` adds four low-payload KERNEL32 current-process file-mapping API definitions with stable generated IDs `136` through `139`.
2. Generated metadata now covers `file_mapping_protection_flags`, `file_mapping_access_flags`, `file_mapping_size_high`, `file_mapping_size_low`, `file_mapping_offset_high`, `file_mapping_offset_low`, `file_mapping_view_size`, `file_mapping_name_pointer`, and `mapped_view_pointer` decode metadata while keeping `kernel32.dll` at module ID `1`.
3. `dumpbin` provider inspection verified that the controlled x64/x86 samples import `CreateFileMappingW`, `OpenFileMappingW`, `MapViewOfFile`, and `UnmapViewOfFile` through `kernel32.dll`.
4. The sample creates a uniquely named pagefile-backed mapping, opens it, maps a 4096-byte view, writes one local byte, unmaps the view, and closes mapping handles without logging or copying the mapping name or view contents.
5. The agent installs IAT hooks for the selected file-mapping APIs through the existing eligible-module sweep and dynamic re-sweep path.
6. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, copy mapping names, decode object-manager namespaces, inspect security descriptors, copy mapped memory contents, read files, parse PE/module metadata, query remote memory, capture thread context/stacks, call injection helpers, or emit arbitrary buffers.
7. The controller renders file/mapping handles, pointer-only security/name evidence, protection/access flags, size/offset values, mapped view pointers, return/error evidence, and timing metadata in generated-metadata arguments while keeping `bufferPreview` empty for the selected file-mapping records.
8. `tools/native-smoke/wave3-kernel32-file-mapping-smoke.ps1` verifies shared-memory `api_call` records for all selected file-mapping APIs, generated memory metadata, stable ID evidence, file-mapping protection/access/size/offset/view-pointer decoding, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of mapping-name/object-namespace/mapped-memory/security/stack/injection/PE/file/hash/credential/byte-preview payload evidence.
9. The optional x86 smoke expectation now includes the same selected KERNEL32 file-mapping slice after a Win32 helper/target/agent build.

Current verified Phase 13N behavior:

1. `definitions/win32/process.json` adds six low-payload KERNEL32 process/thread identity API definitions with stable generated IDs `140` through `145`.
2. Generated metadata now covers `process_handle_value`, `process_id_value`, `thread_handle_value`, and `thread_id_value` decode metadata while keeping `kernel32.dll` at module ID `1`.
3. `dumpbin` provider inspection verified that the controlled x64/x86 samples import `GetCurrentProcess`, `GetCurrentProcessId`, `GetCurrentThread`, `GetCurrentThreadId`, `GetProcessId`, and `GetThreadId` through `kernel32.dll`.
4. The sample probes pseudo/current process and thread handles, direct PID/TID values, and handle-derived PID/TID values, then verifies nonzero IDs and direct/handle-derived matches without using `OpenProcess`, `OpenThread`, `DuplicateHandle`, `CreateProcessW`, remote memory, APC, context, command-line, environment, or process enumeration APIs for this probe.
5. The agent installs IAT hooks for the selected process/thread identity APIs through the existing eligible-module sweep and dynamic re-sweep path.
6. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, enumerate processes or threads, copy command lines or environment blocks, expand token/security capture, inspect remote memory, capture thread context/stacks, inspect modules/PE data, read files, hash data, call injection helpers, or emit arbitrary buffers.
7. The controller renders pseudo/current handles with pointer formatting and PID/TID values as decimal plus hex while keeping `bufferPreview` empty for the selected process/thread identity records.
8. `tools/native-smoke/wave3-kernel32-process-thread-identity-smoke.ps1` verifies shared-memory `api_call` records for all selected identity APIs, generated process metadata, stable ID evidence, PID/TID match evidence, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of process enumeration, command-line, environment, token/security, remote-memory, remote-thread, stack, injection, PE/file/hash, credential, or byte-preview payload evidence.
9. The optional x86 smoke expectation now includes the same selected KERNEL32 process/thread identity slice after a Win32 helper/target/agent build.

Current verified Phase 13O behavior:

1. `definitions/win32/handle.json` adds four low-payload KERNEL32 current-process handle metadata API definitions with stable generated IDs `146` through `149`.
2. Generated metadata now covers `std_handle_selector`, `file_type_value`, `handle_information_flags`, `handle_information_flags_pointer`, and `handle_information_mask` decode metadata while keeping `kernel32.dll` at module ID `1`.
3. `dumpbin` provider inspection verified that the controlled x64/x86 samples import `GetStdHandle`, `GetFileType`, `GetHandleInformation`, and `SetHandleInformation` through `kernel32.dll`.
4. The sample probes `STD_OUTPUT_HANDLE` for selector coverage, then uses a deterministic temp-file handle for `GetFileType`, `GetHandleInformation`, `SetHandleInformation`, and a follow-up `GetHandleInformation` without requiring the standard handle to be valid in every host context.
5. The agent installs IAT hooks for the selected handle metadata APIs through the existing eligible-module sweep and dynamic re-sweep path.
6. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, duplicate handles, enumerate system handles, query object names, inspect security descriptors, copy file/pipe/console payloads, inspect command lines or environments, inspect remote memory, capture thread context/stacks, inspect modules/PE data, read files, hash data, call injection helpers, or emit arbitrary buffers.
7. The controller renders standard-handle selectors, file types, handles, handle flag masks, output flag DWORDs, return/error evidence, and timing metadata while keeping `bufferPreview` empty for the selected handle metadata records.
8. `tools/native-smoke/wave3-kernel32-handle-metadata-smoke.ps1` verifies shared-memory `api_call` records for all selected handle metadata APIs, generated handle metadata, stable ID evidence, file-type and handle-flag decoding, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of object-name, security, handle-duplication, system-handle, file/pipe/console payload, command-line, environment, remote-memory, remote-thread, stack, injection, PE/file/hash, credential, or byte-preview evidence.
9. The optional x86 smoke expectation now includes the same selected KERNEL32 handle metadata slice after a Win32 helper/target/agent build.

Current verified Phase 13P behavior:

1. `definitions/win32/module.json` adds four low-payload KERNEL32 current-process module lifecycle API definitions with stable generated IDs `150` through `153`.
2. Generated metadata now covers `module_lookup_name`, `get_module_handle_ex_flags`, and `module_file_name_buffer_pointer` decode metadata while reusing existing module-handle aliases and keeping `kernel32.dll` at module ID `1`.
3. `dumpbin` provider inspection verified that the controlled x64/x86 samples import `GetModuleHandleW`, `GetModuleHandleExW`, `GetModuleFileNameW`, and `FreeLibrary` through `kernel32.dll`.
4. The sample loads `version.dll`, verifies `GetModuleHandleW` and `GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, ...)` return the expected module handle, captures a bounded `GetModuleFileNameW` output path, and calls `FreeLibrary` exactly once without freeing borrowed handles.
5. The agent installs IAT hooks for the selected module lifecycle APIs through the existing eligible-module sweep and dynamic re-sweep path.
6. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, enumerate remote modules, dump loaded-module lists, inspect module memory, parse PE headers or directories, hash files, validate signatures, inspect command lines or environments, inspect remote memory, capture thread context/stacks, force unload/reference-count probe behavior, call injection helpers, or emit arbitrary buffers.
7. The controller renders module-name input strings, `GetModuleHandleExW` flags, module handles, bounded module path output, return/error evidence, and timing metadata while keeping `bufferPreview` empty for the selected module lifecycle records.
8. `tools/native-smoke/wave3-kernel32-module-lifecycle-smoke.ps1` verifies shared-memory `api_call` records for all selected module lifecycle APIs, generated module metadata, stable ID evidence, module handle/path decoding, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of module memory, PE/header/import/export/resource/relocation/debug, file hash/signature, module enumeration, command-line, environment, remote-memory, remote-thread, stack, injection, credential, or byte-preview evidence.
9. The optional x86 smoke expectation now includes the same selected KERNEL32 module lifecycle slice after a Win32 helper/target/agent build.

Current verified Phase 13Q behavior:

1. `definitions/win32/file-metadata.json` adds three low-payload KERNEL32 current-process file metadata API definitions with stable generated IDs `154` through `156`.
2. Generated metadata now covers `file_size_pointer`, `file_time_pointer`, and `by_handle_file_information_pointer` decode metadata while reusing the existing `handle` alias and keeping `kernel32.dll` at module ID `1`.
3. `dumpbin` provider inspection verified that the controlled x64/x86 samples import `GetFileSizeEx`, `GetFileTime`, and `GetFileInformationByHandle` through `kernel32.dll`.
4. The sample writes deterministic small content to a sample-owned temp file, probes file size, file time, and basic `BY_HANDLE_FILE_INFORMATION` scalar metadata, then validates only size, non-directory attribute, and nonzero link-count invariants without reading file contents, resolving paths, enumerating directories, or querying object names.
5. The agent installs IAT hooks for the selected file metadata APIs through the existing eligible-module sweep and dynamic re-sweep path.
6. Hook fast paths stay on fixed-size shared-memory records and do not serialize JSON, write API events to the named pipe, allocate heap-heavy payloads, copy file contents, enumerate directories, resolve paths, query object names, inspect PE metadata, hash files, validate signatures, duplicate handles, inspect security descriptors, inspect command lines or environments, inspect remote memory, capture thread context/stacks, call injection helpers, or emit arbitrary buffers.
7. The controller renders file handles, output pointers, decoded file size, FILETIME scalar values, file attributes, volume serial, link count, file index, return/error evidence, and timing metadata while keeping `bufferPreview` empty for the selected file metadata records.
8. `tools/native-smoke/wave3-kernel32-file-metadata-smoke.ps1` verifies shared-memory `api_call` records for all selected file metadata APIs, generated file metadata, stable ID evidence, scalar decoding, zero healthy-path transport drops, `restoredHooks=installedHooks`, `failedHooks=0`, and absence of file content, path/name, directory, object-namespace, security, remote-memory, remote-thread, stack, injection, PE/file/hash, credential, or byte-preview evidence.
9. The optional x86 smoke expectation now includes the same selected KERNEL32 file metadata slice after a Win32 helper/target/agent build.

Current verified Wave 2 Winsock connect behavior:

1. `definitions/win32/ws2_32.json` promotes the existing `connect` definition at stable API ID `63` to `hookPolicy: "iat"` and `coverageStatus: "smoke_verified"` without allocating a new ID.
2. Generated metadata keeps `ws2_32.dll` at module ID `8` and reuses the existing `socket_handle`, `sockaddr`, and `byte_count` decode aliases for controller rendering.
3. `dumpbin` provider inspection verifies that the controlled x64 and x86 samples import `connect` through `WS2_32.dll` as ordinal `4`; the agent hook definition therefore matches both by name and explicit ordinal.
4. The sample creates a local loopback listener with `bind`, `getsockname`, `listen`, `connect`, and `accept`, then closes both sockets without calling `send`, `recv`, `sendto`, or `recvfrom`.
5. The agent records `connect` through the existing eligible-module IAT sweep and dynamic re-sweep path.
6. The hook fast path emits a fixed shared-memory record with socket handle, raw `sockaddr` pointer, `namelen`, decoded AF_INET loopback endpoint, return/error/timing, and hook lifecycle evidence only.
7. The controller renders `s`, `name`, and `namelen` arguments with generated metadata and keeps `bufferPreview` empty for `connect`.
8. `tools/native-smoke/wave2-winsock-smoke.ps1` verifies stable module/API IDs, shared-memory events for the selected Winsock slice including `connect`, decoded loopback endpoint evidence, empty payload previews, zero healthy-path drops, and no HTTP/body/header/cookie/credential/network-inventory/remote-memory/thread/stack/injection evidence.
9. The optional x86 smoke expectation now includes the same selected Winsock `connect` metadata slice after a Win32 helper/target/agent build.

Current verified Wave 2 RPCRT4 binding option behavior:

1. `definitions/win32/rpcrt4.json` promotes the existing `RpcBindingSetOption` definition at stable API ID `54` to `hookPolicy: "iat"` and `coverageStatus: "smoke_verified"` without allocating a new ID.
2. Generated metadata keeps `rpcrt4.dll` at module ID `7` and reuses existing RPC binding and scalar decode aliases for controller rendering.
3. `dumpbin` provider inspection verifies that the controlled x64 and x86 samples import `RpcBindingSetOption` through `RPCRT4.dll`.
4. The sample calls `RpcBindingSetOption(binding, RPC_C_OPT_CALL_TIMEOUT, 5000)` after `RpcBindingFromStringBindingW` and before `RpcBindingFree` on the local `ncalrpc` binding path.
5. The agent records `RpcBindingSetOption` through the existing eligible-module IAT sweep and dynamic re-sweep path.
6. The hook fast path emits a fixed shared-memory record with binding handle, option ID, scalar option value, `RPC_STATUS` return, timing, and hook lifecycle evidence only.
7. The controller renders `hBinding`, `option`, and `optionValue` arguments with generated metadata and keeps `bufferPreview` empty for `RpcBindingSetOption`.
8. `tools/native-smoke/wave2-rpcrt4-binding-smoke.ps1` verifies stable module/API IDs, shared-memory events for the selected RPCRT4 binding lifecycle plus binding option slice, decoded option `12` and value `5000`, empty payload previews, zero healthy-path drops, and no RPC auth, endpoint mapper, credential, network payload, RPC server communication, remote-memory, thread, stack, injection, or byte-preview evidence.
9. The optional x86 smoke expectation now includes the same selected RPCRT4 binding option metadata slice after a Win32 helper/target/agent build.

Current verified Wave 2 WinHTTP scalar option behavior:

1. `definitions/win32/winhttp.json` promotes the existing `WinHttpSetOption` definition at stable API ID `89` to `hookPolicy: "iat"` and `coverageStatus: "smoke_verified"` without allocating a new ID.
2. Generated metadata keeps `winhttp.dll` at module ID `10` and adds narrow WinHTTP option ID and option-buffer pointer aliases for controller rendering.
3. `dumpbin` provider inspection verifies that the controlled x64 and x86 samples import `WinHttpOpen`, `WinHttpSetOption`, and `WinHttpCloseHandle` through `WINHTTP.dll`.
4. The sample calls `WinHttpSetOption(session, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeoutMs, sizeof(timeoutMs))` with `timeoutMs = 5000` after `WinHttpOpen` and before `WinHttpCloseHandle`, without opening a connection, request, or transfer.
5. The agent records `WinHttpSetOption` through the existing eligible-module IAT sweep and dynamic re-sweep path.
6. The hook fast path emits a fixed shared-memory record with WinHTTP handle, option ID, option-buffer pointer, option-buffer length, decoded allowlisted DWORD scalar value, BOOL return, last-error/timing, and hook lifecycle evidence only.
7. The controller renders `hInternet`, `dwOption`, `lpBuffer`, and `dwBufferLength` arguments with generated metadata and keeps `bufferPreview` empty for `WinHttpSetOption`.
8. `tools/native-smoke/wave2-winhttp-option-smoke.ps1` verifies stable module/API IDs, shared-memory events for the selected WinHTTP session plus scalar option slice, decoded `WINHTTP_OPTION_RECEIVE_TIMEOUT` and value `5000`, empty payload previews, zero healthy-path drops, and no connection/request/transfer/header/body/cookie/credential/proxy-credential/raw-option-buffer/remote-memory/thread/stack/injection evidence.
9. The optional x86 smoke expectation now includes the same selected WinHTTP scalar option metadata slice after a Win32 helper/target/agent build.

Current verified Phase 12A behavior:

1. The React UI has a catalog-backed replay browser that surfaces path, target image/PID, session id, validation status, recovery state, compression, event count, byte totals, and last validation UTC.
2. Catalog controls can rebuild, query by state/target/limit, dry-run missing-row removal, and apply missing-row pruning through the existing Tauri wrappers.
3. Catalog row replay is explicit: selecting a row only records UI selection, while `Replay` calls `replay_session_path` for that row and records replay source/status/path in output.
4. Missing, corrupt, invalid, or empty replay results clear stale trace selection and report output events instead of leaving an old replay visible as current data.
5. The trace table uses a local virtual row-window helper so DOM row count stays bounded while display filters, row selection, inspector tabs, and full-session JSONL export continue to use the full event array.
6. `tools/ui-validator/validate-virtual-trace-window.mjs` covers empty, top, middle, and clamped-bottom virtual trace window calculations and is included in `npm run verify`.

Current verified Phase 12B behavior:

1. The React UI has a structured trace query builder with `all`/`any` match modes and clauses for API, module, process, PID, TID, tag, return value, error, argument text, duration, and decode status.
2. Query operators cover contains, equals, not equals, starts with, exists, missing, greater than, and less than, with invalid or incomplete clauses highlighted and ignored rather than crashing the UI.
3. The existing free-text display filter is combined with structured query predicates before the virtualized trace window, so query results still keep bounded DOM rows.
4. The error-focused view groups error code/message, erroring module/API pairs, argument decode failures, and high-duration API calls over the current in-memory trace events.
5. Clicking an issue group replaces the structured query with the matching clauses, clears the free-text filter, selects a representative event, and reuses the existing inspector/output state.
6. Full-session JSONL export still uses the complete current event array, not the query-filtered or visible virtual row subset.
7. `tools/ui-validator/validate-trace-query.mjs` covers structured query matching, invalid-clause handling, free-text matching, and issue group construction and is included in `npm run ui:validate`.

Current verified Phase 12C behavior:

1. The React UI has `Threads` and `Timeline` trace modes beside `Flat`, `Call Tree`, and `Errors`.
2. Thread groups are built UI-side from the current trace events by process, PID, and TID, with event counts, first/last relative time, span, error count, decode-failure count, slow-call count, top modules/APIs, and representative samples.
3. Timeline buckets are built UI-side from deterministic relative-time bucket sizes, with event counts, error/decode/slow metrics, dominant API/module, and representative samples.
4. Clicking a thread group or timeline bucket replaces the structured query clauses, clears the free-text filter, selects a representative event, and reuses the existing inspector/output state.
5. Timeline narrowing uses the existing query engine with the added `relativeTimeMs` UI-side field; no helper, agent, transport, or `.knapm` schema changes are required.
6. Summary panels keep bounded DOM rows while the main trace table remains virtualized and full-session JSONL export remains based on the complete event array.
7. `tools/ui-validator/validate-trace-views.mjs` covers empty sessions, single-event sessions, multiple threads, error/decode/slow metrics, deterministic bucket sizing, and query clauses and is included in `npm run ui:validate`.

Current verified Phase 12D behavior:

1. The React UI has a bounded `Highlight Rules` summary over the current in-memory trace events, with a global row-highlighting toggle.
2. `apps/knmon-ui/src/traceHighlights.ts` builds deterministic event highlight matches, event-id lookup maps, per-rule summaries, severity ordering, representative samples, and query clauses without new dependencies.
3. Built-in rules identify error returns, argument decode failures, slow calls using the current threshold, high-signal API-family coverage hints, and missing/unknown module or API metadata.
4. Flat trace rows keep the existing virtualized row window while adding compact severity markers and rule badges for highlighted events.
5. The selected-event inspector shows matched rule labels, severities, and reasons before the normal parameter/buffer/stack/return/output tab content.
6. Clicking a non-empty rule summary selects a representative event and narrows through existing structured query clauses when the rule can be represented by the current query model.
7. Highlighting is UI-side only; it does not add helper calls, target work, injected-agent work, transport changes, or `.knapm` schema changes.
8. `tools/ui-validator/validate-trace-highlights.mjs` covers empty sessions, no-match sessions, error/decode/slow/metadata/coverage matches, multiple rules on one event, severity ordering, threshold changes, summary counts, and generated query clauses and is included in `npm run ui:validate`.

Next implementation focus:

1. Resume small, low-volume system DLL coverage waves only when each slice has deterministic smoke evidence, generated metadata, and transport/hook-overhead gates.
2. Prefer another low-payload handle/lifecycle or explicitly reviewed metadata slice before payload-heavy network, crypto key material, certificate chain decode, service-control, token mutation, RPC auth/endpoint work, UI/GDI payload capture, raw resource capture, Shell payload capture, COM/WinRT activation/object/marshaling/HSTRING/runtime-class/error-info capture, memory-content capture, remote process memory APIs, remote thread/APC/context capture, injection helper capture, or module memory/PE payload capture.
3. Keep automatic daemon crash recovery and orphaned active-agent repair behind separate design reviews; use the Phase 11N dry-run operator runbooks as the review input.
4. Keep Windows service mode, protected/PPL, cross-bitness, stealth/manual-map, and privilege-elevation paths as explicit non-goals unless a separate design review changes the boundary.

## Remaining Roadmap Review

Status: refreshed on 2026-06-20 after low-payload RPCRT4 endpoint inquiry cleanup promotion and manual-decoder batch gate regeneration.

Current definition coverage:

1. Total APIs: 179.
2. `smoke_verified`: 126.
3. `hooked`: 4.
4. `definition_only`: 49.
5. Microsoft-source inventory: 18,086 APIs, with 130 Tier 0 rows, 15,931 Tier 1 rows, 655 Tier 2 rows, and 1,370 Tier 3 rows.
6. Tier 2 hook plan: 279 API-set forwarders, 277 resolved host rows, 376 missing-parameter return-only rows, and zero hooks enabled by default.
7. Tier 2 profile batch plan: 104 review batches, with 16 resolved-host API-set batches, 87 missing-parameter return-only source-DLL batches, 1 blocked unresolved API-set batch, 30 explicit-allowlist-required APIs, and zero hooks enabled by default.
8. Tier 2 profile review manifest: 42 initial-candidate batches covering 55 APIs, 41 broader review-ready batches covering 452 APIs, 20 allowlist-gated batches covering 146 APIs with 30 explicit-allowlist-required APIs, 1 blocked batch covering 2 APIs, and zero hooks enabled by default.
9. DLL batch promotion plan: 25 DLLs, 130 already-live APIs, zero auto-promotable pointer/scalar APIs, zero manual-decoder-required APIs, 49 payload-policy-blocked APIs, and zero broad hooks enabled by default.
10. Manual decoder batch plan: zero DLLs, zero manual-decoder-required APIs, and zero runtime hooks enabled by default.

Safe implementation queue:

1. Injection preflight hardening for supported same-bitness paths:
   - Attach preflight keeps typed pre-mutation diagnostics for unsupported protected/PPL, architecture mismatch, missing helper/agent, access-denied, mitigation-policy conflict, stale/exited PID, and PID identity-change states.
   - Attach preflight now checks process signature mitigation policy where available and fails as `mitigation_policy_conflict` before remote mutation when the target requires Microsoft- or Store-signed images.
   - Recent hardening adds process creation-time identity comparison between query and full attach handles, plus signaled-process checks before remote writes/thread creation.
   - Keep all unsupported outcomes before remote memory writes, thread/APC/context mutation, or helper-side attach mutation.
2. Host-side event-level replay indexing and full-text trace search:
   - Implemented as Phase 13R with separate `trace-index-*` commands, `winsqlite3-fts5`, Tauri wrappers, UI trace search controls, explicit replay-by-path from hits, and focused smoke coverage.
   - Keep future enhancements replay-data-only unless a separate design review changes the boundary.
3. Daemon crash recovery and orphan repair:
   - Dry-run host-side registry classification and operator runbooks are implemented as Phase 11N through `daemon-recovery-plan`.
   - Registry-only recovery apply is implemented as Phase 11O through dry-run-by-default `daemon-recovery-apply` plus explicit `--apply-registry-prune` for records already marked `registryPruneAllowed=true`.
   - Actual automatic recovery, writer restart, agent unload, reinjection repair, target kill/restart, and orphaned active-agent repair remain blocked until recovery invariants are separately proven.
4. Continue low-payload metadata slices only when the candidate API family has bounded scalar/pointer outputs, deterministic sample probes, x64/x86 smoke evidence, zero healthy-path drops, and no sensitive payload capture.
5. Expand Tier 2 only through explicit opt-in selectors:
   - API-set forwarders require resolved host evidence and target import/provider verification.
   - Missing-parameter APIs remain return-only unless a reviewed manual definition adds safe argument metadata.
   - High-risk Tier 2 rows require explicit allowlist or risk override before installation.
   - Broader Tier 2 work must start from `generated/tier2-profile-review-manifest.json` initial-candidate or review-ready batches, with source evidence from `generated/tier2-profile-batch-plan.json` and optional previews from `defs:tier2-profile-batch-plan:select`; do not use raw all-Tier-2 selectors.
   - Representative native smokes must prove at least one API-set generic event, one return-only event, and preserved resolver visibility before adding broader profiles.
6. Use the DLL batch promotion plan as the default promotion queue:
   - Auto-promotable APIs must be implemented by DLL batch, not as isolated unrelated one-offs.
   - The auto-promotable and manual-decoder queues are currently empty after the RPCRT4 endpoint inquiry cleanup promotion.
   - Any future manual-decoder runtime hook must satisfy a generated allowed/forbidden evidence boundary, x64/x86 smoke, payload absence, and overhead gates before promotion.

Remaining definition-only expansion queue:

1. Wave 4 now has stable metadata for `oleaut32.dll`, `secur32.dll`, `userenv.dll`, `dnsapi.dll`, `iphlpapi.dll`, `setupapi.dll`, `shlwapi.dll`, `wintrust.dll`, and `dbghelp.dll`; `SysFreeString`, `VariantClear`, and `SafeArrayDestroy` are already promoted to low-payload OLEAUT32 lifecycle hooks, `FreeCredentialsHandle` and `DeleteSecurityContext` are promoted to low-payload SECUR32 credential/context cleanup coverage, `DestroyEnvironmentBlock` is promoted to low-payload USERENV environment-block destroy coverage, `DnsRecordListFree` is promoted to low-payload DNSAPI record-list free coverage through the modern `DnsFree` import provider, `GetAdaptersAddresses` and `GetIfEntry2` are promoted to low-payload IPHLPAPI adapter/interface metadata coverage, `SetupDiDestroyDeviceInfoList` is promoted to low-payload SETUPAPI device-info close coverage, `PathFileExistsW` is promoted to low-payload SHLWAPI pointer-only path-exists query coverage, `WTHelperProvDataFromStateData` is promoted to low-payload WINTRUST state-query coverage, and `SymInitializeW`/`SymCleanup` are already promoted to low-payload DbgHelp symbol-session hooks. `SysAllocString` remains `definition_only` because its input can carry BSTR text, `AcquireCredentialsHandleW` remains `definition_only` because it can carry principals, package names, auth data, and logon IDs, `InitializeSecurityContextW` remains `definition_only` because it can carry target names and SSPI security buffers/context tokens, `PathCombineW` remains `definition_only` because it can produce or carry path text, and `WinVerifyTrust` remains `definition_only` because it can validate/mutate trust state and carry file/action/provider data.
2. The remaining unselected Wave 4 APIs stay `definition_only` until each family has a hook ABI review, provider/import verification, sample design, payload-safety boundaries, and performance gate.
3. Good first live candidates are low-volume lifecycle/query calls whose hooks can emit scalar handles, flags, return values, and pointer-only evidence without copying arbitrary payload buffers. The generated DLL batch and manual-decoder plans currently have no promotable runtime batches; future runtime expansion should start from a `generated/tier2-profile-review-manifest.json` initial-candidate batch, a reviewed payload-sensitive family plan, or a Tier 3 design slice.
4. Tier 2 API-set forwarders should be grouped by resolved host DLL and profile through the review manifest before implementation; do not add broad API-set hooks just because the host module resolves on the current OS.
5. Tier 3 rows now have a generated planning artifact but remain design-only. COM payloads, object internals, callback payloads, UI text, pixels, raw buffers, credentials, remote memory, injection helper payloads, and arbitrary pointer memory are not default-capture candidates.

Design-only high-risk queue:

1. Resolver-returned pointer instrumentation:
   - Reviewed design input is documented in `docs/resolver-returned-pointer-instrumentation-design.md`.
   - Current runtime can claim resolver visibility, IAT-covered calls, and resolver-pointer candidate or unsupported classification, but not calls through resolver-returned function pointers.
   - Candidate-ledger classification is implemented: resolver return pointers are mapped to module/RVA/API identity where safe, candidate or unsupported reason evidence is emitted, and target code is not mutated.
   - Inline/EAT patching, arbitrary returned-pointer wrapping, breakpoint mutation, skip-call, forced-return behavior, stealth behavior, and broad detours remain out of implementation scope.
2. Token mutation and service-control APIs:
   - `AdjustTokenPrivileges`, service creation/start/control/delete, and privilege mutation need no-op observability, least-payload ABI, and smoke isolation before any hook work.
3. Crypto and certificate secret-bearing APIs:
   - Key, plaintext, ciphertext, IV, hash input, certificate blob, private-key, and message payload capture are prohibited until a separate privacy/security policy exists.
4. RPC auth/endpoint and network payload APIs:
   - Auth material, server principals, endpoint mapper payloads, socket buffers, HTTP bodies, headers, cookies, and credentials remain design-only.
5. Remote process memory/thread/APC/context and injection helper APIs:
   - These remain non-goals for hook implementation until a separate stability, security, and operator-control design is approved.

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
6. Broad COM/WinRT activation, object, interface, vtable, marshaling, storage, HSTRING, runtime-class, or restricted-error-info monitoring.
7. Memory-content capture, remote process memory API capture, or injection helper capture without a separate ABI, stability, and performance review.
8. Full symbol server integration.
9. Cross-bitness injection.
10. Stealth/manual-map injection.
11. Inline detours for broad API coverage without a separate ABI, stability, and performance review.
