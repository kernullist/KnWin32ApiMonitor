# Definition Schema

작성일: 2026-06-08

## Purpose

API definitions describe how raw API calls should be decoded into useful analyst-facing values.

Definition System V1 uses JSON definitions for API metadata plus JSON metadata registries for decode aliases, enum/flag values, and stable transport IDs. Rohitab-style XML import now exists as a prototype fixture tool for generating draft definitions; large imported API dumps remain out of scope.

## Location

Current definitions live under:

```text
definitions/
  metadata/decode-aliases.json
  metadata/enums.json
  metadata/flags.json
  metadata/id-assignments.json
  win32/advapi32.json
  win32/bcrypt.json
  win32/crypt32.json
  win32/file-io.json
  win32/loader.json
  win32/rpcrt4.json
  win32/resolver.json
  win32/winhttp.json
  win32/wininet.json
  win32/ws2_32.json
contracts/
  api-definition.schema.json
  definition-metadata.schema.json
  agent-event.schema.json
  hook-status.schema.json
  capture-result.schema.json
  collector-stats.schema.json
  process-tree-node.schema.json
  process-tree-result.schema.json
  session-info.schema.json
  session-manifest.schema.json
  session-replay-result.schema.json
  knapm-manifest.schema.json
  knapm-index.schema.json
```

`capture-result.schema.json` currently accepts both `bounded-native-capture` with `early-bird APC` and `bounded-native-attach` with `remote LoadLibraryW`. Attach results may include `attachProcessId` and `detachPolicy`, with Phase 11A using `self-disable-no-unload`.

`session-manifest.schema.json` accepts helper-written legacy sessions from `knmon-native-helper capture-sample` and `knmon-native-helper attach-capture`, with capture modes `bounded-native-capture` and `bounded-native-attach`.

`knapm-manifest.schema.json` and `knapm-index.schema.json` describe the Phase 11I/11J directory-backed `.knapm` format written by `attach-session --stream-batches --write-knapm`. The manifest preserves session ownership, finalization state, target/agent evidence, target-vs-host drop counters, chunk count, last indexed record metadata, bounded-helper owner metadata, durable checkpoint metadata, and read-only recovery classification metadata. The index stores one chunk entry per non-empty `trace_batch` with byte length and SHA-256 evidence.

`process-tree-node.schema.json` and `process-tree-result.schema.json` describe Phase 11B helper-side process-tree supervision. They cover root/child process metadata, child policies `observe` and `attach-supported`, eligibility states, policy decisions, audit events, and optional embedded Phase 11A child attach results.

Generated definition ID artifacts live under:

```text
generated/definition-ids.json
generated/definition-decoder-tables.json
native/knmon-common/include/knmon/common/GeneratedApiIds.h
native/knmon-common/include/knmon/common/GeneratedApiMetadata.h
```

## Current Required Fields

Each definition document must include:

```json
{
  "schemaVersion": "0.1.0",
  "module": "file-io",
  "apis": []
}
```

Each API entry must include:

1. `module`
2. `name`
3. `callingConvention`
4. `returnType`
5. `errorSource`
6. `parameters`

Optional V1 fields are validated when present:

1. `apiId`
2. `family`
3. `category`
4. `risk`
5. `minWindowsVersion`
6. `architectures`
7. `ordinal`
8. `aliases`
9. `hookPolicy`
10. `coverageStatus`

Each parameter must include:

1. `name`
2. `type`
3. `direction`
4. `decode`

Optional V1 parameter fields are validated when present:

1. `lengthFrom`
2. `lengthExpression`
3. `enum`
4. `flags`
5. `maxBytes`
6. `nullable`
7. `captureTiming`

Allowed directions:

- `in`
- `out`
- `inout`
- `return`

## Definition System V1 Validation

`npm run defs:validate` now performs:

1. JSON Schema validation for API definition documents through `contracts/api-definition.schema.json`.
2. JSON Schema validation for metadata documents through `contracts/definition-metadata.schema.json`.
3. Semantic duplicate API checks by normalized `module!api` key.
4. Duplicate explicit API id checks.
5. Decode alias registry checks.
6. Enum and flag reference checks.
7. `lengthFrom` parameter reference checks.
8. Restricted `lengthExpression` parsing without `eval`, `Function`, or arbitrary JavaScript execution.
9. Stable ID assignment checks for generated transport IDs.
10. Generated controller-side decoder table freshness checks.
11. Positive and negative definition fixture checks.
12. Rohitab XML importer fixture check.
13. Definition coverage bucket check.

The restricted `lengthExpression` grammar supports only:

1. parameter identifiers
2. integer literals
3. `+`
4. `-`
5. `*`
6. parentheses
7. `min(a,b)`
8. `max(a,b)`

Unsupported tokens such as division, member access, function bodies, or JavaScript expressions are rejected.

## Decode Metadata

Decode aliases are centralized in `definitions/metadata/decode-aliases.json`. Each alias records:

1. semantic kind
2. preview policy
3. whether target memory may be read by a decoder
4. max preview guidance
5. optional enum or flag binding

Enum values live in `definitions/metadata/enums.json`; flag values live in `definitions/metadata/flags.json`. Numeric values may be decimal or hex strings and are normalized by tooling for validation/reporting.

Current File I/O decode metadata covers file access masks, file share masks, CreateFile creation disposition, NT file disposition, File flags/attributes, NT create options, and LoadLibrary flags. Wave 2 metadata also registers generic aliases for registry handles and value buffers, access masks, CNG handles, certificate contexts, RPC bindings, socket handles, internet handles, sockaddr/addrinfo objects, token privileges, service status records, and pointer buffers used by controller-side decoders.

## Stable Transport IDs

`definitions/metadata/id-assignments.json` is the stable assignment source for compact transport IDs. API definition JSON files and decode metadata are also the source for controller-side decoder metadata. `npm run defs:generate` rewrites:

1. `generated/definition-ids.json`
2. `native/knmon-common/include/knmon/common/GeneratedApiIds.h`
3. `generated/definition-decoder-tables.json`
4. `native/knmon-common/include/knmon/common/GeneratedApiMetadata.h`

Existing transport IDs are preserved:

1. File I/O API IDs `1` through `6`.
2. Loader API IDs `7` through `11`.
3. Resolver API IDs `12` through `13`.
4. Wave 2 API IDs `14` through `90`, with selected registry, token query/privilege lookup, bcrypt CNG provider/RNG, crypt32 certificate-store/message-handle, RPCRT4 binding, Winsock, WinHTTP session, and WinINet session IDs promoted from definition-only to smoke-verified IAT coverage.
5. Module IDs:
   - `kernel32.dll = 1`
   - `ntdll.dll = 2`
   - `kernelbase.dll = 3`
   - `advapi32.dll = 4`
   - `bcrypt.dll = 5`
   - `crypt32.dll = 6`
   - `rpcrt4.dll = 7`
   - `ws2_32.dll = 8`
   - `wininet.dll = 9`
   - `winhttp.dll = 10`

The native agent and controller use generated compile-time enum constants through `GeneratedApiIds.h`. The controller also uses `GeneratedApiMetadata.h` for API/module names, API family/category/risk labels, argument names/types/directions, decode aliases, and capture timing. Target hook fast paths still do not parse definitions or metadata.

`generated/definition-decoder-tables.json` is the deterministic JSON view for tooling. It contains module rows, API rows, flattened parameter rows, decode alias rows, and source file lists without wall-clock timestamps or local machine paths.

## File I/O, Loader, Resolver, And Wave 2 Metadata Coverage

The first validator requires definitions for:

1. `CreateFileW`
2. `CreateFileA`
3. `NtCreateFile`
4. `ReadFile`
5. `WriteFile`
6. `CloseHandle`

Current live same-bitness x64/x86 sample capture covers:

1. `CreateFileW`
2. `CreateFileA`
3. `NtCreateFile`
4. `ReadFile`
5. `WriteFile`
6. `CloseHandle`
7. `LoadLibraryW`

The committed definition set also includes loader definitions for:

1. `LoadLibraryW`
2. `LoadLibraryA`
3. `LoadLibraryExW`
4. `LoadLibraryExA`
5. `LdrLoadDll`

Resolver calls are monitored through eligible-module IAT hooks in the controlled same-bitness sample path:

1. `GetProcAddress`
2. `LdrGetProcedureAddress`

The resolver events capture bounded function-name or ordinal evidence, module handle evidence, and return/status values. This coverage intentionally means the resolver API calls themselves are visible. It does not imply returned-pointer instrumentation, inline detours, EAT patching, or automatic coverage for later calls made through resolver-returned function pointers.

Wave 2 metadata adds 77 APIs across:

1. `advapi32.dll`: registry, token, privilege, and service-control APIs.
2. `bcrypt.dll`: CNG algorithm, key, encryption/decryption, hash, and random APIs.
3. `crypt32.dll`: certificate store, certificate chain, and cryptographic message APIs.
4. `rpcrt4.dll`: RPC string binding, binding option/auth, endpoint inquiry, and UUID APIs.
5. `ws2_32.dll`: Winsock startup, socket, connect, send/receive, and address-resolution APIs.
6. `wininet.dll`: WinINet session, connection, request, transfer, and option APIs.
7. `winhttp.dll`: WinHTTP session, connection, request, transfer, option, and header APIs.

The live Wave 2 slices are limited to smoke-verified `advapi32.dll` registry, selected `advapi32.dll` token query/privilege lookup, `bcrypt.dll` CNG provider/RNG, `crypt32.dll` certificate-store/message-handle, `rpcrt4.dll` local RPC binding, `ws2_32.dll` bootstrap/address-resolution, `winhttp.dll` session-handle, and `wininet.dll` session-handle IAT hooks. The selected registry APIs are `RegOpenKeyExW`, `RegCreateKeyExW`, `RegQueryValueExW`, `RegSetValueExW`, `RegDeleteValueW`, and `RegCloseKey`. The selected token query APIs are `OpenProcessToken` and `LookupPrivilegeValueW`. The selected bcrypt APIs are `BCryptOpenAlgorithmProvider`, `BCryptCloseAlgorithmProvider`, `BCryptGetProperty`, and `BCryptGenRandom`. The selected crypt32 APIs are `CertOpenStore`, `CertCloseStore`, `CryptMsgOpenToDecode`, and `CryptMsgClose`. The selected RPCRT4 APIs are `RpcStringBindingComposeW`, `RpcBindingFromStringBindingW`, `RpcStringFreeW`, and `RpcBindingFree`. The selected Winsock APIs are `WSAStartup`, `WSACleanup`, `socket`, `closesocket`, `getaddrinfo`, `freeaddrinfo`, and `WSAGetLastError`. The selected WinHTTP APIs are `WinHttpOpen` and `WinHttpCloseHandle`. The selected WinINet APIs are `InternetOpenW` and `InternetCloseHandle`. All other Wave 2 APIs remain `definition_only`.

The current definition coverage report totals 90 APIs:

1. `definition_only`: 46
2. `hooked`: 4
3. `smoke_verified`: 40

`NtCreateFile` is captured as a controlled `ntdll.dll` IAT hook in the repository sample target. The native event keeps `returnValue` as the NTSTATUS hex string. For compatibility with the existing trace error model, `lastErrorCode` remains `0` on NT success and a mapped Win32 error on NT failure.

The `NtCreateFile` event includes bounded snapshots for:

1. `FileHandle`
2. `DesiredAccess`
3. `ObjectAttributes`
4. `IoStatusBlock`
5. `ShareAccess`
6. `CreateDisposition`
7. `CreateOptions`

`ObjectAttributes` decoding copies at most the bounded `UNICODE_STRING` length used by the agent and falls back to pointer evidence with `invalid_pointer`, `unreadable_memory`, or `truncated` status when needed.

Current native API call records are written by the agent into a shared-memory binary ring, then normalized by the controller into the same `api_call` JSON shape outside the target process. Named-pipe JSON remains only for low-volume control and lifecycle messages.

Controller-side normalization uses generated decoder metadata for descriptors. Per-API shared-memory slot interpretation remains explicit. The selected registry, token query/privilege lookup, bcrypt CNG provider/RNG, crypt32 certificate-store/message-handle, RPCRT4 binding, Winsock, WinHTTP session, and WinINet session slices use the existing fixed transport record slots. The token query slice records current-process `TOKEN_QUERY`, token handle, privilege name, and LUID numeric evidence only; it does not capture token privilege arrays, SID/group/ACL/security descriptor data, credentials, service-control data, or token mutation calls such as `AdjustTokenPrivileges`. The bcrypt slice records provider handles, algorithm/property names, status, pointer, and size evidence only; it does not copy random, key, plaintext, ciphertext, IV, or hash input bytes. The crypt32 slice records certificate-store/message handles, provider ID or bounded provider text, encoding/flag values, and pointer evidence only; it does not copy certificate blobs, private keys, cryptographic message payloads, random bytes, keys, plaintext, ciphertext, IVs, or hash input bytes. The WinHTTP session slice records user-agent/access-type/proxy pointer evidence, session handles, and return/status values only; it does not make network requests or copy URLs, headers, bodies, cookies, credentials, proxy credentials, or payload bytes. The WinINet session slice records user-agent/access-type/proxy pointer evidence, session handles, and return/status values only; it does not make network requests or copy URLs, headers, bodies, cookies, credentials, proxy credentials, or payload bytes. High-volume network payload hooks remain deferred until a later hook ABI expansion and overhead review.

Loader-aware Wave 1 records add `LoadLibraryW` evidence and post-load File I/O evidence from `knmon-dynamic-probe.dll`. Resolver records add `GetProcAddress` and `LdrGetProcedureAddress` evidence for the same dynamic probe export. The agent emits module inventory and IAT sweep status messages through the named pipe, but API call events remain shared-memory records.

## Agent Event Contracts

Bounded native capture uses schema-versioned agent messages. Every agent message carries:

1. `schemaVersion`
2. `messageType`
3. `operationId`
4. `pid`
5. `tid`
6. `timestampUtc`
7. `sequence`

The current message types are:

1. `agent_hello`
2. `hook_installed`
3. `hook_install_failed`
4. `api_call`
5. `dropped_events`
6. `agent_shutdown`
7. `module_inventory`
8. `iat_sweep`

`capture-result.schema.json` wraps the bounded helper result, audit events, raw agent messages, captured `api_call` events, dropped-event accounting, shared-memory transport metrics, and min/average/max hook overhead metrics.

Current transport metric fields are:

1. `transportMode`
2. `transportCapacity`
3. `transportRecordsProduced`
4. `transportRecordsConsumed`
5. `transportDroppedEvents`
6. `transportHighWaterMark`
7. `hookOverheadMinUs`
8. `hookOverheadAvgUs`
9. `hookOverheadMaxUs`

`agent_hello` requires architecture, agent version, and message evidence so the controller/session validator can prove the loaded agent bitness matches the selected same-bitness path.

`agent_shutdown` is the lifecycle closeout event for the controlled same-bitness sample agent. Healthy shutdown requires:

1. `reason`
2. `lifecycleState`
3. `installedHooks`
4. `restoredHooks`
5. `failedHooks`
6. `droppedCount`

For the current healthy x64 and x86 sample paths, at least the six required File I/O hook groups must be installed, `restoredHooks` must equal `installedHooks`, and `failedHooks` must be `0`.

`module_inventory` reports PEB loader-list scan evidence:

1. `scannedModules`
2. `eligibleModules`
3. `skippedModules`

`iat_sweep` reports startup and dynamic-load re-hook evidence:

1. `reason`
2. `scannedModules`
3. `eligibleModules`
4. `skippedModules`
5. `patchedModules`
6. `patchedSlots`
7. `duplicateSlots`
8. `failedSlots`

The helper result and session manifest preserve architecture evidence from the selected same-bitness path. The current supported live architectures are `x64` and `x86`; cross-bitness injection is rejected before remote mutation.

## Session Contracts

The current helper supports two durable session layouts.

Legacy session directory files:

1. `manifest.json`
2. `audit.jsonl`
3. `agent-events.jsonl`
4. `trace-events.jsonl`

Directory-backed `.knapm` files:

1. `manifest.json`
2. `index.json`
3. `audit.jsonl`
4. `agent-events.jsonl`
5. `chunks/trace-000NNN.jsonl`

Phase 11J `.knapm` manifests add:

1. `owner`: bounded-helper writer owner kind, host/helper/writer PID, writer instance id, generation, heartbeat, lease timeout, and lease expiry.
2. `checkpoint`: last committed chunk, batch, record, event id, manifest update, index update, and index consistency.
3. `recovery`: finalized/owned/stale/recovery-required/legacy/malformed state, reason, action, read-only liveness booleans, lease expiry, and restart eligibility.

`session-manifest.schema.json` describes the durable session metadata: source command, backend mode, capture mode, operation id, target, agent, event counts, dropped-event accounting, and file names.

`session-info.schema.json` describes validation and writer status returned to the UI. Additive Phase 11I fields include `format`, `finalized`, chunk count, last batch/record sequence, target transport drops, host dropped batches, and `writerState`. Additive Phase 11J fields include recovery state, reason, action, owner/helper/writer/target liveness, lease expiry, and restart eligibility.

`session-replay-result.schema.json` wraps validated session metadata and replayed trace-compatible events. Replay must not launch the sample target or load an agent.

Finalized session validation requires `agent_shutdown` in `agent-events.jsonl` so hook restore evidence survives persistence and replay workflows. `.knapm` validation additionally checks index identity, chunk SHA-256, byte length, contiguous batch sequence, monotonic record ranges, malformed trace rows, owner/checkpoint/recovery metadata, and finalized vs partial state without target mutation.

## Collector Contracts

`collector-stats.schema.json` describes the current native collector backpressure smoke result.

The first collector policy is `drop-newest`. With bounded capacity, the collector keeps FIFO order for retained events and rejects new events after the queue is full.

Required smoke stats:

1. `acceptedEvents`
2. `drainedEvents`
3. `droppedEvents`
4. `queueDepth`
5. `highWaterMark`
6. `backpressureActivations`
7. `retainedSequences`

The committed fixture under `tests/fixtures/collector/` proves capacity 4 with 10 synthetic events:

1. retained sequence `1,2,3,4`
2. dropped events `6`
3. high-water mark `4`
4. backpressure activations `6`

## Example

```json
{
  "module": "KERNEL32.dll",
  "name": "CreateFileW",
  "callingConvention": "stdcall",
  "returnType": "HANDLE",
  "errorSource": "GetLastError",
  "success": { "returnNotEqual": "INVALID_HANDLE_VALUE" },
  "failure": { "returnEqual": "INVALID_HANDLE_VALUE" },
  "parameters": [
    {
      "name": "lpFileName",
      "type": "LPCWSTR",
      "direction": "in",
      "decode": "utf16_string"
    }
  ]
}
```

## Validation Commands

Run:

```powershell
npm run defs:generate
npm run defs:validate
npm run defs:decoder-tables
npm run defs:coverage
```

`defs:decoder-tables` verifies the generated decoder metadata artifact covers API IDs `1` through `90`, parameter rows, decode alias rows, and length-source resolution.

`defs:coverage` prints a deterministic Markdown report grouped by module, family, risk, hook policy, coverage status, and decode quality. The report explicitly separates:

1. `definition_only`
2. `hooked`
3. `smoke_verified`

Validate session fixtures:

```powershell
npm run sessions:validate
```

Validate collector fixtures and smoke output:

```powershell
npm run collector:validate
```

`npm run verify` runs the UI build, definition validator, session fixture validator, and collector validator.

## Decode Hints

Decode hints remain symbolic for the target runtime. Definition System V1 validates the symbolic names and attaches metadata for future controller-side or collector-side decoders, but the injected hook path still emits fixed-size shared-memory records.

Examples:

- `utf16_string`
- `ansi_string`
- `file_access_mask`
- `file_share_mask`
- `file_creation_disposition`
- `file_flags_attributes`
- `object_attributes`
- `io_status_block`
- `buffer`
- `handle`
