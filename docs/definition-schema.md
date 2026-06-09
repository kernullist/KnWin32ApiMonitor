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
  win32/file-io.json
  win32/loader.json
  win32/resolver.json
contracts/
  api-definition.schema.json
  definition-metadata.schema.json
  agent-event.schema.json
  hook-status.schema.json
  capture-result.schema.json
  collector-stats.schema.json
  session-info.schema.json
  session-manifest.schema.json
  session-replay-result.schema.json
```

Generated definition ID artifacts live under:

```text
generated/definition-ids.json
native/knmon-common/include/knmon/common/GeneratedApiIds.h
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
10. Positive and negative definition fixture checks.
11. Rohitab XML importer fixture check.
12. Definition coverage bucket check.

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

Current File I/O decode metadata covers file access masks, file share masks, CreateFile creation disposition, NT file disposition, File flags/attributes, NT create options, and LoadLibrary flags.

## Stable Transport IDs

`definitions/metadata/id-assignments.json` is the stable assignment source for compact transport IDs. `npm run defs:generate` rewrites:

1. `generated/definition-ids.json`
2. `native/knmon-common/include/knmon/common/GeneratedApiIds.h`

Existing transport IDs are preserved:

1. File I/O API IDs `1` through `6`.
2. Loader API IDs `7` through `11`.
3. Module IDs:
   - `kernel32.dll = 1`
   - `ntdll.dll = 2`
   - `kernelbase.dll = 3`

The native agent and controller use generated compile-time enum constants through `GeneratedApiIds.h`; target hook fast paths do not parse definitions or metadata.

## File I/O And Loader Coverage

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

The current helper session format is a directory, not the future `.knapm` container.

Required files:

1. `manifest.json`
2. `audit.jsonl`
3. `agent-events.jsonl`
4. `trace-events.jsonl`

`session-manifest.schema.json` describes the durable session metadata: source command, backend mode, capture mode, operation id, target, agent, event counts, dropped-event accounting, and file names.

`session-info.schema.json` describes validation and writer status returned to the UI.

`session-replay-result.schema.json` wraps validated session metadata and replayed trace-compatible events. Replay must not launch the sample target or load an agent.

Session validation requires `agent_shutdown` in `agent-events.jsonl` so hook restore evidence survives persistence and replay workflows.

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
npm run defs:coverage
```

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
