# Definition Schema

작성일: 2026-06-08

## Purpose

API definitions describe how raw API calls should be decoded into useful analyst-facing values.

The Phase 1 MVP starts with JSON definitions for File I/O APIs. YAML authoring and Rohitab-style XML import are later roadmap items.

## Location

Current definitions live under:

```text
definitions/
  win32/file-io.json
contracts/
  agent-event.schema.json
  hook-status.schema.json
  capture-result.schema.json
  collector-stats.schema.json
  session-info.schema.json
  session-manifest.schema.json
  session-replay-result.schema.json
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

Each parameter must include:

1. `name`
2. `type`
3. `direction`
4. `decode`

Allowed directions:

- `in`
- `out`
- `inout`
- `return`

## File I/O MVP Coverage

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

For the current healthy x64 and x86 sample paths, `restoredHooks` must be greater than or equal to `installedHooks`, and `failedHooks` must be `0`.

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

## Validation

Run:

```powershell
npm run defs:validate
```

The validator currently performs structural checks and confirms the required File I/O API set is present.

Validate session fixtures:

```powershell
npm run sessions:validate
```

Validate collector fixtures and smoke output:

```powershell
npm run collector:validate
```

`npm run verify` runs the UI build, definition validator, session fixture validator, and collector validator.

Future validation should add:

1. JSON Schema validation.
2. Type alias checks.
3. Enum/flag reference checks.
4. Buffer length expression validation.
5. OS and architecture guard validation.
6. Definition test fixtures.

## Decode Hints

Decode hints are intentionally symbolic in Phase 1. The decoder is not implemented yet, but definitions already reserve the names needed by the UI and future native decoder.

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
