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

Current live x64 sample capture covers:

1. `CreateFileW`
2. `CreateFileA`
3. `ReadFile`
4. `WriteFile`
5. `CloseHandle`

`NtCreateFile` remains definition-only until the Win32 hook path is reviewed.

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

`capture-result.schema.json` wraps the bounded helper result, audit events, raw agent messages, captured `api_call` events, and dropped-event accounting.

`agent_shutdown` is the lifecycle closeout event for the controlled x64 sample agent. Healthy shutdown requires:

1. `reason`
2. `lifecycleState`
3. `installedHooks`
4. `restoredHooks`
5. `failedHooks`
6. `droppedCount`

For the current healthy x64 sample path, `restoredHooks` must be greater than or equal to `installedHooks`, and `failedHooks` must be `0`.

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

`npm run verify` runs the UI build, definition validator, and session fixture validator.

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
