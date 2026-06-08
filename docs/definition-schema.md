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

