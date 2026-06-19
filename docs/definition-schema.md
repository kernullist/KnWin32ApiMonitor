# Definition Schema

작성일: 2026-06-08

## Purpose

API definitions describe how raw API calls should be decoded into useful analyst-facing values.

Definition System V1 uses JSON definitions for API metadata plus JSON metadata registries for decode aliases, enum/flag values, and stable transport IDs. Rohitab-style XML import now exists as a prototype fixture tool for generating draft definitions; large imported API dumps remain out of scope. UI validation now also covers trace virtualization, structured query helpers, thread/timeline grouping helpers, and rule-based highlight helpers.

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
  win32/dbghelp.json
  win32/dnsapi.json
  win32/file-io.json
  win32/gdi32.json
  win32/handle.json
  win32/iphlpapi.json
  win32/loader.json
  win32/memory.json
  win32/module.json
  win32/ole32.json
  win32/oleaut32.json
  win32/process.json
  win32/psapi.json
  win32/rpcrt4.json
  win32/secur32.json
  win32/setupapi.json
  win32/resolver.json
  win32/shell32.json
  win32/shlwapi.json
  win32/synchronization.json
  win32/threading.json
  win32/user32.json
  win32/userenv.json
  win32/version.json
  win32/winhttp.json
  win32/wininet.json
  win32/wintrust.json
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
  session-catalog.schema.json
  native-daemon-status.schema.json
  native-daemon-audit.schema.json
  native-daemon-recovery-plan.schema.json
  native-daemon-recovery-apply.schema.json
```

`capture-result.schema.json` currently accepts both `bounded-native-capture` with `early-bird APC` and `bounded-native-attach` with `remote LoadLibraryW`. Attach results may include `attachProcessId` and `detachPolicy`, with Phase 11A using `self-disable-no-unload`.

`session-manifest.schema.json` accepts helper-written legacy sessions from `knmon-native-helper capture-sample` and `knmon-native-helper attach-capture`, with capture modes `bounded-native-capture` and `bounded-native-attach`.

`knapm-manifest.schema.json` and `knapm-index.schema.json` describe the Phase 11I/11J/11K/11L/11M directory-backed `.knapm` format written by `attach-session --stream-batches --write-knapm` or daemon-owned `daemon-start-session --write-knapm`. The manifest preserves session ownership, finalization state, target/agent evidence, target-vs-host drop counters, chunk count, last indexed record metadata, compression summary, stored/uncompressed byte totals, bounded-helper or persistent-daemon owner metadata, durable checkpoint metadata, and read-only recovery classification metadata. The index stores one chunk entry per non-empty `trace_batch` with stored byte length/SHA-256 evidence, plus required uncompressed byte length/SHA-256 evidence for zstd chunks.

`session-catalog.schema.json` describes the Phase 11M host-side replay catalog emitted by `catalog-sessions`, `catalog-query`, and `catalog-remove-missing`, plus the Phase 13A database-backed catalog index output emitted by `catalog-index-build`, `catalog-index-query`, and `catalog-index-remove-missing`. Catalog rows are built only from disk metadata and validation results. They include session path, format, session/operation identity, target PID/image/path/architecture, owner kind, daemon instance id, writer/finalized/recovery state, chunk/event/record counters, compression totals, validation status, last validation UTC, and a content identity hash. Database-backed output may add `databasePath`, `indexBackend`, `indexSchemaVersion`, and `staleIdentityCount`.

`native-daemon-status.schema.json` describes the Phase 11K/11L daemon status block returned by daemon start/status/stop commands and embedded in daemon audit/prune results. It records daemon PID, daemon instance id, heartbeat UTC, file-registry control endpoint, runtime directory, session count, and machine-readable daemon state including `stale` when a persisted daemon PID is dead.

`native-daemon-audit.schema.json` describes Phase 11L `daemon-audit` and `daemon-prune-stale` results. It wraps daemon status, audited daemon sessions, `pruneEligibleCount`, dry-run and mutation-attempt flags, pruned session ids, and the command message. `daemon-audit` is read-only; `daemon-prune-stale` removes only daemon registry record JSON files selected by `pruneEligible`.

`native-daemon-recovery-plan.schema.json` describes Phase 11N `daemon-recovery-plan` results. It wraps daemon status, audited daemon sessions, session-level dry-run recovery plan items, operator runbook action ids, allowed registry-prune hints, blocked mutation ids, and global safety flags. The command always returns `dryRun=true`, `mutationAttempted=false`, `automaticRecoveryAllowed=false`, and `targetMutationAllowed=false`; it does not recover writers, unload agents, kill targets, reinject, delete `.knapm` data, or mutate daemon registry records.

`native-daemon-recovery-apply.schema.json` describes Phase 11O `daemon-recovery-apply` results. The command is dry-run by default; it mutates host state only when `--apply-registry-prune` is explicit, and even then it can remove only daemon registry records whose recovery plan marks `registryPruneAllowed=true`. It preserves `.knapm` data, does not recover writers, does not unload agents, does not kill or restart targets, and does not reinject.

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

Current File I/O decode metadata covers file access masks, file share masks, CreateFile creation disposition, NT file disposition, File flags/attributes, NT create options, and LoadLibrary flags. Wave 2 metadata also registers generic aliases for registry handles and value buffers, access masks, CNG handles, certificate contexts, RPC bindings, socket handles, internet handles, sockaddr/addrinfo objects, token privileges, service status records, and pointer buffers used by controller-side decoders. Phase 13B adds low-payload HWND/HDC handle aliases and integer system-metric/device-capability index aliases. Phase 13C adds `module_handle_array_pointer` and `module_info_pointer` aliases for bounded PSAPI module-query metadata. Phase 13D adds `dword_value`, `version_info_buffer_pointer`, `version_info_value_pointer`, and `fixed_file_info_pointer` aliases for bounded Version resource metadata. Phase 13E adds `known_folder_id_pointer`, `csidl_value`, `shell_folder_path_pointer`, and `shell_folder_path_pointer_pointer` aliases for allowlisted Shell known-folder metadata. Phase 13F adds `com_init_flags`, `guid_pointer`, and `guid_string_buffer_pointer` aliases for OLE32 COM lifecycle and GUID helper metadata. Phase 13G reuses `guid_pointer`, `rpc_string_pointer`, and `utf16_string` for bounded RPCRT4 UUID helper metadata without adding duplicate UUID aliases. Phase 13H adds `ro_init_type` and `uint64_pointer` aliases for COMBASE-backed WinRT lifecycle metadata. Phase 13I adds `memory_allocation_type`, `memory_free_type`, `memory_protection_flags`, `memory_state_flags`, `memory_type_flags`, and `memory_basic_information_pointer` aliases for low-payload KERNEL32 memory protection metadata. Phase 13J adds `thread_access_flags`, `thread_creation_flags`, `wait_timeout_ms`, `wait_result`, `thread_id_pointer`, `thread_exit_code_pointer`, and `thread_start_routine_pointer` aliases for low-payload KERNEL32 current-process thread lifecycle metadata. Phase 13K adds `event_access_flags`, `event_manual_reset_bool`, `event_initial_state_bool`, `event_name_pointer`, and `wait_alertable_bool` aliases for low-payload KERNEL32 current-process event synchronization metadata. Phase 13L adds `mutex_access_flags`, `mutex_initial_owner_bool`, `semaphore_access_flags`, `semaphore_count_value`, `semaphore_previous_count_pointer`, `sync_object_name_pointer`, `wait_handle_array_pointer`, and `wait_all_bool` aliases for low-payload KERNEL32 current-process mutex/semaphore synchronization metadata. Phase 13M adds `file_mapping_protection_flags`, `file_mapping_access_flags`, `file_mapping_size_high`, `file_mapping_size_low`, `file_mapping_offset_high`, `file_mapping_offset_low`, `file_mapping_view_size`, `file_mapping_name_pointer`, and `mapped_view_pointer` aliases for low-payload KERNEL32 current-process file-mapping metadata. Phase 13N adds `process_handle_value`, `process_id_value`, `thread_handle_value`, and `thread_id_value` aliases for target-memory-free KERNEL32 process/thread identity metadata. Phase 13O adds `std_handle_selector`, `file_type_value`, `handle_information_flags`, `handle_information_flags_pointer`, and `handle_information_mask` aliases for low-payload KERNEL32 current-process handle metadata. Phase 13P adds `module_lookup_name`, `get_module_handle_ex_flags`, and `module_file_name_buffer_pointer` aliases for low-payload KERNEL32 current-process module lifecycle metadata while reusing existing module-handle aliases. Phase 13Q adds `file_size_pointer`, `file_time_pointer`, and `by_handle_file_information_pointer` aliases for fixed-size, handle-based KERNEL32 file metadata outputs. The WinHTTP scalar option slice adds `winhttp_option_id` and `winhttp_option_buffer_pointer` aliases for option ID and pointer-only buffer evidence, with scalar DWORD value decoding performed by explicit controller slot interpretation.

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
4. Wave 2 API IDs `14` through `90`, with selected registry, token query/privilege lookup, bcrypt CNG provider/RNG, crypt32 certificate-store/message-handle, RPCRT4 binding and `UuidCreate` ID `58`, Winsock, WinHTTP session/scalar-option, and WinINet session IDs promoted from definition-only to smoke-verified IAT coverage.
5. Phase 13B Wave 3 API IDs `91` through `97`, with selected User32 system/window metadata and GDI32 DC metadata APIs promoted directly to smoke-verified IAT coverage.
6. Phase 13C Wave 3 API IDs `98` through `101`, with selected PSAPI module-query APIs promoted directly to smoke-verified IAT coverage.
7. Phase 13D Wave 3 API IDs `102` through `104`, with selected Version resource metadata APIs promoted directly to smoke-verified IAT coverage.
8. Phase 13E Wave 3 API IDs `105` through `106`, with selected Shell known-folder metadata APIs promoted directly to smoke-verified IAT coverage.
9. Phase 13F Wave 3 API IDs `107` through `110`, with selected OLE32 COM lifecycle and GUID helper APIs promoted directly to smoke-verified IAT coverage.
10. Phase 13G Wave 3 API IDs `111` through `112`, with selected RPCRT4 UUID helper APIs added as smoke-verified IAT coverage while preserving `UuidCreate` at ID `58`.
11. Phase 13H Wave 3 API IDs `113` through `115`, with selected COMBASE-backed WinRT lifecycle APIs promoted directly to smoke-verified IAT coverage through the observed API-set provider.
12. Phase 13I Wave 3 API IDs `116` through `119`, with selected current-process KERNEL32 memory allocation/protection/query APIs promoted directly to smoke-verified IAT coverage.
13. Phase 13J Wave 3 API IDs `120` through `123`, with selected current-process KERNEL32 thread lifecycle/wait APIs promoted directly to smoke-verified IAT coverage.
14. Phase 13K Wave 3 API IDs `124` through `128`, with selected current-process KERNEL32 event synchronization APIs promoted directly to smoke-verified IAT coverage.
15. Phase 13L Wave 3 API IDs `129` through `135`, with selected current-process KERNEL32 mutex/semaphore synchronization APIs promoted directly to smoke-verified IAT coverage.
16. Phase 13M Wave 3 API IDs `136` through `139`, with selected current-process KERNEL32 file-mapping APIs promoted directly to smoke-verified IAT coverage.
17. Phase 13N Wave 3 API IDs `140` through `145`, with selected current-process KERNEL32 process/thread identity APIs promoted directly to smoke-verified IAT coverage.
18. Phase 13O Wave 3 API IDs `146` through `149`, with selected current-process KERNEL32 handle metadata APIs promoted directly to smoke-verified IAT coverage.
19. Phase 13P Wave 3 API IDs `150` through `153`, with selected current-process KERNEL32 module lifecycle APIs promoted directly to smoke-verified IAT coverage.
20. Phase 13Q Wave 3 API IDs `154` through `156`, with selected current-process KERNEL32 file metadata APIs promoted directly to smoke-verified IAT coverage.
21. Wave 4 definition-only API IDs `157` through `179`, covering OLE Automation, SSPI, user profile/environment, DNS, IP Helper, SetupAPI, Shell lightweight path helpers, WinTrust, and DbgHelp lifecycle/metadata entrypoints without enabling new hooks.
22. Module IDs:
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
   - `user32.dll = 11`
   - `gdi32.dll = 12`
   - `psapi.dll = 13`
   - `version.dll = 14`
   - `shell32.dll = 15`
   - `ole32.dll = 16`
   - `api-ms-win-core-winrt-l1-1-0.dll = 17`
   - `oleaut32.dll = 18`
   - `secur32.dll = 19`
   - `userenv.dll = 20`
   - `dnsapi.dll = 21`
   - `iphlpapi.dll = 22`
   - `setupapi.dll = 23`
   - `shlwapi.dll = 24`
   - `wintrust.dll = 25`
   - `dbghelp.dll = 26`

The native agent and controller use generated compile-time enum constants through `GeneratedApiIds.h`. The controller also uses `GeneratedApiMetadata.h` for API/module names, API family/category/risk labels, argument names/types/directions, decode aliases, and capture timing. Target hook fast paths still do not parse definitions or metadata.

`generated/definition-decoder-tables.json` is the deterministic JSON view for tooling. It contains module rows, API rows through ID `179`, flattened parameter rows, decode alias rows, and source file lists without wall-clock timestamps or local machine paths.

## File I/O, Loader, Resolver, And Wave 2/3/4 Metadata Coverage

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

The live Wave 2/3 slices are limited to smoke-verified `advapi32.dll` registry, selected `advapi32.dll` token query/privilege lookup, `bcrypt.dll` CNG provider/RNG, `crypt32.dll` certificate-store/message-handle, `rpcrt4.dll` local RPC binding, binding option, and UUID helpers, `ws2_32.dll` bootstrap/address-resolution/connect metadata, `winhttp.dll` session/scalar-option metadata, `wininet.dll` session-handle, selected COMBASE-backed WinRT lifecycle, selected KERNEL32 memory protection, selected KERNEL32 thread lifecycle, selected KERNEL32 event synchronization, selected KERNEL32 mutex/semaphore synchronization, selected KERNEL32 file-mapping, selected KERNEL32 process/thread identity, selected KERNEL32 handle metadata, selected KERNEL32 module lifecycle, and selected KERNEL32 file metadata IAT hooks. The selected registry APIs are `RegOpenKeyExW`, `RegCreateKeyExW`, `RegQueryValueExW`, `RegSetValueExW`, `RegDeleteValueW`, and `RegCloseKey`. The selected token query APIs are `OpenProcessToken` and `LookupPrivilegeValueW`. The selected bcrypt APIs are `BCryptOpenAlgorithmProvider`, `BCryptCloseAlgorithmProvider`, `BCryptGetProperty`, and `BCryptGenRandom`. The selected crypt32 APIs are `CertOpenStore`, `CertCloseStore`, `CryptMsgOpenToDecode`, and `CryptMsgClose`. The selected RPCRT4 APIs are `RpcStringBindingComposeW`, `RpcBindingFromStringBindingW`, `RpcStringFreeW`, `RpcBindingFree`, `RpcBindingSetOption`, `UuidCreate`, `UuidToStringW`, and `UuidFromStringW`. The selected Winsock APIs are `WSAStartup`, `WSACleanup`, `socket`, `closesocket`, `connect`, `getaddrinfo`, `freeaddrinfo`, and `WSAGetLastError`. The selected WinHTTP APIs are `WinHttpOpen`, `WinHttpCloseHandle`, and `WinHttpSetOption`. The selected WinINet APIs are `InternetOpenW` and `InternetCloseHandle`. The selected COMBASE-backed WinRT lifecycle APIs are `RoInitialize`, `RoUninitialize`, and `RoGetApartmentIdentifier` from the observed `api-ms-win-core-winrt-l1-1-0.dll` import provider. The selected KERNEL32 memory APIs are `VirtualAlloc`, `VirtualFree`, `VirtualProtect`, and `VirtualQuery`. The selected KERNEL32 thread APIs are `CreateThread`, `OpenThread`, `WaitForSingleObject`, and `GetExitCodeThread`. The selected KERNEL32 event synchronization APIs are `CreateEventW`, `OpenEventW`, `SetEvent`, `ResetEvent`, and `WaitForSingleObjectEx`. The selected KERNEL32 mutex/semaphore synchronization APIs are `CreateMutexW`, `OpenMutexW`, `ReleaseMutex`, `CreateSemaphoreW`, `OpenSemaphoreW`, `ReleaseSemaphore`, and `WaitForMultipleObjectsEx`. The selected KERNEL32 file-mapping APIs are `CreateFileMappingW`, `OpenFileMappingW`, `MapViewOfFile`, and `UnmapViewOfFile`. The selected KERNEL32 process/thread identity APIs are `GetCurrentProcess`, `GetCurrentProcessId`, `GetCurrentThread`, `GetCurrentThreadId`, `GetProcessId`, and `GetThreadId`. The selected KERNEL32 handle metadata APIs are `GetStdHandle`, `GetFileType`, `GetHandleInformation`, and `SetHandleInformation`. The selected KERNEL32 module lifecycle APIs are `GetModuleHandleW`, `GetModuleHandleExW`, `GetModuleFileNameW`, and `FreeLibrary`. The selected KERNEL32 file metadata APIs are `GetFileSizeEx`, `GetFileTime`, and `GetFileInformationByHandle`. `connect` keeps stable API ID `63` and records only socket handle, sockaddr pointer/length, decoded loopback endpoint metadata, return/error/timing, and hook lifecycle evidence. `RpcBindingSetOption` keeps stable API ID `54` and records only binding handle, option ID, scalar option value, return/timing, and hook lifecycle evidence. `WinHttpSetOption` keeps stable API ID `89` and records only WinHTTP handle, option ID, option-buffer pointer, option-buffer length, allowlisted DWORD scalar value, return/error/timing, and hook lifecycle evidence without request, transfer, header, body, cookie, credential, proxy credential, or raw option-buffer payload capture. All other unselected Wave 2 APIs remain `definition_only`.

Wave 4 adds 23 definition-only APIs across:

1. `oleaut32.dll`: BSTR, VARIANT, and SAFEARRAY lifecycle definitions.
2. `secur32.dll`: SSPI credential and context lifecycle definitions.
3. `userenv.dll`: profile-directory and environment-block definitions.
4. `dnsapi.dll`: DNS query and record-list lifecycle definitions.
5. `iphlpapi.dll`: adapter/interface metadata query definitions.
6. `setupapi.dll`: device-info set lifecycle definitions.
7. `shlwapi.dll`: shell path helper definitions.
8. `wintrust.dll`: trust verification/state query definitions.
9. `dbghelp.dll`: symbol-session lifecycle definitions.

Wave 4 is intentionally metadata-only. These APIs have stable IDs and generated controller metadata, but they are not live hooks and do not add target-process overhead until each family gets a separate hook ABI, payload-safety, and performance review.

Phase 13B adds seven smoke-verified Wave 3 APIs across:

1. `user32.dll`: `GetSystemMetrics`, `GetDesktopWindow`, `GetForegroundWindow`, and `GetWindowThreadProcessId`.
2. `gdi32.dll`: `CreateCompatibleDC`, `GetDeviceCaps`, and `DeleteDC`.

These records capture only metric/capability indexes and results, HWND/HDC handle values, and window thread/process numeric evidence. They do not capture window text, screenshots, pixels, bitmaps/DIBs, clipboard, keyboard/mouse input, message hooks, credentials, or arbitrary payload previews.

Phase 13C adds four smoke-verified Wave 3 APIs in `psapi.dll`:

1. `EnumProcessModules`
2. `GetModuleInformation`
3. `GetModuleBaseNameW`
4. `GetModuleFileNameExW`

These records capture only process/module handles, module-array requested/needed byte counts, one bounded first-module handle sample, `MODULEINFO` base address/image size/entry point numeric fields, and bounded module base-name/file-path strings. They do not copy module memory bytes, parse PE headers/sections/import/export/resource/relocation/debug data, read module files, compute hashes, verify signatures, dump full module lists, or emit arbitrary buffer previews.

Phase 13D adds three smoke-verified Wave 3 APIs in `version.dll`:

1. `GetFileVersionInfoSizeW`
2. `GetFileVersionInfoW`
3. `VerQueryValueW`

These records capture only version-info path, requested byte size, output pointer values, root fixed-file-info numeric fields, and the first translation language/codepage pair. They do not copy raw version resource bytes, arbitrary `StringFileInfo` values, PE/resource table dumps, file contents, hashes, signatures, or arbitrary buffer previews.

Phase 13E adds two smoke-verified Wave 3 APIs in `shell32.dll`:

1. `SHGetKnownFolderPath`
2. `SHGetSpecialFolderPathW`

These records capture only known-folder GUID, CSIDL, flag, handle, pointer, return/error, timing, and allowlist status evidence. Returned path strings are copied only for `FOLDERID_Windows`, `FOLDERID_System`, `FOLDERID_ProgramFiles`, `CSIDL_WINDOWS`, `CSIDL_SYSTEM`, and `CSIDL_PROGRAM_FILES`. Non-allowlisted successful queries emit `non_allowlisted_no_path` without returned path strings. They do not capture ShellExecute/process-launch evidence, PIDLs, Shell namespace item data, arbitrary file metadata, user-profile/AppData/Desktop/Documents/Downloads paths, command lines, environment variables, directory listings, file contents, credentials, or arbitrary buffer previews.

Phase 13F adds four smoke-verified Wave 3 APIs in `ole32.dll`:

1. `CoInitializeEx`
2. `CoUninitialize`
3. `CoCreateGuid`
4. `StringFromGUID2`

These records capture only COM apartment init flags, pointer values, HRESULT/int return evidence, GUID values, bounded canonical GUID strings, timing, generated metadata, and hook lifecycle evidence. They do not capture COM activation, class factory/interface/vtable data, marshaled interface payloads, monikers, ROT data, structured storage contents, clipboard/drag-drop payloads, Shell namespace data, user paths, credentials, or arbitrary buffer previews.

Phase 13G adds two new smoke-verified Wave 3 APIs in `rpcrt4.dll` and promotes existing `UuidCreate` ID `58`:

1. `UuidCreate`
2. `UuidToStringW`
3. `UuidFromStringW`

These records capture only UUID pointer values, `RPC_STATUS` returns, UUID values, bounded canonical UUID strings, timing, generated metadata, and hook lifecycle evidence. They do not capture RPC endpoint mapper enumeration, RPC auth/server-principal data, credentials, binding vectors, network payloads, sequential UUID node evidence, COM activation/object/interface/vtable data, marshaled payloads, user paths, or arbitrary buffer previews.

Phase 13H adds three smoke-verified Wave 3 APIs through the observed `api-ms-win-core-winrt-l1-1-0.dll` import provider for COMBASE-backed WinRT lifecycle coverage:

1. `RoInitialize`
2. `RoUninitialize`
3. `RoGetApartmentIdentifier`

These records capture only `RoInitialize` init type/HRESULT evidence, `RoUninitialize` void lifecycle/timing evidence, and `RoGetApartmentIdentifier` output pointer plus decoded `UINT64` apartment id evidence. The sample IAT provider was verified with `dumpbin`; the slice does not capture activation factories, runtime class names, HSTRING values, restricted error info, COM object/interface/vtable data, marshaled payloads, user paths, credentials, or arbitrary buffer previews.

Phase 13I adds four smoke-verified Wave 3 APIs in `kernel32.dll`:

1. `VirtualAlloc`
2. `VirtualFree`
3. `VirtualProtect`
4. `VirtualQuery`

These records capture only current-process address pointers, sizes, allocation/free/protection flags, return values, `VirtualProtect` old-protection output, and `VirtualQuery` `MEMORY_BASIC_INFORMATION` numeric metadata. They do not copy allocated memory contents, read arbitrary process memory, monitor remote process memory APIs, capture injection helper APIs, dump PE/module memory, parse file contents, compute hashes, or emit arbitrary buffer previews.

Phase 13J adds four smoke-verified Wave 3 APIs in `kernel32.dll`:

1. `CreateThread`
2. `OpenThread`
3. `WaitForSingleObject`
4. `GetExitCodeThread`

These records capture only current-process thread handles, pointer-sized inputs, creation/access/wait flags, thread IDs, wait results, and exit-code metadata. They do not capture remote-thread creation, APC queueing, suspend/resume, thread context, termination, stack walking, disassembly, injection helper APIs, memory contents, or arbitrary buffer previews.

Phase 13K adds five smoke-verified Wave 3 APIs in `kernel32.dll`:

1. `CreateEventW`
2. `OpenEventW`
3. `SetEvent`
4. `ResetEvent`
5. `WaitForSingleObjectEx`

These records capture only current-process event handles, pointer-sized inputs, BOOL flags, desired-access flags, wait timeout/result values, return/error evidence, timing, and hook lifecycle metadata. The x64 and x86 sample IAT providers were verified with `dumpbin` as `KERNEL32.dll`. They do not copy event object names, object-manager namespace paths, security descriptors, SIDs, ACLs, token data, wait-chain evidence, APC queue state, thread context, stacks, disassembly, injection helper APIs, memory contents, or arbitrary buffer previews.

Phase 13L adds seven smoke-verified Wave 3 APIs in `kernel32.dll`:

1. `CreateMutexW`
2. `OpenMutexW`
3. `ReleaseMutex`
4. `CreateSemaphoreW`
5. `OpenSemaphoreW`
6. `ReleaseSemaphore`
7. `WaitForMultipleObjectsEx`

These records capture only current-process mutex/semaphore handles, pointer-sized inputs, BOOL flags, desired-access flags, semaphore count values, previous-count scalar output, handle-array pointer-only evidence, multi-wait timeout/result values, return/error evidence, timing, and hook lifecycle metadata. The x64 and x86 sample IAT providers were verified with `dumpbin` as `KERNEL32.dll`. They do not copy mutex/semaphore object names, object-manager namespace paths, handle-array contents, security descriptors, SIDs, ACLs, token data, wait-chain evidence, APC queue state, thread context, stacks, disassembly, injection helper APIs, memory contents, or arbitrary buffer previews.

Phase 13M adds four smoke-verified Wave 3 APIs in `kernel32.dll`:

1. `CreateFileMappingW`
2. `OpenFileMappingW`
3. `MapViewOfFile`
4. `UnmapViewOfFile`

These records capture only current-process mapping/file handles, pointer-sized security/name evidence, protection/access flags, size/offset values, mapped view pointer, return/error evidence, timing, and hook lifecycle metadata. The x64 and x86 sample IAT providers were verified with `dumpbin` as `KERNEL32.dll`. They do not copy mapping object names, object-manager namespace paths, mapped memory contents, security descriptors, SIDs, ACLs, token data, file payloads, PE/module metadata, remote-memory evidence, thread context, stacks, disassembly, injection helper APIs, credentials, or arbitrary buffer previews.

Phase 13N adds six smoke-verified Wave 3 APIs in `kernel32.dll`:

1. `GetCurrentProcess`
2. `GetCurrentProcessId`
3. `GetCurrentThread`
4. `GetCurrentThreadId`
5. `GetProcessId`
6. `GetThreadId`

These records capture only pseudo/current process and thread handle values, current PID/TID numeric values, input process/thread handles for ID lookup calls, return/error evidence, timing, and hook lifecycle metadata. The x64 and x86 sample IAT providers were verified with `dumpbin` as `KERNEL32.dll`. They do not enumerate processes or threads, create processes, duplicate handles, read command lines or environment blocks, expand token/security capture, inspect remote memory, inspect thread context/stacks, dump module/PE/file/hash data, or emit arbitrary buffer previews.

Phase 13O adds four smoke-verified Wave 3 APIs in `kernel32.dll`:

1. `GetStdHandle`
2. `GetFileType`
3. `GetHandleInformation`
4. `SetHandleInformation`

These records capture only standard-handle selector values, handle values, file-type values, handle-information flag DWORDs, return/error evidence, timing, and hook lifecycle metadata. The x64 and x86 sample IAT providers were verified with `dumpbin` as `KERNEL32.dll`. They do not duplicate handles, enumerate system handles, query object names or security descriptors, copy file/pipe/console payloads, read command lines or environment blocks, inspect remote memory, inspect thread context/stacks, dump module/PE/file/hash data, or emit arbitrary buffer previews.

Phase 13P adds four smoke-verified Wave 3 APIs in `kernel32.dll`:

1. `GetModuleHandleW`
2. `GetModuleHandleExW`
3. `GetModuleFileNameW`
4. `FreeLibrary`

These records capture only module-name input strings, module handles, `GetModuleHandleExW` flags, bounded module file-name output text, return/error evidence, timing, and hook lifecycle metadata. The x64 and x86 sample IAT providers were verified with `dumpbin` as `KERNEL32.dll`. They do not enumerate remote modules, dump loaded-module lists, inspect module memory, parse PE headers or directories, hash files, validate signatures, capture command lines or environments, force unload/reference-count probe behavior, inspect remote memory, inspect thread context/stacks, or emit arbitrary buffer previews.

Phase 13Q adds three smoke-verified Wave 3 APIs in `kernel32.dll`:

1. `GetFileSizeEx`
2. `GetFileTime`
3. `GetFileInformationByHandle`

These records capture only file handle values, output pointer values, decoded file size, FILETIME scalar values, file attributes, volume serial, link count, file index, return/error evidence, timing, and hook lifecycle metadata. The x64 and x86 sample IAT providers were verified with `dumpbin` as `KERNEL32.dll`. They do not copy file contents, enumerate directories, resolve paths or object-manager names, inspect PE metadata, hash files, validate signatures, duplicate handles, query security descriptors, capture command lines or environments, inspect remote memory, inspect thread context/stacks, or emit arbitrary buffer previews.

The current definition coverage report totals 179 APIs:

1. `definition_only`: 65
2. `hooked`: 4
3. `smoke_verified`: 110

The Wave 4 common-DLL definitions are included in the `definition_only` count and do not add live target hooks.

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

Controller-side normalization uses generated decoder metadata for descriptors. Per-API shared-memory slot interpretation remains explicit. The selected registry, token query/privilege lookup, bcrypt CNG provider/RNG, crypt32 certificate-store/message-handle, RPCRT4 binding/option/UUID helper, Winsock, WinHTTP session/scalar-option, WinINet session, User32/GDI32 metadata, PSAPI module-query, Version resource metadata, Shell known-folder metadata, OLE32 COM lifecycle/GUID helper, COMBASE-backed WinRT lifecycle, KERNEL32 memory protection, KERNEL32 thread lifecycle, KERNEL32 event synchronization, KERNEL32 mutex/semaphore synchronization, KERNEL32 file-mapping, KERNEL32 process/thread identity, KERNEL32 handle metadata, KERNEL32 module lifecycle, and KERNEL32 file metadata slices use the existing fixed transport record slots. The Winsock slice records startup/cleanup, socket create/close, loopback `connect` sockaddr metadata, address-resolution/free, and error-query evidence only; it does not enable send/recv hooks, packet bytes, HTTP payloads, headers, cookies, credentials, network inventory, DNS cache, route/adapters, or payload previews. The token query slice records current-process `TOKEN_QUERY`, token handle, privilege name, and LUID numeric evidence only; it does not capture token privilege arrays, SID/group/ACL/security descriptor data, credentials, service-control data, or token mutation calls such as `AdjustTokenPrivileges`. The bcrypt slice records provider handles, algorithm/property names, status, pointer, and size evidence only; it does not copy random, key, plaintext, ciphertext, IV, or hash input bytes. The crypt32 slice records certificate-store/message handles, provider ID or bounded provider text, encoding/flag values, and pointer evidence only; it does not copy certificate blobs, private keys, cryptographic message payloads, random bytes, keys, plaintext, ciphertext, IVs, or hash input bytes. The RPCRT4 binding option slice records binding/string handles, bounded local binding text, option ID, scalar option value, `RPC_STATUS`, and timing only; it does not capture endpoint mapper enumeration, RPC auth/server-principal data, credentials, binding vectors, network payloads, RPC server communication, or payload previews. The RPCRT4 UUID helper slice records bounded UUID values and canonical UUID strings only; it does not capture endpoint mapper enumeration, RPC auth/server-principal data, credentials, binding vectors, network payloads, or sequential UUID node evidence. The WinHTTP session/scalar-option slice records user-agent/access-type/proxy pointer evidence, session handles, `WinHttpSetOption` option ID, option-buffer pointer/length, and allowlisted DWORD timeout/retry option values only; it does not make network requests or copy URLs, headers, bodies, cookies, credentials, proxy credentials, raw option-buffer bytes, or payload bytes. The WinINet session slice records user-agent/access-type/proxy pointer evidence, session handles, and return/status values only; it does not make network requests or copy URLs, headers, bodies, cookies, credentials, proxy credentials, or payload bytes. The PSAPI slice records bounded module-query metadata only; it does not copy module memory bytes, parse PE metadata, read files, hash modules, verify signatures, or dump complete module lists. The Version slice records bounded path/size/fixed-info/translation metadata only; it does not copy raw version resource bytes, arbitrary string-table values, PE metadata, file contents, hashes, or signatures. The Shell slice records allowlisted known-folder metadata only; it suppresses returned path strings for non-allowlisted folder IDs and does not capture ShellExecute/process-launch data, PIDLs, Shell namespace item data, arbitrary file metadata, user folder paths, command lines, or environment variables. The OLE32 slice records COM lifecycle and GUID helper metadata only; it does not capture COM activation, object/interface/vtable data, marshaled payloads, storage payloads, clipboard/drag-drop data, user paths, credentials, or arbitrary buffer previews. The COMBASE-backed WinRT lifecycle slice records init type, HRESULT/void return semantics, and numeric apartment identifier evidence only; it does not capture activation factories, runtime class names, HSTRING values, restricted error info, COM object/interface/vtable data, marshaled payloads, user paths, credentials, or arbitrary buffer previews. The KERNEL32 memory protection slice records allocation/free/protection flags, old protection, and `MEMORY_BASIC_INFORMATION` metadata only; it does not copy memory contents, call remote process memory APIs, capture injection helpers, or dump PE/module memory. The KERNEL32 thread lifecycle slice records thread handle, thread ID, creation/access/wait flags, wait-result, and exit-code metadata only; it does not capture remote-thread/APC helpers, suspend/resume, context, termination, stack walking, disassembly, or injection payloads. The KERNEL32 event synchronization slice records event handles, BOOL flags, desired-access flags, wait timeout/result, return/error, and timing metadata only; it does not copy event names, object-manager namespace paths, security descriptors, SIDs, ACLs, token data, wait-chain evidence, APC queue state, context, stacks, disassembly, or injection payloads. The KERNEL32 mutex/semaphore synchronization slice records mutex/semaphore handles, BOOL flags, desired-access flags, semaphore counts, handle-array pointer-only evidence, multi-wait timeout/result, return/error, and timing metadata only; it does not copy object names, object-manager namespace paths, handle-array contents, security descriptors, SIDs, ACLs, token data, wait-chain evidence, APC queue state, context, stacks, disassembly, or injection payloads. The KERNEL32 file-mapping slice records file/mapping handles, pointer-only security/name evidence, protection/access flags, size/offset values, mapped view pointer, return/error, and timing metadata only; it does not copy mapping object names, object-manager namespace paths, mapped memory contents, security descriptors, SIDs, ACLs, token data, file payloads, PE/module metadata, remote-memory evidence, context, stacks, disassembly, or injection payloads. The KERNEL32 process/thread identity slice records pseudo/current process/thread handles, PID/TID numeric values, input handles for ID lookup calls, return/error, and timing metadata only; it does not enumerate processes or threads, create processes, duplicate handles, read command lines or environment blocks, expand token/security capture, inspect remote memory, inspect thread context/stacks, or dump module/PE/file/hash data. The KERNEL32 handle metadata slice records standard-handle selectors, handle values, file-type values, handle-information flag DWORDs, return/error, and timing metadata only; it does not duplicate handles, enumerate system handles, query object names or security descriptors, copy file/pipe/console payloads, inspect command lines or environments, inspect remote memory, inspect thread context/stacks, or dump module/PE/file/hash data. The KERNEL32 module lifecycle slice records module-name input strings, module handles, `GetModuleHandleExW` flags, bounded module file-name output text, return/error, and timing metadata only; it does not enumerate remote modules, dump loaded-module lists, inspect module memory, parse PE headers or directories, hash files, validate signatures, capture command lines or environments, force unload/reference-count probe behavior, inspect remote memory, inspect thread context/stacks, or emit arbitrary buffer previews. The KERNEL32 file metadata slice records file handles, output pointers, file size, FILETIME scalar values, file attributes, volume serial, link count, file index, return/error, and timing metadata only; it does not copy file contents, enumerate directories, resolve paths or object-manager names, inspect PE metadata, hash files, validate signatures, duplicate handles, query security descriptors, inspect remote memory, inspect thread context/stacks, or emit arbitrary buffer previews. High-volume network payload hooks, WinHTTP/WinINet request/transfer/header/body/cookie/credential capture, RPC auth/endpoint capture, raw resource capture, Shell payload capture, COM/WinRT activation/object/marshaling/HSTRING/runtime-class/error-info capture, synchronization object namespace/security/wait-chain payload capture, file-content/path/name/directory capture, memory-content capture, remote memory/injection/thread capture, and module-memory/PE payload capture remain deferred until a later hook ABI expansion and overhead review.

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
5. `chunks/trace-000NNN.jsonl` or `chunks/trace-000NNN.jsonl.zst`

Phase 11J/11K/11L/11M `.knapm` manifests add:

1. `owner`: bounded-helper or persistent-daemon writer owner kind, host/helper/writer PID, writer instance id, generation, heartbeat, lease timeout, lease expiry, and daemon PID/instance/control endpoint when `ownerKind=persistent-daemon`.
2. `checkpoint`: last committed chunk, batch, record, event id, manifest update, index update, and index consistency.
3. `recovery`: finalized/owned/stale/recovery-required/legacy/malformed state, reason, action, read-only liveness booleans, lease expiry, and restart eligibility.
4. `compression`, `compressionAlgorithms`, `storedBytes`, and `uncompressedBytes`: writer compression summary and byte totals.

`session-manifest.schema.json` describes the durable session metadata: source command, backend mode, capture mode, operation id, target, agent, event counts, dropped-event accounting, and file names.

`session-info.schema.json` describes validation and writer status returned to the UI. Additive Phase 11I fields include `format`, `finalized`, chunk count, last batch/record sequence, target transport drops, host dropped batches, and `writerState`. Additive Phase 11J fields include recovery state, reason, action, owner/helper/writer/target liveness, lease expiry, and restart eligibility. Additive Phase 11M fields include `compression`, `storedBytes`, and `uncompressedBytes`. `session-catalog.schema.json` also accepts additive Phase 13A catalog index metadata for database path, backend, schema version, and stale identity count. `native-session.schema.json` accepts additive Phase 11K daemon fields for daemon PID, daemon instance id, daemon heartbeat, daemon control endpoint, and `.knapm` path, plus Phase 11L daemon audit fields for daemon/session/target liveness, `.knapm` existence and validation, audit recovery state/reason/action, and stale registry prune eligibility.

`session-replay-result.schema.json` wraps validated session metadata and replayed trace-compatible events. Replay must not launch the sample target or load an agent.

Finalized session validation requires `agent_shutdown` in `agent-events.jsonl` so hook restore evidence survives persistence and replay workflows. `.knapm` validation additionally checks index identity, stored chunk SHA-256, stored byte length, zstd uncompressed SHA-256/byte length, contiguous batch sequence, monotonic record ranges, malformed trace rows, owner/checkpoint/recovery metadata, persistent-daemon owner metadata where applicable, and finalized vs partial state without target mutation.

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

`defs:decoder-tables` verifies the generated decoder metadata artifact covers API IDs `1` through `156`, parameter rows, decode alias rows, and length-source resolution.

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

`npm run verify` runs the UI build, UI trace virtualizer/query/view validators, definition validator, session fixture validator, and collector validator.

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
