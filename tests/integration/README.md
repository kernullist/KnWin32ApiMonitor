# Integration Tests

Future integration tests for Tauri commands, native helpers, collector sessions, and UI workflows.

Current verification gates include:

1. UI build through `npm run build`.
2. Definition validation through `npm run defs:validate`.
3. Session fixture validation through `npm run sessions:validate`.
4. Native helper smoke runs for `capture-sample`, `validate-session`, and `replay-session`.
5. Repeated native lifecycle smoke through `tools\native-smoke\repeat-capture-sample.ps1`.
6. `NtCreateFile` native capture smoke through `tools\native-smoke\ntcreatefile-capture-smoke.ps1`.
7. Shared-memory transport smoke through `tools\native-smoke\shared-memory-transport-smoke.ps1`.
8. Shared-memory backpressure smoke through `tools\native-smoke\shared-memory-backpressure-smoke.ps1`.
9. Loader-aware IAT sweep smoke through `tools\native-smoke\loader-aware-iat-sweep-smoke.ps1`.
10. Dynamic-load re-hook smoke through `tools\native-smoke\dynamic-load-rehook-smoke.ps1`.
11. Injection preflight negative smoke through `tools\native-smoke\injection-preflight-negative-smoke.ps1`.
12. Wave 2 Winsock smoke through `tools\native-smoke\wave2-winsock-smoke.ps1`.
13. Wave 2 RPCRT4 binding option smoke through `tools\native-smoke\wave2-rpcrt4-binding-smoke.ps1`.
14. Wave 2 WinHTTP scalar option smoke through `tools\native-smoke\wave2-winhttp-option-smoke.ps1`.
15. Wave 3 User32/GDI32 metadata smoke through `tools\native-smoke\wave3-user32-gdi32-smoke.ps1`.
16. Wave 3 PSAPI module-query smoke through `tools\native-smoke\wave3-psapi-module-query-smoke.ps1`.
17. Wave 3 Version resource smoke through `tools\native-smoke\wave3-version-resource-smoke.ps1`.
18. Wave 3 Shell known-folder smoke through `tools\native-smoke\wave3-shell-known-folder-smoke.ps1`.
19. Wave 3 OLE32 COM lifecycle smoke through `tools\native-smoke\wave3-ole32-com-lifecycle-smoke.ps1`.
20. Wave 3 RPCRT4 UUID helper smoke through `tools\native-smoke\wave3-rpcrt4-uuid-helper-smoke.ps1`.
21. Wave 3 COMBASE-backed WinRT lifecycle smoke through `tools\native-smoke\wave3-combase-winrt-lifecycle-smoke.ps1`.
22. Wave 3 KERNEL32 memory protection smoke through `tools\native-smoke\wave3-kernel32-memory-protection-smoke.ps1`.
23. Wave 3 KERNEL32 thread lifecycle smoke through `tools\native-smoke\wave3-kernel32-thread-lifecycle-smoke.ps1`.
24. Wave 3 KERNEL32 event synchronization smoke through `tools\native-smoke\wave3-kernel32-event-sync-smoke.ps1`.
25. Wave 3 KERNEL32 mutex/semaphore synchronization smoke through `tools\native-smoke\wave3-kernel32-mutex-semaphore-smoke.ps1`.
26. Wave 3 KERNEL32 file-mapping smoke through `tools\native-smoke\wave3-kernel32-file-mapping-smoke.ps1`.
27. Wave 3 KERNEL32 process/thread identity smoke through `tools\native-smoke\wave3-kernel32-process-thread-identity-smoke.ps1`.
28. Wave 3 KERNEL32 handle metadata smoke through `tools\native-smoke\wave3-kernel32-handle-metadata-smoke.ps1`.
29. Wave 3 KERNEL32 module lifecycle smoke through `tools\native-smoke\wave3-kernel32-module-lifecycle-smoke.ps1`.
30. Wave 3 KERNEL32 file metadata smoke through `tools\native-smoke\wave3-kernel32-file-metadata-smoke.ps1`.
31. Optional Win32/x86 capture smoke through `tools\native-smoke\x86-capture-sample-smoke.ps1`.
32. Trace index smoke through `tools\native-smoke\trace-index-smoke.ps1`.
33. Collector fixture and native smoke validation through `npm run collector:validate`.

Run repeated lifecycle smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\repeat-capture-sample.ps1 -Count 5
```

The script verifies five consecutive controlled sample captures, the stable File I/O API set, dynamic loader evidence, zero dropped events, exactly one `agent_shutdown` event per run, and restored hook counts.

Run `NtCreateFile` capture smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\ntcreatefile-capture-smoke.ps1
```

The `NtCreateFile` smoke verifies the controlled `ntdll.dll` event, NTSTATUS return format, decoded sample object path evidence, shared-memory transport mode, zero dropped events, and clean hook restore.

Run shared-memory transport smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\shared-memory-transport-smoke.ps1
```

The shared-memory transport smoke verifies the healthy controlled x64 capture uses `transportMode=shared-memory`, consumes all produced records, reports zero dropped transport events, preserves the required File I/O APIs, and records hook overhead metrics.

Run shared-memory backpressure smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\shared-memory-backpressure-smoke.ps1
```

The shared-memory backpressure smoke forces a tiny transport capacity, verifies capture still completes without target hang, and checks nonzero transport dropped-event accounting.

Run loader-aware IAT sweep smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\loader-aware-iat-sweep-smoke.ps1
```

The loader-aware smoke verifies PEB module inventory evidence, initial IAT sweep status, required File I/O API preservation, shared-memory transport mode, zero drops, and clean hook restore.

Run dynamic-load re-hook smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\dynamic-load-rehook-smoke.ps1
```

The dynamic-load smoke verifies `LoadLibraryW` capture for `knmon-dynamic-probe.dll`, a `dynamic_load` IAT re-sweep, new patched slots after load, and post-load File I/O evidence from the probe DLL.

Run injection preflight negative smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\injection-preflight-negative-smoke.ps1
```

The preflight smoke verifies that missing target, missing agent, and available architecture mismatch cases fail before remote mutation and include `preflight_failed` audit evidence.

Run controlled attach smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\controlled-attach-capture-smoke.ps1
```

The controlled attach smoke verifies same-bitness attach, shared-memory transport, self-disable detach, required audit events, and mitigation policy preflight evidence before remote mutation.

Run Wave 2 Winsock smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave2-winsock-smoke.ps1
```

The Winsock smoke verifies selected `ws2_32.dll` bootstrap/address-resolution/connect metadata calls, generated network labels, stable API ID `63` for `connect`, decoded loopback endpoint evidence, shared-memory transport mode, zero dropped events, clean hook restore, and no send/recv payload, HTTP body/header/cookie/credential, network inventory, remote-memory/thread/stack, injection, or byte-preview evidence.

Run Wave 2 RPCRT4 binding option smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave2-rpcrt4-binding-smoke.ps1
```

The RPCRT4 binding smoke verifies selected local binding lifecycle calls plus `RpcBindingSetOption`, generated RPC metadata, stable API ID `54`, decoded binding handle, option ID `12`, scalar option value `5000`, shared-memory transport mode, zero dropped events, clean hook restore, and no auth, endpoint mapper, credential, network payload, RPC server communication, remote-memory/thread/stack, injection, or byte-preview evidence.

Run Wave 2 WinHTTP scalar option smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave2-winhttp-option-smoke.ps1
```

The WinHTTP option smoke verifies selected no-network session lifecycle calls plus `WinHttpSetOption`, generated HTTP metadata, stable API ID `89`, decoded `WINHTTP_OPTION_RECEIVE_TIMEOUT`, scalar option value `5000`, shared-memory transport mode, zero dropped events, clean hook restore, and no connection/request/transfer/header/body/cookie/credential/proxy-credential/raw-option-buffer/remote-memory/thread/stack/injection evidence.

Run Wave 3 User32/GDI32 smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-user32-gdi32-smoke.ps1
```

The Wave 3 smoke verifies selected User32/GDI32 low-payload metadata calls, generated UI/GDI labels, numeric handle/PID/TID/metric evidence, shared-memory transport mode, zero dropped events, clean hook restore, and no window text, pixel, clipboard, input, credential, or byte-preview payload evidence.

Run Wave 3 PSAPI module-query smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-psapi-module-query-smoke.ps1
```

The PSAPI smoke verifies selected module enumeration, module information, module base-name, and module file-name calls, generated module metadata, bounded first-module handle evidence, MODULEINFO numeric fields, module name/path strings, shared-memory transport mode, zero dropped events, clean hook restore, and no module memory, PE, file-content, hash, signature, credential, or byte-preview payload evidence.

Run Wave 3 Version resource smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-version-resource-smoke.ps1
```

The Version smoke verifies selected file version size/load/query calls, generated resource metadata, kernel32 path/size evidence, fixed file/product version fields, translation language/codepage evidence, shared-memory transport mode, zero dropped events, clean hook restore, and no raw resource, string-table, PE, file-content, hash, signature, credential, or byte-preview payload evidence.

Run Wave 3 Shell known-folder smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-shell-known-folder-smoke.ps1
```

The Shell smoke verifies selected known-folder and special-folder calls, generated Shell metadata, GUID/CSIDL/flag/handle/pointer evidence, allowlisted Windows/System/ProgramFiles path evidence, non-allowlisted path suppression, shared-memory transport mode, zero dropped events, clean hook restore, and no user-folder, AppData, command-line, environment, ShellExecute, PIDL, file-content, credential, or byte-preview payload evidence.

Run Wave 3 OLE32 COM lifecycle smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-ole32-com-lifecycle-smoke.ps1
```

The OLE32 smoke verifies selected COM apartment lifecycle and GUID helper calls, generated COM metadata, init flag/pointer/HRESULT/int return/GUID/GUID-string evidence, shared-memory transport mode, zero dropped events, clean hook restore, and no COM activation, object/interface/vtable, marshaling, storage, clipboard, drag-drop, user-path, credential, or byte-preview payload evidence.

Run Wave 3 RPCRT4 UUID helper smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-rpcrt4-uuid-helper-smoke.ps1
```

The RPCRT4 UUID smoke verifies selected UUID create/to-string/from-string calls, generated RPC metadata, stable API ID `58` promotion plus IDs `111` and `112`, bounded UUID value/string evidence, shared-memory transport mode, zero dropped events, clean hook restore, and no endpoint, auth, network, COM, credential, path, or byte-preview payload evidence.

Run Wave 3 COMBASE-backed WinRT lifecycle smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-combase-winrt-lifecycle-smoke.ps1
```

The COMBASE-backed WinRT lifecycle smoke verifies selected `RoInitialize`, `RoUninitialize`, and `RoGetApartmentIdentifier` calls through the observed `api-ms-win-core-winrt-l1-1-0.dll` provider, generated COM metadata, stable API IDs `113` through `115`, init type/HRESULT/void/apartment-id evidence, shared-memory transport mode, zero dropped events, clean hook restore, and no activation, HSTRING, runtime-class, restricted-error-info, COM object, marshaling, user-path, credential, or byte-preview payload evidence.

Run Wave 3 KERNEL32 memory protection smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-memory-protection-smoke.ps1
```

The KERNEL32 memory protection smoke verifies selected `VirtualAlloc`, `VirtualFree`, `VirtualProtect`, and `VirtualQuery` calls, generated memory metadata, stable API IDs `116` through `119`, allocation/free/protection/state/type flag decoding, decoded `MEMORY_BASIC_INFORMATION` metadata, shared-memory transport mode, zero dropped events, clean hook restore, and no remote-memory, injection, file/PE/hash, credential, or byte-preview payload evidence.

Run Wave 3 KERNEL32 thread lifecycle smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-thread-lifecycle-smoke.ps1
```

The KERNEL32 thread lifecycle smoke verifies selected `CreateThread`, `OpenThread`, `WaitForSingleObject`, and `GetExitCodeThread` calls, generated thread metadata, stable API IDs `120` through `123`, thread access/creation/wait decoding, decoded thread ID and exit-code evidence, shared-memory transport mode, zero dropped events, clean hook restore, and no remote-thread, APC, context, stack, injection, credential, or byte-preview payload evidence.

Run Wave 3 KERNEL32 event synchronization smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-event-sync-smoke.ps1
```

The KERNEL32 event synchronization smoke verifies selected `CreateEventW`, `OpenEventW`, `SetEvent`, `ResetEvent`, and `WaitForSingleObjectEx` calls, generated synchronization metadata, stable API IDs `124` through `128`, event access/BOOL/wait decoding, event handle and pointer evidence, shared-memory transport mode, zero dropped events, clean hook restore, and no event-name, object-namespace, security-descriptor, SID/ACL, wait-chain, APC, context, stack, injection, credential, or byte-preview payload evidence.

Run Wave 3 KERNEL32 mutex/semaphore synchronization smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-mutex-semaphore-smoke.ps1
```

The KERNEL32 mutex/semaphore smoke verifies selected `CreateMutexW`, `OpenMutexW`, `ReleaseMutex`, `CreateSemaphoreW`, `OpenSemaphoreW`, `ReleaseSemaphore`, and `WaitForMultipleObjectsEx` calls, generated synchronization metadata, stable API IDs `129` through `135`, mutex/semaphore access/BOOL/count/multi-wait decoding, mutex/semaphore handle and pointer-only name/handle-array evidence, shared-memory transport mode, zero dropped events, clean hook restore, and no object-name, object-namespace, security-descriptor, SID/ACL, handle-array, wait-chain, APC, context, stack, injection, credential, or byte-preview payload evidence.

Run Wave 3 KERNEL32 file-mapping smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-file-mapping-smoke.ps1
```

The KERNEL32 file-mapping smoke verifies selected `CreateFileMappingW`, `OpenFileMappingW`, `MapViewOfFile`, and `UnmapViewOfFile` calls, generated memory metadata, stable API IDs `136` through `139`, protection/access/size/offset/view-pointer decoding, pointer-only name/security evidence, shared-memory transport mode, zero dropped events, clean hook restore, and no mapping-name, object-namespace, mapped-memory, security-descriptor, stack, injection, PE/file/hash, credential, or byte-preview payload evidence.

Run Wave 3 KERNEL32 process/thread identity smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-process-thread-identity-smoke.ps1
```

The KERNEL32 process/thread identity smoke verifies selected `GetCurrentProcess`, `GetCurrentProcessId`, `GetCurrentThread`, `GetCurrentThreadId`, `GetProcessId`, and `GetThreadId` calls, generated process metadata, stable API IDs `140` through `145`, pseudo/current handle evidence, matching PID/TID values, shared-memory transport mode, zero dropped events, clean hook restore, and no process enumeration, command-line, environment, token/security, remote-memory, remote-thread, stack, injection, PE/file/hash, credential, or byte-preview payload evidence.

Run Wave 3 KERNEL32 handle metadata smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-handle-metadata-smoke.ps1
```

The KERNEL32 handle metadata smoke verifies selected `GetStdHandle`, `GetFileType`, `GetHandleInformation`, and `SetHandleInformation` calls, generated handle metadata, stable API IDs `146` through `149`, standard-handle selector, file-type, handle, and handle-flag evidence, shared-memory transport mode, zero dropped events, clean hook restore, and no object-name/security/handle-duplication/system-handle/file-payload/command-line/environment/remote-memory/remote-thread/stack/injection/PE/file/hash/credential/byte-preview payload evidence.

Run Wave 3 KERNEL32 module lifecycle smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-module-lifecycle-smoke.ps1
```

The KERNEL32 module lifecycle smoke verifies selected `GetModuleHandleW`, `GetModuleHandleExW`, `GetModuleFileNameW`, and `FreeLibrary` calls, generated module metadata, stable API IDs `150` through `153`, module-name, flag, module-handle, bounded module-path, and release evidence, shared-memory transport mode, zero dropped events, clean hook restore, and no module-memory/PE/hash/signature/enumeration/command-line/environment/remote-memory/remote-thread/stack/injection/credential/byte-preview payload evidence.

Run Wave 3 KERNEL32 file metadata smoke:

```powershell
powershell -ExecutionPolicy Bypass -File tools\native-smoke\wave3-kernel32-file-metadata-smoke.ps1
```

The KERNEL32 file metadata smoke verifies selected `GetFileSizeEx`, `GetFileTime`, and `GetFileInformationByHandle` calls, generated file metadata, stable API IDs `154` through `156`, handle, output pointer, file size, FILETIME, attributes, volume serial, link count, and file-index scalar evidence, shared-memory transport mode, zero dropped events, clean hook restore, and no file-content/path/name/directory/object-namespace/security/remote-memory/remote-thread/stack/injection/PE/file/hash/credential/byte-preview payload evidence.

Run trace index smoke:

```powershell
npm run trace-index:smoke
```

The trace index smoke verifies host-side `trace-index-*` build/query/prune over `.knapm` replay chunks, FTS text search, API/module/PID/session filters, malformed and format-mismatch DB rejection, missing-row cleanup, and no `.knapm` data deletion.

Run optional Win32/x86 capture smoke:

```powershell
cmake -S native -B build/native-win32 -A Win32
cmake --build build/native-win32 --config Debug
powershell -ExecutionPolicy Bypass -File tools\native-smoke\x86-capture-sample-smoke.ps1
```

The x86 smoke verifies same-bitness Win32 helper/target/agent capture, HELLO `architecture = "x86"`, shared-memory transport mode, the required File I/O APIs, `LoadLibraryW` dynamic-load evidence, `NtCreateFile` NTSTATUS evidence, selected Wave 2 evidence including Winsock connect metadata, RPCRT4 binding option metadata, and WinHTTP scalar option metadata, selected RPCRT4 UUID helper evidence, selected User32/GDI32 evidence, selected PSAPI module-query evidence, selected Version resource evidence, selected Shell known-folder evidence, selected OLE32 COM lifecycle evidence, selected COMBASE-backed WinRT lifecycle evidence, selected KERNEL32 memory protection evidence, selected KERNEL32 thread lifecycle evidence, selected KERNEL32 event synchronization evidence, selected KERNEL32 mutex/semaphore synchronization evidence, selected KERNEL32 file-mapping evidence, selected KERNEL32 process/thread identity evidence, selected KERNEL32 handle metadata evidence, selected KERNEL32 module lifecycle evidence, selected KERNEL32 file metadata evidence, zero dropped events, and clean hook restore.

Run collector backpressure smoke:

```powershell
npm run collector:validate
powershell -ExecutionPolicy Bypass -File tools\native-smoke\collector-backpressure-smoke.ps1
```

The collector smoke verifies synthetic intake only. It does not launch, inject, attach, or consume shared memory. The current `drop-newest` fixture expects capacity 4, events 10, retained FIFO sequence `1,2,3,4`, and dropped events `6`.
