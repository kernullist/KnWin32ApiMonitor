# Sample Targets

`fileio-sample` is the first controlled native-capture target.

It builds as `knmon-sample-fileio.exe` through the native CMake project and performs deterministic File I/O plus small local registry, advapi32 token query/privilege lookup, RPCRT4, bcrypt CNG, crypt32 certificate/message-handle, WinHTTP session, WinINet session, OLE32 COM lifecycle/GUID helper, COMBASE-backed WinRT lifecycle, KERNEL32 memory protection, KERNEL32 handle metadata, KERNEL32 module lifecycle, KERNEL32 process/thread identity, KERNEL32 current-process thread lifecycle, KERNEL32 event synchronization, KERNEL32 mutex/semaphore synchronization, KERNEL32 file mapping, and Winsock probes:

1. Create/open a temp file.
2. Write a small payload.
3. Read the payload back.
4. Close the file handle.
5. Call `NtCreateFile` on the same temp file.
6. Load `knmon-dynamic-probe.dll` and call its exported probe through resolver APIs.
7. Create, set, query, open, delete, and close `HKCU\Software\KNMonApiMonitorSample` with value name `SampleValue`.
8. Remove the empty sample key with `RegDeleteKeyW`; that cleanup API is not part of the monitored registry slice.
9. Open the current process token with `TOKEN_QUERY`, look up the `SeChangeNotifyPrivilege` LUID, and close the token without mutating privileges.
10. Compose a local `ncalrpc` string binding for endpoint `KNMonRpcSample`, convert it to a binding handle, then free the binding and string without contacting a remote RPC server.
11. Open a `bcrypt.dll` RNG provider, query `BCRYPT_ALGORITHM_NAME`, generate 16 random bytes, close the provider, and clear the local random buffer without printing or persisting it.
12. Open and close an in-memory `crypt32.dll` certificate store, then open and close a cryptographic message decode handle without loading certificate files, reading system stores, or copying certificate/message payload bytes.
13. Open and close a `winhttp.dll` session with user agent `KNMonWinHttpSample/1.0`, no proxy, and no network request.
14. Open and close a `wininet.dll` session with user agent `KNMonWinInetSample/1.0`, direct access, and no network request.
15. Run an OLE32 COM lifecycle/GUID helper probe on a dedicated thread without COM activation or object inspection.
16. Run a COMBASE-backed WinRT lifecycle probe on a dedicated thread with `RoInitialize(RO_INIT_MULTITHREADED)`, `RoGetApartmentIdentifier`, and balanced `RoUninitialize`, without activation factories, HSTRINGs, or runtime class names.
17. Reserve and commit a small current-process memory region with `VirtualAlloc`, change the first page to read-only with `VirtualProtect`, query `MEMORY_BASIC_INFORMATION` with `VirtualQuery`, and release the region with `VirtualFree` without copying memory contents.
18. Create/open a named pagefile-backed file mapping with `CreateFileMappingW`/`OpenFileMappingW`, map a 4096-byte view with `MapViewOfFile`, write one local byte, unmap with `UnmapViewOfFile`, and close mapping handles without copying mapping names, namespace paths, mapped memory contents, file payloads, security descriptors, PE/module metadata, remote-memory evidence, context, stacks, or injection evidence.
19. Probe current-process handle metadata with `GetStdHandle`, `GetFileType`, `GetHandleInformation`, and `SetHandleInformation` against a deterministic file handle, and avoid handle duplication, object-name/security queries, system handle enumeration, file/pipe/console payload capture, command-line/environment, remote-memory, APC, context, stack, token, or security APIs.
20. Load `version.dll`, verify `GetModuleHandleW` and `GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, ...)` return the expected module handle, query its path with `GetModuleFileNameW`, and call `FreeLibrary` exactly once without freeing borrowed handles, enumerating modules, parsing PE data, hashing files, validating signatures, copying module memory, or forcing reference-count behavior.
21. Probe current process/thread identity with `GetCurrentProcess`, `GetCurrentProcessId`, `GetProcessId`, `GetCurrentThread`, `GetCurrentThreadId`, and `GetThreadId`, verify nonzero matching PID/TID values, and avoid process enumeration, process creation, handle duplication, command-line/environment, remote-memory, APC, context, stack, token, or security APIs.
22. Create a current-process thread with `CreateThread`, open it with `OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)`, wait for `WAIT_OBJECT_0`, read exit code `0x2A` with `GetExitCodeThread`, and close both handles without remote thread, APC, context, suspend/resume, termination, or stack inspection APIs.
23. Create/open a named current-process event with `CreateEventW`/`OpenEventW`, signal it with `SetEvent`, wait with `WaitForSingleObjectEx(..., 1000, FALSE)`, reset it with `ResetEvent`, and close both handles without copying event names, namespace paths, security descriptors, wait-chain/APC evidence, context, stacks, or injection evidence.
24. Create/open a named current-process mutex with `CreateMutexW`/`OpenMutexW`, wait on it, release it with `ReleaseMutex`, create/open a named current-process semaphore with `CreateSemaphoreW`/`OpenSemaphoreW`, release one count with `ReleaseSemaphore`, wait with `WaitForMultipleObjectsEx(..., 1000, FALSE)`, and close handles without copying object names, namespace paths, security descriptors, handle-array contents, wait-chain/APC evidence, context, stacks, or injection evidence.
25. Call `WSAStartup`, `getaddrinfo("localhost", "80", ...)`, create a loopback listener with `bind`, `getsockname`, and `listen`, call `socket`, `connect`, `accept`, `WSAGetLastError`, `closesocket`, `freeaddrinfo`, and `WSACleanup`, without `send`, `recv`, external network traffic, or socket payload transfer.
26. Attempt missing wide-char and ANSI paths for error coverage.

For Phase 11A attach smoke, the sample also supports:

```powershell
knmon-sample-fileio.exe --attach-loop --iterations 24 --delay-ms 150
```

This mode starts as a normal already-running process, prints `knmon-sample-fileio attach-loop-ready pid=<pid>` with an immediate stdout flush, then performs bounded deterministic File I/O probes long enough for `attach-capture --pid` to attach and collect events.

For Phase 11B process-tree supervision smoke, the sample root supports:

```powershell
knmon-sample-fileio.exe --spawn-child-loop --children 1 --child-iterations 40 --delay-ms 150
```

This mode prints `knmon-sample-fileio tree-root-ready pid=<pid>` with an immediate stdout flush, starts child sample processes that run `--attach-loop`, prints `knmon-sample-fileio child-started pid=<pid>`, waits for children, and prints `tree-root-exiting`. The optional `--child-path <path>` argument lets smoke tests spawn a Win32 child from an x64 root to prove cross-bitness child skip before mutation.

The native helper uses this executable for controlled launch-time early-bird APC agent loading, bounded File I/O, loader, resolver, selected registry, selected advapi32 token query/privilege lookup, selected RPCRT4 binding and UUID helper, selected bcrypt CNG provider/RNG, selected crypt32 certificate-store/message-handle, selected WinHTTP session-handle, selected WinINet session-handle, selected Winsock bootstrap/address-resolution/connect metadata hook capture, selected OLE32 COM lifecycle/GUID helper capture, selected COMBASE-backed WinRT lifecycle capture, selected KERNEL32 memory protection capture, selected KERNEL32 thread lifecycle capture, selected KERNEL32 event synchronization capture, selected KERNEL32 mutex/semaphore synchronization capture, selected KERNEL32 file-mapping capture, selected KERNEL32 process/thread identity capture, selected KERNEL32 handle metadata capture, selected KERNEL32 module lifecycle capture, same-bitness Phase 11A attach validation, and Phase 11B process-tree supervision validation. Broad arbitrary process injection remains out of scope.
