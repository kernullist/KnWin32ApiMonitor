# Sample Targets

`fileio-sample` is the first controlled native-capture target.

It builds as `knmon-sample-fileio.exe` through the native CMake project and performs deterministic File I/O plus small local registry, advapi32 token query/privilege lookup, RPCRT4, bcrypt CNG, crypt32 certificate/message-handle, WinHTTP session, WinINet session, OLE32 COM lifecycle/GUID helper, COMBASE-backed WinRT lifecycle, KERNEL32 memory protection, and Winsock probes:

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
18. Call `WSAStartup`, `getaddrinfo("localhost", "80", ...)`, `socket`, `WSAGetLastError`, `closesocket`, `freeaddrinfo`, and `WSACleanup`.
19. Attempt missing wide-char and ANSI paths for error coverage.

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

The native helper uses this executable for controlled launch-time early-bird APC agent loading, bounded File I/O, loader, resolver, selected registry, selected advapi32 token query/privilege lookup, selected RPCRT4 binding and UUID helper, selected bcrypt CNG provider/RNG, selected crypt32 certificate-store/message-handle, selected WinHTTP session-handle, selected WinINet session-handle, selected Winsock hook capture, selected OLE32 COM lifecycle/GUID helper capture, selected COMBASE-backed WinRT lifecycle capture, selected KERNEL32 memory protection capture, same-bitness Phase 11A attach validation, and Phase 11B process-tree supervision validation. Broad arbitrary process injection remains out of scope.
