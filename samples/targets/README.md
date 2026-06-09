# Sample Targets

`fileio-sample` is the first controlled native-capture target.

It builds as `knmon-sample-fileio.exe` through the native CMake project and performs deterministic File I/O plus small local registry, RPCRT4, bcrypt CNG, crypt32 certificate/message-handle, WinHTTP session, and Winsock probes:

1. Create/open a temp file.
2. Write a small payload.
3. Read the payload back.
4. Close the file handle.
5. Call `NtCreateFile` on the same temp file.
6. Load `knmon-dynamic-probe.dll` and call its exported probe through resolver APIs.
7. Create, set, query, open, delete, and close `HKCU\Software\KNMonApiMonitorSample` with value name `SampleValue`.
8. Remove the empty sample key with `RegDeleteKeyW`; that cleanup API is not part of the monitored registry slice.
9. Compose a local `ncalrpc` string binding for endpoint `KNMonRpcSample`, convert it to a binding handle, then free the binding and string without contacting a remote RPC server.
10. Open a `bcrypt.dll` RNG provider, query `BCRYPT_ALGORITHM_NAME`, generate 16 random bytes, close the provider, and clear the local random buffer without printing or persisting it.
11. Open and close an in-memory `crypt32.dll` certificate store, then open and close a cryptographic message decode handle without loading certificate files, reading system stores, or copying certificate/message payload bytes.
12. Open and close a `winhttp.dll` session with user agent `KNMonWinHttpSample/1.0`, no proxy, and no network request.
13. Call `WSAStartup`, `getaddrinfo("localhost", "80", ...)`, `socket`, `WSAGetLastError`, `closesocket`, `freeaddrinfo`, and `WSACleanup`.
14. Attempt missing wide-char and ANSI paths for error coverage.

The native helper uses this executable for controlled launch-time early-bird APC agent loading and bounded File I/O, loader, resolver, selected registry, selected RPCRT4 binding, selected bcrypt CNG provider/RNG, selected crypt32 certificate-store/message-handle, selected WinHTTP session-handle, and selected Winsock hook capture. Arbitrary already-running process injection remains out of scope.
