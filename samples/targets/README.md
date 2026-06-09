# Sample Targets

`fileio-sample` is the first controlled native-capture target.

It builds as `knmon-sample-fileio.exe` through the native CMake project and performs deterministic File I/O plus small local registry and Winsock probes:

1. Create/open a temp file.
2. Write a small payload.
3. Read the payload back.
4. Close the file handle.
5. Call `NtCreateFile` on the same temp file.
6. Load `knmon-dynamic-probe.dll` and call its exported probe through resolver APIs.
7. Create, set, query, open, delete, and close `HKCU\Software\KNMonApiMonitorSample` with value name `SampleValue`.
8. Remove the empty sample key with `RegDeleteKeyW`; that cleanup API is not part of the monitored registry slice.
9. Call `WSAStartup`, `getaddrinfo("localhost", "80", ...)`, `socket`, `WSAGetLastError`, `closesocket`, `freeaddrinfo`, and `WSACleanup`.
10. Attempt missing wide-char and ANSI paths for error coverage.

The native helper uses this executable for controlled launch-time early-bird APC agent loading and bounded File I/O, loader, resolver, selected registry, and selected Winsock hook capture. Arbitrary already-running process injection remains out of scope.
