# knmon-agent64

x64 agent DLL for the controlled native-capture foundation.

Current behavior:

1. Loaded by the controller through controlled launch-time early-bird APC.
2. Starts a lightweight worker thread from `DllMain`.
3. Sends a versioned HELLO JSON payload to the named pipe supplied in `KNMON_AGENT_PIPE`.
4. Inventories loaded modules from the PEB loader list.
5. Installs IAT hooks in eligible non-agent non-system modules and suppresses duplicate import-slot patches.
6. Writes bounded binary API records for `CreateFileW`, `CreateFileA`, `NtCreateFile`, `ReadFile`, `WriteFile`, `CloseHandle`, loader/resolver events, the selected registry API slice, and the first selected Winsock API slice into the required shared-memory transport when `KNMON_TRANSPORT_NAME` is supplied.
7. Emits hook status, module inventory, IAT sweep status, and dropped-event accounting through the named pipe.
8. Captures `NtCreateFile` from `ntdll.dll` with NTSTATUS return evidence and bounded `OBJECT_ATTRIBUTES` object-name decoding.
9. Re-sweeps eligible modules after dynamic load and captures the controlled `knmon-dynamic-probe.dll` post-load File I/O path.
10. Shares the implementation source used by `knmon-agent32`, with architecture and DLL labels selected at build time.
11. Captures selected `advapi32.dll` registry open/create/query/set/delete/close calls with bounded key/value-name and small value-preview evidence.
12. Captures selected `ws2_32.dll` Winsock startup, cleanup, socket create/close, address-resolution, address-info free, and error-query calls through IAT hooks, including explicit ordinal matching for common Winsock ordinal imports.

The current API hook fast path does not serialize API JSON or write API events to the named pipe. The hook path is intentionally scoped to the repository sample target launched by a same-bitness helper. It does not support arbitrary already-running process injection, cross-bitness injection, manual mapping, stealth loading, returned-pointer instrumentation, inline trampoline hooks, registry enumeration hooks, token/service-control hooks, or high-volume Winsock payload hooks such as `send` and `recv`.
