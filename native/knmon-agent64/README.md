# knmon-agent64

x64 agent DLL for the controlled native-capture foundation.

Current behavior:

1. Loaded by the controller through controlled launch-time early-bird APC.
2. Starts a lightweight worker thread from `DllMain`.
3. Sends a versioned HELLO JSON payload to the named pipe supplied in `KNMON_AGENT_PIPE`.
4. Inventories loaded modules from the PEB loader list.
5. Installs IAT hooks in eligible non-agent non-system modules and suppresses duplicate import-slot patches.
6. Writes bounded binary API records for `CreateFileW`, `CreateFileA`, `NtCreateFile`, `ReadFile`, `WriteFile`, `CloseHandle`, and loader events into the required shared-memory transport when `KNMON_TRANSPORT_NAME` is supplied.
7. Emits hook status, module inventory, IAT sweep status, and dropped-event accounting through the named pipe.
8. Captures `NtCreateFile` from `ntdll.dll` with NTSTATUS return evidence and bounded `OBJECT_ATTRIBUTES` object-name decoding.
9. Re-sweeps eligible modules after dynamic load and captures the controlled `knmon-dynamic-probe.dll` post-load File I/O path.
10. Shares the implementation source used by `knmon-agent32`, with architecture and DLL labels selected at build time.

The current API hook fast path does not serialize API JSON or write API events to the named pipe. The hook path is intentionally scoped to the repository sample target launched by a same-bitness helper. It does not support arbitrary already-running process injection, cross-bitness injection, manual mapping, stealth loading, returned-pointer instrumentation, or inline trampoline hooks.
