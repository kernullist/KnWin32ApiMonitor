# knmon-agent32

x86 agent DLL for the controlled same-bitness native-capture foundation.

Current behavior:

1. Built from the shared agent implementation source used by `knmon-agent64`.
2. Loaded by the Win32 `knmon-native-helper.exe` through controlled launch-time early-bird APC.
3. Supports only same-bitness x86 helper -> x86 target -> `knmon-agent32.dll` capture.
4. Sends a versioned HELLO JSON payload with `architecture = "x86"`.
5. Inventories loaded modules from the PEB loader list.
6. Installs IAT hooks in eligible non-agent non-system modules and suppresses duplicate import-slot patches.
7. Writes bounded binary API records for `CreateFileW`, `CreateFileA`, `NtCreateFile`, `ReadFile`, `WriteFile`, `CloseHandle`, loader/resolver events, and the first selected Winsock API slice into the required shared-memory transport.
8. Emits hook status, module inventory, IAT sweep status, dropped-event accounting, and `agent_shutdown` lifecycle evidence through the named pipe.
9. Captures `NtCreateFile` from `ntdll.dll` with NTSTATUS return evidence and bounded `OBJECT_ATTRIBUTES` object-name decoding.
10. Re-sweeps eligible modules after dynamic load and captures the controlled `knmon-dynamic-probe.dll` post-load File I/O path.
11. Captures selected `ws2_32.dll` Winsock startup, cleanup, socket create/close, address-resolution, address-info free, and error-query calls through IAT hooks, including explicit ordinal matching for common Winsock ordinal imports.

The current API hook fast path does not serialize API JSON or write API events to the named pipe. The x86 path is intentionally scoped to the repository sample target launched by a Win32 helper. It does not support cross-bitness injection, arbitrary already-running process attach, manual mapping, stealth loading, returned-pointer instrumentation, inline trampoline hooks, or high-volume Winsock payload hooks such as `send` and `recv`.
