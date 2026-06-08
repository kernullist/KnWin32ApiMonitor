# knmon-agent32

x86 agent DLL for the controlled same-bitness native-capture foundation.

Current behavior:

1. Built from the shared agent implementation source used by `knmon-agent64`.
2. Loaded by the Win32 `knmon-native-helper.exe` through controlled launch-time early-bird APC.
3. Supports only same-bitness x86 helper -> x86 target -> `knmon-agent32.dll` capture.
4. Sends a versioned HELLO JSON payload with `architecture = "x86"`.
5. Installs main-module IAT hooks in the controlled sample target.
6. Emits bounded `api_call` events for `CreateFileW`, `CreateFileA`, `NtCreateFile`, `ReadFile`, `WriteFile`, and `CloseHandle`.
7. Emits hook status, dropped-event accounting, and `agent_shutdown` lifecycle evidence.
8. Captures `NtCreateFile` from `ntdll.dll` with NTSTATUS return evidence and bounded `OBJECT_ATTRIBUTES` object-name decoding.

The x86 path is intentionally scoped to the repository sample target launched by a Win32 helper. It does not support cross-bitness injection, arbitrary already-running process attach, manual mapping, stealth loading, or inline trampoline hooks.
