# knmon-agent64

x64 agent DLL for the controlled native-capture foundation.

Current behavior:

1. Loaded by the controller through controlled launch-time early-bird APC.
2. Starts a lightweight worker thread from `DllMain`.
3. Sends a versioned HELLO JSON payload to the named pipe supplied in `KNMON_AGENT_PIPE`.
4. Installs main-module IAT hooks in the controlled sample target.
5. Emits bounded `api_call` events for `CreateFileW`, `CreateFileA`, `NtCreateFile`, `ReadFile`, `WriteFile`, and `CloseHandle`.
6. Emits hook status and dropped-event accounting.
7. Captures `NtCreateFile` from `ntdll.dll` with NTSTATUS return evidence and bounded `OBJECT_ATTRIBUTES` object-name decoding.
8. Shares the implementation source used by `knmon-agent32`, with architecture and DLL labels selected at build time.

The current hook path is intentionally scoped to the repository sample target launched by a same-bitness helper. It does not support arbitrary already-running process injection, cross-bitness injection, manual mapping, stealth loading, or inline trampoline hooks.
