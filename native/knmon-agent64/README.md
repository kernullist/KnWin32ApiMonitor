# knmon-agent64

x64 agent DLL for the controlled native-capture foundation.

Current behavior:

1. Loaded by the controller through controlled launch-time early-bird APC.
2. Starts a lightweight worker thread from `DllMain`.
3. Sends a versioned HELLO JSON payload to the named pipe supplied in `KNMON_AGENT_PIPE`.
4. Installs main-module IAT hooks in the controlled sample target.
5. Emits bounded `api_call` events for `CreateFileW`, `CreateFileA`, `ReadFile`, `WriteFile`, and `CloseHandle`.
6. Emits hook status and dropped-event accounting.

The current hook path is intentionally scoped to the repository sample target launched by the controller. It does not support arbitrary already-running process injection, manual mapping, stealth loading, or inline trampoline hooks.
