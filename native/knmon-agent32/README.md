# knmon-agent32

x86 agent DLL for the controlled same-bitness native-capture foundation.

Current behavior:

1. Built from the shared agent implementation source used by `knmon-agent64`.
2. Loaded by the Win32 `knmon-native-helper.exe` through controlled launch-time early-bird APC.
3. Supports only same-bitness x86 helper -> x86 target -> `knmon-agent32.dll` capture.
4. Sends a versioned HELLO JSON payload with `architecture = "x86"`.
5. Inventories loaded modules from the PEB loader list.
6. Installs IAT hooks in eligible non-agent non-system modules and suppresses duplicate import-slot patches.
7. Writes bounded binary API records for `CreateFileW`, `CreateFileA`, `NtCreateFile`, `ReadFile`, `WriteFile`, `CloseHandle`, loader/resolver events, the selected registry API slice, the selected advapi32 token query/privilege lookup slice, the selected RPCRT4 binding slice, the selected bcrypt CNG provider/RNG slice, the selected crypt32 certificate-store/message-handle slice, the selected WinHTTP session-handle slice, the selected WinINet session-handle slice, and the first selected Winsock API slice into the required shared-memory transport.
8. Emits hook status, module inventory, IAT sweep status, dropped-event accounting, and `agent_shutdown` lifecycle evidence through the named pipe.
9. Captures `NtCreateFile` from `ntdll.dll` with NTSTATUS return evidence and bounded `OBJECT_ATTRIBUTES` object-name decoding.
10. Re-sweeps eligible modules after dynamic load and captures the controlled `knmon-dynamic-probe.dll` post-load File I/O path.
11. Captures selected `advapi32.dll` registry open/create/query/set/delete/close calls with bounded key/value-name and small value-preview evidence.
12. Captures selected `ws2_32.dll` Winsock startup, cleanup, socket create/close, address-resolution, address-info free, and error-query calls through IAT hooks, including explicit ordinal matching for common Winsock ordinal imports.
13. Captures selected `rpcrt4.dll` RPC string-binding compose/from/free and binding-free calls with bounded local binding string evidence.
14. Captures selected `bcrypt.dll` CNG provider open/close, algorithm-name property query, and RNG generation calls with handle/status/pointer/size evidence only.
15. Captures selected `crypt32.dll` certificate-store and cryptographic-message open/close calls with handle/provider/encoding/flag/pointer evidence only.
16. Captures selected `winhttp.dll` session open/close calls with user-agent, access-type, proxy pointer, handle, and status evidence only.
17. Captures selected `wininet.dll` session open/close calls with user-agent, access-type, proxy pointer, handle, and status evidence only.
18. Captures selected `advapi32.dll` token query and privilege lookup calls with `TOKEN_QUERY`, token handle, privilege name, and LUID evidence only.

The current API hook fast path does not serialize API JSON or write API events to the named pipe. The x86 path is intentionally scoped to the repository sample target launched by a Win32 helper. It does not support cross-bitness injection, arbitrary already-running process attach, manual mapping, stealth loading, returned-pointer instrumentation, inline trampoline hooks, registry enumeration hooks, token mutation/service-control hooks, RPC auth/endpoint inquiry hooks, bcrypt key/encrypt/decrypt/hash hooks, certificate-chain/query/decode hooks, WinHTTP connection/request/transfer/header hooks, WinINet connection/request/transfer/option hooks, token privilege array/SID/group/ACL/security descriptor/credential capture, certificate blob/private-key/message-payload capture, random/key/plaintext/ciphertext/IV/hash-input buffer capture, URL/header/body/cookie/credential/proxy-credential/payload capture, or high-volume Winsock payload hooks such as `send` and `recv`.
