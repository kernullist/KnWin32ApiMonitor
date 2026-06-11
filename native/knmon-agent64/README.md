# knmon-agent64

x64 agent DLL for the controlled native-capture foundation.

Current behavior:

1. Loaded by the controller through controlled launch-time early-bird APC or Phase 11A remote `LoadLibraryW` attach.
2. Starts a lightweight worker thread from `DllMain` only when launch-time environment configuration is present.
3. For attach, validates `KnMonAttachConfigV1` through exported `KnMonAgentInitialize` and starts the same worker without relying on target environment variables.
4. Exports `KnMonAgentQueryState` for loaded-agent repeated attach detection and `KnMonAgentStop` for self-disable/no-unload detach.
5. Sends a versioned HELLO JSON payload to the configured named pipe.
6. Inventories loaded modules from the PEB loader list.
7. Installs IAT hooks in eligible non-agent non-system modules and suppresses duplicate import-slot patches.
8. Writes bounded binary API records for `CreateFileW`, `CreateFileA`, `NtCreateFile`, `ReadFile`, `WriteFile`, `CloseHandle`, loader/resolver events, the selected registry API slice, the selected advapi32 token query/privilege lookup slice, the selected RPCRT4 binding and UUID helper slices, the selected bcrypt CNG provider/RNG slice, the selected crypt32 certificate-store/message-handle slice, the selected WinHTTP session-handle slice, the selected WinINet session-handle slice, the selected COMBASE-backed WinRT lifecycle slice, the selected KERNEL32 memory protection slice, and the first selected Winsock API slice into the required shared-memory transport.
9. Emits hook status, module inventory, IAT sweep status, and dropped-event accounting through the named pipe.
10. Captures `NtCreateFile` from `ntdll.dll` with NTSTATUS return evidence and bounded `OBJECT_ATTRIBUTES` object-name decoding.
11. Re-sweeps eligible modules after dynamic load and captures the controlled `knmon-dynamic-probe.dll` post-load File I/O path.
12. Supports repeated attach after self-disable by resetting restored hook bookkeeping only from a disabled/resettable lifecycle state.
13. Shares the implementation source used by `knmon-agent32`, with architecture and DLL labels selected at build time.
14. Captures selected `advapi32.dll` registry open/create/query/set/delete/close calls with bounded key/value-name and small value-preview evidence.
15. Captures selected `ws2_32.dll` Winsock startup, cleanup, socket create/close, address-resolution, address-info free, and error-query calls through IAT hooks, including explicit ordinal matching for common Winsock ordinal imports.
16. Captures selected `rpcrt4.dll` RPC string-binding compose/from/free and binding-free calls with bounded local binding string evidence, plus UUID helper calls (`UuidCreate`, `UuidToStringW`, and `UuidFromStringW`) with bounded UUID pointer/status/value/string evidence.
17. Captures selected `bcrypt.dll` CNG provider open/close, algorithm-name property query, and RNG generation calls with handle/status/pointer/size evidence only.
18. Captures selected `crypt32.dll` certificate-store and cryptographic-message open/close calls with handle/provider/encoding/flag/pointer evidence only.
19. Captures selected `winhttp.dll` session open/close calls with user-agent, access-type, proxy pointer, handle, and status evidence only.
20. Captures selected `wininet.dll` session open/close calls with user-agent, access-type, proxy pointer, handle, and status evidence only.
21. Captures selected `advapi32.dll` token query and privilege lookup calls with `TOKEN_QUERY`, token handle, privilege name, and LUID evidence only.
22. Captures selected COMBASE-backed WinRT lifecycle calls imported through `api-ms-win-core-winrt-l1-1-0.dll` with init type, HRESULT/void return, apartment-id pointer, and decoded `UINT64` evidence only.
23. Captures selected `kernel32.dll` memory allocation/protection/query calls with pointer, size, flag, return, old-protection, and `MEMORY_BASIC_INFORMATION` metadata only.

The current API hook fast path does not serialize API JSON or write API events to the named pipe. The hook path is intentionally scoped to repository sample launch or same-bitness Phase 11A/11D attach validation. It does not support cross-bitness injection, protected-process bypass, manual mapping, stealth loading, returned-pointer instrumentation, inline trampoline hooks, registry enumeration hooks, token mutation/service-control hooks, RPC auth/endpoint inquiry hooks, sequential UUID node evidence capture, COM/WinRT activation, HSTRING/runtime-class/restricted-error-info capture, object/interface/vtable/marshaling capture, bcrypt key/encrypt/decrypt/hash hooks, certificate-chain/query/decode hooks, WinHTTP connection/request/transfer/header hooks, WinINet connection/request/transfer/option hooks, token privilege array/SID/group/ACL/security descriptor/credential capture, certificate blob/private-key/message-payload capture, random/key/plaintext/ciphertext/IV/hash-input buffer capture, URL/header/body/cookie/credential/proxy-credential/payload capture, memory-content capture, remote process memory APIs, injection helper APIs, or high-volume Winsock payload hooks such as `send` and `recv`.
