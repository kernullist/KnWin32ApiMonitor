# knmon-agent32

x86 agent DLL for the controlled same-bitness native-capture foundation.

Current behavior:

1. Built from the shared agent implementation source used by `knmon-agent64`.
2. Loaded by the Win32 `knmon-native-helper.exe` through controlled launch-time early-bird APC or Phase 11A remote `LoadLibraryW` attach.
3. Supports only same-bitness x86 helper -> x86 target -> `knmon-agent32.dll` capture.
4. Starts from launch-time environment configuration in `DllMain`, or from exported `KnMonAgentInitialize` with `KnMonAttachConfigV1` in attach mode.
5. Exports `KnMonAgentQueryState` for loaded-agent repeated attach detection and `KnMonAgentStop` for self-disable/no-unload detach.
6. Sends a versioned HELLO JSON payload with `architecture = "x86"`.
7. Inventories loaded modules from the PEB loader list.
8. Installs IAT hooks in eligible non-agent non-system modules and suppresses duplicate import-slot patches.
9. Writes bounded binary API records for `CreateFileW`, `CreateFileA`, `NtCreateFile`, `ReadFile`, `WriteFile`, `CloseHandle`, loader/resolver events, the selected registry API slice, the selected advapi32 token query/privilege lookup slice, the selected RPCRT4 binding and UUID helper slices, the selected bcrypt CNG provider/RNG slice, the selected crypt32 certificate-store/message-handle slice, the selected WinHTTP session-handle slice, the selected WinINet session-handle slice, the selected COMBASE-backed WinRT lifecycle slice, the selected KERNEL32 memory protection slice, the selected KERNEL32 thread lifecycle slice, and the first selected Winsock API slice into the required shared-memory transport.
10. Emits hook status, module inventory, IAT sweep status, dropped-event accounting, and `agent_shutdown` lifecycle evidence through the named pipe.
11. Captures `NtCreateFile` from `ntdll.dll` with NTSTATUS return evidence and bounded `OBJECT_ATTRIBUTES` object-name decoding.
12. Re-sweeps eligible modules after dynamic load and captures the controlled `knmon-dynamic-probe.dll` post-load File I/O path.
13. Supports repeated attach after self-disable by resetting restored hook bookkeeping only from a disabled/resettable lifecycle state.
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
24. Captures selected `kernel32.dll` current-process thread lifecycle/wait calls with pointer-sized inputs, thread access/creation/wait flags, thread IDs, wait results, and exit-code metadata only.

The current API hook fast path does not serialize API JSON or write API events to the named pipe. The x86 path is intentionally scoped to the repository sample target launched or attached by a Win32 helper. It does not support cross-bitness injection, protected-process bypass, broad arbitrary process attach, manual mapping, stealth loading, returned-pointer instrumentation, inline trampoline hooks, registry enumeration hooks, token mutation/service-control hooks, RPC auth/endpoint inquiry hooks, sequential UUID node evidence capture, COM/WinRT activation, HSTRING/runtime-class/restricted-error-info capture, object/interface/vtable/marshaling capture, bcrypt key/encrypt/decrypt/hash hooks, certificate-chain/query/decode hooks, WinHTTP connection/request/transfer/header hooks, WinINet connection/request/transfer/option hooks, token privilege array/SID/group/ACL/security descriptor/credential capture, certificate blob/private-key/message-payload capture, random/key/plaintext/ciphertext/IV/hash-input buffer capture, URL/header/body/cookie/credential/proxy-credential/payload capture, memory-content capture, remote process memory APIs, remote-thread/APC/context/stack capture, injection helper APIs, or high-volume Winsock payload hooks such as `send` and `recv`.
