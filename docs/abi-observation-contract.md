# ABI and argument observation

The native agent supports Windows x86 and x64. `toolchain.json` pins the compiler
and SDK used for the reference build. A successful build checks every installed
wrapper against its original-function slot and an independent declaration:
318 public SDK declarations and two native loader declarations from pinned PHNT.
The assertions are in `GeneratedSdkAbiChecks.inc`. PSAPI export aliases are checked
against their corresponding K32 SDK declarations. The GDI+ flat export uses its
SDK namespace, not a hand-written pointer typedef.

`generated/sdk-abi-ir.json` binds export names, wrapper symbols and declaration
authorities. `generated/sdk-abi-sources.json` pins the SDK header hashes and native
prototype source. These artifacts establish type provenance. Runtime behavior,
module resolution, output validity and exception handling need separate tests.
Compiler checks do not promote a wrapper to `differential_verified`.

The loader signatures come from
[PHNT commit 53fbbdc](https://github.com/winsiderss/phnt/blob/53fbbdc5b5d2b08761db1c7b26bfa8c820924356/ntldr.h).
`LdrLoadDll` takes a **pointer** to DLL characteristics. It must not be passed
through a 32-bit integer. Its path can contain tagged loader flags; the agent
does not read a tagged value as a UTF-16 string. The characteristics argument is
currently preserved as an address, without claiming a pointee sample.

Microsoft's [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
assigns floating-point and aggregate values differently from integer arguments.
Variadic functions have additional rules. Integer dispatch is therefore disabled
for the unverified catalog. The current
[Win32Metadata 71.0.26 preview](https://www.nuget.org/packages/Microsoft.Windows.SDK.Win32Metadata/71.0.26-preview)
is a useful declaration source, but its presence does not prove wrapper safety.

## Typed floating-point, aggregate and callback wrappers

Six reviewed contracts use generated, SDK-typed C++ wrappers: VarR8FromR4,
VarR4FromR8, D2D1ConvertColorSpace, D2D1MakeRotateMatrix, D2D1Vec3Length and
EnumChildWindows. The compiler supplies the x86/x64 calling convention, floating
registers and hidden aggregate-return buffer. The argument pack retains its
actual types. Unknown signatures and variadic functions remain blocked.

The five Automation/Direct2D SDK imports use ordinals in the reference target.
Their reviewed ordinals are included in the hook definition; the existing IAT
address and module-generation checks still have to match the named export.
Production injection tests exercise these imports as well as the named callback
API. An original/wrapper direct call alone would not detect a missing IAT hook.

Arguments include exact entry bits, width and encoding. A by-value point contains
two little-endian binary32 values. Pointer arguments record the address with
`targetMemoryRead: false`; these six wrappers do not sample pointees. The 16-byte
color result uses `rawReturnBytes`, `rawReturnBits: 128` and
`rawReturnEncoding: little_endian_object_bytes`, without a truncated scalar
`rawReturnValue`. Transport ABI 10 and attach configuration ABI 6 reject older
incompatible layouts.

Optional [native stack capture](stack-observation.md) adds a bounded raw-address
observation after the API returns. It does not change argument/result encoding
or establish API-entry frames. The ABI differential corpus runs with capture
disabled and with a 32-frame limit.

`generated/typed-abi-proof.json` records executed x86/x64 Debug differential and
production-injection/replay results on Windows 10.0.26200, with source, binary and
system-DLL hashes. Only these six APIs are marked `differential_verified` in the
runtime manifest. That means the recorded corpus passed on the recorded build;
it does not imply exhaustive inputs, Release behavior or another Windows build.
The proof checker invalidates promotion after relevant source changes. Source
hashes normalize CRLF to LF so checkout line endings do not change the claim.

## Record identity

`eventId` identifies the retained/session presentation event. It is not the
transport sequence. New captures preserve `recordSequence` as a canonical decimal
string through native output, Rust, UI, JSONL export, KNAPM replay and SQLite search.
Strings preserve values beyond JavaScript's exact integer range. Tombstones and
filtered records can leave gaps; readers must not reconstruct sequence numbers
from the chunk start and line offset.

New normal-return events also carry a process-local `callId` allocated at hook
entry. It is independent of return-order `recordSequence`, stays unique across
threads and agent session restarts in that process, and is a decimal string.
Only root calls are observed: `parentCallId` is `"0"` and `callDepth` is zero.
These fields do not imply a captured callback tree. At INT64_MAX, ID allocation
stops and identity fields are omitted instead of wrapping or reusing an ID.
Process identity remains necessary when comparing events from different targets.

A chunk with sequence identities must have a strictly increasing sequence within
its declared first/last bounds, with matching endpoint identities. Legacy chunks
without identities remain readable. Search returns `recordSequence: null` for
them. A mixture of available and missing identities within one chunk is invalid.

Trace index schema 2 stores exact identity strings. Schema 1 derived databases
must be rebuilt with `trace-index-build --rebuild`; their fabricated identities
are not treated as evidence. Original session data is not modified by rebuilding.
Foreign databases are rejected before schema writes. Trace queries accept limits
from 1 through 5000 and retain at most 6 MiB of encoded event results. Exceeding the
byte budget fails the query without returning partial results; reduce the limit
or narrow the filters. SQLite connections also enforce an 8 MiB string/blob/row
limit through [sqlite3_limit](https://sqlite.org/c3ref/limit.html). Embedded NUL
bytes survive text reads, and excerpts end at a UTF-8 code point boundary.

## Observation scope

API records currently describe a normal return from the original call. Nested
calls made while the original function is running, including calls from callbacks,
are suppressed by the reentry guard. An original exception propagates to the
caller and does not produce a normal-return event. These limits are carried in
the `observation` object. There is no IOCP/APC completion correlation claim.

The explicit `capture` object on an argument describes a memory sample:

| Field | Meaning |
| --- | --- |
| `phase` | `entry`, `exit`, or `none` |
| `readStatus` | Complete bounded read, null pointer, unreadable memory, partial read, or not captured |
| `byteCountSource` | The source used to determine the sample extent |
| `requestedBytes` | Logical sample extent, before the capture limit |
| `capturedBytes` | Bytes actually read into the sample |
| `limitBytes` | Maximum bytes allowed for this sample |
| `truncationReason` | Capture limit, read failure, missing count, original failure, or untracked overlapped completion |

A complete bounded read can still be truncated relative to the requested extent.
The separate byte counts and truncation reason distinguish these cases. A pointer
address or legacy `preCallValue`/`postCallValue` label alone is not proof of a
memory sample at that phase. `captureTiming` in definition metadata is a requested
policy; only the explicit observation object describes the recorded sample.

WriteFile snapshots at most 16 input bytes before invoking the original. A failed
call can therefore still have an entry sample. ReadFile samples at most 16 output
bytes only after synchronous success and a readable returned byte count within
the original requested size. Zero-byte output is distinct from unreadable output.
Output count addresses and `lpOverlapped` are preserved; a missing sample is not
replaced with a fabricated zero value.

For overlapped calls, output buffers and output byte counts are not sampled on
return, including an immediate successful return. The capture states that
completion is untracked. This conservative policy follows the lifetime and
completion constraints in the [ReadFile documentation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile).
Failure results with potentially meaningful partial output are not decoded by
this synchronous-success policy. Buffer samples are observations of caller memory,
not an atomic snapshot against concurrent writers.

Rust preserves argument metadata instead of dropping optional fields during
deserialization. The UI displays sample phase, byte counts and truncation reason.
JSONL export preserves timing, raw results, raw error state, sequence identity and
observation metadata.

## Validation commands

Run from the repository root:

```powershell
npm run abi:check
npm run abi:typed:check
npm run abi:sdk:verify
cmake --build build/native-msvc --config Debug --parallel 4
cmake --build build/native-msvc-x86 --config Debug --parallel 4
ctest --test-dir build/native-msvc -C Debug --output-on-failure
ctest --test-dir build/native-msvc-x86 -C Debug --output-on-failure
node tools/session-validator/validate-record-identity.mjs build/native-msvc/Debug/knmon-native-helper.exe
npm run abi:proof:generate
npm run agent-hooks:generate
npm run abi:proof:check
$env:KNMON_COLLECTOR_HELPER = "$PWD/build/native-msvc/Debug/knmon-collector.exe"
npm run verify
```

The ABI differential CTest calls production wrapper bodies inside a test-only
agent. It compares original and wrapped file and native-loader calls, including
return values, output bytes and last-error state. Its injected originals cover
entry-buffer mutation, noncanonical BOOL success and asynchronous states.
Guarded pages and pointer-width/entry-phase negative controls exercise failures
that smoke success alone cannot detect. Production-agent capture/replay tests
separately check the transport, helper and saved-session paths. This scoped corpus
does not imply differential coverage for every SDK-checked API.
The typed corpus additionally compares floating-point status, signed zero,
subnormals, infinities, quiet/signaling NaNs, conversion failure, complete
aggregate bytes, callback context/early termination, original C++/SEH propagation
and suppressed reentry. Concurrent and saturated call-ID tests check identity
allocation. The proof runner rebuilds both architectures before executing tests.
