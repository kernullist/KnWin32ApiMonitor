# Module lifetime and resolver contract

The x86 and x64 agents track loaded-image instances and refuse substitutions that
would call a different original function. This contract covers normal loader
images and the supported typed API set. It does not promise capture of every
first call following a dynamic load.

## Loader work and coverage

`LdrRegisterDllNotification` records a module generation and a dirty generation.
The callback only touches fixed agent-owned storage and interlocked counters.
It performs no allocation, logging, loader lookup, event signaling, or IAT work.
MSVC Debug runtime checks are disabled for this small callback path because they
can introduce CRT calls. The object-code audit rejects calls outside the four
callback functions. The callback remains registered for the pinned agent's
process lifetime, including between capture sessions.

A single worker checks dirty generations every 25 ms. A sweep completes the
generation it started with; arrivals during the sweep remain pending. Incomplete
snapshots retry with a delay that grows to one second. Hooks only request work.
The initial sweep runs during initialization. Dynamic sweeps report
`coverageTiming=eventual`; scheduling is never counted as installed coverage.

`EnumProcessModules` supplies a bounded snapshot. Each image is referenced again
before examining it, and its generation must still match. Failed or oversized
snapshots report `snapshotComplete=false`. No PEB layout or loader-lock offset
is assumed. No provider or target DLL is permanently pinned. Temporary module
references can defer its final unload until the current scan or accessor call
finishes.

`iat_sweep` records attempted patches, existing slots, conflicts, ambiguous
address matches, delay-import modules, limits and the requested generation.
`coverageStatus` is `observed`, `partial`, or `not_observed`. These are sweep
results, not a claim that all selected API calls were observed.
`unscannedModuleUnloads` counts notified image instances unloaded before a scan
examined them. It includes images that might have been ineligible and excludes
loads predating notification registration. It is a diagnostic lower bound on
unexamined dynamic instances, not an API-call loss count. A DLL can execute and
unload between worker passes. Its first calls may be unobserved even when a
later sweep installs hooks successfully.

Limits are 4,096 snapshot modules, 8,192 historical base-address keys, 32,768 hook
records, 4,096 import descriptors, 65,536 thunks per descriptor and 1,048,576
import slots per sweep. Limits and unknown identities are reported; unknown
identity never proves that a hook owner was unloaded. Paths exceeding the
current 512-byte inventory buffer cannot be used for substitution.

## Imports and original bindings

Each module's import directories are traversed once per sweep and matched to an
index of enabled module definitions. A named or known-ordinal import must still
contain the bound original address. Existing foreign IAT hooks are preserved.
Installation uses compare-and-exchange after making the slot writable, and
restoration also compares against the installed wrapper. A foreign update wins.

An absent `OriginalFirstThunk` is never treated as a name table. A unique bound
address match can be patched. Multiple matching definitions are ambiguous and
remain unchanged. Unresolved delay thunks are retained. The delay helper can be
observed through its patched resolver import; already resolved RVA-based delay
IATs are also scanned. Legacy VA-based delay descriptors are reported as
unsupported. The first delayed call is not generally guaranteed to be captured.

Hook records retain their importing module's generation. Unloaded or replaced
instances retire those records. Stop closes admission and joins the worker
before restoration. A two-second timeout retains the mapping and state as
`stop_incomplete`; it does not free storage beneath a blocked sweep.

## Resolver identity

The requested module and returned address are separately referenced. Name lookup
is case sensitive. Export identity, executable image range, target base, RVA,
load generation and the original slot are checked before substitution.

A binding is immutable for the process lifetime. A different address or a new
provider generation produces `original_conflict` and retains the resolver's
actual result. Reloading a provider therefore may leave that API uninstrumented.
Per-instance wrapper dispatch is not implemented. Cached pointers require the
same module-lifetime discipline as the original Windows function pointers.

Supported ordinal entries use the typed manual definition's verified name and
address. Unknown ordinals remain unchanged. Aliases to the same canonical
address and generation do not create competing original bindings; unknown
alias names remain uninstrumented. Resolver reports preserve `lookupKind`,
requested and target generations, original and replacement pointers, and the
reason for acceptance or refusal. A substitution intentionally changes the
published function pointer while retaining the original callable target.

Winsock error accessors are resolved under a reference held for the current
guard's lifetime. No cached accessor into an unloaded provider is reused.
Resolver classification and reporting failures are contained after the original
call; they do not replace its error state or propagate an observation exception.

## Reproduction

Build both `native` CMake configurations with `BUILD_TESTING=ON`, then run CTest.
`module-lifecycle` uses actual DLLs to cover burst loads without a later trigger,
40 unload/reload cycles, OFT absence and address ambiguity, prior IAT hooks,
delay-load resolution, two different `winmm.dll` instances, name and ordinal
lookup, alias rejection, export conflicts, generation conflicts, accessor
lifetime, short-lived unscanned instances and a paused worker racing stop.

`tools/native-smoke/dynamic-load-rehook-smoke.ps1` checks the production agent.
Its fixture enables `KNMON_DYNAMIC_PROBE_WAIT_FOR_IAT=1` and waits for an actual
IAT-owner change before the positive call. The ordinary sample retains immediate
load/call/unload behavior. This separates eventual coverage from a first-call
guarantee. Resolver and saved-session smoke tests also run against production
agents. Natural process exit is reported as `released_by_process_exit`, not as
agent-driven IAT restoration.

Run `python tools/native-smoke/verify-loader-callback.py <dumpbin.exe>
<AgentMain.obj>` on each architecture's Debug agent object. The audit checks the
callback and its complete direct-call closure, including absence of `/RTC`
helpers and x86 arithmetic helpers.

## Primary references

- [DLL notification callback restrictions](https://learn.microsoft.com/en-us/windows/win32/devnotes/ldrdllnotification)
- [Module references and handle reuse](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw)
- [Snapshot limitations](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules)
- [MSVC delay loading and IAT reset](https://learn.microsoft.com/en-us/cpp/build/reference/linker-support-for-delay-loaded-dlls?view=msvc-170)
- [MSVC runtime-check pragma](https://learn.microsoft.com/en-us/cpp/preprocessor/runtime-checks?view=msvc-170)
