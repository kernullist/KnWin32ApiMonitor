# Resolver-Returned Pointer Instrumentation Design

Status: reviewed design with candidate-ledger implementation, no pointer-call instrumentation.

Updated: 2026-06-20

## Goal

Close the coverage gap between resolver visibility and actual calls made through
function pointers returned by `GetProcAddress` or `LdrGetProcedureAddress`
without overstating current IAT hook coverage.

The current product can claim resolver call visibility. It cannot claim that a
later direct call through the returned function pointer is instrumented unless a
separate reviewed method has installed and proven call interception for that
specific pointer target.

## Current Behavior

Current loader-aware coverage provides these paths:

1. Initial PEB module inventory.
2. Eligible-module IAT sweep.
3. Dynamic-load IAT re-sweep after `LoadLibrary*` and `LdrLoadDll` activity.
4. Resolver call monitoring for `GetProcAddress` and
   `LdrGetProcedureAddress`.
5. Bounded shared-memory `api_call` records for the selected imported APIs.
6. Candidate-ledger lifecycle messages for resolver-returned pointers:
   - `resolver_pointer_candidate`
   - `resolver_pointer_unsupported`
7. Controller audit/output summaries for candidate-ledger messages.

This captures APIs reached through import slots in eligible modules. It also
captures resolver calls with bounded function-name evidence and return/status
values. The candidate ledger classifies returned pointers, but it does not
automatically capture a later call through a raw function pointer returned by
the resolver.

## Coverage Model

Every API definition and runtime observation must be classified using one of the
following labels. UI, session replay, and coverage reporting should preserve the
distinction.

### IAT Covered

The target API is imported through an eligible module import table, the import
slot was patched by the agent, and the hook path emits bounded shared-memory
records.

Claim allowed:

1. Calls through that patched import slot are instrumented.
2. Hook lifecycle, restore counts, transport metrics, and smoke evidence can be
   used as coverage proof.

Claim not allowed:

1. Calls made through separately resolved function pointers are covered.
2. Calls through unpatched modules, delay-load helpers that bypass the patched
   slot, or direct syscalls are covered.

### Resolver Observed

`GetProcAddress` or `LdrGetProcedureAddress` was called and the monitor recorded
the resolver module, requested function name or ordinal when available, status
or return pointer, caller process/thread identity, and bounded timing evidence.

Claim allowed:

1. The resolver lookup was observed.
2. The requested symbol can be correlated with known definitions when metadata
   is sufficient.

Claim not allowed:

1. The returned pointer was later called.
2. Any call through that pointer was instrumented.

### Resolver Pointer Candidate

The resolver returned a non-null pointer that can be mapped to a loaded module,
an executable image range, and a known or safely reportable export identity. No
call interception has been installed.

Claim allowed:

1. The pointer is a candidate for future reviewed instrumentation.
2. The pointer identity can be reported as `candidate` with reason evidence.

Claim not allowed:

1. The pointer call is covered.
2. A mutation has been made to the target code or export table.

### Resolver Pointer Instrumented

A reviewed pointer-call interception method has been installed for the resolved
target and has an explicit rollback record.

Claim allowed:

1. Calls reaching that installed interception point are instrumented.
2. The installed method, API id, target module identity, target RVA, rollback
   state, and hook lifecycle evidence can be used as proof.

Claim not allowed:

1. Other resolver-returned pointers for the same API are covered unless they
   share the exact installed interception point.
2. Inline/EAT/breakpoint/skip-call behavior is implied unless the reviewed
   method explicitly says so.

### Unsupported

The resolver result cannot be safely associated with an instrumentable API, or
instrumentation is not permitted by policy.

Common unsupported reasons:

1. Null result or resolver failure.
2. Ordinal-only lookup without trusted metadata.
3. Forwarded export whose final host is not verified.
4. Pointer outside a loaded executable image range.
5. Pointer into an agent, helper, JIT, private allocation, or unknown module.
6. Existing third-party patch or instruction pattern that cannot be validated.
7. Module unload race or unstable module identity.
8. API family blocked by payload, credential, remote-memory, COM/vtable,
   callback, window-message, or injection-helper policy.
9. Missing ABI descriptor, calling convention, or safe argument model.

Unsupported does not mean failure of resolver monitoring. It means the product
must not claim pointer-call coverage for that resolver result.

## Recommended Implementation Path

The first implementation slice is a candidate ledger only. It does not patch
code, patch export tables, rewrite caller variables, wrap arbitrary function
pointers, or install broad detours.

Candidate ledger responsibilities:

1. On each successful resolver event, classify the returned pointer.
2. Map the pointer to the current loaded-module list by base and image size.
3. Verify that the pointer lies in an executable image section when PE metadata
   is available.
4. Resolve an export identity by module, RVA, function name, ordinal, and
   forwarder host where possible.
5. Compare the export identity to generated API definitions and hook policy.
6. Emit low-volume lifecycle evidence:
   - `resolver_pointer_candidate`
   - `resolver_pointer_unsupported`
7. Keep `api_call` events reserved for actual API calls, not resolver
   classification.
8. Preserve current hot-path constraints: fixed-size shared-memory records for
   high-volume hooks, no JSON serialization in target hook fast paths, no
   blocking writes, and no heap-heavy payload capture.

This gives the product honest coverage reporting before introducing a risky
call-interception method.

## Future Hook Method

Any future pointer-call interception should be opt-in, allowlisted, and
definition-driven. Broad inline detours are not approved by this design.

A future prototype may be reviewed only after the candidate ledger is stable.
The smallest acceptable prototype is one low-risk, low-volume, fixed-signature
API in a repository-owned sample target, with both x64 and x86 rollback smoke
coverage.

Required hook descriptor fields:

1. API id and generated definition version.
2. Provider module identity:
   - normalized path
   - base address
   - image size
   - timestamp or checksum when available
3. Export identity:
   - function name or ordinal
   - resolved host for API-set and forwarded exports
   - target RVA
4. Calling convention and architecture.
5. Install method.
6. Install state and rollback state.
7. Original bytes or original pointer value when mutation is used.
8. Owning session and operation id.
9. Duplicate suppression key.

Duplicate suppression key:

```text
module_identity + export_rva + api_id + architecture + calling_convention + install_method
```

Rollback requirements:

1. Do not install if the module identity changed after classification.
2. Do not install if the target address no longer points into the same image
   executable range.
3. Record the exact original state before mutation.
4. Restore before detach, self-disable, or unload-sensitive shutdown.
5. If rollback cannot be proven, emit `recovery_required` evidence and stop
   claiming healthy pointer instrumentation for that target.
6. Never write stale bytes into an unloaded or remapped module.

## Transport ABI

No transport ABI change is required for this design-only step.

The candidate-ledger implementation can use low-volume lifecycle events because
resolver classification is tied to resolver calls, not high-volume API call
hooks.

Potential future additive event kinds:

1. `resolver_pointer_candidate`
2. `resolver_pointer_unsupported`
3. `resolver_pointer_instrumented`
4. `resolver_pointer_uninstrumented`
5. `resolver_pointer_rollback`
6. `resolver_pointer_call`

The only high-volume future event is `resolver_pointer_call`, and it must use
the same bounded binary shared-memory principles as existing `api_call` records.
Do not put JSON serialization, export parsing, symbol resolution, PE parsing, or
heap-heavy decode work into a hot call path.

Minimum candidate lifecycle fields:

1. Resolver event sequence or correlation id.
2. Process id and thread id.
3. Resolver API id.
4. Requested module/name/ordinal evidence.
5. Returned pointer.
6. Classified module id or module path hash.
7. Export RVA when known.
8. Classification:
   - `candidate`
   - `unsupported`
9. Reason code.
10. Definition API id when mapped.

## Failure And Race Handling

Resolver-pointer classification must fail closed. If any invariant is uncertain,
record `unsupported` with reason evidence and keep resolver visibility intact.

Required handling:

1. Module unload between resolver return and classification:
   - report `unsupported_module_unloaded`
   - do not dereference stale image memory
2. Module remap at the same base:
   - report `unsupported_module_identity_changed`
   - require a fresh resolver event
3. Forwarded export:
   - resolve to the final host only when loader evidence and export metadata
     agree
   - otherwise report `unsupported_forwarder_unresolved`
4. API-set host mismatch:
   - report the requested API-set name and observed host
   - do not assume that current-OS host mapping is universal
5. Ordinal-only lookup:
   - allow candidate only when the ordinal maps to trusted generated metadata
   - otherwise report `unsupported_ordinal_metadata_missing`
6. Existing patch or unknown prologue:
   - report `unsupported_existing_patch`
   - do not chain broad hooks by default
7. CFG/CET or mitigation uncertainty:
   - report `unsupported_mitigation_uncertain`
8. Blocked API family:
   - report the policy reason, such as `blocked_payload_sensitive`,
     `blocked_remote_memory`, `blocked_com_vtable`, or
     `blocked_injection_helper`
9. Transport pressure:
   - candidate lifecycle evidence may be dropped according to low-volume control
     channel policy, but dropped counts must be visible

## Smoke Plan

Use `knmon-dynamic-probe.dll` because it already proves dynamic-load IAT
re-sweep and resolver monitoring.

### Phase A: Candidate Ledger Smoke

Purpose: prove honest classification without pointer-call instrumentation.

Sample behavior:

1. Load `knmon-dynamic-probe.dll`.
2. Resolve a known low-payload API through `GetProcAddress`, such as
   `kernel32.dll!GetCurrentProcessId`.
3. Resolve the same or equivalent function through `LdrGetProcedureAddress`.
4. Call the returned function pointer from the probe.

Expected monitor evidence:

1. Resolver `api_call` events are present.
2. `resolver_pointer_candidate` or `resolver_pointer_unsupported` lifecycle
   events are present with reason codes.
3. No `resolver_pointer_call` event is emitted.
4. Coverage report labels the result as resolver observed or candidate, not
   instrumented.
5. Healthy path reports zero target transport drops.
6. Shutdown still reports restored hooks equal installed hooks and failed hooks
   equal zero.

### Phase B: Future Instrumented Prototype Smoke

Purpose: only after a separately approved hook method exists.

Expected monitor evidence:

1. Candidate classification appears before install.
2. Install lifecycle reports `resolver_pointer_instrumented`.
3. A call through the resolved pointer emits `resolver_pointer_call`.
4. Return/error/timing evidence matches the generated definition.
5. Rollback lifecycle proves original state restoration.
6. Negative smokes cover blocked API, ordinal-only metadata miss, forwarded
   export unresolved, module unload race, and existing-patch rejection.

## Explicit Non-Goals

The following are not approved by this design:

1. EAT patching.
2. Broad inline detours.
3. Arbitrary returned-pointer wrapping.
4. Breakpoint mutation.
5. Skip-call behavior.
6. Forced return behavior.
7. Stealth behavior.
8. Manual-map injection.
9. PPL bypass.
10. Remote thread, APC, context, or injection-helper capture expansion.
11. Capturing arbitrary payload buffers or pointer memory.
12. COM vtable/interface instrumentation.
13. Callback or window-message procedure instrumentation.
14. Claiming pointer-call coverage from resolver visibility alone.

## Acceptance Criteria For The Next Implementation Slice

The next implementation goal should stop at candidate-ledger behavior.

Done means:

1. Resolver-returned pointers are classified as candidate or unsupported.
2. The classification preserves module/export/API identity where safe.
3. Unsupported states are explicit and reason-coded.
4. No code patching, export patching, breakpoint mutation, pointer rewriting, or
   trampoline installation is added.
5. `knmon-dynamic-probe.dll` smoke proves resolver visibility plus candidate
   ledger evidence.
6. Capture results and session manifests expose candidate/unsupported ledger
   counters without making them pointer-call coverage.
7. Existing `npm run defs:validate`, native smoke, and `npm run verify` gates
   remain green.
8. README and roadmap continue to state that resolver observation is not
   pointer-call instrumentation.
