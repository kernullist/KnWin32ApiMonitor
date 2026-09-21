# Local hardware shadow-stack evidence

`tools/readiness/cet_evidence.py` builds an independent x64 MSVC/MASM probe and
executes it in owned Windows Jobs. The probe creates separate children with
shadow stacks explicitly off or strict. A valid return must succeed in both
policies. A leaf that pushes its own local return destination and executes
`ret` must reach that destination with protection off. Under strict protection,
the debugger must observe a second-chance `0xC0000409` exception with invalid
return address reason `57`, followed by the same process exit code. The fixture
does not call `__fastfail` to manufacture that result.

The parent queries each actual child's `ProcessUserShadowStackPolicy`; the
child independently records its policy, PID and primary thread. Policy enable
and strict bits must be set, with audit disabled. Creation identity, exception
thread, positive-control return value and clean Job rundown are checked as well.
Microsoft documents the [process policy fields](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_user_shadow_stack_policy)
and [creation attributes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).
The separate [CET-compatible linker marker](https://learn.microsoft.com/en-us/cpp/build/reference/cetcompat?view=msvc-170)
is checked in the probe's PE hardening step; it cannot replace the executed
fault controls. References were reviewed on 2026-09-21.

Two additional real children exercise the probe's failure paths. One waits
past its two-second deadline; another floods output past 64 KiB. Both must be
terminated using owned handles, preserve the initial child policy observation,
and leave no active process in their Job. Normal child exit waits for bounded
Job accounting rundown before considering forced cleanup. This avoids labeling
delayed exit accounting as an actual termination request.

After enforcement passes, the producer launches the existing independent
six-API caller with explicit off/strict process creation attributes. These
targets run without a debugger. It executes original, metadata, arguments,
preview, metadata with 32 stack frames, and preview with 32 stack frames in
both policies. One additional strict preview/stack run uses explicit cancel.
Each fresh target runs 64 iterations and two deliberate failures: 450 calls.

The caller's ready/start/done/release events hold work until the real helper
publishes hook readiness and keep the target alive until detach finishes.
The consumer compares the independent oracle with every captured event:
identity, order, call IDs, return width/result, last error, input arguments,
output count, preview bytes, stack provenance and QPC containment. It checks
HELLO, ready and shutdown against the same operation, PID and channel nonce,
requires complete hook restoration and zero recorded loss, and queries the
target's policy before attach, after readiness, after capture and after detach.
The target then exits normally after release. The explicit cancel case retains
the API's `success=false`, `ERROR_CANCELLED` outcome and independently proves
successful cleanup; that result is not rewritten as a successful bounded call.

Run on a Windows x64 host with the configured MSVC toolchain and current native
Debug binaries:

```powershell
python -B -X utf8 tools/readiness/cet_evidence.py
python -B -X utf8 tools/readiness/cet_evidence.py --verify build/cet-evidence-ID
python -B -X utf8 tools/readiness/verify_cet_evidence.py build/cet-evidence-ID
python -B -X utf8 tools/readiness/technical_gate.py --cet build/cet-evidence-ID
```

The build occurs separately from the production native CMake project. The pack
retains compiler configuration, exact commands, bounded logs, staged binary
hashes, producer hashes, current native source fingerprint and raw observations.
Verification rejects stale sources/binaries, incomplete matrices, mismatched
commands, changed artifacts and inconsistent summaries. Build tool records are
cross-checked with the retained CMake compiler and generator configuration.
Reparse points are rejected in the evidence inventory.

A host that cannot establish the requested strict policy remains `not_verified`;
it cannot pass from PE metadata or CPU model alone. Unexpected probe failures,
capture failures and inconsistent supplied evidence fail validation. Failed
executions remain in their original fresh directories.

The result covers the recorded local Windows build, x64 process policy and
native Debug six-API corpus. It establishes no x86, other-host, other-Windows,
native Release, complete API coverage or performance result. It also does not
establish CET protection for every module in the desktop process tree. These
are unsigned local consistency checks, not authentication of a producer that
can rewrite all artifacts coherently. User evaluation is not part of this gate.
