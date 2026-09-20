# Executed Windows validation matrix

Observed on 2026-09-20 and 2026-09-21, Windows 10.0.26200, with the compiler/SDK versions in
`toolchain.json`. Rows describe executed checks, not certification of every
Windows 10/11 release or every API input.

| Component | x64 Debug | x86 Debug | x64 Release | x86 Release |
|---|---|---|---|---|
| Native compile/link | passed | passed | prior build passed | prior build passed |
| Native CTest | 23/23 passed | 23/23 passed | prior 23/23 passed | prior 17 passed, 6 not started |
| Desktop compile/link | prior test executable passed | prior test executable passed | application passed | application passed |
| Desktop security tests | prior 3/3 passed | prior 3/3 passed | 6/6 passed | 6/6 passed |
| Desktop attach/filter/stop/export and Job resources | native tools used | native tools used | passed with Debug native tools | passed with Debug native tools |
| Desktop PE hardening | passed | passed | passed | passed |
| Rust backend with real helper | prior 18/18 passed | prior 18/18 passed | 19/19 with Debug helper | 19/19 with Debug helper; Release helper remains blocked |
| All-supported sample live/replay | 376 events, 16 errors | 376 events, 16 errors | prior 376 events, 16 errors | blocked before launch |
| Comparative six-API corpus | 50 runs passed | 50 runs passed | not run | not run |
| Sustained overload, original/observed | 5 s and 15 s passed | 5 s and 15 s passed | default 5 s CTest passed | blocked before launch |
| Clean source ZIP native reconstruction | prior 23/23 passed; refresh required | prior 23/23 passed; refresh required | not run | not run |

The Debug comparison uses ten fresh-process repetitions of each of five modes.
Each run has 450 expected calls, with zero missing, unexpected or reordered
events and matching outputs/errors. Frida CModule is faster and uses less
target RSS than KNMon on this corpus. This evidence does not support a World
No.1 or lowest-overhead claim.

The [desktop polling change](desktop-control-polling.md) passes 14 deterministic
polling, terminal-tail and WOW64 regressions, the full UI validator suite, both
Release desktop builds/security suites, and real attach/filter/stop/export on
both architectures. Those UI runs exported 250/230 events, retained native
record totals through terminal draining and left both targets alive after stop.

The latest [observation correction](stack-observation.md) separates hook metadata
from stack frames and UI ingestion gaps from actual trimming. Both native Debug
suites pass 23/23, with 2,329 native/Node JSON cases and 130 session cases per
architecture. Each actual sample preserves all 376 events, including one
resolved API-set host, through capture, UI conversion and saved replay. The
six-API typed proof is freshly executed on both architectures. Frontend checks
include two stack regressions and the 200,000-row worker/count regression.

Adversarial review reproduced and fixed Rust accepting object-encoded provenance
enums and the UI falsely labeling native/UI snapshot lag as trimming. Real
desktop testing also corrected tab-selection assumptions and stop-audit capture
in the driver. The final consumer rejects 59 adversarial cases and passes three
positive groups; the backend consumer rejects 45. Earlier failed attempts remain
failed. Native Release results in the table predate this correction and do not
validate its native code.

After the failure-state correction in `4e5a9df`, both native Release builds
completed again. x64 executed all 23 CTests. x86 passed 17; six cases could not
start. Defender recorded these x86 Release detections on 2026-09-20:

| Artifact | Detection time (Asia/Seoul) | Result |
|---|---|---|
| `knmon-runtime-support-test.exe` | 21:22:13 | runtime-support test not started |
| `knmon-sustained-capture-test.exe` | 21:22:23 | sustained-capture test not started |
| `knmon-capture-semantics-test.exe` | 21:22:23 | four capture tests not started |
| `knmon-native-helper.exe` | 21:26:19 | file hashing failed before the Release backend test process launched |

The recorded threat ID is 2147959533 and Defender reports successful actions;
the four files are absent afterward. The initial detections at 16:27-16:28 are
retained separately. No exclusion, policy change or renaming workaround was applied.
The x86 Release runtime gate remains incomplete. A successful desktop build
does not clear the separate native-helper gate.

The current CTest XML consumer accepts the x64 report and rejects the actual
x86 report as failed or unexecuted. The x64 Release backend additionally ran
all 18 tests against the Release helper, with matching native binary hashes
before and after execution. These direct probes retain commands and raw logs;
they are not a complete source-bound, two-architecture Release evidence pack.
The integrated native Release gate therefore remains `not_verified`.

Desktop Release builds were executed through `Build.ps1 -Release -SkipNative`
and `Build.ps1 -Release -Win32 -SkipNative`; native Release builds were executed
separately with CMake. The desktop release security tests used `cargo test
--release --locked --features tauri/custom-protocol` with each explicit target.
This validates the bundled-protocol build configuration, CFG policy and command
authority/navigation checks; it is not an end-to-end WebView interaction test.
After the URLPattern backport, both Release suites execute six tests, adding
Unicode identifier, URL component and remote-fixture authority regressions.
The Debug desktop entries describe the earlier three-test dependency baseline;
they are not a validation of the new backport.
The latest desktop runs export 240/250 native events, retain exact
terminal totals with no recorded loss, leave the targets alive after stop,
and close normally with all owned Jobs drained. Both retain 199 process-tree
samples; the largest observed gaps are 313 ms (x64) and 297 ms (x86). Actual
Call Stack observations match the exported uncaptured state and agent identity.

The [Release backend suite](backend-release-evidence.md) now includes the actual
failed-target path. Missing the target's dynamic probe DLL previously left a
failed capture in `stopping_agent`, causing the backend to wait until its test
deadline. Native launch/attach finalization and backend result validation now
preserve a terminal failure and its error message. Both Release architectures
execute all 19 tests, including the two normally ignored real-helper cases and
the new stack-observation roundtrip/rejection test. None are ignored or filtered.

The sustained fixture measures native controller and target CPU/memory/handles,
and reconciles every attempted call against delivered records and explicit
transport drops. See `sustained-capture.md` for its bounds and reproduction
commands. This does not measure the complete desktop WebView process tree.

Other Windows builds, cross-user/elevated IPC, hardware CET enforcement,
complete desktop Release binary
distribution reconstruction still need their own evidence. Kernel ETW session creation on this
medium-integrity host returns access denied (5). User evaluation is excluded
from the technical acceptance criteria.

The [desktop probe](desktop-evidence.md) separately exercises the bundled UI with
matching Debug helpers. Both architectures receive actual native events, filter
and export them, detach while the target survives, and exit normally. Raw Job
samples include WebView children and separate target resources. The hidden-window
scope and sampled working-set sums are not a foreground performance score.

The previous clean source archive from `7e290fc` was extracted without Git metadata and
rebuilt with the pinned Node/CMake/MSVC/SDK configuration. npm installation,
frontend build/validation and both complete native Debug suites passed. The
frozen reconstruction producer retained source, command, compiler and binary
hashes. The archive contains 805 source files plus its manifest (806 ZIP entries)
and has SHA-256
`39e9a770fbadf8dba4bdfb923b93cac261efd7da467ecbf553abeda766d90c9a`.
Both architectures executed all 23 CTests, including the new failed-launch
regression; the extracted-source UI suite includes all 14 polling, terminal-tail
and WOW64 regressions. All cases actually ran; none were skipped or disabled.
Revalidation rejects 31 malformed or altered readiness/source-evidence cases,
including command, compiler, binary, test and frontend records.

An earlier attempt passed both test suites but failed final source closure:
an independently executed dependency inventory had generated a Python cache
file in the extracted source. The inventory now disables bytecode writes before
local imports. Its BOM also uses locked package names instead of checkout and
workspace directory labels. The failed attempt remains recorded as failed.

The corrected archive passed in a fresh directory. Running the extracted
inventory afterward produced a byte-identical 339-component BOM, including
metadata, with SHA-256
`137ed5dccff850b027640f13a157af5957769705b15608a5c681628587348179`.
The direct CLI created no source cache; complete source closure and every
retained reconstruction artifact revalidated afterward.

The dependency graph and advisory evidence now remove the five reachable UNIC
warnings while
retaining two warnings outside the Windows graphs. Native Release, broader
platform and performance claims remain subject to the separate limits above.
The current integrated report has seven passed scopes, zero failed scopes and
ten unverified scopes. The source archive above predates the observation
correction and must be refreshed. Dependency maintenance, Release backend and
actual desktop paths pass together with the current advisory, inventory,
typed-ABI and competitive-semantics evidence. All failed
attempts and their raw logs remain distinct from the successful evidence sets.
See `source-build-contract.md` for reproduction and
`technical-readiness.md` for the fail-closed artifact verification policy.
