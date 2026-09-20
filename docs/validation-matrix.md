# Executed Windows validation matrix

Observed on 2026-09-20, Windows 10.0.26200, with the compiler/SDK versions in
`toolchain.json`. Rows describe executed checks, not certification of every
Windows 10/11 release or every API input.

| Component | x64 Debug | x86 Debug | x64 Release | x86 Release |
|---|---|---|---|---|
| Native compile/link | passed | passed | passed | passed |
| Native CTest | 23/23 passed | 23/23 passed | 23/23 passed | 17 passed, 6 not started |
| Desktop compile/link | test executable passed | test executable passed | application passed | application passed |
| Desktop security tests | 3/3 passed | 3/3 passed | 3/3 passed | 3/3 passed |
| Desktop attach/filter/stop/export and Job resources | native tools used | native tools used | passed with Debug native tools | passed with Debug native tools |
| Desktop PE hardening | passed | passed | passed | passed |
| Rust backend with real helper | 18/18 passed | 18/18 passed | 18/18 with Debug and Release helpers | 18/18 with Debug helper; Release helper blocked before tests |
| All-supported sample live/replay | 376 events, 16 errors | 376 events, 16 errors | 376 events, 16 errors | blocked before launch |
| Comparative six-API corpus | 50 runs passed | 50 runs passed | not run | not run |
| Sustained overload, original/observed | 5 s and 15 s passed | 5 s and 15 s passed | default 5 s CTest passed | blocked before launch |
| Clean source ZIP native reconstruction | 23/23 passed | 23/23 passed | not run | not run |

The Debug comparison uses ten fresh-process repetitions of each of five modes.
Each run has 450 expected calls, with zero missing, unexpected or reordered
events and matching outputs/errors. Frida CModule is faster and uses less
target RSS than KNMon on this corpus. This evidence does not support a World
No.1 or lowest-overhead claim.

The [desktop polling change](desktop-control-polling.md) passes 14 deterministic
polling, terminal-tail and WOW64 regressions, the full UI validator suite, both
Release desktop builds/security suites, and real attach/filter/stop/export on
both architectures. The final UI runs exported 250/230 events, retained native
record totals through terminal draining and left both targets alive after stop.

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

The [Release backend suite](backend-release-evidence.md) now includes the actual
failed-target path. Missing the target's dynamic probe DLL previously left a
failed capture in `stopping_agent`, causing the backend to wait until its test
deadline. Native launch/attach finalization and backend result validation now
preserve a terminal failure and its error message. Both Release architectures
execute all 18 tests, including the two normally ignored real-helper cases.

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

The earlier clean source archive from `4e5a9df` was extracted without Git metadata and
rebuilt with the pinned Node/CMake/MSVC/SDK configuration. npm installation,
frontend build/validation and both complete native Debug suites passed. The
frozen reconstruction producer retained source, command, compiler and binary
hashes. The archive contains 763 entries and has SHA-256
`76e86e5a680eea586b949c100a11ef1fa3ef2e29b602f4b79f1e54029a6bd29e`.
Both architectures executed all 23 CTests, including the new failed-launch
regression; the extracted-source WOW64 UI regressions also passed. Revalidation
rejects altered command, compiler, binary, test and frontend records. The
integrated report for that revision passed seven evidence scopes and retained ten incomplete
scopes, with current source reconstruction, Release backend execution, desktop
interaction, dependency/advisory checks, typed ABI freshness and competitive
semantics verified together. The subsequent desktop polling and tail-retention
changes require a fresh source reconstruction from their shipped revision before
that gate can pass again; the earlier archive is historical evidence.
See `source-build-contract.md` for reproduction and
`technical-readiness.md` for the fail-closed artifact verification policy.
