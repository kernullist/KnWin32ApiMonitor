# Technical readiness evidence gate

Run the verifier with the retained directories produced by the source,
dependency and comparison commands:

```powershell
python tools/readiness/technical_gate.py `
  --source-build build/source-rebuild-ID --archive build/knmon-source.zip `
  --dependencies build/dependency-evidence-ID --comparison build/comparison-ID `
  --advisory build/advisory-evidence-ID --desktop build/desktop-evidence-ID `
  --backend-release build/backend-release-ID --native-profiles build/native-profile-ID `
  --desktop-profiles build/desktop-corpus-ID
```

The report lives in `build/technical-readiness-ID/report.json`. Exit code 0
requires every required gate to pass. Code 2 means that inspected evidence was
consistent but required scopes remain unverified. Code 1 means evidence failed
validation or the verifier failed. Missing inputs, skipped checks and unknown
gate overrides cannot yield success. The command does not take a supplied
readiness status or accept an incomplete-result override.

`--node` selects the Node interpreter. `--comparison-python` selects the
isolated interpreter with the recorded Frida version; its default is
`build/deps/frida-venv/Scripts/python.exe`. Competitive replay runs in an owned
job with bounded output and a deadline. The ordinary Python installation does
not need Frida. A missing or mismatched comparison environment fails its gate.

The source reconstruction check binds the clean ZIP to its original manifest,
the current reconstruction producers and current input files. It rechecks the
eight ordered commands, owned command requests, exit codes, log bytes/hashes,
both complete CTest reports, compiler metadata, native binaries and frontend
artifacts. Documentation and this reporting tool are outside the reconstruction
input comparison; reporting producers have separate hashes. New or missing
product input files invalidate the earlier rebuild. Ignored source files in the
native, frontend, backend, generation and tool source trees are also rejected;
Git ignore rules cannot hide an extra compiled source or asset from this check.
Only Python bytecode cache entries are exempt in those trees. Build artifact
paths are checked against the source root, including directory junction targets.
Bound inputs, reconstruction source files, verifier files and the checkout
revision are checked again before the report is finalized. The archive revision remains
visible even when only reporting tools or documentation have since changed.

The dependency check reruns the existing offline schema and locked Windows
resolution verifier. The comparison check replays raw oracle/capture artifacts
and requires the full current corpus matrix and source fingerprints. Its cost
row compares median call time, the median of per-run p99 times and median target
RSS with both recorded Frida adapters. These are point estimates from that
corpus, without a statistical-significance or general ranking claim. The typed
ABI row verifies source freshness and proof structure; it is explicitly not a
new runtime execution or a replay of its retained session.

The [advisory consumer](advisory-evidence.md) checks current lockfiles, retained
unfiltered npm/Cargo scans, tool identities, a bounded report age and the current
official RustSec database contents. Windows-reachable warning packages remain a
separate maintenance gate; advisories outside those graphs are still retained.
The pinned local Tauri backport also receives an upstream registry-identity
scan, because cargo-audit skips local path packages. Inherited warnings map to
its local graph version. A passed maintenance row means that the current
Windows graphs contain no reported maintenance warning; it does not certify
the long-term maintenance of every dependency or the absence of unknown bugs.

The [desktop consumer](desktop-evidence.md) verifies both architectures of the
actual attach/filter/stop/export path and recomputes process-tree resource
summaries from raw Job samples. The configuration is a hidden Release desktop
with Debug native tools; this does not clear the native Release or complete
binary-distribution gates. Desktop evidence retains the requested stack limit
and compares the actual stack inspector with exported native addresses. A run
with optional stack capture enabled verifies that mode's observation path; it
does not establish the separate capture-profile cost gate.
The requested metadata, arguments or preview detail also remains bound to the
actual UI controls, parameter inspector and exported events.

The separate [native profile-cost matrix](native-profile-costs.md) measures
original, metadata, arguments, preview and two stack-enabled configurations on
the same independent caller corpus. Its native Debug scope does not clear
`capture_profile_costs`; collector, desktop and comparable UI costs remain
required. `--native-profiles` executes its replay consumer in an owned command
and retains the native measurements under that still-unverified row. An invalid
supplied native evidence pack fails the row. The matrix also has separate
adversarial controls.

The [coordinated desktop matrix](desktop-corpus-costs.md) extends that caller to
the actual Release desktop with Debug native tools. `--desktop-profiles`
recomputes all 120 trials, owned Job resource windows and hidden-window DOM
delivery bounds. It retains `desktopStatus: passed` for consistent complete
evidence, while `capture_profile_costs` remains `not_verified`. Invalid supplied
evidence fails the row. Separate collector, serialization and disk attribution,
visible presentation and Release-native costs remain outside this matrix.

The [Release backend consumer](backend-release-evidence.md) checks Cargo's
optimized test artifacts, both actual PE architectures and all 21 named backend
tests, including the real-helper success and failed-target paths. It retains
matching Debug native binaries and does not clear the native Release gate.

Required scopes without an implemented evidence consumer remain `not_verified`:
the current full native Release matrix, other Windows
builds, elevated/cross-user IPC, hardware CET,
separate capture profiles, complete binary
distribution reconstruction and broader competitive coverage. Kernel ETW session
availability is evaluated separately from private application ETW. User
evaluation is excluded from this policy.

These checks establish consistency of retained local artifacts with the source
and declared execution scope. They cannot authenticate a malicious producer that
rewrites all artifacts consistently. Reports are unsigned and do not claim a
SLSA level. The policy follows the distinction between artifact provenance and
verification decisions described in [SLSA 1.2 provenance](https://slsa.dev/spec/v1.2/provenance)
and the [verification summary model](https://slsa.dev/spec/v1.2/verification_summary).

Run the adversarial checks with `python tools/readiness/verify_technical_gate.py`.
Adding the same `--source-build` and `--archive` arguments also checks mutations
against a completed actual reconstruction. Synthetic controls are labeled as
fixtures and do not count as product runtime evidence.
