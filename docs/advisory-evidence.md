# Source-bound advisory evidence

`python tools/readiness/advisory_audit.py` runs npm and Cargo audits with bounded
output and owned process lifetimes. The command creates
`build/advisory-evidence-ID/evidence.json`; failures retain logs and a failed
status. `--node`, `--npm-cli`, `--cargo-audit` and `--db` select installed tools
and the RustSec checkout. The supported cargo-audit baseline is 0.22.2.

The npm request uses the lockfile, every dependency category and workspace,
the public npm registry and an explicit low-severity exit threshold. The raw
report must nevertheless contain zero findings at every severity, including
informational findings. Registry output has a request time rather than a
database revision. This does not certify the registry's own update latency.
See the [npm audit contract](https://docs.npmjs.com/cli/v11/commands/npm-audit/).

RustSec verification independently checks the official upstream `main` revision,
every worktree file against its committed Git blob, and exact advisory-file
membership. Git status alone is insufficient: assume-unchanged files and ignored
extra advisories are negative controls. The audit uses `--no-fetch` only after
that freshness check, and repeats the revision/content check afterward. It does
not enable stale-database mode or suppress advisory IDs, warning classes,
architectures, operating systems or severity levels. Database query commands and
their outputs are retained and checked against the verified revision.
Advisories use Markdown with TOML front matter. The verifier checks all files in
the advisory collections, rejects directory reparse points and compares the
auditor's loaded advisory and package counts with the verified database and
complete Cargo lockfile.

Cargo-audit 0.22.2 skips local path packages. The Tauri backport therefore has
an additional audit input containing its original registry name, version and
archive checksum, derived from the independently verified vendor provenance.
This one-package `vendor-upstream.Cargo.lock` is retained separately from the
actual build lockfile. The sixth audit step scans it against the same complete
RustSec database. Its bytes, hash, exact command and raw result are verified;
rewriting its package version and recomputing the hash cannot pass.

Inherited warnings retain the upstream version and map to the local
`tauri-utils 2.9.2+knmon.1` graph identity. This keeps them visible to the Windows
maintenance gate. An inherited vulnerability fails the audit. This scope covers
the original published Rust source; the maintained URLPattern dependency is
also present in the ordinary build-lock scan. It does not claim that registry
advisories discover new defects introduced by a local patch.

The result binds both dependency lockfiles/manifests, tool binaries, producer
files, exact audit arguments, successful process exits and raw report hashes.
Parsers consume the bytes whose hashes were checked. Warning rows remain in the
result; zero vulnerability findings does not mean zero maintenance warnings.
The readiness gate joins those warnings to independently verified Windows Cargo
graphs and keeps reachable warnings as a separate unverified maintenance gate.

`python tools/readiness/advisory_audit.py --check build/advisory-evidence-ID`
rechecks retained artifacts and the current official RustSec checkout. The
report must be at most 24 hours old; a newer upstream revision invalidates it
even within that interval. A future timestamp more than five minutes ahead is
rejected. An unavailable upstream check is a failure, not an offline freshness
claim. This is unsigned local evidence of known advisories, with the same trust
limits as `technical-readiness.md`; it does not authenticate the builder or
establish the absence of unknown vulnerabilities.

Use `python tools/readiness/verify_advisory_audit.py build/advisory-evidence-ID`
to test altered/stale reports, filtered findings, hidden advisory inputs and
missing execution evidence. Synthetic fixtures remain separate from actual
audit results. An executed private advisory fixture reproduces the local-source
skip, detects the vulnerable original version through registry identity, and
excludes a patched-version control. Additional controls exercise inherited
warning mapping, incomplete vendor scope, suppression and altered audit inputs.
