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
audit results.
