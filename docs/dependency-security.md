# Dependency security evidence

The 2026-09-20 audit updated only compatible transitive dependencies. The npm
lockfile now resolves fast-uri 3.1.8, nanoid 3.3.19 and PostCSS 8.5.28. npm also
removed unused optional esbuild entries. A clean Node 24.21.0 `npm ci` and the
complete `npm run verify` passed. `npm audit --include=dev` changed from three
high and one low finding to zero reported vulnerabilities.

The desktop Cargo lockfile now resolves plist 1.10.1, quick-xml 0.42.0 and
anyhow 1.0.104, with plist's base64 0.23.1 dependency. This addresses the two
quick-xml denial-of-service advisories
[RUSTSEC-2026-0194](https://rustsec.org/advisories/RUSTSEC-2026-0194.html) and
[RUSTSEC-2026-0195](https://rustsec.org/advisories/RUSTSEC-2026-0195.html), plus
the anyhow soundness advisory RUSTSEC-2026-0190. cargo-audit 0.22.2 reports zero
vulnerabilities
against RustSec database commit `d5c17953a895cf19e8d3ce66eaa42b6fcfe1fb16`.

The desktop now uses the [provenance-bound Tauri backport](../crates/third-party/README.md)
`tauri-utils 2.9.2+knmon.1`. Its Rust source is unchanged from the validated
stable 2.9.2 crate; only the package build metadata and URLPattern dependency
change. The dependency update follows
[Tauri's merged URLPattern 0.6 change](https://github.com/tauri-apps/tauri/commit/dd725f4b13c30a86b398ccc59eb498f151f461c5).
URLPattern 0.6 uses ICU properties and removes five unmaintained UNIC crates
from both Windows graphs. The locked update preserves every unrelated package
record and dependency edge. It does not adopt unrelated stable or alpha Tauri
source changes.

Both `x86_64-pc-windows-msvc` and `i686-pc-windows-msvc` select 254 packages.
The full cross-platform lockfile still reports proc-macro-error as unmaintained
and glib 0.18.5 as unsound; neither is selected by either Windows graph. These
warnings remain in the report without suppression. This is target-specific
applicability evidence, not a claim that those packages are fixed. Linux builds
are outside the supported runtime and this validation.

Before the update, an executed probe through Tauri's `RemoteUrlPattern` API
rejected Kawi U+11F02 as a parameter's initial character, although it is a
Unicode ID_Start character. The regression suite covers that case, ID_Continue
boundaries, malformed patterns, protocol/host/port/path matching, and actual
Tauri command-authority resolution. Remote grants appear only in test fixtures;
shipping capabilities remain local-only. See the
[executed architecture matrix](validation-matrix.md) for validation scope.

`node tools/security/dependency-regression.mjs` executes bounded regressions
for malformed IPv6 normalization, zero/negative nanoid generator sizes and
PostCSS map annotations without a source path or outside the stylesheet
directory. Positive controls preserve valid hosts, nonempty IDs and permitted
maps. The child process has a five-second deadline so a reintroduced infinite
loop becomes a failed test.

Re-run audits when preparing a release; a dated clean report cannot rule out
later advisories or unknown defects. The source lockfiles and registry checksums
are the dependency identities. These audit results do not certify native PE
hardening, the Windows OS matrix or the complete release package.

The combined [dependency inventory](dependency-inventory.md) now preserves npm
archive integrity, both locked Windows Cargo graphs, dependency edges and native
file checksums in CycloneDX 1.7. Its verifier rejects stale and consistently
rewritten graph evidence. A fresh 2026-09-20 audit still reports zero npm/Cargo
vulnerabilities. RustSec upstream `main` and the audited local database both
resolve to `d5c17953a895cf19e8d3ce66eaa42b6fcfe1fb16`.

The [source-bound advisory producer](advisory-evidence.md) now records actual
unfiltered npm/Cargo runs, checks every RustSec worktree blob and collection
entry against the current official revision, and reconciles the 1,251 loaded
advisories and 446 lockfile packages on this baseline. Cargo-audit skips local
path packages, so the producer additionally audits the verified original
registry identity of tauri-utils and maps inherited warnings to its local
version. The separate one-package scan is also clean. Both retained warning
rows are outside the Windows graphs; the previously reachable five UNIC
warnings are absent because their packages were removed. This narrowly clears
the Windows maintenance-warning scope, without certifying unknown defects or
the future maintenance of every dependency.
