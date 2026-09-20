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
the anyhow soundness advisory RUSTSEC-2026-0190. The locked desktop build and
both Tauri security tests pass. cargo-audit 0.22.2 reports zero vulnerabilities
against RustSec database commit `d5c17953a895cf19e8d3ce66eaa42b6fcfe1fb16`.

Warnings remain visible. Cargo metadata for both `x86_64-pc-windows-msvc` and
`i686-pc-windows-msvc` selects 259 packages. Five unmaintained UNIC packages
are reachable through `tauri-utils -> urlpattern`: unic-char-property,
unic-char-range, unic-common, unic-ucd-ident and unic-ucd-version. The full
cross-platform lockfile additionally reports proc-macro-error as unmaintained
and glib 0.18.5 as unsound; neither is selected by either Windows graph. This
is target-specific applicability evidence, not an advisory ignore rule or a
claim that those packages are fixed. Linux builds are outside the supported
runtime and this validation.

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
resolve to `d5c17953a895cf19e8d3ce66eaa42b6fcfe1fb16`; the five Windows-reachable
unmaintained UNIC warnings remain unchanged.

The [source-bound advisory producer](advisory-evidence.md) now records actual
unfiltered npm/Cargo runs, checks every RustSec worktree blob and collection
entry against the current official revision, and reconciles the 1,251 loaded
advisories and 451 lockfile packages on this baseline. Its readiness consumer
preserves all seven warning rows and identifies the five Windows-reachable
UNIC warnings as an unresolved maintenance gate. A clean vulnerability count
does not clear that separate gate.
