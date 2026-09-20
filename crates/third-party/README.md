# Tauri URLPattern backport

The desktop uses `tauri-utils 2.9.2+knmon.1`, a local backport based on the
previously validated stable 2.9.2 crate. Its Rust/JavaScript source and both
licenses are byte-identical to that published crate. Only `Cargo.toml` and
`Cargo.toml.orig` change: `urlpattern` moves from 0.3 to 0.6, and the local
package version gains `+knmon.1` to distinguish it from the registry release.

The dependency change was merged upstream in
[Tauri commit dd725f4](https://github.com/tauri-apps/tauri/commit/dd725f4b13c30a86b398ccc59eb498f151f461c5).
The published stable 2.9.3 still requires URLPattern 0.3. We retain the existing
2.9.2 source to isolate this change from unrelated permission-value conversion
changes in 2.9.3. The maintained URLPattern 0.6 parser uses ICU properties;
the five UNIC crates leave the resolved graph without advisory suppression.

`tauri-utils-2.9.2.crate` is the original registry archive, SHA-256
`092379df9a707631978e6c56b1bc2401d387f01e2d4a3c123360d167bbb9aa95`.
`tauri-utils.provenance.json` records each original and retained file hash,
the upstream revision and the backport commit. The original crate's unused
`Cargo.lock` remains unchanged for provenance; the desktop lockfile controls
the actual build. The CycloneDX inventory identifies the local version and
its upstream ancestor separately.

Cargo-audit 0.22.2 skips local path packages. The advisory producer therefore
also scans a one-package registry identity derived from the verified upstream
archive. This audit input is separate from the build lockfile. Inherited
warnings are mapped to `tauri-utils 2.9.2+knmon.1` so the Windows graph retains
them. An executed synthetic advisory demonstrates the original local-package
blind spot, detection through the registry identity, and the unaffected-version
boundary. The real audit uses the current official RustSec database.

From the repository root, verify the retained payload with:

```powershell
python -X utf8 tools/security/tauri_backport.py --check
npm run source:check
```

Reconstruct it offline into a new build directory with:

```powershell
python -X utf8 tools/security/tauri_backport.py
```

Reconstruction requires the exact pinned archive and applies the two manifest
edits deterministically. Source preflight rejects changed or unlisted vendor
inputs and reparse points. Dependency inventory additionally rejects replacement
of the local backport with a registry crate or another local package path.
The repository's Rust 1.96 toolchain remains the tested baseline; the original
crate's MSRV does not establish the complete dependency graph's MSRV.

Remove this patch only when a supported stable Tauri release resolves a
maintained URLPattern implementation and passes both architecture security,
desktop interaction and dependency/advisory checks. Reassess upstream
advisories for the local version as well as the registry graph. These unsigned
local consistency checks are not publisher authentication or SLSA certification.
