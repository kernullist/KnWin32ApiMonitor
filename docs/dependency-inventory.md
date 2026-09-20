# Dependency inventory and provenance

Run from the source root with the pinned toolchain and populated Cargo cache:

```powershell
python tools/security/dependency_inventory.py
python tools/security/dependency_inventory.py --check build/dependency-evidence-<id>
python tools/security/verify_dependency_inventory.py build/dependency-evidence-<id>
```

`--node` selects a Node executable; `--npm-cli` selects its installed
`npm-cli.js` when npm is not beside that executable. The producer invokes npm
through Node without shell interpolation. Cargo resolution uses `--locked
--offline --filter-platform` for both Windows MSVC triples and enables
`tauri/custom-protocol`, matching the desktop Release feature. Missing cached
dependencies fail rather than changing the lockfile. Tool versions and flags
are recorded in `tools.json`.

The output includes a CycloneDX 1.7 `bom.cdx.json`, architecture-specific
`cargo-targets.json`, raw npm/Cargo output and a hash manifest. Repeating the
producer with identical source inputs and dependency resolution produces the
same BOM bytes. Raw npm timestamps and local Cargo paths are retained only in
their separate evidence files, not copied into the BOM.

The inventory currently contains 344 top-level components: 80 npm packages
including the workspace roots, 261 distinct Rust packages across the two
Windows target graphs, two vendored native libraries and one Windows platform
requirement. Each Cargo target selects 259 packages; target-specific packages
explain the larger union. The native libraries include 69 independently hashed
source/license files. These counts are observations, not fixed acceptance
thresholds.

The verifier checks more than file hashes:

- npm identities, versions, archive integrity, distribution URLs and dependency
  edges must agree with the lockfile, including workspace and peer edges.
- Cargo packages must have matching locked registry checksums or repo-local
  manifests. Features, dependency kinds and target-specific edges are retained.
  Verification repeats current locked Cargo resolution so a consistently
  rewritten graph cannot silently omit a dependency.
- Every retained vendored file must appear in the checksum manifest. CMake
  enforces the same zstd file-set boundary before compilation; newly added
  files cannot bypass validation merely because the manifest omits them.
- Artifact sets, source fingerprints and graph identities must be complete.
  JSON duplicate keys, non-finite values, oversized inputs, dangling edges,
  duplicate nodes and path escapes fail. Consumed artifact bytes are hashed
  and parsed from the same bounded buffer.
- The pinned official CycloneDX schema validates structure offline. Its
  `format` annotations are not asserted by Ajv; source/graph validation handles
  the identities, checksums and distribution URLs used by this producer.

The adversarial command includes 18 negative controls, including a Cargo edge
removed from raw metadata and all derived files with recomputed hashes, plus
an actual CMake configure attempt with an unlisted zstd source file.

This is a **pre-build source dependency inventory**. npm includes development
and optional packages for other platforms. Rust includes build dependencies.
It does not identify every object linked into a PE image, every dynamically
loaded library, toolchain internals, or the deployed WebView/Windows DLL
versions. The BOM explicitly marks its overall composition incomplete and
records OS-supplied APIs, including winsqlite3, as environment-dependent.
Declared package licenses and registry checksums are not a third-party
authenticity attestation. Vulnerability audit results remain separate in
`dependency-security.md` and must be refreshed for release.

Primary references: [CycloneDX 1.7 specification](https://github.com/CycloneDX/specification/tree/4b3f59453366e27c8073fd24e98bf21ef8892c8e),
[npm sbom](https://docs.npmjs.com/cli/commands/npm-sbom/) and
[Cargo metadata](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html).
