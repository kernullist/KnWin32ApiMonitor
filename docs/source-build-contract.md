# Source build contract

The reproduction baseline is recorded in `toolchain.json`: Node 24.21.0 LTS,
Rust 1.96.0, CMake 4.3.3, Visual Studio 2022 / MSVC 14.44.35207, Windows SDK
10.0.26100.0, x64 and Win32. Other supported Node lines are 22.18+ and 26.x.
Node 20 is excluded. Compiler/SDK baseline selection is explicit in `Build.ps1`.

1. Clone the exact repository and revision. Run `npm run source:check` before
   parsing generated artifacts. In the verified `kernullist/KnWin32ApiMonitor`
   checkout, `npm run source:hydrate` downloads the three required LFS objects and
   verifies their SHA-256 against the checked-out Git index. It does not invent a
   remote for an arbitrary source ZIP.
2. Run `npm ci`, then `npm run build` and `npm run ui:validate`. The UI build checks
   source inputs and compact catalog freshness, checks both TypeScript projects
   without emitting configuration files, and uses the locally installed Vite.
3. Run `./Build.ps1 -SkipUi` and `./Build.ps1 -SkipUi -Win32` in a fresh source
   directory. These select the baseline compiler and SDK. Existing build caches
   with a different generator/toolset must use a separate build directory.
4. Run `ctest --test-dir build/native -C Debug --output-on-failure` and the same
   command for `build/native-win32`. Tauri builds use the tracked application
   `Cargo.lock`; `cargo test --locked --manifest-path apps/knmon-ui/src-tauri/Cargo.toml`
   validates that resolved desktop dependency graph.
5. Release builds preserve `VERSION`. `-BumpBuildVersion` is an explicit opt-in.
   `./Build.ps1 -Release` builds the x64 desktop and native tools;
   `./Build.ps1 -Release -Win32` selects `i686-pc-windows-msvc` for the desktop
   as well as Win32 for native tools. Install that Rust target with
   `rustup target add i686-pc-windows-msvc` before the first x86 desktop build.
   Tauri receives `--locked`, so a release build cannot silently update the
   application dependency graph. Run from this repository or a descendant so
   Cargo loads the repository's Windows hardening configuration.

`python tools/source/package-source.py --output dist/release/knmon-source.zip`
packages tracked files from a clean checkout, including hydrated LFS bytes.
The ZIP contains `SOURCE-MANIFEST.json` with revision, length and SHA-256 for every
file; fixed ZIP timestamps and ordering make identical inputs produce identical
archive bytes. `AGENTS.md`, local planning files, untracked files and build outputs
are excluded. `--allow-dirty` is for pre-commit verification only and marks the
archive as a dirty snapshot. It is not release provenance.

Clean packaging also compares every payload with its Git index object through
Git's configured clean filters. An `assume-unchanged` flag cannot hide modified
source content. Index, revision, tracked status and collected file hashes are
checked again before writing the archive. Dirty snapshots retain their explicit
candidate status. Individual source files are limited to 128 MiB and aggregate
source payloads to 1 GiB.

Extracted source packages need no Git metadata or LFS network requests. Source
preflight verifies their complete hash manifest. npm/Cargo dependency installation
still requires registry access or populated caches. These steps demonstrate a
reproducible source build; byte-identical PE binaries across machines are not
claimed without a separately validated deterministic-linking environment.

With Python 3.12+ and the baseline Node selected, the automated reconstruction command is:

```powershell
python tools/source/rebuild_source.py build/knmon-source.zip
```

Use `--node` and `--npm-cli` to select side-by-side installations. The producer
extracts into a fresh directory, validates exact manifest membership and every
payload hash, and proves that Git cannot resolve a worktree from that directory.
It runs npm installation, the frontend build/validators, and both native Debug
builds through `Build.ps1`, followed by all 26 CTests per architecture. Failed,
skipped or unexecuted test cases cannot pass the evidence check. Final source
hashes must still match the archive. Unexpected source files and directory
reparse points outside the declared build output locations are rejected. ZIP
central-directory limits are checked before parsing its entries; the accepted
format is a single-disk ZIP32 archive without an archive comment, as emitted by
the package producer. Compressed size is limited to 512 MiB and the central
directory to 4 MiB.

Commands run in owned Windows jobs. A startup gate establishes job ownership
before a command can spawn descendants; output has a byte limit and each command
has a deadline. Failure, timeout or producer exit terminates only that owned
process tree. Logs, JUnit reports, compiler information, binary hashes and command
outcomes remain in `build/source-rebuild-<id>/evidence.json`. A failed run retains
`status: failed`. This producer covers the frontend and native Debug source
rebuild; it does not claim a Rust desktop Release rebuild, another OS, or
byte-identical PE outputs.

The 2026-09-21 reconstruction of `de63483` passed all eight commands in
`build/source-rebuild-n0vgqmck`, including the frontend validators and 26/26
native tests on each architecture. Its clean archive is
`build/g12z-corrected-source.zip`, SHA-256
`7111cc0f88be06a61044f8f8a0550b7d8d33840388fb93b80d277c11cb395c9c`.
The extracted archive validator also passed its positive controls and 39
rejections. Its positive CTest fixture compares the required names, replacing
an obsolete fixed count; omitted tests, duplicate names and the wrong
architecture are rejected even when the declared count looks consistent.

`python tools/source/verify_source_archive.py` exercises malformed archives,
Windows path boundaries, skipped test rejection and owned process cleanup.
`python tools/source/verify_source_package.py` verifies deterministic clean
packages, hidden index changes and explicit dirty candidates in isolated repos.

The upstream native JSON and zstd sources and licenses are vendored and verified
by CMake hashes. They require no configure-time network fetch and are absent from
injected agent binaries. UI catalog generation retains all 30,112 catalog rows
and their selection metadata, while excluding decoder parameter tables from the
renderer bundle.

References: [Node 24.21.0](https://nodejs.org/en/blog/release/v24.21.0),
[Node release schedule](https://github.com/nodejs/Release),
[Vite prerequisites](https://vite.dev/guide/),
[Zstandard 1.5.7](https://github.com/facebook/zstd/releases/tag/v1.5.7).
