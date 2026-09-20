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

Extracted source packages need no Git metadata or LFS network requests. Source
preflight verifies their complete hash manifest. npm/Cargo dependency installation
still requires registry access or populated caches. These steps demonstrate a
reproducible source build; byte-identical PE binaries across machines are not
claimed without a separately validated deterministic-linking environment.

The upstream native JSON and zstd sources and licenses are vendored and verified
by CMake hashes. They require no configure-time network fetch and are absent from
injected agent binaries. UI catalog generation retains all 30,112 catalog rows
and their selection metadata, while excluding decoder parameter tables from the
renderer bundle.

References: [Node 24.21.0](https://nodejs.org/en/blog/release/v24.21.0),
[Node release schedule](https://github.com/nodejs/Release),
[Vite prerequisites](https://vite.dev/guide/),
[Zstandard 1.5.7](https://github.com/facebook/zstd/releases/tag/v1.5.7).
