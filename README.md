# KN Win32 API Monitor

KN Win32 API Monitor is a modern Windows 10/11 API monitoring workstation for
security engineering, reverse engineering, debugging, and anti-cheat research.

The project is inspired by Rohitab API Monitor, but the implementation is being
rebuilt around a modern desktop UI, explicit native helper contracts, durable
capture artifacts, and generated API definition metadata.

## What It Does

- Launches supported targets and injects the monitoring agent through the
  controlled early-bird APC path.
- Attaches to already-running same-bitness, non-protected targets through the
  native helper path.
- Captures API calls through native IAT hooks and shared-memory event transport.
- Supports dynamic loader and resolver coverage for loaded modules,
  `GetProcAddress`, and `LdrGetProcedureAddress`.
- Stores durable `.knapm` replay sessions and supports target-free validation,
  replay, catalog indexing, trace indexing, and full-text trace search.
- Provides a Tauri 2 + React/TypeScript desktop UI for target selection,
  launch/attach control, trace browsing, filtering, highlighting, timeline
  views, replay, and catalog/search workflows.
- Uses generated API definition metadata for module/API IDs, groups, argument
  labels, decode aliases, enum/flag rendering, and coverage reporting.

## Current Coverage

The current definition and hook pipeline reports:

- Microsoft-source inventory candidates: `30,182`
- Defined APIs: `30,112`
- Runtime-monitorable APIs: `30,000`
- Definition-only APIs awaiting payload/ABI review: `112`
- Data exports included as monitor targets: `0`
- Parameter metadata rows: `226,754`
- Parameters missing decode metadata: `0`
- API families: `61`
- API categories/groups: `475`
- Generated hook coverage: `required=30000`, `manual=314`,
  `generated=29686`, `covered=30000`

Runtime-monitorable means the API has a generated or manual hook definition
that can be selected by API filter or enabled through the relevant runtime
profile. Payload-sensitive APIs and APIs requiring manual decoder work remain
definition-only until separately reviewed.

## Architecture

```text
apps/knmon-ui/          Tauri + React workstation UI
crates/knmon-tauri/     Rust command layer
native/                 C++20 helper, collector, controller, and agent code
contracts/              Versioned JSON contracts
definitions/            API definitions and metadata registries
generated/              Deterministic generated API/decoder/hook artifacts
docs/                   Architecture and design notes
samples/                Controlled sample targets
tools/                  Validators, generators, importer, and smoke tests
tests/                  Test and validation assets
```

The native path is intentionally explicit:

1. The helper owns process launch, attach, preflight, cancellation, and session
   lifecycle.
2. The injected agent keeps hot-path work compact and writes API events through
   shared memory.
3. The host-side collector drains committed transport records, decodes metadata,
   writes sessions, and reports drop/overhead counters.
4. Replay, catalog indexing, and trace indexing validate/read `.knapm` data
   without launching targets or reinjecting agents.

## Safety Boundary

The supported native monitoring paths are currently same-bitness user-mode
flows:

- x64 helper -> x64 target -> `knmon-agent64.dll`
- Win32 helper -> x86 target -> `knmon-agent32.dll`

Cross-bitness injection, protected-process bypass, manual mapping, stealth
loading, kernel-mode capture, skip-call, forced return values, memory editing,
and broad inline detours are not enabled by default and require separate design
review.

Data exports are excluded from the runtime monitoring target set because they
are not callable APIs.

## Prerequisites

- Windows 10/11
- Node.js 20 or newer
- Rust toolchain with Cargo
- CMake 3.24 or newer
- Visual Studio Build Tools with a C++20-capable MSVC toolchain
- WebView2 runtime for Tauri desktop execution

Optional:

- Win32/x86 MSVC components if you want to build the x86 helper/agent/target
  tree.

## Install

Clone the repository and install JavaScript dependencies:

```powershell
git clone https://github.com/kernullist/KnWin32ApiMonitor.git
cd KnWin32ApiMonitor
npm install
```

Configure and build the native x64 tree:

```powershell
npm run native:configure
npm run native:build
```

Build the desktop UI:

```powershell
npm run build
```

Or use the repository build script:

```powershell
.\Build.ps1
```

For release builds, the script increments the fourth PE resource version
component in `VERSION` before configuring and building native Release outputs:

```powershell
.\Build.ps1 -Release
```

Optional Win32/x86 native build:

```powershell
cmake -S native -B build/native-win32 -A Win32
cmake --build build/native-win32 --config Debug
```

## Run

Run the Tauri desktop app:

```powershell
npm run tauri:dev
```

Run the browser/Vite UI only:

```powershell
npm run dev
```

Browser/Vite mode is useful for UI work, but native launch/attach actions
require the Tauri desktop runtime and built native helper binaries.

Use the root scripts when you want simple local app control:

```powershell
.\Start-App.ps1
.\Stop-App.ps1
```

## Native Helper Examples

List target processes:

```powershell
build\native\Debug\knmon-native-helper.exe list-targets
```

Launch the controlled sample target:

```powershell
build\native\Debug\knmon-native-helper.exe launch-sample
```

Capture the controlled sample target:

```powershell
build\native\Debug\knmon-native-helper.exe capture-sample
```

Attach to an already-running supported same-bitness target:

```powershell
build\native\Debug\knmon-native-helper.exe attach-capture --pid <pid> --duration-ms 3000
```

Write and validate a replayable session:

```powershell
build\native\Debug\knmon-native-helper.exe capture-sample --write-session captures\latest-sample-fileio
build\native\Debug\knmon-native-helper.exe validate-session --session captures\latest-sample-fileio
build\native\Debug\knmon-native-helper.exe replay-session --session captures\latest-sample-fileio
```

## Validation

Validate API definitions, generated decoder tables, inventory, plans, importer
fixtures, and the 30,000 runtime-hookable API gate:

```powershell
npm run defs:validate
```

Regenerate definition artifacts when intentionally changing API metadata:

```powershell
npm run defs:bulk-expansion
npm run defs:generate
npm run defs:inventory
npm run agent-hooks:generate
```

Run the core build checks:

```powershell
npm run build
npm run native:build
```

Run the generic profile smokes used to verify the current broad hook table:

```powershell
npm run tier1-generic:smoke
npm run tier2-generic:smoke
```

Run all available repository verification:

```powershell
npm run verify
```

Additional focused native smokes are available under `tools/native-smoke/`.

## Definition Reports

Print the current definition and inventory report:

```powershell
npm run defs:coverage
```

Check generated agent hook coverage directly:

```powershell
npm run agent-hooks:check
```

Expected current hook check:

```text
Generated agent hook definitions. required=30000 manual=314 generated=29686 covered=30000 chunks=58
```

## Release Package

Create a ZIP package from existing Release build outputs:

```powershell
.\Release.ps1
```

Include an already-built Win32/x86 native tree:

```powershell
.\Release.ps1 -IncludeWin32
```

The ZIP is written under `dist\release\` and includes native PE outputs,
`README.md`, `VERSION`, `BUILD-INFO.json`, the UI `dist` folder when present,
and Tauri `target\release`/`bundle` outputs when they have been built.

## Design Docs

- [Product Design](docs/product-design.md)
- [Architecture](docs/architecture.md)
- [Definition Schema](docs/definition-schema.md)
- [Resolver-Returned Pointer Instrumentation Design](docs/resolver-returned-pointer-instrumentation-design.md)
- [Roadmap](docs/roadmap.md)
