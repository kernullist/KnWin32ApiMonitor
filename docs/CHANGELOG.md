# Changelog

## 2026-11-21 — v0.1.0.4

### Fixed

- `.gitattributes` now pins `generated/runtime-support.json` to LF so the `agent-hooks:check` byte comparison passes on Windows checkouts with `core.autocrlf=true` (`npm run verify` failed on fresh Windows clones before this).
- Agent: session leases are now held only for the emission window, so a hooked call that blocks (wait/connect) can no longer wedge `KnMonAgentStop` into a permanent `Stopping` state with hooks left installed. Admission still captures the gate epoch; shutdown quiescence now guarantees no in-flight transport writes. The module-lifecycle test's paused-sweep assertion now checks the sweep-thread invariant instead of gate quiescence.
- Agent: `UninstallHooks` snapshots/restores hook records under `g_hookLock` (loader references stay outside the lock, matching the sweep convention).
- Agent: `CopyWideText` keeps a bounded UTF-8 prefix on `ERROR_INSUFFICIENT_BUFFER` instead of wiping the whole conversion, and `CopyGuidStringPointerText` clamps instead of rejecting `StringFromGUID2` buffers larger than 64 chars.
- Agent: Tier 2 return-only hooks with `BOOL` returns now publish the captured `GetLastError` value on failure like every manual wrapper, and the (currently disabled) generated-generic `NTSTATUS` error path maps through `RtlNtStatusToDosError`.
- Agent: Winsock fallback stubs (`WSAStartup`, `WSACleanup`, `socket`, `closesocket`, `connect`, `getaddrinfo`, `WSARevertImpersonation`) set the contract-required Winsock last error instead of leaving a stale one.
- Agent/controller: ANSI text slots (`CreateFileA`/`LoadLibraryA` paths, probed ANSI strings) are transcoded from the target ANSI codepage to UTF-8 before they enter event records; non-ASCII target text no longer poisons the JSON event stream for UTF-8-strict hosts.
- Controller: launch capture now observes the cancellation event during the window-reveal loop and the shutdown drain, so a cancel in those windows is recorded instead of being reported as a clean success.
- Controller: `ReadPipeMessage` resets the manual-reset OVERLAPPED event before each re-issued read so a stale `ERROR_MORE_DATA` completion cannot report the next pending read as done.
- Collector: `ThreadedSharedTransportReader::Start` no longer bricks the reader after a failed thread creation.
- Documentation: stale generated-hook coverage figures (`required=30092`/`generated=29778`/`chunks=59` → `required=332`/`manual=326`/`generated=0`/`chunks=0`), parameter-row count (226,754 → 226,700), Wave 2 API count (77 → 79), runtime-monitorable totals, the always-installed hook list (now enumerates all 130 always-on hooks), and the Tauri command list (removed 3 phantom commands, added 6 registered commands).
- Smoke: `tier2-generic-profile-smoke.ps1` gates optional-module assertions on the helper architecture — the `fxsutility.dll!CanSendToFaxRecipient` assertion runs only when the Fax utility DLL matching the helper/sample bitness exists (System32 for x64, SysWOW64 for x86, with Sysnative redirection for 32-bit PowerShell hosts), and `GetCurrentMonitorTopologyId` is asserted only when the user32 export exists on the machine; the sample resolves both APIs dynamically and they may be absent. The helper path is pinned to an absolute provider path so the PE-header reader works when the PowerShell location differs from the Win32 process CWD.
- Smoke: `generated-generic-preview-smoke.ps1` now skips with a clear message while the `compiler-bound-typed` runtime policy installs zero generated wrappers — its 29-API selection can never pass `RuntimeSupportedApiKeys` validation in that state (verified against clean-HEAD artifacts), and it remains the re-enable gate for a future typed-generator rollout.
- Runtime support: `HasProfileToken` (agent) and `SelectionContainsToken` (controller) now treat tabs and CR/LF as token separators, matching `ValidateRuntimeApiSelection`; previously a tab-separated selection passed validation but matched nothing downstream, producing zero-event captures (a tab-separated selection is now verified end-to-end to capture its APIs).
- Smoke: five daemon/session smokes wrote fixture JSON with `Set-Content -Encoding UTF8`, which Windows PowerShell 5.1 emits with a UTF-8 BOM that the helper JSON validator rejects; they now write BOM-less UTF-8 (`session-recovery-state` and `knapm-recovery-ownership` pass as a result, `daemon-recovery-plan`/`daemon-recovery-apply`/`persistent-daemon-hardening` progress past the BOM step).

### Added

- Twelve modern low-payload APIs promoted from definition-only metadata to live manual hooks (Phase 13R): `QueryPerformanceCounter`, `QueryPerformanceFrequency`, `GetSystemTimeAsFileTime`, `GetSystemTimePreciseAsFileTime`, `GetSystemInfo`, `GetNativeSystemInfo`, `GetCurrentProcessorNumberEx`, `GetNumaHighestNodeNumber`, `GetActiveProcessorCount`, `GetDpiForWindow`, `GetAwarenessFromDpiAwarenessContext` (Tier 1 generic `system-safe`/`ui-safe`), and `GetCurrentMonitorTopologyId` (Tier 2 `tier2-initial-return-only`; hook definition carries import ordinal 2683, the sample resolves it dynamically so it loads on Windows 10 too, and the tier2 smoke asserts the event only when the user32 export exists). Runtime policy now admits 332 APIs (326 manual + 6 typed). The sample exerciser probes and tier1/tier2 profile smokes cover the new hooks with pointer-only/scalar evidence on x64 and x86.

### Known limitations

- Non-streaming captures still retain every matched event unbounded; a chatty target can exceed the host's final-frame byte budget after the capture completes. Bounding non-streaming history is a session-contract change deferred for design review.
- `trace_batch.recordsStreamed` counts transport-consumed records (including selection-filtered records), not delivered events; renaming or recomputing the field is a schema-contract change deferred for design review.
- Over-long UTF-16 strings that fill a record text slot keep a bounded prefix but still report `decoded` status; threading a `truncated` status through every text-slot writer is deferred to avoid a cross-cutting emit-function contract change.
- Pre-existing (verified identical on clean-HEAD binaries via worktree A/B): the launch-sample capture path races the sample's process exit against the controller's stop/self-disable sequence, so `agent_shutdown` may be absent under machine load (`hookCleanupOutcome=released_by_process_exit`). The smokes that assert shutdown receipt (`loader-aware-iat-sweep`, `repeat-capture-sample`, `shared-memory-transport`, `shared-memory-backpressure`, `ntcreatefile-capture`) are therefore timing-sensitive on loaded machines. Restructuring that stop-vs-exit timing is a launch-contract change deferred for design review.
- Pre-existing on non-English-locale machines (verified identical on clean-HEAD binaries): `generated-decoder-tables-smoke` requires English last-error rendering while this machine renders Korean system messages, and `persistent-daemon-hardening-smoke` fails its healthy-daemon-audit assertion after the fixed BOM step; both are locale/environment issues outside the capture pipeline.

## 2026-08-11 — v0.1.0.3

### Fixed

- Unique operation/writer/daemon IDs no longer collide within the same millisecond (helper + Tauri).
- Shared-memory transport creation fails closed when the mapping name already exists.
- Threaded shared-transport reader destructor no longer risks `std::terminate` on join timeout.
- Agent transport open validates header size and capacity bounds.
- Transport producer CAS failure publishes a poison slot instead of permanently stalling the consumer.
- Named cancellation events are reset on open so stale signals cannot cancel a new operation.
- Transport record sequence is loaded/stored with interlocked 64-bit operations for x86 safety.
- Release packaging supports single-config native output layouts (Ninja/NMake).

See `docs/plan/2026-08-11-adversarial-bug-review.md` and `docs/release-notes/v0.1.0.3.md`.
