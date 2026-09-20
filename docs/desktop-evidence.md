# Desktop interaction and resource evidence

The desktop probe operates the bundled Tauri page through a private WebView2 CDP
connection. It selects an owned sample process, starts streaming attach, observes
native rows, types a `WriteFile` filter, stops the session, exports JSONL through
the UI, waits for the target's normal exit, and closes the application's main
window. It neither inserts telemetry nor changes React state. This is an automated
technical check; no user evaluation is required.

The tested configuration is a Release desktop with same-bitness **Debug** native
tools. This does not resolve the separate x86 native Release quarantine recorded
in [the validation matrix](validation-matrix.md).

Run from the repository root after building both desktop and Debug native targets:

```powershell
node --test tools/ui-validator/target-architecture.test.mjs
python -X utf8 tools/readiness/desktop_evidence.py
python -X utf8 tools/readiness/desktop_evidence.py --check build/desktop-evidence-<id>
python -X utf8 tools/readiness/verify_desktop_evidence.py --evidence build/desktop-evidence-<id>/x64
```

The default Node executable is the pinned Node 24 installation under `build/deps`.
`--architecture x64` or `x86` is useful while diagnosing a failure, but readiness
requires one successful evidence set containing both architectures. Supply it to
`technical_gate.py --desktop <directory>` with the other evidence inputs.

Each run uses fresh portable, temporary and WebView2 profile directories under
`build`. Child-only environment settings enable an ephemeral loopback debugging
port. The probe verifies the listener belongs to its WebView Job before connecting.
It sets no registry values or antivirus exceptions. Processes start suspended and
are assigned to an owned, process-count-bounded Job before resuming. Separate Jobs
contain the desktop tree, target tree and automation driver. Failure and deadline
cleanup terminate only those Jobs. The normal path requires target, driver and
desktop exit code zero and all three Jobs drained.

The main window is hidden for the measurements. Input goes through CDP mouse and
keyboard commands against actual rendered controls. The screenshot proves what
the renderer displayed; it is not a foreground frame-rate or usability score.

The evidence retains:

- Current product source and producer fingerprints, actual staged PE hashes and
  architecture checks, WebView runtime and observed process image hashes.
- Raw samples at a nominal 200 ms interval, including PID plus creation time,
  image path, working set, private bytes, handles and cumulative Job CPU.
- UI observations, the downloaded JSONL and a rendered screenshot. Revalidation
  reconciles event counts, sequences, target identity, native file-buffer bytes,
  filtered rows and the terminal UI state.
- Exact exit/cleanup outcomes. Failed attempts remain in their original folders.

The process list includes nested WebView Jobs. Opening a PID is followed by an
exact Job-membership check; a foreign or reused PID is never sampled. A process
that exits during collection is recorded explicitly. An inaccessible live process
fails the evidence check. Cumulative Job CPU includes short-lived descendants,
whereas a short-lived process can appear and disappear between memory samples.

Memory figures are **sampled maxima of summed working sets and private bytes**,
not exact simultaneous peaks or physical RAM usage. Working-set sums count shared
pages more than once. Phase CPU deltas cover the first through last sample in that
phase. The driver is excluded from desktop/target sums. These short controlled
runs do not establish long-term leak freedom, foreground rendering performance,
or a universal competitive ranking.

All evidence is unsigned local consistency data. Hashes identify tested binaries;
they do not authenticate a builder or prove that the recorded source produced
those binaries. Complete binary distribution reconstruction remains a separate
readiness gate.

The initial x86 execution reproduced a product defect: the native process list
returned `x86-wow64`, while the UI accepted only `x86` and `x64`. The UI now maps
that documented native label to x86 for eligibility checks, retains the original
display label, and continues to reject cross-bitness and unsupported targets.

The implementation follows Microsoft's documented [WebView2 debugging environment
settings](https://learn.microsoft.com/en-us/microsoft-edge/webview2/how-to/debug-visual-studio-code)
and [nested Job process-list semantics](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_process_id_list).
