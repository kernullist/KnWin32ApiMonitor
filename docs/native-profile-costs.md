# Native capture-profile cost evidence

Run the independent caller matrix and its adversarial checks on Windows:

```powershell
python -B -X utf8 tools/readiness/native_profile_costs.py
python -B -X utf8 tools/readiness/native_profile_costs.py --check build/native-profile-ID
python -B -X utf8 tools/readiness/verify_native_profile_costs.py build/native-profile-ID
```

The producer uses the pinned local Node executable from `toolchain.json`, the
current Python executable and the existing x64/x86 Debug native builds. It
copies the helper, production Agent and independent comparison target into a
fresh evidence directory. Each command runs in an owned Windows Job with a
deadline and bounded output. Failed attempts retain their partial artifacts and
a failed evidence record.

The matrix executes ten fresh-process repetitions of six configurations on each
architecture: original, metadata, arguments, preview, metadata with 32 stack
frames, and preview with 32 stack frames. The order rotates between repetitions.
Every run executes the same six-API corpus: 64 iterations and two final failure
calls, for 450 calls. Processes do not share a target instance between modes.

The target measures each call independently of the monitor. Validation requires
the same caller success/error behavior, transferred byte counts and output bytes
across all modes. Observed modes must deliver exactly 450 ordered events, report
zero loss or abandoned records, and drain their committed tail. Return widths,
raw errors, call clocks, requested detail and stack provenance are checked
against the architecture and original caller oracle. Saved Agent, audit and
trace streams must agree with the capture and replay, including their counts.
The six signatures, fixed corpus input values and file/allocation handle chains
are validated whenever arguments are enabled. Sequential call IDs and queue
high-water values must agree with the delivered population.

Each run retains its raw oracle, commands, output logs and session. Source,
producer, tool, native binary and artifact hashes are checked again at the end.
The consumer recomputes per-run and per-API nearest-rank median, p95 and p99
caller intervals. Aggregate latency values are the median of each run's
quantiles; they are not quantiles of one pooled population. Aggregate workload,
CPU and memory values are also medians over ten runs. Individual runs remain
available to inspect variability.

The timing boundaries matter:

| Measurement | Boundary |
|---|---|
| Caller interval | Independent QPC readings immediately before and after each API call; includes synchronous observation work |
| Workload interval | Target's entire measured corpus, including untimed loop and file-position work |
| Target CPU | Difference in target kernel/user process times around the workload |
| Target working set | Resident pages reported after the workload |
| Target peak working set | Process lifetime high-water value, including initialization |
| Whole-command time | Owned launcher, helper startup, injection, capture, persistence and output draining; replay is a separate command |

Short CPU intervals can round to zero at the process-accounting resolution.
Working set is neither total committed memory nor a measurement of helper or
desktop memory. Warm OS caches, scheduling, Debug compilation and the small
single-thread corpus affect these results. No confidence interval, statistical
significance or general performance ranking is inferred from ten point samples.

Measurement contracts were checked on 2026-09-21 against Microsoft's
[QPC guidance](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps),
[GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes),
[PROCESS_MEMORY_COUNTERS_EX](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex)
and [Job objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).
QPC values compare intervals on the same host. Reported precision does not remove
clock tick uncertainty or the measurement cost itself.

This is the native portion of the capture-profile-cost objective. Collector and
desktop CPU/memory, serialization and disk costs, sustained queue behavior and
actual UI latency still need comparable workloads and explicit loss accounting.
The full `capture_profile_costs` readiness gate remains unverified. Unsigned
local evidence checks consistency; it cannot authenticate a producer that
rewrites all sources and artifacts consistently.

On 2026-09-21, the final Windows 10.0.26200 matrix completed all 120 runs. All
54,000 calls preserved the expected result, error and byte behavior, and all 45,000
monitored events survived capture, saved streams and replay without loss or
reordering. The point estimates were:

| Architecture | Mode | Median call us | Median run p99 us | Median target RSS MiB | Median whole command ms |
|---|---|---:|---:|---:|---:|
| x64 | original | 6.10 | 275.00 | 5.629 | 125.0 |
| x64 | metadata | 8.65 | 307.80 | 17.461 | 1969.0 |
| x64 | arguments | 9.35 | 314.40 | 17.469 | 3429.5 |
| x64 | preview | 10.00 | 308.55 | 17.467 | 3391.0 |
| x64 | metadata + 32 frames | 10.30 | 329.40 | 17.588 | 2289.5 |
| x64 | preview + 32 frames | 11.55 | 320.25 | 17.582 | 3718.0 |
| x86 | original | 6.20 | 291.20 | 6.717 | 133.0 |
| x86 | metadata | 9.35 | 309.05 | 17.846 | 2390.0 |
| x86 | arguments | 10.15 | 311.20 | 17.855 | 4296.5 |
| x86 | preview | 10.55 | 317.95 | 17.850 | 4305.0 |
| x86 | metadata + 32 frames | 9.75 | 296.85 | 17.840 | 2735.0 |
| x86 | preview + 32 frames | 11.05 | 320.75 | 17.852 | 4703.0 |

The low-detail modes reduced the observed median caller interval on this corpus,
while target RSS stayed close across monitored modes. Tail point estimates did
not increase monotonically with detail; they include file-system and scheduling
variability. The 32-frame setting is a requested limit; individual captures can
return fewer frames. Whole-command time is much larger than the roughly 19-22ms median
target workload and includes persistence and startup. These observations
motivate separately measuring collector and desktop costs.

Adversarial review reproduced a verifier accepting missing CreateFileW
arguments, duplicate call IDs and an impossible queue high-water value. The
corrected checks require full enabled signatures, known input values, handle
chains, sequential call IDs and high-water no greater than produced records.
The first full execution also exposed an incorrect 64MiB file bound for the
81.8MiB x64 Debug helper. Only the explicitly staged native binaries receive a
128MiB limit; other files retain 64MiB and the complete pack retains 1GiB limits.
The failed pack and the fresh corrected execution remain separate.
The final adversarial suite rejects 281 mutations and excessive artifact counts
and sizes. A separate real directory-junction probe confirms link rejection.
Readiness controls reject an incomplete supplied pack and preserve the partial
gate state for a valid native pack.

Pass `--native-profiles build/native-profile-ID` to the
[technical readiness reporter](technical-readiness.md) to include these checked
measurements. That row retains `nativeStatus: passed` with overall
`status: not_verified` until its remaining scopes have executed evidence.
