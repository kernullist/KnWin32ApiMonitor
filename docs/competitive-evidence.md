# Executed Windows comparison corpus

The Apache-2.0 corpus in `tests/corpus/windows-api-v1.json` executes six real
Windows APIs on x86 and x64. The target writes an independent caller-side oracle.
Each iteration creates a file, writes and reads 64 bytes, reads EOF, closes the
handle, allocates memory and frees it. Invalid-handle and missing-file failures
follow the loop. Sleep and SetFilePointerEx are unselected negative controls.

Four modes run in fresh processes with rotating order: original, KN Monitor,
Frida and private ETW. Ten repetitions per architecture produce 80 runs, with
450 expected selected calls in each run. Counts, ordering, success/failure, raw
last-error and 16-byte buffer previews must match the target oracle. Caller
observations must also match the original process. Failure, timeout, nonzero
exit, observer errors and unaccounted transport loss fail the comparison.

The Frida adapter pins [17.18.0](https://frida.re/news/2026/09/09/frida-17-18-0-released/)
and uses JavaScript Interceptor callbacks with batched delivery. It filters for
the target's direct call sites and observation interval, then detaches before
process teardown. These measurements describe that adapter. Frida also supports
[native CModule callbacks](https://frida.re/docs/javascript-api/), which require
a separate measurement before making a claim about its lowest overhead.

The first validated Debug comparison on Windows 10.0.26200 recorded the following
medians across ten fresh-process runs per architecture and mode. The p99 column
is the median of each run's p99, not a pooled p99.

| Architecture | Mode | Median call, us | Median run p99, us | Target RSS, MiB |
| --- | --- | ---: | ---: | ---: |
| x64 | Original | 6.65 | 324.65 | 5.52 |
| x64 | KN Monitor | 11.55 | 334.35 | 37.14 |
| x64 | Frida JS | 24.15 | 349.95 | 14.07 |
| x64 | Private ETW | 6.55 | 327.25 | 5.72 |
| x86 | Original | 6.50 | 308.30 | 6.51 |
| x86 | KN Monitor | 12.15 | 343.15 | 17.46 |
| x86 | Frida JS | 27.00 | 351.90 | 13.42 |
| x86 | Private ETW | 6.85 | 339.50 | 6.76 |

Each mode matched all 450 expected calls per run, including failure and preview
semantics. KN Monitor used more target memory than this Frida adapter; this is a
measured improvement target. The system-logger probe returned access denied (5)
on both architectures. No kernel ETW execution is claimed for this run.

The next validated run removed the unused x64 generic-dispatch exports and the
host-only API catalog from the injected DLL. All 320 supported wrappers remain.
The x64 Debug DLL shrank from 83,187,200 to 2,127,360 bytes; the x86 DLL remained
1,686,016 bytes. The `agent-footprint` CTest enforces an 8 MiB on-disk budget,
checks the four control exports and rejects test or disabled-dispatch exports.

The same 80-run comparison then measured x64 KN Monitor target RSS at 17.12 MiB
(54% below the initial 37.14 MiB), median call time at 10.95 us and median run
p99 at 335.00 us. The contemporaneous original/Frida JS RSS values were
5.51/14.06 MiB and median call times were 6.25/23.25 us. x86 KN Monitor RSS was
17.46 MiB and median call time was 12.05 us. All 450 calls per run still matched,
with zero transport loss. This is a measured footprint improvement; it does
not establish a latency improvement from these separate short experiments.
The current proof records this second run; the table above retains the original
baseline. Native ABI/live/replay proof and all 18 CTests pass on each architecture.

Private ETW is an application-instrumented auxiliary trace. The target emits its
oracle records through an actual in-process ETW provider, and a separate native
reader decodes the ETL file. It checks transport/replay fidelity; it does not
independently discover arbitrary API calls. Microsoft documents the supported
[private logger scope](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-private-logger-session).
The separate system-logger probe records availability and actual Win32 status.
An unavailable kernel trace is never counted as a successful kernel baseline.

## Measurement and recorded evidence

`generated/comparison-proof.json` records actual binary, source and artifact
hashes, tool versions, OS, architecture and per-run results. Source hashes use
UTF-8 with LF normalization. The proof checker rejects stale sources, incomplete
matrices, missing observations and invalid metrics. Full raw artifacts remain in
the output directory so the replay validator can recompute comparisons and
metrics and check every recorded artifact hash.

Caller QPC intervals measure the complete selected API call, including wrapper
entry sampling, original execution and record emission. They differ from the
agent's narrower original-call duration and emission-only overhead metrics.
The report includes workload time, controller wall time, target CPU accounting,
working set and peak working set. CPU accounting may round a short run to zero.
The working set is the target process's RSS, not aggregate UI/helper memory.
Fresh-process repetitions include cold initialization effects; no warmup run is
discarded. Per-run call quantiles are nearest-rank estimates, not guarantees.

These are scoped Debug results on the recorded Windows build. Six successful
API comparisons establish neither complete Windows API coverage nor a World
No.1 ranking. Other OS builds, Release behavior, CModule comparison, sustained
overload and complete UI/helper resource costs remain separate gates.

## Reproduce and inspect

Run from the repository root with configured x86/x64 MSVC build directories:

```powershell
python -m venv build/deps/frida-venv
build/deps/frida-venv/Scripts/python.exe -m pip install -r tools/comparison/requirements.txt
build/deps/frida-venv/Scripts/python.exe tools/comparison/run_comparison.py
build/deps/frida-venv/Scripts/python.exe tools/comparison/replay_comparison.py build/comparison-OUTPUT
build/deps/frida-venv/Scripts/python.exe tools/comparison/validate_evidence_mutations.py build/comparison-OUTPUT
build/deps/frida-venv/Scripts/python.exe tools/comparison/validate_native_corpus.py
build/deps/frida-venv/Scripts/python.exe -m unittest discover -s tools/comparison -p 'test_*.py'
node tools/comparison/test_frida_observer.mjs
build/deps/frida-venv/Scripts/python.exe tools/comparison/check_proof.py --publish build/comparison-OUTPUT
```

The runner rebuilds both architectures before execution and checks PE machine
types. It also rejects changes to source or binaries during the run. Evidence
imports restrict paths and file sizes, recheck consumed JSON hashes, and refuse
partial matrices. Negative controls include missing/duplicate/reordered events,
wrong output/error fields, forged metrics, stale sources, escaped paths, malformed
ETL payloads and a target that writes a valid report then exits with code 7.
