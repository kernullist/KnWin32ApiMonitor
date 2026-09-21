# Coordinated desktop corpus costs

The producer runs the independent six-API caller through the real Release
desktop, with matching Debug native helper and Agent binaries. It uses the
[readiness handshake](capture-readiness.md) to hold the caller until the actual
streaming session reaches `running`, then retains the target through detach.
No benchmark-only hook path is added to the product.

```powershell
python -B -X utf8 tools/readiness/corpus_desktop.py
python -B -X utf8 tools/readiness/corpus_desktop.py --check <evidence-directory>
python -B -X utf8 tools/readiness/verify_corpus_desktop.py <evidence-directory>
python -B -X utf8 tools/readiness/technical_gate.py --desktop-profiles <evidence-directory>
```

`--probe --architecture x64 --mode preview` runs one diagnostic trial and labels
it `probe_passed`. A probe cannot pass the matrix consumer or the complete cost
gate. Failed attempts are retained in separate directories.

## Workload and observation contract

There are ten fresh-process repetitions of original, metadata, arguments,
preview, metadata with 32 stack frames, and preview with 32 stack frames on each
architecture. Mode order rotates between repetitions. Every run performs 64
iterations, 450 calls and 30 ms of pacing per iteration, with a fresh WebView
profile. The original baseline keeps an idle desktop open without attaching.
All observed modes select exactly the same six APIs using the real UI controls.
Before measuring idle, the driver opens Output and waits for the initial native
enumeration completion audit and enabled controls. This excludes the transient
enabled state before the initialization effect starts. Output remains the active
inspector during this corpus scenario.
The caller's timing includes pacing in workload duration, but excludes it from
individual API call intervals. Return values, errors, file bytes, argument policy,
stacks, event order and complete delivery are independently checked.

The window is hidden during execution. Its DOM counter is read through its
owned loopback CDP listener. This is ingestion/presentation-state evidence under
that visibility condition; it is not visible-window performance, frame paint or
display scanout. Background scheduling and the external observer contribute to
these measured intervals.

The parent records QPC before requesting each DOM snapshot and after receiving
it. For newly counted events, the preceding snapshot's request time provides a
conservative lower bound; the current response time provides the upper bound.
Bounds are relative to each event's original-call end QPC. Chromium clock origins
are not assumed to equal the caller's. The report retains both bounds and their
widths instead of inventing an exact delivery timestamp.

Requests and replies use unique sequence-numbered files, written once. A new
request does not replace a file that a Windows reader may still hold open.
The consumer compares those files with the recorded observations. A missing or
temporarily locked WebView discovery file is retried within the existing startup
deadline; it never bypasses the owned-listener check or publishes capture readiness.

## Resources and limitations

The producer samples owned application and target Jobs every 100 ms. Job CPU
and logical I/O include processes that exit between samples. Identified process
samples record working set, private bytes and handles. The workload resource
window uses the last sample before the caller begins and the first after it
ends, so its reported duration includes guard time. Idle samples are retained
separately. Sampling gaps over 500 ms invalidate the active run.

`medianApplicationCpu100ns` describes that caller-bracketing window. It excludes
startup and work performed after the last bracket sample, including later queue
drain and export work. It is not total session CPU cost. The raw samples remain
available through detach, followed by final Job accounting after normal exit.

Working-set sums can count shared pages repeatedly; they are not unique physical
memory. Sampled maxima can miss intervening peaks. I/O counters include pipes and
other logical operations, not just physical disk traffic. Short CPU intervals
are quantized. The Node driver and Python observer are outside the application
Job, but their system load and CDP traffic still affect the experiment.

The matrix records product, producer, runtime and binary hashes, raw caller and
UI data, process identities and normal process exits. Its consumer recomputes
every trial and aggregate. Mutable WebView profiles and temporary runtime caches
are retained but excluded from the measurement artifact manifest. Reparse paths,
unbounded artifact inputs and changed bound data are rejected. These are unsigned
local consistency checks, not authenticated source-to-binary provenance.

`capture_profile_costs` remains `not_verified` after this matrix passes. Separate
collector, disk and serialization attribution, visible presentation costs,
Release-native evidence and broader workloads remain necessary before general
performance claims. The matrix does not establish a World No.1 ranking.

## Recorded matrix, 2026-09-21, source revision eb8a4f1

`build/desktop-corpus-bjh1xvw0` passes all 120 runs: 54,000 caller invocations,
including 45,000 observed records with exact ordering, zero recorded loss,
complete hook restoration, target survival through detach and normal Job exits.
This pack includes the Agent readiness-delivery retry, streaming startup-state
correction and persistent desktop failure reporting changes.
Its source snapshot was shipped as `eb8a4f1`. The later source-archive validator
change also changes the broader source fingerprint, so this pack remains
historical for the current-source consumer. The validator update changes neither
the measured native/UI code nor the measurement scope.
The following values are medians of ten run-level measurements, not pooled-call
quantiles. DOM p95 bounds include the observer interval; they are not exact
rendering latency. Application CPU is summed across the owned processes within
the caller-bracketing window described above.

| Arch | Mode | Caller median (us) | App CPU (ms) | App sampled RSS sum (MiB) | DOM p95 lower..upper (ms) |
|---|---|---:|---:|---:|---:|
| x64 | original | 10.05 | 148.44 | 596.07 | n/a |
| x64 | metadata | 32.35 | 1664.06 | 734.16 | 371.39..581.85 |
| x64 | arguments | 36.20 | 2617.19 | 733.69 | 519.42..728.12 |
| x64 | preview | 36.35 | 2640.62 | 728.52 | 538.94..747.95 |
| x64 | metadata, stack32 | 43.10 | 1921.88 | 739.71 | 409.44..618.69 |
| x64 | preview, stack32 | 44.80 | 2718.75 | 737.15 | 575.82..784.27 |
| x86 | original | 10.50 | 187.50 | 589.90 | n/a |
| x86 | metadata | 34.95 | 1937.50 | 722.95 | 407.12..619.25 |
| x86 | arguments | 39.20 | 2750.00 | 719.96 | 761.51..971.84 |
| x86 | preview | 40.35 | 2843.75 | 716.77 | 739.14..949.82 |
| x86 | metadata, stack32 | 36.35 | 2101.56 | 724.36 | 442.83..654.31 |
| x86 | preview, stack32 | 39.80 | 2828.12 | 720.13 | 1066.68..1275.55 |

These observations identify desktop resource use and delivery delay for further
profiling. They do not attribute the increase to a particular component or prove
that one setting is consistently faster. Raw per-run samples, caller quantiles,
I/O counts and delivery bounds are retained in the pack.

The preceding attempt, `build/desktop-corpus-j29m69yi`, remains failed because
one active resource-sampling gap reached 2233.85 ms. Its affected trial still
delivered all 450 records, but that cannot repair the missing resource samples.
Five instrumented diagnostic probes did not reproduce the gap; its cause remains
unresolved. The fresh matrix above used unchanged product sources and producers
and retained the 500 ms sampling limit.

Measurement semantics follow Microsoft's [QPC guidance](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps),
[Job accounting](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_and_io_accounting_information),
[I/O counters](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-io_counters)
and [WebView2 process model](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/process-model),
checked on 2026-09-21. The [WebView2 performance guidance](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/performance)
supports measuring the actual process tree and communication costs; it does not
certify the local results.
