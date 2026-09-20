# Sustained capture regression

`sustained-capture` runs an owned four-thread target twice: first without an
agent, then with the production agent and `kernel32.dll!CloseHandle` selected.
Every worker repeatedly calls `CloseHandle(nullptr)` and checks the original
`FALSE` / `ERROR_INVALID_HANDLE` result. Both executions sample CPU time, peak
working set, private bytes and handle count every 50 ms.

The observed execution uses a 64-record transport and a consumer that sleeps
20 ms per batch. This deliberately saturates the queue. It is a loss-accounting
and bounded-resource regression, not an ordinary capture overhead benchmark.
The independent target counts every attempted call and reads the shared
transport counters at quiescent workload boundaries. The controller verifies:

- Attempts equal committed records plus explicitly reported drops.
- Every committed sequence in the measured window is delivered exactly once,
  in order; the terminal transport is fully consumed without aborted records.
- The queue never exceeds 64 records, retained history never exceeds 128
  events, and omitted history reconciles with streamed delivery.
- Original and observed calls preserve the required result and error state.
- Sampled target memory remains below 128 MiB, controller memory below 512 MiB,
  private-byte variation after the first second below 32 MiB, and handle count
  below 256. These are regression budgets, not competitive performance targets.

CTest uses a five-second workload per execution. A longer check can run from
any working directory; evidence is written under the supplied build directory:

```powershell
ctest --test-dir build/native-msvc -C Debug -R '^sustained-capture$' --output-on-failure
& build/native-msvc/Debug/knmon-sustained-capture-test.exe "$PWD/build/native-msvc/Debug" 15000
& build/native-msvc-x86/Debug/knmon-sustained-capture-test.exe "$PWD/build/native-msvc-x86/Debug" 15000
```

The output directory contains bounded `original.json`, `observed.json` and
`summary.json` files. A summary with `status: passed` is written only after all
checks pass, and failure to persist it fails the executable. Process exit status
must also be checked. The workload includes closing its four thread handles and
start event inside the accounting window; initial setup and closing the report
file occur outside it.

Executed on Windows 10.0.26200 with the pinned MSVC toolchain, Debug, on
2026-09-20. Each observed workload ran for 15 seconds:

| Measurement | x64 | x86 |
|---|---:|---:|
| Attempted calls in window | 66,381,198 | 48,108,983 |
| Delivered records in window | 2,942 | 2,494 |
| Explicit drops in window | 66,378,256 | 48,106,489 |
| Target peak working set, bytes | 19,546,112 | 19,890,176 |
| Controller peak working set, bytes | 35,172,352 | 30,916,608 |
| Target private-byte variation after 1 s | 159,744 | 303,104 |
| Controller private-byte variation after 1 s | 212,992 | 245,760 |
| Target CPU time, seconds across four workers | 59.78125 | 59.78125 |
| Controller CPU time, seconds | 11.609375 | 12.515625 |

Both targets reported zero behavior errors. Both queues reached their 64-record
bound and drained fully; retained history stayed at 128 events. The controller
CPU samples include launch, collection and shutdown (15.719 s / 15.891 s wall
intervals). These results describe deliberate saturation and substantial loss.

The tested interval is finite. It does not establish indefinite leak freedom,
all API behavior, performance of unimplemented capture modes, or whole desktop
WebView resource use. The existing comparative corpus measures normal capture
latency separately. Release and other Windows-build evidence are tracked in
`validation-matrix.md`.
