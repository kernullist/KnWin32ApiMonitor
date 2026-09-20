# Capture readiness and coordinated corpus

Launch and attach sessions begin in `starting`. `KnMonAgentInitialize` starts
an asynchronous worker; a successful return and an authenticated `agent_hello`
do not prove that hooks are installed. The Agent sends `agent_ready` after its
initial hook installation and module-sweep worker startup succeed. The message
contains the requested `captureDetail` and `stackFrames`.

The Controller requires the channel's operation ID, PID and nonce, HELLO order,
architecture and exact requested capture policy to agree before publishing
`running`. Duplicate readiness, readiness before HELLO or after shutdown, and
policy mismatches invalidate the channel. A later valid message cannot repair
an invalid channel. Readiness received while stopping cannot restore `running`.
Both streamed and retained CLI sessions deliver these state transitions;
retained sessions do not acquire trace-batch output as a side effect.

Launch and attach require readiness within `TimeoutMs` after pipe connection,
including continuous captures. A shorter bounded capture can end before this
deadline and fail its missing-readiness requirement. Cancellation can stop
initialization without publishing readiness. Protocol failure remains a failure
if the target exits. Attach cleanup after a fatal protocol error requires the
remote state query; an earlier shutdown message on that invalid channel is
insufficient.

Use matching Agent and helper builds. This is a required live launch/attach
message in the current bundle, with no change to transport record layout or
attach configuration layout. An older Agent without the message cannot satisfy
the new readiness requirement. Existing saved sessions remain replayable without
this message. Bounded capture history reserves a lifecycle slot for readiness
so a full diagnostic budget cannot discard it. Readiness describes the initial installation pass; it does not
promise coverage of every export, pre-attach call or future module load.

## Independent workload coordination

The comparison caller has an opt-in mode:

```text
knmon-comparison-target.exe OUTPUT_DIRECTORY ITERATIONS --coordinated ID DELAY_MS WAIT_MS
```

The directory must exist without `oracle.json` or `corpus.bin`. Before starting
the target, the producer creates four fresh, nonsignaled manual-reset events:

```text
Local\KNMon.Corpus.ID.ready
Local\KNMon.Corpus.ID.start
Local\KNMon.Corpus.ID.done
Local\KNMon.Corpus.ID.release
```

`ID` contains 16–64 ASCII letters, digits, hyphens or underscores. Delay and
timeout are canonical unsigned decimal operands: delay 0–1,000 ms, timeout
100–30,000 ms, and delay times iterations at most 20,000 ms. The target opens
existing events with only the rights needed for each operation. Existing
signaled events, missing events and malformed operands fail before readiness.
These events coordinate a producer-owned test process within its Windows
session. They are not an authentication boundary.

1. The target signals `ready`, then waits for `start` before its timed workload.
2. The producer attaches and waits for authenticated capture readiness before
   signaling `start`.
3. The target executes the unchanged six-API corpus. It closes `oracle.json`
   before signaling `done`, then waits for `release`.
4. The producer finishes capture and verifies detach while the target is alive.
   Only then does it signal `release` and require exit code zero.

The start/release waits and synchronization-handle cleanup lie outside the
workload QPC and CPU intervals. Pacing lies inside workload duration but outside
per-call latency. The optional `coordination` object records the ID, requested
pacing, timeout, ready QPC and start-gate QPC. It is absent in legacy modes.
The target's own process-memory sample remains a snapshot after the workload;
it is not a desktop process-tree measurement.

A correct oracle alone does not prove successful coordination: failure to
release the target produces a nonzero exit after the oracle was written. The
producer must validate the complete event sequence, target lifetime, capture
closure and exit status. Windows 8 and later exclude low-power time from these
wait timeouts, so this is not a strict wall-clock deadline across sleep.

The default, private-ETW and forced-exit modes retain their existing behavior.
The paced corpus enables later comparable desktop measurements; this change
does not itself complete the capture-profile-cost gate.

## Executed checks

`corpus-control` owns child lifetimes using kill-on-close Jobs. It checks the
default and forced-exit modes, exact 58-call oracle, pacing, pre-start exclusion,
release holding, timeouts, malformed controls and actual attach/detach. The
real Agent captures exactly those 58 calls with no coordination-handle records.
A separate test-only DLL installs no hooks and supplies eight faulty startup
flows, including missing readiness in bounded and continuous modes. Failed
attach must preserve the target and finish agent cleanup.

`ipc-security` checks channel ordering, sticky failure and request binding.
Twenty shared JSON fixtures check the native parser, Node parser and published
schema. `validate-session-readiness.mjs` checks actual retained, streamed and
failed launch transitions; native session fixtures check that daemon discovery
preserves an active `starting` state while integrity is pending.

Windows synchronization semantics were checked against Microsoft's
[CreateEventW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventw),
[OpenEventW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-openeventw)
and [WaitForMultipleObjects](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitformultipleobjects)
documentation on 2026-09-21.
