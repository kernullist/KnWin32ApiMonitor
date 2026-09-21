# Release backend runtime evidence

Run the complete Rust backend suite against both Windows architectures:

```powershell
python tools/readiness/backend_release.py
python tools/readiness/backend_release.py --check build/backend-release-ID
python tools/readiness/verify_backend_release.py build/backend-release-ID
```

The producer builds `knmon-tauri` through the desktop manifest and its committed
Cargo.lock. `--release --locked --lib --no-run` selects the library test target;
the standalone, untracked backend lockfile is preserved. The x64 and x86 test
executables run with matching Debug helpers, agents, File I/O targets and the
target's dynamic probe DLL. This configuration does not clear the separate
native Release gate.

Cargo's [compiler-artifact messages](https://doc.rust-lang.org/cargo/reference/external-tools.html)
bind the package, source path, test target, optimized profile and executable.
The verifier also checks the executable's actual PE architecture. Builds and
tests run in owned Jobs with deadlines and bounded logs. Test runs explicitly
use [--include-ignored](https://doc.rust-lang.org/rustc/tests/), one test thread
and uncolored pretty output. Both real-helper tests are ignored by ordinary
`cargo test`; this producer requires all 21 named tests to execute and pass.
Missing, filtered, ignored, duplicate or failed test results are rejected.

Streaming registration must remain `starting` until a matching helper state
announces readiness. Obtaining a helper PID is insufficient. The regression
covers both launch and attach, pending cancellation and unchanged nonstream
operation states; the desktop corpus checks the resulting real capture path.

The stack observation regression exercises the shared malformed/legacy corpus
through both agent and trace DTOs. It rejects object-encoded enum values, nulls,
unknown provenance and contradictory uncaptured frames, and verifies lossless
legacy string and hook-context roundtrips. See the
[stack observation contract](stack-observation.md).

The capture-detail regression runs 31 shared cases through both DTOs. It
preserves explicit metadata, arguments and preview policies, retains unspecified
legacy events, and rejects unknown policies and contradictory argument/buffer
payloads. See the [capture detail contract](capture-detail.md).

The positive integration test requires a completed capture, nonempty trace
batches, no reported native or host loss, retained launch identity and helper
exit. The failure integration test copies the sample into a fresh directory
without its dynamic probe DLL. Its nonzero exit must become a terminal failure
with the error message and process-exit cleanup evidence preserved. The native
capture-retention CTest separately checks a launched target returning code 1.

This failure case exposed a completed native result that still reported
`stopping_agent`. The backend consequently kept the operation active after the
helper exited. Launch and attach now finalize their operation and session
states after cleanup. Cleanup failure remains distinct, and transport-consumer
failure takes precedence over cancellation. The backend rejects nonterminal
final results and inconsistent success/state pairs before accepting them. It
also retains a failed result's diagnostic message; ordinary cancellation does
not populate `lastError`.

Evidence includes tool identities, product source hashes, command requests,
raw Cargo/test output, the explicit helper/compiler environment binding and
retained binary hashes. Replay checks the original and staged binaries, current
sources and producers, and rechecks inputs before returning. Adversarial
controls alter the raw reports, profiles, commands, environment and summaries;
they also execute the ordinary ignored-test path and an actual missing-agent
failure on both architectures.

These are unsigned local consistency checks, not builder authentication. A
passed suite establishes its exercised cases on the recorded Windows build;
it does not prove every concurrency schedule, other Windows builds, the native
Release configuration or absence of unknown defects. User evaluation is outside
this gate. Pass `--backend-release build/backend-release-ID` to the
[technical readiness verifier](technical-readiness.md) to check this evidence
alongside the other required scopes.
