# Native hardening and controller lifetime

MSVC builds compile C/C++ with `/guard:cf /GS` and link with
`/GUARD:CF /DYNAMICBASE /NXCOMPAT`. x64 additionally declares high-entropy ASLR
and CET compatibility; x86 requires SafeSEH. CTest checks the production agent,
helper and collector PE metadata. `cfg-enforcement` also runs real child
processes: an allowed indirect call succeeds and a guard-suppressed call must
terminate with `0xc0000409`. CET compatibility metadata does not prove hardware
shadow-stack enforcement on every host.

The Rust desktop uses `.cargo/config.toml` target-specific MSVC flags, including
`-C control-flow-guard=yes` for LLVM instrumentation. Rust's
[documented default is disabled](https://doc.rust-lang.org/rustc/codegen-options/index.html#control-flow-guard).
Its test executable queries the actual process CFG policy. As with native
linkage, system libraries and precompiled runtime dependencies do not become
newly instrumented merely because the application is built with CFG enabled.

Enabling CFG exposed an existing resolver defect on Windows 10.0.26200:
`kernel32!GetProcAddress` has `IMAGE_GUARD_FLAG_FID_SUPPRESSED`. Calling its
correct export address through a mutable function pointer fails CFG. The
wrapper now calls its own compiler-bound IAT entry, which the monitor excludes
from patching, and only accepts an original binding that matches that import.
The [Microsoft PE metadata contract](https://learn.microsoft.com/en-us/windows/win32/secbp/pe-metadata)
explicitly permits IAT calls to suppressed exports. No `guard(nocf)` exemption
or CFG bitmap relaxation is used. The module-lifecycle test covers hooked
delay-load resolution, named/ordinal lookups, unload/reload and conflicting
exports on both architectures.

The agent retains the authenticated controller process handle, including its
creation-time and logon identity. A dedicated wait thread observes that process
object, avoiding PID reuse. Controller death closes hook admission and runs the
same bounded shutdown used by explicit detach. Normal stop wakes and joins the
watcher; watcher-initiated stop never joins itself. In-flight calls that miss the
existing two-second quiescence deadline retain their resources and report an
incomplete stop. The DLL remains pinned under the existing no-unload policy.

Authenticated control pipes use atomic message writes in nonblocking wait mode.
Messages are limited to 64 KiB; a full pipe, unavailable writer lock or failed
write increments the agent loss counter. A failed HELLO prevents hook startup.
This deliberately drops whole messages when a controller stops reading; there
is no asynchronous write retaining the caller's temporary JSON buffer.
[Microsoft documents the message-pipe full-buffer behavior](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-type-read-and-wait-modes).
IPC tests fill an actual unread pipe, check bounded completion, reject byte
pipes and reject empty/oversized messages.

Run the native matrix with:

```powershell
ctest --test-dir build/native-msvc -C Debug --output-on-failure
ctest --test-dir build/native-msvc-x86 -C Debug --output-on-failure
python tools/native-smoke/attach-controller-death-smoke.py --helper build/native-msvc/Debug/knmon-native-helper.exe
python tools/native-smoke/mitigation-denial-smoke.py --helper build/native-msvc/Debug/knmon-native-helper.exe
```

Repeat both Python commands against `build/native-msvc-x86/Debug`. The first
kills only its owned controller and verifies target survival and actual
reattachment. The second enables Microsoft-signed-only CIG in an owned target,
requires preflight denial before transport or remote allocation, and verifies
normal target exit with no agent loaded. All process handles used for forced
cleanup belong to processes created by the test. No machine policy changes or
Defender exclusions are needed.

These checks establish the executed build/OS scope. Other Windows versions,
elevated or cross-user peers, and runtime CET enforcement need separate matrix
evidence. A successful mitigation denial is not monitoring coverage of that
protected target.
