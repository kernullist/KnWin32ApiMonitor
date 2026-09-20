# IPC and operation ownership

Agent 0.4.0 uses attach configuration ABI 3. Controllers and agents must be built together. The configuration carries the controller PID, its exact process creation time, and the expected transport byte extent. These are separate from the user-visible operation ID.

Operation IDs contain 1 to 63 ASCII letters, digits, hyphens, or underscores. Oversized or unsafe IDs are rejected before starting a target or creating its channel.

## Channel identity

Each pipe and section name contains an independently generated 256-bit BCrypt nonce. Pipe creation uses `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`. The explicit protected DACL grants the current logon SID only the rights required by the server and writer. It does not grant `FILE_CREATE_PIPE_INSTANCE`, which shares a bit with `FILE_APPEND_DATA`; granting `GENERIC_WRITE` to pipe clients would unintentionally include that right. Clients request individual write, attribute, and synchronization rights instead.

An `OWNER RIGHTS` ACE grants the owner only `READ_CONTROL`, suppressing implicit `WRITE_DAC`. Without this ACE, another process running as the same account could use ownership to rewrite the DACL despite the logon SID restriction. A negative test reproduces that bypass and verifies that reopening a protected event with `WRITE_DAC` is refused.

IPC objects have an explicit medium integrity, no-write-up label. Low integrity writers are refused. Medium and elevated interactive processes in the same logon can exchange untrusted capture data without granting access to other logons. Different sessions, logon SIDs, and authentication IDs are refused. Service accounts without a logon SID and restricted/AppContainer processes are outside this channel policy; failures are explicit rather than accommodated with an Everyone ACL.

The controller retains the expected target process handle and compares the connected pipe client PID with that process object. It also checks target and controller token logon identities. The agent checks the pipe server PID, expected creation time, and logon identity before sending data or installing hooks. Its pipe connection permits identification-level impersonation only.

Every message carries the channel nonce, operation ID, and target PID. A bounded typed parser checks the envelope, and the channel requires exactly one initial HELLO. Wrong identity, a message before HELLO, or a duplicate HELLO causes a sticky channel failure. An unauthorized first connection fails the session closed; this is not a denial-of-service prevention guarantee.

The section name is independent of the operation ID. Existing sections are never reused. The agent maps the trusted expected extent, validates a local header snapshot including architecture and operation ID, and fixes its writer capacity from the supplied extent. The controller continues to treat every record and mutable counter as hostile input. A matching client identity does not prove that an injected process reports truthful events.

Child launch uses a private Unicode environment block. It does not temporarily change the controller process environment, so concurrent launches cannot exchange channel identities. Attach supplies the same identity through the bounded versioned configuration.

## Cancellation and launch ownership

Cancellation events use the same explicit logon DACL and integrity label. A controller refuses a preexisting named event. Nested tree captures share an event already owned by that controller through retained handles; they never reset a parent's pending cancellation. Rust signals registered operations directly and retries briefly when cancellation races event creation. A terminal operation stays terminal when stopped again.

Rust startup uses a rollback guard. Helper lookup, argument validation, process spawn, output setup, and worker setup failures leave a terminal failed record with a reason. The child-process guard owns termination/reaping until ownership passes to the stream worker. Bounded capture and tree supervision use the same operation guard.

The stream reader limits a frame to 8 MiB and retained stderr to 64 KiB, verifies operation/session/helper/target identity, and prevents later frames from clearing an earlier failure. A final capture result is required. Reader shutdown uses a stop flag and `CancelSynchronousIo`; incomplete reader shutdown is reported as failure. Error cleanup requests agent stop, drains output, then applies a finite helper-exit deadline. An unfinished agent cleanup is not reported as a successful detach.

Rust duplicates the actual helper process handle. A launched target is retained only after its PID and creation time match the helper's `CreateProcess` result. Destructive cleanup uses retained handles. There is no snapshot-based PID tree termination.

The desktop launch path opts into `--own-launch-job`. The native helper assigns a kill-on-close job while the target is suspended. Failure to assign is a launch failure; the target is not resumed. Nested-job compatibility is exercised by the smoke test. A helper crash or owner-process exit closes the owned target tree. A controlled monitoring stop relinquishes kill-on-close, including an incomplete agent stop, so that failure does not unexpectedly terminate the target. The neutral job association persists until its processes exit. Arbitrary CLI launches retain their existing behavior unless this option is supplied.

For a separate owner, `--owner-pid` requires `--owner-created` with that process's Windows creation FILETIME. The helper retains and verifies the owner handle. The desktop exit path lets a live launch helper observe that original owner object instead of cancelling and losing its ownership first. Bounded attach sessions never gain target termination rights through this mechanism.

## Renderer boundary

The desktop shell refuses an elevated process token. Elevated capture remains a native CLI operation; an elevated renderer is not an elevation broker. The main webview permits the bundled origin only, plus the exact local Vite origin in debug builds. New-window requests and remote navigation are denied.

CSP restricts scripts, connections, workers, frames, objects, and form submission. Inline styles remain allowed for React layout. Each application command is declared in `AppManifest`, and only the local main window receives its explicit command permissions and file-open dialog permission. Remote origins receive none. The helper executable is resolved from the app's own directory, or a build-tree location in debug builds; the current working directory and arbitrary parent directories are not executable search locations.

## Verification

- `ipc-security` CTest: actual independent clients, exact DACL and integrity label, wrong PID/creation time, low integrity write denial, name collision, section extent, nonce/operation mismatch, initial/duplicate HELLO, and sticky failure.
- `tools/native-smoke/ipc-ownership-smoke.py`: helper crash, owner exit, normal detach, and cancellation-event collision. Retained handles verify both the root and two children under a preexisting outer job.
- Rust tests: rollback, failed spawn, byte/UTF-8 framing limits, immutable stream identity, sticky failure, creation-time mismatch, child rollback, and synchronous reader cancellation with a live writer. The ignored native integration test runs when `KNMON_TEST_NATIVE_HELPER` names a built x86 or x64 helper.
- Tauri tests: exact navigation origins and release/development separation. Native capture, saved replay, hostile transport, module lifetime, and x86/x64 regression tests remain required.

Cross-user interactive logon and elevated-to-medium end-to-end scenarios require a host with those tokens available. The local host's standard-user and lowered impersonation-token checks do not stand in for those environment-specific runs.

## Primary references

- [Named pipe access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Pipe client process identity](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid)
- [Mandatory integrity control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [Synchronous I/O cancellation](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelsynchronousio)
- [Tauri CSP](https://v2.tauri.app/security/csp/)
- [Tauri application command capabilities](https://v2.tauri.app/security/capabilities/)
