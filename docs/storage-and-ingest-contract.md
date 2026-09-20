# Storage and ingest bounds

KNAPM keeps its existing schema and compression identifier `zstd`. New chunks use
the pinned upstream Zstandard 1.5.7 codec, level 3, with content size and checksum.
The decoder accepts standard raw, RLE and compressed blocks, optional checksums,
known or unknown content size and old raw-only KNAPM frames. Each chunk is exactly
one ordinary frame. External dictionaries, skippable/concatenated frames, trailing
bytes, malformed checksums and output-size mismatches are rejected. Stored input,
decoded output and decoder window are independently capped at 64 MiB. A failed
decode exposes no partial output. Agent binaries do not link the codec.

UI replay requests `--window-limit 5000`. The helper validates the entire session
and traverses chunks without accumulating the full trace, retaining at most 5000
rows and 6 MiB of serialized trace data. With `--selected-event-id`, the window ends
at that event; later chunks are still validated. A missing requested event fails.
The total capture count remains distinct from retained rows. The immutable index
digest and chunk hashes are checked again on the replay pass. Legacy single-file
sessions and full batch replay retain their explicit aggregate limits. Index-based
search provides access to events outside the display window. A renderer-window
request rejects event IDs outside JavaScript's exact integer range.

The native streaming controller keeps a bounded summary: up to 128 captured
messages / 512 KiB, ordinary agent diagnostics up to 512 entries / 256 KiB, one
HELLO/drop/shutdown record each (256 KiB each), and audit entries up to 256 / 256 KiB. Complete
selected trace batches still reach the consumer and KNAPM writer. `retainedHistory`
reports total captured and omitted summary counts, including omitted resolver
observations, independently of transport loss. Batch requests are clamped to
1..64 records. Lifecycle evidence remains separate from the sampled summary.
Serialized batch frames are limited to 8 MiB. A rejected batch, consumer exception,
stdout failure or KNAPM write failure stops capture after agent cleanup and cannot
produce a successful terminal result. A KNAPM writer stops with an explicit error
at 8192 chunks, keeping its complete index within the reader's JSON limits; the
caller must start a new session. Automatic session rotation is not implemented.
Shutdown drains committed tail batches within one transport-capacity budget. An
unconsumed reservation produces an incomplete result. A controller query proving
disabled hooks is persisted as typed `cleanupState` evidence with its operation
identity and hook counts when the final agent pipe message is unavailable. Replay
validates that evidence separately; it does not fabricate an `agent_shutdown` event
or authenticate the truth of a target-supplied state report.

Background helper processes receive valid `NUL` standard streams through an
explicit handle inheritance list. Their complete trace goes to the KNAPM writer.
Metadata and chunk writes use an exclusively created temporary file, checked
writes and flushing before atomic replacement. Readers permit delete sharing so
they can finish reading an old version without blocking the writer. Storage
failure is sticky, clears finalized state, preserves `writerError`, and is reflected
in the terminal capture result. Failed storage startup does not attach an agent.
Live daemon status uses a bounded, identity-checked manifest snapshot. It reports
integrity as pending (`knapmValid=false`) until full terminal validation; status
polling does not repeatedly decode an ever-growing capture or treat files from
different in-flight commits as a corrupt terminal session.

Rust helper commands now bound stdout to 64 MiB, retain at most 64 KiB of stderr,
require valid UTF-8 and a complete EOF, and enforce process/read deadlines. A
descendant retaining a pipe cannot cause an unbounded join. Streaming batches
retain at most 128 batches and 32 MiB of serialized payload. A drain returns the
oldest pending prefix, up to 32 batches and 8 MiB; it no longer discards earlier
batches to satisfy a response limit. Queue eviction increments host-drop counts.
These byte limits cover encoded payload, not a claim about exact allocator RSS.
All operation queues together are limited to 64 MiB; eviction begins with the
oldest session and updates that session's host-drop count. The registry retains at
most 64 operations. Starting another removes the oldest terminal operation whose
helper has exited and has no unresolved recovery action, or returns a capacity
error if no safe slot is available. Saved
KNAPM files remain available independently of this in-memory history.

The UI advances its native cursor only after the worker's matching epoch/sequence
ACK is applied. Only one request is in flight; repeated reset/replace requests
coalesce to one latest pending replacement. A worker error/deadline closes ingest
with an explicit diagnostic rather than acknowledging lost data. Native queues
remain bounded when the renderer is paused. Old epochs, duplicate ACKs and delayed
replay responses cannot modify a newer view. Clear and new capture start establish
new epochs; replay pauses live view ingestion.

Workers send only new rows plus an eviction count. The worker retains IDs/byte
counts instead of a second full display-object array. The renderer retains at
most 5000 rows and 16 MiB of serialized UTF-8 data; selection is preserved while
its row remains, with an explicit selected replay event taking precedence. A
display-window eviction is not presented as a capture transport drop.

Tests: `validate-zstd-codec.mjs` uses Node's upstream codec as a separately packaged
encoder and decoder to check interoperability; `validate-large-replay.mjs` creates a standard-compressed 12000-row
session exceeding the old 64 MiB aggregate cap and checks bounded replay, selected
events and a corrupt final chunk. `validate-trace-ingest.mjs` exercises 200000 rows,
UTF-8 byte caps, stale/duplicate ACKs and reset storms.

References: [Zstandard API](https://github.com/facebook/zstd/blob/v1.5.7/lib/zstd.h),
[frame format](https://github.com/facebook/zstd/blob/v1.5.7/doc/zstd_compression_format.md),
[worker message semantics](https://developer.mozilla.org/en-US/docs/Web/API/Worker/postMessage).
