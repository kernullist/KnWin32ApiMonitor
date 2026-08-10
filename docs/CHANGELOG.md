# Changelog

## 2026-08-11 — v0.1.0.3

### Fixed

- Unique operation/writer/daemon IDs no longer collide within the same millisecond (helper + Tauri).
- Shared-memory transport creation fails closed when the mapping name already exists.
- Threaded shared-transport reader destructor no longer risks `std::terminate` on join timeout.
- Agent transport open validates header size and capacity bounds.
- Transport producer CAS failure publishes a poison slot instead of permanently stalling the consumer.
- Named cancellation events are reset on open so stale signals cannot cancel a new operation.
- Transport record sequence is loaded/stored with interlocked 64-bit operations for x86 safety.
- Release packaging supports single-config native output layouts (Ninja/NMake).

See `docs/plan/2026-08-11-adversarial-bug-review.md` and `docs/release-notes/v0.1.0.3.md`.
