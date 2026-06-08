# Sample Sessions

Generated helper sessions are written under `captures/` and remain ignored by git.

The current replayable helper format is:

1. `manifest.json`
2. `audit.jsonl`
3. `agent-events.jsonl`
4. `trace-events.jsonl`

Use:

```powershell
build\native\Debug\knmon-native-helper.exe capture-sample --write-session captures\latest-sample-fileio
build\native\Debug\knmon-native-helper.exe validate-session --session captures\latest-sample-fileio
build\native\Debug\knmon-native-helper.exe replay-session --session captures\latest-sample-fileio
```

Tracked test fixtures live under `tests/fixtures/session/`. Future `.knapm` samples can move here once the compressed container format stabilizes.
