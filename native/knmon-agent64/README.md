# knmon-agent64

Minimal x64 agent DLL for the controlled native-capture foundation.

Current behavior:

1. Loaded by the controller through controlled launch-time early-bird APC.
2. Starts a lightweight worker thread from `DllMain`.
3. Sends a versioned HELLO JSON payload to the named pipe supplied in `KNMON_AGENT_PIPE`.

It does not install API hooks yet. A successful HELLO proves agent load and controller/agent handshake only.
