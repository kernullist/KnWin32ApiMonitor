# knmon-agent32 source notes

`knmon-agent32.dll` is currently built from the shared source at `native/knmon-agent64/src/AgentMain.cpp` with Win32-specific compile definitions.

This folder remains reserved for x86-only source files if a future ABI-specific split becomes necessary. Do not duplicate the shared agent implementation here unless the divergence is documented and covered by x86/x64 smoke tests.
