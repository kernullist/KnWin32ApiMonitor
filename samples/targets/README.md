# Sample Targets

`fileio-sample` is the first controlled native-capture target.

It builds as `knmon-sample-fileio.exe` through the native CMake project and performs deterministic File I/O:

1. Create/open a temp file.
2. Write a small payload.
3. Read the payload back.
4. Close the file handle.
5. Attempt one missing path for error coverage.

The native helper uses this executable for controlled launch-time early-bird APC agent loading. Arbitrary already-running process injection remains out of scope.
