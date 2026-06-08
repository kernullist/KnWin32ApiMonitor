# Sample Targets

`fileio-sample` is the first controlled native-capture target.

It builds as `knmon-sample-fileio.exe` through the native CMake project and performs deterministic File I/O:

1. Create/open a temp file.
2. Write a small payload.
3. Read the payload back.
4. Close the file handle.
5. Attempt missing wide-char and ANSI paths for error coverage.

The native helper uses this executable for controlled launch-time early-bird APC agent loading and bounded File I/O hook capture. Arbitrary already-running process injection remains out of scope.
