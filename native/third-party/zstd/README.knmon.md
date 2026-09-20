# Zstandard 1.5.7

Unmodified library sources from the official v1.5.7 release archive.
Source: https://github.com/facebook/zstd/releases/tag/v1.5.7
Archive SHA-256: eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3

BSD-3-Clause license is selected from the upstream dual license; LICENSE and COPYING are retained.
Only lib root, common, compress and decompress source/header files are included.
SHA256SUMS pins every retained upstream file; CMake verifies it before compiling.
Dictionary building, deprecated legacy codecs, multithreading and assembly are disabled.
The helper links the codec statically. Injected agents do not include it.
