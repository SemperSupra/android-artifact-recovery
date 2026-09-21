# Golden JNI/native workload

This source-known Android workload exercises a native C++ analysis routine
through JNI while remaining deterministic and small enough for recovery
experiments.

The workload computes six observable properties over an arbitrary byte payload:

- FNV-1a 64-bit fingerprint;
- payload length;
- zero-byte count;
- printable ASCII count;
- longest identical-byte run;
- distinct-byte count.

The same C++ core is compiled in two ways:

1. a host executable used as an independent behavioral oracle;
2. an Android shared library embedded in an APK for both `arm64-v8a` and
   `x86_64`.

This gives AAR a source-known target containing:

- Kotlin/JNI boundary code;
- ELF native code;
- two Android ABI builds from the same semantics;
- loops, branches, fixed-width arithmetic, table state, and structured output;
- a deterministic cross-build test vector.

A successful build is not by itself semantic recovery. Later AAR stages recover
the DEX/JNI/native correspondence and compare recovered behavior to the oracle.
