# A8: Partial native semantic recovery from real Ghidra typed JNI observations

This is a source-owned **qualification candidate**, not production Android recovery.
It is stacked on A7, A4 strict-record admission, and the signedness guard.

## Discover → Observe → Plan → Apply → Verify

The real pinned Android NDK r27 / Ghidra 12.1.4 A7 observations for
**x86_64 and AArch64** contain two independently recovered function boundaries.
One body is a restricted `uint(uint)` expression and the other has a signed
input parameter; the existing A7 stage rejects the pair as a unit.

A8 recovers each helper independently:

1. `recover_ndk_jni_typed_partial_v0.py` observes the ephemeral Ghidra log
   and freezes an IR candidate **without reading the C producer, address truth,
   or behavioral oracle**. It labels each helper `RESTRICTED_UINT_CANDIDATE`
   or explicit `ABSTAIN`. Neither is automatically accepted.
2. `verify_ndk_jni_typed_partial_native_v0.py` opens producer-side
   source-known ELF SHA/ABI/helper-address truth **only after the candidate
   has been frozen**. It rejects swapped helper identities and any attempt
   to promote the signed parameter to unsigned semantics.
3. The independent source-known C oracle in
   `a8_unsigned_native_oracle.c` is compiled with host GCC and Clang at
   O0/O2. Each build executes 1,034 deterministic uint32 vectors, yielding
   **4,136 real native C comparisons per observed ABI**. A mismatch is fatal.
   This validates only the source-owned unsigned helper on host x86_64.
4. Only bounded aggregate JSON is published; the frozen IR, raw Ghidra C,
   full vectors, private owner address map, and ELF binaries remain ephemeral.

## Execution

Portable negative controls (Linux GCC/Clang required):

```sh
python3 tests/test_ndk_jni_typed_partial_v0.py
```

The public source-known NDK/Ghidra job runs source-blind candidate creation
for both ABIs before invoking the independent native oracle, then publishes
only `a8/*-partial-result.json`. Logs redact encoded Ghidra observations.

## Evidence grading and restrictions

- **Potential accepted scope:** one `uint32` source-owned expression per
  Ghidra-observed ABI, checked against independent native x86_64 C behavior.
- **Always unqualified:** signed/implementation-defined right shift; actual
  Android ART/JNI runtime; native AArch64 behavioral execution; general C
  integer promotions/width; unseen/private targets; AI actor or production
  release qualification.
- AArch64 Ghidra pseudocode is **observed**, not executed as ARM64 native code.
- The source-known native C oracle is independent of the parser process,
  but does not prove behavior on unseen binaries or arbitrary targets.
- No product merge/release/target promotion before distinct independent review.

Owners: AAR private DLE #82 and cross-portfolio reversing DLE ghidra-tools #4.
