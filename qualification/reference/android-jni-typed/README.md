# A4 restricted JNI expression IR — type and shift guard

This source-owned experimental slice extends the existing A4 **uint32-only**
pseudocode evaluator. It deliberately **abstains** on signed or mixed-type
function signatures, rather than treating signed-negative C shifts as
unsigned logical shifts. It also rejects shift counts >=32; C leaves these
operations undefined at that width.

## Execution

Portable static regressions:
```sh
python -m unittest -v tests/test_ndk_jni_typed_guard_v0.py
```

Source-known native C controls on a host with GCC and Clang:
```sh
python qualification/reference/android-jni-typed/verify_native.py
```

The native comparison evaluates four GCC/Clang O0/O2 combinations with
seven unsigned inputs each (28 native observations) and checks all three
signed/mixed signatures abstain. It does NOT exercise Android, ART, JNI,
Ghidra, private APKs, or supported production semantics for signed C.

## Evidence and restrictions

The original parser/evaluator at `9726c8b56e229b0dad80f1d97a8c4a0c838d75a2`
collapsed all four signedness signatures. Prior independent native C
experiments reported 16/80 mismatches for signed-negative inputs.
This PR contains a fail-closed local corrective candidate; it does not
merge into or promote draft #39 and does not upgrade acceptance.

Owning method DLE: `SemperSupra/android-artifact-recovery-private#82`.
Cross-target DLE: `mark-e-deyoung/ghidra-tools#4`.
Provisional original evidence ZIP SHA-256:
`11179cf74fcda547eb2f8453186d0324e870f4caeed7b1f647922410f77ee0d0`.

Product gates: exact-head independent review, cross-ABI source-known
compiler controls, real Ghidra/JNI/ART checks, source-rights and merge.
