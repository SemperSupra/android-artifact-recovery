# Ghidra FID qualification on DEX

Status: experimental qualification

Hubitat's cheap attribution prepass exposed a large likely third-party DEX
footprint. Namespace evidence alone cannot safely remove that code from residual
recovery, so AAR measures whether the already-qualified Ghidra Function ID
primitive is useful on Dalvik methods.

The source-known DEX interview set contains:

- known implementation;
- exact copy;
- one-method patched derivative;
- API-compatible false friend;
- package-shaded implementation with otherwise matching source logic.

Required first-stage behavior:

- exact copy matches both target method hashes;
- the unchanged method in the patched derivative remains stable;
- the deliberately patched method changes;
- both false-friend methods are rejected.

The shaded result is recorded as an observation rather than assumed. Package
shading can alter constant-pool/type references and may or may not be normalized
by the Dalvik Function ID path.

A matching FID hash remains **structural evidence**. It is not sufficient by
itself to claim an exact Maven/AndroidX component or version.
