# Ghidra BSim incremental qualification

Status: experimental

BSim is not added merely because Ghidra provides it. The exact/function-hash FID
qualification showed that a rebuild at a different optimization level changes
FID hashes. BSim is therefore interviewed specifically for that unresolved
build-variant/delta case.

The source-known native interview corpus compares the O2 reference against:

- exact copy;
- stripped copy;
- one-function patched derivative;
- same-name false friend with unrelated logic;
- O0 rebuild from the same source.

Qualification requires exact/stripped and the unchanged patched sibling to be
near-exact under BSim. BSim then earns incremental value only if at least one O0
function has a material similarity margin over its false friend.

The first qualification intentionally does **not** establish a universal
similarity/confidence threshold for production component attribution. It only
determines whether the primitive provides information beyond FID on the controlled
build-variant problem.

Any later operational BSim evidence remains a candidate correspondence signal and
cannot independently establish component/version identity.
