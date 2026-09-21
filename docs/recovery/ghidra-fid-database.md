# Populated Ghidra FID reference database qualification

Status: experimental qualification

The prior FID increment proved deterministic Function ID hash behavior. This
increment exercises the next layer: creation of a small reference FID database
from a source-known library and lookup of adversarial variants against that
database.

AAR creates the database from the known native golden, then queries:

- exact copy;
- stripped copy;
- one-function patched derivative;
- false friend exposing the same API names;
- alternate optimization build.

Required behavior:

- exact and stripped unchanged functions are found;
- the unchanged sibling in the patched derivative is found;
- the deliberately patched function is not accepted as an exact named/specific
  match;
- false-friend functions are not accepted.

The alternate optimization result is recorded rather than required because FID
is primarily an exact/function-signature matcher, not the cross-compiler
similarity layer. BSim remains the candidate for that later need.

The generated `.fidb` is disposable derived tooling state. AAR stores the
normalized query evidence, Ghidra version, reference identity, and database hash
where used operationally.
