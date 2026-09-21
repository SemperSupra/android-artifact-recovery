# Repair-assisted Kotlin/JADX representation

Status: experimental qualification

The raw JADX representation remains immutable evidence. This stage creates a
second, explicitly derived representation with narrowly bounded repairs for
known Java-compiler problems caused by Kotlin/JVM synthetic/default-argument
artifacts.

The initial rule set is deliberately small:

- remove duplicate simple data-class accessors emitted twice by JADX;
- replace calls to Java-invisible synthetic Kotlin `$default` bridges with the
  corresponding public overload and explicit default values;
- insert one helper when a default argument depends on the original operand.

Every rule has an expected match count. Unexpected counts fail closed. The
repair manifest records input/output SHA-256 and each applied transformation.

A successful compile after repair is **not** a semantic claim. The repaired
candidate must still execute against the same behavioral oracle. Raw recovery,
repair-assisted recovery, rebuildability, and behavioral equivalence remain
separate evidence.
