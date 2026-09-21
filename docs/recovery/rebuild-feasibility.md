# Rebuild feasibility probe

Status: experimental MVP

AAR distinguishes "can a decompiler export something that builds?" from "was
the original semantic behavior recovered correctly?"

This increment measures only the first question.

For a source-known APK, JADX exports an Android Gradle project. AAR then attempts
to build the export **without repair** and records:

- exact rebuild command;
- exit status and timeout state;
- stdout/stderr;
- elapsed time;
- any APK outputs and their hashes;
- whether repair was applied.

Possible result labels are:

- `REBUILDABLE-AS-EXPORTED`
- `NOT-REBUILDABLE-AS-EXPORTED`

A successful rebuild is useful evidence but is not semantic validation. A failed
rebuild is also useful evidence and must not be silently patched into a pass.
Any later repair-assisted rebuild is a distinct representation and must record
the applied transformations.
