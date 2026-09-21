# Behavioral validation of recovered representations

Status: MVP

AAR behavioral validation executes a source-known oracle and an independently
recovered representation against the same input and compares consequential
observable results.

For the Kotlin/DEX golden, the first comparison vector covers canonical UTF-8
record bytes, SHA-256 fingerprint, record count, and unique-key count.

The original observation is produced by executing the compiled source-known
Kotlin class. The candidate observation is produced by compiling and executing
only JADX-recovered sources from the AAR-owned package against independently
supplied Kotlin runtime dependencies.

This is separate from the JADX Gradle-export rebuild experiment. A recovered
representation may be behaviorally executable in isolation even when the
exported Android project is not rebuildable as-is.

Outcomes are BEHAVIOR-MATCH, BEHAVIOR-MISMATCH, or UNKNOWN. A compile or
execution failure is evidence and is not silently repaired into a match.
