# Kotlin golden end-to-end recovery qualification

This workflow composes the already qualified AAR primitives into one bounded
source-known recovery experiment.

The proving chain is:

1. build the source-known Kotlin APK;
2. pin its exact SHA-256;
3. recover low-level DEX and high-level JADX representations;
4. export a recovered Gradle project and measure rebuildability without repair;
5. execute the source-known behavioral oracle;
6. attempt the raw recovered Java behavior;
7. create the separately recorded repair-assisted representation;
8. execute and compare the repaired representation;
9. synthesize two evidence summaries: raw and repair-assisted.

The workflow intentionally preserves both outcomes. For the current pinned
golden/JADX combination the raw recovered Java remains non-compilable and is
therefore behavioral UNKNOWN, while the bounded repair-assisted representation
must match the declared behavioral vector.

This is a composition qualification, not evidence that arbitrary APKs are
recoverable. Artifact identity, representation provenance, rebuildability,
repair lineage, behavioral evidence, and UNKNOWNs remain separate.
