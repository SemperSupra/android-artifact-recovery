# Explicit Maven candidate materialization

Status: bounded acquisition primitive

`tools/materialize_maven_candidates.py` materializes only exact Maven
coordinates supplied by an upstream authority. It exists to bridge a small,
accepted release-candidate set into the existing DEX class-set/FID pipeline.

It deliberately does **not**:

- search Maven repositories;
- choose a component family;
- choose or infer a version;
- resolve transitive dependencies;
- establish component or version identity;
- turn an observed digest into reference truth.

A request uses `aar-maven-candidate-request/v0` and supplies an HTTPS repository,
group, artifact, exact version, and optional JAR/AAR packaging/classifier.
`expected_sha256` is optional. Without it, the materialized digest is recorded
as `observed_unpinned` and must not be treated as authoritative reference
identity. With it, mismatch fails closed.

The intended pipeline is:

```
private/public-safe candidate authority
    -> exact coordinate request
    -> explicit candidate materialization
    -> bounded DEX class-set score
    -> selected source-known candidate(s)
    -> DEX FID
    -> private target correspondence / residual interpretation
```

This tool is appropriate for public Actions only when the coordinate request is
itself explicitly public-safe. It does not declassify target-derived findings.
