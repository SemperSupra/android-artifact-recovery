# Component correspondence and residual recovery

Status: foundation

AAR does not reverse known implementation merely because the bytes are present,
and it does not ignore implementation merely because a tool guessed a library
name.

Component correspondence is an evidence layer between code-bearing discovery
and expensive recovery.

## Non-destructive model

The original artifact and every discovered code-bearing object's exact bytes and
hash remain authoritative.

"Subtraction" means only a **logical recovery disposition**. AAR never rewrites
the APK to remove known code.

A known component remains visible for:

- configuration and version evidence;
- imports/exports and call boundaries;
- JNI registration and callbacks;
- protocol/API use;
- application-specific glue;
- modifications and deltas;
- cross-version comparison.

## Independent dimensions

Every correspondence claim separates:

1. **identity**
   - `EXACT_BYTES`
   - `REPRODUCIBLE_EQUIVALENT`
   - `STRONG_CORRESPONDENCE`
   - `FAMILY_MATCH`
   - `UNKNOWN`

2. **coverage**
   - `WHOLE_OBJECT`
   - `CLASS_SET`
   - `METHOD_SET`
   - `FUNCTION_SET`
   - `BYTE_REGION`

3. **modification state**
   - `UNMODIFIED`
   - `MODIFIED_DERIVATIVE`
   - `BUILD_VARIANT`
   - `UNKNOWN`

4. **recovery disposition**
   - `REFERENCE_ONLY`
   - `BOUNDARY_ANALYSIS`
   - `DELTA_RECOVERY`
   - `RESIDUAL_RECOVERY`

These dimensions must not be collapsed into a single score.

## Reference provenance classes

Reference records carry an evidence-provenance class:

- `R0` — exact official release bytes;
- `R1` — official source/tag plus reproducible build evidence;
- `R2` — authoritative package-repository artifact;
- `R3` — independently verified upstream mirror;
- `R4` — community/reference database;
- `R5` — heuristic identification only.

This class describes the source of the correspondence reference, not software
quality or trustworthiness.

## Foundation matcher policy

The first matcher is deliberately conservative.

- Exact SHA-256 equality against a reference binary can establish
  `EXACT_BYTES` for the whole observed object.
- Metadata overlap such as SONAME, namespace, package coordinate, Build ID,
  version string, or license notice is retained as `FAMILY_MATCH`.
- Metadata overlap **never** promotes an object out of residual recovery.
- Strong/modified correspondence requires a later qualified structural or
  reproducible-build evidence producer.

This asymmetry is intentional: a false negative costs recovery effort; a false
positive can hide consequential application code.

## Boundary invariant

Even an exact known component requires boundary analysis.

The residual planner may mark its implementation `REFERENCE_ONLY`, but callers,
configuration, callbacks, imports/exports, and application-specific integration
remain in scope.

## Tool independence

Ghidra FID/BSim, DEX structural matchers, SBOM scanners, and future analyzers are
evidence producers. Their native project databases are disposable derived
artifacts.

The normalized correspondence record is the durable AAR evidence plane.

## Promotion rule

A new analyzer joins the permanent AAR stack only if qualification shows that it
reduces consequential UNKNOWNs or recovery cost without materially increasing
false attribution.
