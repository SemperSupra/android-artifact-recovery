# AAR System Boundary

## Role

AAR is an originating project for recovering and validating useful source-level/semantic representations from Android artifacts and for characterizing Android execution environments.

AAR owns:
- artifact/code discovery semantics;
- recovery evidence and confidence;
- DEX/native/runtime correspondence;
- cross-version and cross-ABI lineage;
- golden workloads;
- Android/environment spelunking;
- rebuild and behavioral validation.

## Stable flow

```text
artifact
  -> immutable identity + provenance
  -> recursive code-bearing discovery
  -> multiple derived representations
  -> known-component identification/subtraction
  -> correspondence + lineage
  -> semantic recovery
  -> isolated execution when needed
  -> behavioral validation
  -> evidence/confidence
```

Runtime discovery may feed newly observed artifacts back into discovery until a bounded fixed point is reached.

## Shared systems

### Agent Dispatch

Agent Dispatch is an optional execution/qualification hub. AAR work may be classified into reusable task families such as:

- `aar.artifact.characterize`
- `aar.artifact.recover`
- `aar.environment.spelunk`
- `aar.lineage.compare`
- `aar.recovery.validate`
- `aar.golden.qualify`

Those names classify execution; they do not move AAR workset authority into Agent Dispatch.

### Model Artifact Foundry

AAR should reuse Foundry primitives for immutable identity, provenance, validation, OCI publication, and digest-pinned hydration when an artifact family is eligible.

Publicly available does not imply redistributable. Restricted or uncertain-rights bytes remain outside the public repository and public artifact plane; AAR may retain private content-addressed references and evidence.

## Deployment

Public build/qualification should favor public GitHub-hosted resources where sufficient. Private, large, restricted, or long-running work may use qualified self-hosted/local substrates. Placement must depend on required/measured capabilities rather than hard-coded provider identity.

## Minimality

Do not create a new scheduler, artifact registry, task database, model qualification system, or generalized software catalog inside AAR unless existing portfolio primitives demonstrably fail a required invariant.
