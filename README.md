# Android Artifact Recovery (AAR)

Public build, recovery, qualification, and deployment plane for **Android Artifact Recovery: DEX, Native, Spelunking & Golden Workloads**.

This repository contains the public-safe reusable implementation: artifact discovery, DEX/native/runtime recovery adapters, golden workloads, environment spelunkers, schemas, validators, and reproducible build/qualification workflows.

It is **not** the authoritative project workset, a mirror of arbitrary APKs, a private corpus store, or an Agent Dispatch task database.

## Authority boundary

- Project intent, experiments, private corpus references, findings, and promotion decisions live in `SemperSupra/android-artifact-recovery-private`.
- Reusable execution and qualification may use `SemperSupra/agent-dispatch`; Agent Dispatch does not own AAR work semantics.
- Eligible large immutable artifacts may use `SemperSupra/model-artifact-foundry`; restricted or redistribution-uncertain bytes must remain outside this public repository.
- Git stores code, schemas, small evidence, manifests, and public-safe golden sources—not downloaded APK corpora or large derived binaries.

> Bootstrap note: this initial commit exists only to initialize the empty repository. Substantive contracts and implementation should arrive through reviewed branches and pull requests.
