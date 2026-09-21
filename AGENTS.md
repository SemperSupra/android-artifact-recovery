# AAR Public Agent Contract

## Authority

This repository is the public reusable implementation and qualification plane for Android Artifact Recovery (AAR). It is not the authoritative project workset.

Before substantial work:
1. Read `README.md` and `CURRENT_TASK.md`.
2. Preserve the public/private boundary.
3. Prefer existing portfolio primitives before introducing new infrastructure.
4. Keep execution adapters replaceable; do not make Agent Dispatch, GitHub Actions, a specific decompiler, or a specific artifact registry part of stable AAR semantics.

## Core invariants

- Original bytes and exact hashes are ground truth; every representation is derived.
- Discover code-bearing artifacts recursively and by content/signature, not only conventional APK paths.
- DEX is one code representation, not the Android code model.
- Native ELF, ART artifacts, embedded runtimes, scripts, WASM, assets, and runtime-discovered code are first-class where present.
- A single decompiler is never authoritative.
- Facts, recovered structure, inference, generated source, and UNKNOWN must remain distinguishable.
- Compilation is not semantic validation.
- Behavioral evidence should validate consequential recovered semantics where practical.
- Static discovery cannot prove completeness when runtime loading/generation is possible.
- Names are evidence, not identity.
- Tool-specific databases/formats must not become the durable corpus schema.
- Untrusted artifacts execute only in appropriately isolated disposable environments.
- Do not commit arbitrary downloaded APK corpora, restricted bytes, secrets, or private workset information.

## Shared infrastructure

- Agent Dispatch may execute/qualify bounded work; AAR retains workset authority.
- Model Artifact Foundry may provide immutable artifact identity/hydration when eligibility and rights allow.
- Public workflows must remain independently understandable and must not require credentials capable of reading the private AAR repository.
