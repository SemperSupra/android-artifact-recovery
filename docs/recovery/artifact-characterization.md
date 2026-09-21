# Android artifact characterization

This stage is deliberately lighter than decompilation. It inventories
code-bearing material while preserving exact artifact identity and explicit
bounds.

Supported inputs:

- single APK;
- XAPK/APKS/ZIP containers containing APKs;
- directories containing APK split sets.

The current discovery pass recognizes:

- DEX by magic, including version;
- ELF by magic, including class/endianness/machine and path-derived ABI;
- WebAssembly by magic;
- script-like assets by extension;
- nested archive candidates such as JAR/ZIP/APK/AAR.

The tool does not claim that filename extensions are authoritative. Magic wins
for DEX/ELF/WASM and ZIP-like archives. Extensions remain hints for script
languages.

Safety/scale invariants:

- no unbounded archive-tree extraction;
- embedded APK expansion is bounded;
- large entry hashing is bounded;
- skipped material is explicit `SKIPPED_BOUND`, never silently absent;
- characterization is not decompilation and does not imply semantic recovery.

The output schema is `aar-artifact-characterization/v0`.
