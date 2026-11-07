# R024 — targeted JADX fallback on the actual signed Android donor (2026-11-07)

## Authority and custody

- Workcell: existing [public AAR draft PR #37](https://github.com/SemperSupra/android-artifact-recovery/pull/37). Original fallback rep [GHA #42328879746](https://github.com/SemperSupra/android-artifact-recovery/actions/runs/42328879746) source commit `fbaf4a68eaea874e667f152e78e8945ceeab7303`: all jobs/steps PASS, including source-owned adversarial controls, APK source selection/signing, two bounded native JVM processes, derived-only publication and ephemeral runner cleanup.
- Original source archive: signed APKPure `com.openai.chatgpt` SHA256 `b05ceacd37481c95ef74a836394b1db9b69e19d360bbb119645ef949d44abb36`. This is **not** Google Play delivery; requested ARM64 ELF is still **not** verified (12 observed ARM32 ELF). No ART/runtime/GUI/CRUD/IPC execution occurred.
- Derived-only GHA artifact ID `13556770898`; downloaded, every ZIP CRC checked. Artifact ZIP SHA256 `3d8f0f17fac0041836f7bc4d504dfd7629d88e56deafd3a012ffa90f87876ba0`. Persisted under the established private Drive folder: [R024 targeted fallback receipt](https://drive.google.com/file/d/1LrRLpE_VfwnOZW8IzNtpZUhPgrvOEDx6/view).
- Source-only native GHA [#42328879699](https://github.com/SemperSupra/android-artifact-recovery/actions/runs/42328879699) PASS. No source/class files, DEX payloads, raw JADX logs, credentials, account/session data or original APK bytes are in the public Git evidence record.

## Actual independently observed per-DEX results

JADX `1.5.6` pinned digest `545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974`, `--decompilation-mode fallback`, one thread, per-shard JVM `-Xmx4g`, 150s timeout, 2 selected DEXs out of the signed package's nine.

| Root DEX | Structural class_defs | Structural method_ids | R023 structured Java files | R023 original error | R024 fallback-rendered .java files | R024 process outcome |
|---|---:|---:|---:|---|---:|---|
| `classes3.dex` | 9,807 | 65,536 | 7,415 | 120s timeout | 8,648 | Exit 0; no OOM/timeout |
| `classes7.dex` | 12,144 | 57,237 | 4,600 | Java heap OOM | 10,988 | Exit 0; no OOM/timeout |
| **Selected-only** | **21,951** | **122,773** | **12,015** | 2 unresolved | **19,636** | Both exits zero |

**Do not combine or ratio the Java file counts from structured and fallback modes as equivalent class coverage.** Fallback rendering emits raw instruction-oriented .java files; it is a distinct evidence grade, `FALLBACK_RAW_INSTRUCTION_RENDERING`, not independently verified structured source. Both per-shard log `reported_error_count` values are `null`, **not zero**. Process exit zero does not prove correctness/exhaustive recovery.

**Post-readback erratum:** the *original R024 JSON* correctly reports selected `total_dex_class_defs=21951` but `total_dex_method_ids=484770` denotes the **entire nine-DEX archive**, not the two selected shards. The correct selected method-ID sum is **122,773**, calculated from the individually recorded `method_ids_header_count` values 65,536 and 57,237. The original whole-package count is still 484,770. This issue was **corrected in source** at `07810fef8d6ad30b67dd0f8039bc0dae34aa1793` with a new separate `all_original_dex_method_ids` field and source-owned negative synthetic controls. Historical artifact must remain immutable; use this erratum, never silently substitute its original value. [Source-only run #42329183670](https://github.com/SemperSupra/android-artifact-recovery/actions/runs/42329183670) PASS; exact-head original repeat [#42329183627](https://github.com/SemperSupra/android-artifact-recovery/actions/runs/42329183627) was queued at document inception, final admission/receipt readback pending.

## Next critical-path experiments, negative controls and repository hygiene

1. Retain R023 nine-shard structured mode and R024 two-shard fallback as **separate** original donor evidence grades; never let source-count comparisons promote protocol/runtime claims.
2. Qualify R024 exact-head method-ID correction from the new native receipt; ensure no uncontrolled full nine-shard repeat (only two bounded fallback processes).
3. For the remaining structured exit3 shards `classes.dex`, `classes2.dex`, `classes4.dex`, `classes5.dex`, `classes6.dex`, `classes8.dex`, develop class-level residuals with held-out DEX code and `--single-class`/`--no-inline-methods`/fallback **only after** independent class/method evidence oracle, not blind class-file ratios.
4. Preserve signing/provenance and architecture holds (APKPure, ARM32, no current Play ARM64, no original app ART/GUI/process/CRUD). No explicit user creds or private conversation uploads.
5. Retain existing PR #37 DRAFT; avoid redundant PRs, branches or paid/private runners. Do not close owner DLE while critical acceptance holds remain.

DLE owner: [Android recovery private #79](https://github.com/SemperSupra/android-artifact-recovery-private/issues/79). Shared portfolio authority: [ghidra-tools #4](https://github.com/mark-e-deyoung/ghidra-tools/issues/4). **Status:** `TWO_FALLBACK_SHARDS_EXIT_ZERO`, `STRUCTURED_SOURCE_AND_RUNTIME_NOT_QUALIFIED`, `NO_MERGE_OR_RELEASE`.
