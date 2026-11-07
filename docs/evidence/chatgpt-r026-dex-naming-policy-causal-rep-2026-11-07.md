# R026 — Controlled JADX renaming experiment on two original ChatGPT Android DEX shards

**Date:** 2026-11-07. **Authority:** existing [AAR public draft PR #37](https://github.com/SemperSupra/android-artifact-recovery/pull/37), [private owner #79](https://github.com/SemperSupra/android-artifact-recovery-private/issues/79), [shared reversing #4](https://github.com/mark-e-deyoung/ghidra-tools/issues/4). **Status:** `STATIC_NAME_PATH_CORRESPONDENCE_CAUSE_QUALIFIED`; `STRUCTURED_METHOD_RECOVERY_NOT_VERIFIED`; `ORIGINAL_ART_RUNTIME_NOT_RUN`.

## Original-source and tool identity controlled

| Invariant | R025 original control | R026 isolated variable |
|---|---|---|
| Signed donor provenance | APKPure signer-verified, not Play-delivered | Identical APKPure archive |
| Original APK SHA256 | `b05ceacd37481c95ef74a836394b1db9b69e19d360bbb119645ef949d44abb36` | Identical |
| `classes3.dex` SHA256 | `c15a7183282c41801daa7c9cc167e8c228d9da7fac801cbdd3a5fbfc2649df34` | Identical |
| `classes7.dex` SHA256 | `9d813a15599f980e4c39203f7079ac1c40879ffe694ae6dc30e2c1c60bbb8c7b` | Identical |
| Pinned JADX | `v1.5.6`, `--decompilation-mode fallback`, 1 thread, 4 GiB JVM, 150sec per shard | Identical |
| Only experimental variable | Default JADX identifier rename policy | Explicit `--rename-flags none` |
| Qualified original GHA | [R025 #42330186965](https://github.com/SemperSupra/android-artifact-recovery/actions/runs/42330186965), SHA `6e3d91372b0c41737c90e8f16a46c6ba5c011b6b` | [R026 #42330637908](https://github.com/SemperSupra/android-artifact-recovery/actions/runs/42330637908), SHA `45b5066bca8f5bb7b72414c3f8d5ff49336c62ea` |
| ZIP SHA256, all members CRC verified | `8abff6b989d20ba16ebf3385f3d57cb080f86cd7e018b8caeaea86eb107defc4` | `efbf25451bfe1cf7b7f24eb59866f829eeb5ae19119a79a2cb1a624276c4604e` |
| Durable derived-only custody | [R025 Drive](https://drive.google.com/file/d/17ygRgkzWBIgnZTWyLE1gNEChL_W0NFZJ/view) | [R026 Drive](https://drive.google.com/file/d/1AUNXuPVoXGotms83mFRggJkJ4NTFq75P/view) |

AOSP's [DEX file-format specification](https://source.android.com/docs/core/runtime/dex-format) independently grounds the class_def→type_id→string_id→string_data descriptor traversal. Source-owned parser keeps original names and file paths only in ephemeral runner memory and emits classified aggregate counters, never original class/Java files or names. JADX's [v1.5.6 CLI documentation](https://github.com/skylot/jadx/blob/v1.5.6/README.md) explicitly documents `--rename-flags none`. Both independent fallback shard processes exited zero, with 0 heap OOM, 0 timeout, and 19,636 output .java files. That is still **raw-instruction rendering**, not recompilable Java validation.

## Measured behavior of the filename sensor

| Category among original 21,951 DEX class definitions | R025 default renamed | R026 `--rename-flags none` | Change |
|---|---:|---:|---:|
| Top-level exact descriptor↔generated-file matches | 2,506 | 19,155 | **+16,649** |
| Top-level descriptor without exact matching filename | 18,070 | 1,421 | **−16,649** |
| Dollar-named class has own exact file | 481 | 481 | 0 |
| Dollar-named class has parent file only | 828 | 829 | +1 |
| Dollar-named class has neither | 66 | 65 | −1 |
| Invalid/non-ASCII unsupported descriptors | 0 | 0 | 0 |
| **Total independently accounted class definitions** | **21,951** | **21,951** | **0** |

Original source and generated file counts were held fixed. Therefore most earlier "unmatched" top-level names were an **instrumentation alias mismatch** driven by JADX's default renaming. This is a same-donor, same-resource, one-variable causal test of the **sensor-to-file path contract**, not a claim that 16,649 extra class implementations were recovered. It establishes that default renaming is inappropriate when we use literal DEX descriptor↔filename correspondence as an observer.

Residual R026 **1,421 top-level nonmatches** and **65 dollar-named neither** remain `UNEXPLAINED_NAME_PATH_NONCORRESPONDENCE`, not "missing classes". Candidate confounders include class folding, invalid/obfuscated source names, changed filename layout, and omitted/partial raw-instruction emission. Actual method code recovery, control-flow equivalence, compile validity, runtime IPC/state/CRUD and Play-delivered ARM64 remain NOT_VERIFIED.

## CI, housekeeping and next implementation constraints

- Source-owned synthetic [R026 GHA #42330637900](https://github.com/SemperSupra/android-artifact-recovery/actions/runs/42330637900) **SUCCESS** and native [#42330637908](https://github.com/SemperSupra/android-artifact-recovery/actions/runs/42330637908) **SUCCESS**, all original and cleanup jobs. A preliminary red run #42330538185 was due to a test looking for a synthetic invocation file under the wrong `fallback/` directory instead of actual `outputs/`; fixed with fixture assertions and explicit `fallback_renaming_policy=none` receipt field at `45b5066bca8f5bb7b72414c3f8d5ff49336c62ea`.
- Keep renaming policy explicit in every future source-to-DEX comparison. Do not compare a renamed baseline to an unrenamed derived-output path census as though they measure recovered code.
- Next independent rep should target **remaining 1,421 top-level descriptor path disagreements** using reviewed, non-executing filename layout/alias mapping hypotheses. Only later consider `--no-move-inner-classes` as a distinct variable for the 829 parent-only dollar-named classes. Use source-only negative controls and a bounded, trusted original-APK runner; no path/string publication.
- Maintain **draft #37** and existing durable owner issues; no new PRs, branches, private/paid runners, unreviewed merges or releases.

**Claim boundary:** `R026_SAME_DONOR_NAME_CORRESPONDENCE_IMPROVED`; this is not `FULL_CODE_RECOVERY`, `FEATURE_PARITY`, `ORIGINAL_APP_RUNTIME`, or `PERMISSIONED_CRUD`.
