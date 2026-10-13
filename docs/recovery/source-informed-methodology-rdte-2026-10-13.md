# Source-informed recovery RDT&E: tranche 1 (2026-10-13)

Authority: AAR-private #82; public-safe execution tracker: AAR-public #38.
Status: **candidate methodology**, not an accepted performance improvement.

## Purpose and non-goals

Use readable source of forward compiler/optimizer and recovery tools to find
information-preserving evidence and measure better recovery **on the same cases**.
Existing AAR and CDR evidence models remain authoritative. This is NOT another
scheduler, source mirror, decompiler, vulnerability scanner or generic framework.
Do not assume that a source-available tool is installed, fully buildable, fit for
commercial use, or qualified for a target merely because a repository is public.

## Source census (read-only source availability, not build qualifications)

The following heads were observed through GitHub on 2026-10-13; exact SHA pins
are for subsequent source reading, not version/release compatibility claims:

| Family | Source repository | Observed head | Role / caveat |
| --- | --- | --- | --- |
| JADX | https://github.com/skylot/jadx | `0e2575e2eebea36060fa86adb99475abed6e8c8e` | Apache-2.0; inspect plugin/pass API first; existing AAR golden uses release v1.5.6, not necessarily this head |
| ReDex | https://github.com/facebook/redex | `fcb9ec4a978b78a24541168aeaeb8ab07b18cdde` | MIT; alternate DEX pass ordering/optimization |
| Androguard | https://github.com/androguard/androguard | `3ea3da38e74b4d74579463d0688ab513786c4750` | Apache-2.0; alternative DEX/CFG producer |
| Ghidra | https://github.com/NationalSecurityAgency/ghidra | `73a102ba2730bf20d0b8cbdc131ef12928e2690a` | Apache-2.0; source-known FID/BSim/native comparisons; AAR has separate pinned Ghidra 12.1.4 |
| Kotlin | https://github.com/JetBrains/kotlin | `bdab7487af122deb00588be7c6582425eb33e344` | Source available; investigate IR/lowering; license verification required per relevant subtree |
| smali/dexlib2 | https://github.com/JesusFreke/smali | `2771eae0a11f07bd892732232e6ee4e32437230d` | Historical source; archived; qualify maintenance and license before admission |
| D8/R8 | https://r8.googlesource.com/r8 | `b0d966bc2d7270f4e2e81634fc98eee9ecb65cad` | Official Gitiles main commit observed 2026-10-13 (Oct 9 commit date); detailed compiler-pass audit still pending |
| Android ART | https://android.googlesource.com/platform/art | **PIN_PENDING** | Runtime and DEX semantics; not all proprietary vendor components are present |
| Android LLVM toolchain | https://android.googlesource.com/toolchain/llvm_android | **PIN_PENDING** | Native reference-build transformations; compiler/flag differences require measurement |

Unknown license or exact-source revision means inspect first, not approve binary redistribution.
The current AAR baseline remains at its own pinned commits/workflows regardless of these moving upstream heads.
The source census is a discovery input, not a versioned software bill of materials.

## Distinct execution lanes

**PUBLIC_SAFE_DETERMINISTIC**: official upstream source reading, public papers,
compiler/source-known golden builds, pure synthetic tests, public comparison and
sanitized tool instrumentation on public Actions. Use contents:read only,
bounded timeout, small job count, no repository secrets and no private GHA minutes.

**PRIVATE_ENGINEERING / PRIVATE_ARTIFACT_COMPUTE**: target-specific hypotheses
or proprietary/rights-uncertain APK/DEX/ELF, private correspondence, unpublished
findings and real campaign bytes. Only an admitted trusted private executor,
never a public Actions runner with a private credential. Existing CDR campaign
owns questions and oracle interpretation. Sealed-public input mode is not
available until its separate live trusted-side qualification passes.

**SENSITIVE_AUTH_DEVICE**: credentials, authenticated Google Play sessions,
real hardware/device mutation, account/personal data. Out of scope in this
tranche and cannot silently fall back to a public cloud worker.

## Dependency DAG

Parallel readiness after source census:
- S1: inspect JADX pass and plugin extension points (only public source).
- S2: inspect D8/R8/ReDex transformations and their possible irreversible effects.
- S3: build/measure the existing source-known Kotlin/JNI baseline unchanged.
- S4: original-language prior art and independent-lineage deduplication.
- S5: inspect Ghidra/DEX IR/Androguard source evidence for cross-representation questions.

Sequential:
- S1/S2/S3 -> freeze reproducible source/transform fixtures -> compare identical
  artifact/version/test vectors under alternate recovery ordering.
- S3 plus paired candidate evidence -> independent scorer -> adversarial
  held-out validation -> AAR method-promotion review.
- Any blind campaign recovery -> immutable provider seal -> evaluator-only oracle
  comparison by CDR. Private runtime proof required before private target execution.
- Shared schema changes and production adoption are serialized.

## First instrument: paired evidence comparator

`tools/qualify_method_comparison.py` consumes source-known oracle JSON and
two **already produced, sealed** observation JSON documents. It enforces identical
SHA-256 artifact identity, declared questions, explicit UNKNOWN, and independent
per-question accuracy accounting; it never infers correctness from a decompiler's
self-reported confidence or code length. Candidate evidence is merely a **signal**,
not qualified improvement. Self-reported time is marked as such.

For source-known public fixtures, the oracle may be public at scoring time; in a
blind pilot it must be withheld from the recovery actors until their outputs are
sealed. This program deliberately does not run a decompiler or accept a private APK.

Fixture example (synthetic; not an observed Android recovery):

```json
{"schema":"aar-method-oracle/v0","artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","questions":{"q1":{"expected":"A","consequential":true}}}
```

Inputs:
- baseline and candidate: `{"schema":"aar-method-observations/v0","artifact_sha256":"<same-64-hex>","method_id":"baseline-or-candidate","elapsed_ms":100,"observations":{"q1":{"state":"OBSERVED","value":"A"}}}`
- `UNKNOWN` is permitted only without a value; absent questions are UNKNOWN.
- stdout/result `CANDIDATE_QUALITY_SIGNAL` / `CANDIDATE_COST_SIGNAL` never
  implies acceptance. All candidates require independent replication and holdouts.

## Next real experiment

E1: run the already-qualified source-known Kotlin APK baseline at its pinned
AAR public workflow revision; preserve original vector/DEX and unmodified JADX
outcomes. On a separate pinned candidate branch build controlled D8/R8
transformation variants and measure whether a selected source-informed recovery
step changes independently observed behavior. Keep optimization/debug/source
mapping as factors, never provide the mapping file to a blind recovering actor.
Record zero-progress and contradictory results. Do not claim superiority from
the comparator's unit tests.

E2 and E3 may reuse S3 baseline but must not mutate it: independently compare
DEX-IR/high-level representations and reference-first/decompile-first ordering.
No broad decompiler fan-out until an actual residual gap establishes need.

## Completion and stop conditions

Public qualification job must PASS on its actual GHA run. Source-pin/license
gaps remain UNKNOWN. Do not merge this tranche until independent review.
Do not promote a method for structural similarity, decompiled line count,
self-reported timing, raw recovery compilation, or synthetic-scorer PASS alone.
Stop and record BLOCK if rights, actor admission, tool source pin, or independent
behavioral validation cannot be proven.

Success: measured increase in validated consequential behavior or lower
independently measured cost for **the same validated behaviors** without
new false attributions, repeatable on disjoint holdout workloads.

## First live public synthetic calibration

- Public Actions run [#38404154793](https://github.com/SemperSupra/android-artifact-recovery/actions/runs/38404154793) PASS with exact downloaded JADX v1.5.6 archive SHA-256 `545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974` and preinstalled Android D8.
- Source-known public Java BranchAndFold fixture processed as D8 debug and release, separate exact DEX artifact SHA per mode; raw JADX `auto` and `restructure` recompilation and behavioral oracle both MATCH for both DEX variants.
- A preliminary `CANDIDATE_COST_SIGNAL` is confounded because modes executed in fixed order; it is **not** a cost finding or improvement. A later ABBA crossover rerun deliberately tests this risk.
- D8 debug/release changes debug information/DEX output; it is not an R8 optimization/inlining/shrinking qualification. Follow-on E1 must separately instrument R8 source-level optimization on synthetics.
- Gitiles evidence: https://r8.googlesource.com/r8/+/b0d966bc2d7270f4e2e81634fc98eee9ecb65cad . This source head and GitHub tool heads do **not** imply identical versions to AAR's current packaged toolchain.
