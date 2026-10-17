# Sovereign AAR — free-cloud transfer and external-tool qualification
Date: 2026-10-17. Scope: public-safe local recovery readiness only.
Authority: AAR-private #82; AAR-public #38/PR #39; Agent Dispatch-private #104. CDR owns target campaigns.

## Avoid a new control plane

Reuse the AAR characterization, low-level static representations, source-known Kotlin/DEX and JNI/ELF goldens, Ghidra FID/BSim, component correspondence, reference-first experiments, rebuild probes, raw/repair-assisted behavioral comparison and evidence synthesis. Agent Dispatch owns configured actor/model qualification and optional capacity. This adapter only adds source admission, non-clobbering resume and evidence receipt verification.

## Confidence / transfer levels

| Level | What to prove | What it does NOT prove |
| --- | --- | --- |
| Q0 public synthetic | archive hashes, bounded ZIP CRC/path/size safeguards, case resume, script and CLI portability | recovered semantics or actor performance |
| Q1 public authored APK | SDK/JADX/DEX/native build and artifact flow, with independent source-known oracle | private APK behavior, original proprietary sources |
| Q2 actor plus deterministic mock API | exact actor executable and configuration can call OpenAI-compatible endpoint, request tools and produce bounded receipt | meaningful model inference |
| Q3 actor plus public licensed model | configured actor on actual small open-weight model, held-out tasks, costs, independent validator | quality of distinct BigMac/TrueNAS models |
| Q4 sovereign local acceptance | exact Windows actor wrapper, BigMac M2 Ultra/TrueNAS models, local SDK, private corpus and hardware HIL | live service authorization |

Retain actual CLI executable SHA, model/checkpoint/config revision, provider transport, context and generation parameters and resource use. Small-task qualifications cannot be promoted to full APK reconstruction by extrapolation. Public hosted jobs must never connect to or expose private LAN model endpoints, copy restricted APKs or call authenticated consumer services.

## Existing free venue options

- Standard public GitHub-hosted runners: primary automated synthetic source and Android tool qualification. Keep timeout, least-privilege read-only checkout and no private minutes.
- Standard public macOS runners: optional portable actor/platform smoke. Reconcile Agent Dispatch-private #285; do not equate hosted GPU or CPU to local Apple M2 Ultra.
- Android emulator/ART: reuse the existing Agent Dispatch public AVD source-known acceptance path rather than rebuild the emulator harness.
- Public free model-serving tiers: optional Q3 only when actual available quota, acceptable license and measured throughput are established; never assume gratis persistent 30B/120B inference.
- Existing GARM/TrueNAS trusted lane: Agent Dispatch-private #640/#266 governs private local execution. Reuse once admitted, no implied grant or runner deployment.

## External tools — each must earn its keep

| Tier | Tool(s) | Bounded purpose | Evidence needed |
| --- | --- | --- | --- |
| Core | OpenJDK 17, Android SDK build-tools (aapt2, apksigner, dexdump, d8), Android Gradle Plugin/Gradle | canonical package/manifest/dex/build and signing inventory | actual executable SHA, known-source build and output parity |
| Core | JADX 1.5.6 | high-level source-like view, independent low-level correspondence | exact release ZIP SHA256 545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974 and source-known tests |
| Core-on-demand | Apktool 3.0.3, Google Smali 3.0.7 candidate | binary XML/resources and smali roundtrip | pinned asset digest and falsifiable golden output |
| Native code | LLVM readelf/objdump, Ghidra 12.1.4 with AAR FID/BSim | ELF control flow, cross ABI, JNI + library correspondence | isolate headless execution; false-friend/negative attribution tests |
| Diagnostics | released Androguard 4.1.4, APKiD | independent DEX/packer and obfuscator classification | exact tool version, rule false-positive controls; APKiD dual-license review |
| Packaging | Google bundletool, SDK apkanalyzer | true AAB/APKS and split variant topology where available | installed splits never asserted to reconstruct publisher AAB |
| Android HIL | adb, emulator, logcat, Perfetto, UIAutomator | stateful observed behavior on synthetic fixture | emulator/device build and independent test vectors |
| Conditional HIL | Frida and mitmproxy | strictly authorized native/transport observation | separate private-device/account/rights gates; no control bypass |
| Research only | FlowDroid, LibScout, Quark, MobSF, R8/ReDex source/plugin passes | only if actual unresolved component question requires them | improvement versus already qualified AAR methods at same budget |

Do not install all tools by default. Use existing PR #39's paired comparator to test candidates against the same source-known goldens, a held-out negative set, exact hashes and time/memory budgets. A decompiler output count, name similarity or inferred library source is not independent semantic correctness.

## First integration path and limitations

The public local case adapter provides a source SHA-addressed immutable case, ZIP integrity and resource limits, an unmodified existing AAR characterizer, atomic output+receipt and explicit UNKNOWN status. Test it on synthetic APK and XAPK split fixtures; then independently built Kotlin DEX fixture. No claim of full recovery until source+bytecode+runtime oracle tests pass, and no promotion of non-applicable deployment or CDR rights. Cloud test receipt is NOT local actor or private target qualification.

Next increment: measured source-known JNI/ELF coverage, exact toolchain parity, selected actor Q2 mock API calls, then Q3 open model on public synthetic tasks. Reconcile existing Agent Dispatch-private #104 before introducing a standalone actor driver or duplicate scorer. Keep the Q4 sovereign local gate open.
