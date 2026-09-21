# Ghidra headless and Function ID qualification

Status: experimental qualification

This increment introduces Ghidra as an AAR evidence producer, not a canonical
artifact database.

## Pinned release

Qualification currently pins official Ghidra 12.1.4:

- release tag: `Ghidra_12.1.4_build`
- release asset: `ghidra_12.1.4_PUBLIC_20260921.zip`
- SHA-256: `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`
- runtime: JDK 21

The release archive hash is verified before execution.

## Headless evidence

AAR imports each native adversarial golden through `analyzeHeadless`, runs
ordinary auto-analysis, and records:

- language and compiler specification;
- discovered function counts;
- target function entry points and sizes;
- whether decompilation completed;
- a SHA-256 of decompiled C text for evidence/provenance.

Ghidra project files are disposable derived state.

## Function ID evidence

`AarFidHashes.java` calls Ghidra's `FidService.hashFunction` for analyzed
functions and records the full/specific Function ID hashes.

The first qualification deliberately measures a narrow claim:

- exact copy should match;
- stripped binary should match when function code is unchanged;
- a deliberately patched function should stop exact-matching while an unchanged
  sibling remains stable;
- an unrelated false friend exposing the same API names must not exact-match;
- an alternate optimization build is not required to match at this stage.

This is a qualification of FID's exact/function-hash correspondence primitive,
not yet a claim that a populated FID database can identify arbitrary OSS
libraries.

## Next boundary

If the hash primitive passes, the next FID increment may create a reference
database from source-known libraries and measure query behavior. Database
results must still enter AAR as normalized evidence and may not independently
promote uncertain correspondence to known implementation.
