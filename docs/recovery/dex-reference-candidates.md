# DEX class-set reference candidate scoring

Status: candidate-narrowing primitive

AAR sometimes has strong package-family evidence but no retained Maven/component
version metadata. Building structural FID references for every historical release
would be wasteful and can encourage false attribution.

`tools/score_dex_reference_candidates.py` provides a cheap pre-FID filter.

It compares class descriptors from a target DEX/APK against class paths exposed by
a bounded set of candidate JAR/AAR/APK/ZIP artifacts. The output records exact class
overlap and simple-name overlap separately.

This primitive **does not** establish:

- component identity;
- component version;
- unmodified implementation;
- semantic equivalence;
- permission to suppress residual code.

Simple-name overlap is family evidence only and is deliberately preserved separately
because shaded or unrelated same-name classes are common. A candidate that survives
this cheap filter still requires DEX FID or stronger structural evidence before
attribution.

The intended pipeline is:

```
observed namespace/family
    -> small provenance-justified release candidate set
    -> class-set candidate score
    -> selected source-known candidate(s)
    -> DEX FID
    -> residual/delta interpretation
```

The tool accepts repeated `--candidate LABEL=PATH` arguments so acquisition policy
remains outside the scorer. It does not crawl Maven repositories or select releases
on its own.
