# Android arm64 source-reference builds

Status: qualification

Smart Life's bounded hint pass identified concrete upstream version candidates:

- OpenSSL 1.1.1w;
- OpenSSL 3.5.4;
- FFmpeg 4.4.2;
- Opus 1.1.3.

AAR does not assume those upstream releases are byte-identical to the embedded
application code. Instead it builds **source-known Android arm64 reference
variants** from the official upstream tagged commits.

These builds exist to feed the already-qualified FID/BSim correspondence layer.

## Provenance

Pinned official source tags/commits:

- OpenSSL 1.1.1w:
  `openssl/openssl@e04bd3433fd84e1861bf258ea37928d9845e6a86`
  (`OpenSSL_1_1_1w`);
- OpenSSL 3.5.4:
  `openssl/openssl@c1eeb9406b6142148f267594197d853403d10208`
  (`openssl-3.5.4`);
- FFmpeg 4.4.2:
  `FFmpeg/FFmpeg@d61977cbe453869cec28d32b71fe25c2cd965dcf`
  (`n4.4.2`);
- Opus 1.1.3:
  `xiph/opus@aa32042a50f2cbe0ff9d339948cb4712f5cc3d6e`
  (`v1.1.3`).

The first build matrix uses Android NDK 27.0.12077973, arm64, API 21. This is a
controlled reference build variant, not a claim about the compiler/NDK/options
used by the application vendor.

## Evidence semantics

A successful reference build may provide:

- exact hashes for the generated reference binaries;
- ELF architecture/build metadata;
- a source commit/tag identity;
- inputs for FID database generation;
- inputs for BSim build-variant comparison.

It does not establish:

- byte identity with the application artifact;
- a reproducible upstream release binary;
- the vendor's compiler or flags;
- absence of vendor patches;
- component identity from a similarity result alone.

The build scripts are intentionally small and deterministic enough to rerun
with alternate NDK/API/optimization combinations if real evidence justifies a
broader build-variant matrix.
