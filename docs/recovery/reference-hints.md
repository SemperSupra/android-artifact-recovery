# Reference/version hint extraction

Status: qualified candidate-evidence stage

AAR now has exact-hash, FID, and BSim correspondence primitives, but those
primitives need authoritative candidate references. The reference-hint stage
narrows that search without converting metadata into identity claims.

It inspects bounded APK/ZIP entries for:

- Maven `pom.properties` / simple POM coordinates and versions;
- retained `META-INF/*.version` module/version records, with strict version-value validation;
- embedded `package.json` package/version metadata;
- JavaScript/source-map paths containing `node_modules/<package>`;
- selected native version banners such as OpenSSL/FFmpeg/Opus/SQLite/protobuf;
- selected source/project URLs embedded in native binaries.

Every result is a **candidate hint**.

The stage never emits `EXACT_BYTES`, `STRONG_CORRESPONDENCE`, or a residual
suppression decision. Its job is to tell the on-demand reference resolver which
upstream artifacts are worth acquiring and testing.

Version-looking strings from generic metadata are especially weak evidence and
must remain independently verified. Retained `.version` records are stronger
package-supplied metadata, but still remain candidate reference evidence rather
than component identity. Malformed `.version` values are preserved explicitly
as `REJECTED` evidence and never converted into Maven coordinates.

The extractor is bounded by per-entry size and records `SKIPPED_BOUND`
explicitly rather than silently omitting material.
