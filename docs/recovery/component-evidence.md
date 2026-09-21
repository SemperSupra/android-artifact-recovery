# Cheap component evidence and on-demand references

The component correspondence layer begins with cheap evidence before any
structural similarity or decompilation.

## Observation extraction

`tools/extract_component_evidence.py` records:

DEX:
- exact object SHA-256;
- DEX version;
- class-definition count;
- namespaces derived directly from class descriptors.

ELF:
- exact object SHA-256;
- class/machine basics;
- SONAME;
- Build ID;
- DT_NEEDED;
- dynamic-symbol inventory;
- compiler/comment strings when available;
- ABI path evidence.

JavaScript:
- exact object SHA-256;
- a deliberately small set of runtime/bundler markers;
- bounded license/copyright notice evidence.

The extractor does not identify a component. It produces observations for a
separate correspondence step.

## On-demand reference resolver

`tools/resolve_reference_catalog.py` fetches only explicitly requested
reference artifacts.

Every fetched object requires an expected SHA-256 in advance. A mutable URL can
therefore never silently become reference truth.

The reference request records:
- component/version identity;
- provenance class;
- authoritative source reference;
- explicit artifact URL;
- expected artifact hash;
- code kind and optional ABI/name.

The resulting cache is content-addressed by expected hash and the catalog can be
fed to the conservative component-correspondence matcher.

Provider-specific helpers for Maven/AOSP/other ecosystems may later generate
these explicit requests, but the resolver itself remains provider-neutral.
