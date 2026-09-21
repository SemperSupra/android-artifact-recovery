# Ghidra headless qualification

Ghidra is introduced as a derived-evidence producer, not as AAR canonical state.

The first qualification boundary covers:

- pinned official Ghidra release bytes;
- Java runtime requirement;
- headless import and default analysis;
- bounded function inventory;
- bounded decompilation;
- normalized deterministic evidence emitted outside the Ghidra project;
- deletion of the temporary Ghidra project after analysis.

The AAR adapter records the analyzed binary SHA-256 and hashes decompiled C text
for each emitted function. Raw Ghidra projects are disposable.

This increment intentionally does **not** qualify FID or BSim. Those are later
evidence producers tested against the adversarial attribution goldens.

A successful Ghidra decompilation is not a component-identity claim.
