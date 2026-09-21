# Static APK recovery representations

Status: MVP

The static recovery stage consumes an APK whose exact bytes/hash are already
known and emits multiple derived representations. Android split delivery means
an individual APK is not required to contain DEX: native/config splits may be
valid recovery units containing ELF code but no root classes*.dex.

## Current representations

DEX:

- low level: Android build-tools `dexdump -d`;
- high level: JADX source-like decompilation.

Native ELF, when present:

- ELF headers/sections/symbol table via `llvm-readelf`;
- instruction-level disassembly via `llvm-objdump`.

The native branch intentionally does not claim high-level C/C++ recovery yet.
That requires a separately qualified native decompiler and remains a distinct
increment.

## Invariants

- APK bytes and SHA-256 remain ground truth.
- Extracted DEX/ELF inputs are content-addressed in the recovery manifest.
- Tool versions, argv, return code, stderr, elapsed time, and output hashes are
  evidence.
- JADX output is not authoritative source.
- dexdump/objdump output is not proof of completeness.
- Native code discovered without supplied native analysis tools is reported as
  UNKNOWN rather than silently ignored.
- A native-only split records DEX recovery as ABSENT and continues with native
  recovery; absence of root DEX in a split is not itself a failure.
- An APK containing neither supported root DEX nor native ELF records a hard
  recovery failure rather than being treated as an empty success.
- Tool-specific output is derived evidence and is not the durable canonical
  corpus schema.
