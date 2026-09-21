# Static APK recovery representations

Status: MVP

The static recovery stage consumes an APK whose exact bytes/hash are already
known and emits multiple derived representations.

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
- Tool-specific output is derived evidence and is not the durable canonical
  corpus schema.
