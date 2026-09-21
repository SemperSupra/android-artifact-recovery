# Current Task — Post-MVP Real-Artifact Recovery

Status: post-MVP

## Objective

Turn the proven AAR primitives into reusable, bounded recovery machinery for
real Android artifacts without weakening the evidence model established by the
goldens.

## Proven implementation

The public implementation has qualified:

- passive Android environment spelunking;
- Kotlin/DEX source-known golden;
- JNI/C++ source-known golden across arm64-v8a and x86_64;
- static DEX and native low-level recovery;
- rebuild feasibility measurement;
- raw and repair-assisted behavioral comparison as distinct evidence states;
- evidence/UNKNOWN synthesis;
- bounded APK/XAPK/APKS characterization;
- magic-first discovery for DEX/ELF/WASM/archive content;
- end-to-end Kotlin golden composition.

## Current implementation frontier

1. Apply characterization to real corpus artifacts and collect structural
   profiles before broad decompilation.
2. Select bounded real-artifact pilots from observed structural diversity.
3. Harden recursive discovery only where real evidence demonstrates a gap.
4. Add native/high-level or runtime recovery primitives only when a concrete
   pilot requires them.
5. Preserve raw, repair-assisted, inferred, and validated representations as
   separate states.
6. Keep every semantic claim tied to an independent validator/oracle where one
   exists; otherwise retain UNKNOWN.

## Public/private boundary

This repository owns reusable implementation, schemas, goldens, validators, and
public-safe qualification.

It does not own:

- private/restricted corpus bytes;
- acquisition credentials or authenticated Play state;
- package-specific private findings;
- rights decisions;
- originating workset authority;
- automatic promotion decisions.

Those remain in the private AAR authority plane.

## Non-goals

Do not grow AAR into a generic scheduler, vulnerability scanner, package mirror,
or tool-specific canonical database. Agent Dispatch remains optional execution
infrastructure, not AAR authority.
