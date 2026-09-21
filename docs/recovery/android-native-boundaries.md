# Android native platform boundary classification

AAR should not reverse Android's platform libraries merely because application
ELF objects import them. It should also not pretend that an AOSP source tree is
the exact deployed runtime on every device.

This stage classifies `DT_NEEDED` edges into four states:

- `ANDROID_PLATFORM_BOUNDARY` — a conservative Android/NDK platform library
  such as libc, libdl, libm, liblog, libandroid, or libz. AOSP/NDK source is a
  semantic reference plane for these calls.
- `BUNDLED_DEPENDENCY` — the requested SONAME is also present among observed
  artifact ELF objects. That bundled implementation still requires normal
  component correspondence.
- `NDK_RUNTIME_CANDIDATE` — for example libc++_shared. This commonly ships
  with apps and is not treated as platform implementation merely from its name.
- `UNRESOLVED_EXTERNAL` — no safe classification.

The classifier intentionally uses a small platform allowlist rather than
guessing every Android/vendor native library.

A platform-boundary classification means "do not reconstruct the platform
implementation as application code." It does **not** mean exact runtime bytes,
OEM behavior, Android release, or device implementation are proven.

Boundary callers, imported symbols, configuration, error handling, and
application behavior remain in recovery scope.

## Evidence-driven platform expansion

The first Smart Life boundary run left several well-known Android NDK linkage
surfaces in `UNRESOLVED_EXTERNAL`. The allowlist is therefore expanded only
for observed, public NDK/platform interfaces:

- EGL and GLES 1/2/3 loader/API surfaces;
- `libjnigraphics`;
- OpenSL ES.

The legacy `libstdc++.so` edge is intentionally weaker: it is classified as an
NDK/system runtime candidate rather than exact platform implementation.

Vendor/runtime-specific names such as `libv8_libfull.cr.so` remain unresolved.
