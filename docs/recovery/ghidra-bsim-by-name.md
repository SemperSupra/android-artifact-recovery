# Bounded BSim comparison by function name

Status: qualification

AAR's original BSim qualification proved that similarity can add evidence when
FID fails across compiler/build variation, but the first adapter was intentionally
hard-coded to the source-known interview functions.

Real Smart Life FFmpeg evidence exposed the next concrete gap: independently
verified version banners and 95–100% exported-symbol overlap exist across the
dedicated FFmpeg libraries, while populated FID produced zero matches against the
source-known Android arm64 build.

The by-name adapter therefore compares only an explicit bounded list of function
names already supported by independent evidence (for example shared exported
symbols). It:

- requires exactly one non-external function of each requested name in query and
  reference;
- records missing/ambiguous names rather than guessing;
- caps a run at 128 requested functions;
- emits similarity/significance as candidate build-variant/delta evidence;
- defines no production similarity threshold;
- never treats name equality or BSim similarity alone as component identity.

This adapter is not a general nearest-neighbor search. It exists to answer a
narrow question: when two already-supported component candidates expose the same
function name but FID differs, does BSim show structural similarity consistent
with build/compiler variation?
