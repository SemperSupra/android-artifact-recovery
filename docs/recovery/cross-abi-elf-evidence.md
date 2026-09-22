# Cross-ABI ELF evidence

Status: qualification

AAR may receive multiple native builds of the same logical application component across Android ABIs. Those builds can preserve materially different reverse-engineering evidence even when they implement the same higher-level behavior.

The cross-ABI evidence producer compares two ELF objects without claiming identity from filename or architecture.

It records:

- ELF machine/build ID;
- SHA-256 and size;
- symbol-table/debug-section presence;
- defined dynamic/all-symbol counts;
- printable-string counts;
- cross-ABI dynamic-symbol overlap and coverage;
- cross-ABI printable-string overlap and coverage;
- a bounded analysis-richness hint.

The richness hint exists only to choose which ABI may be the better analysis oracle. It is not component identity, source correspondence, or proof of semantic equivalence.

AAR's JNI golden provides a controlled qualification case because the same source-known C++ workload is built into both arm64-v8a and x86_64 shared libraries.

Operational use should preserve both ABI artifacts. If one ABI is richer, its names/strings/structure may guide analysis of the poorer build, but any function/body correspondence transferred across ABI still requires independent alignment evidence.
