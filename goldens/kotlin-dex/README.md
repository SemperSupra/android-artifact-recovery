# Golden Kotlin/DEX workload

This source-known Android workload is intentionally small but useful: it
canonicalizes `key=value` records and computes a SHA-256 fingerprint over the
canonical UTF-8 byte stream.

It provides a behavioral oracle for AAR recovery experiments:

1. build the source-known APK;
2. recover semantics from its DEX;
3. rebuild or independently implement the recovered behavior;
4. apply the same test vectors;
5. compare canonical bytes, digest, record count, and unique-key count.

The workload exercises string parsing, filtering, sorting, collection behavior,
UTF-8 encoding, cryptographic digest use, and a structured result without relying
on Android UI behavior.

The source-known implementation and tests are the oracle. Decompiled output is
not authoritative.
