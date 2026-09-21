#!/usr/bin/env python3
"""Apply bounded, auditable Java-source repairs to JADX output from Kotlin bytecode.

Repairs only well-understood decompiler/JVM-synthetic artifacts. Each applied
rule is counted and written to a manifest. Unexpected match counts fail closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
from dataclasses import dataclass


@dataclass
class RuleResult:
    rule_id: str
    count: int
    detail: str


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def apply_exact(text: str, old: str, new: str, *, rule_id: str, expected: int = 1) -> tuple[str, RuleResult]:
    count = text.count(old)
    if count != expected:
        raise ValueError(f"{rule_id}: expected {expected} match(es), found {count}")
    return text.replace(old, new, expected), RuleResult(rule_id, count, "exact textual normalization")


def dedupe_simple_getters(text: str, expected_removed: int = 4) -> tuple[str, RuleResult]:
    pattern = re.compile(
        r"(?P<block>"
        r"(?P<indent> {8})public final (?P<ret>[A-Za-z0-9_.$<>]+) (?P<name>get[A-Za-z0-9_]+)\(\) \{\n"
        r"(?P=indent)    return this\.(?P<field>[A-Za-z0-9_]+);\n"
        r"(?P=indent)\}\n"
        r")"
    )
    seen: set[tuple[str, str, str]] = set()
    removed = 0

    def repl(match: re.Match[str]) -> str:
        nonlocal removed
        key = (match.group("ret"), match.group("name"), match.group("field"))
        if key in seen:
            removed += 1
            return ""
        seen.add(key)
        return match.group("block")

    out = pattern.sub(repl, text)
    if removed != expected_removed:
        raise ValueError(
            f"jadx.kotlin.duplicate-data-class-getters: expected {expected_removed} duplicate getter(s), removed {removed}"
        )
    return out, RuleResult(
        "jadx.kotlin.duplicate-data-class-getters",
        removed,
        "removed duplicate simple accessors emitted for the same data-class fields",
    )


def repair(source: str) -> tuple[str, list[RuleResult]]:
    results: list[RuleResult] = []
    text = source

    text, result = dedupe_simple_getters(text)
    results.append(result)

    replacements = [
        (
            "jadx.kotlin.startsWith-default-bridge",
            'kotlin.text.StringsKt.startsWith$default(it, "#", false, 2, (java.lang.Object) null)',
            'kotlin.text.StringsKt.startsWith(it, "#", false)',
            "replace synthetic Kotlin default-argument bridge with its explicit public overload",
        ),
        (
            "jadx.kotlin.indexOf-default-bridge",
            "kotlin.text.StringsKt.indexOf$default((java.lang.CharSequence) line, '=', 0, false, 6, (java.lang.Object) null)",
            "kotlin.text.StringsKt.indexOf((java.lang.CharSequence) line, '=', 0, false)",
            "replace synthetic Kotlin default-argument bridge with its explicit public overload",
        ),
        (
            "jadx.kotlin.collection-join-default-bridge",
            'kotlin.collections.CollectionsKt.joinToString$default(arrayList, " ", null, null, 0, null, null, 62, null)',
            'kotlin.collections.CollectionsKt.joinToString(arrayList, " ", "", "", -1, "...", null)',
            "expand Kotlin default arguments explicitly",
        ),
        (
            "jadx.kotlin.substringBefore-default-bridge",
            "kotlin.text.StringsKt.substringBefore$default((java.lang.String) it.next(), '=', (java.lang.String) null, 2, (java.lang.Object) null)",
            "aarRepairSubstringBeforeEq((java.lang.String) it.next())",
            "route through an explicit helper so the default missing-delimiter value remains the original string",
        ),
    ]

    for rule_id, old, new, detail in replacements:
        text, rr = apply_exact(text, old, new, rule_id=rule_id)
        rr.detail = detail
        results.append(rr)

    text, rr = apply_exact(
        text,
        'kotlin.collections.CollectionsKt.joinToString$default(list, "\\n", null, "\\n", 0, null, ',
        'kotlin.collections.CollectionsKt.joinToString(list, "\\n", "", "\\n", -1, "...", ',
        rule_id="jadx.kotlin.canonical-join-default-bridge-prefix",
    )
    rr.detail = "expand prefix/postfix/limit/truncated defaults explicitly"
    results.append(rr)

    text, rr = apply_exact(
        text,
        "        }, 26, null);",
        "        });",
        rule_id="jadx.kotlin.canonical-join-default-bridge-tail",
    )
    rr.detail = "remove Kotlin default-argument mask/object tail after explicit expansion"
    results.append(rr)

    text, rr = apply_exact(
        text,
        'kotlin.collections.ArraysKt.joinToString$default(bArrDigest, (java.lang.CharSequence) "", (java.lang.CharSequence) null, (java.lang.CharSequence) null, 0, (java.lang.CharSequence) null, ',
        'kotlin.collections.ArraysKt.joinToString(bArrDigest, (java.lang.CharSequence) "", (java.lang.CharSequence) "", (java.lang.CharSequence) "", -1, (java.lang.CharSequence) "...", ',
        rule_id="jadx.kotlin.byte-array-join-default-bridge-prefix",
    )
    rr.detail = "expand Kotlin byte-array join defaults explicitly"
    results.append(rr)

    text, rr = apply_exact(
        text,
        "        }, 30, (java.lang.Object) null);",
        "        });",
        rule_id="jadx.kotlin.byte-array-join-default-bridge-tail",
    )
    rr.detail = "remove Kotlin default-argument mask/object tail after explicit expansion"
    results.append(rr)

    helper_anchor = "    public final org.sempersupra.aar.golden.kotlin.GoldenRecordFingerprint.Result fingerprint(java.lang.String input)"
    helper = (
        "    private static final java.lang.String aarRepairSubstringBeforeEq(java.lang.String value) {\n"
        "        return kotlin.text.StringsKt.substringBefore(value, '=', value);\n"
        "    }\n\n"
    )
    if text.count(helper_anchor) != 1:
        raise ValueError("jadx.kotlin.substringBefore-helper: fingerprint anchor missing or ambiguous")
    text = text.replace(helper_anchor, helper + helper_anchor, 1)
    results.append(
        RuleResult(
            "jadx.kotlin.substringBefore-helper",
            1,
            "insert explicit public-overload helper preserving Kotlin default behavior",
        )
    )

    return text, results


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--manifest", required=True)
    args = p.parse_args()

    src = pathlib.Path(args.input)
    dst = pathlib.Path(args.output)
    manifest = pathlib.Path(args.manifest)

    raw = src.read_bytes()
    repaired_text, rules = repair(raw.decode("utf-8"))
    repaired = repaired_text.encode("utf-8")

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(repaired)

    record = {
        "schema": "aar-repair-manifest/v0",
        "producer": "repair_jadx_kotlin_java.py",
        "input": {
            "path": str(src),
            "sha256": sha256_bytes(raw),
            "size_bytes": len(raw),
        },
        "output": {
            "path": str(dst),
            "sha256": sha256_bytes(repaired),
            "size_bytes": len(repaired),
        },
        "repairs": [
            {"id": r.rule_id, "count": r.count, "detail": r.detail}
            for r in rules
        ],
        "semantic_claim": "NONE",
        "note": "Repairs make a derived representation independently compilable; behavior must be validated separately.",
    }
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"repair_count": sum(r.count for r in rules), "rules": len(rules)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
