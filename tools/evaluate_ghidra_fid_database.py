#!/usr/bin/env python3
"""Evaluate populated Ghidra FID database behavior on native goldens."""

from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any

TARGETS = ("aar_known_mix", "aar_known_checksum")
VARIANTS = ("exact-copy", "stripped", "patched", "false-friend", "o0")


def load(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def matches_for(doc: dict[str, Any], query_function: str) -> list[dict[str, Any]]:
    return [m for m in doc.get("matches", []) if m["query_function"] == query_function]


def exact_named_match(doc: dict[str, Any], function: str) -> bool:
    return any(
        m["reference_function"] == function and m["specific_match"]
        for m in matches_for(doc, function)
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--reference", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    root = pathlib.Path(args.dir)
    reference = load(pathlib.Path(args.reference))
    if reference["total_added"] < 2:
        raise SystemExit(f"reference database ingested too few functions: {reference['total_added']}")

    docs = {v: load(root / f"{v}.json") for v in VARIANTS}

    checks = {
        "exact_copy_mix_found": exact_named_match(docs["exact-copy"], "aar_known_mix"),
        "exact_copy_checksum_found": exact_named_match(docs["exact-copy"], "aar_known_checksum"),
        "stripped_mix_found": exact_named_match(docs["stripped"], "aar_known_mix"),
        "stripped_checksum_found": exact_named_match(docs["stripped"], "aar_known_checksum"),
        "patched_unchanged_mix_found": exact_named_match(docs["patched"], "aar_known_mix"),
        "patched_checksum_not_exact": not exact_named_match(docs["patched"], "aar_known_checksum"),
        "false_friend_mix_not_exact": not exact_named_match(docs["false-friend"], "aar_known_mix"),
        "false_friend_checksum_not_exact": not exact_named_match(docs["false-friend"], "aar_known_checksum"),
    }
    failed = sorted(k for k, v in checks.items() if not v)

    report = {
        "schema": "aar-ghidra-fid-database-qualification/v0",
        "qualification": "PASS" if not failed else "FAIL",
        "failed_checks": failed,
        "required_checks": checks,
        "o0_observation": {
            target: exact_named_match(docs["o0"], target)
            for target in TARGETS
        },
        "reference_ingest": {
            "total_attempted": reference["total_attempted"],
            "total_added": reference["total_added"],
            "total_excluded": reference["total_excluded"],
        },
        "boundary": "database match is normalized structural evidence; component/version promotion still requires AAR correspondence policy",
    }

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
