#!/usr/bin/env python3
"""Evaluate Ghidra FID behavior on source-known DEX attribution variants."""

from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any

TARGETS = ("fold", "normalize")
VARIANTS = (
    "known",
    "exact-copy",
    "patched",
    "false-friend",
    "shaded",
)


def load(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def candidates(doc: dict[str, Any], target: str) -> list[dict[str, Any]]:
    rows = []
    for row in doc.get("functions", []):
        name = str(row.get("name", ""))
        lowered = name.lower()
        t = target.lower()
        if (
            lowered == t
            or lowered.endswith("." + t)
            or lowered.endswith("::" + t)
            or lowered.endswith("/" + t)
            or ("knowncodec" in lowered and t in lowered)
        ):
            rows.append(row)
    return rows


def pick(doc: dict[str, Any], target: str, variant: str) -> dict[str, Any]:
    rows = candidates(doc, target)
    if len(rows) != 1:
        names = sorted(str(x.get("name")) for x in doc.get("functions", []))
        raise SystemExit(
            f"{variant}: expected one FID function for {target}, got {len(rows)}; "
            f"available={names}"
        )
    return rows[0]


def same(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return (
        a["full_hash"] == b["full_hash"]
        and a["specific_hash"] == b["specific_hash"]
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence-dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    root = pathlib.Path(args.evidence_dir)
    docs = {
        variant: load(root / f"{variant}.fid.json")
        for variant in VARIANTS
    }
    rows = {
        variant: {
            target: pick(docs[variant], target, variant)
            for target in TARGETS
        }
        for variant in VARIANTS
    }

    base = rows["known"]
    exact = rows["exact-copy"]
    patched = rows["patched"]
    false_friend = rows["false-friend"]
    shaded = rows["shaded"]

    checks = {
        "exact_copy_fold_matches": same(base["fold"], exact["fold"]),
        "exact_copy_normalize_matches": same(base["normalize"], exact["normalize"]),
        "patched_unchanged_normalize_matches": same(base["normalize"], patched["normalize"]),
        "patched_fold_changes": not same(base["fold"], patched["fold"]),
        "false_friend_fold_rejected": not same(base["fold"], false_friend["fold"]),
        "false_friend_normalize_rejected": not same(base["normalize"], false_friend["normalize"]),
    }
    shaded_observation = {
        "fold_matches": same(base["fold"], shaded["fold"]),
        "normalize_matches": same(base["normalize"], shaded["normalize"]),
    }
    failed = sorted(k for k, value in checks.items() if not value)

    report = {
        "schema": "aar-ghidra-fid-dex-qualification/v0",
        "qualification": "PASS" if not failed else "FAIL",
        "failed_checks": failed,
        "required_checks": checks,
        "shaded_observation": shaded_observation,
        "interpretation": {
            "required": "exact identity, one-method patch detection, and false-friend rejection",
            "shaded": "measured but not promoted to a required invariant in this first DEX FID qualification",
            "boundary": "FID hash equality is structural evidence; it is not by itself component/version identity",
        },
        "functions": rows,
    }

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "qualification": report["qualification"],
        "failed_checks": failed,
        "required_checks": checks,
        "shaded_observation": shaded_observation,
    }, indent=2, sort_keys=True))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
