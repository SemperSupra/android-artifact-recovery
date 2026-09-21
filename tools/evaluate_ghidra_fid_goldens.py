#!/usr/bin/env python3
"""Evaluate Ghidra headless and FID behavior over attribution goldens."""

from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any

TARGETS = ("aar_known_mix", "aar_known_checksum")
VARIANTS = (
    "libaarknown.so",
    "libaarknown-exact-copy.so",
    "libaarknown-o0.so",
    "libaarknown-stripped.so",
    "libaarknown-patched.so",
    "libaarknown-false-friend.so",
)


def load(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def fid_by_name(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {x["name"]: x for x in doc["functions"]}


def dec_by_name(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {x["name"]: x for x in doc["target_decompilations"]}


def same_hash(a: dict[str, Any], b: dict[str, Any]) -> bool:
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
    inventories = {
        name: load(root / f"{name}.inventory.json")
        for name in VARIANTS
    }
    fids = {
        name: fid_by_name(load(root / f"{name}.fid.json"))
        for name in VARIANTS
    }

    for name in VARIANTS:
        inv = inventories[name]
        if inv["internal_function_count"] <= 0:
            raise SystemExit(f"{name}: no internal functions discovered")
        by_name = dec_by_name(inv)
        for target in TARGETS:
            if target not in by_name:
                raise SystemExit(f"{name}: target function missing from Ghidra inventory: {target}")
            if not by_name[target]["decompile_completed"]:
                raise SystemExit(f"{name}: Ghidra decompile failed for {target}")
            if target not in fids[name]:
                raise SystemExit(f"{name}: FID hash unavailable for {target}")

    base = fids["libaarknown.so"]
    exact = fids["libaarknown-exact-copy.so"]
    o0 = fids["libaarknown-o0.so"]
    stripped = fids["libaarknown-stripped.so"]
    patched = fids["libaarknown-patched.so"]
    false_friend = fids["libaarknown-false-friend.so"]

    checks = {
        "exact_copy_mix_matches": same_hash(base["aar_known_mix"], exact["aar_known_mix"]),
        "exact_copy_checksum_matches": same_hash(base["aar_known_checksum"], exact["aar_known_checksum"]),
        "stripped_mix_matches": same_hash(base["aar_known_mix"], stripped["aar_known_mix"]),
        "stripped_checksum_matches": same_hash(base["aar_known_checksum"], stripped["aar_known_checksum"]),
        "patched_unchanged_mix_matches": same_hash(base["aar_known_mix"], patched["aar_known_mix"]),
        "patched_checksum_changes": not same_hash(base["aar_known_checksum"], patched["aar_known_checksum"]),
        "false_friend_mix_rejected": not same_hash(base["aar_known_mix"], false_friend["aar_known_mix"]),
        "false_friend_checksum_rejected": not same_hash(base["aar_known_checksum"], false_friend["aar_known_checksum"]),
        "optimization_change_detected": any(
            not same_hash(base[target], o0[target])
            for target in TARGETS
        ),
    }

    failed = sorted(k for k, v in checks.items() if not v)

    report = {
        "schema": "aar-ghidra-fid-qualification/v0",
        "ghidra_headless": {
            "variants_imported": len(VARIANTS),
            "target_functions_per_variant": len(TARGETS),
            "all_target_decompilations_completed": True,
        },
        "fid_checks": checks,
        "failed_checks": failed,
        "interpretation": {
            "exact_and_stripped": "FID should preserve identity when function code is unchanged",
            "patched": "an unchanged function should remain stable while the deliberately modified function should not exact-match",
            "false_friend": "same exported API names with unrelated implementations must not exact-match",
            "optimization": "this first FID qualification does not require robustness to changed optimization; at least one changed hash demonstrates the build variant is not silently exact",
        },
        "qualification": "PASS" if not failed else "FAIL",
    }

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
