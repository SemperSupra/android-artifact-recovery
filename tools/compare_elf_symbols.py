#!/usr/bin/env python3
"""Compare ELF defined dynamic-symbol sets as architecture-independent evidence.

This produces component-family correspondence evidence only. Symbol overlap
never establishes exact implementation identity or authorizes residual
suppression.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
from typing import Any


ROW_RE = re.compile(
    r"\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$"
)
ALLOWED_TYPES = {"FUNC", "OBJECT", "IFUNC"}


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def defined_dynamic_symbols(path: pathlib.Path, readelf: str) -> set[str]:
    cp = subprocess.run(
        [readelf, "--wide", "--dyn-syms", str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        check=False,
    )
    if cp.returncode != 0:
        raise SystemExit(f"readelf failed for {path}: {cp.stderr.strip()}")

    symbols: set[str] = set()
    for line in cp.stdout.splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        typ, _bind, _vis, ndx, raw_name = m.groups()
        if ndx == "UND" or typ not in ALLOWED_TYPES:
            continue
        name = raw_name.strip().split("@", 1)[0]
        if name:
            symbols.add(name)
    return symbols


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--reference", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--reference-id")
    p.add_argument("--target-id")
    p.add_argument("--readelf", default=shutil.which("readelf") or "")
    p.add_argument("--sample-limit", type=int, default=100)
    a = p.parse_args()

    reference = pathlib.Path(a.reference).resolve()
    target = pathlib.Path(a.target).resolve()
    if not reference.is_file() or not target.is_file():
        raise SystemExit("reference and target must be files")
    if not a.readelf:
        raise SystemExit("readelf not found; supply --readelf")

    ref_symbols = defined_dynamic_symbols(reference, a.readelf)
    target_symbols = defined_dynamic_symbols(target, a.readelf)
    overlap = ref_symbols & target_symbols
    ref_only = ref_symbols - target_symbols
    target_only = target_symbols - ref_symbols

    ref_count = len(ref_symbols)
    target_count = len(target_symbols)
    overlap_count = len(overlap)

    doc: dict[str, Any] = {
        "schema": "aar-elf-symbol-correspondence/v0",
        "reference": {
            "id": a.reference_id or reference.name,
            "path": str(reference),
            "sha256": sha256_file(reference),
            "defined_dynamic_symbol_count": ref_count,
        },
        "target": {
            "id": a.target_id or target.name,
            "path": str(target),
            "sha256": sha256_file(target),
            "defined_dynamic_symbol_count": target_count,
        },
        "overlap": {
            "count": overlap_count,
            "reference_coverage": (overlap_count / ref_count) if ref_count else 0.0,
            "target_coverage": (overlap_count / target_count) if target_count else 0.0,
            "sample": sorted(overlap)[: a.sample_limit],
        },
        "differences": {
            "reference_only_count": len(ref_only),
            "target_only_count": len(target_only),
            "reference_only_sample": sorted(ref_only)[: a.sample_limit],
            "target_only_sample": sorted(target_only)[: a.sample_limit],
        },
        "policy": {
            "evidence_family": "symbol",
            "architecture_independent": True,
            "establishes_exact_identity": False,
            "establishes_unmodified_state": False,
            "authorizes_residual_suppression": False,
        },
    }

    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "reference_symbol_count": ref_count,
        "target_symbol_count": target_count,
        "overlap_count": overlap_count,
        "reference_coverage": doc["overlap"]["reference_coverage"],
        "target_coverage": doc["overlap"]["target_coverage"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
