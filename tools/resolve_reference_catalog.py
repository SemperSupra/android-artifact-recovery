#!/usr/bin/env python3
"""Resolve only explicitly requested reference artifacts into an AAR catalog.

Every fetched binary must have an expected SHA-256 supplied by the request.
This prevents the resolver from turning a mutable URL into silent reference
truth. The resolver is intentionally provider-neutral and on-demand.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import urllib.request
from typing import Any


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_name(component_id: str, index: int, logical_name: str | None) -> str:
    base = logical_name or f"artifact-{index}"
    clean = "".join(c if c.isalnum() or c in "._-" else "_" for c in base)
    cid = "".join(c if c.isalnum() or c in "._-" else "_" for c in component_id)
    return f"{cid}__{index}__{clean}"


def fetch(url: str, destination: pathlib.Path, max_bytes: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=60) as src, destination.open("wb") as dst:
        total = 0
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise SystemExit(f"reference artifact exceeds max-bytes: {url}")
            dst.write(chunk)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--request", required=True)
    ap.add_argument("--cache", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-bytes", type=int, default=512 * 1024 * 1024)
    args = ap.parse_args()

    request = json.loads(pathlib.Path(args.request).read_text(encoding="utf-8"))
    if request.get("schema") != "aar-reference-request/v0":
        raise SystemExit("unsupported reference request schema")

    cache = pathlib.Path(args.cache)
    catalog_refs: list[dict[str, Any]] = []

    for ref in request.get("references", []):
        binaries = []
        for index, artifact in enumerate(ref.get("artifacts", []) or []):
            expected = artifact["expected_sha256"].lower()
            name = safe_name(ref["component_id"], index, artifact.get("logical_name"))
            target = cache / expected[:2] / expected / name
            if target.is_file() and sha256_file(target) != expected:
                raise SystemExit(f"cached reference hash mismatch: {target}")
            if not target.is_file():
                fetch(artifact["url"], target, args.max_bytes)
            actual = sha256_file(target)
            if actual != expected:
                target.unlink(missing_ok=True)
                raise SystemExit(
                    f"reference hash mismatch for {artifact['url']}: expected={expected} actual={actual}"
                )
            binaries.append({
                "sha256": actual,
                "kind": artifact["kind"],
                "abi": artifact.get("abi"),
                "logical_name": artifact.get("logical_name") or name,
                "resolved_from": artifact["url"],
                "cache_path": str(target),
            })

        catalog_refs.append({
            "component_id": ref["component_id"],
            "name": ref["name"],
            "version": ref.get("version"),
            "purl": ref.get("purl"),
            "provenance_class": ref["provenance_class"],
            "source_ref": ref["source_ref"],
            "binaries": binaries,
            "metadata": ref.get("metadata", {}),
        })

    out_doc = {
        "schema": "aar-reference-catalog/v0",
        "references": catalog_refs,
        "resolver": {
            "mode": "explicit-on-demand",
            "mutable_url_requires_expected_sha256": True,
        },
    }
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(out_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "references": len(catalog_refs),
        "binaries": sum(len(x["binaries"]) for x in catalog_refs),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
