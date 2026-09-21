#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def readelf_machine(path: pathlib.Path) -> dict[str, str]:
    cp = subprocess.run(
        ["readelf", "-h", str(path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if cp.returncode != 0:
        return {"state": "UNKNOWN", "stderr": cp.stderr[-2000:]}
    info: dict[str, str] = {}
    for line in cp.stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in {"Class", "Data", "Machine", "Type"}:
            info[key.lower()] = value.strip()
    return {"state": "OBSERVED", **info}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--component", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--source-repository", required=True)
    ap.add_argument("--source-commit", required=True)
    ap.add_argument("--source-tag", required=True)
    ap.add_argument("--ndk-version", required=True)
    ap.add_argument("--api", required=True, type=int)
    ap.add_argument("--lib-dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    lib_dir = pathlib.Path(args.lib_dir)
    binaries = []
    for path in sorted(p for p in lib_dir.iterdir() if p.is_file()):
        binaries.append({
            "logical_name": path.name,
            "sha256": sha256(path),
            "size_bytes": path.stat().st_size,
            "elf": readelf_machine(path),
        })

    if not binaries:
        raise SystemExit("no reference binaries found")

    doc = {
        "schema": "aar-source-reference-build/v0",
        "component": args.component,
        "version": args.version,
        "source": {
            "repository": args.source_repository,
            "tag": args.source_tag,
            "commit": args.source_commit,
            "provenance": "official-upstream-git-tag",
        },
        "build": {
            "target": "android-arm64",
            "android_api": args.api,
            "ndk_version": args.ndk_version,
            "reproducibility_claim": "SOURCE-KNOWN-BUILD-VARIANT",
        },
        "binaries": binaries,
        "policy": {
            "exact_match_to_application_not_assumed": True,
            "eligible_for_fid_bsim_reference": True,
            "reference_build_is_not_upstream_release_binary": True,
        },
    }

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "component": args.component,
        "version": args.version,
        "binary_count": len(binaries),
        "binaries": [
            {"name": x["logical_name"], "sha256": x["sha256"], "machine": x["elf"].get("machine")}
            for x in binaries
        ],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
