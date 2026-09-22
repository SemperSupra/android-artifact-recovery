#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess


def run(*args: str) -> tuple[int, str]:
    cp = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return cp.returncode, cp.stdout


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def symbol_set(path: pathlib.Path, dynamic: bool) -> set[str]:
    cmd = ["nm"]
    if dynamic:
        cmd.append("-D")
    cmd.extend(["--defined-only", str(path)])
    rc, out = run(*cmd)
    if rc != 0:
        return set()
    names: set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        names.add(parts[-1].split("@", 1)[0])
    return names


def string_set(path: pathlib.Path) -> set[str]:
    rc, out = run("strings", "-a", "-n", "6", str(path))
    if rc != 0:
        return set()
    # Bounded normalized evidence: retain no raw strings in output.
    return set(out.splitlines())


def inspect(path: pathlib.Path, abi: str) -> tuple[dict, set[str], set[str]]:
    rc, hdr = run("readelf", "-h", str(path))
    machine = None
    if rc == 0:
        for line in hdr.splitlines():
            if "Machine:" in line:
                machine = line.split(":", 1)[1].strip()
                break

    rc, secs = run("readelf", "-S", str(path))
    has_symtab = ".symtab" in secs if rc == 0 else None
    has_debug = any(x in secs for x in (".debug_info", ".debug_line", ".zdebug_info")) if rc == 0 else None

    rc, notes = run("readelf", "-n", str(path))
    build_id = None
    if rc == 0:
        m = re.search(r"Build ID:\s*([0-9a-fA-F]+)", notes)
        if m:
            build_id = m.group(1).lower()

    dyn = symbol_set(path, True)
    all_defined = symbol_set(path, False)
    strings = string_set(path)

    doc = {
        "abi": abi,
        "path": path.name,
        "sha256": sha256(path),
        "size_bytes": path.stat().st_size,
        "machine": machine,
        "build_id": build_id,
        "has_symtab": has_symtab,
        "has_debug_sections": has_debug,
        "defined_dynamic_symbol_count": len(dyn),
        "defined_all_symbol_count": len(all_defined),
        "printable_string_count_min6": len(strings),
    }
    return doc, dyn, strings


def ratio(n: int, d: int) -> float | None:
    return n / d if d else None


def richness(doc: dict) -> tuple[int, int, int]:
    return (
        int(bool(doc["has_debug_sections"])) + int(bool(doc["has_symtab"])),
        int(doc["defined_dynamic_symbol_count"]),
        int(doc["printable_string_count_min6"]),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--left", required=True)
    ap.add_argument("--left-abi", required=True)
    ap.add_argument("--right", required=True)
    ap.add_argument("--right-abi", required=True)
    ap.add_argument("--logical-name")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    left_path = pathlib.Path(args.left)
    right_path = pathlib.Path(args.right)
    for p in (left_path, right_path):
        if not p.is_file():
            raise SystemExit(f"missing ELF: {p}")

    left, left_dyn, left_strings = inspect(left_path, args.left_abi)
    right, right_dyn, right_strings = inspect(right_path, args.right_abi)

    shared_dyn = left_dyn & right_dyn
    shared_strings = left_strings & right_strings

    lr = richness(left)
    rr = richness(right)
    richer = args.left_abi if lr > rr else args.right_abi if rr > lr else "TIE"

    doc = {
        "schema": "aar-elf-cross-abi-evidence/v0",
        "logical_name": args.logical_name or left_path.name,
        "left": left,
        "right": right,
        "correspondence_evidence": {
            "shared_defined_dynamic_symbol_count": len(shared_dyn),
            "left_dynamic_symbol_coverage": ratio(len(shared_dyn), len(left_dyn)),
            "right_dynamic_symbol_coverage": ratio(len(shared_dyn), len(right_dyn)),
            "shared_printable_string_count_min6": len(shared_strings),
            "left_string_coverage": ratio(len(shared_strings), len(left_strings)),
            "right_string_coverage": ratio(len(shared_strings), len(right_strings)),
        },
        "analysis_richness_hint": richer,
        "policy": {
            "richness_is_not_identity": True,
            "filename_match_is_not_identity": True,
            "cross_abi_similarity_is_not_identity": True,
            "cross_abi_evidence_may_select_analysis_oracle": True,
            "raw_strings_emitted": False,
        },
    }

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(doc, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
