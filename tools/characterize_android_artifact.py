#!/usr/bin/env python3
"""Bounded, format-aware characterization of Android code-bearing artifacts.

This is discovery, not decompilation. Exact input bytes remain ground truth.
The tool inventories DEX, ELF, WASM, script-like assets, and nested archives
without extracting an unbounded filesystem tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import struct
import tempfile
import zipfile
from dataclasses import dataclass, asdict
from typing import BinaryIO, Iterable


SCRIPT_EXTS = {
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsbundle": "javascript",
    ".py": "python",
    ".pyc": "python-bytecode",
    ".lua": "lua",
    ".luac": "lua-bytecode",
    ".sh": "shell",
    ".rb": "ruby",
    ".pl": "perl",
}
ARCHIVE_EXTS = {".jar", ".zip", ".apk", ".xapk", ".apks", ".aar"}
ABI_RE = re.compile(r"(?:^|/)lib/([^/]+)/([^/]+)$")

ELF_MACHINES = {
    3: "x86",
    8: "mips",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}


def sha256_path(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_stream(fh: BinaryIO, max_bytes: int | None = None) -> tuple[str, int, bytes, bool]:
    h = hashlib.sha256()
    total = 0
    prefix = bytearray()
    complete = True
    while True:
        chunk = fh.read(1024 * 1024)
        if not chunk:
            break
        if max_bytes is not None and total + len(chunk) > max_bytes:
            allowed = max(0, max_bytes - total)
            if allowed:
                piece = chunk[:allowed]
                h.update(piece)
                if len(prefix) < 64:
                    prefix.extend(piece[: 64 - len(prefix)])
                total += len(piece)
            complete = False
            break
        h.update(chunk)
        if len(prefix) < 64:
            prefix.extend(chunk[: 64 - len(prefix)])
        total += len(chunk)
    return h.hexdigest(), total, bytes(prefix), complete


def elf_metadata(prefix: bytes) -> dict[str, object]:
    if len(prefix) < 20 or not prefix.startswith(b"\x7fELF"):
        return {}
    elf_class = {1: "ELF32", 2: "ELF64"}.get(prefix[4], f"unknown-{prefix[4]}")
    data = prefix[5]
    endian = "<" if data == 1 else ">" if data == 2 else None
    machine = None
    if endian:
        machine_num = struct.unpack(endian + "H", prefix[18:20])[0]
        machine = {"number": machine_num, "name": ELF_MACHINES.get(machine_num, "unknown")}
    return {
        "class": elf_class,
        "endianness": {1: "little", 2: "big"}.get(data, "unknown"),
        "machine": machine,
    }


def dex_metadata(prefix: bytes) -> dict[str, object]:
    if len(prefix) < 8 or not prefix.startswith(b"dex\n"):
        return {}
    raw = prefix[4:7]
    try:
        version = raw.decode("ascii")
    except UnicodeDecodeError:
        version = raw.hex()
    return {"version": version}


def classify_entry(name: str, prefix: bytes) -> tuple[str | None, dict[str, object]]:
    suffix = pathlib.PurePosixPath(name).suffix.lower()
    if prefix.startswith(b"dex\n"):
        return "dex", dex_metadata(prefix)
    if prefix.startswith(b"\x7fELF"):
        return "elf", elf_metadata(prefix)
    if prefix.startswith(b"\x00asm"):
        return "wasm", {"version_bytes": prefix[4:8].hex() if len(prefix) >= 8 else None}
    if suffix in SCRIPT_EXTS:
        return SCRIPT_EXTS[suffix], {}
    if suffix in ARCHIVE_EXTS or prefix.startswith(b"PK\x03\x04"):
        return "archive", {"extension": suffix or None}
    return None, {}


def role_hint(name: str) -> str:
    base = pathlib.PurePosixPath(name).name.lower()
    if base == "base.apk":
        return "base-candidate"
    if base.startswith("config.") or base.startswith("split_config."):
        return "config-split"
    if base.endswith(".apk"):
        return "base-or-feature-candidate"
    return "unknown"


@dataclass
class CodeEntry:
    path: str
    kind: str
    size_bytes: int
    compressed_bytes: int | None
    sha256: str | None
    hash_complete: bool
    metadata: dict[str, object]


def characterize_apk(path: pathlib.Path, *, logical_name: str | None, max_hash_bytes: int) -> dict[str, object]:
    result: dict[str, object] = {
        "logical_name": logical_name or path.name,
        "path": str(path),
        "sha256": sha256_path(path),
        "size_bytes": path.stat().st_size,
        "zip_valid": False,
        "entries": 0,
        "compressed_bytes": 0,
        "uncompressed_bytes": 0,
        "code_entries": [],
        "summary": {},
        "errors": [],
    }
    code: list[CodeEntry] = []

    try:
        with zipfile.ZipFile(path) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            result["zip_valid"] = True
            result["entries"] = len(infos)
            result["compressed_bytes"] = sum(i.compress_size for i in infos)
            result["uncompressed_bytes"] = sum(i.file_size for i in infos)

            for info in infos:
                # Sniff every entry before applying filename/path hints. Code-bearing
                # material may be deliberately or incidentally stored under opaque
                # names, so DEX/ELF/WASM/archive magic must win over extensions.
                try:
                    with zf.open(info) as fh:
                        prefix = fh.read(64)
                except (RuntimeError, OSError, zipfile.BadZipFile) as exc:
                    result["errors"].append(f"{info.filename}: prefix read failed: {exc}")
                    continue

                kind, meta = classify_entry(info.filename, prefix)
                if kind is None:
                    continue

                try:
                    with zf.open(info) as fh:
                        digest, read_bytes, hashed_prefix, complete = hash_stream(
                            fh, max_hash_bytes
                        )
                except (RuntimeError, OSError, zipfile.BadZipFile) as exc:
                    result["errors"].append(f"{info.filename}: bounded hash failed: {exc}")
                    continue

                # Classification metadata comes from the independent fixed-size
                # sniff above. hashed_prefix is retained only as an integrity
                # cross-check against a surprising archive-reader result.
                if hashed_prefix[: len(prefix)] != prefix[: len(hashed_prefix)]:
                    result["errors"].append(
                        f"{info.filename}: prefix changed between sniff and hash"
                    )
                    continue

                if kind == "elf":
                    m = ABI_RE.search(info.filename)
                    if m:
                        meta = dict(meta)
                        meta["path_abi"] = m.group(1)
                        meta["soname_hint"] = m.group(2)

                code.append(
                    CodeEntry(
                        path=info.filename,
                        kind=kind,
                        size_bytes=info.file_size,
                        compressed_bytes=info.compress_size,
                        sha256=digest if complete else None,
                        hash_complete=complete,
                        metadata=meta,
                    )
                )
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        result["errors"].append(str(exc))

    result["code_entries"] = [asdict(x) for x in sorted(code, key=lambda x: (x.kind, x.path))]

    dex = [x for x in code if x.kind == "dex"]
    elf = [x for x in code if x.kind == "elf"]
    wasm = [x for x in code if x.kind == "wasm"]
    scripts = [x for x in code if x.kind in set(SCRIPT_EXTS.values())]
    archives = [x for x in code if x.kind == "archive"]
    abis = sorted(
        {
            str(x.metadata.get("path_abi"))
            for x in elf
            if x.metadata.get("path_abi")
        }
    )
    result["summary"] = {
        "dex_count": len(dex),
        "root_dex_count": sum(1 for x in dex if "/" not in x.path),
        "elf_count": len(elf),
        "abis": abis,
        "wasm_count": len(wasm),
        "script_count": len(scripts),
        "nested_archive_count": len(archives),
    }
    return result


def extract_member_bounded(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    destination: pathlib.Path,
    *,
    max_bytes: int,
) -> tuple[bool, str | None]:
    if info.file_size > max_bytes:
        return False, f"claimed size {info.file_size} exceeds max_nested_apk_bytes={max_bytes}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with zf.open(info) as src, destination.open("wb") as dst:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                destination.unlink(missing_ok=True)
                return False, f"expanded size exceeded max_nested_apk_bytes={max_bytes}"
            dst.write(chunk)
    return True, None


def discover_inputs(path: pathlib.Path, *, max_nested_apk_bytes: int) -> tuple[list[tuple[pathlib.Path, str]], list[dict[str, object]], str]:
    if path.is_dir():
        apks = sorted(p for p in path.rglob("*.apk") if p.is_file())
        return [(p, p.relative_to(path).as_posix()) for p in apks], [], "directory"

    suffix = path.suffix.lower()
    if suffix == ".apk":
        return [(path, path.name)], [], "apk"

    if suffix not in {".xapk", ".apks", ".zip"}:
        return [(path, path.name)], [{"state": "UNKNOWN", "reason": f"unrecognized container suffix {suffix}"}], "unknown"

    skipped: list[dict[str, object]] = []
    temp_root = pathlib.Path(tempfile.mkdtemp(prefix="aar-characterize-"))
    found: list[tuple[pathlib.Path, str]] = []
    try:
        with zipfile.ZipFile(path) as zf:
            members = sorted(
                [i for i in zf.infolist() if not i.is_dir() and i.filename.lower().endswith(".apk")],
                key=lambda i: i.filename,
            )
            for index, info in enumerate(members):
                target = temp_root / f"{index:04d}-{pathlib.PurePosixPath(info.filename).name}"
                ok, reason = extract_member_bounded(
                    zf,
                    info,
                    target,
                    max_bytes=max_nested_apk_bytes,
                )
                if ok:
                    found.append((target, info.filename))
                else:
                    skipped.append({
                        "path": info.filename,
                        "state": "SKIPPED_BOUND",
                        "reason": reason,
                        "size_bytes": info.file_size,
                    })
    except (zipfile.BadZipFile, OSError) as exc:
        skipped.append({"state": "ERROR", "reason": str(exc)})
    return found, skipped, suffix.lstrip(".")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("artifact")
    p.add_argument("--out", required=True)
    p.add_argument("--max-entry-hash-bytes", type=int, default=512 * 1024 * 1024)
    p.add_argument("--max-nested-apk-bytes", type=int, default=768 * 1024 * 1024)
    args = p.parse_args()

    artifact = pathlib.Path(args.artifact).resolve()
    if not artifact.exists():
        raise SystemExit(f"artifact not found: {artifact}")

    source_hash = sha256_path(artifact) if artifact.is_file() else None
    inputs, skipped, container_kind = discover_inputs(
        artifact,
        max_nested_apk_bytes=args.max_nested_apk_bytes,
    )

    apks: list[dict[str, object]] = []
    for apk_path, logical_name in inputs:
        record = characterize_apk(
            apk_path,
            logical_name=logical_name,
            max_hash_bytes=args.max_entry_hash_bytes,
        )
        record["role_hint"] = role_hint(logical_name)
        apks.append(record)

    all_code = [
        entry
        for apk in apks
        for entry in apk.get("code_entries", [])
        if isinstance(entry, dict)
    ]
    kinds: dict[str, int] = {}
    for entry in all_code:
        kind = str(entry.get("kind"))
        kinds[kind] = kinds.get(kind, 0) + 1

    doc = {
        "schema": "aar-artifact-characterization/v0",
        "source": {
            "path": str(artifact),
            "kind": container_kind,
            "sha256": source_hash,
            "size_bytes": artifact.stat().st_size if artifact.is_file() else None,
        },
        "bounds": {
            "max_entry_hash_bytes": args.max_entry_hash_bytes,
            "max_nested_apk_bytes": args.max_nested_apk_bytes,
        },
        "apks": apks,
        "skipped": skipped,
        "summary": {
            "apk_count": len(apks),
            "code_entry_count": len(all_code),
            "kinds": dict(sorted(kinds.items())),
            "abis": sorted({
                abi
                for apk in apks
                for abi in apk.get("summary", {}).get("abis", [])
            }),
            "unknown_or_skipped": len(skipped),
        },
    }

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(doc["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
