#!/usr/bin/env python3
"""Cheap, bounded component-evidence extraction for APK/ZIP or raw code objects.

This stage produces observations only. It does not claim component identity.
DEX namespaces are parsed directly from class definitions. ELF metadata is
obtained from a bounded readelf invocation when available.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
from typing import Any


DEX_MAGIC = b"dex\n"
ELF_MAGIC = b"\x7fELF"
JS_SUFFIXES = {".js", ".mjs", ".cjs", ".jsbundle"}
MAX_DEX_STRINGS = 250_000
MAX_DEX_CLASSES = 250_000
MAX_NAMESPACES = 20_000
MAX_SYMBOL_LINES = 20_000


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def uleb128(data: bytes, off: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for i in range(5):
        if off + i >= len(data):
            raise ValueError("truncated uleb128")
        b = data[off + i]
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, off + i + 1
        shift += 7
    raise ValueError("uleb128 too long")


def read_dex_string(data: bytes, off: int) -> str:
    _, pos = uleb128(data, off)
    end = data.find(b"\x00", pos)
    if end < 0:
        raise ValueError("unterminated dex string")
    return data[pos:end].decode("utf-8", "replace")


def descriptor_namespace(descriptor: str) -> str | None:
    if not (descriptor.startswith("L") and descriptor.endswith(";")):
        return None
    body = descriptor[1:-1]
    if "/" not in body:
        return None
    package = body.rsplit("/", 1)[0]
    return package.replace("/", ".")


def dex_metadata(data: bytes) -> dict[str, Any]:
    if len(data) < 112 or not data.startswith(DEX_MAGIC):
        return {}
    try:
        version = data[4:7].decode("ascii", "replace")
        string_ids_size, string_ids_off = struct.unpack_from("<II", data, 56)
        type_ids_size, type_ids_off = struct.unpack_from("<II", data, 64)
        class_defs_size, class_defs_off = struct.unpack_from("<II", data, 96)

        if string_ids_size > MAX_DEX_STRINGS or class_defs_size > MAX_DEX_CLASSES:
            raise ValueError("dex table count exceeds bounded parser limit")
        if string_ids_off + string_ids_size * 4 > len(data):
            raise ValueError("string_ids outside file")
        if type_ids_off + type_ids_size * 4 > len(data):
            raise ValueError("type_ids outside file")
        if class_defs_off + class_defs_size * 32 > len(data):
            raise ValueError("class_defs outside file")

        string_offsets = [
            struct.unpack_from("<I", data, string_ids_off + i * 4)[0]
            for i in range(string_ids_size)
        ]
        type_string_idx = [
            struct.unpack_from("<I", data, type_ids_off + i * 4)[0]
            for i in range(type_ids_size)
        ]

        namespaces: set[str] = set()
        descriptor_count = 0
        for i in range(class_defs_size):
            class_idx = struct.unpack_from("<I", data, class_defs_off + i * 32)[0]
            if class_idx >= len(type_string_idx):
                continue
            string_idx = type_string_idx[class_idx]
            if string_idx >= len(string_offsets):
                continue
            descriptor = read_dex_string(data, string_offsets[string_idx])
            descriptor_count += 1
            ns = descriptor_namespace(descriptor)
            if ns and len(namespaces) < MAX_NAMESPACES:
                namespaces.add(ns)

        return {
            "dex_version": version,
            "class_definition_count": class_defs_size,
            "class_descriptors_read": descriptor_count,
            "namespaces": sorted(namespaces),
        }
    except (ValueError, struct.error) as exc:
        return {"dex_parse_error": str(exc), "namespaces": []}


def parse_readelf(text: str) -> dict[str, Any]:
    sonames = sorted(set(re.findall(r"\(SONAME\).*?\[(.*?)\]", text)))
    needed = sorted(set(re.findall(r"\(NEEDED\).*?\[(.*?)\]", text)))
    build_ids = sorted(set(re.findall(r"Build ID:\s*([0-9a-fA-F]+)", text)))
    comments: list[str] = []
    symbols: list[str] = []
    in_comment = False
    for line in text.splitlines():
        if "String dump of section '.comment'" in line:
            in_comment = True
            continue
        if in_comment:
            m = re.search(r"\]\s+(.*\S)", line)
            if m:
                comments.append(m.group(1).strip())
            elif line.strip() == "":
                in_comment = False
        if len(symbols) < MAX_SYMBOL_LINES:
            m = re.match(r"\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$", line)
            if m:
                name = m.group(1).strip().split("@", 1)[0]
                if name and name != "UND":
                    symbols.append(name)
    return {
        "sonames": sonames,
        "build_ids": build_ids,
        "needed": needed,
        "comments": sorted(set(comments)),
        "dynamic_symbols": sorted(set(symbols)),
    }


def elf_metadata(data: bytes, readelf: str | None) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    if len(data) >= 20 and data.startswith(ELF_MAGIC):
        elf_class = {1: "ELF32", 2: "ELF64"}.get(data[4], "unknown")
        endian = "<" if data[5] == 1 else ">" if data[5] == 2 else None
        meta["elf_class"] = elf_class
        if endian:
            machine = struct.unpack_from(endian + "H", data, 18)[0]
            meta["machine"] = machine

    if not readelf:
        meta["readelf_state"] = "ABSENT"
        return meta

    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td) / "object.so"
        p.write_bytes(data)
        cp = subprocess.run(
            [readelf, "-d", "-n", "--dyn-syms", "-p", ".comment", "--wide", str(p)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=30,
            check=False,
        )
    meta["readelf_returncode"] = cp.returncode
    meta["readelf_stderr"] = cp.stderr[-4000:]
    meta.update(parse_readelf(cp.stdout))
    return meta


def js_metadata(data: bytes) -> dict[str, Any]:
    text = data[:2_000_000].decode("utf-8", "replace")
    markers = []
    for marker in (
        "__webpack_require__",
        "webpackChunk",
        "__METRO_GLOBAL_PREFIX__",
        "__d(function",
        "ReactNative",
        "sourceMappingURL=",
    ):
        if marker in text:
            markers.append(marker)
    license_notices = sorted(set(
        m.group(0)[:500]
        for m in re.finditer(r"(?im)^.*(?:copyright|licensed under|spdx-license-identifier).*$", text)
    ))[:100]
    return {
        "runtime_markers": markers,
        "license_notices": license_notices,
    }


def kind_for(name: str, data: bytes) -> str | None:
    if data.startswith(DEX_MAGIC):
        return "dex"
    if data.startswith(ELF_MAGIC):
        return "elf"
    if data.startswith(b"\x00asm"):
        return "wasm"
    if pathlib.PurePosixPath(name).suffix.lower() in JS_SUFFIXES:
        return "javascript"
    return None


def observation(object_id: str, kind: str, data: bytes, archive_path: str | None, readelf: str | None) -> dict[str, Any]:
    if kind == "dex":
        metadata = dex_metadata(data)
    elif kind == "elf":
        metadata = elf_metadata(data, readelf)
        if archive_path:
            m = re.search(r"(?:^|/)lib/([^/]+)/([^/]+)$", archive_path)
            if m:
                metadata["abi"] = m.group(1)
                metadata.setdefault("sonames", [])
                if m.group(2) not in metadata["sonames"]:
                    metadata["sonames"].append(m.group(2))
                    metadata["sonames"].sort()
    elif kind == "javascript":
        metadata = js_metadata(data)
    else:
        metadata = {}
    return {
        "object_id": object_id,
        "kind": kind,
        "sha256": sha256_bytes(data),
        "size_bytes": len(data),
        "archive_path": archive_path,
        "metadata": metadata,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("artifact")
    ap.add_argument("--out", required=True)
    ap.add_argument("--readelf", default=shutil.which("readelf") or "")
    ap.add_argument("--max-entry-bytes", type=int, default=256 * 1024 * 1024)
    args = ap.parse_args()

    artifact = pathlib.Path(args.artifact).resolve()
    if not artifact.is_file():
        raise SystemExit(f"artifact not found: {artifact}")
    artifact_sha = sha256_file(artifact)
    objects: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    if zipfile.is_zipfile(artifact):
        with zipfile.ZipFile(artifact) as zf:
            for info in sorted((x for x in zf.infolist() if not x.is_dir()), key=lambda x: x.filename):
                if info.file_size > args.max_entry_bytes:
                    skipped.append({
                        "path": info.filename,
                        "state": "SKIPPED_BOUND",
                        "reason": f"size {info.file_size} exceeds max-entry-bytes={args.max_entry_bytes}",
                    })
                    continue
                with zf.open(info) as fh:
                    data = fh.read(args.max_entry_bytes + 1)
                if len(data) > args.max_entry_bytes:
                    skipped.append({
                        "path": info.filename,
                        "state": "SKIPPED_BOUND",
                        "reason": "stream exceeded max-entry-bytes",
                    })
                    continue
                kind = kind_for(info.filename, data)
                if not kind:
                    continue
                objects.append(observation(
                    f"zip:{info.filename}",
                    kind,
                    data,
                    info.filename,
                    args.readelf or None,
                ))
    else:
        data = artifact.read_bytes()
        if len(data) > args.max_entry_bytes:
            raise SystemExit("raw artifact exceeds max-entry-bytes")
        kind = kind_for(artifact.name, data)
        if not kind:
            raise SystemExit("raw artifact is not a supported code-bearing type")
        objects.append(observation(
            f"file:{artifact.name}",
            kind,
            data,
            None,
            args.readelf or None,
        ))

    doc = {
        "schema": "aar-component-observations/v0",
        "artifact": {
            "path": str(artifact),
            "sha256": artifact_sha,
            "size_bytes": artifact.stat().st_size,
        },
        "objects": objects,
        "skipped": skipped,
        "tooling": {
            "readelf": args.readelf or None,
            "max_entry_bytes": args.max_entry_bytes,
        },
    }
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "objects": len(objects),
        "kinds": {k: sum(x["kind"] == k for x in objects) for k in sorted({x["kind"] for x in objects})},
        "skipped": len(skipped),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
