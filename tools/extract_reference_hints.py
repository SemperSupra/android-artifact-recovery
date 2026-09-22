#!/usr/bin/env python3
"""Extract bounded reference/version hints without claiming component identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import zipfile
from typing import Any

MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_HINTS_PER_OBJECT = 200
PRINTABLE_RE = re.compile(rb"[ -~]{6,200}")

POM_PROPS_RE = re.compile(
    r"(?m)^(groupId|artifactId|version)\s*=\s*(.+?)\s*$"
)
PACKAGE_JSON_KEYS = ("name", "version")
SOURCE_PATH_RE = re.compile(r"(?:^|[/\\])node_modules[/\\](@[^/\\\\\"'\\s]+[/\\][^/\\\\\"'\\s]+|[^/\\\\\"'\\s]+)")
SEMVER_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)?(?:[-+._][0-9A-Za-z.-]+)?\b")
RETAINED_VERSION_VALUE_RE = re.compile(r"^\\d+(?:\\.\\d+){1,3}(?:[-+._][0-9A-Za-z.-]+)?$")
RETAINED_VERSION_FILE_RE = re.compile(r"^META-INF/(.+)\\.version$", re.I)

KNOWN_PATTERNS = [
    ("openssl", re.compile(r"\bOpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]?(?:[-+._][0-9A-Za-z.-]+)?)\b", re.I)),
    ("ffmpeg", re.compile(r"\bFFmpeg\s+version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+._][0-9A-Za-z.-]+)?)\b", re.I)),
    ("opus", re.compile(r"\b(?:lib)?opus(?:\s+version)?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b", re.I)),
    ("sqlite", re.compile(r"\bSQLite\s+version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b", re.I)),
    ("protobuf", re.compile(r"\bprotobuf(?:\s+version)?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b", re.I)),
]

META_SUFFIXES = {
    ".properties",
    ".json",
    ".xml",
    ".txt",
    ".mf",
}
META_NAME_FRAGMENTS = (
    "pom.properties",
    "pom.xml",
    "package.json",
    "manifest.mf",
    "notice",
    "license",
    "version",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def printable_strings(data: bytes) -> list[str]:
    out = []
    seen = set()
    for match in PRINTABLE_RE.finditer(data):
        value = match.group().decode("utf-8", "replace").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
        if len(out) >= 20000:
            break
    return out


def add_hint(hints: list[dict[str, Any]], seen: set[tuple[str, str, str]], *,
             family: str, kind: str, value: str, evidence: str,
             state: str = "CANDIDATE") -> None:
    key = (family, kind, value)
    if key in seen or len(hints) >= MAX_HINTS_PER_OBJECT:
        return
    seen.add(key)
    hints.append({
        "family": family,
        "kind": kind,
        "value": value,
        "evidence": evidence,
        "state": state,
    })


def metadata_hints(name: str, data: bytes) -> list[dict[str, Any]]:
    lower = name.lower()
    suffix = pathlib.PurePosixPath(lower).suffix
    if suffix not in META_SUFFIXES and not any(x in lower for x in META_NAME_FRAGMENTS):
        return []

    text = data.decode("utf-8", "replace")
    hints: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    retained = RETAINED_VERSION_FILE_RE.match(name)
    if retained:
        module_key = retained.group(1)
        value = text.strip()
        if RETAINED_VERSION_VALUE_RE.fullmatch(value):
            add_hint(
                hints, seen,
                family="retained-version",
                kind="module-version",
                value=f"{module_key}@{value}",
                evidence=name,
            )
            if "_" in module_key:
                group, artifact = module_key.split("_", 1)
                if "." in group and artifact:
                    add_hint(
                        hints, seen,
                        family="maven",
                        kind="gav",
                        value=f"{group}:{artifact}:{value}",
                        evidence=name,
                    )
        else:
            rejected = value[:200] if value else "<empty>"
            add_hint(
                hints, seen,
                family="retained-version",
                kind="rejected-version-value",
                value=rejected,
                evidence=name,
                state="REJECTED",
            )

    if lower.endswith("pom.properties"):
        props = dict(POM_PROPS_RE.findall(text))
        if props.get("groupId") and props.get("artifactId"):
            coordinate = f"{props['groupId']}:{props['artifactId']}"
            add_hint(hints, seen, family="maven", kind="coordinate",
                     value=coordinate, evidence=name)
            if props.get("version"):
                add_hint(hints, seen, family="maven", kind="version",
                         value=props["version"], evidence=name)
                add_hint(hints, seen, family="maven", kind="gav",
                         value=f"{coordinate}:{props['version']}", evidence=name)

    if lower.endswith("pom.xml"):
        group = re.search(r"<groupId>\s*([^<]+)\s*</groupId>", text)
        artifact = re.search(r"<artifactId>\s*([^<]+)\s*</artifactId>", text)
        version = re.search(r"<version>\s*([^<]+)\s*</version>", text)
        if group and artifact:
            coordinate = f"{group.group(1).strip()}:{artifact.group(1).strip()}"
            add_hint(hints, seen, family="maven", kind="coordinate",
                     value=coordinate, evidence=name)
            if version:
                v = version.group(1).strip()
                add_hint(hints, seen, family="maven", kind="version",
                         value=v, evidence=name)
                add_hint(hints, seen, family="maven", kind="gav",
                         value=f"{coordinate}:{v}", evidence=name)

    if lower.endswith("package.json"):
        try:
            doc = json.loads(text)
        except Exception:
            doc = None
        if isinstance(doc, dict):
            pkg = doc.get("name")
            ver = doc.get("version")
            if isinstance(pkg, str):
                add_hint(hints, seen, family="npm", kind="package",
                         value=pkg, evidence=name)
            if isinstance(pkg, str) and isinstance(ver, str):
                add_hint(hints, seen, family="npm", kind="package-version",
                         value=f"{pkg}@{ver}", evidence=name)

    for source_pkg in SOURCE_PATH_RE.findall(text):
        value = source_pkg.replace("\\", "/")
        add_hint(hints, seen, family="npm", kind="source-path-package",
                 value=value, evidence=name)

    if "version" in lower or lower.endswith(".properties"):
        for candidate in SEMVER_RE.findall(text):
            add_hint(hints, seen, family="generic", kind="version-string",
                     value=candidate, evidence=name)

    return hints


def binary_hints(name: str, data: bytes) -> list[dict[str, Any]]:
    if not data.startswith(b"\x7fELF"):
        return []

    strings = printable_strings(data)
    hints: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for value in strings:
        for family, pattern in KNOWN_PATTERNS:
            m = pattern.search(value)
            if m:
                add_hint(hints, seen, family=family, kind="version",
                         value=m.group(1), evidence=f"{name}:printable-string")
        if value.startswith("http://") or value.startswith("https://"):
            if any(host in value.lower() for host in (
                "openssl", "ffmpeg", "xiph", "chromium", "github.com",
                "google.com", "android.googlesource.com",
            )):
                add_hint(hints, seen, family="source", kind="url",
                         value=value, evidence=f"{name}:printable-string")
    return hints


def js_hints(name: str, data: bytes) -> list[dict[str, Any]]:
    if pathlib.PurePosixPath(name).suffix.lower() not in {".js", ".mjs", ".cjs", ".jsbundle"}:
        return []
    text = data[:8_000_000].decode("utf-8", "replace")
    hints: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for source_pkg in SOURCE_PATH_RE.findall(text):
        value = source_pkg.replace("\\", "/")
        add_hint(hints, seen, family="npm", kind="source-path-package",
                 value=value, evidence=name)
    return hints


def process_zip(path: pathlib.Path, max_entry_bytes: int) -> dict[str, Any]:
    hints = []
    skipped = []
    with zipfile.ZipFile(path) as zf:
        for info in sorted((i for i in zf.infolist() if not i.is_dir()), key=lambda x: x.filename):
            if info.file_size > max_entry_bytes:
                skipped.append({
                    "path": info.filename,
                    "state": "SKIPPED_BOUND",
                    "reason": f"size {info.file_size} exceeds max-entry-bytes={max_entry_bytes}",
                })
                continue
            with zf.open(info) as fh:
                data = fh.read(max_entry_bytes + 1)
            if len(data) > max_entry_bytes:
                skipped.append({
                    "path": info.filename,
                    "state": "SKIPPED_BOUND",
                    "reason": "stream exceeded max-entry-bytes",
                })
                continue
            object_hints = metadata_hints(info.filename, data)
            object_hints.extend(binary_hints(info.filename, data))
            object_hints.extend(js_hints(info.filename, data))
            if object_hints:
                hints.append({
                    "path": info.filename,
                    "sha256": sha256(data),
                    "size_bytes": len(data),
                    "hints": object_hints[:MAX_HINTS_PER_OBJECT],
                })
    return {"objects": hints, "skipped": skipped}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("artifact")
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-entry-bytes", type=int, default=MAX_ENTRY_BYTES)
    args = ap.parse_args()

    path = pathlib.Path(args.artifact).resolve()
    if not path.is_file():
        raise SystemExit(f"artifact not found: {path}")
    if not zipfile.is_zipfile(path):
        raise SystemExit("reference hint extraction currently expects an APK/ZIP container")

    body = process_zip(path, args.max_entry_bytes)
    family_counts: dict[str, int] = {}
    for obj in body["objects"]:
        for hint in obj["hints"]:
            family_counts[hint["family"]] = family_counts.get(hint["family"], 0) + 1

    doc = {
        "schema": "aar-reference-hints/v0",
        "artifact": {
            "path": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        },
        "objects": body["objects"],
        "skipped": body["skipped"],
        "summary": {
            "objects_with_hints": len(body["objects"]),
            "hint_count": sum(len(x["hints"]) for x in body["objects"]),
            "family_counts": dict(sorted(family_counts.items())),
        },
        "policy": {
            "identity_claims": False,
            "version_hints_are_candidates_only": True,
            "automatic_residual_suppression": False,
        },
    }

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(doc["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
