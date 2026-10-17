#!/usr/bin/env python3
"""Immutable, resumable, source-only case admission for Android Artifact Recovery.

This deliberately composes the existing AAR characterizer. It does not infer
original source, semantics, permissions, or CDR campaign decisions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

SCHEMA = "aar-local-case/v0"
ALLOWED = {".apk", ".apks", ".xapk", ".apkm", ".zip"}
DEFAULT_CHARACTERIZER = pathlib.Path(__file__).with_name("characterize_android_artifact.py")


class CaseError(Exception):
    pass


def digest(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_json(path: pathlib.Path, data: dict) -> None:
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".aar-pending-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(data, out, indent=2, sort_keys=True)
            out.write("\n")
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def scan_archive(path: pathlib.Path, *, max_entries: int, max_total: int,
                 max_member: int, max_ratio: int) -> dict:
    if path.suffix.lower() not in ALLOWED:
        raise CaseError("unsupported container suffix")
    count = 0
    total = 0
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > max_entries:
                raise CaseError("archive entry limit exceeded")
            for entry in infos:
                name = entry.filename
                parts = name.split("/")
                if (not name or name.startswith("/") or "\\" in name
                        or "\x00" in name or ":" in parts[0]
                        or any(p in ("", ".", "..") for p in parts if p != parts[-1])
                        or ".." in parts or name.rstrip("/") in seen):
                    raise CaseError("unsafe or duplicate archive member")
                seen.add(name.rstrip("/"))
                mode = (entry.external_attr >> 16) & 0xffff
                if stat.S_ISLNK(mode):
                    raise CaseError("archive contains symlink")
                if entry.flag_bits & 1:
                    raise CaseError("archive contains encrypted member")
                if entry.is_dir():
                    continue
                if entry.file_size > max_member:
                    raise CaseError("uncompressed member limit exceeded")
                if entry.file_size > max_ratio * max(1, entry.compress_size):
                    raise CaseError("archive compression-ratio limit exceeded")
                total += entry.file_size
                count += 1
                if total > max_total:
                    raise CaseError("archive uncompressed-byte budget exceeded")
                # Streaming every entry also checks the ZIP CRC; do not extract.
                with zf.open(entry) as reader:
                    observed = 0
                    for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                        observed += len(chunk)
                        if observed > entry.file_size or observed > max_member:
                            raise CaseError("archive stream exceeds declared size")
                    if observed != entry.file_size:
                        raise CaseError("archive member truncated")
    except (zipfile.BadZipFile, OSError, RuntimeError, EOFError) as error:
        raise CaseError("corrupt or unreadable archive") from error
    if not count:
        raise CaseError("archive contains no files")
    return {"files_crc_verified": count, "uncompressed_bytes": total,
            "limits": {"entries": max_entries, "total_bytes": max_total,
                       "member_bytes": max_member, "ratio": max_ratio}}


def identify(args: argparse.Namespace) -> dict:
    source = args.artifact.resolve(strict=True)
    if not source.is_file():
        raise CaseError("input must be a regular file")
    source_hash = digest(source)
    scan = scan_archive(source, max_entries=args.max_entries,
                        max_total=args.max_total_bytes,
                        max_member=args.max_member_bytes, max_ratio=args.max_ratio)
    script = args.characterizer.resolve(strict=True)
    if not script.is_file():
        raise CaseError("missing characterizer")
    return {"sha256": source_hash, "size_bytes": source.stat().st_size,
            "type": source.suffix.lower(), "integrity": scan,
            "characterizer_sha256": digest(script)}


def case_paths(args: argparse.Namespace, identity: dict) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    case = args.work_root.resolve() / identity["sha256"]
    return case, case / "characterization.json", case / "receipt.json"


def verify(args: argparse.Namespace, identity: dict, *, quiet: bool = False) -> dict:
    case, output, receipt_path = case_paths(args, identity)
    if not receipt_path.is_file() or not output.is_file():
        raise CaseError("case not completed")
    receipt = load(receipt_path)
    if (receipt.get("schema") != SCHEMA or receipt.get("input") != identity
            or receipt.get("characterization_sha256") != digest(output)
            or receipt.get("stage") != "CHARACTERIZED_ONLY"):
        raise CaseError("receipt/input/tool mismatch or modified evidence")
    doc = load(output)
    if (doc.get("schema") != "aar-artifact-characterization/v0"
            or doc.get("source", {}).get("sha256") != identity["sha256"]
            or receipt.get("result_schema") != doc.get("schema")):
        raise CaseError("characterization source/schema mismatch")
    if any(item.get("state") == "ERROR" for item in doc.get("skipped", [])):
        raise CaseError("characterization contains unacknowledged errors")
    result = {"case": identity["sha256"], "status": receipt["status"],
              "stage": receipt["stage"], "receipt": str(receipt_path)}
    if not quiet:
        print(json.dumps(result, sort_keys=True))
    return result


def run(args: argparse.Namespace, identity: dict) -> dict:
    case, output, receipt = case_paths(args, identity)
    if receipt.exists() or output.exists():
        checked = verify(args, identity)
        checked["reused"] = True
        return checked
    case.mkdir(parents=True, exist_ok=True)
    fd, pending = tempfile.mkstemp(dir=case, prefix=".aar-characterization-", suffix=".json")
    os.close(fd)
    pending_path = pathlib.Path(pending)
    pending_path.unlink()  # The underlying characterizer creates its own output.
    started = time.monotonic()
    cmd = [sys.executable, str(args.characterizer.resolve()), str(args.artifact.resolve()),
           "--out", str(pending_path), "--max-entry-hash-bytes",
           str(args.max_member_bytes), "--max-nested-apk-bytes",
           str(args.max_member_bytes)]
    try:
        try:
            cp = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=args.timeout, check=False)
        except subprocess.TimeoutExpired as err:
            raise CaseError("characterization timed out") from err
        if cp.returncode != 0 or not pending_path.exists():
            raise CaseError("characterizer failed (see local operator output)")
        doc = load(pending_path)
        if (doc.get("schema") != "aar-artifact-characterization/v0"
                or doc.get("source", {}).get("sha256") != identity["sha256"]):
            raise CaseError("unexpected characterizer source identity/schema")
        if any(x.get("state") == "ERROR" for x in doc.get("skipped", [])):
            raise CaseError("characterization reported error")
        status = "PARTIAL" if doc.get("skipped") else "PASS"
        # Do not claim semantic recovery, complete code coverage or split consistency.
        os.replace(pending_path, output)
        data = {"schema": SCHEMA, "input": identity, "stage": "CHARACTERIZED_ONLY",
                "status": status, "result_schema": doc["schema"],
                "characterization_sha256": digest(output),
                "observed_elapsed_ms": round((time.monotonic() - started) * 1000),
                "unknowns": ["source_semantics", "dynamic_code", "runtime_behavior",
                             "split_signer_consistency", "device_coverage"],
                "scope": "local/public-safe fixture only; no code execution"}
        atomic_json(receipt, data)
        return verify(args, identity)
    finally:
        if pending_path.exists():
            pending_path.unlink()


def probe() -> None:
    binaries = ("java", "javac", "jadx", "apktool", "aapt2", "apksigner",
                "dexdump", "llvm-readelf", "llvm-objdump", "adb",
                "emulator", "analyzeHeadless", "goose", "aider", "pi",
                "opencode", "qwen", "vibe")
    print(json.dumps({"schema": "aar-local-probe/v0",
                      "python": sys.version.split()[0],
                      "executables": {name: shutil.which(name) for name in binaries},
                      "qualification": "PRESENCE_ONLY_NOT_MODEL_OR_TOOL_PASS"},
                     indent=2, sort_keys=True))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("probe", "plan", "run", "verify", "report"))
    p.add_argument("artifact", type=pathlib.Path, nargs="?")
    p.add_argument("--work-root", type=pathlib.Path, default=pathlib.Path(".aar-local"))
    p.add_argument("--characterizer", type=pathlib.Path, default=DEFAULT_CHARACTERIZER)
    p.add_argument("--max-entries", type=int, default=20000)
    p.add_argument("--max-total-bytes", type=int, default=1024 * 1024 * 1024)
    p.add_argument("--max-member-bytes", type=int, default=256 * 1024 * 1024)
    p.add_argument("--max-ratio", type=int, default=1000)
    p.add_argument("--timeout", type=int, default=180)
    args = p.parse_args()
    try:
        if args.command == "probe":
            probe()
            return 0
        if args.artifact is None:
            raise CaseError("artifact path required")
        if any(x <= 0 for x in (args.max_entries, args.max_total_bytes,
                                args.max_member_bytes, args.max_ratio, args.timeout)):
            raise CaseError("resource limits must be positive")
        identity = identify(args)
        if args.command == "plan":
            print(json.dumps({"schema": "aar-local-plan/v0", "input": identity,
                              "case": str(case_paths(args, identity)[0]),
                              "planned_stage": "CHARACTERIZED_ONLY",
                              "runtime_or_original_source": "UNKNOWN"},
                             indent=2, sort_keys=True))
        elif args.command == "run":
            run(args, identity)
        else:
            verify(args, identity)
        return 0
    except (CaseError, FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
