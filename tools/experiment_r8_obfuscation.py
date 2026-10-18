#!/usr/bin/env python3
"""Independent R8-obfuscation calibration and bounded *blind* JADX options sweep.

Source-known evaluator sees R8 mapping and hashes it; JADX contestants do not.
A lower JADX exit code, renamed alias, or more files is NOT evidence of
correctness or behavior equivalence. This script makes no best-mode selection.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import zipfile

SCHEMA = "aar-r8-obfuscation-interview/v0"
CLASS = "org.sempersupra.aar.golden.kotlin.GoldenRecordFingerprint"
MODES = {
    "auto": [],
    "synthetic-aliases": ["--deobf", "--deobf-cfg-file-mode", "ignore"],
    "simple": ["--decompilation-mode", "simple"],
    "fallback": ["--decompilation-mode", "fallback"],
    "no-inline-methods": ["--no-inline-methods"],
    "no-inline-kotlin-lambda": ["--no-inline-kotlin-lambda"],
}

def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for part in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()

def read_mapping(path: Path, *, max_bytes: int = 8 * 1024 * 1024) -> dict:
    if path.stat().st_size > max_bytes:
        raise ValueError("mapping byte budget exceeded")
    classes: dict[str, str] = {}
    # Class mapping lines are unindented; member lines are indented.
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line[0].isspace() or line.startswith("#"):
            continue
        match = re.fullmatch(r"([^\s]+) -> ([^\s:]+):", line)
        if match:
            if match[1] in classes:
                raise ValueError("duplicate mapping class")
            classes[match[1]] = match[2]
    if not classes:
        raise ValueError("R8 mapping missing class mappings")
    if CLASS not in classes:
        raise ValueError("known public oracle class absent from R8 mapping")
    changed = {k: v for k, v in classes.items() if k != v}
    if CLASS not in changed:
        raise ValueError("source-known oracle class was not renamed by R8")
    return {"mapping_classes": len(classes),
            "renamed_classes": len(changed),
            "known_oracle_class_renamed": True}

def dex_members(path: Path) -> dict:
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("public APK size cap exceeded")
    members: dict = {}
    with zipfile.ZipFile(path) as zf:
        for entry in zf.infolist():
            if re.fullmatch(r"classes(?:[2-9]\d*)?\.dex", entry.filename):
                if entry.file_size > 64 * 1024 * 1024:
                    raise ValueError("DEX size budget exceeded")
                blob = zf.read(entry)
                if not blob.startswith(b"dex\n"):
                    raise ValueError("classes dex entry not valid DEX header")
                members[entry.filename] = hashlib.sha256(blob).hexdigest()
    if not members:
        raise ValueError("APK has no root DEX")
    return dict(sorted(members.items()))

def execute(argv: list[str], timeout: int) -> dict:
    started = time.monotonic()
    try:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
        out = proc.stdout.decode("utf-8", "replace")
        errors = re.findall(r"finished with errors, count: (\d+)", out)
        return {
            "exit_code": proc.returncode,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            "jadx_reported_error_count": int(errors[-1]) if errors else None,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": None, "elapsed_ms": timeout * 1000,
                "jadx_reported_error_count": None, "timed_out": True}

def interview(baseline: Path, candidate: Path, mapping: Path, jadx: Path,
              out: Path, timeout: int = 120) -> dict:
    if out.exists():
        raise ValueError("output already exists; results must not be overwritten")
    mapping_stats = read_mapping(mapping)
    base_dex = dex_members(baseline)
    cand_dex = dex_members(candidate)
    if sha(baseline) == sha(candidate):
        raise ValueError("R8 candidate APK did not differ from source-known baseline")
    out.mkdir(parents=True)
    reports = {}
    for key, flags in MODES.items():
        root = out / key
        # JADX never sees the R8 mapping or source. Per-mode path is unique.
        # No jobf state is imported; each run starts with fresh alias state.
        root.mkdir()
        result = execute([str(jadx), *flags,
                          "--no-res", "--no-imports", "--show-bad-code",
                          "-d", str(root), str(candidate)], timeout=timeout)
        files = sorted((root / "sources").rglob("*.java")) if (root / "sources").exists() else []
        result.update({
            "source_file_count": len(files),
            "recovered_behavior": "UNKNOWN",
            "recovered_original_names": "UNKNOWN",
            "source_equivalence": "UNKNOWN",
            "qualification": "NOT_EVALUATED",
        })
        reports[key] = result
        print(json.dumps({"mode": key, "jadx_exit": result["exit_code"],
                          "reported_errors": result["jadx_reported_error_count"],
                          "java_files": result["source_file_count"],
                          "behavior": "UNKNOWN"}, sort_keys=True), flush=True)
    result = {
        "schema": SCHEMA,
        "source_known": True,
        "unobfuscated_apk_sha256": sha(baseline),
        "obfuscated_apk_sha256": sha(candidate),
        "r8_mapping_sha256": sha(mapping),
        "oracle_mapping_visible_to_candidates": False,
        "calibration": mapping_stats,
        "baseline_dex_sha256": base_dex,
        "candidate_dex_sha256": cand_dex,
        "modes": reports,
        "selection": "NO_BEST_MODE_WITHOUT_INDEPENDENT_BEHAVIORAL_ORACLE",
        "mitigation": "ALIASES_NOT_ORIGINAL_NAMES; NO_BYPASS; REPAIR_NOT_APPLIED",
        "blind_target_obfuscation_detection": "NOT_CALIBRATED",
    }
    (out / "interview.json").write_text(json.dumps(result, indent=2, sort_keys=True)+"\n",
                                         encoding="utf-8")
    return result

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline_apk", "candidate_apk", "mapping", "jadx", "out"):
        p.add_argument("--"+name.replace("_","-"), type=Path, required=True)
    p.add_argument("--timeout", type=int, default=120)
    a=p.parse_args()
    if a.timeout < 5 or a.timeout > 240:
        p.error("timeout must be 5..240")
    try:
        result=interview(a.baseline_apk, a.candidate_apk,
                         a.mapping, a.jadx, a.out, timeout=a.timeout)
        print(json.dumps({"state":"SOURCE_KNOWN_CALIBRATION_EXECUTED",
                          "renamed_classes":result["calibration"]["renamed_classes"],
                          "mode_count":len(result["modes"]),
                          "best_method":"UNKNOWN"},sort_keys=True))
        return 0
    except (OSError, ValueError, zipfile.BadZipFile) as e:
        print(json.dumps({"state":"BLOCKED","reason":str(e)}),file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
