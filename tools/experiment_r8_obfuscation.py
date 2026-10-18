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


def blind_dex_name_signals(apk: Path) -> dict:
    """Bounded DEX class-name lengths only; no R8 mapping, no identity lookup.

    Low name lengths are a weak indication, not an obfuscation verdict.
    """
    import struct
    total, short, unreadable = 0, 0, 0
    with zipfile.ZipFile(apk) as zf:
        members = [x for x in zf.infolist()
                   if re.fullmatch(r"classes(?:[2-9]\d*)?\.dex", x.filename)]
        if len(members) > 32:
            raise ValueError("DEX member count limit")
        for entry in members:
            if entry.file_size < 112 or entry.file_size > 64 * 1024 * 1024:
                raise ValueError("invalid DEX member size for independent name probe")
            with zf.open(entry) as reader:
                buf = reader.read(64 * 1024 * 1024 + 1)
            if len(buf) != entry.file_size or len(buf) > 64 * 1024 * 1024:
                raise ValueError("DEX byte limit exceeded")
            if not buf.startswith(b"dex\n") or buf[7] != 0:
                raise ValueError("invalid DEX magic")
            def uint(offset: int) -> int:
                if offset < 0 or offset + 4 > len(buf):
                    raise ValueError("DEX table outside file")
                return struct.unpack_from("<I", buf, offset)[0]
            if uint(0x20) != len(buf) or uint(0x24) != 112 or uint(0x28) != 0x12345678:
                raise ValueError("DEX header or declared length invalid")
            string_count,string_off = uint(0x38),uint(0x3c)
            type_count,type_off = uint(0x40),uint(0x44)
            class_count,class_off = uint(0x60),uint(0x64)
            if string_count > 2_000_000 or type_count > 1_000_000 or class_count > 100_000:
                raise ValueError("DEX table count budget exceeded")
            for count, start, width in ((string_count,string_off,4),
                                        (type_count,type_off,4),
                                        (class_count,class_off,32)):
                if start < 112 or start + count * width > len(buf):
                    raise ValueError("DEX table outside file")
            for i in range(class_count):
                idx = uint(class_off + i*32)
                if idx >= type_count:
                    raise ValueError("class type index outside DEX type table")
                string_idx=uint(type_off + idx*4)
                if string_idx >= string_count:
                    raise ValueError("type descriptor string index outside table")
                start=uint(string_off + string_idx*4)
                if start >= len(buf):
                    raise ValueError("DEX descriptor data offset outside file")
                # DEX string-data item begins with UTF-16 length encoded ULEB128.
                pos=start
                for _ in range(5):
                    if pos >= len(buf):
                        raise ValueError("truncated DEX ULEB128")
                    val=buf[pos]
                    pos+=1
                    if not val & 0x80:
                        break
                else:
                    raise ValueError("oversized DEX ULEB128")
                end=buf.find(b"\0",pos,min(len(buf),pos+4096))
                if end < 0:
                    raise ValueError("unterminated DEX class descriptor")
                try:
                    descriptor=buf[pos:end].decode("utf-8")
                except UnicodeDecodeError:
                    unreadable+=1
                    continue
                if not (descriptor.startswith("L") and descriptor.endswith(";")):
                    unreadable+=1
                    continue
                basename=descriptor[1:-1].split("/")[-1]
                total+=1
                if len(basename) <= 2:
                    short+=1
    return {"classes_with_decodable_descriptor": total,
            "short_simple_names_1_to_2_chars": short,
            "unreadable_descriptor_count": unreadable,
            "short_name_fraction": round(short / total, 4) if total else None,
            "classification": "INDICATOR_ONLY" if total >= 10 else "INSUFFICIENT_SAMPLES",
            "source_name_restoration": "UNKNOWN"}

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
    blind_baseline = blind_dex_name_signals(baseline)
    blind_candidate = blind_dex_name_signals(candidate)
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
        "blind_name_signals": {"baseline": blind_baseline, "candidate": blind_candidate},
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
