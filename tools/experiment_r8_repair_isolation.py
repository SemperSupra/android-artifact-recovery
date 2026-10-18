#!/usr/bin/env python3
"""Apply existing audited Kotlin repair ONLY to separate source-known R8 copies.

Raw JADX trees are immutable evidence. Renamed classes are not deobfuscated.
Unsupported patterns fail closed and produce an explicit unchanged-control
source tree. Only an independent Java execution oracle can claim a match.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

from repair_jadx_kotlin_java import repair

LABELS=("release","rename-only","shrink-only","shrink-optimize","full-r8")
ELIGIBLE=("release","shrink-only","shrink-optimize")
TARGET=Path("org/sempersupra/aar/golden/kotlin/GoldenRecordFingerprint.java")

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def stage(raw: Path, out: Path) -> dict:
    if out.exists():
        raise ValueError("do not overwrite intervention experiment")
    if any(not (raw/label/"sources").is_dir() for label in LABELS):
        raise ValueError("five immutable raw source trees required")
    out.mkdir(parents=True)
    copied=out/"sources"
    records={}
    for label in LABELS:
        dst=copied/label/"sources"
        shutil.copytree(raw/label/"sources",dst,symlinks=False)
        rel=TARGET
        source=raw/label/"sources"/rel
        target=dst/rel
        if label not in ELIGIBLE:
            records[label]={"state":"NO_RENAMED_CLASS_ADAPTER",
                            "repair_applied":False,"semantic_evidence":"UNKNOWN"}
            continue
        if not source.is_file() or not target.is_file():
            records[label]={"state":"TARGET_MISSING",
                            "repair_applied":False,"semantic_evidence":"UNKNOWN"}
            continue
        before=digest(source)
        assert before==digest(target)
        try:
            changed,rules=repair(source.read_text(encoding="utf-8"))
        except ValueError as error:
            records[label]={"state":"UNSUPPORTED_PATTERN",
                            "repair_applied":False,"raw_sha256":before,
                            "error_category":"EXPECTED_PATTERN_MISMATCH",
                            "semantic_evidence":"UNKNOWN"}
            continue
        # The reference pattern count is fixed in the *existing* repair,
        # not loosened to accommodate unknown obfuscation variants.
        encoded=changed.encode("utf-8")
        after=hashlib.sha256(encoded).hexdigest()
        if before==after:
            records[label]={"state":"NO_BYTE_CHANGE","raw_sha256":before,
                            "repair_applied":False,"semantic_evidence":"UNKNOWN"}
            continue
        target.write_bytes(encoded)
        records[label]={"state":"BOUNDED_REPAIR_APPLIED",
                        "repair_applied":True,
                        "raw_sha256":before,"repaired_sha256":after,
                        "rules":[{"id":x.rule_id,"count":x.count} for x in rules],
                        "semantic_evidence":"UNKNOWN"}
    report={"schema":"aar-r8-repair-intervention/v0",
            "profiles":records,"mutation_of_raw_jadx":False,
            "repair_qualifies_semantics":False,
            "R8_ground_truth_mapping_used":False}
    (out/"intervention.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",
                                         encoding="utf-8")
    return report

def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--raw",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    try:
        d=stage(args.raw,args.out)
        print(json.dumps({"state":"R8_SCOPED_REPAIR_STAGED",
                          "applied":sum(r["repair_applied"] for r in d["profiles"].values()),
                          "generalized_recovery":False},sort_keys=True))
        return 0
    except (OSError,ValueError) as error:
        print(json.dumps({"state":"BLOCKED","reason":str(error)}),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
