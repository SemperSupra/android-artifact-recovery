#!/usr/bin/env python3
"""Bounded R8 configuration *sequence*, not an orthogonal factorial.

R8 -dontshrink may also inhibit optimization. Measure the effects from
source-authored variants without claiming three independent causal variables.
All mapping data stays evaluator-side; never pass it to JADX or an actor.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from experiment_r8_obfuscation import (
    CLASS, blind_dex_name_signals, dex_members, execute, read_mapping, sha
)

PROFILES = {
    "release": {"r8": False, "renaming": False, "shrinking": False,
                "optimization": False},
    "rename-only": {"r8": True, "renaming": True, "shrinking": False,
                    "optimization": False},
    "shrink-only": {"r8": True, "renaming": False, "shrinking": True,
                    "optimization": False},
    "shrink-optimize": {"r8": True, "renaming": False, "shrinking": True,
                        "optimization": True},
    "full-r8": {"r8": True, "renaming": True, "shrinking": True,
                "optimization": True},
}
COMPARISONS = {
    "rename-vs-release": ["release", "rename-only"],
    "shrink-vs-release": ["release", "shrink-only"],
    "optimize-given-shrink": ["shrink-only", "shrink-optimize"],
    "rename-given-shrink-and-optimize": ["shrink-optimize", "full-r8"],
}

def validate_factors(profiles: dict) -> None:
    if set(profiles) != set(PROFILES):
        raise ValueError("missing or extra R8 factor profile")
    for k, v in PROFILES.items():
        if profiles[k]["flags"] != v:
            raise ValueError("factor plan changed")

def examine(paths: dict[str, Path], maps: dict[str, Path],
            jadx: Path, out: Path, timeout: int = 90) -> dict:
    if out.exists():
        raise ValueError("evidence output already exists")
    if set(paths) != set(PROFILES):
        raise ValueError("all five source-known APK variants required")
    if set(maps) != {"rename-only", "full-r8"}:
        raise ValueError("only two evaluator-only R8 name mappings admitted")
    if timeout < 5 or timeout > 120:
        raise ValueError("invalid per-variant timeout")
    # All input validity and transformation checks occur before output creation.
    observations = {}
    for label, apk in paths.items():
        dex = dex_members(apk)
        names = blind_dex_name_signals(apk)
        observations[label] = {
            "flags": dict(PROFILES[label]),
            "apk_sha256": sha(apk), "dex_members": dex,
            "blind_name_signals": names,
            "behavior": "UNKNOWN",
        }
    hashes=[observations[k]["apk_sha256"] for k in PROFILES]
    if len(set(hashes)) != len(hashes):
        raise ValueError("one or more independent R8 build variants have identical APK bytes")
    for label, mapping in maps.items():
        stats = read_mapping(mapping)
        observations[label]["evaluator_mapping_sha256"] = sha(mapping)
        observations[label]["evaluator_known_class_renamed"] = stats["known_oracle_class_renamed"]
        observations[label]["evaluator_renamed_class_count"] = stats["renamed_classes"]
    out.mkdir(parents=True)
    for label, apk in paths.items():
        dest=out / label
        dest.mkdir()
        report=execute([str(jadx), "--no-res", "--no-imports", "--show-bad-code",
                        "-d", str(dest), str(apk)], timeout)
        sources=sorted((dest/"sources").rglob("*.java")) if (dest/"sources").exists() else []
        report["java_file_count"]=len(sources)
        report["behavior"]="UNKNOWN"
        report["raw_source_compilation"]="NOT_RUN"
        observations[label]["jadx_auto"]=report
        print(json.dumps({"variant":label,"exit":report["exit_code"],
                          "files":len(sources),"behavior":"UNKNOWN"},sort_keys=True),flush=True)
    contrasts={}
    for key,(a,b) in COMPARISONS.items():
        contrasts[key]={
            "lhs":a,"rhs":b,
            "dex_identity_changed":observations[a]["dex_members"]!=observations[b]["dex_members"],
            "blind_name_signal_difference": None if
                observations[a]["blind_name_signals"]["short_name_fraction"] is None or
                observations[b]["blind_name_signals"]["short_name_fraction"] is None else
                round(observations[b]["blind_name_signals"]["short_name_fraction"]-
                      observations[a]["blind_name_signals"]["short_name_fraction"],4),
            "behavior_effect":"UNKNOWN",
            "causal_status":"CONTROLLED_CONFIGURATION_CONTRAST_NOT_INDEPENDENT_FACTOR",
        }
    result={
        "schema":"aar-r8-factor-sequence/v0",
        "profiles":observations,
        "contrasts":contrasts,
        "controls":{
            "R8_switches_are_not_orthogonal":True,
            "dontshrink_can_limit_optimization":True,
            "compiler_runtime_and_dependency_closure":"SAME_BUILD_WORKFLOW_UNPROVEN_BINARY",
            "mapping_fed_to_jadx":False,
            "original_behavior_oracle":"NOT_EXECUTED_ON_R8_OUTPUT",
            "best_recovery_mode":"UNKNOWN",
            "source_equivalence":"UNKNOWN",
        },
        "limitations":"R8 source change can restructure a corpus; no behavioral conclusion."
    }
    (out/"matrix.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",
                                   encoding="utf-8")
    return result

def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    for label in PROFILES:
        p.add_argument("--"+label+"-apk",type=Path,required=True)
    for label in ("rename-only","full-r8"):
        p.add_argument("--"+label+"-mapping",type=Path,required=True)
    p.add_argument("--jadx",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--timeout",type=int,default=90)
    a=p.parse_args()
    paths={k:getattr(a,k.replace("-","_")+"_apk") for k in PROFILES}
    maps={k:getattr(a,k.replace("-","_")+"_mapping") for k in ("rename-only","full-r8")}
    try:
        result=examine(paths,maps,a.jadx,a.out,a.timeout)
        print(json.dumps({"state":"R8_FACTOR_SEQUENCE_OBSERVED",
                          "profiles":len(result["profiles"]),
                          "contrasts":len(result["contrasts"]),
                          "behavior":"UNKNOWN"},sort_keys=True))
        return 0
    except (OSError,ValueError) as err:
        print(json.dumps({"state":"BLOCKED","reason":str(err)}),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
