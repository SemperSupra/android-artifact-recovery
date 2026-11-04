#!/usr/bin/env python3
"""A9 preregistered disjoint source-known Ghidra IR, frozen before oracle.

The producer oracle and native C reference are opened ONLY after the source-
blind A8 parser has frozen the candidate in a separate workflow step.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from verify_ndk_jni_typed_partial_native_v0 import judge, vectors, make_host_oracles

ORACLE_SOURCE=(Path(__file__).resolve().parents[1] /
               "qualification/reference/android-jni-typed/a9_independent_native_oracle.c")

def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument("--abi",required=True,choices=("x86_64","aarch64"))
    ap.add_argument("--root",required=True,type=Path)
    ap.add_argument("--candidate",required=True,type=Path)
    ap.add_argument("--out",required=True,type=Path)
    args=ap.parse_args()
    if args.candidate.stat().st_size>50_000:
        raise ValueError("oversized heldout source-blind candidate")
    frozen=args.candidate.read_bytes()
    candidate=json.loads(frozen)
    # Producer-side source and behavioral truth opened ONLY after frozen bytes.
    source=json.loads((args.root/(args.abi+"-private-oracle.json")).read_text())
    samples=vectors()
    native,source_hash=make_host_oracles(ORACLE_SOURCE,samples,"a9_u32_reference")
    receipt=judge(candidate,args.abi,source,
                  args.root/(args.abi+"-ghidra-stripped.so"),
                  samples,native,source_hash,fixture_kind="heldout_a9")
    receipt["preregistered_disjoint_family"]=True
    receipt["frozen_candidate_sha256"]=hashlib.sha256(frozen).hexdigest()
    receipt["aarch64_native_behavior_executed"]=False
    receipt["android_art_jni_runtime_executed"]=False
    args.out.write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    print("A9_AGGREGATE="+json.dumps(receipt,sort_keys=True))

if __name__=="__main__":
    main()
