#!/usr/bin/env python3
"""Source-blind A8: recover independently parseable IR per Ghidra helper.

This stage MUST run and freeze its candidate before opening any producer-side
symbol/address truth or native behavioral oracle. No original C source,
source maps, or expected() implementation are imported by this module.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
from recover_ndk_jni_semantics_v0 import one, parse_c, read_ir_rows

ABSTAIN_SHAPE = (
    "unhandled pseudocode structure", "unsupported decompiled C operation",
    "expression too large", "invalid syntax", "Ghidra pseudocode size/hidden-symbol leak",
)

def classify(text: str) -> tuple[str, dict | None, str]:
    try:
        ir = parse_c(text)
    except (ValueError, SyntaxError) as error:
        message = str(error)
        if "UNSUPPORTED_SIGNED_OR_MIXED_IR" in message:
            return "ABSTAIN", None, "UNSUPPORTED_SIGNED_OR_MIXED_IR"
        if any(s in message for s in ABSTAIN_SHAPE):
            return "ABSTAIN", None, "UNSUPPORTED_PSEUDOCODE_SHAPE"
        raise
    return "RESTRICTED_UINT_CANDIDATE", ir, "PARSEABLE_NOT_YET_QUALIFIED"

def recover_partial(log: str, abi: str) -> dict:
    if abi not in ("x86_64", "aarch64") or one(log, "ABI") != abi:
        raise ValueError("A8 ABI mismatch")
    base = int(one(log,"BASE"),16)
    if int(one(log,"COUNT"))!=2:
        raise ValueError("A8 malformed Ghidra count")
    observations=read_ir_rows(log)
    records=[]
    seen=set()
    for address,encoded in observations:
        absolute=int(address,16)
        rva=absolute-base
        if rva<=0 or rva in seen:
            raise ValueError("A8 duplicate or invalid helper address")
        seen.add(rva)
        raw=base64.b64decode(encoded,validate=True)
        if not 12<len(raw)<4096:
            raise ValueError("A8 invalid Ghidra C byte count")
        text=raw.decode("ascii")
        status,ir,reason=classify(text)
        records.append({"rva":rva,"status":status,"reason":reason,
                        "ir":ir,"ghidra_c_sha256":hashlib.sha256(raw).hexdigest()})
    return {"schema":1,"abi":abi,"source_blind":True,
            "producer_oracle_opened":False,"source_truth_available":False,
            "base":base,"records":sorted(records,key=lambda r:r["rva"]),
            "semantic_predictions_accepted":0,"actor_qualified":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--abi",required=True,choices=("x86_64","aarch64"))
    p.add_argument("--log",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    if a.log.stat().st_size>5_000_000:
        raise ValueError("oversized source-known Ghidra log")
    candidate=recover_partial(a.log.read_text(errors="replace"),a.abi)
    a.out.write_text(json.dumps(candidate,sort_keys=True,indent=2)+"\n")
    print("A8_CANDIDATE_FROZEN="+json.dumps({"abi":a.abi,
        "record_count":len(candidate["records"]),"source_blind":True,
        "oracle_opened":False,"semantic_predictions_accepted":0},sort_keys=True))

if __name__=="__main__":
    main()
