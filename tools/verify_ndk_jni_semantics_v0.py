#!/usr/bin/env python3
"""A-4 source-known *evaluator-only* semantic oracle after sealed Ghidra IR.

This module alone may access original A-2 semantic truth and A-3 producer-side
ELF symbol oracle. Reconstructor reads neither. This is deterministic analysis
calibration, not an OS-isolated blind AI actor evaluation.
"""
from __future__ import annotations
import argparse,hashlib,json,random,sys
from pathlib import Path
from experiment_ndk_jni_art_runtime_v0 import expected
from recover_ndk_jni_semantics_v0 import evaluate

def vectors():
    fixed=[0,1,-1,2,-2,7,-7,17,31,42,127,255,256,65535,65536,
           0x7fffffff,-0x80000000,0x12345678,-0x1234567,0x40000000]
    rnd=random.Random(0xA4211)
    return fixed+[rnd.randrange(-(1<<31),1<<31) for _ in range(1024)]
def evaluate_withheld(candidate,truth):
    if candidate.get("schema")!=1 or candidate.get("abi")!=truth.get("abi"):
        raise ValueError("schema or ABI mismatch")
    if candidate.get("source_blind") is not True:
        raise ValueError("untrusted reconstructor flag")
    helpers=candidate.get("helpers")
    oracle=truth.get("helper_truth",{})
    if type(helpers)!=dict or len(helpers)!=2 or set(oracle)!={"aar_fold","aar_affine"}:
        raise ValueError("missing/extra helper evidence")
    if set(helpers)!={format(v,"x") for v in oracle.values()}:
        raise ValueError("source oracle helper boundaries not recovered")
    cases=vectors()
    if len(cases)<1000:raise ValueError("insufficient held-out vectors")
    modes={"aar_fold":5,"aar_affine":7}
    results={}
    for symbol,mode in modes.items():
        key=format(oracle[symbol],"x")
        candidate_expression=helpers[key]["expression"]
        mismatches=0
        for u in cases:
            predicted=evaluate(candidate_expression,u)
            if predicted!=(expected(mode,u)&0xffffffff):
                mismatches+=1
        results[symbol]=mismatches
    if any(results.values()):raise ValueError("held-out semantic mismatch")
    # The alternative attribution is a negative-control assertion; rejects a
    # swapped helper even if both are code-bearing and correctly decompiled.
    swapped=sum(evaluate(helpers[format(oracle["aar_fold"],"x")]["expression"],u)!=
                (expected(7,u)&0xffffffff) for u in cases)
    if swapped==0:raise ValueError("semantic false friend not discriminated")
    return {"schema":1,"status":"A4_RESTRICTED_GHIDRA_IR_SEMANTICS_PASS",
        "abi":candidate["abi"],"helpers_evaluated":2,
        "independent_vectors_per_helper":len(cases),"total_correct":2*len(cases),
        "semantic_mismatches":sum(results.values()),
        "negative_wrong_helper_detected":True,
        "candidate_source_access_os_blocked":False,
        "reconstructor_code_imported_source_oracle":False,
        "new_android_runtime_executed":False,
        "arm64_art_qualified":False,"ai_actor_qualified":False,
        "general_c_decompiler_reconstruction_qualified":False}
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--candidate",type=Path,required=True)
    ap.add_argument("--oracle",type=Path,required=True)
    ap.add_argument("--out",type=Path,required=True)
    a=ap.parse_args()
    candidate=json.loads(a.candidate.read_text())
    truth=json.loads(a.oracle.read_text())
    summary=evaluate_withheld(candidate,truth)
    a.out.write_text(json.dumps(summary,sort_keys=True,indent=2)+"\n")
    print("A4_INDEPENDENT_ORACLE="+json.dumps(summary,sort_keys=True))
if __name__=="__main__":
    try:main()
    except (OSError,ValueError,TypeError,KeyError,RecursionError) as e:
        print("A4_ORACLE_FAIL="+str(e),file=sys.stderr)
        raise SystemExit(1)
