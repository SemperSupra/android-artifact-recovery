#!/usr/bin/env python3
"""A6 independent source-known validator for disjoint control-flow JNI golden.

This is evaluator-only; the A4 reconstructor is invoked before answer truth
is loaded and has no imports of this module. A verified two-callee boundary
with unsupported pseudocode is UNKNOWN, not a semantic PASS. No ART runtime.
"""
from __future__ import annotations
import argparse,hashlib,json,re,sys
from pathlib import Path
from recover_ndk_jni_semantics_v0 import recover,one,evaluate
from verify_ndk_jni_semantics_v0 import vectors
from experiment_ndk_jni_ghidra_recovery_v0 import digest

MASK=0xffffffff
UNKNOWN=("unhandled pseudocode structure", "unsupported decompiled C operation",
         "expression too large", "invalid syntax")
def independent_reference(mode:int,x:int)->int:
    v=x&MASK
    if mode==5:
        y=v^0xa5a55a5a
        if v&1:
            y=(33*y+0x13579bdf)&MASK
        else:
            y=((y>>5)^((y<<27)&MASK)^0x2468ace0)&MASK
        return y
    if mode==7:
        y=v^0x10203040
        for idx in range(1,5):
            y=((y^(y>>13))*0x27d4eb2d+idx)&MASK
        return y
    raise ValueError("invalid reference mode")

def judge(log:str,abi:str,oracle:dict,elf:Path)->dict:
    if abi not in ("x86_64","aarch64") or oracle.get("abi")!=abi:
        raise ValueError("cross-ABI oracle prohibited")
    if oracle.get("fixture_kind")!="controlflow" or oracle.get("optimization")!="-O0":
        raise ValueError("not an admitted distinct source/O0 fixture")
    if digest(elf)!=oracle.get("elf_sha256"):
        raise ValueError("Ghidra ELF hash must equal producer's frozen image")
    if one(log,"ABI")!=abi or int(one(log,"COUNT"))!=2:
        raise ValueError("wrong ABI, incomplete or duplicate decompiler evidence")
    base=int(one(log,"BASE"),16)
    matches=re.findall(r"AAR_A4_IR=([a-f0-9]+)\|([A-Za-z0-9+/=]+)",log)
    if len(matches)!=2:
        raise ValueError("missing or duplicated decompiler body")
    discovered={int(address,16)-base for address,_ in matches}
    expected_entries=set(oracle.get("helper_truth",{}).values())
    if len(discovered)!=2 or discovered!=expected_entries:
        raise ValueError("helper boundary disagreement with independent producer")
    stamp={"schema":1,"abi":abi,"fixture_kind":"controlflow",
           "optimization":"-O0","elf_sha256":oracle["elf_sha256"],
           "helper_entries_source_independently_confirmed":2,
           "source_truth_passed_to_ghidra":False,
           "source_truth_in_candidate_parser":False,
           "os_isolated_actor":False,"art_runtime_executed":False,
           "ai_actor_qualified":False}
    try:
        candidate=recover(log,abi)
    except (ValueError,SyntaxError) as exc:
        if not any(k in str(exc) for k in UNKNOWN):
            raise
        return {**stamp,"status":"A6_DISJOINT_UNSUPPORTED_ABSTAIN",
                "semantics_qualified":False,"wrong_semantic_claims":0,
                "unknown_helpers":2,"heldout_vectors_evaluated":0}
    # Any supported expression must pass the independently generated behavior
    # truth. Never promote because Ghidra completed or parser merely returned.
    data=vectors()
    for sym,mode in (("aar_fold",5),("aar_affine",7)):
        address=format(oracle["helper_truth"][sym],"x")
        if address not in candidate["helpers"]:
            raise ValueError("missing source-verified helper expression")
        ir=candidate["helpers"][address]["expression"]
        for value in data:
            if evaluate(ir,value)!=independent_reference(mode,value):
                raise ValueError("A6_SOURCE_BLIND_SEMANTIC_MISMATCH")
    return {**stamp,"status":"A6_DISJOINT_RESTRICTED_SEMANTICS_PASS",
            "semantics_qualified":True,"unknown_helpers":0,
            "heldout_vectors_evaluated":len(data)*2,"wrong_semantic_claims":0}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--root",required=True,type=Path)
    ap.add_argument("--abi",required=True,choices=("x86_64","aarch64"))
    ap.add_argument("--log",required=True,type=Path)
    ap.add_argument("--out",required=True,type=Path)
    a=ap.parse_args()
    log=a.log.read_text(errors="replace")
    if len(log)>5_000_000:raise ValueError("oversized Ghidra log")
    oracle=json.loads((a.root/(a.abi+"-private-oracle.json")).read_text())
    result=judge(log,a.abi,oracle,a.root/(a.abi+"-ghidra-stripped.so"))
    a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("A6_AGGREGATE="+json.dumps(result,sort_keys=True))
if __name__=="__main__":
    try:main()
    except (ValueError,KeyError,OSError,SyntaxError) as e:
        print("A6_ORACLE_FAIL="+str(e),file=sys.stderr)
        raise SystemExit(1)
