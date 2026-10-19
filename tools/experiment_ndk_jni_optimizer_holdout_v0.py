#!/usr/bin/env python3
"""A-5 independent NDK -O0 transformation control for existing A-4 interpreter.

The candidate parser is reused unchanged, with no optimizer-specific repair.
A valid but unsupported compiler-generated C shape is UNKNOWN, never PASS.
Source and helper identity oracle are opened only after candidate recovery.
"""
from __future__ import annotations
import argparse,hashlib,json,re,subprocess,sys
from pathlib import Path
from experiment_ndk_jni_bridge_v0 import ndk_root
from recover_ndk_jni_semantics_v0 import recover,one
from verify_ndk_jni_semantics_v0 import evaluate_withheld

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def code_bytes(lib:Path, objcopy:Path, directory:Path) -> bytes:
    target=directory/(lib.stem+".text-only")
    subprocess.run([str(objcopy),"--dump-section", ".text="+str(target), str(lib)],
                   check=True,capture_output=True,text=True,timeout=60)
    data=target.read_bytes()
    if not 1<=len(data)<=10_000_000:raise ValueError("invalid ELF .text section")
    target.unlink()
    return data

def attest(baseline:Path, heldout:Path, abi:str) -> dict:
    if abi not in ("x86_64","aarch64"):raise ValueError("unadmitted ABI")
    a=json.loads((baseline/(abi+"-private-oracle.json")).read_text())
    b=json.loads((heldout/(abi+"-private-oracle.json")).read_text())
    if a["abi"]!=abi or b["abi"]!=abi or a["cpp_sha256"]!=b["cpp_sha256"]:
        raise ValueError("source or ABI not matched across treatment")
    if a["optimization"]!="-O1" or b["optimization"]!="-O0":
        raise ValueError("actual optimizer treatment not recorded")
    if a["elf_sha256"]==b["elf_sha256"]:raise ValueError("no ELF difference")
    bins=list((ndk_root()/"toolchains/llvm/prebuilt").glob("*/bin/llvm-objcopy"))
    if len(bins)!=1:raise ValueError("NDK llvm-objcopy unavailable")
    code_a=code_bytes(baseline/(abi+"-ghidra-stripped.so"),bins[0],baseline)
    code_b=code_bytes(heldout/(abi+"-ghidra-stripped.so"),bins[0],heldout)
    if code_a==code_b:raise ValueError("no actual executable code difference")
    return {"abi":abi,"baseline_optimizer":"-O1","heldout_optimizer":"-O0",
            "baseline_text_sha256":sha(code_a),"heldout_text_sha256":sha(code_b),
            "baseline_text_bytes":len(code_a),"heldout_text_bytes":len(code_b),
            "source_digest_equal":True,"executable_code_distinct":True,
            "binary_executed":False,"source_truth_available_to_reconstructor":False}

UNSUPPORTED=("unhandled pseudocode structure","unsupported decompiled C operation",
             "expression too large","invalid syntax")

def run_evaluator(log:str,oracle:dict,abi:str) -> dict:
    # A5 quality depends on exactly two complete Ghidra C bodies, even if
    # the current restricted parser cannot interpret those bodies.
    if one(log,"ABI")!=abi or int(one(log,"COUNT"))!=2:
        raise ValueError("invalid Ghidra ABI/function observation")
    rows=re.findall(r"AAR_A4_IR=([a-f0-9]+)\|([A-Za-z0-9+/=]+)",log)
    if len(rows)!=2:raise ValueError("missing/extra decompiler evidence")
    try:
        candidate=recover(log,abi)
    except (ValueError,SyntaxError) as exc:
        if not any(x in str(exc) for x in UNSUPPORTED):
            raise
        return {"schema":1,"abi":abi,"status":"A5_UNSUPPORTED_DECOMPILER_EXPRESSION",
                "semantic_correct_predictions":0,"qualified":False,
                "source_truth_reached_candidate":False,
                "unsupported_reason_class":"UNSUPPORTED_EXPRESSION_SHAPE",
                "new_runtime_executed":False,"actor_qualified":False}
    result=evaluate_withheld(candidate,oracle)
    return {"schema":1,"abi":abi,"status":"A5_RESTRICTED_SEMANTICS_PASS",
            "semantic_correct_predictions":result["total_correct"],
            "independent_vectors_per_helper":result["independent_vectors_per_helper"],
            "semantic_mismatches":result["semantic_mismatches"],
            "qualified":True,"source_truth_reached_candidate":False,
            "new_runtime_executed":False,"actor_qualified":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--baseline",type=Path,required=True)
    p.add_argument("--heldout",type=Path,required=True)
    p.add_argument("--abi",choices=("x86_64","aarch64"),required=True)
    p.add_argument("--log",type=Path)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    att=attest(a.baseline,a.heldout,a.abi)
    if a.log:
        # Operator/oracle do not flow backwards into Ghidra.
        log=a.log.read_text(errors="replace")
        if len(log)>5_000_000:raise ValueError("oversized Ghidra evidence")
        truth=json.loads((a.heldout/(a.abi+"-private-oracle.json")).read_text())
        result={**att,**run_evaluator(log,truth,a.abi)}
    else:
        result={**att,"schema":1,"status":"A5_NATIVE_CODE_DIVERGENCE_PASS",
                "qualified":False}
    a.out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("A5_AGGREGATE="+json.dumps(result,sort_keys=True))

if __name__=="__main__":
    try:main()
    except (OSError,ValueError,KeyError,SyntaxError,subprocess.SubprocessError) as exc:
        print("A5_FAIL="+str(exc),file=sys.stderr)
        raise SystemExit(1)
