#!/usr/bin/env python3
"""A8 independently checks frozen per-helper Ghidra IR vs native C.

The source-blind candidate is read from a file produced by another process,
BEFORE producer truth is opened. The independent host GCC/Clang source-known
oracle is not an Android ART or AArch64 execution oracle. No source-side
helper name, Ghidra C, vectors or native code is published to the candidate.
"""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from recover_ndk_jni_semantics_v0 import evaluate

MACHINES={"x86_64":62,"aarch64":183}
SOURCE_ORACLE=(Path(__file__).resolve().parents[1] /
               "qualification/reference/android-jni-typed/a8_unsigned_native_oracle.c")

def vectors() -> list[int]:
    # Fixed edge cases plus 1024 deterministic PRNG values, never fed to A8.
    fixed=[0,1,2,3,7,127,0x7fffffff,0x80000000,0xfffffffe,0xffffffff]
    state=0x12345678
    values=list(fixed)
    for _ in range(1024):
        state=(1664525*state+1013904223)&0xffffffff
        values.append(state)
    return values

def make_host_oracles(source: Path, values: list[int]) -> tuple[list[list[int]],str]:
    if not source.is_file() or source.stat().st_size>100_000:
        raise ValueError("missing/oversized source-known native oracle")
    source_hash=hashlib.sha256(source.read_bytes()).hexdigest()
    outputs=[]
    with tempfile.TemporaryDirectory() as tmp:
        for compiler in ("gcc","clang"):
            if shutil.which(compiler) is None:
                raise ValueError("missing native C compiler: "+compiler)
            for opt in ("-O0","-O2"):
                output=Path(tmp)/(compiler+opt[2:]+".so")
                subprocess.run([compiler,"-std=c11","-shared","-fPIC",opt,
                     str(source),"-o",str(output)],check=True,capture_output=True,
                     timeout=60)
                lib=ctypes.CDLL(str(output))
                fn=lib.a8_u32_reference
                fn.argtypes=[ctypes.c_uint32]
                fn.restype=ctypes.c_uint32
                outputs.append([int(fn(v)) for v in values])
    if len(outputs)!=4 or any(row!=outputs[0] for row in outputs[1:]):
        raise ValueError("native compiler reference disagreement")
    return outputs,source_hash

def judge(candidate: dict, abi: str, producer: dict, elf: Path,
          samples: list[int], native_output: list[list[int]], source_hash: str) -> dict:
    if abi not in MACHINES or producer.get("abi")!=abi or candidate.get("abi")!=abi:
        raise ValueError("A8 cross-ABI candidate/oracle mismatch")
    if producer.get("fixture_kind")!="typed" or producer.get("optimization")!="-O0":
        raise ValueError("A8 unexpected fixture or optimizer")
    if producer.get("elf_machine")!=MACHINES[abi] or not elf.is_file():
        raise ValueError("A8 unexpected ELF machine")
    actual_hash=hashlib.sha256(elf.read_bytes()).hexdigest()
    if actual_hash!=producer.get("elf_sha256"):
        raise ValueError("A8 wrong stripped ELF SHA256")
    if candidate.get("source_blind") is not True or candidate.get("producer_oracle_opened") is not False:
        raise ValueError("A8 candidate provenance boundary broken")
    if candidate.get("semantic_predictions_accepted")!=0:
        raise ValueError("A8 candidate pre-promoted itself")
    entries=producer.get("helper_truth")
    if type(entries)!=dict or set(entries)!={"aar_fold","aar_affine"}:
        raise ValueError("A8 producer expected exactly two hidden helpers")
    records=candidate.get("records")
    if type(records)!=list or len(records)!=2:
        raise ValueError("A8 incomplete candidate records")
    if any(type(r)!=dict or type(r.get("rva"))!=int for r in records):
        raise ValueError("A8 malformed candidate record")
    by_rva={r["rva"]:r for r in records}
    if len(by_rva)!=2 or set(by_rva)!=set(entries.values()):
        raise ValueError("A8 native helper attribution mismatch")
    good=by_rva[entries["aar_fold"]]
    unknown=by_rva[entries["aar_affine"]]
    if good.get("status")!="RESTRICTED_UINT_CANDIDATE" or type(good.get("ir"))!=dict:
        raise ValueError("A8 unsigned helper missing supported IR")
    if unknown.get("status")!="ABSTAIN" or unknown.get("ir") is not None or unknown.get("reason")!="UNSUPPORTED_SIGNED_OR_MIXED_IR":
        raise ValueError("A8 signed helper must remain explicitly unqualified")
    if len(samples)<1000 or len(native_output)!=4 or any(len(a)!=len(samples) for a in native_output):
        raise ValueError("A8 native reference census incomplete")
    for row in native_output:
        for u,want in zip(samples,row):
            if evaluate(good["ir"],u)!=want:
                raise ValueError("A8 native source-known UNSIGNED_SEMANTIC_MISMATCH")
    return {"schema":1,"abi":abi,"status":"A8_UNSIGNED_SOURCE_KNOWN_NATIVE_MATCH_SIGNED_ABSTAIN",
        "fixture_kind":"typed","elf_sha256":actual_hash,
        "source_blind_recovered_unsigned_helpers":1,
        "signed_helpers_abstained":1,
        "source_truth_accessed_after_candidate_freeze":True,
        "independent_host_native_compiler_builds":4,
        "native_unsigned_behavioral_comparisons":len(samples)*4,
        "native_unsigned_mismatches":0,
        "native_oracle_source_sha256":source_hash,
        "android_art_jni_runtime_executed":False,
        "aarch64_native_behavior_executed":False,
        "general_signed_semantics_qualified":False,
        "actor_qualified":False,"production_semantics_qualified":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--abi",required=True,choices=tuple(MACHINES))
    p.add_argument("--root",required=True,type=Path)
    p.add_argument("--candidate",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    if a.candidate.stat().st_size>50_000:
        raise ValueError("oversized A8 candidate")
    frozen=a.candidate.read_bytes()
    # The following opens the owner truth ONLY AFTER the candidate is frozen.
    candidate=json.loads(frozen)
    producer=json.loads((a.root/(a.abi+"-private-oracle.json")).read_text())
    sample=vectors()
    native,source_hash=make_host_oracles(SOURCE_ORACLE,sample)
    result=judge(candidate,a.abi,producer,
            a.root/(a.abi+"-ghidra-stripped.so"),sample,native,source_hash)
    result["frozen_candidate_sha256"]=hashlib.sha256(frozen).hexdigest()
    a.out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("A8_AGGREGATE="+json.dumps(result,sort_keys=True))

if __name__=="__main__":
    main()
